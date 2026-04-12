#include "connection_handler.h"
#include "channel.h"
#include "tls/tls_connection.h"
#include "log/logger.h"
#include "log/log_utils.h"

ConnectionHandler::ConnectionHandler(std::shared_ptr<Dispatcher> _dispatcher, std::unique_ptr<SocketHandler> _sock)
    : event_dispatcher_(_dispatcher), sock_(std::move(_sock))
{
    client_channel_ = std::shared_ptr<Channel>(new Channel(event_dispatcher_, sock_ -> fd()));
    // Note: Cannot call shared_from_this() in constructor
    // Callbacks registered in RegisterCallbacks() after shared_ptr is created
}

// Out-of-line destructor: unique_ptr<TlsConnection> requires complete type.
// TlsConnection is forward-declared in the header; full definition is available here.
ConnectionHandler::~ConnectionHandler() = default;

void ConnectionHandler::RegisterCallbacks(){
    // Use weak_ptr to avoid keeping ConnectionHandler alive via callbacks
    // This prevents use-after-free when server shuts down during callback execution
    std::weak_ptr<ConnectionHandler> weak_self = shared_from_this();

    client_channel_ -> SetReadCallBackFn([weak_self]() {
        if (auto self = weak_self.lock()) {
            self->OnMessage();
        }
    });

    client_channel_ -> SetCloseCallBackFn([weak_self]() {
        if (auto self = weak_self.lock()) {
            self->CallCloseCb();
        }
    });

    client_channel_ -> SetErrorCallBackFn([weak_self]() {
        if (auto self = weak_self.lock()) {
            self->CallErroCb();
        }
    });

    client_channel_ -> SetWriteCallBackFn([weak_self]() {
        if (auto self = weak_self.lock()) {
            self->CallWriteCb();
        }
    });

    client_channel_ -> EnableETMode();
    client_channel_ -> EnableReadMode();
}

void ConnectionHandler::RegisterOutboundCallbacks(){
    // Use weak_ptr to avoid keeping ConnectionHandler alive via callbacks
    std::weak_ptr<ConnectionHandler> weak_self = shared_from_this();

    client_channel_ -> SetReadCallBackFn([weak_self]() {
        if (auto self = weak_self.lock()) {
            self->OnMessage();
        }
    });

    client_channel_ -> SetCloseCallBackFn([weak_self]() {
        if (auto self = weak_self.lock()) {
            self->CallCloseCb();
        }
    });

    client_channel_ -> SetErrorCallBackFn([weak_self]() {
        if (auto self = weak_self.lock()) {
            self->CallErroCb();
        }
    });

    client_channel_ -> SetWriteCallBackFn([weak_self]() {
        if (auto self = weak_self.lock()) {
            self->CallWriteCb();
        }
    });

    connect_state_ = ConnectState::CONNECTING;
    client_channel_ -> EnableETMode();
    // Enable ONLY write mode — EPOLLOUT fires when connect() completes.
    // Read mode is enabled later in CallWriteCb after connect succeeds.
    client_channel_ -> EnableWriteMode();
}

int ConnectionHandler::FinishConnect(){
    int err = 0;
    socklen_t len = sizeof(err);
    int ret;
    do {
        ret = ::getsockopt(fd(), SOL_SOCKET, SO_ERROR, &err, &len);
    } while (ret == -1 && errno == EINTR);
    if (ret < 0) {
        logging::Get()->warn("getsockopt(SO_ERROR) failed fd={}: {} (errno={})",
                             fd(), logging::SafeStrerror(errno), errno);
        return SocketHandler::CONNECT_ERROR;
    }
    if (err != 0) {
        logging::Get()->warn("Outbound connect SO_ERROR fd={}: {} (errno={})",
                             fd(), logging::SafeStrerror(err), err);
        return SocketHandler::CONNECT_ERROR;
    }
    return SocketHandler::CONNECT_SUCCESS;
}

void ConnectionHandler::SetConnectCompleteCallback(ConnectCompleteCallback cb) {
    connect_complete_callback_ = std::move(cb);
}

int ConnectionHandler::TlsPeek(char* buf, size_t len) {
    if (tls_state_ != TlsState::READY || !tls_) {
        return TlsConnection::TLS_ERROR;
    }
    return tls_->Peek(buf, len);
}

int ConnectionHandler::dispatcher_index() const {
    return event_dispatcher_ ? event_dispatcher_->dispatcher_index() : -1;
}

void ConnectionHandler::OnMessage(){
    if(client_channel_ -> is_channel_closed()){
        return;
    }

    // TLS handshake phase — may also complete via CallWriteCb (EPOLLOUT path)
    bool tls_just_ready = tls_ready_from_write_;
    tls_ready_from_write_ = false;  // consume
    if (tls_state_ == TlsState::HANDSHAKE) {
        int result = tls_->DoHandshake();
        if (result == TlsConnection::TLS_COMPLETE) {
            tls_state_ = TlsState::READY;
            tls_just_ready = true;
            // Handshake complete, fall through to read any buffered data
        } else if (result == TlsConnection::TLS_WANT_READ) {
            // Want read — already enabled
            return;
        } else if (result == TlsConnection::TLS_WANT_WRITE) {
            // Want write
            client_channel_->EnableWriteMode();
            return;
        } else {
            // Handshake failed — use CallCloseCb for proper cleanup
            logging::Get()->warn("TLS handshake failed fd={}", fd());
            CallCloseCb();
            return;
        }
    }

    // If a previous SSL_write returned WANT_READ, the next readable event
    // must retry that write instead of doing a new SSL_read.
    // After the retry, fall through to the normal read loop to drain any
    // readable bytes that arrived — ET mode won't fire another EPOLLIN.
    if (tls_write_wants_read_) {
        tls_write_wants_read_ = false;
        CallWriteCb();  // Retry the pending write
        // CallWriteCb may have closed the connection (ForceClose on write error
        // or after draining a close_after_write response). Check before falling
        // through to the read loop — reading from a closed fd is UB.
        if (tls_write_wants_read_ || is_closing_ ||
            (client_channel_ && client_channel_->is_channel_closed())) {
            return;
        }
        // Otherwise fall through to read loop
    }

    bool peer_closed = false;  // Track if we saw EOF, close after dispatching buffered data
    bool stopped_for_cap = false; // True when we stopped reading due to input cap
    char buffer[MAX_BUFFER_SIZE];
    while(true){
        memset(buffer, 0, sizeof buffer);
        ssize_t nread;

        if (tls_state_ == TlsState::READY) {
            nread = tls_->Read(buffer, sizeof buffer);
            if (nread == TlsConnection::TLS_COMPLETE) {
                // WANT_READ — wait for more data (already in read mode)
                break;
            }
            if (nread == TlsConnection::TLS_CROSS_RW) {
                // WANT_WRITE — SSL needs write readiness to complete this read
                // (renegotiation/key update). Set flag so CallWriteCb retries the read.
                tls_read_wants_write_ = true;
                client_channel_->EnableWriteMode();
                break;
            }
            if (nread == TlsConnection::TLS_PEER_CLOSED) {
                // Peer closed TLS connection cleanly (close_notify).
                // Break out of the read loop — dispatch any buffered data first,
                // then the peer_closed flag will trigger CloseAfterWrite.
                peer_closed = true;
                break;
            }
        } else {
            nread = ::read(fd(), buffer, sizeof buffer);
        }

        if(nread > 0){
            input_bf_.Append(buffer, nread);
            // Enforce input buffer cap — stop reading when the cap is hit.
            // Data stays in the kernel buffer (not discarded). After the
            // callback processes what we have, another read is scheduled
            // via EnQueue. This bounds per-cycle allocation without losing
            // data, and works correctly with chunked encoding and WS framing
            // regardless of wire overhead.
            if (max_input_size_ > 0 && input_bf_.Size() >= max_input_size_) {
                stopped_for_cap = true;
                break;
            }
        } else if(nread < 0 && errno == EINTR){
            // Interrupted by signal — retry
            continue;
        } else if(nread == 0 && tls_state_ != TlsState::READY){
            // Client close (raw TCP). Break out of the read loop to dispatch any
            // buffered data first, then close after processing.
            peer_closed = true;
            break;
        } else if (nread < 0) {
            if (tls_state_ == TlsState::READY) {
                // TLS read error — use CallCloseCb for proper cleanup
                logging::Get()->warn("TLS read error fd={}, closing", fd());
                CallCloseCb();
                return;
            }
            if((errno == EAGAIN) || (errno == EWOULDBLOCK)){
                break;
            }
            // Read error — use CallCloseCb for proper server map cleanup
            int saved_errno = errno;
            // ECONNRESET/EPIPE/ENOTCONN are peer-initiated disconnections,
            // not server errors — log at debug to avoid noise under load.
            if (saved_errno == ECONNRESET || saved_errno == EPIPE || saved_errno == ENOTCONN) {
                logging::Get()->debug("Peer disconnected fd={}: {} (errno={})", fd(), logging::SafeStrerror(saved_errno), saved_errno);
            } else {
                logging::Get()->warn("Read error fd={}: {} (errno={})", fd(), logging::SafeStrerror(saved_errno), saved_errno);
            }
            CallCloseCb();
            return;
        } else {
            break;  // nread == 0 for TLS means would_block, already handled
        }
    }

    // If peer sent EOF, arm close_after_write_ BEFORE the callback so that
    // synchronous sends (DoSendRaw fast-path) see the flag and ForceClose
    // immediately after flushing, without waiting for a post-callback check.
    // This avoids the ordering issue where close_after_write_ is set AFTER
    // the fast-path already checked it and returned.
    if (peer_closed) {
        close_after_write_.store(true, std::memory_order_release);
    }

    // After reading all available data, call the application callback if data was received.
    // Also fire on TLS handshake completion without data ONLY when ALPN negotiated h2,
    // so the upper layer can send the server SETTINGS preface immediately.
    // For HTTP/1.x, skip the empty callback to avoid arming request timeout prematurely.
    // Fire on TLS handshake completion for h2 (to send SETTINGS preface) and
    // for outbound connections (connect_state_ == CONNECTED) regardless of ALPN
    // so the upstream pool's checkout completes for HTTP/1.1 upstreams too.
    // Inbound connections always have connect_state_ == NONE, so this doesn't
    // affect the server-side path.
    bool alpn_h2_ready = tls_just_ready && input_bf_.Size() == 0 && tls_ &&
                         (GetAlpnProtocol() == "h2" ||
                          connect_state_ == ConnectState::CONNECTED);
    bool callback_ran = false;
    if((input_bf_.Size() > 0 || alpn_h2_ready) && callbacks_.on_message_callback){
        std::string message(input_bf_.Data(), input_bf_.Size());
        callbacks_.on_message_callback(shared_from_this(), message);
        // Update timestamp
        ts_ = TimeStamp::Now();
        // Clear the input buffer after processing
        input_bf_.Clear();
        callback_ran = true;
    }

    // If peer sent EOF and connection isn't already closing (the sync fast-path
    // in DoSendRaw/DoSend may have already ForceClose'd), handle the close.
    //
    // HTTP/1 clients are allowed to half-close the write side
    // (shutdown(SHUT_WR) after sending the request) while waiting for
    // the response. When that happens we see peer_closed=true with an
    // empty output buffer (the async handler has not written anything
    // yet), and force-closing the socket here would cancel the
    // in-flight request before the handler can reply. We must instead
    // let the handler run to completion; the existing deferred
    // heartbeat and its absolute safety cap (cap_sec) bound the wait,
    // and any actual write failure (client read-shutdown or
    // full-disconnect) already funnels through the send-side fast-path
    // which sets close_after_write_ / calls ForceClose on EPIPE.
    if (peer_closed && !is_closing_.load(std::memory_order_acquire)) {
        if (output_bf_.Size() > 0) {
            // Data still being flushed — enable write mode to drain it.
            // CallWriteCb will ForceClose when the buffer empties.
            client_channel_->EnableWriteMode();
        } else if (callback_ran) {
            // Callback ran but buffer is empty and connection not
            // closed. Possible cases:
            //   - Sync handler sent response, fast-path ForceClose'd
            //     → is_closing_ == true (caught by outer guard).
            //   - Async handler will send response later via
            //     SendData/SendRaw; the send fast-path will see
            //     close_after_write_ and ForceClose when it runs.
            //   - Client is half-closed waiting for the response;
            //     the deferred heartbeat already armed a deadline
            //     that will either fire cap_sec or re-arm until the
            //     handler completes.
            // Arm a modest fallback deadline when nothing else has —
            // guarantees the timer callback eventually runs so the
            // connection can be torn down if the handler hangs,
            // without closing a valid in-flight request up front.
            if (!has_deadline_) {
                SetDeadline(std::chrono::steady_clock::now() +
                            std::chrono::seconds(5));
            }
        } else {
            // No callback ran (EOF without any input this cycle and
            // no handler in-flight) — nothing to wait for.
            ForceClose();
        }
    }

    // If we stopped reading due to the input cap (not EAGAIN/EOF), there's
    // more data in the kernel buffer (raw TCP) or OpenSSL's internal buffer
    // (TLS). Schedule another OnMessage on the next event loop iteration to
    // continue processing. This is non-recursive (EnQueue) and works for
    // both raw TCP and TLS without needing EPOLL_CTL_MOD re-arm.
    if (stopped_for_cap &&
        !is_closing_.load(std::memory_order_acquire) &&
        !close_after_write_.load(std::memory_order_acquire)) {
        std::weak_ptr<ConnectionHandler> weak_self = shared_from_this();
        event_dispatcher_->EnQueue([weak_self]() {
            if (auto self = weak_self.lock()) {
                if (!self->is_closing_.load(std::memory_order_acquire)) {
                    self->OnMessage();
                }
            }
        });
    }
}

void ConnectionHandler::SendData(const char *data, size_t size){
    // Thread-safety: if we are already on the dispatcher's event-loop thread,
    // we can call DoSend inline. Otherwise we must EnQueue so that buffer
    // mutations happen on the correct thread (avoids racing with the reactor).
    if(event_dispatcher_ && event_dispatcher_->is_on_loop_thread()) {
        DoSend(data, size);
    } else {
        std::string data_copy(data, size);
        std::weak_ptr<ConnectionHandler> weak_self = shared_from_this();
        event_dispatcher_ -> EnQueue([weak_self, data_copy]() {
            if (auto self = weak_self.lock()) {
                self->DoSend(data_copy.data(), data_copy.size());
            }
        });
    }
}

void ConnectionHandler::DoSend(const char *data, size_t size){
    if (is_closing_) return;

    // If a TLS write retry is pending, just buffer — don't try to write.
    // OpenSSL requires retrying with the same buffer after WANT_READ/WANT_WRITE.
    if (tls_write_wants_read_ || tls_read_wants_write_) {
        output_bf_.AppendWithHead(data, size);
        return;
    }

    // Prepend the 4-byte length header, then attempt direct send.

    // This avoids the edge-triggered EPOLLOUT issue where a freshly writable
    // socket won't generate a new event when EPOLLOUT is first registered.
    output_bf_.AppendWithHead(data, size);

    if (output_bf_.Size() > 0) {
        ssize_t written;
        if (tls_state_ == TlsState::READY) {
            size_t try_len = output_bf_.Size();
            written = tls_->Write(output_bf_.Data(), try_len);
            if (written == TlsConnection::TLS_COMPLETE) {
                // WANT_WRITE — treat as EAGAIN for the send path
                tls_pending_write_size_ = try_len;
                written = TlsConnection::TLS_ERROR;
                errno = EAGAIN;
            } else if (written == TlsConnection::TLS_CROSS_RW) {
                tls_pending_write_size_ = try_len;
                tls_write_wants_read_ = true;
                client_channel_->EnableReadMode();
                // Don't enable write mode — wait for read readiness first.
                // OnMessage() will retry the write when read data arrives.
                // Without this, EPOLLOUT fires continuously (socket is writable)
                // and we busy-loop retrying SSL_write that keeps returning WANT_READ.
                return;
            }
        } else if (tls_state_ == TlsState::NONE) {
            // No TLS — raw send
            written = ::send(fd(), output_bf_.Data(), output_bf_.Size(), SEND_FLAGS);
        }
        // tls_state_ == HANDSHAKE: skip direct send, data stays buffered
        if (tls_state_ != TlsState::HANDSHAKE) {
            if (written > 0) {
                output_bf_.Erase(0, written);
                ts_ = TimeStamp::Now();
                tls_pending_write_size_ = 0;
                if (output_bf_.Size() == 0) {
                    if (callbacks_.complete_callback)
                        callbacks_.complete_callback(shared_from_this());
                    // Check close_after_write — connection may need to close
                    if (close_after_write_.load(std::memory_order_acquire)) {
                        ForceClose();
                    }
                    return;
                }
            } else if (written < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                int saved_errno = errno;
                logging::Get()->warn("Write error fd={}: {} (errno={})", fd(), logging::SafeStrerror(saved_errno), saved_errno);
                CallCloseCb();
                return;
            }
        }
    }

    client_channel_ -> EnableWriteMode();
}

void ConnectionHandler::SendRaw(const char *data, size_t size){
    // Thread-safety: same pattern as SendData() — inline on loop thread,
    // EnQueue otherwise.
    if(event_dispatcher_ && event_dispatcher_->is_on_loop_thread()) {
        DoSendRaw(data, size);
    } else {
        std::string data_copy(data, size);
        std::weak_ptr<ConnectionHandler> weak_self = shared_from_this();
        event_dispatcher_ -> EnQueue([weak_self, data_copy]() {
            if (auto self = weak_self.lock()) {
                self->DoSendRaw(data_copy.data(), data_copy.size());
            }
        });
    }
}

void ConnectionHandler::DoSendRaw(const char *data, size_t size){
    if (is_closing_) return;

    // If a TLS write retry is pending, just buffer — don't try to write.
    if (tls_write_wants_read_) {
        // SSL_write needs read readiness — just buffer without enabling write.
        // OnMessage will retry the write when read data arrives. Enabling
        // write mode here would undo the busy-loop prevention (EPOLLOUT fires
        // continuously on a writable socket while TLS is waiting for read).
        output_bf_.Append(data, size);
        return;
    }
    if (tls_read_wants_write_) {
        // SSL_read needs write readiness — buffer and ensure write mode is on
        // so CallWriteCb can retry the read.
        output_bf_.Append(data, size);
        client_channel_->EnableWriteMode();
        return;
    }

    // If output buffer is empty, try sending directly first.
    // This avoids the edge-triggered EPOLLOUT issue where a freshly writable
    // socket won't generate a new event when EPOLLOUT is first registered.
    if (output_bf_.Size() == 0 && tls_state_ != TlsState::HANDSHAKE) {
        ssize_t written;
        if (tls_state_ == TlsState::READY) {
            written = tls_->Write(data, size);
            if (written == TlsConnection::TLS_COMPLETE) {
                // WANT_WRITE — data will be buffered below, record size for retry
                tls_pending_write_size_ = size;
                written = TlsConnection::TLS_ERROR;
                errno = EAGAIN;
            } else if (written == TlsConnection::TLS_CROSS_RW) {
                tls_pending_write_size_ = size;
                tls_write_wants_read_ = true;
                client_channel_->EnableReadMode();
                // Buffer the data and stop watching write readiness.
                // OnMessage() will retry the write when read data arrives.
                output_bf_.Append(data, size);
                return;
            }
        } else {
            // No TLS — raw send
            written = ::send(fd(), data, size, SEND_FLAGS);
        }
        if (written > 0) {
            ts_ = TimeStamp::Now();
            tls_pending_write_size_ = 0;
            if (static_cast<size_t>(written) == size) {
                if (callbacks_.complete_callback)
                    callbacks_.complete_callback(shared_from_this());
                if (close_after_write_.load(std::memory_order_acquire)) {
                    ForceClose();
                }
                return;
            }
            // Partial write -- buffer the remainder
            data += written;
            size -= written;
        } else if (written < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            // Send error — close the connection (same as buffered write path)
            CallCloseCb();
            return;
        }
        // written == 0 or EAGAIN -- fall through to buffering
    }

    output_bf_.Append(data, size);
    client_channel_ -> EnableWriteMode();
}

void ConnectionHandler::CloseAfterWrite(){
    close_after_write_.store(true, std::memory_order_release);
    // Always enqueue the buffer-check/close so it runs after any previously
    // queued send tasks (e.g., WS close frames via SendRaw, or cross-thread
    // broadcast sends). Without this, an inline call on the loop thread can
    // see an empty output_bf_ (queued sends haven't executed yet) and
    // ForceClose, truncating in-flight data. The close_after_write_ flag
    // (set above) ensures that concurrent CallCloseCb and write-completion
    // paths also defer properly.
    if (event_dispatcher_ && !event_dispatcher_->was_stopped()) {
        std::weak_ptr<ConnectionHandler> weak_self = shared_from_this();
        event_dispatcher_->EnQueue([weak_self]() {
            if (auto self = weak_self.lock()) {
                // Re-check shutdown exemption here on the dispatcher
                // thread: a request can enter its async handler (which
                // flips shutdown_exempt_ in BeginAsyncResponse) between
                // the stopper thread calling CloseAfterWrite() and this
                // lambda running. Without this recheck, an exempt
                // connection with an empty buffer would be force-closed
                // under the deferred async response. The close_after_write_
                // flag stays set so CompleteAsyncResponse sees shutdown
                // in progress and forces Connection: close on its reply.
                if (self->IsShutdownExempt()) return;
                if (self->output_bf_.Size() > 0) {
                    self->client_channel_->EnableWriteMode();
                } else {
                    self->ForceClose();
                }
            }
        });
        return;
    }
    // Dispatcher stopped — execute inline as last resort. Still honor the
    // exemption flag so stop-from-handler paths can't race the sweep.
    if (IsShutdownExempt()) return;
    if (output_bf_.Size() > 0) {
        client_channel_ -> EnableWriteMode();
    } else {
        ForceClose();
    }
}

void ConnectionHandler::ForceClose(){
    // Skip the close_after_write defer — used when a deferred close stalls
    // and the timer needs to reclaim the connection.
    logging::Get()->debug("Force-closing fd={}", fd());
    close_after_write_.store(false, std::memory_order_release);
    CallCloseCb();
}

void ConnectionHandler::CallCloseCb(){
    // If close_after_write is armed, defer to the write path.
    // CallWriteCb will close after the buffer drains. For async handlers,
    // DoSend will enable write mode when data arrives. If nothing ever
    // arrives, the idle/deadline timeout will force-close via ForceClose().
    if (close_after_write_.load(std::memory_order_acquire)) {
        return;
    }

    // Prevent duplicate close callbacks with atomic compare-exchange
    bool expected = false;
    if (!is_closing_.compare_exchange_strong(expected, true)) {
        logging::Get()->debug("Duplicate close prevented fd={}", fd());
        return;
    }

    // IMPORTANT: Capture shared_ptr to self to keep this alive during callback
    std::shared_ptr<ConnectionHandler> self = shared_from_this();

    // If off the dispatcher thread and the dispatcher is still running,
    // enqueue the close so EPOLL_CTL_DEL and ::close(fd) happen atomically
    // on the loop thread (prevents fd-reuse races).
    if (event_dispatcher_ && !event_dispatcher_->is_on_loop_thread()
        && !event_dispatcher_->was_stopped()) {
        event_dispatcher_->EnQueue([self]() {
            // Best-effort TLS close_notify (phase 1 only -- don't wait for peer reply)
            if (self->tls_state_ == TlsState::READY && self->tls_) {
                self->tls_->Shutdown();
                self->tls_state_ = TlsState::NONE;
            }
            if (self->client_channel_ && !self->client_channel_->is_channel_closed()) {
                self->client_channel_->CloseChannel();
            }
            if (self->callbacks_.close_callback)
                self->callbacks_.close_callback(self);
            if (self->sock_) self->sock_->ReleaseFd();
        });
        return;
    }

    // On-thread or dispatcher stopped: execute inline

    // Best-effort TLS close_notify (phase 1 only -- don't wait for peer reply)
    if (tls_state_ == TlsState::READY && tls_) {
        tls_->Shutdown();
        tls_state_ = TlsState::NONE;
    }

    // Close the channel to clean up fd and remove from epoll.
    // CloseChannel() calls ::close(fd) and sets Channel::fd_ = -1.
    if(client_channel_ && !client_channel_->is_channel_closed()){
        client_channel_->CloseChannel();
    }

    // Call the application callback (needs fd() to still work for map lookups)
    if (callbacks_.close_callback)
        callbacks_.close_callback(self);

    // AFTER the callback: release fd from SocketHandler to prevent double-close.
    // CloseChannel already closed the fd, but SocketHandler still has the old fd number.
    // Under connection churn the kernel can reuse the fd before SocketHandler destructs.
    if (sock_) sock_->ReleaseFd();
}

void ConnectionHandler::CallErroCb(){
    // Guard against double-close
    bool expected = false;
    if (!is_closing_.compare_exchange_strong(expected, true)) {
        return;
    }

    std::shared_ptr<ConnectionHandler> self = shared_from_this();

    // If off the dispatcher thread and the dispatcher is still running,
    // enqueue the error handling so EPOLL_CTL_DEL and ::close(fd) happen
    // atomically on the loop thread (prevents fd-reuse races).
    if (event_dispatcher_ && !event_dispatcher_->is_on_loop_thread()
        && !event_dispatcher_->was_stopped()) {
        event_dispatcher_->EnQueue([self]() {
            if (self->callbacks_.error_callback)
                self->callbacks_.error_callback(self);
            // Best-effort TLS close_notify (phase 1 only)
            if (self->tls_state_ == TlsState::READY && self->tls_) {
                self->tls_->Shutdown();
                self->tls_state_ = TlsState::NONE;
            }
            if (self->client_channel_ && !self->client_channel_->is_channel_closed()) {
                self->client_channel_->CloseChannel();
            }
            if (self->sock_) self->sock_->ReleaseFd();
        });
        return;
    }

    // On-thread or dispatcher stopped: execute inline

    // Notify error handler (NOT close handler -- avoid duplicate callbacks)
    if (callbacks_.error_callback)
        callbacks_.error_callback(self);

    // Best-effort TLS close_notify (phase 1 only)
    if (tls_state_ == TlsState::READY && tls_) {
        tls_->Shutdown();
        tls_state_ = TlsState::NONE;
    }

    // Close the channel and release fd -- same cleanup as CallCloseCb
    // but without firing the close callback (which would be a second notification)
    if(client_channel_ && !client_channel_->is_channel_closed()){
        client_channel_->CloseChannel();
    }

    if (sock_) sock_->ReleaseFd();
}

void ConnectionHandler::CallWriteCb(){
    // Check if channel is closed or write mode disabled (can happen during shutdown)
    if(!client_channel_ || client_channel_->is_channel_closed() || !client_channel_->isEnableWriteMode()) {
        return; // Silently ignore - channel is closing or already closed
    }

    // Outbound connect completion: the first EPOLLOUT after connect(EINPROGRESS)
    // signals that the TCP handshake finished. Must be checked before any TLS
    // or write logic — the socket isn't usable until connect succeeds.
    if (connect_state_ == ConnectState::CONNECTING) {
        // If close_after_write was set (e.g., deadline timeout fired in the
        // same epoll batch), skip connect completion — the connection is
        // already doomed. Fall through to the write/close logic below.
        if (close_after_write_.load(std::memory_order_acquire)) {
            // Do NOT change connect_state_ — leave it as CONNECTING so the
            // close callback (which checks IsConnecting()) fires the error_cb
            // with CHECKOUT_CONNECT_TIMEOUT / CHECKOUT_SHUTTING_DOWN.
            // Changing to CONNECTED here would make the close callback skip
            // the error delivery, leaving the caller hanging.
            connect_complete_callback_ = nullptr;
            // Fall through — the output-buffer-empty check below will
            // see close_after_write_ and ForceClose.
        } else {
            int result = FinishConnect();
            if (result == SocketHandler::CONNECT_SUCCESS) {
                connect_state_ = ConnectState::CONNECTED;
                client_channel_->EnableReadMode();
                if (connect_complete_callback_) {
                    // Move the callable onto the stack BEFORE invoking.
                    // The pool's WirePoolCallbacks (called from inside this
                    // callback on a successful checkout) does
                    // SetConnectCompleteCallback(nullptr), which destroys
                    // the std::function that's currently executing. The
                    // local `cb` keeps the target alive until it returns,
                    // and the move leaves the member empty (one-shot).
                    auto cb = std::move(connect_complete_callback_);
                    cb(shared_from_this());
                }
                // CRITICAL: If callback set tls_state_ = HANDSHAKE, fall through
                // to the existing TLS handshake block. With ET mode, returning
                // here would stall — no new EPOLLOUT fires on an already-writable
                // socket.
                if (tls_state_ == TlsState::HANDSHAKE) {
                    // Fall through to existing TLS handshake handler below
                } else if (output_bf_.Size() > 0) {
                    // The connect-complete callback sent data. Fall through to
                    // the write logic to flush it — returning would consume the
                    // EPOLLOUT edge and stall the buffered request.
                } else {
                    client_channel_->DisableWriteMode();
                    return;
                }
            } else {
                logging::Get()->warn("Outbound connect failed fd={}", fd());
                CallCloseCb();
                return;
            }
        }
    }

    // If a previous SSL_read returned WANT_WRITE, the next writable event
    // must retry that read instead of doing a normal write.
    // After the retry, fall through to the normal write path to flush any
    // pending output — ET mode won't fire another EPOLLOUT for already-writable.
    if (tls_read_wants_write_) {
        tls_read_wants_write_ = false;
        OnMessage();  // Retry the pending read
        // OnMessage may have closed the channel or re-armed a TLS flag
        if (tls_read_wants_write_ || is_closing_ ||
            (client_channel_ && client_channel_->is_channel_closed())) {
            return;
        }
        // Otherwise fall through to write path
    }

    // TLS handshake WANT_WRITE handling
    if (tls_state_ == TlsState::HANDSHAKE) {
        int result = tls_->DoHandshake();
        if (result == TlsConnection::TLS_COMPLETE) {
            tls_state_ = TlsState::READY;
            tls_ready_from_write_ = true;  // signal OnMessage to fire callback
            // Handshake complete — OpenSSL may have buffered application data.
            OnMessage();
            // OnMessage may have closed the channel
            if (is_closing_ || (client_channel_ && client_channel_->is_channel_closed())) {
                return;
            }
            // Fall through to normal write logic to flush any pending output buffer
        } else if (result == TlsConnection::TLS_WANT_READ) {
            client_channel_->DisableWriteMode();
            // Want read — read mode already enabled
            return;
        } else if (result == TlsConnection::TLS_WANT_WRITE) {
            // Want write again, will get another EPOLLOUT
            return;
        } else {
            // Handshake error — use CallCloseCb for proper cleanup
            CallCloseCb();
            return;
        }
    }

    // Nothing to write
    if (output_bf_.Size() == 0) {
        client_channel_->DisableWriteMode();
        if (close_after_write_.load(std::memory_order_acquire)) {
            ForceClose();
        }
        return;
    }

    int write_sz;
    if (tls_state_ == TlsState::HANDSHAKE) {
        // Don't write during handshake — data stays buffered until READY
        return;
    } else if (tls_state_ == TlsState::READY) {
        // Use pending size for retry, or full buffer for new write
        size_t write_len = tls_pending_write_size_ > 0 ? tls_pending_write_size_ : output_bf_.Size();
        write_sz = tls_->Write(output_bf_.Data(), write_len);
        if (write_sz == TlsConnection::TLS_COMPLETE) {
            tls_pending_write_size_ = write_len;  // Track for retry
            return;  // WANT_WRITE — try again on next EPOLLOUT
        }
        if (write_sz == TlsConnection::TLS_CROSS_RW) {
            tls_pending_write_size_ = write_len;  // Track for retry
            tls_write_wants_read_ = true;
            client_channel_->EnableReadMode();
            // Stop watching write readiness — the TLS layer needs read data
            // from the peer before it can complete this write. OnMessage()
            // will retry when read data arrives. Without disabling write,
            // EPOLLOUT fires continuously and we busy-loop.
            client_channel_->DisableWriteMode();
            return;
        }
        if (write_sz < 0) {
            // TLS write error — ForceClose bypasses close_after_write defer
            logging::Get()->warn("TLS write error fd={}, force-closing", fd());
            ForceClose();
            return;
        }
    } else {
        write_sz = ::send(fd(), output_bf_.Data(), output_bf_.Size(), SEND_FLAGS);
        if (write_sz < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            // Send failed (EPIPE, ECONNRESET, etc.) — ForceClose bypasses defer
            int saved_errno = errno;
            logging::Get()->warn("Write callback send error fd={}: {} (errno={})", fd(), logging::SafeStrerror(saved_errno), saved_errno);
            ForceClose();
            return;
        }
    }

    // Remove sent data and refresh idle timestamp
    if(write_sz > 0) {
        output_bf_.Erase(0, write_sz);
        ts_ = TimeStamp::Now();
        tls_pending_write_size_ = 0;  // Clear pending — write succeeded
        // Refresh close-after-write deadline — the connection is actively draining.
        // Without this, a large/slow-but-healthy response can be force-closed
        // mid-transfer by the fixed 30s deadline from CloseConnection().
        // Only refresh when close_after_write_ is set (close-drain deadline),
        // NOT for request deadlines (Slowloris protection) which should be absolute.
        if (has_deadline_ && close_after_write_.load(std::memory_order_acquire)) {
            // Extend the drain deadline to prevent force-close mid-transfer,
            // but never shorten a tighter deadline (e.g. WS 5s close timeout).
            auto new_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
            if (new_deadline > deadline_) {
                deadline_ = new_deadline;
            }
        }
    }

    // If there's no data waiting to write, then unregister writing event
    if(output_bf_.Size() == 0){
        client_channel_->DisableWriteMode();
        if (close_after_write_.load(std::memory_order_acquire)) {
            ForceClose();  // Buffer drained — close now
            return;
        }
        if(callbacks_.complete_callback)
            callbacks_.complete_callback(shared_from_this());
    } else {
        // Partial write — notify progress (HTTP/2 low watermark resume)
        if (write_sz > 0 && callbacks_.write_progress_callback)
            callbacks_.write_progress_callback(shared_from_this(), output_bf_.Size());
        // Still data to send — ensure write mode is enabled.
        // This is essential after the WANT_READ recovery path (OnMessage → CallWriteCb)
        // where write mode was disabled while waiting for read readiness.
        // For the normal EPOLLOUT path, write mode is already enabled, so this is a no-op.
        client_channel_->EnableWriteMode();
    }
}

void ConnectionHandler::SetOnMessageCb(CALLBACKS_NAMESPACE::ConnOnMsgCallback fn){
    callbacks_.on_message_callback = std::move(fn);
}

void ConnectionHandler::SetCompletionCb(CALLBACKS_NAMESPACE::ConnCompleteCallback fn){
    callbacks_.complete_callback = std::move(fn);
}

void ConnectionHandler::SetWriteProgressCb(CALLBACKS_NAMESPACE::ConnWriteProgressCallback fn){
    callbacks_.write_progress_callback = std::move(fn);
}

void ConnectionHandler::SetCloseCb(CALLBACKS_NAMESPACE::ConnCloseCallback fn){
    callbacks_.close_callback = std::move(fn);
}

void ConnectionHandler::SetErrorCb(CALLBACKS_NAMESPACE::ConnErrorCallback fn){
    callbacks_.error_callback = std::move(fn);
}

void ConnectionHandler::SetTlsConnection(std::unique_ptr<TlsConnection> tls) {
    tls_ = std::move(tls);
    tls_state_ = TlsState::HANDSHAKE;
}

void ConnectionHandler::RunOnDispatcher(std::function<void()> task) {
    if (event_dispatcher_) {
        event_dispatcher_->EnQueue(std::move(task));  // EnQueue handles was_stopped check
    }
}

std::string ConnectionHandler::GetAlpnProtocol() const {
    if (tls_ && tls_state_ == TlsState::READY) {
        return tls_->GetAlpnProtocol();
    }
    return "";
}

void ConnectionHandler::SetDeadlineTimeoutCb(DeadlineTimeoutCb cb) {
    deadline_timeout_cb_ = std::move(cb);
    ++deadline_cb_generation_;
}

bool ConnectionHandler::CallDeadlineTimeoutCb() {
    if (deadline_timeout_cb_) {
        // Move to stack local before invoking: the callback may call
        // SetDeadlineTimeoutCb(nullptr) (e.g., proxy's ClearResponseTimeout),
        // which would destroy the std::function while it's executing (UB).
        //
        // After invocation, restore the callback UNLESS the callback
        // explicitly called SetDeadlineTimeoutCb() during invocation
        // (detected by generation change). This supports both:
        //   - One-shot callbacks (proxy): clear themselves → generation changed → no restore
        //   - Recurring callbacks (H2): don't touch Set → generation unchanged → restored
        auto gen_before = deadline_cb_generation_;
        auto cb = std::move(deadline_timeout_cb_);
        bool result = cb();
        if (deadline_cb_generation_ == gen_before && !deadline_timeout_cb_) {
            deadline_timeout_cb_ = std::move(cb);
        }
        return result;
    }
    return false;
}

void ConnectionHandler::SetDeadline(std::chrono::steady_clock::time_point deadline) {
    if (event_dispatcher_ && event_dispatcher_->is_on_loop_thread()) {
        // On the dispatcher thread — direct write (no race with IsTimeOut/TimerHandler).
        has_deadline_ = true;
        deadline_ = deadline;
        deadline_generation_.fetch_add(1, std::memory_order_relaxed);
    } else {
        // Off-thread (e.g., acceptor thread in HandleNewConnection).
        // Route through EnQueue so has_deadline_/deadline_ are only written from the
        // dispatcher thread, avoiding a data race with IsTimeOut on the timer thread.
        // Capture the current generation — only apply if no on-thread deadline
        // activity (set or clear) has occurred since queuing. This prevents a
        // stale accept-time deadline from being resurrected after ClearDeadline.
        unsigned gen = deadline_generation_.load(std::memory_order_relaxed);
        std::weak_ptr<ConnectionHandler> weak_self = shared_from_this();
        event_dispatcher_->EnQueue([weak_self, deadline, gen]() {
            if (auto self = weak_self.lock()) {
                if (self->deadline_generation_.load(std::memory_order_relaxed) == gen) {
                    self->has_deadline_ = true;
                    self->deadline_ = deadline;
                    self->deadline_generation_.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }
}

void ConnectionHandler::ClearDeadline() {
    // ClearDeadline is only called from OnRawData/CloseConnection (on dispatcher thread),
    // so no off-thread routing is needed.
    has_deadline_ = false;
    deadline_generation_.fetch_add(1, std::memory_order_relaxed);
}

bool ConnectionHandler::IsTimeOut(std::chrono::seconds duration) const {
    // Fully closed — don't re-trigger
    if (is_closing_.load(std::memory_order_acquire)) {
        return false;
    }
    // Check request deadline first (Slowloris protection)
    if (has_deadline_ && std::chrono::steady_clock::now() > deadline_) {
        return true;
    }
    // If a protocol-specific deadline is active but not yet expired, skip
    // the idle timeout — the deadline governs this connection's lifetime
    // (e.g., HTTP 30s close-drain, WS 5s close-handshake). Without this,
    // a shorter idle timeout would force-close healthy drain/handshake
    // phases, causing truncated HTTP responses or spurious WS 1006 closures.
    if (has_deadline_) return false;
    // duration == 0 means idle timeout is disabled
    if (duration.count() == 0) return false;
    return ts_.IsTimeOut(duration);
}