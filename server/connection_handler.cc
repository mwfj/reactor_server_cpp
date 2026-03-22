#include "connection_handler.h"
#include "channel.h"
#include "tls/tls_connection.h"

ConnectionHandler::ConnectionHandler(std::shared_ptr<Dispatcher> _dispatcher, std::unique_ptr<SocketHandler> _sock)
    : event_dispatcher_(_dispatcher), sock_(std::move(_sock))
{
    client_channel_ = std::shared_ptr<Channel>(new Channel(event_dispatcher_, sock_ -> fd()));
    // Note: Cannot call shared_from_this() in constructor
    // Callbacks registered in RegisterCallbacks() after shared_ptr is created
}

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


void ConnectionHandler::OnMessage(){
    if(client_channel_ -> is_channel_closed()){
        return;
    }

    // TLS handshake phase
    if (tls_state_ == TlsState::HANDSHAKE) {
        int result = tls_->DoHandshake();
        if (result == 0) {
            tls_state_ = TlsState::READY;
            // Handshake complete, fall through to read any buffered data
        } else if (result == 1) {
            // Want read — already enabled
            return;
        } else if (result == 2) {
            // Want write
            client_channel_->EnableWriteMode();
            return;
        } else {
            // Handshake failed — use CallCloseCb for proper cleanup
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
        // If SSL still needs read readiness, keep read mode (already enabled)
        if (tls_write_wants_read_) {
            return;
        }
        // Otherwise fall through to read loop
    }

    bool peer_closed = false;  // Track if we saw EOF, close after dispatching buffered data
    char buffer[MAX_BUFFER_SIZE];
    while(true){
        memset(buffer, 0, sizeof buffer);
        ssize_t nread;

        if (tls_state_ == TlsState::READY) {
            nread = tls_->Read(buffer, sizeof buffer);
            if (nread == 0) {
                // WANT_READ — wait for more data (already in read mode)
                break;
            }
            if (nread == -3) {
                // WANT_WRITE — SSL needs write readiness to complete this read
                // (renegotiation/key update). Set flag so CallWriteCb retries the read.
                tls_read_wants_write_ = true;
                client_channel_->EnableWriteMode();
                break;
            }
            if (nread == -2) {
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
                CallCloseCb();
                return;
            }
            if((errno == EAGAIN) || (errno == EWOULDBLOCK)){
                break;
            }
            // Read error — use CallCloseCb for proper server map cleanup
            CallCloseCb();
            return;
        } else {
            break;  // nread == 0 for TLS means would_block, already handled
        }
    }

    // After reading all available data, call the application callback if data was received
    if(input_bf_.Size() > 0 && callbacks_.on_message_callback){
        std::string message(input_bf_.Data(), input_bf_.Size());
        callbacks_.on_message_callback(shared_from_this(), message);
        // Update timestamp
        ts_ = TimeStamp::Now();
        // Clear the input buffer after processing
        input_bf_.Clear();
    }

    // If peer sent EOF, defer close until any pending response is flushed.
    // CloseAfterWrite handles both cases:
    //   - Buffer has data → EnableWriteMode → CallWriteCb flushes then closes
    //   - Buffer empty → ForceClose immediately (avoids ET stall)
    if (peer_closed) {
        CloseAfterWrite();
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

    // Prepend the 4-byte length header, then attempt direct send.

    // This avoids the edge-triggered EPOLLOUT issue where a freshly writable
    // socket won't generate a new event when EPOLLOUT is first registered.
    output_bf_.AppendWithHead(data, size);

    if (output_bf_.Size() > 0) {
        ssize_t written;
        if (tls_state_ == TlsState::READY) {
            written = tls_->Write(output_bf_.Data(), output_bf_.Size());
            if (written == 0) {
                written = -1;
                errno = EAGAIN;
            } else if (written == -3) {
                tls_write_wants_read_ = true;
                client_channel_->EnableReadMode();
                written = -1;
                errno = EAGAIN;
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
                if (output_bf_.Size() == 0) {
                    // All sent — fire completion callback
                    if (callbacks_.complete_callback)
                        callbacks_.complete_callback(shared_from_this());
                    return;
                }
            } else if (written < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
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
    // Same as DoSend but uses Append() instead of AppendWithHead()
    // No 4-byte length prefix -- HTTP uses its own framing
    if (is_closing_) return;

    // If output buffer is empty, try sending directly first.
    // This avoids the edge-triggered EPOLLOUT issue where a freshly writable
    // socket won't generate a new event when EPOLLOUT is first registered.
    if (output_bf_.Size() == 0 && tls_state_ != TlsState::HANDSHAKE) {
        ssize_t written;
        if (tls_state_ == TlsState::READY) {
            written = tls_->Write(data, size);
            if (written == 0) {
                written = -1;
                errno = EAGAIN;
            } else if (written == -3) {
                tls_write_wants_read_ = true;
                client_channel_->EnableReadMode();
                written = -1;
                errno = EAGAIN;
            }
        } else {
            // No TLS — raw send
            written = ::send(fd(), data, size, SEND_FLAGS);
        }
        if (written > 0) {
            ts_ = TimeStamp::Now();
            if (static_cast<size_t>(written) == size) {
                // All sent — fire completion callback
                if (callbacks_.complete_callback)
                    callbacks_.complete_callback(shared_from_this());
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
    if (output_bf_.Size() == 0) {
        ForceClose();
    } else {
        client_channel_ -> EnableWriteMode();
    }
}

void ConnectionHandler::ForceClose(){
    // Skip the close_after_write defer — used when a deferred close stalls
    // and the timer needs to reclaim the connection.
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

    // If a previous SSL_read returned WANT_WRITE, the next writable event
    // must retry that read instead of doing a normal write.
    // After the retry, fall through to the normal write path to flush any
    // pending output — ET mode won't fire another EPOLLOUT for already-writable.
    if (tls_read_wants_write_) {
        tls_read_wants_write_ = false;
        OnMessage();  // Retry the pending read
        // If SSL still needs write readiness (flag re-armed by OnMessage),
        // keep write mode enabled — don't fall through to disable it.
        if (tls_read_wants_write_) {
            return;  // Will get another EPOLLOUT
        }
        // Otherwise fall through to write path
    }

    // TLS handshake WANT_WRITE handling
    if (tls_state_ == TlsState::HANDSHAKE) {
        int result = tls_->DoHandshake();
        if (result == 0) {
            tls_state_ = TlsState::READY;
            // Fall through to normal write logic to flush any pending output buffer
        } else if (result == 1) {
            client_channel_->DisableWriteMode();
            // Want read — read mode already enabled
            return;
        } else if (result == 2) {
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
        write_sz = tls_->Write(output_bf_.Data(), output_bf_.Size());
        if (write_sz == 0) return;  // WANT_WRITE — try again on next EPOLLOUT
        if (write_sz == -3) {
            // WANT_READ — SSL needs read readiness to complete this write
            // (renegotiation/key update). Set flag so OnMessage retries the write.
            tls_write_wants_read_ = true;
            client_channel_->EnableReadMode();
            return;
        }
        if (write_sz < 0) {
            // TLS write error — ForceClose bypasses close_after_write defer
            ForceClose();
            return;
        }
    } else {
        write_sz = ::send(fd(), output_bf_.Data(), output_bf_.Size(), SEND_FLAGS);
        if (write_sz < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            // Send failed (EPIPE, ECONNRESET, etc.) — ForceClose bypasses defer
            ForceClose();
            return;
        }
    }

    // Remove sent data and refresh idle timestamp
    if(write_sz > 0) {
        output_bf_.Erase(0, write_sz);
        ts_ = TimeStamp::Now();  // Refresh idle timeout on successful write
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
    }
}

void ConnectionHandler::SetOnMessageCb(CALLBACKS_NAMESPACE::ConnOnMsgCallback fn){
    callbacks_.on_message_callback = std::move(fn);
}

void ConnectionHandler::SetCompletionCb(CALLBACKS_NAMESPACE::ConnCompleteCallback fn){
    callbacks_.complete_callback = std::move(fn);
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

void ConnectionHandler::SetDeadlineTimeoutCb(DeadlineTimeoutCb cb) {
    deadline_timeout_cb_ = std::move(cb);
}

void ConnectionHandler::CallDeadlineTimeoutCb() {
    if (deadline_timeout_cb_) {
        deadline_timeout_cb_();
    }
}

void ConnectionHandler::SetDeadline(std::chrono::steady_clock::time_point deadline) {
    has_deadline_ = true;
    deadline_ = deadline;
}

void ConnectionHandler::ClearDeadline() {
    has_deadline_ = false;
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
    // duration == 0 means idle timeout is disabled
    if (duration.count() == 0) return false;
    return ts_.IsTimeOut(duration);
}