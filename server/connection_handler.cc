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
            // Handshake failed
            if(client_channel_ && !client_channel_->is_channel_closed()){
                client_channel_->CloseChannel();
            }
            return;
        }
    }

    char buffer[MAX_BUFFER_SIZE];
    while(true){
        memset(buffer, 0, sizeof buffer);
        ssize_t nread;

        if (tls_state_ == TlsState::READY) {
            nread = tls_->Read(buffer, sizeof buffer);
            if (nread == 0) {
                // Would block (WANT_READ/WANT_WRITE)
                break;
            }
            if (nread == -2) {
                // Peer closed TLS connection cleanly (close_notify)
                if(client_channel_ && !client_channel_->is_channel_closed()){
                    client_channel_->CloseChannel();
                }
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
            // Client close (raw TCP only; TLS nread==0 means would_block above)
           if(client_channel_ && !client_channel_->is_channel_closed()){
               client_channel_->CloseChannel();
           }
           break;
        } else if (nread < 0) {
            if (tls_state_ == TlsState::READY) {
                // TLS read error — close
                if(client_channel_ && !client_channel_->is_channel_closed()){
                    client_channel_->CloseChannel();
                }
                break;
            }
            if((errno == EAGAIN) || (errno == EWOULDBLOCK)){
                break;
            }
            // Read error - close the channel, which will trigger the close callback
            if(client_channel_ && !client_channel_->is_channel_closed()){
                client_channel_->CloseChannel();
            }
            break;
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
}

void ConnectionHandler::SendData(const char *data, size_t size){
    // Thread-safe: All buffer operations must happen in socket dispatcher thread
    // Copy data immediately to avoid dangling pointer
    std::string data_copy(data, size);

    if(event_dispatcher_ && !event_dispatcher_ -> is_sock_dispatcher()) {
        // Capture data_copy by value to preserve across thread boundary
        event_dispatcher_ -> EnQueue([this, data_copy]() {
            this->DoSend(data_copy.data(), data_copy.size());
        });
    } else {
        // Already in socket dispatcher thread
        DoSend(data, size);
    }
}

void ConnectionHandler::DoSend(const char *data, size_t size){
    // All buffer operations happen in socket dispatcher thread (thread-safe)
    output_bf_.AppendWithHead(data, size);
    client_channel_ -> EnableWriteMode();
}

void ConnectionHandler::SendRaw(const char *data, size_t size){
    // Thread-safe: same pattern as SendData()
    std::string data_copy(data, size);

    if(event_dispatcher_ && !event_dispatcher_ -> is_sock_dispatcher()) {
        event_dispatcher_ -> EnQueue([this, data_copy]() {
            this->DoSendRaw(data_copy.data(), data_copy.size());
        });
    } else {
        DoSendRaw(data, size);
    }
}

void ConnectionHandler::DoSendRaw(const char *data, size_t size){
    // Same as DoSend but uses Append() instead of AppendWithHead()
    // No 4-byte length prefix -- HTTP uses its own framing
    if (is_closing_) return;

    // If output buffer is empty, try sending directly first.
    // This avoids the edge-triggered EPOLLOUT issue where a freshly writable
    // socket won't generate a new event when EPOLLOUT is first registered.
    if (output_bf_.Size() == 0) {
        ssize_t written;
        if (tls_state_ == TlsState::READY) {
            written = tls_->Write(data, size);
            if (written == 0) {
                // Would block -- fall through to buffering
                written = -1;
                errno = EAGAIN;
            }
        } else {
            written = ::send(fd(), data, size, MSG_NOSIGNAL);
        }
        if (written > 0) {
            if (static_cast<size_t>(written) == size) {
                // All data sent immediately, no need to buffer
                return;
            }
            // Partial write -- buffer the remainder
            data += written;
            size -= written;
        } else if (written < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            // Send error
            return;
        }
        // written == 0 or EAGAIN -- fall through to buffering
    }

    output_bf_.Append(data, size);
    client_channel_ -> EnableWriteMode();
}

void ConnectionHandler::CallCloseCb(){
    // Prevent duplicate close callbacks with atomic compare-exchange
    bool expected = false;
    if (!is_closing_.compare_exchange_strong(expected, true)) {
        // Already closing, return immediately to prevent duplicate callbacks
        return;
    }

    // IMPORTANT: Capture shared_ptr to self to keep this alive during callback
    std::shared_ptr<ConnectionHandler> self = shared_from_this();

    // Close the channel to clean up fd and remove from epoll
    // CloseChannel() will NOT call this callback again (no recursion)
    if(client_channel_ && !client_channel_->is_channel_closed()){
        client_channel_->CloseChannel();
    }

    // Call the application callback
    if (callbacks_.close_callback)
        callbacks_.close_callback(self);
}

void ConnectionHandler::CallErroCb(){
    if (callbacks_.error_callback)
        callbacks_.error_callback(shared_from_this());
}

void ConnectionHandler::CallWriteCb(){
    // Check if channel is closed or write mode disabled (can happen during shutdown)
    if(!client_channel_ || client_channel_->is_channel_closed() || !client_channel_->isEnableWriteMode()) {
        return; // Silently ignore - channel is closing or already closed
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
            // Handshake error — close the channel (same as read-path error handling)
            if(client_channel_ && !client_channel_->is_channel_closed()){
                client_channel_->CloseChannel();
            }
            return;
        }
    }

    int write_sz;
    if (tls_state_ == TlsState::READY) {
        write_sz = tls_->Write(output_bf_.Data(), output_bf_.Size());
        if (write_sz == 0) return;  // Would block, try again later
        if (write_sz < 0) {
            // TLS write error
            if(client_channel_ && !client_channel_->is_channel_closed()){
                client_channel_->CloseChannel();
            }
            return;
        }
    } else {
        write_sz = ::send(fd(), output_bf_.Data(), output_bf_.Size(), 0);
    }

    // Remove sent data
    if(write_sz > 0)
        output_bf_.Erase(0, write_sz);

    // If there's no data waiting to write, then unregister writing event
    if(output_bf_.Size() == 0){
        client_channel_->DisableWriteMode();
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

bool ConnectionHandler::IsTimeOut(std::chrono::seconds duration) const {
    return ts_.IsTimeOut(duration);
}