#include "connection_handler.h"
#include "channel.h"

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

    char buffer[MAX_BUFFER_SIZE];
    while(true){
        memset(buffer, 0, sizeof buffer);
        ssize_t nread = ::read(fd(), buffer, sizeof buffer);

        if(nread > 0){
            input_bf_.Append(buffer, nread);
            if(errno == EINTR){ // Interruptted by signal
                continue;
            }
        } else if(nread == 0){ // Client close the connection
           // Close the channel, which will trigger the close callback
           if(client_channel_ && !client_channel_->is_channel_closed()){
               client_channel_->CloseChannel();
           }
           break;
        } else{ // The incoming data is finished reading
            if((errno == EAGAIN) || (errno == EWOULDBLOCK)){
                break;
            }
            // Read error - close the channel, which will trigger the close callback
            if(client_channel_ && !client_channel_->is_channel_closed()){
                client_channel_->CloseChannel();
            }
            break;
        }
    }

    // After reading all available data, call the application callback if data was received
    if(input_bf_.Size() > 0 && on_message_callback_){
        std::string message(input_bf_.Data(), input_bf_.Size());
        on_message_callback_(shared_from_this(), message);
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

void ConnectionHandler::SetOnMessageCb(std::function<void(std::shared_ptr<ConnectionHandler>, std::string&)> fn){
    on_message_callback_ = fn;
}

void ConnectionHandler::SetCompletionCb(std::function<void(std::shared_ptr<ConnectionHandler>)> fn){
    completion_callback_ = fn;
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
    if (close_callback_)
        close_callback_(self);
}

void ConnectionHandler::CallErroCb(){
    if (error_callback_)
        error_callback_(shared_from_this());
}

void ConnectionHandler::CallWriteCb(){
    // Check if channel is closed or write mode disabled (can happen during shutdown)
    if(!client_channel_ || client_channel_->is_channel_closed() || !client_channel_->isEnableWriteMode()) {
        return; // Silently ignore - channel is closing or already closed
    }

    int write_sz = ::send(fd(), output_bf_.Data(), output_bf_.Size(), 0);
    // Remove sent data
    if(write_sz > 0)
        output_bf_.Erase(0, write_sz);

    // If there's no data waiting to write, then unregister writing event
    if(output_bf_.Size() == 0){
        client_channel_->DisableWriteMode();
        if(completion_callback_)
            completion_callback_(shared_from_this());
    }
}

void ConnectionHandler::SetCloseCb(std::function<void(std::shared_ptr<ConnectionHandler>)> fn){
    close_callback_ = fn;
}

void ConnectionHandler::SetErrorCb(std::function<void(std::shared_ptr<ConnectionHandler>)> fn){
    error_callback_ = fn;
}
