#include "connection_handler.h"
#include "channel.h"

ConnectionHandler::ConnectionHandler(std::shared_ptr<Dispatcher> _dispatcher, std::unique_ptr<SocketHandler> _sock)
    : event_dispatcher_(_dispatcher), sock_(std::move(_sock))
{
    client_channel_ = std::shared_ptr<Channel>(new Channel(event_dispatcher_, sock_ -> fd()));

    client_channel_ -> SetReadCallBackFn(std::bind(&ConnectionHandler::OnMessage, this));
    client_channel_ -> SetCloseCallBackFn(std::bind(&ConnectionHandler::CallCloseCb, this));
    client_channel_ -> SetErrorCallBackFn(std::bind(&ConnectionHandler::CallErroCb, this));
    client_channel_ -> SetWriteCallBackFn(std::bind(&ConnectionHandler::CallWriteCb, this));

    client_channel_ -> EnableETMode();
    client_channel_ -> EnableReadMode();
}


void ConnectionHandler::OnMessage(){
    if(client_channel_ -> is_channel_closed())
        return;

    char buffer[MAX_BUFFER_SIZE];
    while(true){
        memset(buffer, 0, sizeof buffer);
        ssize_t nread = ::read(fd(), buffer, sizeof buffer);

        if(nread > 0){
            ssize_t total_written = 0;
            input_bf_.Append(buffer, nread);
            if(errno == EINTR){ // Interruptted by signal
                continue;
            }
        } else if(nread == 0){ // Client close the connection
           CallCloseCb(); 
           break;
        } else{ // The incoming data is finished reading
            if((errno == EAGAIN) || (errno == EWOULDBLOCK)){
                break;
            }
            CallCloseCb();
        }
    }
}

void ConnectionHandler::SendData(const char *data, size_t size){
    output_bf_.AppendWithHead(data, size);
    client_channel_ -> EnableWriteMode();
}

void ConnectionHandler::SetOnMessageCb(std::function<void(std::shared_ptr<ConnectionHandler>, std::string&)> fn){
    if(on_message_callback_)
        on_message_callback_ = fn;
}

void ConnectionHandler::SetCompletionCb(std::function<void(std::shared_ptr<ConnectionHandler>)> fn){
    if(completion_callback_)
        completion_callback_ = fn;
}

void ConnectionHandler::CallCloseCb(){
    if (close_callback_)
        close_callback_(shared_from_this());
}

void ConnectionHandler::CallErroCb(){
    if (error_callback_)
        error_callback_(shared_from_this());
}

void ConnectionHandler::CallWriteCb(){
    if(!client_channel_ -> isEnableWriteMode())
        throw std::runtime_error("Client Channel Not Enable the Write Mode");

    int write_sz = ::send(fd(), output_bf_.Data(), output_bf_.Size(), 0);
    // Remove sents data
    if(write_sz > 0)
        output_bf_.Erase(0, write_sz);

    // If there has no data waiting to write, then unregister writing event
    if(output_bf_.Size() == 0){
        client_channel_ -> DisableWriteMode();
        completion_callback_(shared_from_this());
    }
}

void ConnectionHandler::SetCloseCb(std::function<void(std::shared_ptr<ConnectionHandler>)> fn){
    close_callback_ = fn;
}

void ConnectionHandler::SetErrorCb(std::function<void(std::shared_ptr<ConnectionHandler>)> fn){
    error_callback_ = fn;
}
