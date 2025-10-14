#include "connection_handler.h"
#include "channel.h"

ConnectionHandler::ConnectionHandler(std::shared_ptr<Dispatcher> _dispatcher, std::unique_ptr<SocketHandler> _sock)
    : event_dispatcher_(_dispatcher), sock_(std::move(_sock))
{
    client_channel_ = std::shared_ptr<Channel>(new Channel(event_dispatcher_, sock_ -> fd()));

    client_channel_ -> SetReadCallBackFn(std::bind(&Channel::OnMessage, client_channel_));
    client_channel_ -> SetCloseCallBackFn(std::bind(&ConnectionHandler::CallCloseCb, this));
    client_channel_ -> SetErrorCallBackFn(std::bind(&ConnectionHandler::CallErroCb, this));
    client_channel_ -> EnableETMode();
    client_channel_ -> EnableReadMode(client_channel_);
}

void ConnectionHandler::CallCloseCb(){
    if (!close_callback_) return;
    close_callback_(shared_from_this());
}

void ConnectionHandler::CallErroCb(){
    if (!error_callback_) return;
    error_callback_(shared_from_this());
}

void ConnectionHandler::SetCloseCb(std::function<void(std::shared_ptr<ConnectionHandler>)> fn){
    close_callback_ = fn;
}

void ConnectionHandler::SetErrorCb(std::function<void(std::shared_ptr<ConnectionHandler>)> fn){
    error_callback_ = fn;
}
