#pragma once
#include "common.h"
#include "dispatcher.h"
#include "socket_handler.h"
#include "buffer.h"

class ConnectionHandler : public std::enable_shared_from_this<ConnectionHandler>
{
private:
    std::shared_ptr<Dispatcher> event_dispatcher_;
    std::unique_ptr<SocketHandler> sock_;  // Sole owner of client socket
    std::shared_ptr<Channel> client_channel_;

    std::function<void(std::shared_ptr<ConnectionHandler>, std::string&)> on_message_callback_;
    std::function<void(std::shared_ptr<ConnectionHandler>)> completion_callback_;
    std::function<void(std::shared_ptr<ConnectionHandler>)> close_callback_;
    std::function<void(std::shared_ptr<ConnectionHandler>)> error_callback_;

    Buffer input_bf_;
    Buffer output_bf_;
public:
    ConnectionHandler() = delete;
    ConnectionHandler(std::shared_ptr<Dispatcher>, std::unique_ptr<SocketHandler>);
    ~ConnectionHandler() = default; // no need the release resource for smart pointer

    int fd() const{ return sock_ -> fd(); }
    const std::string& ip_addr() const { return sock_ -> ip_addr(); }
    int port() const { return sock_ -> port(); }

    void OnMessage();

    void SendData(const char*, size_t);
    
    void CallCloseCb();
    void CallErroCb();
    void CallWriteCb();

    void SetOnMessageCb(std::function<void(std::shared_ptr<ConnectionHandler>, std::string&)>);
    void SetCompletionCb(std::function<void(std::shared_ptr<ConnectionHandler>)>);
    void SetCloseCb(std::function<void(std::shared_ptr<ConnectionHandler>)>);
    void SetErrorCb(std::function<void(std::shared_ptr<ConnectionHandler>)>);
};
