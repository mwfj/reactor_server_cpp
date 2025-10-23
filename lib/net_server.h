#pragma once
#include "common.h"
#include "socket_handler.h"
#include "inet_addr.h"
#include "epoll_handler.h"
#include "channel.h"
#include "dispatcher.h"
#include "connection_handler.h"
#include "acceptor.h"

class NetServer {
private:
    // Owner (shared with components for coordination)
    // TODO: One server can have multiple dispatcher for multi-threads design
    std::shared_ptr<Dispatcher> event_dispatcher_; 
    std::map<int, std::shared_ptr<ConnectionHandler>> connections_;
    std::unique_ptr<Acceptor> acceptor_;  // Sole owner of Acceptor

    // Callbacks
    std::function<void(std::shared_ptr<ConnectionHandler>)>  new_conn_callback_ = nullptr;
    std::function<void(std::shared_ptr<ConnectionHandler>)>  close_conn_callback_ = nullptr;
    std::function<void(std::shared_ptr<ConnectionHandler>)>  error_callback_ = nullptr;

    std::function<void(std::shared_ptr<ConnectionHandler>, std::string&)>  on_message_callback_ = nullptr;
    std::function<void(std::shared_ptr<ConnectionHandler>)>  send_complete_callback_ = nullptr;
public:
    NetServer() = delete;
    NetServer(const std::string& _ip, const size_t _port);
    ~NetServer(); 

    void Start();
    void Stop();

    void HandleNewConnction(std::unique_ptr<SocketHandler>);
    void CloseConnection(std::shared_ptr<ConnectionHandler>);
    void ErrorConnection(std::shared_ptr<ConnectionHandler>);
    void OnMessage(std::shared_ptr<ConnectionHandler>, std::string&);
    void SendComplete(std::shared_ptr<ConnectionHandler>);

    void SetNewConnectionCb(std::function<void(std::shared_ptr<ConnectionHandler>)> fn);
    void SetCloseConnectionCb(std::function<void(std::shared_ptr<ConnectionHandler>)> fn);
    void SetErrorCb(std::function<void(std::shared_ptr<ConnectionHandler>)> fn);
    void SetOnMessageCb(std::function<void(std::shared_ptr<ConnectionHandler>, std::string&)> fn);
    void SetSendCompletionCb(std::function<void(std::shared_ptr<ConnectionHandler>)> fn);
};