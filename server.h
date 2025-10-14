#pragma once
#include "common.h"
#include "socket_handler.h"
#include "inet_addr.h"
#include "epoll_handler.h"
#include "channel.h"
#include "dispatcher.h"
#include "connection_handler.h"
#include "acceptor.h"

class ReactorServer {
private:
    std::shared_ptr<Dispatcher> event_dispatcher_;  // Owner (shared with components for coordination)

    std::map<int, std::shared_ptr<ConnectionHandler>> connections_;
    std::unique_ptr<Acceptor> acceptor_;  // Sole owner of Acceptor
public:
    ReactorServer() = delete;
    ReactorServer(const std::string& _ip, const size_t _port);
    ~ReactorServer(); 

    void Start();
    void Stop();

    void NewConnction(std::unique_ptr<SocketHandler>);

    void CloseConnection(std::shared_ptr<ConnectionHandler>);
    void ErrorConnection(std::shared_ptr<ConnectionHandler>);
};