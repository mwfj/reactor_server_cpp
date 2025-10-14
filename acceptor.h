#pragma once
#include "common.h"
#include "socket_handler.h"
#include "inet_addr.h"
#include "channel.h"
#include "dispatcher.h"

class Acceptor{
private:
    std::shared_ptr<Dispatcher> event_dispatcher_;
    std::unique_ptr<SocketHandler> servsock_;  // Sole owner of listening socket
    std::shared_ptr<Channel> acceptor_channel_;

    std::function<void(std::unique_ptr<SocketHandler>)> new_conn_cb_;
public:
    Acceptor() = delete;
    Acceptor(std::shared_ptr<Dispatcher>, const std::string&, const uint16_t);
    ~Acceptor() = default; // smart pointer will release the source

    void NewConnection(); // process the request from client

    void SetNewConnCb(std::function<void(std::unique_ptr<SocketHandler>)>);
};