#pragma once
#include "common.h"
#include "connection_handler.h"
#include "inet_addr.h"
#include "epoll_handler.h"
#include "channel.h"
#include <memory>

class NetworkServer {
private:
    std::string ip_addr_;
    int port_;
    bool is_running_ = false;
    std::unique_ptr<ConnectionHandler> listen_conn_;
    std::shared_ptr<Channel> serv_ch_;  // Changed to shared_ptr so it can be added to EpollHandler map
    std::vector<std::shared_ptr<Channel>> channels_;
    std::shared_ptr<EpollHandler> ep_;  // Changed to shared_ptr so Channel can hold weak_ptr
    void set_running_state(bool);
public:
    NetworkServer() = delete;
    NetworkServer(const std::string& _ip, int _port);
    ~NetworkServer() = default;  // Smart pointers automatically clean up
    void Start();
    void Stop();
    void Run();
    bool is_running() const {return is_running_;}
};