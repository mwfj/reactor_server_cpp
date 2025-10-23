#pragma once
#include "common.h"
#include "epoll_handler.h"

// Forward declaration to break circular dependency
class Channel;

class Dispatcher{
private:
    bool is_running_ = false;
    std::unique_ptr<EpollHandler> ep_;  // Sole owner of EpollHandler
    void set_running_state(bool);
public:
    Dispatcher();
    ~Dispatcher() = default;  // Smart pointers automatically clean up

    void RunEventLoop();
    void StopEventLoop();
    bool is_running() const {return is_running_;}

    void UpdateChannel(std::shared_ptr<Channel>);
    void RemoveChannel(std::shared_ptr<Channel>);
};