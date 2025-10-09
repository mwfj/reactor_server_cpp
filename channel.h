#pragma once

#include "common.h"
#include "inet_addr.h"
#include "epoll_handler.h"
#include <functional>

class Channel{
public:
    Channel() = default;
    Channel(std::shared_ptr<EpollHandler> _ep, int _fd);
    ~Channel();

    const int fd() const { return fd_; }
    // enable LT mode
    void EnableLTMode(){
        event_ |= EPOLLET;
    }
    void EnableReadMode(){
        event_ |= EPOLLIN;
        if(ep_)
            ep_->UpdateChannel(this);
    }
private:
    int fd_ = -1;
    // the corresponding red-black tree strcuture in epoll,
    std::shared_ptr<EpollHandler> ep_ = nullptr;
    // to mark whether the channel has been put in the epoll tree
    bool is_epoll_in_ = false;
    // the event that fd_ need to monitoring
    uint32_t event_ = 0;
    // the event that already finished 
    uint32_t devent_ = 0;
    // read callback
    std::function<void()> read_fn_;
};