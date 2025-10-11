#pragma once

#include "common.h"
#include "inet_addr.h"
#include "epoll_handler.h"
#include "connection_handler.h"
#include <functional>
#include <memory>

class Channel{
public:
    Channel() = delete;
    Channel(std::shared_ptr<EpollHandler> _ep, int _fd);
    ~Channel();

    const int fd() const { return fd_; }
    // enable ET (Edge-Triggered) mode
    void EnableETMode(){
        if(is_channel_closed_) return;
        event_ |= EPOLLET;
    }
    void EnableReadMode(){
        if(is_channel_closed_) return;
        event_ |= EPOLLIN;
        auto ep_shared = ep_.lock();
        if(ep_shared)
            ep_shared->UpdateChannel(this);
    }

    uint32_t Event() const {return event_;}
    uint32_t dEvent() const {return devent_;}
    bool is_epoll_in() const {return is_epoll_in_;}
    void SetEpollIn() {
        is_epoll_in_ = true;
    }
    void SetEvent(uint32_t ev){
        event_ = ev;
    }
    void SetDEvent(uint32_t ev){
        devent_ = ev;
    }

    void HandleEvent();

    void NewConnection(ConnectionHandler&);
    void OnMessage();
    void SetReadCallBackFn(std::function<void()>);
    void CloseChannel();
    bool is_channel_closed() const { return is_channel_closed_; }
private:
    int fd_ = -1;
    /**
     * Non-owning reference to EpollHandler.
     * Uses weak_ptr for type safety and to detect if EpollHandler is destroyed.
     * The EpollHandler is owned by NetworkServer and Channel just needs to reference it. 
     */
    std::weak_ptr<EpollHandler> ep_;
    // to mark whether the channel has been put in the epoll tree
    bool is_epoll_in_ = false;
    // the event that fd_ need to monitoring
    uint32_t event_ = 0;
    // the event that already finished 
    uint32_t devent_ = 0;
    // read callback
    std::function<void()> read_fn_;
    bool is_channel_closed_ = false;
};
