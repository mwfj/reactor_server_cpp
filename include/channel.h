#pragma once

#include "common.h"
#include "inet_addr.h"
#include "epoll_handler.h"
#include "socket_handler.h"
#include "dispatcher.h"

class Channel : public std::enable_shared_from_this<Channel> {
private:
    int fd_ = -1;
    /**
     * Non-owning reference to Epoll loop.
     * Uses weak_ptr for type safety and to detect if Dispatcher is destroyed.
     * The Dispatcher is owned by NetServer and Channel just needs to reference it. 
     */
    std::weak_ptr<Dispatcher> event_dispatcher_;
    // to mark whether the channel has been put in the epoll tree
    bool is_read_event_ = false;
    // the event that fd_ need to monitoring
    uint32_t event_ = 0;
    // the event that already finished
    uint32_t devent_ = 0;

    std::atomic<bool> is_channel_closed_{false};

    // Read callback
    // - Callback Acceptor::NewConnection if is the acceptor channel
    // - Callback Channel::OnMessage if is the client channel
    std::function<void()>   read_fn_;
    std::function<void()>   write_fn_;
    std::function<void()>   close_fn_;
    std::function<void()>   error_fn_;
public:
    Channel() = delete;
    Channel(std::shared_ptr<Dispatcher> _ep, int _fd);
    ~Channel();

    const int fd() const { return fd_; }
    // Set ET (Edge-Triggered) mode
    void EnableETMode();
    void DisableETMode();
    bool isEnableETMode() const;

    void EnableReadMode();
    void DisableReadMode();
    bool isEnableReadMode() const;

    void EnableWriteMode();
    void DisableWriteMode();
    bool isEnableWriteMode() const;

    uint32_t Event() const {return event_;}
    uint32_t dEvent() const {return devent_;}
    bool is_read_event() const {return is_read_event_;}
    void SetEventRead() {
        is_read_event_ = true;
    }
    bool is_channel_closed() const { return is_channel_closed_.load(); }
    void SetEvent(uint32_t ev){
        event_ = ev;
    }
    void SetDEvent(uint32_t ev){
        devent_ = ev;
    }

    void HandleEvent();

    void CloseChannel();

    void SetReadCallBackFn(std::function<void()>);
    void SetWriteCallBackFn(std::function<void()>);
    void SetCloseCallBackFn(std::function<void()>);
    void SetErrorCallBackFn(std::function<void()>);
};
