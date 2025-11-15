#pragma once
#include "common.h"
#include "epoll_handler.h"
#include "kqueue_handler.h"
/**
 * @brief This is the wrapping class that encapsulate 
 * the I/O multiplexing system level library (kqueue or epoll)
 * 
 * Channel will call this class to get I/O multiplexing related feature
 * and event_handler will handle the cross-platfrom detail
 */

class EventHandler{
private:
#ifdef defined(__linux__)
    std::unique_ptr<EpollHandler> epoll_event_;
#elif defined(__APPLE__) || defined(__MACH__)
    std::unique_ptr<KqueueHandler> kqueue_event_;
#endif
public:
    const int fd() const;
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
};