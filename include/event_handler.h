#pragma once
#include "common.h"
#include "epoll_handler.h"
#include "kqueue_handler.h"

// Forward declaration to break circular dependency
class Channel;

/**
 * @brief This is the wrapping class that encapsulate 
 * the I/O multiplexing system level library (kqueue or epoll)
 * 
 * Channel will call this class to get I/O multiplexing related feature
 * and event_handler will handle the cross-platfrom detail
 */
class EventHandler{
private:
#if defined(__linux__)
    std::unique_ptr<EpollHandler> epoll_event_ = nullptr;
#elif defined(__APPLE__) || defined(__MACH__)
    std::unique_ptr<KqueueHandler> kqueue_event_ = nullptr;
#endif
public:
    EventHandler();
    ~EventHandler() = default;
    void UpdateEvent(std::shared_ptr<Channel>);
    void RemoveChannel(std::shared_ptr<Channel>);  // Remove channel from epoll/kqueue
    std::vector<std::shared_ptr<Channel>> WaitForEvent(int);

    // Timer support — used by Dispatcher on macOS (EVFILT_TIMER).
    // On Linux these are no-ops because the timer is a timerfd Channel.
    void RegisterTimer(int interval_sec);
    void ResetTimer(int interval_sec);
    bool ConsumeTimerFired();
};
