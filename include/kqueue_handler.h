#pragma once
#if defined(__APPLE__) || defined(__MACH__)

#include "common.h"

// Forward declaration to break circular dependency
class Channel;

// For macOS/BSD Kqueue
class KqueueHandler{
public:
    // Well-known ident for the dispatcher timer. Set to UINTPTR_MAX so it
    // can never collide with a real fd (fds are always non-negative ints).
    static constexpr uintptr_t KQUEUE_TIMER_IDENT = static_cast<uintptr_t>(-1);

    KqueueHandler();
    ~KqueueHandler();
    void UpdateEvent(std::shared_ptr<Channel>);
    void RemoveChannel(std::shared_ptr<Channel>);  // Remove channel from kqueue
    std::vector<std::shared_ptr<Channel>> WaitForEvent(int);

    // EVFILT_TIMER support — replaces the timerfd that macOS lacks.
    // RegisterTimer/ResetTimer are called only from the dispatcher's own
    // event-loop thread, so no mutex is needed for timer_fired_.
    void RegisterTimer(int interval_sec);
    void ResetTimer(int interval_sec);
    bool ConsumeTimerFired();

private:
    int kqueuefd_ = -1;
    struct kevent events_[MAX_EVENT_NUMS];
    std::map<int, std::shared_ptr<Channel>> channel_map_; // Store channel ownership
    std::mutex channel_map_mutex_; // Protect concurrent access to channel_map_
    std::atomic<bool> timer_fired_{false};  // Set by WaitForEvent, consumed by dispatcher (same thread, atomic for defensive safety)
};

#endif
