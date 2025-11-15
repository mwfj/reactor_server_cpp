#pragma once
#if defined(__APPLE__) || defined(__MACH__)

#include "common.h"

// Forward declaration to break circular dependency
class Channel;

// For macOS/BSD Kqueue
class KqueueHandler{
public:
    KqueueHandler() = default;
    ~KqueueHandler() = default;
    void UpdateEvent(std::shared_ptr<Channel>);
    void RemoveChannel(std::shared_ptr<Channel>);  // Remove channel from kqueue
    std::vector<std::shared_ptr<Channel>> WaitForEvent(int);

private:
    int kqueuefd_ = -1;
    struct kevent events_[MAX_EVETN_NUMS];
    std::map<int, std::shared_ptr<Channel>> channel_map_; // Store channel ownership
    std::mutex channel_map_mutex_; // Protect concurrent access to channel_map_
};

#endif