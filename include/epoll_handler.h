#pragma once
#if defined(__linux__)

#include "common.h"

// Forward declaration to break circular dependency
class Channel;

// For Linux Epoll
class EpollHandler{
public:
    EpollHandler();
    ~EpollHandler();
    void UpdateEvent(std::shared_ptr<Channel>);
    void RemoveChannel(std::shared_ptr<Channel>);  // Remove channel from epoll
    std::vector<std::shared_ptr<Channel>> WaitForEvent(int);

private:
    int epollfd_ = -1;
    epoll_event events_[MAX_EVETN_NUMS];
    std::map<int, std::shared_ptr<Channel>> channel_map_; // Store channel ownership
    std::mutex channel_map_mutex_; // Protect concurrent access to channel_map_
};

#endif
