#pragma once
#include "common.h"
#include <vector>

// Forward declaration to break circular dependency
class Channel;

class EpollHandler{
public:
    EpollHandler();
    ~EpollHandler();
    void UpdateEvent(std::shared_ptr<Channel>);
    std::vector<std::shared_ptr<Channel>> WaitForEvent(int);

    // Store channel ownership
    void AddToReadyEvent(std::shared_ptr<Channel> ch);
    void RemoveFromReadyEvent(int fd);
private:
    static const int MaxEpollEvents = 1000; // Max events to process per epoll_wait call
    int epollfd_ = -1;
    epoll_event events_[MaxEpollEvents];
    std::map<int, std::shared_ptr<Channel>> channel_map_; // Store channel ownership
};
