#pragma once
#include "common.h"
#include "channel.h"

// typedef struct {
// #ifdef __linux__
//     struct epoll_event ev;
// #elif defined(__APPLE__) || defined(__FreeBSD__)
//     struct kevent ev;
// #elif defined(_WIN32)
//     WSAEVENT ev;
// #endif
// } gen_epoll_evts;

class EpollHandler{
public:
    EpollHandler();
    ~EpollHandler();
    void UpdateChannel(std::unique_ptr<Channel>);
private:
    static const int MaxEpollEvents = 1000; // Max events to process per epoll_wait call
    int epollfd_ = -1;
    // gen_epoll_evts events[MaxEpollEvents];
    epoll_event events[MaxEpollEvents];
    std::vector<std::unique_ptr<Channel>> channels_;
};