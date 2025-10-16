#include "epoll_handler.h"
#include "channel.h"

EpollHandler::EpollHandler(){
    if((epollfd_ = ::epoll_create(1)) == -1){
        std::cout << "[Epoll Handler] epoll_create failed: " << strerror(errno) << std::endl;
        throw std::runtime_error("Epoll created failed");
    }
}

EpollHandler::~EpollHandler(){
    close(epollfd_);
}

/**
 * Store channel in map and register with epoll.
 * Linux epoll API requires raw void* pointer in epoll_event,
 * but we maintain ownership with smart pointers in channel_map_.
 */
void EpollHandler::UpdateEvent(std::shared_ptr<Channel> ch){
    epoll_event ev;
    ev.data.ptr = ch.get(); // Store raw pointer for epoll
    ev.events = ch->Event();

    if(ch->is_epoll_in()){
        if(::epoll_ctl(epollfd_, EPOLL_CTL_MOD, ch->fd(), &ev) == -1){
            std::cout << "[Epoll Handler] epoll_ctl MOD failed: " << strerror(errno) << std::endl;
            throw std::runtime_error("epoll_ctl MOD failed");
        }
    }else{
        if(::epoll_ctl(epollfd_, EPOLL_CTL_ADD, ch->fd(), &ev) == -1){
            std::cout << "[Epoll Handler] epoll_ctl ADD failed: " << strerror(errno) << std::endl;
            throw std::runtime_error("epoll_ctl ADD failed");
        }
        ch->SetEpollIn();
        // Store in map to maintain ownership
        channel_map_[ch->fd()] = ch;
    }
}

std::vector<std::shared_ptr<Channel>> EpollHandler::WaitForEvent(int timeout){
    std::vector<std::shared_ptr<Channel>> channels;
    // init event array
    memset(events_, 0, sizeof(events_));

    int infds = -1;


    infds = epoll_wait(epollfd_, events_, MaxEpollEvents, timeout);

    if(infds < 0){
        std::cout << "[Epoll Handler] epoll_wait() failed: " << strerror(errno) << std::endl;
        throw std::runtime_error("epoll_wait() failed");
    }

    // interruptted by other signal
    if(errno == EINTR){
        std::cout << "[Epoll Handler] epoll_wait() failed, iterruptted by other signal: " << strerror(errno) << std::endl;
        throw std::runtime_error("epoll_wait() iterruptted by other signal");
    }
    
    // timeout
    if(infds == 0){
        return channels;
    }

    for(int idx = 0; idx < infds; idx ++){
        Channel *ch_raw = (Channel*)events_[idx].data.ptr;
        ch_raw->SetDEvent(events_[idx].events);
        // Look up the channel from our map instead of creating a new shared_ptr
        int fd = ch_raw->fd();
        auto it = channel_map_.find(fd);
        if(it != channel_map_.end()) {
            channels.push_back(it->second);
        }
    }

    return channels;
}