#include "epoll_handler.h"
#include "channel.h"

EpollHandler::EpollHandler(){
    if((epollfd_ = ::epoll_create(1)) == -1){
        throw std::runtime_error("Epoll created failed");
    }
}

EpollHandler::~EpollHandler(){
    close(epollfd_);
}

/**
 * for the raw pointer of the parameter `*ch`
 * this is the Linux kernel's epoll API requirement. 
 * the epoll_event struct requires a raw void* pointer. 
 * we store the raw pointer here but maintain ownership with smart pointers in channel_map_.
 * 
 * function parameters can accept raw pointers extracted from smart pointers (using .get()). 
 * this follows C++ Core Guidelines: "Pass smart pointers only to express ownership transfer
 */
void EpollHandler::UpdateChannel(Channel *ch){
    epoll_event ev;
    ev.data.ptr = ch;
    ev.events = ch -> Event();

    if(ch -> is_epoll_in()){
        if(::epoll_ctl(epollfd_, EPOLL_CTL_MOD, ch -> fd(), &ev) == -1){
            throw std::runtime_error("epoll_ctl MOD failed");
        }
    }else{
        if(::epoll_ctl(epollfd_, EPOLL_CTL_ADD, ch -> fd(), &ev) == -1){
            throw std::runtime_error("epoll_ctl ADD failed");
        }
        ch -> SetEpollIn();
    }
}

void EpollHandler::AddChannel(std::shared_ptr<Channel> ch){
    channel_map_[ch->fd()] = ch;
}

std::vector<std::shared_ptr<Channel>> EpollHandler::WaitForEvent(int timeout){
    std::vector<std::shared_ptr<Channel>> channels;
    // init event array
    memset(events_, 0, sizeof(events_));

    int infds = -1;

    while(true){
        infds = epoll_wait(epollfd_, events_, MaxEpollEvents, timeout);
        if(infds >= 0){
            break;
        }
        if(errno == EINTR){
            continue;
        }
        std::cout << "epoll_wait() failed: " << strerror(errno) << std::endl;
        throw std::runtime_error("epoll_wait() failed");
    }

    if(infds == 0){
        // Timeout is not an error - just return empty vector
        return channels;
    }

    for(int idx = 0; idx < infds; idx ++){
        Channel *ch_raw = (Channel*)events_[idx].data.ptr;
        ch_raw->SetDEvent(events_[idx].events);
        int fd = ch_raw->fd();

        // Find the shared_ptr for this channel
        auto it = channel_map_.find(fd);
        if(it != channel_map_.end()){
            channels.push_back(it->second);
        }
    }

    return channels;
}

void EpollHandler::RemoveChannel(int fd){
    auto it = channel_map_.find(fd);
    if(it == channel_map_.end()){
        return;
    }

    if(epollfd_ != -1){
        if(::epoll_ctl(epollfd_, EPOLL_CTL_DEL, fd, nullptr) == -1){
            if(errno != EBADF && errno != ENOENT){
                std::cerr << "epoll_ctl DEL failed for fd " << fd << ": " << strerror(errno) << std::endl;
            }
        }
    }

    channel_map_.erase(it);
}
