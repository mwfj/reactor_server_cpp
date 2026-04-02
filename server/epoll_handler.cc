#if defined(__linux__)

#include "epoll_handler.h"
#include "channel.h"
#include "log/logger.h"
#include "log/log_utils.h"

EpollHandler::EpollHandler(){
    if((epollfd_ = ::epoll_create1(EPOLL_CLOEXEC)) == -1){
        int saved_errno = errno;
        logging::Get()->error("epoll_create failed: {}", logging::SafeStrerror(saved_errno));
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
    // Check if channel is closed - prevents TOCTOU race
    // This must be checked here, not just in Enable*/Disable* methods
    if (ch->is_channel_closed()) {
        return;  // Silently ignore - channel is closing or closed
    }

    int fd = ch->fd();

    // Double-check fd is valid before epoll operations
    if (fd < 0) {
        return;  // Invalid fd, nothing to do
    }

    epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.data.fd = fd;  // Store fd for O(1) lookup in WaitForEvent
    ev.events = ch->Event();

    if(ch->is_read_event()){
        if(::epoll_ctl(epollfd_, EPOLL_CTL_MOD, fd, &ev) == -1){
            int saved_errno = errno;
            // If fd is invalid or not in epoll, it might be closing - don't throw
            if (saved_errno == EBADF || saved_errno == ENOENT) {
                return;  // Gracefully handle race condition
            }
            logging::Get()->error("epoll_ctl MOD failed: {}", logging::SafeStrerror(saved_errno));
            throw std::runtime_error("epoll_ctl MOD failed");
        }
    }else{
        if(::epoll_ctl(epollfd_, EPOLL_CTL_ADD, fd, &ev) == -1){
            int saved_errno = errno;
            // If fd is invalid or already in epoll, it might be a race - don't throw
            if (saved_errno == EBADF || saved_errno == EEXIST) {
                return;  // Gracefully handle race condition
            }
            logging::Get()->error("epoll_ctl ADD failed: {}", logging::SafeStrerror(saved_errno));
            throw std::runtime_error("epoll_ctl ADD failed");
        }
        ch->SetEventRead();
        // Store in map to maintain ownership - must lock to prevent race with WaitForEvent
        {
            std::lock_guard<std::mutex> lock(channel_map_mutex_);
            channel_map_[fd] = ch;
        }
    }
}

/**
 * Remove channel from epoll and channel map
 * MUST be called before closing the fd to prevent fd reuse bugs
 */
void EpollHandler::RemoveChannel(std::shared_ptr<Channel> ch){
    int fd = ch->fd();

    // Remove from epoll if it was registered
    if(ch->is_read_event()){
        if(::epoll_ctl(epollfd_, EPOLL_CTL_DEL, fd, nullptr) == -1){
            int saved_errno = errno;
            // ENOENT means it wasn't in epoll (already removed or never added)
            // EBADF means fd is invalid (already closed)
            // Both are ok - we just want to ensure it's not in epoll
            if(saved_errno != ENOENT && saved_errno != EBADF){
                logging::Get()->warn("epoll_ctl DEL warning fd={}: {}", fd, logging::SafeStrerror(saved_errno));
            }
        }
    }

    // Remove from channel map - must lock to prevent race with WaitForEvent
    {
        std::lock_guard<std::mutex> lock(channel_map_mutex_);
        auto it = channel_map_.find(fd);
        if(it != channel_map_.end()){
            channel_map_.erase(it);
        }
    }
}

std::vector<std::shared_ptr<Channel>> EpollHandler::WaitForEvent(int timeout){
    std::vector<std::shared_ptr<Channel>> channels;
    // init event array
    memset(events_, 0, sizeof(events_));

    int infds = epoll_wait(epollfd_, events_, MAX_EVENT_NUMS, timeout);

    if(infds < 0){
        int saved_errno = errno;
        if (saved_errno == EINTR) {
            // Interrupted by signal — not an error, just return empty
            return channels;
        }
        logging::Get()->error("epoll_wait() failed: {}", logging::SafeStrerror(saved_errno));
        throw std::runtime_error("epoll_wait() failed");
    }

    // timeout or no events
    if(infds == 0){
        return channels;  // RVO will optimize this
    }

    // Reserve space to avoid reallocations
    channels.reserve(infds);

    {
        // Lock once for all events — prevents channel_map_ from changing
        // while we process the batch.
        std::lock_guard<std::mutex> lock(channel_map_mutex_);

        for(int idx = 0; idx < infds; idx++){
            int event_fd = events_[idx].data.fd;

            // O(log N) lookup by fd instead of O(N) linear scan
            auto it = channel_map_.find(event_fd);
            if(it == channel_map_.end() || !it->second) {
                continue;  // Channel was removed between epoll_wait and now
            }

            auto& ch = it->second;
            ch->SetDEvent(events_[idx].events);
            channels.push_back(ch);
        }
    }

    return channels;  // RVO/NRVO will optimize this (no copy!)
}

#endif