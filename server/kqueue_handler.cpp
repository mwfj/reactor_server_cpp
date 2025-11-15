#if defined(__APPLE__) || defined(__MACH__)
#include "kqueue_handler.h"
#include "channel.h"

KqueueHandler::KqueueHandler(){
    if((kqueuefd_ = ::kqueue()) == -1){
        std::cout << "[Epoll Handler] epoll_create failed: " << strerror(errno) << std::endl;
        throw std::runtime_error("Epoll created failed");
    }
}

KqueueHandler::~KqueueHandler(){
    close(kqueuefd_);
}

/**
 * Store channel in map and register with epoll.
 * Linux epoll API requires raw void* pointer in epoll_event,
 * but we maintain ownership with smart pointers in channel_map_.
 */
void KqueueHandler::UpdateEvent(std::shared_ptr<Channel> ch){
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

    
    uint32_t kevents = ch->Event();

    // kqueue requires separate kevents for read and write filters
    struct kevent evSet[2];
    int numChanges = 0;


    if(ch->is_read_event()){
        if(::epoll_ctl(kqueuefd_, EPOLL_CTL_MOD, fd, &ev) == -1){
            // If fd is invalid or not in epoll, it might be closing - don't throw
            if (errno == EBADF || errno == ENOENT) {
                return;  // Gracefully handle race condition
            }
            std::cout << "[Epoll Handler] epoll_ctl MOD failed: " << strerror(errno) << std::endl;
            throw std::runtime_error("epoll_ctl MOD failed");
        }
    }else{
        if(::epoll_ctl(kqueuefd_, EPOLL_CTL_ADD, fd, &ev) == -1){
            // If fd is invalid or already in epoll, it might be a race - don't throw
            if (errno == EBADF || errno == EEXIST) {
                return;  // Gracefully handle race condition
            }
            std::cout << "[Epoll Handler] epoll_ctl ADD failed: " << strerror(errno) << std::endl;
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
void KqueueHandler::RemoveChannel(std::shared_ptr<Channel> ch){
    int fd = ch->fd();

    // Remove from epoll if it was registered
    if(ch->is_read_event()){
        struct kevent evSets[2];
        // Delete both read and write flags
        EV_SET(&evSets[0], fd, EVFILT_READ, EV_DELETE, 0, 0, nullptr);
        EV_SET(&evSets[1], fd, EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);
        if(::kevent(kqueuefd_, evSets, 2, nullptr, 0, nullptr) == -1){
            // ENOENT means it wasn't in epoll (already removed or never added)
            // EBADF means fd is invalid (already closed)
            // Both are ok - we just want to ensure it's not in epoll
            if(errno != ENOENT && errno != EBADF){
                std::cout << "[KqueueHandler] epoll_ctl DEL warning for fd=" << fd
                          << ": " << strerror(errno) << std::endl;
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

std::vector<std::shared_ptr<Channel>> KqueueHandler::WaitForEvent(int timeout){
    std::vector<std::shared_ptr<Channel>> channels;
    // init event array
    memset(events_, 0, sizeof(events_));

    // Convert timeout from millionseconds to timespec
    struct timespec ts;
    struct timespec *timeout_ptr = nullptr;

    if(timeout >= 0) {
        ts.tv_sec = timeout / 1000;
        ts.tv_nsec = (timeout % 1000) * 1000000;
        timeout_ptr = &ts;
    }

    int nevents = kevent(kqueuefd_, nullptr, 0,  events_, MAX_EVETN_NUMS, timeout_ptr);

    if(nevents < 0){
        // interruptted by other signal
        if(errno == EINTR){
             std::cout << "[Epoll Handler] epoll_wait() failed, iterruptted by other signal: " << strerror(errno) << std::endl;
             return {};
        }
        std::cout << "[Epoll Handler] epoll_wait() failed: " << strerror(errno) << std::endl;
        throw std::runtime_error("epoll_wait() failed");
    }

    // timeout or no events
    if(nevents == 0){
        return channels;
    }

    // Reserve space to avoid reallocations
    channels.reserve(nevents);

    for(int idx = 0; idx < nevents; idx++){
        Channel *ch_raw = static_cast<Channel*>(events_[idx].udata);

        // CRITICAL: Lock and validate BEFORE dereferencing the raw pointer
        // The channel may have been deleted between epoll_wait() returning and now
        std::lock_guard<std::mutex> lock(channel_map_mutex_);

        // Find the shared_ptr by searching for matching raw pointer
        std::shared_ptr<Channel> ch;
        for(auto& pair : channel_map_) {
            if(pair.second && pair.second.get() == ch_raw) {
                ch = pair.second;
                break;
            }
        }

        // Only dereference if we found a valid shared_ptr
        if(ch) {
            ch->SetDEvent(events_[idx].events);  // NOW SAFE - we hold a shared_ptr
            channels.push_back(ch);
        }
    }

    return channels;  // RVO/NRVO will optimize this (no copy!)
}
#endif