#if defined(__APPLE__) || defined(__MACH__)
#include "kqueue_handler.h"
#include "channel.h"

KqueueHandler::KqueueHandler(){
    if((kqueuefd_ = ::kqueue()) == -1){
        std::cout << "[Kqueue Handler] kqueue() failed: " << strerror(errno) << std::endl;
        throw std::runtime_error("kqueue() failed");
    }
}

KqueueHandler::~KqueueHandler(){
    if(kqueuefd_ != -1) {
        close(kqueuefd_);
    }
}

/**
 * Store channel in map and register with kqueue.
 * kqueue uses separate filters for read/write instead of bitflags.
 */
void KqueueHandler::UpdateEvent(std::shared_ptr<Channel> ch){
    // Check if channel is closed - prevents TOCTOU race
    if (ch->is_channel_closed()) {
        return;  // Silently ignore - channel is closing or closed
    }

    int fd = ch->fd();

    // Double-check fd is valid before kqueue operations
    if (fd < 0) {
        return;  // Invalid fd, nothing to do
    }

    uint32_t events = ch->Event();

    // kqueue requires separate kevents for read and write filters
    // Use EV_ADD | EV_ONESHOT to get edge-triggered behavior
    // EV_CLEAR would work too, but ONESHOT is closer to epoll ET semantics
    struct kevent evSet[4];  // Max: add/delete read + add/delete write
    int numChanges = 0;

    // Check if already registered
    bool is_registered = ch->is_read_event();

    // Handle read filter
    if(events & EVENT_READ){
        // Add or re-enable read filter
        EV_SET(&evSet[numChanges++], fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, ch.get());
    } else if(is_registered) {
        // Remove read filter if it was previously registered
        EV_SET(&evSet[numChanges++], fd, EVFILT_READ, EV_DELETE, 0, 0, nullptr);
    }

    // Handle write filter
    if(events & EVENT_WRITE){
        // Add or re-enable write filter
        EV_SET(&evSet[numChanges++], fd, EVFILT_WRITE, EV_ADD | EV_CLEAR, 0, 0, ch.get());
    } else if(is_registered) {
        // Remove write filter if it was previously registered
        EV_SET(&evSet[numChanges++], fd, EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);
    }

    // Apply changes to kqueue
    if(numChanges > 0){
        if(::kevent(kqueuefd_, evSet, numChanges, nullptr, 0, nullptr) == -1){
            // If fd is invalid or not in kqueue, it might be closing - don't throw
            if (errno == EBADF || errno == ENOENT) {
                return;  // Gracefully handle race condition
            }
            std::cout << "[Kqueue Handler] kevent failed (fd=" << fd << "): " << strerror(errno) << std::endl;
            // Don't throw - just log and continue
            return;
        }

        // Store in map to maintain ownership - must lock to prevent race with WaitForEvent
        if(events != 0) {
            std::lock_guard<std::mutex> lock(channel_map_mutex_);
            channel_map_[fd] = ch;
            ch->SetEventRead();  // Mark as registered
        }
    }
}

/**
 * Remove channel from kqueue and channel map
 * MUST be called before closing the fd to prevent fd reuse bugs
 */
void KqueueHandler::RemoveChannel(std::shared_ptr<Channel> ch){
    int fd = ch->fd();

    // Remove from kqueue if it was registered
    if(ch->is_read_event()){
        struct kevent evSets[2];
        // Delete both read and write filters
        EV_SET(&evSets[0], fd, EVFILT_READ, EV_DELETE, 0, 0, nullptr);
        EV_SET(&evSets[1], fd, EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);
        if(::kevent(kqueuefd_, evSets, 2, nullptr, 0, nullptr) == -1){
            // ENOENT means it wasn't in kqueue (already removed or never added)
            // EBADF means fd is invalid (already closed)
            // Both are ok - we just want to ensure it's not in kqueue
            if(errno != ENOENT && errno != EBADF){
                std::cout << "[KqueueHandler] kevent DEL warning for fd=" << fd
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

    // Convert timeout from milliseconds to timespec
    struct timespec ts;
    struct timespec *timeout_ptr = nullptr;

    if(timeout >= 0) {
        ts.tv_sec = timeout / 1000;
        ts.tv_nsec = (timeout % 1000) * 1000000;
        timeout_ptr = &ts;
    }

    int nevents = kevent(kqueuefd_, nullptr, 0,  events_, MAX_EVETN_NUMS, timeout_ptr);

    if(nevents < 0){
        // interrupted by other signal
        if(errno == EINTR){
             std::cout << "[Kqueue Handler] kevent() failed, interrupted by signal: " << strerror(errno) << std::endl;
             return {};
        }
        std::cout << "[Kqueue Handler] kevent() failed: " << strerror(errno) << std::endl;
        throw std::runtime_error("kevent() failed");
    }

    // timeout or no events
    if(nevents == 0){
        return channels;
    }

    // kqueue can return multiple events for the same fd (read + write)
    // We need to consolidate them into a single Channel with combined events
    std::map<int, std::pair<std::shared_ptr<Channel>, uint32_t>> fd_events;

    // Lock once for the entire event processing
    {
        std::lock_guard<std::mutex> lock(channel_map_mutex_);

        for(int idx = 0; idx < nevents; idx++){
            Channel *ch_raw = static_cast<Channel*>(events_[idx].udata);

            // Find the shared_ptr by searching for matching raw pointer
            std::shared_ptr<Channel> ch;
            for(auto& pair : channel_map_) {
                if(pair.second && pair.second.get() == ch_raw) {
                    ch = pair.second;
                    break;
                }
            }

            // Only process if we found a valid shared_ptr
            if(ch) {
                int fd = ch->fd();

                // Convert kqueue filter events to our platform-agnostic EVENT_ constants
                uint32_t platform_events = 0;
                if(events_[idx].filter == EVFILT_READ) {
                    platform_events |= EVENT_READ;
                    if(events_[idx].flags & EV_EOF) {
                        platform_events |= EVENT_RDHUP;  // EOF on read = peer closed
                    }
                }
                if(events_[idx].filter == EVFILT_WRITE) {
                    platform_events |= EVENT_WRITE;
                }
                if(events_[idx].flags & EV_ERROR) {
                    platform_events |= EVENT_ERR;
                }

                // Consolidate events for the same fd
                auto it = fd_events.find(fd);
                if(it != fd_events.end()) {
                    // Merge events for same fd
                    it->second.second |= platform_events;
                } else {
                    // First event for this fd
                    fd_events[fd] = std::make_pair(ch, platform_events);
                }
            }
        }
    }  // Release lock

    // Build final channel list with consolidated events
    channels.reserve(fd_events.size());
    for(auto& pair : fd_events) {
        auto& ch = pair.second.first;
        uint32_t events = pair.second.second;
        ch->SetDEvent(events);
        channels.push_back(ch);
    }

    return channels;  // RVO/NRVO will optimize this (no copy!)
}
#endif
