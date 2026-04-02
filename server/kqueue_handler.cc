#if defined(__APPLE__) || defined(__MACH__)
#include "kqueue_handler.h"
#include "channel.h"
#include "log/logger.h"
#include "log/log_utils.h"

KqueueHandler::KqueueHandler(){
    if((kqueuefd_ = ::kqueue()) == -1){
        int saved_errno = errno;
        logging::Get()->error("kqueue() failed: {}", logging::SafeStrerror(saved_errno));
        throw std::runtime_error("kqueue() failed");
    }
    // Set close-on-exec to prevent leaking the kqueue fd into child processes.
    // kqueue() has no CLOEXEC flag (unlike Linux's epoll_create1), so use fcntl.
    int fd_flags = fcntl(kqueuefd_, F_GETFD);
    if (fd_flags != -1) {
        fcntl(kqueuefd_, F_SETFD, fd_flags | FD_CLOEXEC);
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
    // EV_CLEAR resets the event state after retrieval — functionally
    // equivalent to epoll's EPOLLET (edge-triggered) for read/write filters.
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

    // Apply each change independently — batching can fail entirely if one
    // operation returns ENOENT (e.g., deleting a filter that was never added),
    // silently skipping subsequent operations in the same batch.
    for (int i = 0; i < numChanges; ++i) {
        if (::kevent(kqueuefd_, &evSet[i], 1, nullptr, 0, nullptr) == -1) {
            int saved_errno = errno;
            if (saved_errno == EBADF) {
                return;  // fd is dead — nothing more to do
            }
            if (saved_errno == ENOENT) {
                continue;  // Filter wasn't registered — skip, try next
            }
            logging::Get()->error("kevent failed (fd={}): {}", fd, logging::SafeStrerror(saved_errno));
            return;
        }
    }

    // Store in map to maintain ownership - must lock to prevent race with WaitForEvent
    if(events != 0) {
        std::lock_guard<std::mutex> lock(channel_map_mutex_);
        channel_map_[fd] = ch;
        ch->SetEventRead();  // Mark as registered
    } else if (is_registered) {
        // All interest bits cleared — kqueue filters were deleted above.
        // Remove from channel_map_ to release the shared_ptr and prevent
        // stale entries from keeping the channel alive indefinitely.
        std::lock_guard<std::mutex> lock(channel_map_mutex_);
        channel_map_.erase(fd);
    }
}

/**
 * Remove channel from kqueue and channel map
 * MUST be called before closing the fd to prevent fd reuse bugs
 */
void KqueueHandler::RemoveChannel(std::shared_ptr<Channel> ch){
    int fd = ch->fd();

    // Remove from kqueue if it was registered.
    // Delete each filter independently — batching both in one kevent() call
    // fails entirely if either filter doesn't exist (ENOENT), leaving the
    // other filter still registered. Write-only channels would leak the
    // EVFILT_WRITE filter when the batched EVFILT_READ delete returns ENOENT.
    if(ch->is_read_event()){
        struct kevent ev;
        // Delete read filter (may not be registered for write-only channels)
        EV_SET(&ev, fd, EVFILT_READ, EV_DELETE, 0, 0, nullptr);
        if(::kevent(kqueuefd_, &ev, 1, nullptr, 0, nullptr) == -1){
            int saved_errno = errno;
            if(saved_errno != ENOENT && saved_errno != EBADF){
                logging::Get()->warn("kevent EVFILT_READ DEL warning fd={}: {}", fd, logging::SafeStrerror(saved_errno));
            }
        }
        // Delete write filter (may not be registered for read-only channels)
        EV_SET(&ev, fd, EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);
        if(::kevent(kqueuefd_, &ev, 1, nullptr, 0, nullptr) == -1){
            int saved_errno = errno;
            if(saved_errno != ENOENT && saved_errno != EBADF){
                logging::Get()->warn("kevent EVFILT_WRITE DEL warning fd={}: {}", fd, logging::SafeStrerror(saved_errno));
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

    int nevents = kevent(kqueuefd_, nullptr, 0,  events_, MAX_EVENT_NUMS, timeout_ptr);

    if(nevents < 0){
        int saved_errno = errno;
        // interrupted by other signal
        if(saved_errno == EINTR){
             logging::Get()->debug("kevent() interrupted by signal");
             return {};
        }
        logging::Get()->error("kevent() failed: {}", logging::SafeStrerror(saved_errno));
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
            // EVFILT_TIMER events have no associated Channel — set the flag
            // and skip to the next event.
            if(events_[idx].filter == EVFILT_TIMER) {
                timer_fired_.store(true, std::memory_order_relaxed);
                continue;
            }

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
                    if(events_[idx].flags & EV_EOF) {
                        platform_events |= EVENT_RDHUP;  // Peer closed — detected via write filter
                    }
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

void KqueueHandler::RegisterTimer(int interval_sec) {
    struct kevent ev;
    // EV_ONESHOT: fire once, then disarm. Re-armed explicitly by ResetTimer()
    // after TimerHandler() completes — matches the Linux timerfd pattern where
    // ResetTimerFd() re-arms at the start of TimerHandler().
    EV_SET(&ev, KQUEUE_TIMER_IDENT, EVFILT_TIMER,
           EV_ADD | EV_ONESHOT, NOTE_SECONDS, interval_sec, nullptr);
    if (::kevent(kqueuefd_, &ev, 1, nullptr, 0, nullptr) == -1) {
        int saved_errno = errno;
        logging::Get()->error("kevent EVFILT_TIMER register failed: {}",
                              logging::SafeStrerror(saved_errno));
        throw std::runtime_error("Failed to register kqueue timer");
    }
    logging::Get()->debug("Kqueue timer registered: interval={}s", interval_sec);
}

void KqueueHandler::ResetTimer(int interval_sec) {
    struct kevent ev;
    // Re-add with EV_ONESHOT — idempotent, replaces the previous timer.
    // With EV_ONESHOT and no fallback, a failed re-arm permanently disables
    // idle timeout and deadline scanning. Retry on EINTR; error-level log
    // on persistent failure so operators notice.
    EV_SET(&ev, KQUEUE_TIMER_IDENT, EVFILT_TIMER,
           EV_ADD | EV_ONESHOT, NOTE_SECONDS, interval_sec, nullptr);
    for (int attempt = 0; attempt < 3; ++attempt) {
        if (::kevent(kqueuefd_, &ev, 1, nullptr, 0, nullptr) == 0) {
            return;  // Success
        }
        int saved_errno = errno;
        if (saved_errno == EINTR) {
            continue;  // Transient — retry
        }
        logging::Get()->error("kevent EVFILT_TIMER re-arm failed (attempt {}): {}",
                              attempt + 1, logging::SafeStrerror(saved_errno));
        return;  // Non-transient error — no point retrying
    }
    logging::Get()->error("kevent EVFILT_TIMER re-arm failed after 3 EINTR retries");
}

bool KqueueHandler::ConsumeTimerFired() {
    return timer_fired_.exchange(false);
}
#endif
