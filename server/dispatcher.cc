#include "dispatcher.h"
#include "channel.h"
#include "connection_handler.h"
#include "log/logger.h"
#include "log/log_utils.h"

Dispatcher::Dispatcher() :
    ep_(std::unique_ptr<EventHandler>(new EventHandler())),
    is_sock_dispatcher_(false),
    timer_fd_(-1),
    end_t_(0),
    timeout_(std::chrono::seconds(0))
{
#if defined(__linux__)
    eventfd_ = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (eventfd_ == -1) {
        throw std::runtime_error(std::string("eventfd creation failed: ") + logging::SafeStrerror(errno));
    }
#elif defined(__APPLE__) || defined(__MACH__)
    if (::pipe(wakeup_pipe_) == -1) {
        throw std::runtime_error(std::string("pipe creation failed: ") + logging::SafeStrerror(errno));
    }
    // Set both ends to non-blocking
    ::fcntl(wakeup_pipe_[0], F_SETFL, O_NONBLOCK);
    ::fcntl(wakeup_pipe_[1], F_SETFL, O_NONBLOCK);
#endif
    // Note: wake_channel_ initialization moved to Initialize()
    // Cannot use shared_from_this() in constructor
}

Dispatcher::Dispatcher(bool _is_sock,  int _end_t, std::chrono::seconds _timeout):
    ep_(std::unique_ptr<EventHandler>(new EventHandler())),
    is_sock_dispatcher_(_is_sock),
    end_t_(_end_t),
    timeout_(_timeout)
{
#if defined(__linux__)
    eventfd_ = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (eventfd_ == -1) {
        throw std::runtime_error(std::string("eventfd creation failed: ") + logging::SafeStrerror(errno));
    }
#elif defined(__APPLE__) || defined(__MACH__)
    if (::pipe(wakeup_pipe_) == -1) {
        throw std::runtime_error(std::string("pipe creation failed: ") + logging::SafeStrerror(errno));
    }
    // Set both ends to non-blocking
    ::fcntl(wakeup_pipe_[0], F_SETFL, O_NONBLOCK);
    ::fcntl(wakeup_pipe_[1], F_SETFL, O_NONBLOCK);
#endif
    // Note: wake_channel_ initialization moved to Init()
    // Cannot use shared_from_this() in constructor
}

void Dispatcher::Init() {
    // Create wake_channel_ for eventfd/pipe now that shared_from_this() is safe
    // Must use shared_ptr because Channel calls shared_from_this() in its methods
#if defined(__linux__)
    wake_channel_ = std::make_shared<Channel>(shared_from_this(), eventfd_);
#elif defined(__APPLE__) || defined(__MACH__)
    wake_channel_ = std::make_shared<Channel>(shared_from_this(), wakeup_pipe_[0]);  // Read end of pipe
#endif
    wake_channel_->SetReadCallBackFn(std::bind(&Dispatcher::HandleEventId, this));
    wake_channel_->EnableReadMode();

    // Initialize timer for socket dispatchers.
    // Timer is needed for both idle timeout (timeout_.count() > 0) and request
    // deadline scanning (has_deadline_ per-connection). Always create when
    // end_t_ > 0 (scan interval configured), even if idle timeout is disabled.
    if (is_sock_dispatcher_ && end_t_ > 0) {
        // Use end_t_ (scan interval) for the initial timer fire, not timeout_ (idle timeout).
        // TimerHandler re-arms with end_t_ on each fire. Using timeout_ here would delay
        // the first scan to 300s, missing 30s request deadlines.
        timer_fd_ = TimeStamp::GenTimerFd(std::chrono::seconds(end_t_), std::chrono::nanoseconds(0));
        // Guard against platforms where GenTimerFd returns -1 (e.g., macOS)
        if (timer_fd_ >= 0) {
            timer_channel_ = std::make_shared<Channel>(shared_from_this(), timer_fd_);
            timer_channel_->SetReadCallBackFn(std::bind(&Dispatcher::TimerHandler, this));
            timer_channel_->EnableReadMode();
        }
    }
}

Dispatcher::~Dispatcher() {
    // Let smart pointers handle cleanup automatically
    // wake_channel_ destructor will close the eventfd / wakeup_pipe_[0]
#if defined(__APPLE__) || defined(__MACH__)
    // Close the write end of the wakeup pipe (not owned by wake_channel_)
    if (wakeup_pipe_[1] >= 0) {
        ::close(wakeup_pipe_[1]);
        wakeup_pipe_[1] = -1;
    }
#endif
}

void Dispatcher::set_running_state(bool status){
    is_running_.store(status, std::memory_order_release);
}

void Dispatcher::RunEventLoop(){
    set_running_state(true);

    thread_id_.store(std::this_thread::get_id(), std::memory_order_release);

    while(is_running()){
      try {
        // Use 1000ms timeout instead of blocking indefinitely
        // This allows the server to check is_running() periodically
        std::vector<std::shared_ptr<Channel>> channels = ep_->WaitForEvent(1000);

        // If no events, just continue loop (don't shutdown!)
        // The timeout is for periodic checking, not termination
        if(channels.size() == 0){
            // Drain queued tasks on timeout — if WakeUp's write failed
            // (EAGAIN on full pipe/eventfd), tasks would be stranded until
            // the next real I/O event without this opportunistic drain.
            {
                std::deque<std::function<void()>> tasks;
                {
                    std::lock_guard<std::mutex> lck(mtx_);
                    if (!task_que_.empty()) tasks.swap(task_que_);
                }
                for (auto& fn : tasks) {
                    try { fn(); } catch (...) {}
                }
            }
            if(callbacks_.timeout_trigger_callback){
                callbacks_.timeout_trigger_callback(shared_from_this());
            }
            // Fallback timer for platforms without timerfd (macOS):
            if (is_sock_dispatcher_ && timer_fd_ < 0 && end_t_ > 0) {
                auto now = std::chrono::steady_clock::now();
                if (now - last_fallback_timer_ >= std::chrono::seconds(end_t_)) {
                    last_fallback_timer_ = now;
                    TimerHandler();
                }
            }
            continue;
        }

        // Process all active channels
        for(auto& ch : channels) {
            if (!ch) {
                // Skip null/expired channel entry
                logging::Get()->warn("Skipping null Channel in channels list");
                continue;
            }
            try {
                ch->HandleEvent();
            } catch (const std::exception& e) {
                // Log error and tear down via the close callback so server maps
                // (connections_, http_connections_) are properly cleaned up.
                // Just calling CloseChannel() would leave stale entries.
                logging::Get()->error("Error handling event: {}", e.what());
                if (!ch->is_channel_closed()) {
                    // Invoke the close callback (wired to ConnectionHandler::CallCloseCb
                    // which handles channel close + server map cleanup + fd release)
                    ch->InvokeCloseCallback();
                }
            }
        }

        // Fallback timer for platforms without timerfd (macOS):
        // Throttled by end_t_ to match the configured scan interval.
        if (is_sock_dispatcher_ && timer_fd_ < 0 && end_t_ > 0) {
            auto now = std::chrono::steady_clock::now();
            if (now - last_fallback_timer_ >= std::chrono::seconds(end_t_)) {
                last_fallback_timer_ = now;
                TimerHandler();
            }
        }

      } catch (const std::exception& e) {
        // Catch exceptions from WaitForEvent, TimerHandler, or timeout callbacks
        // that escape the inner try/catch. Without this, the dispatcher thread dies
        // and NetServer::Stop()'s barrier future.wait() hangs forever.
        logging::Get()->error("Event loop error: {}", e.what());
      } catch (...) {
        logging::Get()->error("Unknown event loop error");
      }
    } // end of while(is_running())

    // Final drain: process all tasks enqueued during shutdown.
    // Loop because a task may EnQueue more work (e.g., close callback
    // triggers timer removal which enqueues to this dispatcher).
    // Note: EnQueue guards against was_stopped_, but tasks enqueued BEFORE
    // was_stopped_ was set may themselves enqueue more work.
    for (int drain_rounds = 0; drain_rounds < 10; ++drain_rounds) {
        std::deque<std::function<void()>> tasks;
        {
            std::lock_guard<std::mutex> lck(mtx_);
            if (task_que_.empty()) break;
            tasks.swap(task_que_);
        }
        for (auto& fn : tasks) {
            try { fn(); } catch (...) {}
        }
    }
}

void Dispatcher::StopEventLoop(){
    was_stopped_.store(true, std::memory_order_release);
    set_running_state(false);
    WakeUp();  // Wake up epoll_wait() immediately for fast shutdown
}

void Dispatcher::UpdateChannel(std::shared_ptr<Channel> ch){
    // CRITICAL FIX: Always use EnQueue when not in dispatcher thread
    // The original condition `if(!is_running() || is_dispatcher_thread())` was buggy:
    // - It would call UpdateChannelInLoop() directly when !is_running(), even from wrong thread
    // - This caused race conditions where channels weren't properly registered in epoll
    if(is_dispatcher_thread()){
        UpdateChannelInLoop(ch);
        return;
    }

    // From other threads: use EnQueue to ensure thread-safe epoll modifications
    // But ONLY if running - otherwise, calls during initialization will deadlock
    if(!is_running()){
        // Dispatcher not started yet - this is a bug in the calling code
        // But to maintain compatibility, call directly (thread-unsafe but works for init)
        UpdateChannelInLoop(ch);
        return;
    }

    std::weak_ptr<Dispatcher> self = shared_from_this();
    EnQueue([self, ch]() {
        if(auto dispatcher = self.lock()){
            dispatcher->UpdateChannelInLoop(ch);
        }
    });
}

void Dispatcher::RemoveChannel(std::shared_ptr<Channel> ch){
    if(is_dispatcher_thread()){
        RemoveChannelInLoop(ch);
        return;
    }

    if(!is_running()){
        // Dispatcher not started yet - call directly to avoid deadlock
        RemoveChannelInLoop(ch);
        return;
    }

    std::weak_ptr<Dispatcher> self = shared_from_this();
    EnQueue([self, ch]() {
        if(auto dispatcher = self.lock()){
            dispatcher->RemoveChannelInLoop(ch);
        }
    });
}

void Dispatcher::UpdateChannelInLoop(std::shared_ptr<Channel> ch){
    ep_->UpdateEvent(ch);
}

void Dispatcher::RemoveChannelInLoop(std::shared_ptr<Channel> ch){
    ep_->RemoveChannel(ch);
}

void Dispatcher::WakeUp(){
#if defined(__linux__)
    uint64_t val = 1;
    ssize_t n = ::write(eventfd_, &val, sizeof val);
    if (n != sizeof val) {
        int saved_errno = errno;
        logging::Get()->error("eventfd write failed: {}", logging::SafeStrerror(saved_errno));
    }
#elif defined(__APPLE__) || defined(__MACH__)
    char buf = 1;
    ssize_t n = ::write(wakeup_pipe_[1], &buf, sizeof buf);  // Write to pipe[1]
    if (n != sizeof buf) {
        int saved_errno = errno;
        logging::Get()->error("pipe write failed: {}", logging::SafeStrerror(saved_errno));
    }
#endif
}

void Dispatcher::HandleEventId(){
#if defined(__linux__)
    uint64_t val;
    ssize_t n = ::read(eventfd_, &val, sizeof val);
    if (n != sizeof val) {
        logging::Get()->error("eventfd read failed");
        return;
    }
#elif defined(__APPLE__) || defined(__MACH__)
    // Drain the pipe - may have multiple wake-ups queued
    char buf[256];
    while (::read(wakeup_pipe_[0], buf, sizeof buf) > 0) {
        // Just drain, don't care about content
    }
#endif

    // Move tasks out of queue while holding lock, then execute without lock
    // This prevents deadlock if a task calls EnQueue()
    std::deque<std::function<void()>> tasks;

    {
        std::lock_guard<std::mutex> lck(mtx_);
        tasks.swap(task_que_);
    }

    // Execute tasks without holding lock
    while(!tasks.empty()){
        auto fn = std::move(tasks.front());
        tasks.pop_front();
        try {
            fn();
        } catch (const std::exception& e) {
            logging::Get()->error("Task execution error: {}", e.what());
        }
    }
}

void Dispatcher::EnQueue(std::function<void()> fn){
    // Only discard tasks after explicit stop — allow during startup (before RunEventLoop)
    if (was_stopped_.load(std::memory_order_acquire)) return;
    {
        std::lock_guard<std::mutex> lck(mtx_);
        task_que_.push_back(fn);
    }
    WakeUp();
}

void Dispatcher::AddConnection(std::shared_ptr<ConnectionHandler> conn){
    connections_[conn -> fd()] = conn;
}

void Dispatcher::ClearConnections(){
    connections_.clear();
}

void Dispatcher::RemoveTimerConnection(int fd) {
    connections_.erase(fd);
}

void Dispatcher::RemoveTimerConnectionIfMatch(int fd, std::shared_ptr<ConnectionHandler> conn) {
    if (!conn) return;  // Original connection already destroyed — can't verify identity
    auto it = connections_.find(fd);
    if (it != connections_.end() && it->second == conn) {
        connections_.erase(it);
    }
}

void Dispatcher::SetTimerCB(CALLBACKS_NAMESPACE::DispatcherTimerCallback fn){
    callbacks_.timer_callback = std::move(fn);
}

void Dispatcher::SetTimeOutTriggerCB(CALLBACKS_NAMESPACE::DispatcherTOTriggerCallback fn){
    callbacks_.timeout_trigger_callback = std::move(fn);
}

void Dispatcher::SetTimerInterval(int interval) {
    end_t_ = interval;
    // Re-arm the timerfd immediately so a downward reload takes effect
    // without waiting for the old (potentially much longer) interval to fire.
    if (timer_fd_ >= 0 && interval > 0) {
        TimeStamp::ResetTimerFd(timer_fd_, interval);
    }
}

void Dispatcher::TimerHandler(){
    // Drain the timerfd expiration count before re-arming.
    // On Linux, timerfd stays readable until read(); without draining,
    // epoll_wait returns the timer channel continuously in a tight loop.
#if defined(__linux__)
    uint64_t expirations;
    ::read(timer_fd_, &expirations, sizeof(expirations));
#endif
    TimeStamp::ResetTimerFd(timer_fd_, end_t_);

    // Periodic log rotation check. Uses try_lock — skips if another
    // dispatcher is already checking. No contention in steady state.
    logging::CheckRotation();

    if(is_sock_dispatcher()){
        logging::Get()->trace("Dispatcher: reset timer");

        // Collect all timed-out connection fds first to avoid iterator invalidation
        // No mutex needed: AddConnection/RemoveTimerConnection/TimerHandler all run
        // on this dispatcher's event-loop thread via EnQueue.
        std::vector<int> timeout_fds;

        // Check every connection to find whether it has timeout
        // Collect shared_ptrs so we can close them after map cleanup
        std::vector<std::shared_ptr<ConnectionHandler>> timed_out_conns;
        for(auto& conn : connections_){
            if(conn.second && conn.second->IsTimeOut(timeout_)){
                timeout_fds.push_back(conn.first);
                timed_out_conns.push_back(conn.second);
            }
        }

        // Close timed-out connections.
        for(auto& conn : timed_out_conns){
            logging::Get()->debug("Connection timed out fd={}", conn->fd());
            if (conn->IsClosing() || conn->IsCloseDeferred()) {
                // Already closing (previous timeout triggered CloseAfterWrite but flush stalled).
                // Force close now — the buffered response will never drain.
                conn->ForceClose();
            } else {
                // First timeout: invoke deadline callback. If it returns true,
                // the protocol layer handled the timeout (e.g., HTTP/2 RST'd
                // expired streams and re-armed the deadline) — keep connection alive.
                if (conn->CallDeadlineTimeoutCb()) {
                    continue;  // Handled — skip close
                }
                // Not handled: send 408 response (if callback set above), then close.
                // Re-arm deadline to give the response time to flush (30s drain window).
                conn->SetDeadline(std::chrono::steady_clock::now() + std::chrono::seconds(30));
                conn->CloseAfterWrite();
            }
        }
    }
}