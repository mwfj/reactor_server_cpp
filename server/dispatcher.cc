#include "dispatcher.h"
#include "channel.h"
#include "connection_handler.h"
#include "log/logger.h"
#include "log/log_utils.h"

Dispatcher::Dispatcher() :
    ep_(std::unique_ptr<EventHandler>(new EventHandler())),
    is_sock_dispatcher_(false),
    end_t_(0),
    timeout_(std::chrono::seconds(0))
{
#if defined(__linux__)
    timer_fd_ = -1;
    eventfd_ = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (eventfd_ == -1) {
        throw std::runtime_error(std::string("eventfd creation failed: ") + logging::SafeStrerror(errno));
    }
#elif defined(__APPLE__) || defined(__MACH__)
    if (::pipe(wakeup_pipe_) == -1) {
        throw std::runtime_error(std::string("pipe creation failed: ") + logging::SafeStrerror(errno));
    }
    // Set both ends to non-blocking + close-on-exec
    for (int i = 0; i < 2; ++i) {
        ::fcntl(wakeup_pipe_[i], F_SETFL, O_NONBLOCK);
        int fd_flags = ::fcntl(wakeup_pipe_[i], F_GETFD);
        if (fd_flags != -1) ::fcntl(wakeup_pipe_[i], F_SETFD, fd_flags | FD_CLOEXEC);
    }
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
    timer_fd_ = -1;
    eventfd_ = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (eventfd_ == -1) {
        throw std::runtime_error(std::string("eventfd creation failed: ") + logging::SafeStrerror(errno));
    }
#elif defined(__APPLE__) || defined(__MACH__)
    if (::pipe(wakeup_pipe_) == -1) {
        throw std::runtime_error(std::string("pipe creation failed: ") + logging::SafeStrerror(errno));
    }
    // Set both ends to non-blocking + close-on-exec
    for (int i = 0; i < 2; ++i) {
        ::fcntl(wakeup_pipe_[i], F_SETFL, O_NONBLOCK);
        int fd_flags = ::fcntl(wakeup_pipe_[i], F_GETFD);
        if (fd_flags != -1) ::fcntl(wakeup_pipe_[i], F_SETFD, fd_flags | FD_CLOEXEC);
    }
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
    // Register the wake channel synchronously — MUST NOT go through
    // EnableReadMode() → UpdateChannel() → EnQueue(), because the wake
    // channel itself is what drains the task queue. Enqueueing its own
    // registration creates a chicken-and-egg deadlock.
    // Init() runs single-threaded before any event loop, so direct
    // registration is safe (no concurrent epoll/kqueue access).
    wake_channel_->EnableETMode();
    wake_channel_->SetEvent(wake_channel_->Event() | EVENT_READ | EVENT_RDHUP);
    UpdateChannelInLoop(wake_channel_);

    // Initialize timer for socket dispatchers.
    // Timer is needed for both idle timeout (timeout_.count() > 0) and request
    // deadline scanning (has_deadline_ per-connection). Always create when
    // end_t_ > 0 (scan interval configured), even if idle timeout is disabled.
    if (is_sock_dispatcher_ && end_t_ > 0) {
#if defined(__linux__)
        // Linux: timerfd becomes a Channel in the epoll interest list.
        // Same synchronous registration as wake_channel_ — safe during Init().
        timer_fd_ = TimeStamp::GenTimerFd(std::chrono::seconds(end_t_), std::chrono::nanoseconds(0));
        if (timer_fd_ >= 0) {
            timer_channel_ = std::make_shared<Channel>(shared_from_this(), timer_fd_);
            timer_channel_->SetReadCallBackFn(std::bind(&Dispatcher::TimerHandler, this));
            timer_channel_->EnableETMode();
            timer_channel_->SetEvent(timer_channel_->Event() | EVENT_READ | EVENT_RDHUP);
            UpdateChannelInLoop(timer_channel_);
        }
#elif defined(__APPLE__) || defined(__MACH__)
        // macOS: EVFILT_TIMER registered directly on the kqueue — no fd, no Channel.
        // EV_ONESHOT fires once; re-armed by ResetTimer() inside TimerHandler().
        ep_->RegisterTimer(end_t_);
#endif
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
    // Guard: if StopEventLoop() was called before we entered the loop
    // (e.g., TestServerRunner timeout calling Stop() while the server thread
    // is still setting up), return immediately so the thread can be joined.
    // Without this, set_running_state(true) would override the stop and the
    // loop would run forever, hanging the join().
    if (was_stopped()) return;

    set_running_state(true);

    thread_id_.store(std::this_thread::get_id(), std::memory_order_release);

    while(is_running()){
      try {
        // Use 1000ms timeout instead of blocking indefinitely
        // This allows the server to check is_running() periodically
        std::vector<std::shared_ptr<Channel>> channels = ep_->WaitForEvent(1000);

        // If no channel events, just continue loop (don't shutdown!)
        // The timeout is for periodic checking, not termination.
        // Note: on macOS, EVFILT_TIMER may fire with no channel events,
        // so we still need to check ConsumeTimerFired() below.
        if(channels.size() == 0){
            // Call timeout callback if set
            if(callbacks_.timeout_trigger_callback){
                callbacks_.timeout_trigger_callback(shared_from_this());
            }
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

        // macOS EVFILT_TIMER: check if the timer fired during WaitForEvent().
        // ConsumeTimerFired() returns false on Linux (timer is a timerfd Channel
        // that invokes TimerHandler() directly via its read callback).
        if (is_sock_dispatcher_ && ep_->ConsumeTimerFired()) {
            TimerHandler();
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
    if(is_dispatcher_thread()){
        UpdateChannelInLoop(ch);
        return;
    }

    // Always enqueue when off-thread. This is safe even before RunEventLoop()
    // starts — the task queues up and is drained when the loop begins.
    // The previous !is_running() fallback called UpdateChannelInLoop()
    // directly from the wrong thread, causing cross-thread epoll/kqueue
    // mutations that are undefined behavior.
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

    // Always enqueue when off-thread — same rationale as UpdateChannel.
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
    if (n != sizeof val && errno != EAGAIN && errno != EWOULDBLOCK) {
        logging::Get()->error("eventfd read failed: {}",
                              logging::SafeStrerror(errno));
    }
    // Proceed to drain tasks even if no token was pending (EAGAIN).
    // HandleEventId() is called both from the event loop (token guaranteed)
    // and from inline drain paths (e.g., self-dispatcher barrier in
    // NetServer::Stop) where no token may exist.
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

void Dispatcher::TimerHandler(){
    // Re-arm BEFORE scanning connections — matches the cadence on both platforms.
    // On Linux, timerfd stays readable until read(); draining + re-arm prevents
    // epoll_wait from returning the timer channel continuously in a tight loop.
    // On macOS, EVFILT_TIMER was registered with EV_ONESHOT so it must be
    // explicitly re-armed via ResetTimer().
#if defined(__linux__)
    uint64_t expirations;
    ::read(timer_fd_, &expirations, sizeof(expirations));
    TimeStamp::ResetTimerFd(timer_fd_, end_t_);
#elif defined(__APPLE__) || defined(__MACH__)
    ep_->ResetTimer(end_t_);
#endif

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