#include "dispatcher.h"
#include "channel.h"
#include "connection_handler.h"

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
        throw std::runtime_error(std::string("eventfd creation failed: ") + strerror(errno));
    }
#elif defined(__APPLE__) || defined(__MACH__)
    if (::pipe(wakeup_pipe_) == -1) {
        throw std::runtime_error(std::string("pipe creation failed: ") + strerror(errno));
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
        throw std::runtime_error(std::string("eventfd creation failed: ") + strerror(errno));
    }
#elif defined(__APPLE__) || defined(__MACH__)
    if (::pipe(wakeup_pipe_) == -1) {
        throw std::runtime_error(std::string("pipe creation failed: ") + strerror(errno));
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
    // wake_channel_ destructor will close the eventfd
    // No need to explicitly remove from epoll - ep_ is being destroyed anyway
}

void Dispatcher::set_running_state(bool status){
    is_running_.store(status, std::memory_order_release);
}

void Dispatcher::RunEventLoop(){
    set_running_state(true);

    thread_id_.store(std::this_thread::get_id(), std::memory_order_release);

    while(is_running()){
        // Use 1000ms timeout instead of blocking indefinitely
        // This allows the server to check is_running() periodically
        std::vector<std::shared_ptr<Channel>> channels = ep_->WaitForEvent(1000);

        // If no events, just continue loop (don't shutdown!)
        // The timeout is for periodic checking, not termination
        if(channels.size() == 0){
            // Call timeout callback if set
            if(callbacks_.timeout_trigger_callback){
                callbacks_.timeout_trigger_callback(shared_from_this());
            }
            // Fallback timer for platforms without timerfd (macOS):
            // Must also run here so idle connections are caught even with no traffic.
            if (is_sock_dispatcher_ && timer_fd_ < 0 && end_t_ > 0) {
                TimerHandler();
            }
            continue;
        }

        // Process all active channels
        for(auto& ch : channels) {
            if (!ch) {
                // Skip null/expired channel entry
                std::cerr << "[Dispatcher] Skipping null Channel in channels list" << std::endl;
                continue;
            }
            try {
                ch->HandleEvent();
            } catch (const std::exception& e) {
                // Log error and close the affected channel to avoid corrupted state.
                // The connection's input buffer may have stale data from before the exception.
                std::cerr << "[Dispatcher] Error handling event: " << e.what() << std::endl;
                if (!ch->is_channel_closed()) {
                    ch->CloseChannel();
                }
            }
        }

        // Fallback timer for platforms without timerfd (macOS):
        // Run TimerHandler after processing events so it works even under load.
        // WaitForEvent has a 1s timeout, so this runs approximately once per second.
        if (is_sock_dispatcher_ && timer_fd_ < 0 && end_t_ > 0) {
            TimerHandler();
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
        std::cerr << "[Dispatcher] eventfd write failed: " << strerror(errno) << std::endl;
    }
#elif defined(__APPLE__) || defined(__MACH__)
    char buf = 1;
    ssize_t n = ::write(wakeup_pipe_[1], &buf, sizeof buf);  // Write to pipe[1]
    if (n != sizeof buf) {
        std::cerr << "[Dispatcher] pipe write failed: " << strerror(errno) << std::endl;
    }
#endif
}

void Dispatcher::HandleEventId(){
#if defined(__linux__)
    uint64_t val;
    ssize_t n = ::read(eventfd_, &val, sizeof val);
    if (n != sizeof val) {
        std::cerr << "[Dispatcher] eventfd read failed" << std::endl;
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
            std::cerr << "[Dispatcher] Task execution error: " << e.what() << std::endl;
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
    auto it = connections_.find(fd);
    if (it != connections_.end() && (!conn || it->second == conn)) {
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
    // Drain the timerfd expiration count before re-arming.
    // On Linux, timerfd stays readable until read(); without draining,
    // epoll_wait returns the timer channel continuously in a tight loop.
#if defined(__linux__)
    uint64_t expirations;
    ::read(timer_fd_, &expirations, sizeof(expirations));
#endif
    TimeStamp::ResetTimerFd(timer_fd_, end_t_);

    if(is_sock_dispatcher()){
        std::cout << "[Dispatcher - " << std::this_thread::get_id() << "]: reset timer" << std::endl;

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

        // Remove timed-out connections from our map
        for(int fd : timeout_fds){
            connections_.erase(fd);
        }

        // Close timed-out connections.
        // Call deadline timeout callback first (allows HTTP layer to send 408),
        // then use CloseAfterWrite so the 408 response flushes before close.
        // CloseAfterWrite → CallCloseCb → HandleCloseConnection handles
        // identity-checked removal from NetServer::connections_.
        // No separate timer callback needed (bare-fd removal is unsafe under fd reuse).
        for(auto& conn : timed_out_conns){
            conn->CallDeadlineTimeoutCb();
            conn->CloseAfterWrite();
        }
    }
}