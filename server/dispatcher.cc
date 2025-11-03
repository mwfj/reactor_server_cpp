#include "dispatcher.h"
#include "channel.h"
#include "connection_handler.h"

Dispatcher::Dispatcher() :
    ep_(std::unique_ptr<EpollHandler>(new EpollHandler())),
    is_sock_dispatcher_(false),
    eventfd_(::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC)),
    timer_fd_(-1),
    end_t_(0),
    timeout_(std::chrono::seconds(0))
{
    if (eventfd_ == -1) {
        throw std::runtime_error(std::string("eventfd creation failed: ") + strerror(errno));
    }
    // Note: wake_channel_ initialization moved to Initialize()
    // Cannot use shared_from_this() in constructor
}

Dispatcher::Dispatcher(bool _is_sock,  int _end_t, std::chrono::seconds _timeout):
    ep_(std::unique_ptr<EpollHandler>(new EpollHandler())),
    is_sock_dispatcher_(_is_sock),
    eventfd_(::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC)),
    end_t_(_end_t),
    timeout_(_timeout)
{
    if (eventfd_ == -1) {
        throw std::runtime_error(std::string("eventfd creation failed: ") + strerror(errno));
    }
    // Note: wake_channel_ initialization moved to Init()
    // Cannot use shared_from_this() in constructor
}

void Dispatcher::Init() {
    // Create wake_channel_ for eventfd now that shared_from_this() is safe
    // Must use shared_ptr because Channel calls shared_from_this() in its methods
    wake_channel_ = std::make_shared<Channel>(shared_from_this(), eventfd_);
    wake_channel_->SetReadCallBackFn(std::bind(&Dispatcher::HandleEventId, this)); // Should we replace std::bind with lambda here?
    wake_channel_->EnableReadMode();

    // Only initialize timer if this is a socket dispatcher with timeout configured
    if (is_sock_dispatcher_ && timeout_.count() > 0) {
        timer_fd_ = TimeStamp::GenTimerFd(timeout_, std::chrono::nanoseconds(0));
        timer_channel_ = std::make_shared<Channel>(shared_from_this(), timer_fd_);
        timer_channel_->SetReadCallBackFn(std::bind(&Dispatcher::TimerHandler, this));
        timer_channel_->EnableReadMode();
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

    thread_id_ = std::this_thread::get_id();

    while(is_running()){
        // Use 1000ms timeout instead of blocking indefinitely
        // This allows the server to check is_running() periodically
        std::vector<std::shared_ptr<Channel>> channels = ep_->WaitForEvent(1000);

        // If no events, just continue loop (don't shutdown!)
        // The timeout is for periodic checking, not termination
        if(channels.size() == 0){
            // Optional: Call timeout callback if set (but don't stop the loop)
            if(timeout_trigger_callback_){
                timeout_trigger_callback_(shared_from_this());
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
                // Log error but continue serving other clients
                // Don't re-throw - just log and continue processing other events
                std::cerr << "[Dispatcher] Error handling event: " << e.what() << std::endl;
            }
        }

    }
}

void Dispatcher::StopEventLoop(){
    set_running_state(false);
    WakeUp();  // Wake up epoll_wait() immediately for fast shutdown
}

void Dispatcher::UpdateChannel(std::shared_ptr<Channel> ch){
    // Don't call ep_->UpdateEvent() here - UpdateChannelInLoop will do it
    if(!is_running() || is_dispatcher_thread()){
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
    if(!is_running() || is_dispatcher_thread()){
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
    uint64_t val = 1;
    ssize_t n = ::write(eventfd_, &val, sizeof val);
    if (n != sizeof val) {
        std::cerr << "[Dispatcher] eventfd write failed: " << strerror(errno) << std::endl;
    }
}

void Dispatcher::HandleEventId(){
    uint64_t val;
    ssize_t n = ::read(eventfd_, &val, sizeof val);
    if (n != sizeof val) {
        std::cerr << "[Dispatcher] eventfd read failed" << std::endl;
        return;
    }

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
    {
        std::lock_guard<std::mutex> lck(mtx_);
        task_que_.push_back(fn);
    }
    WakeUp();
}

void Dispatcher::AddConnection(std::shared_ptr<ConnectionHandler> conn){
    std::lock_guard<std::mutex> lck(timer_mtx_);
    connections_[conn -> fd()] = conn;
}

void Dispatcher::SetTimerCB(std::function<void(int)> fn){
    timer_callback_ = fn;
}

void Dispatcher::SetTimeOutTriggerCB(std::function<void(std::shared_ptr<Dispatcher>)> fn){
    timeout_trigger_callback_ = fn;
}

void Dispatcher::TimerHandler(){
    TimeStamp::ResetTimerFd(timer_fd_, end_t_);

    if(is_sock_dispatcher()){
        std::cout << "[Dispatcher - " << std::this_thread::get_id() << "]: reset timer" << std::endl;

        // Collect all timed-out connection fds first to avoid iterator invalidation
        std::vector<int> timeout_fds;

        {
            // Lock before iterating to prevent data races
            std::lock_guard<std::mutex> lck(timer_mtx_);

            // Check every connection to find whether it has timeout
            for(auto& conn : connections_){
                // fd -> connection handler shared_ptr
                if(conn.second && conn.second->IsTimeOut(timeout_)){
                    timeout_fds.push_back(conn.first);
                }
            }

            // Remove timed-out connections from our map
            for(int fd : timeout_fds){
                connections_.erase(fd);
            }
        }

        // Call callback for each timed-out connection to remove from NetServer
        if(timer_callback_){
            for(int fd : timeout_fds){
                timer_callback_(fd);
            }
        }
    }
}