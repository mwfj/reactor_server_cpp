#pragma once
#include "common.h"
#include "epoll_handler.h"
#include <deque>

// Forward declarations to break circular dependency
class Channel;
class ConnectionHandler;

class Dispatcher : public std::enable_shared_from_this<Dispatcher> {
private:
    // CRITICAL: Must be atomic to prevent data race between StopEventLoop() and RunEventLoop()
    // When Stop() sets is_running_ = false from one thread, the event loop thread MUST see
    // this change immediately. Without atomic, CPU caching can cause the loop to never exit.
    std::atomic<bool> is_running_{false};
    std::unique_ptr<EpollHandler> ep_;  // Sole owner of EpollHandler
    void set_running_state(bool);

    std::atomic_bool is_sock_dispatcher_;

    std::mutex mtx_;

    // The feature task worker sent the task back to
    // the socket worker task letting to continue to do
    // the I/O related job
    // Note: Must be shared_ptr because Channel uses shared_from_this()
    std::shared_ptr<Channel> wake_channel_;
    int eventfd_;
    std::deque<std::function<void()>> task_que_;

    std::thread::id thread_id_;

    // Connection Timer
    int timer_fd_;
    int end_t_; // the time that timer should triggered
    std::chrono::seconds timeout_; // Timeout duration for connection handler

    std::shared_ptr<Channel> timer_channel_;  // Must be shared_ptr because Channel uses shared_from_this()
    std::function<void(std::shared_ptr<Dispatcher>)> timeout_trigger_callback_;

    // Manage the connection in a dispatcher(Eventloop)
    std::map<int, std::shared_ptr<ConnectionHandler>> connections_;
 
    std::function<void(int)> timer_callback_;
    std::mutex timer_mtx_;
public:
    Dispatcher();
    Dispatcher(bool, int = 60, std::chrono::seconds = std::chrono::seconds(30));
    ~Dispatcher();

    // Must be called after construction to initialize wake_channel_
    // Cannot be done in constructor because shared_from_this() doesn't work there
    void Init();

    void RunEventLoop();
    void StopEventLoop();
    bool is_running() const {return is_running_.load(std::memory_order_acquire);}
    bool is_dispatcher_thread() const { return std::this_thread::get_id() == thread_id_; }
    bool is_sock_dispatcher() const { return is_sock_dispatcher_.load(); }

    void UpdateChannel(std::shared_ptr<Channel>);
    void RemoveChannel(std::shared_ptr<Channel>);
    void UpdateChannelInLoop(std::shared_ptr<Channel>);
    void RemoveChannelInLoop(std::shared_ptr<Channel>);

    void WakeUp();
    void HandleEventId();
    void EnQueue(std::function<void()>);

    void AddConnection(std::shared_ptr<ConnectionHandler>);
    void SetTimerCB(std::function<void(int)>);
    void SetTimeOutTriggerCB(std::function<void(std::shared_ptr<Dispatcher>)>);
    void TimerHandler();
};