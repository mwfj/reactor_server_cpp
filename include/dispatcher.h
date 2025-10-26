#pragma once
#include "common.h"
#include "epoll_handler.h"
#include <deque>

// Forward declaration to break circular dependency
class Channel;

class Dispatcher : public std::enable_shared_from_this<Dispatcher> {
private:
    bool is_running_ = false;
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
public:
    Dispatcher();
    Dispatcher(bool);
    ~Dispatcher();

    // Must be called after construction to initialize wake_channel_
    // Cannot be done in constructor because shared_from_this() doesn't work there
    void Init();

    void RunEventLoop();
    void StopEventLoop();
    bool is_running() const {return is_running_;}
    bool is_dispatcher_thread() const { return std::this_thread::get_id() == thread_id_; }
    bool is_sock_dispatcher() const { return is_sock_dispatcher_.load(); }

    void UpdateChannel(std::shared_ptr<Channel>);
    void RemoveChannel(std::shared_ptr<Channel>);

    void WakeUp();
    void HandleEventId();
    void EnQueue(std::function<void()>);
};