#pragma once
#include "common.h"
#include "event_handler.h"
// <deque>, <queue>, <functional>, <chrono>, <mutex>, <map>, <atomic>
// provided by common.h
#include "callbacks.h"

// Forward declarations to break circular dependency
class Channel;
class ConnectionHandler;

class Dispatcher : public std::enable_shared_from_this<Dispatcher> {
private:
    // CRITICAL: Must be atomic to prevent data race between StopEventLoop() and RunEventLoop()
    // When Stop() sets is_running_ = false from one thread, the event loop thread MUST see
    // this change immediately. Without atomic, CPU caching can cause the loop to never exit.
    std::atomic<bool> is_running_{false};
    std::atomic<bool> was_stopped_{false};  // Set on StopEventLoop, never cleared
    std::unique_ptr<EventHandler> ep_;  // Sole owner of EventHandler
    void set_running_state(bool);

    std::atomic_bool is_sock_dispatcher_;

    std::mutex mtx_;

    // The feature task worker sent the task back to
    // the socket worker task letting to continue to do
    // the I/O related job
    // Note: Must be shared_ptr because Channel uses shared_from_this()
    std::shared_ptr<Channel> wake_channel_;
#if defined(__linux__)
    int eventfd_;  // Linux uses eventfd for wakeup
#elif defined(__APPLE__) || defined(__MACH__)
    int wakeup_pipe_[2];  // macOS uses pipe for wakeup (pipe[0]=read, pipe[1]=write)
#endif
    std::deque<std::function<void()>> task_que_;

    // Delayed task queue — min-heap ordered by deadline (earliest first).
    // Used by EnQueueDelayed() for timer-based retry backoff and other
    // sub-second deferred work. Separate from task_que_ to avoid
    // accelerating EnQueueDeferred users (see Decision 7 in
    // TIMER_BASED_RETRY_BACKOFF_DESIGN.md).
    struct DelayedTask {
        std::chrono::steady_clock::time_point deadline;
        // mutable: allows move-out from priority_queue::top() (which
        // returns const&) without const_cast. Safe because callback is
        // not part of the heap's comparison logic (only deadline is).
        mutable std::function<void()> callback;
        bool operator>(const DelayedTask& other) const {
            return deadline > other.deadline;
        }
    };
    std::priority_queue<DelayedTask, std::vector<DelayedTask>,
                        std::greater<DelayedTask>> delayed_tasks_;

    // Wall-clock gate for the opportunistic task_que_ drain in the
    // channels.size()==0 path. Ensures EnQueueDeferred users get ~1s
    // cadence even when delayed tasks shorten the WaitForEvent timeout.
    // Accessed only from the event loop thread — no atomic needed.
    std::chrono::steady_clock::time_point last_deferred_drain_{};

    std::atomic<std::thread::id> thread_id_{};

    // Connection Timer
#if defined(__linux__)
    int timer_fd_;                             // Linux: timerfd as a Channel in epoll
    std::shared_ptr<Channel> timer_channel_;   // Must be shared_ptr because Channel uses shared_from_this()
#endif
    // macOS: EVFILT_TIMER registered directly on kqueue — no fd or Channel needed.
    int end_t_; // the time interval (seconds) that timer should trigger
    std::chrono::seconds timeout_; // Timeout duration for connection handler
    
    // Timer callback
    CALLBACKS_NAMESPACE::DispatcherCallbacks callbacks_;

    // Manage the connection in a dispatcher(Eventloop)
    std::map<int, std::shared_ptr<ConnectionHandler>> connections_;

    std::atomic<int> dispatcher_index_{-1};
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
    bool was_stopped() const { return was_stopped_.load(std::memory_order_acquire); }
    bool is_on_loop_thread() const {
        std::thread::id tid = thread_id_.load(std::memory_order_acquire);
        if (tid == std::thread::id{}) return false;  // not yet running -> assume off-thread
        return std::this_thread::get_id() == tid;
    }
    bool is_dispatcher_thread() const { return is_on_loop_thread(); }
    bool is_sock_dispatcher() const { return is_sock_dispatcher_.load(); }

    void SetDispatcherIndex(int idx) { dispatcher_index_.store(idx, std::memory_order_release); }
    int dispatcher_index() const { return dispatcher_index_.load(std::memory_order_acquire); }

    void UpdateChannel(std::shared_ptr<Channel>);
    void RemoveChannel(std::shared_ptr<Channel>);
    void UpdateChannelInLoop(std::shared_ptr<Channel>);
    void RemoveChannelInLoop(std::shared_ptr<Channel>);

    void WakeUp();
    void HandleEventId();
    // Process all queued tasks without requiring a wakeup signal.
    // Used by stop-from-handler drain to pump enqueued tasks while
    // the event loop is paused (blocked in a handler callback).
    void ProcessPendingTasks();
    void EnQueue(std::function<void()>);
    // Enqueue a task without waking the event loop. The task runs on the
    // next natural WaitForEvent timeout (~1s) or next HandleEventId from
    // another EnQueue. Used for deferred retries that need backoff.
    void EnQueueDeferred(std::function<void()>);
    // Schedule a task to run after `delay` milliseconds. The task runs on
    // this dispatcher's event loop thread. Safe to call from any thread
    // (uses mtx_ + WakeUp for off-thread). Tasks pending at shutdown are
    // silently discarded during the final drain.
    //
    // LIFETIME CONTRACT (same rules as EnQueue/EnQueueDeferred):
    //   - Capture shared_ptr or weak_ptr in callbacks, NEVER raw `this`.
    //   - If the captured object uses an inflight-guard pattern (like
    //     PoolPartition::MakeInflightGuard), the guard MUST be captured
    //     so the destructor's wait-for-zero barrier works correctly.
    //   - The callback must be self-contained — no dangling references
    //     to stack variables or objects with shorter lifetimes.
    // Returns true if the task was enqueued, false if dropped (dispatcher
    // stopped). Callers MUST handle the false case — e.g., deliver an
    // error response — since the callback will never fire.
    bool EnQueueDelayed(std::function<void()> fn,
                        std::chrono::milliseconds delay);
    void AddConnection(std::shared_ptr<ConnectionHandler>);
    void RemoveTimerConnection(int fd);
    void RemoveTimerConnectionIfMatch(int fd, std::shared_ptr<ConnectionHandler> conn);
    void ClearConnections();

    void SetTimerCB(CALLBACKS_NAMESPACE::DispatcherTimerCallback);
    void SetTimeOutTriggerCB(CALLBACKS_NAMESPACE::DispatcherTOTriggerCallback);
    void TimerHandler();

    // Update idle timeout duration at runtime. Must be called on the
    // dispatcher thread (via EnQueue) to avoid racing with TimerHandler.
    void SetTimeout(std::chrono::seconds timeout) { timeout_ = timeout; }

    // Get the current timer scan interval (seconds).
    int GetTimerInterval() const { return end_t_; }

    // Update timer scan interval at runtime and re-arm the timerfd so the
    // new cadence takes effect immediately (not deferred to the next fire).
    // Must be called on the dispatcher thread (via EnQueue).
    void SetTimerInterval(int interval);
};
