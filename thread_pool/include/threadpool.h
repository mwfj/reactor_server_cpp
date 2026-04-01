#pragma once
#include <deque>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <memory>
#include <iostream>
#include <stdexcept>
#include "threadtask.h"

class ThreadTaskInterface;

class ThreadPool{
private:
    // list of stored worker threads
    std::vector<std::thread> workers_;
    // double-end link list to store the tasks awaiting processing
    std::deque<std::shared_ptr<ThreadTaskInterface>> tasks_;

    std::mutex mtx_;
    std::condition_variable cv_;

    int thread_nums = 0;
    const int DEFAULT_THREAD_NUMS = 6;
    // Shared state: accessed by worker threads after Run() loop breaks.
    // Allocated on the heap so orphaned workers (self-destruction path)
    // don't use-after-free when the pool object is destroyed.
    struct SharedState {
        std::atomic_int running_threads{0};
        std::atomic_bool is_running{false};
        std::mutex logger_mtx;
        std::function<void(const std::string&)> error_logger;
    };
    std::shared_ptr<SharedState> state_ = std::make_shared<SharedState>();
    // When Stop() is called from a worker thread, the self-thread can't be
    // joined inline (deadlock). It is moved here and joined at the next
    // safe point (destructor or Start()) to avoid detach-related races.
    std::thread pending_self_stop_;
    void Run();
    void JoinPendingSelfStop();
    void LogError(const std::string& msg);
public:
    ThreadPool() = default;

    // Destructor automatically calls Stop() to ensure proper cleanup (RAII principle).
    // This is safe because Stop() is idempotent (can be called multiple times):
    //   - Uses atomic compare_exchange to ensure cleanup logic runs only once
    //   - Checks thread::joinable() before calling join() to prevent double-join
    //   - Returns early if already stopped, making it exception-safe
    //
    // Users can call Stop() explicitly for:
    //   - Controlled shutdown timing (e.g., before destruction)
    //   - Custom error handling during shutdown
    //   - Graceful cleanup in specific code paths
    //
    // If Stop() is called explicitly, destructor's Stop() call becomes a no-op.
    ~ThreadPool();

    void Init();
    void Init(int);
    void Start();
    void Stop();

    void SetThreadWorkerNum(int, bool);
    int GetThreadWorkerNum();

    // Set a custom error logger. Default: std::cerr. Set this to route
    // errors through spdlog when running in daemon mode (stderr is /dev/null).
    void SetErrorLogger(std::function<void(const std::string&)> logger) {
        std::lock_guard<std::mutex> lk(state_->logger_mtx);
        state_->error_logger = std::move(logger);
    }

    bool is_running() const { return state_->is_running.load(); }
    int running_threads() const { return state_->running_threads.load(); }

    std::shared_ptr<ThreadTaskInterface> GetTask();
    void AddTask(std::shared_ptr<ThreadTaskInterface>);
};
