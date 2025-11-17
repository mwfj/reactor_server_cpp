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
    std::atomic_int running_threads_{0};
    std::atomic_bool is_running_{false};
    void Run();
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

    bool is_running() const { return is_running_; }
    int running_threads() const { return running_threads_.load(); }

    std::shared_ptr<ThreadTaskInterface> GetTask();
    void AddTask(std::shared_ptr<ThreadTaskInterface>);
};
