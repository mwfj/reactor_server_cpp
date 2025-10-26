#pragma once
#include <deque>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <memory>
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
    ~ThreadPool() = default;

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
