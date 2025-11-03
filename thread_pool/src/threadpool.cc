#include "../include/threadpool.h"
#include <iostream>
#include <stdexcept>

ThreadPool::~ThreadPool() {
    // RAII: Ensure threads are properly stopped and joined during destruction
    // This is safe because Stop() is idempotent - calling it multiple times is harmless
    Stop();
}

inline void ThreadPool::SetThreadWorkerNum(int nums, bool set_by_init){
    thread_nums = nums;
    if(!set_by_init)
        std::cout << "Set Max Worker Number to: " << nums << std::endl;
}

inline int ThreadPool::GetThreadWorkerNum(){
    return thread_nums;
}

void ThreadPool::Init(int worker_nums){
    std::lock_guard<std::mutex> lck(mtx_);
    SetThreadWorkerNum(worker_nums, true);
    std::cout << "[" << std::this_thread::get_id() << "]: Thread Pool Init, worker number: " << GetThreadWorkerNum() << std::endl;
}

void ThreadPool::Init(){
    std::lock_guard<std::mutex> lck(mtx_);
    // init the number of thread worker same as the CPU core number
    unsigned int suggested_workers = std::thread::hardware_concurrency() >> 1;
    if(suggested_workers == 0) {
        std::cout << "Invalid core numbers, set to default number: "<< DEFAULT_THREAD_NUMS << "\n";
        suggested_workers = DEFAULT_THREAD_NUMS;
    }
    SetThreadWorkerNum(static_cast<int>(suggested_workers), true);
    std::cout << "[" << std::this_thread::get_id() << "]: Thread Pool Init, worker number: " << GetThreadWorkerNum() << std::endl;
}


void ThreadPool::Start(){
    std::lock_guard<std::mutex> lck(mtx_);

    if(GetThreadWorkerNum() <= 0) {
        std::cerr << "Thread Pool Start failed: thread count <= 0" << std::endl;
        throw std::runtime_error("Thread Pool Start failed: thread count <= 0");
    }

    if(!workers_.empty()){
        std::cerr << "Thread Pool already started" << std::endl;
        throw std::runtime_error("Thread Pool already started");
    }

    is_running_.store(true);
    workers_.reserve(static_cast<std::size_t>(GetThreadWorkerNum()));

    for(int idx = 0; idx < GetThreadWorkerNum(); idx ++){
        workers_.emplace_back(&ThreadPool::Run, this);
    }
    std::cout << "[" << std::this_thread::get_id() << "]: ThreadPool Start" << std::endl;
}

void ThreadPool::Stop(){
    // Make Stop() idempotent - safe to call multiple times
    // Use compare_exchange to atomically check and set is_running_
    bool expected = true;
    if (!is_running_.compare_exchange_strong(expected, false)) {
        // Already stopped (is_running_ was already false)
        return;
    }

    // CRITICAL: Acquire mutex before notifying to prevent lost wakeup
    // This ensures that any thread checking the predicate in GetTask()
    // either sees is_running_==false OR receives the notification
    {
        std::lock_guard<std::mutex> lck(mtx_);
        // Lock establishes happens-before relationship with cv_.wait()
    }
    // Signal all worker threads to exit (safe to call after releasing lock)
    cv_.notify_all();

    // Wait for all worker threads to finish
    for(std::thread& th : workers_){
        if(th.joinable())
            th.join();
    }

    {
        std::lock_guard<std::mutex> lck(mtx_);
        // throw exception for awaiting tasks
        for(const auto& task : tasks_){
            task -> SetException(std::make_exception_ptr(std::runtime_error("ThreadPool Stopped")));
        }
        tasks_.clear();
        workers_.clear();
    }

    std::cout << "[" << std::this_thread::get_id() << "]: ThreadPool Stopped" << std::endl;
}

void ThreadPool::Run() {
    std::cout << "[" << std::this_thread::get_id() << "]: ThreadPool Begin Running" << "\n";

    while(is_running()){
        std::shared_ptr<ThreadTaskInterface> task = GetTask();

        // check the running status if no task get
        if(!task){
            if(!is_running())
                break;
            continue;
        }

        // RAII guard to ensure running_threads_ is always decremented
        running_threads_++;
        struct RunningGuard {
            std::atomic<int>& counter;
            RunningGuard(std::atomic<int>& c) : counter(c) {}
            ~RunningGuard() { counter--; }
        } guard(running_threads_);

        try{
            // Execute task
            int res = task->RunTask();

            // Set result - wrap in try-catch to prevent thread termination
            try {
                task->SetValue(res);
            } catch(const std::exception& e) {
                std::cerr << "[ThreadPool] SetValue() failed: " << e.what() << std::endl;
            } catch(...) {
                std::cerr << "[ThreadPool] SetValue() failed with unknown exception" << std::endl;
            }
        } catch(...) {
            // Task execution failed - capture exception
            std::exception_ptr ex = std::current_exception();
            try{
                if(ex) {
                    std::rethrow_exception(ex);
                }
            } catch (const std::exception& e){
                std::cerr << "[ThreadPool] Task failed: " << e.what() << std::endl;
            } catch(...) {
                std::cerr << "[ThreadPool] Task failed with unknown exception" << std::endl;
            }

            // Set exception - wrap in try-catch to prevent thread termination
            try {
                task->SetException(std::move(ex));
            } catch(const std::exception& e) {
                std::cerr << "[ThreadPool] SetException() failed: " << e.what() << std::endl;
            } catch(...) {
                std::cerr << "[ThreadPool] SetException() failed with unknown exception" << std::endl;
            }
        }
        // running_threads_ automatically decremented by RunningGuard destructor
    }
    std::cout << "[" << std::this_thread::get_id() << "]: End Run" << std::endl;
}

void ThreadPool::AddTask(std::shared_ptr<ThreadTaskInterface> task) {
    {
        std::lock_guard<std::mutex> lck(mtx_);
        if(!is_running())
            throw std::runtime_error("ThreadPool has been stopped");
        task -> SetRunningChecker([this] {return is_running();});
        tasks_.push_back(std::move(task));
    }
    cv_.notify_one();
}

std::shared_ptr<ThreadTaskInterface> ThreadPool::GetTask() {
    std::unique_lock<std::mutex> lck(mtx_);
    cv_.wait(lck, [this]{ return !is_running() || !tasks_.empty();});

    if(tasks_.empty()){
        return nullptr;
    }

    std::shared_ptr<ThreadTaskInterface> task = std::move(tasks_.front());
    tasks_.pop_front();
    return task;
}
