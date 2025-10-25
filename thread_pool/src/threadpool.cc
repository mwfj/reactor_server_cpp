#include "../include/threadpool.h"
#include <iostream>
#include <stdexcept>

inline void ThreadPool::SetMaxThreadWorkerNum(int nums, bool set_by_init){
    Max_Thread_Nums = nums;
    if(!set_by_init)
        std::cout << "Set Max Worker Number to: " << nums << std::endl;
}

inline int ThreadPool::GetMaxThreadWorkerNum(){
    return Max_Thread_Nums;
}

void ThreadPool::Init(int worker_nums){
    std::lock_guard<std::mutex> lck(mtx_);
    SetMaxThreadWorkerNum(worker_nums, true);
    std::cout << "[" << std::this_thread::get_id() << "]: Thread Pool Init, worker number: " << GetMaxThreadWorkerNum() << std::endl;
}

void ThreadPool::Init(){
    std::lock_guard<std::mutex> lck(mtx_);
    // init the number of thread worker same as the CPU core number
    unsigned int suggested_workers = std::thread::hardware_concurrency();
    if(suggested_workers == 0) {
        std::cout << "Invalid core numbers, set to default number: "<< DEFAULT_THREAD_NUMS << "\n";
        suggested_workers = DEFAULT_THREAD_NUMS;
    }
    SetMaxThreadWorkerNum(static_cast<int>(suggested_workers), true);
    std::cout << "[" << std::this_thread::get_id() << "]: Thread Pool Init, worker number: " << GetMaxThreadWorkerNum() << std::endl;
}


void ThreadPool::Start(){
    std::lock_guard<std::mutex> lck(mtx_);

    if(GetMaxThreadWorkerNum() <= 0) {
        std::cerr << "Thread Pool Start failed: thread count <= 0" << std::endl;
        throw std::runtime_error("Thread Pool Start failed: thread count <= 0");
    }

    if(!workers_.empty()){
        std::cerr << "Thread Pool already started" << std::endl;
        throw std::runtime_error("Thread Pool already started");
    }

    is_running_.store(true);
    workers_.reserve(static_cast<std::size_t>(GetMaxThreadWorkerNum()));

    for(int idx = 0; idx < GetMaxThreadWorkerNum(); idx ++){
        workers_.emplace_back(&ThreadPool::Run, this);
    }
    std::cout << "[" << std::this_thread::get_id() << "]: ThreadPool Start" << std::endl;
}

void ThreadPool::Stop(){
    is_running_.store(false);
    cv_.notify_all();

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
        running_threads_ ++;
        try{
            int res = task -> RunTask();
            task -> SetValue(res);
        }catch(...) {
            std::exception_ptr ex = std::current_exception();
            try{
                if(ex) {
                    std::rethrow_exception(ex);
                }
            } catch (const std::exception& e){
                std::cerr << e.what() << std::endl;
            } catch(...) {
                std::cerr << "Unknown task exception make threadpool stop" << "\n";
            }
            task ->SetException(std::move(ex));
        }
        running_threads_ --;
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
