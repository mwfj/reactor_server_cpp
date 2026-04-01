#include "../include/threadpool.h"

// Process-level collector for worker threads that can't be joined inline
// (self-join from destructor). Joined at process exit to avoid use-after-free.
static std::mutex s_orphan_mtx;
static std::vector<std::thread>* s_orphan_threads = nullptr;

static void JoinOrphans() {
    if (s_orphan_threads) {
        for (auto& t : *s_orphan_threads) {
            if (t.joinable()) t.join();
        }
        delete s_orphan_threads;
        s_orphan_threads = nullptr;
    }
}

static void AdoptOrphan(std::thread t) {
    std::lock_guard<std::mutex> lk(s_orphan_mtx);
    if (!s_orphan_threads) {
        s_orphan_threads = new std::vector<std::thread>();
        std::atexit(JoinOrphans);
    }
    s_orphan_threads->push_back(std::move(t));
}

ThreadPool::~ThreadPool() {
    Stop();
    JoinPendingSelfStop();
}

void ThreadPool::JoinPendingSelfStop() {
    if (pending_self_stop_.joinable()) {
        if (pending_self_stop_.get_id() == std::this_thread::get_id()) {
            // Self-join would deadlock. Move the thread to a process-level
            // collector that joins it at exit. This keeps the thread alive
            // without accessing the (potentially freed) pool object — the
            // thread is already past its Run() loop and only unwinding.
            AdoptOrphan(std::move(pending_self_stop_));
        } else {
            pending_self_stop_.join();
        }
    }
}

void ThreadPool::LogError(const std::string& msg) {
    if (error_logger_) {
        error_logger_(msg);
    } else {
        std::cerr << msg << std::endl;
    }
}

inline void ThreadPool::SetThreadWorkerNum(int nums, bool /*set_by_init*/){
    thread_nums = nums;
}

inline int ThreadPool::GetThreadWorkerNum(){
    return thread_nums;
}

void ThreadPool::Init(int worker_nums){
    std::lock_guard<std::mutex> lck(mtx_);
    SetThreadWorkerNum(worker_nums, true);
}

void ThreadPool::Init(){
    std::lock_guard<std::mutex> lck(mtx_);
    // init the number of thread worker same as the CPU core number
    unsigned int suggested_workers = std::thread::hardware_concurrency() >> 1;
    if(suggested_workers == 0) {
        suggested_workers = DEFAULT_THREAD_NUMS;
    }
    SetThreadWorkerNum(static_cast<int>(suggested_workers), true);
}


void ThreadPool::Start(){
    // Join any pending self-stop worker from a previous Stop() cycle.
    // This acts as a barrier: the old worker has fully exited before
    // new workers are created, preventing untracked extra workers.
    JoinPendingSelfStop();

    std::lock_guard<std::mutex> lck(mtx_);

    if(GetThreadWorkerNum() <= 0) {
        throw std::runtime_error("Thread Pool Start failed: thread count <= 0");
    }

    if(!workers_.empty()){
        throw std::runtime_error("Thread Pool already started");
    }

    is_running_.store(true);
    workers_.reserve(static_cast<std::size_t>(GetThreadWorkerNum()));

    for(int idx = 0; idx < GetThreadWorkerNum(); idx ++){
        workers_.emplace_back(&ThreadPool::Run, this);
    }
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

    // Wait for all worker threads to finish.
    // If Stop() is called from a worker thread (e.g., a request handler
    // calling HttpServer::Stop()), move the self-thread to pending_self_stop_
    // instead of joining (self-join would deadlock). The pending thread is
    // joined at the next safe point: ~ThreadPool() or Start(). This avoids
    // detach races where the worker outlives the pool.
    auto self_id = std::this_thread::get_id();
    for(std::thread& th : workers_){
        if(th.joinable()) {
            if (th.get_id() == self_id) {
                pending_self_stop_ = std::move(th);
            } else {
                th.join();
            }
        }
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
}

void ThreadPool::Run() {
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
                LogError(std::string("[ThreadPool] SetValue() failed: ") + e.what());
            } catch(...) {
                LogError("[ThreadPool] SetValue() failed with unknown exception");
            }
        } catch(...) {
            // Task execution failed - capture exception
            std::exception_ptr ex = std::current_exception();
            try{
                if(ex) {
                    std::rethrow_exception(ex);
                }
            } catch (const std::exception& e){
                LogError(std::string("[ThreadPool] Task failed: ") + e.what());
            } catch(...) {
                LogError("[ThreadPool] Task failed with unknown exception");
            }

            // Set exception - wrap in try-catch to prevent thread termination
            try {
                task->SetException(std::move(ex));
            } catch(const std::exception& e) {
                LogError(std::string("[ThreadPool] SetException() failed: ") + e.what());
            } catch(...) {
                LogError("[ThreadPool] SetException() failed with unknown exception");
            }
        }
        // running_threads_ automatically decremented by RunningGuard destructor
    }
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
