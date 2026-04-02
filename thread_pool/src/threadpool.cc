#include "../include/threadpool.h"

ThreadPool::~ThreadPool() {
    Stop();
    JoinPendingSelfStop();
}

void ThreadPool::JoinPendingSelfStop() {
    if (pending_self_stop_.joinable()) {
        if (pending_self_stop_.get_id() == std::this_thread::get_id()) {
            // Self-join scenario: destructor running on a worker thread.
            // Detach — the worker exits promptly (is_running=false) and
            // only accesses heap-allocated SharedState after this point.
            // The shared_ptr<SharedState> captured in Run() keeps it alive.
            // Detach is safe here because there are no pool-local members
            // accessed after Stop() returns from the task.
            pending_self_stop_.detach();
        } else {
            pending_self_stop_.join();
        }
    }
}

void ThreadPool::LogError(const std::string& msg) {
    std::lock_guard<std::mutex> lk(state_->logger_mtx);
    if (state_->error_logger) {
        state_->error_logger(msg);
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
    std::lock_guard<std::mutex> lck(state_->mtx);
    SetThreadWorkerNum(worker_nums, true);
}

void ThreadPool::Init(){
    std::lock_guard<std::mutex> lck(state_->mtx);
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
    // If called from a worker thread (Stop+Start in same task), the
    // barrier can't work (self-join). Reject to prevent leaked workers.
    if (pending_self_stop_.joinable() &&
        pending_self_stop_.get_id() == std::this_thread::get_id()) {
        throw std::runtime_error(
            "ThreadPool::Start() cannot be called from a worker task "
            "after Stop() — the self-stop barrier requires a different thread");
    }
    JoinPendingSelfStop();

    std::lock_guard<std::mutex> lck(state_->mtx);

    if(GetThreadWorkerNum() <= 0) {
        throw std::runtime_error("Thread Pool Start failed: thread count <= 0");
    }

    if(!workers_.empty()){
        throw std::runtime_error("Thread Pool already started");
    }

    state_->is_running.store(true);
    workers_.reserve(static_cast<std::size_t>(GetThreadWorkerNum()));

    for(int idx = 0; idx < GetThreadWorkerNum(); idx ++){
        workers_.emplace_back(&ThreadPool::Run, this);
    }
}

void ThreadPool::Stop(){
    // Make Stop() idempotent - safe to call multiple times
    // Use compare_exchange to atomically check and set is_running_
    bool expected = true;
    if (!state_->is_running.compare_exchange_strong(expected, false)) {
        // Already stopped (is_running_ was already false)
        return;
    }

    // CRITICAL: Acquire mutex before notifying to prevent lost wakeup
    // This ensures that any thread checking the predicate in GetTask()
    // either sees is_running_==false OR receives the notification
    {
        std::lock_guard<std::mutex> lck(state_->mtx);
        // Lock establishes happens-before relationship with cv.wait()
    }
    // Signal all worker threads to exit (safe to call after releasing lock)
    state_->cv.notify_all();

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
        std::lock_guard<std::mutex> lck(state_->mtx);
        // throw exception for awaiting tasks
        for(const auto& task : tasks_){
            task -> SetException(std::make_exception_ptr(std::runtime_error("ThreadPool Stopped")));
        }
        tasks_.clear();
        workers_.clear();
    }
}

void ThreadPool::Run() {
    // Capture shared state and error logger locally so they survive pool
    // destruction. If a task destroys the pool, this-> becomes dangling,
    // but these locals keep the needed state alive for the unwind path.
    auto local_state = state_;
    auto log_error = [local_state](const std::string& msg) {
        std::lock_guard<std::mutex> lk(local_state->logger_mtx);
        if (local_state->error_logger) {
            local_state->error_logger(msg);
        } else {
            std::cerr << msg << std::endl;
        }
    };

    while(local_state->is_running.load()){
        std::shared_ptr<ThreadTaskInterface> task = GetTask();

        if(!task){
            if(!local_state->is_running.load())
                break;
            continue;
        }

        local_state->running_threads++;
        struct RunningGuard {
            std::atomic<int>& counter;
            RunningGuard(std::atomic<int>& c) : counter(c) {}
            ~RunningGuard() { counter--; }
        } guard(local_state->running_threads);

        try{
            // Execute task
            int res = task->RunTask();

            // Set result - wrap in try-catch to prevent thread termination
            try {
                task->SetValue(res);
            } catch(const std::exception& e) {
                log_error(std::string("[ThreadPool] SetValue() failed: ") + e.what());
            } catch(...) {
                log_error("[ThreadPool] SetValue() failed with unknown exception");
            }
        } catch(...) {
            // Task execution failed - capture exception
            std::exception_ptr ex = std::current_exception();
            try{
                if(ex) {
                    std::rethrow_exception(ex);
                }
            } catch (const std::exception& e){
                log_error(std::string("[ThreadPool] Task failed: ") + e.what());
            } catch(...) {
                log_error("[ThreadPool] Task failed with unknown exception");
            }

            // Set exception - wrap in try-catch to prevent thread termination
            try {
                task->SetException(std::move(ex));
            } catch(const std::exception& e) {
                log_error(std::string("[ThreadPool] SetException() failed: ") + e.what());
            } catch(...) {
                log_error("[ThreadPool] SetException() failed with unknown exception");
            }
        }
        // running_threads_ automatically decremented by RunningGuard destructor
    }
}

void ThreadPool::AddTask(std::shared_ptr<ThreadTaskInterface> task) {
    {
        std::lock_guard<std::mutex> lck(state_->mtx);
        if(!is_running())
            throw std::runtime_error("ThreadPool has been stopped");
        // Capture state_ (shared_ptr) instead of this — the task's running
        // checker must survive pool destruction (self-stop scenario).
        auto s = state_;
        task -> SetRunningChecker([s] {return s->is_running.load();});
        tasks_.push_back(std::move(task));
    }
    state_->cv.notify_one();
}

std::shared_ptr<ThreadTaskInterface> ThreadPool::GetTask() {
    std::unique_lock<std::mutex> lck(state_->mtx);
    state_->cv.wait(lck, [this]{ return !is_running() || !tasks_.empty();});

    // After shutdown, don't pop tasks — Stop() will set exceptions on
    // remaining items. Without this, a queued task can still execute
    // between is_running=false and Stop()'s join.
    if(!is_running() || tasks_.empty()){
        return nullptr;
    }

    std::shared_ptr<ThreadTaskInterface> task = std::move(tasks_.front());
    tasks_.pop_front();
    return task;
}
