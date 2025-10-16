#pragma once
#include <future>
#include <exception>
#include <functional>

class ThreadTaskInterface{
private:
    friend class ThreadPool;

    std::function<bool(void)> is_running_func_ = nullptr;
    // received the asynchronized result from the thread workers
    std::promise<int> promise_;
    // set asynchronized task for thread workers
    std::future<int> future_;

    void SetValue(int);
    void SetRunningChecker(std::function<bool(void)>);
    void SetException(std::exception_ptr);

protected:
    virtual int RunTask() = 0;
    bool is_running() const;

public:
    ThreadTaskInterface();
    virtual ~ThreadTaskInterface() = default;
    int GetValue();
};