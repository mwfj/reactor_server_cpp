#include "../include/threadtask.h"

ThreadTaskInterface::ThreadTaskInterface()
    :future_(promise_.get_future()) {}

int ThreadTaskInterface::GetValue() {
    return future_.get();
}

bool ThreadTaskInterface::is_running() const {
    return is_running_func_ && is_running_func_();
}

void ThreadTaskInterface::SetValue(int val) {
    try{
        promise_.set_value(val);
    } catch (const std::future_error&){
        // promise already satisfied or retrieved; ignore to keep shutdown robust
    }
}

void ThreadTaskInterface::SetRunningChecker(std::function<bool(void)> checker_fn){
    is_running_func_ = checker_fn;
}

void ThreadTaskInterface::SetException(std::exception_ptr ex){
    try{
        promise_.set_exception(std::move(ex));
    } catch (const std::future_error&){
        // promise already satisfied or retrieved; ignore to keep shutdown robust
    }
}
