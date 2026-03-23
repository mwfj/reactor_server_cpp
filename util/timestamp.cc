#include "timestamp.h"

TimeStamp::TimeStamp() : time_(std::chrono::steady_clock::now()) {}

TimeStamp TimeStamp::Now(){
    TimeStamp ts;
    ts.time_ = std::chrono::steady_clock::now();
    return ts;
}

int TimeStamp::GenTimerFd(std::chrono::seconds sec, std::chrono::nanoseconds nsec) {
#if defined(__linux__)
    int timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
    if (timer_fd == -1) {
        throw std::runtime_error("Failed to create timer fd");
    }

    struct itimerspec timer_spec;
    memset(&timer_spec, 0, sizeof(struct itimerspec));
    timer_spec.it_value.tv_sec = sec.count();
    timer_spec.it_value.tv_nsec = nsec.count();

    if (timerfd_settime(timer_fd, 0, &timer_spec, 0) == -1) {
        close(timer_fd);
        throw std::runtime_error("Failed to set timer");
    }

    return timer_fd;
#elif defined(__APPLE__) || defined(__MACH__)
    // macOS: kqueue timers are managed differently
    // For now, return -1 to indicate timer not supported on macOS
    // TODO: Implement kqueue-based timer support
    (void)sec;   // Suppress unused parameter warning
    (void)nsec;  // Suppress unused parameter warning
    return -1;
#endif
}

void TimeStamp::ResetTimerFd(int& timer_fd, int duration){
#if defined(__linux__)
    struct itimerspec timeout;
    memset(&timeout,0,sizeof(struct itimerspec));
    timeout.it_value.tv_sec = duration;
    timeout.it_value.tv_nsec = 0;
    timerfd_settime(timer_fd,0,&timeout,0);
#elif defined(__APPLE__) || defined(__MACH__)
    // macOS: kqueue timers handled differently
    // For now, no-op
    (void)timer_fd;  // Suppress unused parameter warning
    (void)duration;  // Suppress unused parameter warning
#endif
}

bool TimeStamp::IsTimeOut(std::chrono::seconds duration) const {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - time_);
    // Use >= so the timeout fires as soon as the elapsed time reaches the
    // duration. With > and truncating duration_cast, a 300s timeout would
    // require 301s elapsed (truncation of 300.9s → 300s, 300 > 300 is false).
    return elapsed >= duration;
}
