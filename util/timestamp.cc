#include "timestamp.h"
#include <time.h>

TimeStamp::TimeStamp() : time_(std::chrono::system_clock::now()) {}

TimeStamp::TimeStamp(std::chrono::system_clock::time_point tp) : time_(tp) {}

TimeStamp::TimeStamp(int seconds_since_epoch)
    : time_(std::chrono::system_clock::from_time_t(static_cast<time_t>(seconds_since_epoch))) {}

std::chrono::system_clock::time_point TimeStamp::GetCurrentTS() {
    return std::chrono::system_clock::now();
}

TimeStamp TimeStamp::Now(){
    return TimeStamp(std::chrono::system_clock::now());
}

int TimeStamp::GenTimerFd(std::chrono::seconds sec, std::chrono::nanoseconds nsec) {
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
}

void TimeStamp::ResetTimerFd(int& timer_fd, int duration){
    struct itimerspec timeout;
    memset(&timeout,0,sizeof(struct itimerspec));
    timeout.it_value.tv_sec = duration;
    timeout.it_value.tv_nsec = 0;
    timerfd_settime(timer_fd,0,&timeout,0);
}

std::string TimeStamp::toString() const{
    char buf[32] = {0};
    tm local_tm;
    time_t time = std::chrono::system_clock::to_time_t(time_);
    localtime_r(&time, &local_tm);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &local_tm);
    return std::string(buf);
}

int64_t TimeStamp::toInt() const{
    auto duration = time_.time_since_epoch();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
    return seconds.count();
}

std::chrono::system_clock::time_point TimeStamp::GetTime() const {
    return time_;
}

bool TimeStamp::IsTimeOut(std::chrono::seconds duration) const {
    auto now = TimeStamp::Now().GetTime();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - time_);
    return elapsed > duration;
}