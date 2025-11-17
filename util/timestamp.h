#pragma once

#include "common.h"
#include <time.h>

class TimeStamp{
private:
    std::chrono::system_clock::time_point time_;
public:
    TimeStamp();
    explicit TimeStamp(std::chrono::system_clock::time_point tp);
    explicit TimeStamp(int seconds_since_epoch);
    ~TimeStamp() = default;

    static TimeStamp Now();
    static int GenTimerFd(std::chrono::seconds sec, std::chrono::nanoseconds nsec);
    static void ResetTimerFd(int&, int);
    static std::chrono::system_clock::time_point GetCurrentTS();

    std::string toString() const;
    int64_t toInt() const;  // Returns seconds since epoch
    std::chrono::system_clock::time_point GetTime() const;
    bool IsTimeOut(std::chrono::seconds duration) const;
};