#pragma once

#include "common.h"
#include <time.h>

class TimeStamp{
private:
    // Use steady_clock for idle timeout tracking — immune to NTP/wall-clock
    // adjustments that can spuriously expire or prolong connections.
    std::chrono::steady_clock::time_point time_;
public:
    TimeStamp();
    ~TimeStamp() = default;

    static TimeStamp Now();
    static int GenTimerFd(std::chrono::seconds sec, std::chrono::nanoseconds nsec);
    static void ResetTimerFd(int&, int);

    bool IsTimeOut(std::chrono::seconds duration) const;
};
