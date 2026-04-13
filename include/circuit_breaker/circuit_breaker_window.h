#pragma once

#include "common.h"
// <vector>, <chrono> provided by common.h

namespace circuit_breaker {

// Time-bucketed sliding window. One bucket per second; ring indexed by
// `epoch_sec % window_seconds`. Advances lazily on every Add* call:
// when the incoming `now` is ahead of the recorded head, all buckets
// that have aged out of the window are zeroed before the new increment.
//
// Dispatcher-thread-local by design — NO synchronization. Used from
// CircuitBreakerSlice, which is owned by a single dispatcher.
class CircuitBreakerWindow {
public:
    explicit CircuitBreakerWindow(int window_seconds);

    // Record one outcome at `now`. Advances the ring if needed.
    void AddSuccess(std::chrono::steady_clock::time_point now);
    void AddFailure(std::chrono::steady_clock::time_point now);

    // Observed counts across the current window. `now` is used to expire
    // stale buckets before reading.
    int64_t TotalCount(std::chrono::steady_clock::time_point now);
    int64_t FailureCount(std::chrono::steady_clock::time_point now);

    // Reset the ring to zero. Called on state transitions that should
    // start a fresh observation (e.g. HALF_OPEN → CLOSED).
    void Reset();

    // Reinitialize for a new window size (config reload). Resets buckets.
    void Resize(int new_window_seconds);

    int window_seconds() const { return window_seconds_; }

private:
    struct Bucket {
        int64_t total = 0;
        int64_t failures = 0;
    };

    int window_seconds_;
    std::vector<Bucket> buckets_;

    // Epoch-seconds of the most recent observation. Used to compute how
    // many buckets need to be zeroed on advance.
    int64_t head_epoch_sec_ = -1;

    // Advance the ring if `now_sec` is newer than `head_epoch_sec_`,
    // zeroing any buckets that aged out.
    void Advance(int64_t now_sec);

    // Convert a steady_clock time_point to epoch-seconds (we only
    // care about relative seconds; steady_clock is monotonic).
    static int64_t ToEpochSec(std::chrono::steady_clock::time_point now);
};

}  // namespace circuit_breaker
