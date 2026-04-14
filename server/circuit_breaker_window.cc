#include "circuit_breaker/circuit_breaker_window.h"

namespace circuit_breaker {

// Map an epoch-second value into a non-negative bucket index. C++ built-in `%`
// can return a negative result when the dividend is negative — and while
// `steady_clock::time_since_epoch()` is zero-based on all mainstream
// libstdc++/libc++ implementations, the standard does not strictly guarantee a
// non-negative epoch across every implementation. The extra `+ w` and second
// `% w` costs a single add + mod on the slow (negative) branch, zero observable
// overhead on the common positive branch after the compiler eliminates the
// redundant math.
static inline size_t BucketIndex(int64_t epoch_sec, int window_seconds) {
    const int64_t w = window_seconds;
    return static_cast<size_t>(((epoch_sec % w) + w) % w);
}

CircuitBreakerWindow::CircuitBreakerWindow(int window_seconds)
    // Clamp to a minimum of 1 bucket. ConfigLoader::Validate() rejects
    // window_seconds <= 0 on the production path, but the constructor is a
    // public API and programmatic callers (tests, future direct users) may
    // bypass that validation. Without the clamp, BucketIndex() does `% 0` on
    // the first Add/TotalCount and crashes; negative values violate the ring
    // math. Matches Resize()'s clamp so the two entry points are symmetric.
    : window_seconds_(window_seconds > 0 ? window_seconds : 1),
      buckets_(static_cast<size_t>(window_seconds_)) {
}

int64_t CircuitBreakerWindow::ToEpochSec(
    std::chrono::steady_clock::time_point now) {
    return std::chrono::duration_cast<std::chrono::seconds>(
               now.time_since_epoch()).count();
}

void CircuitBreakerWindow::Advance(int64_t now_sec) {
    if (head_epoch_sec_ < 0) {
        head_epoch_sec_ = now_sec;
        return;
    }
    if (now_sec <= head_epoch_sec_) return;
    int64_t delta = now_sec - head_epoch_sec_;
    // If delta exceeds window size, everything is stale — full reset.
    if (delta >= window_seconds_) {
        for (auto& b : buckets_) { b.total = 0; b.failures = 0; }
    } else {
        // Zero buckets from head+1..now_sec inclusive.
        for (int64_t s = head_epoch_sec_ + 1; s <= now_sec; ++s) {
            size_t idx = BucketIndex(s, window_seconds_);
            buckets_[idx].total = 0;
            buckets_[idx].failures = 0;
        }
    }
    head_epoch_sec_ = now_sec;
}

void CircuitBreakerWindow::AddSuccess(
    std::chrono::steady_clock::time_point now) {
    int64_t now_sec = ToEpochSec(now);
    Advance(now_sec);
    buckets_[BucketIndex(now_sec, window_seconds_)].total++;
}

void CircuitBreakerWindow::AddFailure(
    std::chrono::steady_clock::time_point now) {
    int64_t now_sec = ToEpochSec(now);
    Advance(now_sec);
    size_t idx = BucketIndex(now_sec, window_seconds_);
    buckets_[idx].total++;
    buckets_[idx].failures++;
}

int64_t CircuitBreakerWindow::TotalCount(
    std::chrono::steady_clock::time_point now) {
    Advance(ToEpochSec(now));
    int64_t sum = 0;
    for (const auto& b : buckets_) sum += b.total;
    return sum;
}

int64_t CircuitBreakerWindow::FailureCount(
    std::chrono::steady_clock::time_point now) {
    Advance(ToEpochSec(now));
    int64_t sum = 0;
    for (const auto& b : buckets_) sum += b.failures;
    return sum;
}

void CircuitBreakerWindow::Reset() {
    for (auto& b : buckets_) { b.total = 0; b.failures = 0; }
    head_epoch_sec_ = -1;
}

void CircuitBreakerWindow::Resize(int new_window_seconds) {
    window_seconds_ = new_window_seconds > 0 ? new_window_seconds : 1;
    buckets_.assign(static_cast<size_t>(window_seconds_), Bucket{});
    head_epoch_sec_ = -1;
}

}  // namespace circuit_breaker
