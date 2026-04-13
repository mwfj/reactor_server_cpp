#include "circuit_breaker/circuit_breaker_window.h"

namespace circuit_breaker {

CircuitBreakerWindow::CircuitBreakerWindow(int window_seconds)
    : window_seconds_(window_seconds),
      buckets_(window_seconds > 0 ? static_cast<size_t>(window_seconds) : 1) {
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
            size_t idx = static_cast<size_t>(s % window_seconds_);
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
    size_t idx = static_cast<size_t>(now_sec % window_seconds_);
    buckets_[idx].total++;
}

void CircuitBreakerWindow::AddFailure(
    std::chrono::steady_clock::time_point now) {
    int64_t now_sec = ToEpochSec(now);
    Advance(now_sec);
    size_t idx = static_cast<size_t>(now_sec % window_seconds_);
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
