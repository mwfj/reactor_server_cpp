#pragma once

#include "common.h"
// <atomic>, <cstdint> provided by common.h

namespace circuit_breaker {

// Retry budget — orthogonal to the breaker state machine.
//
// Problem: even when the circuit is CLOSED, a cascading failure on a
// healthy-looking upstream can be amplified by per-request retries. If
// 100 requests are in flight and each retries once, the upstream sees
// 200. If each retries twice, 300. A sick-but-not-dead upstream gets
// tipped over by the retry multiplier itself.
//
// Fix: cap concurrent retries as a fraction of concurrent non-retry
// traffic plus a floor for low-volume correctness.
//
//   allowed_retries = max(min_concurrency, in_flight * percent / 100)
//
// The retry budget is PER-HOST (one instance owned by CircuitBreakerHost,
// shared across its partitions — the percent math is about aggregate
// upstream load, not per-dispatcher slicing). All counters are atomic
// relaxed — snapshots can be slightly stale, which is fine for a
// capacity gate on a retry storm.
//
// Usage (Phase 5 wires this in):
//   1. On every attempt (first or retry), call TrackInFlight() and keep
//      the returned guard alive until the attempt completes. The guard
//      decrements in_flight_ in its destructor.
//   2. Before issuing a retry attempt, call TryConsumeRetry(). Proceed
//      if it returns true; reject as RETRY_BUDGET_EXHAUSTED if false.
//   3. When the retried attempt completes, call ReleaseRetry().
class RetryBudget {
public:
    // `percent` — cap retries at this % of in-flight (0-100).
    // `min_concurrency` — always allow at least this many concurrent
    // retries regardless of in_flight; ensures low-volume correctness
    // (without it, a 20% budget allows 0 retries when in_flight < 5).
    RetryBudget(int percent, int min_concurrency);

    // Non-copyable, non-movable. Lifetime-stable under its owner
    // (CircuitBreakerHost).
    RetryBudget(const RetryBudget&) = delete;
    RetryBudget& operator=(const RetryBudget&) = delete;

    // RAII guard — decrements in_flight_ on destruction. Move-only.
    class InFlightGuard {
    public:
        InFlightGuard() = default;
        explicit InFlightGuard(std::atomic<int64_t>* counter) : counter_(counter) {}
        ~InFlightGuard() {
            if (counter_) counter_->fetch_sub(1, std::memory_order_relaxed);
        }
        InFlightGuard(InFlightGuard&& o) noexcept : counter_(o.counter_) {
            o.counter_ = nullptr;
        }
        InFlightGuard& operator=(InFlightGuard&& o) noexcept {
            if (this != &o) {
                if (counter_) counter_->fetch_sub(1, std::memory_order_relaxed);
                counter_ = o.counter_;
                o.counter_ = nullptr;
            }
            return *this;
        }
        InFlightGuard(const InFlightGuard&) = delete;
        InFlightGuard& operator=(const InFlightGuard&) = delete;

    private:
        std::atomic<int64_t>* counter_ = nullptr;
    };

    // Call on every upstream attempt entry (first try OR retry). The
    // returned guard MUST outlive the attempt — typically stored as a
    // ProxyTransaction member. Never returns an empty guard.
    InFlightGuard TrackInFlight();

    // Call BEFORE issuing a retry attempt. Returns true if the retry
    // fits under the budget (retries_in_flight < cap); caller must pair
    // a true return with a matching ReleaseRetry when the retry
    // completes. Returns false if over budget — caller must NOT retry
    // and must NOT call ReleaseRetry.
    //
    // The cap is computed against a freshly-loaded in_flight snapshot:
    //   cap = max(min_concurrency, in_flight * percent / 100)
    bool TryConsumeRetry();

    // Call when a consumed retry attempt finishes. Must be paired with a
    // prior successful TryConsumeRetry.
    void ReleaseRetry();

    // Apply new tuning. Thread-safe (atomics). Preserves in-flight counters
    // — only the admission formula changes.
    void Reload(int percent, int min_concurrency);

    // Observability — safe from any thread, relaxed.
    int64_t InFlight() const {
        return in_flight_.load(std::memory_order_relaxed);
    }
    int64_t RetriesInFlight() const {
        return retries_in_flight_.load(std::memory_order_relaxed);
    }
    int64_t RetriesRejected() const {
        return retries_rejected_.load(std::memory_order_relaxed);
    }

    int percent() const { return percent_.load(std::memory_order_relaxed); }
    int min_concurrency() const {
        return min_concurrency_.load(std::memory_order_relaxed);
    }

private:
    // Tuning — atomic so Reload() is lock-free.
    std::atomic<int> percent_;
    std::atomic<int> min_concurrency_;

    // Counters (relaxed — admission decisions tolerate slightly stale
    // reads; correctness depends on each guard's fetch_sub pairing with
    // its increment, which holds under relaxed because they touch the
    // same atomic).
    std::atomic<int64_t> in_flight_{0};
    std::atomic<int64_t> retries_in_flight_{0};
    std::atomic<int64_t> retries_rejected_{0};
};

}  // namespace circuit_breaker
