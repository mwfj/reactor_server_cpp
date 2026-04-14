#include "circuit_breaker/retry_budget.h"

namespace circuit_breaker {

namespace {

// Clamp floors for direct-ctor / Reload callers that bypass
// ConfigLoader::Validate(). Mirrors the hardening elsewhere in the
// circuit-breaker code (window ctor, probe budget snapshot,
// ComputeOpenDuration) so programmatic callers can't disable the
// budget by passing pathological values.
//   percent < 0          → 0 (pure min_concurrency floor, no %-based cap)
//   percent > 100        → 100 (retries capped at total in_flight)
//   min_concurrency < 0  → 0 (no floor)
int ClampPercent(int p) {
    if (p < 0) return 0;
    if (p > 100) return 100;
    return p;
}
int ClampMinConcurrency(int m) {
    return m < 0 ? 0 : m;
}

}  // namespace

RetryBudget::RetryBudget(int percent, int min_concurrency)
    : percent_(ClampPercent(percent)),
      min_concurrency_(ClampMinConcurrency(min_concurrency)) {}

RetryBudget::InFlightGuard RetryBudget::TrackInFlight() {
    in_flight_.fetch_add(1, std::memory_order_relaxed);
    return InFlightGuard(&in_flight_);
}

bool RetryBudget::TryConsumeRetry() {
    // Snapshot tuning + in_flight once — cap is computed against a
    // consistent slice. Retrying the cap math inside the CAS loop would
    // just churn without improving accuracy (in_flight is inherently a
    // moving target).
    int64_t in_flight = in_flight_.load(std::memory_order_relaxed);
    int pct = percent_.load(std::memory_order_relaxed);
    int min_conc = min_concurrency_.load(std::memory_order_relaxed);

    // cap = max(min_concurrency, in_flight * percent / 100)
    // Integer math is fine — percent is 0..100, in_flight is an int64.
    // Overflow is impossible within reasonable load levels (in_flight
    // would need to exceed ~2e16 to overflow after multiplying by 100).
    int64_t pct_cap = (in_flight * pct) / 100;
    int64_t cap = pct_cap > min_conc ? pct_cap : min_conc;

    // Atomically reserve a slot: load current, verify under cap, CAS up
    // by 1. Separate load + fetch_add would let N concurrent callers
    // all observe current < cap and all increment past the cap — under
    // the cross-dispatcher load the retry budget is meant to protect
    // against, the gate would stop bounding anything.
    int64_t current = retries_in_flight_.load(std::memory_order_relaxed);
    while (current < cap) {
        if (retries_in_flight_.compare_exchange_weak(
                current, current + 1,
                std::memory_order_acq_rel,
                std::memory_order_relaxed)) {
            return true;
        }
        // CAS failure — `current` was updated with the latest value;
        // loop re-evaluates against cap. Spurious wakeups on weak CAS
        // are also handled by the retry.
    }
    retries_rejected_.fetch_add(1, std::memory_order_relaxed);
    return false;
}

void RetryBudget::ReleaseRetry() {
    retries_in_flight_.fetch_sub(1, std::memory_order_relaxed);
}

void RetryBudget::Reload(int percent, int min_concurrency) {
    percent_.store(ClampPercent(percent), std::memory_order_relaxed);
    min_concurrency_.store(ClampMinConcurrency(min_concurrency),
                           std::memory_order_relaxed);
}

}  // namespace circuit_breaker
