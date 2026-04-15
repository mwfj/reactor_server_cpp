#include "circuit_breaker/retry_budget.h"

namespace CIRCUIT_BREAKER_NAMESPACE {

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
    // Snapshot tuning + both in-flight counters once so the cap is
    // computed against a consistent slice. Retrying the cap math inside
    // the CAS loop would just churn without improving accuracy
    // (in_flight is inherently a moving target).
    int64_t in_flight = in_flight_.load(std::memory_order_relaxed);
    int64_t retries_in_flight = retries_in_flight_.load(std::memory_order_relaxed);
    int pct = percent_.load(std::memory_order_relaxed);
    int min_conc = min_concurrency_.load(std::memory_order_relaxed);

    // cap = max(min_concurrency, (in_flight - retries_in_flight) * percent / 100)
    //
    // Subtracting retries from the in_flight base prevents the budget
    // from self-inflating: callers hold TrackInFlight() for BOTH first-
    // attempts and retries (per the documented API), so admitting a
    // retry increases in_flight_. Using the raw in_flight as the base
    // would then increase the cap, which in steady state converges
    // above the configured percentage of ORIGINAL traffic (e.g. a 20%
    // budget with retries counted in would allow ~25% of originals to
    // retry simultaneously; at higher percents the amplification grows
    // faster).
    //
    // Floor the subtraction at 0: `retries_in_flight > in_flight` is
    // transiently possible under racing increments (retry admitted and
    // in_flight guard observed before first-attempt guard's pair) —
    // clamp rather than letting the multiply go negative.
    int64_t non_retry_in_flight = in_flight - retries_in_flight;
    if (non_retry_in_flight < 0) non_retry_in_flight = 0;
    int64_t pct_cap = (non_retry_in_flight * pct) / 100;
    int64_t cap = pct_cap > min_conc ? pct_cap : min_conc;

    // Atomically reserve a slot: load current, verify under cap, CAS up
    // by 1. Separate load + fetch_add would let N concurrent callers
    // all observe current < cap and all increment past the cap — under
    // the cross-dispatcher load the retry budget is meant to protect
    // against, the gate would stop bounding anything.
    int64_t current = retries_in_flight;
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

}  // namespace CIRCUIT_BREAKER_NAMESPACE
