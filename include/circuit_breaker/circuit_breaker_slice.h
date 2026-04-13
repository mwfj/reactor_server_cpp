#pragma once

#include "common.h"
#include "config/server_config.h"
#include "circuit_breaker/circuit_breaker_state.h"
#include "circuit_breaker/circuit_breaker_window.h"
// <chrono>, <atomic>, <string> provided by common.h

namespace circuit_breaker {

// One per-dispatcher slice of the breaker state for a given upstream host.
// Dispatcher-thread-local for hot-path correctness: TryAcquire, ReportSuccess,
// ReportFailure must only be called on the dispatcher that owns this slice.
//
// Observability counters (`trips_`, `rejected_`, etc.) are atomic so other
// threads can snapshot them without synchronization. Everything else is
// plain (no atomics) — single-writer, single-reader.
class CircuitBreakerSlice {
public:
    // `time_source` defaults to steady_clock::now. Tests inject a mock clock.
    using TimeSource = std::function<std::chrono::steady_clock::time_point()>;

    CircuitBreakerSlice(std::string host_label,
                        size_t dispatcher_index,
                        const CircuitBreakerConfig& config,
                        TimeSource time_source = nullptr);

    // Non-copyable, non-movable: slices are pinned in a Host's vector and
    // callbacks capture raw pointers.
    CircuitBreakerSlice(const CircuitBreakerSlice&) = delete;
    CircuitBreakerSlice& operator=(const CircuitBreakerSlice&) = delete;

    // Hot-path decision. Consults state + (if applicable) advances OPEN→HALF_OPEN
    // and reserves a probe slot. Increments `rejected_` on REJECTED_OPEN*
    // (both enforce and dry-run). Emits reject log on dispatcher thread.
    Decision TryAcquire();

    // Outcome reporting. `probe` is true iff the paired TryAcquire returned
    // ADMITTED_PROBE. Report* may trigger state transitions and fire the
    // transition callback.
    void ReportSuccess(bool probe);
    void ReportFailure(FailureKind kind, bool probe);

    // Apply a new config (called on this slice's dispatcher thread).
    // Preserves live state (CLOSED/OPEN/HALF_OPEN). Resets window if
    // window_seconds changed.
    void Reload(const CircuitBreakerConfig& new_config);

    // Install or replace the state-transition callback. Safe to call before
    // any traffic (startup wiring) OR after a hot-reload flips enabled=false→true.
    // Callers must invoke on this slice's dispatcher thread.
    void SetTransitionCallback(StateTransitionCallback cb);

    // Observability — safe from any thread.
    State    CurrentState() const { return state_.load(std::memory_order_acquire); }
    int64_t  Trips()            const { return trips_.load(std::memory_order_relaxed); }
    int64_t  Rejected()         const { return rejected_.load(std::memory_order_relaxed); }
    int64_t  ProbeSuccesses()   const { return probe_successes_.load(std::memory_order_relaxed); }
    int64_t  ProbeFailures()    const { return probe_failures_.load(std::memory_order_relaxed); }
    // Rejections specifically caused by HALF_OPEN being out of probe slots
    // (subset of `Rejected()`). Lets dashboards distinguish "backoff has not
    // elapsed" from "probing, no capacity left".
    int64_t  RejectedHalfOpenFull() const {
        return rejected_half_open_full_.load(std::memory_order_relaxed);
    }

    const std::string& host_label() const { return host_label_; }
    size_t dispatcher_index() const { return dispatcher_index_; }

    // Current open_until time. Used by ProxyTransaction to compute
    // Retry-After. Returns zero ns when not OPEN.
    std::chrono::steady_clock::time_point OpenUntil() const;

private:
    // Logging label: "service=X host=Y:Z partition=N" built once.
    std::string host_label_;
    size_t dispatcher_index_;
    CircuitBreakerConfig config_;

    TimeSource time_source_;

    // Hot-path state — state_ written on dispatcher, read by observers.
    std::atomic<State> state_{State::CLOSED};
    // Nanoseconds since steady_clock epoch — 0 when not OPEN.
    std::atomic<int64_t> open_until_steady_ns_{0};
    // Count of consecutive trips (OPEN entries) since last CLOSED —
    // drives exponential backoff of open duration.
    std::atomic<int> consecutive_trips_{0};

    // Dispatcher-thread-only (no atomics).
    int consecutive_failures_ = 0;
    CircuitBreakerWindow window_;
    int half_open_inflight_ = 0;
    int half_open_successes_ = 0;
    bool half_open_saw_failure_ = false;

    // Observability counters.
    std::atomic<int64_t> trips_{0};
    std::atomic<int64_t> rejected_{0};
    std::atomic<int64_t> rejected_half_open_full_{0};
    std::atomic<int64_t> probe_successes_{0};
    std::atomic<int64_t> probe_failures_{0};

    // One-shot flag: true after the slice has emitted a higher-level
    // (info) log for the first rejection in the current OPEN/HALF_OPEN
    // cycle. Reset on transition to CLOSED and on each fresh trip. Keeps
    // per-request reject logs at debug while still surfacing the first
    // post-trip reject in default-warn operator logs. Dispatcher-thread only.
    bool first_reject_logged_for_open_ = false;

    StateTransitionCallback transition_cb_;

    // Internal transitions (dispatcher-thread).
    void TripClosedToOpen(const char* trigger);
    void TransitionOpenToHalfOpen();
    void TransitionHalfOpenToClosed();
    void TripHalfOpenToOpen(const char* trigger);

    // Emit the correct reject log line, bump counters, and return the matching
    // Decision (enforce or dry-run). Used by both the OPEN (backoff active)
    // and HALF_OPEN-full paths — keeps the three loggers/counters consistent.
    Decision RejectWithLog(const char* state_label, bool half_open_full);

    // Compute open duration for the current consecutive_trips_ value:
    // min(base * 2^consecutive_trips, max). Always >= base_open_duration_ms.
    std::chrono::nanoseconds ComputeOpenDuration() const;

    // Check whether CLOSED trip conditions are met. Called after every failure.
    bool ShouldTripClosed();

    std::chrono::steady_clock::time_point Now() const;
};

}  // namespace circuit_breaker
