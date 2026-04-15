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

    // Return value of TryAcquire. `generation` is a monotonically-increasing
    // token identifying which state-machine cycle the admission belongs to.
    // Callers MUST pass it back to Report*() unchanged so the slice can drop
    // late completions that belong to a prior cycle (crossed a state
    // transition or a Reload()-reset boundary). Without this, stale
    // completions can pollute the bookkeeping of a fresh CLOSED/HALF_OPEN
    // cycle (e.g., a pre-toggle failure incrementing the post-toggle
    // consecutive_failures_, or a pre-CLOSED'-cycle success wiping a
    // legitimate post-CLOSED' counter).
    struct Admission {
        Decision decision;
        uint64_t generation;
    };

    // Hot-path decision. Consults state + (if applicable) advances OPEN→HALF_OPEN
    // and reserves a probe slot. Increments `rejected_` on REJECTED_OPEN*
    // (both enforce and dry-run). Emits reject log on dispatcher thread.
    // Returned generation must be threaded to the paired Report*().
    Admission TryAcquire();

    // Outcome reporting. `probe` is true iff the paired TryAcquire returned
    // ADMITTED_PROBE. `admission_generation` is the generation returned by
    // the paired TryAcquire — reports from a stale generation are silently
    // dropped (observability counters still update so the outcome is not
    // lost from dashboards). Report* may trigger state transitions and fire
    // the transition callback.
    void ReportSuccess(bool probe, uint64_t admission_generation);
    void ReportFailure(FailureKind kind, bool probe, uint64_t admission_generation);

    // Neutral completion — the admission never exercised the upstream.
    // Use when the request was terminated locally before reaching the
    // upstream (POOL_EXHAUSTED after admission, shutdown draining, client
    // disconnect, RESULT_PARSE_ERROR self-attributable). Must NOT be used
    // for upstream outcomes — those go to ReportSuccess / ReportFailure.
    //
    // For probe=true (HALF_OPEN admission): returns the probe slot to the
    // cycle — decrements `half_open_inflight_` AND `half_open_admitted_`
    // so a replacement probe can still exercise the upstream within this
    // cycle's budget. Without this path, a probe that dies locally leaks
    // its slot forever, eventually wedging the slice in HALF_OPEN.
    //
    // For probe=false (CLOSED admission): no-op — CLOSED admissions have
    // no slot to release. The bool matches ReportSuccess/ReportFailure so
    // callers can use the same dispatch pattern.
    void ReportNeutral(bool probe, uint64_t admission_generation);

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
    // Number of Report* calls silently dropped because their admission
    // generation no longer matches the relevant per-domain counter
    // (closed_gen_ for non-probe, halfopen_gen_ for probe). These are
    // reports of requests admitted before a state transition or a
    // Reload()-reset. Useful for detecting mis-threaded admission tokens.
    int64_t  ReportsStaleGeneration() const {
        return reports_stale_generation_.load(std::memory_order_relaxed);
    }

    // **Test-only** accessor for the generation that the current state's
    // next admission would receive. Returns `halfopen_gen_` when state is
    // HALF_OPEN (probe admissions use that counter), otherwise `closed_gen_`
    // (non-probe admissions use that counter). This matches what TryAcquire
    // would stamp on a new admission right now.
    //
    // Production callers MUST use the generation returned by TryAcquire
    // (racy otherwise — these getters are not atomic). Tests use it as
    // ergonomic shorthand for "admission just happened in the current
    // cycle", bypassing the need to thread a token per synthetic Report*.
    uint64_t CurrentGenerationForTesting() const {
        return (state_.load(std::memory_order_acquire) == State::HALF_OPEN)
                   ? halfopen_gen_ : closed_gen_;
    }
    // Explicit per-domain getters for tests that cross state transitions
    // while holding a captured generation from a specific domain.
    uint64_t CurrentClosedGenForTesting()   const { return closed_gen_; }
    uint64_t CurrentHalfOpenGenForTesting() const { return halfopen_gen_; }

    const std::string& host_label() const { return host_label_; }
    size_t dispatcher_index() const { return dispatcher_index_; }

    // Read-only view of the live config. Dispatcher-thread-owned for
    // writes (Reload only mutates here); readers on other threads get a
    // potentially-torn read, which is acceptable for observability hints
    // like Retry-After clamping.
    const CircuitBreakerConfig& config() const { return config_; }

    // Current open_until time. Used by ProxyTransaction to compute
    // Retry-After. Returns zero ns when not OPEN.
    std::chrono::steady_clock::time_point OpenUntil() const;

    // Convenience predicate: whether OpenUntil() currently holds a
    // non-zero deadline. Avoids callers hand-rolling the zero-epoch
    // check against `time_since_epoch().count() > 0`.
    bool IsOpenDeadlineSet() const {
        return open_until_steady_ns_.load(std::memory_order_relaxed) > 0;
    }

    // Expected next open-duration in milliseconds if the slice re-trips
    // from its current state. Computed from base_open_duration_ms
    // shifted by the current `consecutive_trips_` count and clamped by
    // max_open_duration_ms. Used by the Retry-After hint path for
    // HALF_OPEN rejections, where there's no stored deadline but the
    // next OPEN window (if the probe cycle fails) will follow the
    // exponential-backoff curve — base alone would under-report after
    // multiple trips.
    //
    // Safe from any thread (atomic load of consecutive_trips_ + plain
    // reads of config_ fields). Config fields are dispatcher-owned but
    // a slightly-torn read is fine for an observability hint.
    int64_t NextOpenDurationMs() const;

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
    // Total probes admitted in the CURRENT HALF_OPEN cycle. Never decrements
    // within a cycle; resets on every cycle entry (TransitionOpenToHalfOpen)
    // and cycle exit (TransitionHalfOpenToClosed / TripHalfOpenToOpen). This
    // is what caps the cycle's probe budget — NOT half_open_inflight_, which
    // can free slots as probes complete. Gating on inflight would let an
    // early-completing probe's slot be reused, causing the cycle to admit
    // more than permitted_half_open_calls total probes. The close check
    // (successes >= snapshot) could then fire while a late-admitted probe
    // is still running; its eventual failure would drop as stale (generation
    // bumped by the transition) and the breaker would falsely mark an
    // unhealthy host recovered.
    int half_open_admitted_ = 0;
    // Probe budget for the CURRENT HALF_OPEN cycle. Snapshotted from
    // config_.permitted_half_open_calls at the moment TransitionOpenToHalfOpen
    // fires. A live Reload() may lower (or raise) the config field mid-cycle;
    // the snapshot ensures TryAcquire's slot gate and ReportSuccess's close
    // check both operate against the budget that was in effect when the probes
    // were admitted — preventing early close or indefinitely-open behaviour.
    int half_open_permitted_snapshot_ = 0;

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

    // Monotonic generation counters — one per admission domain. TryAcquire
    // stamps the admission with the domain's current value; Report* compares
    // against it and drops reports whose admission no longer matches a live
    // cycle. Split into two counters so operations that reset ONE domain
    // (e.g., window_seconds reload wipes the CLOSED rate window) don't
    // invalidate admissions in the OTHER domain (HALF_OPEN probes) — which
    // would strand probe capacity and wedge the slice in HALF_OPEN.
    //
    // Dispatcher-thread only — plain ints (no atomics needed).
    //
    //   closed_gen_   bumps on: TripClosedToOpen (CLOSED cycle ends),
    //                           Reload enabled-toggle reset,
    //                           Reload window_seconds change (rate-window wipe).
    //   halfopen_gen_ bumps on: TripHalfOpenToOpen (HALF_OPEN cycle ends),
    //                           TransitionHalfOpenToClosed (HALF_OPEN cycle ends on success),
    //                           Reload enabled-toggle reset.
    //
    // Initial value 1 (so 0 can be a "not-applicable" sentinel for
    // admissions returned from disabled slices or the REJECTED_* paths).
    uint64_t closed_gen_   = 1;
    uint64_t halfopen_gen_ = 1;

    // Rejections silently dropped because their admission generation no
    // longer matches `generation_`. Observability only; lets dashboards see
    // how often the generation guard fires.
    std::atomic<int64_t> reports_stale_generation_{0};

    StateTransitionCallback transition_cb_;

    // Internal transitions (dispatcher-thread).
    // `now` is threaded through from ReportFailure so the window_total /
    // window_fail_rate fields in the trip log reflect the SAME sliding-window
    // view that ShouldTripClosed just saw — a fresh Now() here can cross a
    // bucket boundary (especially with window_seconds=1 or under a dispatcher
    // stall) and trigger Window::Advance's full-reset, zeroing the bucket that
    // holds the failure which actually tripped the breaker.
    void TripClosedToOpen(const char* trigger,
                          std::chrono::steady_clock::time_point now);
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
    // Takes `now` as a parameter so the caller can record the failure and
    // evaluate the trip against THE SAME timestamp — otherwise a clock tick
    // between AddFailure() and ShouldTripClosed() can advance the ring and
    // wipe the just-recorded failure (critical when window_seconds is small:
    // with window=1, a 1-second delta triggers the full-reset path).
    bool ShouldTripClosed(std::chrono::steady_clock::time_point now);

    std::chrono::steady_clock::time_point Now() const;
};

}  // namespace circuit_breaker
