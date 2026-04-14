#include "circuit_breaker/circuit_breaker_slice.h"
#include "log/logger.h"

namespace circuit_breaker {

CircuitBreakerSlice::CircuitBreakerSlice(std::string host_label,
                                         size_t dispatcher_index,
                                         const CircuitBreakerConfig& config,
                                         TimeSource time_source)
    : host_label_(std::move(host_label)),
      dispatcher_index_(dispatcher_index),
      config_(config),
      time_source_(std::move(time_source)),
      window_(config.window_seconds) {
}

std::chrono::steady_clock::time_point CircuitBreakerSlice::Now() const {
    if (time_source_) return time_source_();
    return std::chrono::steady_clock::now();
}

std::chrono::steady_clock::time_point CircuitBreakerSlice::OpenUntil() const {
    int64_t ns = open_until_steady_ns_.load(std::memory_order_acquire);
    if (ns == 0) return std::chrono::steady_clock::time_point{};
    return std::chrono::steady_clock::time_point(std::chrono::nanoseconds(ns));
}

// Cap the left-shift exponent used to compute open duration. `1 << 30` already
// covers ~12.4 days of base open duration even before the `max_open_duration_ms`
// clamp — higher shift amounts would invoke undefined behavior on `int`.
static constexpr int MAX_OPEN_DURATION_SHIFT = 30;

// Scale factor for integer percent math: `fails * PERCENT_SCALE >= threshold * total`.
static constexpr int PERCENT_SCALE = 100;

std::chrono::nanoseconds CircuitBreakerSlice::ComputeOpenDuration() const {
    // Duration = base << consecutive_trips_ (shift expresses 2^n exponential).
    // `consecutive_trips_` is the number of trips observed BEFORE this one, so
    // the first trip uses 2^0 = 1x base, the second trip uses 2x, etc.
    // Callers must increment consecutive_trips_ AFTER calling this method.
    int trips = consecutive_trips_.load(std::memory_order_relaxed);
    if (trips > MAX_OPEN_DURATION_SHIFT) trips = MAX_OPEN_DURATION_SHIFT;
    int64_t base_ms = config_.base_open_duration_ms;
    int64_t max_ms  = config_.max_open_duration_ms;
    int64_t scaled_ms = base_ms << trips;
    if (scaled_ms < base_ms /* overflow */ || scaled_ms > max_ms) {
        scaled_ms = max_ms;
    }
    return std::chrono::milliseconds(scaled_ms);
}

bool CircuitBreakerSlice::ShouldTripClosed(
        std::chrono::steady_clock::time_point now) {
    if (consecutive_failures_ >= config_.consecutive_failure_threshold) {
        return true;
    }
    int64_t total = window_.TotalCount(now);
    if (total < config_.minimum_volume) return false;
    int64_t fails = window_.FailureCount(now);
    // Integer percent math: fails * PERCENT_SCALE >= threshold_pct * total.
    return (fails * PERCENT_SCALE) >=
           (static_cast<int64_t>(config_.failure_rate_threshold) * total);
}

void CircuitBreakerSlice::TripClosedToOpen(const char* trigger) {
    auto duration = ComputeOpenDuration();   // uses current consecutive_trips_
    consecutive_trips_.fetch_add(1, std::memory_order_relaxed);
    auto now = Now();
    auto open_until = now + duration;
    int64_t open_until_ns =
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            open_until.time_since_epoch()).count();

    open_until_steady_ns_.store(open_until_ns, std::memory_order_release);
    state_.store(State::OPEN, std::memory_order_release);

    // Reset on-trip bookkeeping.
    consecutive_failures_ = 0;
    half_open_inflight_ = 0;
    half_open_successes_ = 0;
    half_open_saw_failure_ = false;
    first_reject_logged_for_open_ = false;
    // Bump closed_gen_: non-probe admissions from the closing CLOSED cycle
    // are now stale. Late Report(false, ...) calls for those requests drop.
    // halfopen_gen_ is NOT bumped — OPEN holds no HALF_OPEN admissions.
    ++closed_gen_;

    trips_.fetch_add(1, std::memory_order_relaxed);

    logging::Get()->warn(
        "circuit breaker tripped {} trigger={} open_for_ms={} consecutive_trips={}",
        host_label_, trigger,
        std::chrono::duration_cast<std::chrono::milliseconds>(duration).count(),
        consecutive_trips_.load(std::memory_order_relaxed));

    if (transition_cb_) transition_cb_(State::CLOSED, State::OPEN, trigger);
}

void CircuitBreakerSlice::TransitionOpenToHalfOpen() {
    state_.store(State::HALF_OPEN, std::memory_order_release);
    // Clear open_until_steady_ns_ per the OpenUntil() contract ("zero when
    // not OPEN"). Leaving a stale deadline here would cause Phase 4's
    // ProxyTransaction::MakeCircuitOpenResponse to compute a Retry-After
    // from a past time_point (negative delta → floor at 1s, misleading for
    // a reject in the HALF_OPEN probe-budget-full path). Retry-After for
    // HALF_OPEN rejects is computed fresh by callers when needed.
    open_until_steady_ns_.store(0, std::memory_order_release);
    half_open_inflight_ = 0;
    half_open_successes_ = 0;
    half_open_saw_failure_ = false;
    // Snapshot the probe budget for this cycle. A live Reload() during this
    // HALF_OPEN episode may lower or raise config_.permitted_half_open_calls,
    // but TryAcquire's slot gate (Case B) and ReportSuccess's close check must
    // both operate against the budget that was in effect when probes were
    // admitted. Without the snapshot: lowering the limit causes premature close
    // (first success satisfies the reduced count → TransitionHalfOpenToClosed
    // bumps halfopen_gen_ → remaining admitted probes become stale → their
    // failures are silently dropped and the breaker falsely closes).
    //
    // Clamp to a minimum of 1. ConfigLoader::Validate() enforces >= 1 on the
    // production path, but programmatic callers (tests, future direct users)
    // that bypass validation could set permitted_half_open_calls <= 0. With
    // snapshot=0, TryAcquire's Case B check (`inflight >= snapshot`) is
    // immediately true for every probe → no probe ever admitted → no probe
    // ever completes → half_open_inflight_ stays at 0 forever → slice is
    // permanently stuck in HALF_OPEN rejecting all traffic. Matches the
    // symmetric clamp in CircuitBreakerWindow's ctor.
    int permitted = config_.permitted_half_open_calls;
    half_open_permitted_snapshot_ = permitted > 0 ? permitted : 1;
    // Reset the info-log "first reject" breadcrumb so the first rejection
    // observed in the HALF_OPEN phase surfaces at info, not debug. HALF_OPEN
    // rejection (recovery attempt failing or probe budget full) is
    // operationally distinct from OPEN rejection (still backing off) and
    // deserves its own breadcrumb in default-warn operator logs.
    first_reject_logged_for_open_ = false;
    // NOTE: neither closed_gen_ nor halfopen_gen_ is bumped here. No
    // admissions are made in OPEN — the previous HALF_OPEN cycle (if any)
    // already bumped halfopen_gen_ on its exit (TripHalfOpenToOpen) or on
    // cycle-complete (TransitionHalfOpenToClosed), so any latent stale
    // probes are already tagged. Bumping again would be redundant.

    logging::Get()->info(
        "circuit breaker half-open {} probes_allowed={}",
        host_label_, half_open_permitted_snapshot_);

    if (transition_cb_) {
        transition_cb_(State::OPEN, State::HALF_OPEN, "open_elapsed");
    }
}

void CircuitBreakerSlice::TransitionHalfOpenToClosed() {
    // Capture actual probes-succeeded BEFORE resetting — the log then reflects
    // reality instead of the configured target (the two are equal at the moment
    // of transition today, but relying on that is brittle if the transition
    // logic ever changes).
    int probes_succeeded = half_open_successes_;

    state_.store(State::CLOSED, std::memory_order_release);
    open_until_steady_ns_.store(0, std::memory_order_release);
    consecutive_trips_.store(0, std::memory_order_relaxed);
    consecutive_failures_ = 0;
    window_.Reset();
    half_open_inflight_ = 0;
    half_open_successes_ = 0;
    half_open_saw_failure_ = false;
    first_reject_logged_for_open_ = false;
    // Bump halfopen_gen_: the just-completed HALF_OPEN cycle's probe
    // admissions are now stale. closed_gen_ is NOT bumped — pre-trip
    // CLOSED admissions were already invalidated by TripClosedToOpen
    // when we left CLOSED.
    ++halfopen_gen_;

    logging::Get()->info(
        "circuit breaker closed {} probes_succeeded={}",
        host_label_, probes_succeeded);

    if (transition_cb_) {
        transition_cb_(State::HALF_OPEN, State::CLOSED, "probe_success");
    }
}

void CircuitBreakerSlice::TripHalfOpenToOpen(const char* trigger) {
    auto duration = ComputeOpenDuration();   // uses current consecutive_trips_
    consecutive_trips_.fetch_add(1, std::memory_order_relaxed);
    auto now = Now();
    auto open_until = now + duration;
    int64_t open_until_ns =
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            open_until.time_since_epoch()).count();

    open_until_steady_ns_.store(open_until_ns, std::memory_order_release);
    state_.store(State::OPEN, std::memory_order_release);

    half_open_inflight_ = 0;
    half_open_successes_ = 0;
    half_open_saw_failure_ = false;
    first_reject_logged_for_open_ = false;
    // Bump halfopen_gen_: probe admissions from the closing HALF_OPEN
    // cycle are now stale. closed_gen_ is NOT bumped — no CLOSED
    // admissions are outstanding (we came from HALF_OPEN, not CLOSED).
    ++halfopen_gen_;

    trips_.fetch_add(1, std::memory_order_relaxed);

    logging::Get()->warn(
        "circuit breaker re-tripped {} trigger={} open_for_ms={} consecutive_trips={}",
        host_label_, trigger,
        std::chrono::duration_cast<std::chrono::milliseconds>(duration).count(),
        consecutive_trips_.load(std::memory_order_relaxed));

    if (transition_cb_) transition_cb_(State::HALF_OPEN, State::OPEN, trigger);
}

CircuitBreakerSlice::Admission CircuitBreakerSlice::TryAcquire() {
    // Disabled fast path — zero overhead when config.enabled=false.
    // Use generation 0 (sentinel) since the slice won't consult it on report.
    if (!config_.enabled) {
        return Admission{Decision::ADMITTED, /*generation=*/0};
    }

    State s = state_.load(std::memory_order_acquire);

    if (s == State::OPEN) {
        // Check whether the open window has elapsed.
        int64_t open_until_ns =
            open_until_steady_ns_.load(std::memory_order_acquire);
        int64_t now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                             Now().time_since_epoch()).count();
        if (now_ns >= open_until_ns) {
            // Transition OPEN → HALF_OPEN on this thread. Because slices are
            // dispatcher-thread-pinned, no CAS is needed (a plain store is
            // safe under the single-writer invariant).
            TransitionOpenToHalfOpen();
            s = State::HALF_OPEN;
        } else {
            // Rejected admissions get generation 0 — callers must not call
            // Report* for a rejected admission, and 0 always compares stale
            // (domain gens start at 1), so an accidental Report would drop
            // safely rather than mutating state.
            return Admission{RejectWithLog("open", /*half_open_full=*/false),
                             /*generation=*/0};
        }
    }

    if (s == State::HALF_OPEN) {
        // Case A: a sibling probe already failed. Short-circuit remaining
        // admissions — the breaker is guaranteed to re-trip once in-flight
        // probes drain. This is operationally DIFFERENT from "budget
        // exhausted" (case B): probe slots may still be free, we just know
        // using them can't change the outcome. Track it with its own log
        // label and do NOT bump `rejected_half_open_full_` — that counter
        // is specifically "probing, no capacity left" for dashboards.
        if (half_open_saw_failure_) {
            return Admission{RejectWithLog("half_open_recovery_failing",
                                           /*half_open_full=*/false),
                             /*generation=*/0};
        }
        // Case B: probe budget fully in flight. "No capacity" — bump the
        // dedicated counter so dashboards can tell these two apart.
        // Use the cycle snapshot, not config_, so a live Reload() that
        // lowers permitted_half_open_calls mid-cycle doesn't change how many
        // probes were promised to this cycle.
        if (half_open_inflight_ >= half_open_permitted_snapshot_) {
            return Admission{RejectWithLog("half_open_full",
                                           /*half_open_full=*/true),
                             /*generation=*/0};
        }
        half_open_inflight_++;
        // Probe admission — stamp with halfopen_gen_.
        return Admission{Decision::ADMITTED_PROBE, halfopen_gen_};
    }

    // CLOSED: fast path — stamp with closed_gen_.
    return Admission{Decision::ADMITTED, closed_gen_};
}

Decision CircuitBreakerSlice::RejectWithLog(const char* state_label,
                                            bool half_open_full) {
    rejected_.fetch_add(1, std::memory_order_relaxed);
    if (half_open_full) {
        rejected_half_open_full_.fetch_add(1, std::memory_order_relaxed);
    }
    // First reject in this OPEN/HALF_OPEN cycle is info — gives operators
    // looking at a flurry of 503s a single high-level breadcrumb in default-
    // warn logs without flooding them. Subsequent rejects are debug.
    const bool first = !first_reject_logged_for_open_;
    if (first) first_reject_logged_for_open_ = true;

    if (config_.dry_run) {
        if (first) {
            logging::Get()->info(
                "[dry-run] circuit breaker would reject {} state={}",
                host_label_, state_label);
        } else {
            logging::Get()->debug(
                "[dry-run] circuit breaker would reject {} state={}",
                host_label_, state_label);
        }
        return Decision::REJECTED_OPEN_DRYRUN;
    }
    if (first) {
        logging::Get()->info(
            "circuit breaker rejecting {} state={} (first reject this cycle)",
            host_label_, state_label);
    } else {
        logging::Get()->debug(
            "circuit breaker rejected {} state={}", host_label_, state_label);
    }
    return Decision::REJECTED_OPEN;
}

void CircuitBreakerSlice::ReportSuccess(bool probe,
                                        uint64_t admission_generation) {
    if (!config_.enabled) return;

    if (probe) {
        // Record the completed-probe outcome for observability regardless of
        // current state — this is a signal about upstream behavior, not a
        // signal about our state machine.
        probe_successes_.fetch_add(1, std::memory_order_relaxed);

        // Generation guard: drop reports for probes admitted before the
        // current HALF_OPEN cycle. Probes use halfopen_gen_ exclusively —
        // so a window_seconds reload (bumps closed_gen_, NOT halfopen_gen_)
        // does NOT invalidate in-flight probes, which would otherwise
        // strand half_open_inflight_ at its pre-reload value and wedge the
        // slice in HALF_OPEN/half_open_full.
        if (admission_generation != halfopen_gen_) {
            reports_stale_generation_.fetch_add(1, std::memory_order_relaxed);
            return;
        }

        // Stale probe defense: we admitted this probe in HALF_OPEN, but the
        // slice may have transitioned out (e.g., `Reload()` flipped enabled,
        // `TransitionHalfOpenToClosed` already fired on sibling probes, or —
        // post-Phase 8 — an operator toggle transitioned us to CLOSED).
        // Only touch HALF_OPEN bookkeeping / fire transitions when state is
        // STILL HALF_OPEN.
        if (state_.load(std::memory_order_acquire) != State::HALF_OPEN) return;

        if (half_open_inflight_ > 0) half_open_inflight_--;
        if (half_open_saw_failure_) {
            // A sibling probe already failed; whichever probe finishes last
            // transitions to OPEN. Handle here only if this is the last probe.
            if (half_open_inflight_ == 0) {
                TripHalfOpenToOpen("probe_fail");
            }
            return;
        }
        half_open_successes_++;
        // Use the cycle snapshot so a mid-cycle Reload() that lowers the
        // limit doesn't close the breaker early (before all admitted probes
        // have reported back), silently dropping the remaining probes' failures.
        if (half_open_successes_ >= half_open_permitted_snapshot_) {
            TransitionHalfOpenToClosed();
        }
        return;
    }

    // Non-probe success path — checked against closed_gen_.
    if (admission_generation != closed_gen_) {
        reports_stale_generation_.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    // Only meaningful when state is CLOSED. If the slice has since
    // transitioned (e.g., other requests in this burst tripped it), this
    // late outcome must NOT retroactively reset `consecutive_failures_` or
    // pollute the window — a fresh CLOSED cycle after recovery would start
    // with bogus success history. (Transitions bump `closed_gen_`, so the
    // guard above catches this too; the state check is a direct guard for
    // observability clarity.)
    if (state_.load(std::memory_order_acquire) != State::CLOSED) return;
    consecutive_failures_ = 0;
    window_.AddSuccess(Now());
}

void CircuitBreakerSlice::ReportFailure(FailureKind kind, bool probe,
                                        uint64_t admission_generation) {
    (void)kind;  // Kind is used by higher layers for logging; slice itself
                 // treats all failures the same way for trip math.
    if (!config_.enabled) return;

    if (probe) {
        probe_failures_.fetch_add(1, std::memory_order_relaxed);

        // Probes use halfopen_gen_ — see matching comment in ReportSuccess.
        if (admission_generation != halfopen_gen_) {
            reports_stale_generation_.fetch_add(1, std::memory_order_relaxed);
            return;
        }

        // Stale probe defense — see matching comment in ReportSuccess above.
        if (state_.load(std::memory_order_acquire) != State::HALF_OPEN) return;

        if (half_open_inflight_ > 0) half_open_inflight_--;
        half_open_saw_failure_ = true;
        // On the last probe (or if all remaining complete) transition OPEN.
        if (half_open_inflight_ == 0) {
            TripHalfOpenToOpen("probe_fail");
        }
        return;
    }

    // Non-probe failure path — checked against closed_gen_.
    if (admission_generation != closed_gen_) {
        reports_stale_generation_.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    // Only count when CLOSED. Late failures from requests admitted in CLOSED
    // but completing after a trip must NOT re-enter `TripClosedToOpen` —
    // doing so double-increments `consecutive_trips_` (inflating
    // open_duration) and fires a spurious CLOSED→OPEN transition edge that
    // downstream consumers (wait-queue drain, snapshot telemetry) would see
    // as a ghost trip. (Again, the generation guard above catches this too;
    // keep the state check for observability clarity.)
    if (state_.load(std::memory_order_acquire) != State::CLOSED) return;

    consecutive_failures_++;
    // Capture Now() once and reuse for both the record and the trip check.
    // Separate Now() calls can cross a second boundary, letting TotalCount's
    // internal Advance() zero the bucket we just wrote — with window_seconds=1,
    // a 1-second delta trips the Advance full-reset path and the just-recorded
    // failure disappears from the ring, missing a rate trip that should fire.
    auto now = Now();
    window_.AddFailure(now);

    if (ShouldTripClosed(now)) {
        const char* trigger =
            (consecutive_failures_ >= config_.consecutive_failure_threshold)
                ? "consecutive" : "rate";
        TripClosedToOpen(trigger);
    }
}

void CircuitBreakerSlice::Reload(const CircuitBreakerConfig& new_config) {
    const bool enabled_changed = (config_.enabled != new_config.enabled);
    const bool window_changed =
        (config_.window_seconds != new_config.window_seconds);

    config_ = new_config;
    if (window_changed) {
        // Resize wipes the failure-rate ring buckets. Without bumping
        // closed_gen_ here, late completions from pre-reload CLOSED
        // admissions would pass the generation guard and repopulate the
        // freshly empty window — mixing pre-reload and post-reload traffic
        // in the rate-trip calc.
        //
        // CRUCIALLY: we bump ONLY closed_gen_, NOT halfopen_gen_.
        // window_seconds affects only the CLOSED rate window. Bumping
        // halfopen_gen_ too (as prior fix did) would invalidate in-flight
        // probes, whose late reports could no longer decrement
        // half_open_inflight_ or honor saw_failure/TripHalfOpenToOpen —
        // wedging the slice in HALF_OPEN/half_open_full with full probe
        // slots until another reset. Probe bookkeeping is untouched by
        // Resize, so preserving halfopen_gen_ keeps probes live.
        //
        // Skip when enabled_changed is also true: the full-reset branch
        // below bumps both generations as part of its larger reset.
        window_.Resize(new_config.window_seconds);
        if (!enabled_changed) {
            // Reset consecutive_failures_ alongside the window wipe.
            // Both are CLOSED-domain state from the same observation cycle.
            // Bumping closed_gen_ drops all pre-reload CLOSED reports
            // (correct — they must not seed the fresh window). But if
            // consecutive_failures_ is NOT also reset, those dropped reports
            // can no longer clear or advance the counter either, so the
            // leftover count becomes an orphaned value that mis-fires future
            // trip evaluations (spurious trip: pre-reload success was going
            // to clear the counter but got dropped, so the next real failure
            // crosses the threshold using a stale count).
            consecutive_failures_ = 0;
            ++closed_gen_;
        }
    }

    if (enabled_changed) {
        // Toggling `enabled` is an operator intent to start fresh, not a
        // runtime state transition. Without this reset:
        //   - Disabling while OPEN and re-enabling later would resume the
        //     OPEN state and reject requests even though the operator
        //     explicitly turned the breaker off and back on.
        //   - Disabling while HALF_OPEN with in-flight probes would leave
        //     inconsistent bookkeeping (inflight > 0, state=HALF_OPEN) that
        //     a subsequent enable would interpret as live probes.
        //   - Disabling mid-CLOSED-cycle and re-enabling would trip on the
        //     very next failure because consecutive_failures_ persisted.
        // Matches design doc §10.1 (enabled→disabled / disabled→enabled
        // transitions both get a clean CLOSED start).
        //
        // Silent reset — no transition callback. The change is operator-
        // initiated configuration, not a runtime state signal; firing the
        // callback would cause PoolPartition::DrainWaitQueueOnTrip-style
        // consumers (Phase 6) to spuriously drain waiters on a config edit.
        state_.store(State::CLOSED, std::memory_order_release);
        open_until_steady_ns_.store(0, std::memory_order_release);
        consecutive_trips_.store(0, std::memory_order_relaxed);
        consecutive_failures_ = 0;
        window_.Reset();
        half_open_inflight_ = 0;
        half_open_successes_ = 0;
        half_open_saw_failure_ = false;
        first_reject_logged_for_open_ = false;
        // Fresh generations for BOTH domains: this is a full reset.
        // Both pre-toggle non-probe admissions (closed_gen) and in-flight
        // probes (halfopen_gen) are invalidated — their late reports
        // silently drop, preserving clean-restart semantics.
        ++closed_gen_;
        ++halfopen_gen_;
    }
    // When `enabled` is unchanged: live state preserved — operator expects
    // new thresholds to apply to the next evaluation, not to reset an
    // in-progress trip.

    logging::Get()->info(
        "circuit breaker config applied {} enabled={} window_s={} "
        "fail_rate={} consec_threshold={}{}",
        host_label_, new_config.enabled, new_config.window_seconds,
        new_config.failure_rate_threshold,
        new_config.consecutive_failure_threshold,
        enabled_changed ? " (enabled toggled — state reset to CLOSED)" : "");
}

void CircuitBreakerSlice::SetTransitionCallback(StateTransitionCallback cb) {
    transition_cb_ = std::move(cb);
}

}  // namespace circuit_breaker
