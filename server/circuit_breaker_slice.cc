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

std::chrono::nanoseconds CircuitBreakerSlice::ComputeOpenDuration() const {
    // Duration = base << consecutive_trips_ (shift expresses 2^n exponential).
    // `consecutive_trips_` is the number of trips observed BEFORE this one, so
    // the first trip uses 2^0 = 1x base, the second trip uses 2x, etc.
    // Callers must increment consecutive_trips_ AFTER calling this method.
    int trips = consecutive_trips_.load(std::memory_order_relaxed);
    // Saturate shift at 30 to avoid UB on huge trip counts.
    if (trips > 30) trips = 30;
    int64_t base_ms = config_.base_open_duration_ms;
    int64_t max_ms  = config_.max_open_duration_ms;
    int64_t scaled_ms = base_ms << trips;
    if (scaled_ms < base_ms /* overflow */ || scaled_ms > max_ms) {
        scaled_ms = max_ms;
    }
    return std::chrono::milliseconds(scaled_ms);
}

bool CircuitBreakerSlice::ShouldTripClosed() {
    if (consecutive_failures_ >= config_.consecutive_failure_threshold) {
        return true;
    }
    auto now = Now();
    int64_t total = window_.TotalCount(now);
    if (total < config_.minimum_volume) return false;
    int64_t fails = window_.FailureCount(now);
    // Compare without floating point: fails * 100 >= threshold * total.
    return (fails * 100) >= (static_cast<int64_t>(config_.failure_rate_threshold) * total);
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
    // Keep open_until_steady_ns_ so observers see the "last open" boundary;
    // it's cleared on transition to CLOSED.
    half_open_inflight_ = 0;
    half_open_successes_ = 0;
    half_open_saw_failure_ = false;

    logging::Get()->info(
        "circuit breaker half-open {} probes_allowed={}",
        host_label_, config_.permitted_half_open_calls);

    if (transition_cb_) {
        transition_cb_(State::OPEN, State::HALF_OPEN, "open_elapsed");
    }
}

void CircuitBreakerSlice::TransitionHalfOpenToClosed() {
    state_.store(State::CLOSED, std::memory_order_release);
    open_until_steady_ns_.store(0, std::memory_order_release);
    consecutive_trips_.store(0, std::memory_order_relaxed);
    consecutive_failures_ = 0;
    window_.Reset();
    half_open_inflight_ = 0;
    half_open_successes_ = 0;
    half_open_saw_failure_ = false;

    logging::Get()->info(
        "circuit breaker closed {} probes_succeeded={}",
        host_label_, config_.permitted_half_open_calls);

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

    trips_.fetch_add(1, std::memory_order_relaxed);

    logging::Get()->warn(
        "circuit breaker re-tripped {} trigger={} open_for_ms={} consecutive_trips={}",
        host_label_, trigger,
        std::chrono::duration_cast<std::chrono::milliseconds>(duration).count(),
        consecutive_trips_.load(std::memory_order_relaxed));

    if (transition_cb_) transition_cb_(State::HALF_OPEN, State::OPEN, trigger);
}

Decision CircuitBreakerSlice::TryAcquire() {
    // Disabled fast path — zero overhead when config.enabled=false.
    if (!config_.enabled) return Decision::ADMITTED;

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
            rejected_.fetch_add(1, std::memory_order_relaxed);
            if (config_.dry_run) {
                logging::Get()->info(
                    "[dry-run] circuit breaker would reject {} state=open",
                    host_label_);
                return Decision::REJECTED_OPEN_DRYRUN;
            }
            logging::Get()->debug(
                "circuit breaker rejected {} state=open", host_label_);
            return Decision::REJECTED_OPEN;
        }
    }

    if (s == State::HALF_OPEN) {
        if (half_open_inflight_ >= config_.permitted_half_open_calls) {
            rejected_.fetch_add(1, std::memory_order_relaxed);
            if (config_.dry_run) {
                logging::Get()->info(
                    "[dry-run] circuit breaker would reject {} state=half_open_full",
                    host_label_);
                return Decision::REJECTED_OPEN_DRYRUN;
            }
            logging::Get()->debug(
                "circuit breaker rejected {} state=half_open_full", host_label_);
            return Decision::REJECTED_OPEN;
        }
        half_open_inflight_++;
        return Decision::ADMITTED_PROBE;
    }

    // CLOSED: fast path.
    return Decision::ADMITTED;
}

void CircuitBreakerSlice::ReportSuccess(bool probe) {
    if (!config_.enabled) return;

    if (probe) {
        probe_successes_.fetch_add(1, std::memory_order_relaxed);
        // Count the completed probe regardless of saw_failure state (we still
        // decrement inflight to release the slot).
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
        if (half_open_successes_ >= config_.permitted_half_open_calls) {
            TransitionHalfOpenToClosed();
        }
        return;
    }

    // CLOSED success: reset consecutive counter, record in window.
    consecutive_failures_ = 0;
    window_.AddSuccess(Now());
}

void CircuitBreakerSlice::ReportFailure(FailureKind kind, bool probe) {
    (void)kind;  // Kind is used by higher layers for logging; slice itself
                 // treats all failures the same way for trip math.
    if (!config_.enabled) return;

    if (probe) {
        probe_failures_.fetch_add(1, std::memory_order_relaxed);
        if (half_open_inflight_ > 0) half_open_inflight_--;
        half_open_saw_failure_ = true;
        // On the last probe (or if all remaining complete) transition OPEN.
        if (half_open_inflight_ == 0) {
            TripHalfOpenToOpen("probe_fail");
        }
        return;
    }

    // CLOSED failure path.
    consecutive_failures_++;
    window_.AddFailure(Now());

    if (ShouldTripClosed()) {
        const char* trigger =
            (consecutive_failures_ >= config_.consecutive_failure_threshold)
                ? "consecutive" : "rate";
        TripClosedToOpen(trigger);
    }
}

void CircuitBreakerSlice::Reload(const CircuitBreakerConfig& new_config) {
    bool window_changed = (config_.window_seconds != new_config.window_seconds);
    config_ = new_config;
    if (window_changed) window_.Resize(new_config.window_seconds);
    // Live state preserved — operator expects new thresholds to apply to the
    // next evaluation, not to reset an in-progress trip.

    logging::Get()->info(
        "circuit breaker config applied {} enabled={} window_s={} "
        "fail_rate={} consec_threshold={}",
        host_label_, new_config.enabled, new_config.window_seconds,
        new_config.failure_rate_threshold,
        new_config.consecutive_failure_threshold);
}

void CircuitBreakerSlice::SetTransitionCallback(StateTransitionCallback cb) {
    transition_cb_ = std::move(cb);
}

}  // namespace circuit_breaker
