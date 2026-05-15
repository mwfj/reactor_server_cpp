#pragma once

#include "common.h"
// <cstdint>, <functional>, <string> provided by common.h

// Circuit breaker state machine and classification enums. Used by
// CircuitBreakerSlice, CircuitBreakerHost, CircuitBreakerManager, and
// ProxyTransaction to talk about state, admission decisions, and
// failure kinds.
//
// Three-state resilience4j-style machine:
//
//   CLOSED ──trip── OPEN ──(open_until elapsed)── HALF_OPEN ──success── CLOSED
//                                                       │
//                                                       failure
//                                                       ▼
//                                                      OPEN
namespace CIRCUIT_BREAKER_NAMESPACE {

enum class State : uint8_t {
    CLOSED    = 0,
    OPEN      = 1,
    HALF_OPEN = 2,
};

// Result of CircuitBreakerSlice::TryAcquire. Callers branch on this enum
// only — they never read the CircuitBreakerConfig directly. Dry-run policy
// is encoded in the decision, not in a separate flag.
enum class Decision : uint8_t {
    ADMITTED,              // CLOSED — proceed to pool
    ADMITTED_PROBE,        // HALF_OPEN probe slot consumed — proceed, tag as probe
    REJECTED_OPEN,         // OPEN (or HALF_OPEN-full); ENFORCE — drop with 503
    REJECTED_OPEN_DRYRUN,  // Shadow mode: slice would reject but operator asked
                           // for pass-through. Caller proceeds to pool. Counters
                           // and log already updated by TryAcquire.
};

// Reason annotation paired with every TryAcquire admission outcome.
// Reject paths stamp the matching variant; ADMITTED / ADMITTED_PROBE
// outcomes carry NONE. Callers use this to drive observability emit
// (reactor.circuit_breaker.rejected{reason}) — the Decision enum
// collapses every reject path to REJECTED_OPEN / REJECTED_OPEN_DRYRUN,
// so the reason label cannot be recovered from Decision alone.
enum class RejectReason : uint8_t {
    NONE,
    OPEN,
    OPEN_DRYRUN,
    HALF_OPEN_FULL,
    HALF_OPEN_RECOVERY_FAILING,
};

// Failure classification. Only these kinds feed ReportFailure — 4xx and
// local-capacity issues (POOL_EXHAUSTED, QUEUE_TIMEOUT, shutdown) are NOT
// reported as failures.
enum class FailureKind : uint8_t {
    CONNECT_FAILURE,
    RESPONSE_5XX,
    RESPONSE_TIMEOUT,
    UPSTREAM_DISCONNECT,
};

// Callback fired on every slice state transition. Runs on the slice's
// owning dispatcher thread. Callers can compare old/new to key off a
// specific edge (e.g. CLOSED→OPEN fires wait-queue drain).
// `trigger` is a short static string such as "consecutive" / "rate" /
// "probe_success" / "probe_fail" / "open_elapsed" for logging.
//
// TODO(post-v1): once a snapshot / admin JSON endpoint lands, convert
// `trigger` to an `enum class TransitionTrigger` so the valid set is
// compile-time checked rather than string-compared.
using StateTransitionCallback =
    std::function<void(State old_state, State new_state, const char* trigger)>;

// Convert a state to a short lowercase label for logging.
inline const char* StateName(State s) {
    switch (s) {
        case State::CLOSED:    return "closed";
        case State::OPEN:      return "open";
        case State::HALF_OPEN: return "half_open";
    }
    return "unknown";
}

// Convert a reject reason to its closed-vocab label string for
// `reactor.circuit_breaker.rejected{reason}`. Returns nullptr for NONE
// (admit paths) — caller short-circuits on null.
inline const char* RejectReasonLabel(RejectReason r) {
    switch (r) {
        case RejectReason::OPEN:                       return "open";
        case RejectReason::OPEN_DRYRUN:                return "open_dry_run";
        case RejectReason::HALF_OPEN_FULL:             return "half_open_full";
        case RejectReason::HALF_OPEN_RECOVERY_FAILING: return "half_open_recovery_failing";
        case RejectReason::NONE:                       return nullptr;
    }
    return nullptr;
}

}  // namespace CIRCUIT_BREAKER_NAMESPACE
