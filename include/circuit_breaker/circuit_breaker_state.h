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
namespace circuit_breaker {

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
// compile-time checked rather than string-compared. See design doc §15.8.
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

}  // namespace circuit_breaker
