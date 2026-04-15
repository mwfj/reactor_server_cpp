#pragma once

#include "common.h"
#include "config/server_config.h"
#include "circuit_breaker/circuit_breaker_slice.h"
#include "circuit_breaker/retry_budget.h"
// <memory>, <string>, <vector> provided by common.h

class Dispatcher;

namespace CIRCUIT_BREAKER_NAMESPACE {

// Observability snapshot of a single host, aggregated across all its
// partition slices. Safe to call from any thread (relaxed reads of
// atomic counters). Per-slice rows let dashboards detect skewed
// failure distribution across dispatchers.
struct CircuitBreakerHostSnapshot {
    std::string service_name;
    std::string host;
    int port = 0;

    struct SliceRow {
        size_t dispatcher_index = 0;
        State state = State::CLOSED;
        int64_t trips = 0;
        int64_t rejected = 0;
        int64_t probe_successes = 0;
        int64_t probe_failures = 0;
    };
    std::vector<SliceRow> slices;

    // Aggregates across slices.
    int64_t total_trips = 0;
    int64_t total_rejected = 0;
    int open_partitions = 0;
    int half_open_partitions = 0;

    // Retry budget state (per-host, shared across partitions).
    int64_t retries_in_flight = 0;
    int64_t retries_rejected = 0;
    int64_t in_flight = 0;
};

// Per-upstream-service aggregation layer. Owns:
//   - N CircuitBreakerSlice instances (one per dispatcher partition,
//     each pinned to its dispatcher for lock-free hot-path access).
//   - One RetryBudget (shared across partitions — retry %-of-in-flight
//     is a host-level metric, not per-dispatcher).
//
// Lifetime: constructed by CircuitBreakerManager at server start, lives
// for the server's lifetime. `service_name`, `host`, `port`, and the
// slice vector are never mutated post-construction (keys are stable for
// lock-free map lookup in the manager).
class CircuitBreakerHost {
public:
    // `partition_count` must equal the number of dispatcher partitions
    // in the server — typically NetServer's socket worker count or
    // upstream pool's partition count. One slice is created per
    // partition up-front.
    CircuitBreakerHost(std::string service_name,
                       std::string host,
                       int port,
                       size_t partition_count,
                       const CircuitBreakerConfig& config);

    CircuitBreakerHost(const CircuitBreakerHost&) = delete;
    CircuitBreakerHost& operator=(const CircuitBreakerHost&) = delete;

    // Hot-path lookup — returns nullptr only if `dispatcher_index` is
    // out of range (programming error). Caller must invoke the
    // returned slice's methods on its owning dispatcher thread.
    CircuitBreakerSlice* GetSlice(size_t dispatcher_index);

    // Owned retry budget. Never null for the host's lifetime; safe to
    // cache the pointer. Shared across all partitions of this host.
    RetryBudget* GetRetryBudget() { return retry_budget_.get(); }
    const RetryBudget* GetRetryBudget() const { return retry_budget_.get(); }

    // Aggregate snapshot across all slices + retry budget. Reads are
    // relaxed atomic — eventually consistent across threads, which is
    // fine for dashboards.
    CircuitBreakerHostSnapshot Snapshot() const;

    // Apply a new config to every slice. Because each slice is pinned
    // to its dispatcher thread, the call is dispatched per-partition —
    // the caller provides the dispatcher list in the same order used at
    // construction. If `dispatchers.size() != slices_.size()`, the
    // method logs an error and returns without applying.
    //
    // The retry-budget sub-fields (percent, min_concurrency) are
    // updated immediately (atomic stores, any thread) as part of this
    // call — they don't need dispatcher routing.
    void Reload(const std::vector<std::shared_ptr<Dispatcher>>& dispatchers,
                const CircuitBreakerConfig& new_config);

    // Install a transition callback on every slice. Uniform callback
    // across partitions — callers that need partition-specific behavior
    // can read `slice->dispatcher_index()` inside the callback.
    // Must be called before live traffic; thread-safety depends on
    // slice-dispatcher affinity at the Reload layer.
    void SetTransitionCallbackOnAllSlices(StateTransitionCallback cb);

    // Accessors.
    const std::string& service_name() const { return service_name_; }
    const std::string& host() const { return host_; }
    int port() const { return port_; }
    size_t partition_count() const { return slices_.size(); }

private:
    std::string service_name_;
    std::string host_;
    int port_;
    CircuitBreakerConfig config_;
    std::vector<std::unique_ptr<CircuitBreakerSlice>> slices_;
    std::unique_ptr<RetryBudget> retry_budget_;
};

}  // namespace CIRCUIT_BREAKER_NAMESPACE
