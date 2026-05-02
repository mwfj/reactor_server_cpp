#pragma once

// ObservabilityManager — the top-level owner of TracerProvider +
// MeterProvider + the live-snapshot registry. Inherits
// `enable_shared_from_this` so per-snapshot weak_ptr captures can
// safely upgrade-or-no-op when the manager outlives a kill marshal.
//
// Per OPENTELEMETRY_DESIGN.md §6.1.2 + §13:
//
//   live_snapshots_ + live_snapshots_mtx_:
//     RegisterLiveSnapshot is the SINGLE atomic register-and-count
//     site (per r45). PopulateSnapshot is a pure field-fill helper
//     that does NOT touch inflight_finalizations_.
//
//   inflight_finalizations_:
//     Incremented INSIDE RegisterLiveSnapshot under live_snapshots_mtx_.
//     Decremented inside FinalizeFromSnapshot's CAS-from-false-to-true
//     success path (matched with live_snapshots_ deregister under the
//     same mutex). Phase 1c kill loop also performs the
//     decrement-and-deregister pair on every CAS-won snapshot.
//     Phase 1c's WaitForAllAsyncDrain reads this counter.
//
//   finalizers_in_progress_ + finalizers_done_cv_:
//     Incremented at FinalizeFromSnapshot entry (after CAS); decremented
//     before return. The Phase 1c kill loop's wait predicate requires
//     finalizers_in_progress_ == 0 AND kill_marshals_in_flight_ == 0
//     before Phase 2 begins.
//
//   kill_marshals_in_flight_:
//     CASE A (off-dispatcher kill marshal) increments before EnQueue;
//     the closure decrements + cv-notifies on completion. CASE B
//     (self-dispatcher inline) does NOT touch this counter — no marshal
//     is pending. Per r80.
//
//   BeginShutdown(t):
//     Phase 2 entry. Tells the BatchSpanProcessor + PeriodicMetricReader
//     to drain bounded by `t`. Idempotent — repeat calls no-op.

#include "observability/common.h"
#include "observability/meter_provider.h"
#include "observability/observability_config.h"
#include "observability/observability_snapshot.h"
#include "observability/sampler.h"
#include "observability/span_processor.h"
#include "observability/tracer_provider.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace OBSERVABILITY_NAMESPACE {

class ObservabilityManager
    : public std::enable_shared_from_this<ObservabilityManager> {
public:
    // Factory — must be used (NOT direct constructor) so
    // enable_shared_from_this seeds the internal weak reference. Per
    // §17.1 r37 lifecycle.
    static std::shared_ptr<ObservabilityManager> Create(
        ObservabilityConfig config,
        std::shared_ptr<const Resource> resource,
        std::shared_ptr<SpanProcessor>  span_processor,
        std::shared_ptr<RandomSource>   random);

    ObservabilityManager(const ObservabilityManager&) = delete;
    ObservabilityManager& operator=(const ObservabilityManager&) = delete;
    ~ObservabilityManager();

    // ---- Provider accessors (raw pointers; manager owns the providers) ----
    TracerProvider* tracer_provider() noexcept { return tracer_provider_.get(); }
    MeterProvider*  meter_provider()  noexcept { return meter_provider_.get();  }
    const Resource& resource() const noexcept { return *resource_; }

    // Convenience accessor matching the design's catalog access pattern.
    Tracer* GetTracer(const std::string& name,
                       const std::string& version = {}) {
        return tracer_provider_->GetTracer(name, version);
    }

    // ---- Live-flag accessors (used by hot path to skip work) ----
    bool TracesEnabled() const noexcept {
        return traces_enabled_.load(std::memory_order_acquire);
    }
    bool MetricsEnabled() const noexcept {
        return metrics_enabled_.load(std::memory_order_acquire);
    }
    // Live read of metrics.prometheus.include_target_info — flipped by
    // SIGHUP through Reload(). The /metrics handler consults this on
    // every scrape so operators see flips immediately.
    bool IncludeTargetInfo() const noexcept {
        return include_target_info_.load(std::memory_order_acquire);
    }

    // ---- Snapshot lifecycle ----
    //
    // RegisterLiveSnapshot — atomic register-and-count site. Inserts
    // weak_ptr into live_snapshots_ AND increments inflight_finalizations_
    // under live_snapshots_mtx_ in ONE critical section. Returns the
    // input shared_ptr unchanged (chainable).
    void RegisterLiveSnapshot(const std::shared_ptr<ObservabilitySnapshot>& snap);

    // FinalizeFromSnapshot — the single terminal-event entry point.
    // Idempotent: only the CAS-from-false-to-true winner runs the
    // span End + metric Record + counter decrement. Late callers
    // no-op cleanly. Returns true on win, false on no-op.
    bool FinalizeFromSnapshot(ObservabilitySnapshot& snap,
                                int      status_code,
                                uint64_t wire_body_size,
                                std::string error_type);

    // ---- Phase 2 shutdown entry (§13) ----
    // Idempotent. Drains processor + reader bounded by `t`.
    void BeginShutdown(std::chrono::milliseconds timeout);

    // ---- Phase 1c kill loop (§13 r80) ----
    // Iterates live_snapshots_ and CAS-wins finalize on every snapshot
    // that survived the drain. CASE A (off-dispatcher) marshals via
    // EnQueue with weak_from_this() capture per r80; CASE B
    // (self-dispatcher) runs inline + falls through to common
    // bookkeeping. The kill flag (kill_for_shutdown on each linked
    // ProxyTransaction) is published INLINE before the EnQueue per
    // r48 — Phase-3 terminal callbacks acquire-load it BEFORE
    // Span::End and skip End when set.
    void KillOutstandingSnapshots(std::chrono::milliseconds grace);

    // ---- Reload (§11.1 r77/r79) ----
    //
    // Apply the live-reloadable subset of `new_config` to the running
    // pipeline. Master flag (`enabled`) and Resource fields are
    // restart-required and IGNORED here (a separate WARN log fires at
    // the call site when those change). Live subset:
    //   - traces.enabled / metrics.enabled (atomic stores)
    //   - traces.sampler.* (TracerProvider::Reload swaps sampler)
    //   - metrics.export_interval / export_timeout
    //     (MeterProvider::Reload stores reader options)
    void Reload(const ObservabilityConfig& new_config);

    // ---- Counters (read-only; used by Phase 1c WaitForAllAsyncDrain) ----
    int64_t inflight_finalizations() const noexcept {
        return inflight_finalizations_.load(std::memory_order_acquire);
    }
    int64_t kill_marshals_in_flight() const noexcept {
        return kill_marshals_in_flight_.load(std::memory_order_acquire);
    }
    int64_t finalizers_in_progress() const noexcept {
        return finalizers_in_progress_.load(std::memory_order_acquire);
    }

    // CV used by Phase 1c WaitForAllAsyncDrain to block until counters
    // reach zero. Public so the call-site can wait on it. r78 contract:
    // null-manager guards live INSIDE WaitForAllAsyncDrain at HttpServer,
    // not on the cv itself.
    std::condition_variable& finalizers_done_cv() noexcept {
        return finalizers_done_cv_;
    }
    std::mutex& finalizers_done_mtx() noexcept {
        return finalizers_done_mtx_;
    }

private:
    ObservabilityManager(ObservabilityConfig config,
                          std::shared_ptr<const Resource> resource,
                          std::shared_ptr<SpanProcessor>  span_processor,
                          std::shared_ptr<RandomSource>   random);

    void Init();

    std::shared_ptr<const Sampler> BuildSamplerFromConfig() const;

    // Configuration snapshot — `enabled` is preserved verbatim (LIVE
    // truth per r78); other live-reloadable fields update on Reload.
    ObservabilityConfig                       config_;
    std::shared_ptr<const Resource>           resource_;
    std::shared_ptr<RandomSource>             random_;
    std::shared_ptr<SpanProcessor>            span_processor_;

    std::unique_ptr<TracerProvider>           tracer_provider_;
    std::unique_ptr<MeterProvider>            meter_provider_;

    // Live-flag snapshots (atomic; updated on Reload).
    std::atomic<bool> traces_enabled_{true};
    std::atomic<bool> metrics_enabled_{true};
    std::atomic<bool> include_target_info_{true};

    // ---- Snapshot registry + counter (r45 atomic register-and-count) ----
    //
    // Keyed on the snapshot's raw address (heap-allocated by
    // make_shared, never moves during the snapshot's lifetime).
    // Touched ONLY under live_snapshots_mtx_ so no per-entry
    // synchronization is needed. Expired weak_ptr entries are erased
    // on Finalize / kill — they cannot accumulate because every
    // RegisterLiveSnapshot is paired with exactly one
    // DeregisterAndDecrement.
    mutable std::mutex                          live_snapshots_mtx_;
    std::unordered_map<ObservabilitySnapshot*,
                        std::weak_ptr<ObservabilitySnapshot>>
                                                 live_snapshots_;
    std::atomic<int64_t> inflight_finalizations_{0};
    std::atomic<int64_t> kill_marshals_in_flight_{0};
    std::atomic<int64_t> finalizers_in_progress_{0};

    std::mutex                                  finalizers_done_mtx_;
    std::condition_variable                     finalizers_done_cv_;

    // Shutdown latch — set true by BeginShutdown. Idempotent.
    std::atomic<bool>                           shutdown_started_{false};

    // ---- Snapshot-killed counter (diagnostics; bumped on every kill) ----
    std::atomic<int64_t> snapshots_killed_on_timeout_{0};

    // -- Internal helpers --
    void OnFinalizeWinner(ObservabilitySnapshot& snap,
                            int      status_code,
                            uint64_t wire_body_size,
                            const std::string& error_type);
    void DeregisterAndDecrement(ObservabilitySnapshot& snap);
};

}  // namespace OBSERVABILITY_NAMESPACE
