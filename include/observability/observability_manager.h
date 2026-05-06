#pragma once

// ObservabilityManager — top-level owner of TracerProvider +
// MeterProvider + the live-snapshot registry. Inherits
// enable_shared_from_this so kill marshals can safely upgrade-or-no-op
// when the manager outlives them.
//
// Counter lifecycle for the shutdown drain predicate:
//
//   inflight_finalizations_  — bumped under live_snapshots_mtx_ in
//                              RegisterLiveSnapshot; decremented under
//                              the same mutex by FinalizeFromSnapshot
//                              (CAS-winner) AND the kill loop.
//   finalizers_in_progress_  — bumped at FinalizeFromSnapshot entry,
//                              decremented before return; signaled on
//                              finalizers_done_cv_.
//   kill_marshals_in_flight_ — RESERVED for a future per-dispatcher
//                              kill-marshal path. Today
//                              KillOutstandingSnapshots invokes
//                              Span::DropWithoutEnd inline from the
//                              stopper thread (DropWithoutEnd is
//                              off-thread-safe — flips an atomic flag
//                              only; vector/shared_ptr cleanup runs in
//                              the destructor when the last shared_ptr
//                              releases, bounded by Phase 4 dispatcher
//                              stop). The counter stays at 0 today and
//                              is consulted by WaitForAllAsyncDrain so
//                              the predicate is forward-compatible
//                              with any future marshal step that bumps
//                              it before EnQueue + decrements when the
//                              closure runs.
//
// BeginShutdown(t) drains the BatchSpanProcessor + PeriodicMetricReader
// bounded by t. Idempotent.

#include "observability/common.h"
#include "observability/histogram.h"
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
    // Factory — must be used (NOT the direct constructor) so
    // enable_shared_from_this seeds the internal weak reference before
    // any caller can capture a weak_ptr.
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
    // every scrape.
    bool IncludeTargetInfo() const noexcept {
        return include_target_info_.load(std::memory_order_acquire);
    }

    // ---- Snapshot lifecycle ----
    //
    // Atomic register-and-count site: inserts the weak_ptr AND bumps
    // inflight_finalizations_ under one critical section.
    void RegisterLiveSnapshot(const std::shared_ptr<ObservabilitySnapshot>& snap);

    // Single terminal-event entry. Idempotent CAS-from-false-to-true:
    // exactly one caller wins; late callers no-op. Returns the win flag.
    bool FinalizeFromSnapshot(ObservabilitySnapshot& snap,
                                int      status_code,
                                uint64_t wire_body_size,
                                std::string error_type);

    // Idempotent. Drains processor + reader bounded by `timeout`.
    void BeginShutdown(std::chrono::milliseconds timeout);

    // Iterates live_snapshots_ and CAS-wins a terminal event on every
    // snapshot that survived the drain. Off-dispatcher marshals via
    // EnQueue with weak_from_this() capture; self-dispatcher kills run
    // inline. The kill flag on the linked ProxyTransaction is published
    // before the EnQueue so terminal callbacks can short-circuit
    // Span::End on shutdown.
    void KillOutstandingSnapshots(std::chrono::milliseconds grace);

    // Apply the live-reloadable subset of `new_config`. Master `enabled`
    // and Resource are restart-required and ignored here; the call site
    // emits the warn for those. Live subset:
    //   - traces.enabled / metrics.enabled (atomic stores)
    //   - traces.sampler.* (TracerProvider::Reload swaps sampler)
    //   - metrics.export_interval / export_timeout
    //     (MeterProvider::Reload stores reader options)
    void Reload(const ObservabilityConfig& new_config);

    // Match `path` against the configured `traces.sampler.routes`
    // overrides (literal byte-prefix). Returns the per-route sampler
    // when an override matches, or null when the global sampler should
    // be used. Callers pass the result into `StartSpanOptions::sampler_override`.
    std::shared_ptr<const Sampler> EffectiveSamplerForPath(
        const std::string& path) const noexcept;

    // Shared RandomSource used by Tracer / outbound-context callers
    // (proxy attempt CLIENT contexts, auth IdP issue contexts) that
    // need fresh span_ids without going through Tracer::StartSpan.
    // The source is internally synchronised so concurrent calls from
    // multiple dispatchers are safe.
    std::shared_ptr<RandomSource> random() const noexcept {
        return random_;
    }

    // Read-only accessors consumed by the shutdown drain predicate.
    int64_t inflight_finalizations() const noexcept {
        return inflight_finalizations_.load(std::memory_order_acquire);
    }
    int64_t kill_marshals_in_flight() const noexcept {
        return kill_marshals_in_flight_.load(std::memory_order_acquire);
    }
    int64_t finalizers_in_progress() const noexcept {
        return finalizers_in_progress_.load(std::memory_order_acquire);
    }

    // Signaled by every finalize / kill decrement; the call site uses it
    // to wake from the drain wait.
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

    // Build per-route sampler overrides from `config_.traces.sampler.routes`.
    // Stored in `route_overrides_snapshot_` and atomic-swapped on Reload.
    struct RouteOverride {
        std::string path_prefix;
        std::shared_ptr<const Sampler> sampler;
    };
    std::shared_ptr<const std::vector<RouteOverride>>
    BuildRouteOverridesFromConfig() const;

    // Republish the live-flag atomics from the supplied config. Called
    // by both the ctor and Reload so the publication path is single-sourced.
    void PublishLiveFlags(const ObservabilityConfig& c);

    // Live truth: master `enabled` is preserved verbatim across Reload;
    // other live-reloadable fields are updated by Reload.
    ObservabilityConfig                       config_;
    std::shared_ptr<const Resource>           resource_;
    std::shared_ptr<RandomSource>             random_;
    std::shared_ptr<SpanProcessor>            span_processor_;

    std::unique_ptr<TracerProvider>           tracer_provider_;
    std::unique_ptr<MeterProvider>            meter_provider_;
    // Built at Init() time, registered into meter_provider_'s
    // "reactor.http.server" Meter. Not owned by this manager — Meter
    // owns the Histogram. Recorded once per request from
    // OnFinalizeWinner so /metrics + OTLP exports surface real traffic
    // (only the duration histogram is wired today; the rest of the
    // §7.1 catalog is deferred to Phase 2).
    Histogram*                                http_server_request_duration_ = nullptr;

    // Live-flag snapshots (atomic; updated on Reload).
    std::atomic<bool> traces_enabled_{true};
    std::atomic<bool> metrics_enabled_{true};
    std::atomic<bool> include_target_info_{true};

    // Snapshot registry. Keyed on the snapshot's raw address (stable
    // for its lifetime — make_shared never moves). Touched only under
    // live_snapshots_mtx_; the matching counter increment+decrement
    // also lives inside that critical section so a registered-but-
    // uncounted snapshot cannot exist.
    mutable std::mutex                          live_snapshots_mtx_;
    std::unordered_map<ObservabilitySnapshot*,
                        std::weak_ptr<ObservabilitySnapshot>>
                                                 live_snapshots_;
    std::atomic<int64_t> inflight_finalizations_{0};
    std::atomic<int64_t> kill_marshals_in_flight_{0};
    std::atomic<int64_t> finalizers_in_progress_{0};

    std::mutex                                  finalizers_done_mtx_;
    std::condition_variable                     finalizers_done_cv_;

    // Idempotent BeginShutdown latch.
    std::atomic<bool>                           shutdown_started_{false};

    // Diagnostic — bumped on every kill-loop CAS-win.
    std::atomic<int64_t> snapshots_killed_on_timeout_{0};

    // Compiled `traces.sampler.routes` overrides. shared_ptr so reads
    // can capture the snapshot lock-free while a Reload swaps in a new
    // vector. Iteration is O(N) over typically <10 entries; no lock
    // needed because the vector is immutable post-construction.
    std::shared_ptr<const std::vector<RouteOverride>>
        route_overrides_snapshot_;

    // -- Internal helpers --
    void OnFinalizeWinner(ObservabilitySnapshot& snap,
                            int      status_code,
                            uint64_t wire_body_size,
                            const std::string& error_type);
    void DeregisterAndDecrement(ObservabilitySnapshot& snap);
};

}  // namespace OBSERVABILITY_NAMESPACE
