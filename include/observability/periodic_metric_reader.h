#pragma once

// PeriodicMetricReader — worker thread that calls
// MeterProvider::Snapshot on a fixed interval and hands the result
// to a MetricExporter.
//
// Reader-side knobs are export_interval and export_timeout only.
// Trace-only knobs (max_export_batch_size, schedule_delay) live on
// BatchSpanProcessor.

#include "observability/metric_exporter.h"
#include "observability/meter_provider.h"

#include "../common.h"
#include <condition_variable>
// <atomic>, <chrono>, <memory>, <mutex>, <thread> via common.h

namespace OBSERVABILITY_NAMESPACE {

class ObservabilityManager;

class PeriodicMetricReader {
public:
    PeriodicMetricReader(MeterProvider*                 provider,
                          std::shared_ptr<MetricExporter> exporter,
                          MeterReaderOptions             options = {},
                          ObservabilityManager*          manager = nullptr);

    PeriodicMetricReader(const PeriodicMetricReader&) = delete;
    PeriodicMetricReader& operator=(const PeriodicMetricReader&) = delete;
    ~PeriodicMetricReader();

    // Lifecycle hooks — same shape as the SpanExporter trio.
    void SignalShutdown();
    void JoinWorkers(std::chrono::milliseconds deadline);

    // Update the reader's atomic interval/timeout snapshot so the
    // worker observes new values without a Snapshot() round-trip.
    // MeterProvider::reader_options() remains the source of truth.
    void Reload(MeterReaderOptions new_options);

    // Force a single export now, bounded by `deadline`. Idempotent
    // wakeup; the worker loop drains and exports once.
    void ForceFlush(std::chrono::milliseconds deadline);

    // Diagnostics.
    int64_t exported_cycles() const noexcept {
        return exported_cycles_.load(std::memory_order_acquire);
    }
    int64_t signal_shutdown_calls() const noexcept {
        return signal_shutdown_calls_.load(std::memory_order_relaxed);
    }
    int64_t worker_loop_iterations() const noexcept {
        return worker_loop_iterations_.load(std::memory_order_relaxed);
    }

    // Skip the worker-loop exporter SignalShutdown when the exporter
    // is shared with a BatchSpanProcessor — see the matching method
    // on BatchSpanProcessor for the rationale.
    void DisableExporterShutdownOnDrain() noexcept {
        exporter_shutdown_disabled_.store(true, std::memory_order_release);
    }

    // Live emission gate — when false the worker still ticks and bumps
    // flush_completed_count_ (preserving ForceFlush handshake) but
    // skips the Snapshot+Export pair so no metrics traffic is pushed.
    // Backs the documented `metrics.enabled=false` SIGHUP semantic:
    // emission stops, allocation stays so a `false → true` flip works
    // without restart. Counters keep accumulating in MeterProvider.
    void SetEnabled(bool on) noexcept {
        enabled_.store(on, std::memory_order_release);
    }
    bool enabled() const noexcept {
        return enabled_.load(std::memory_order_acquire);
    }

    // Exposed so ObservabilityManager::BeginShutdown can detect a
    // MetricExporter shared with the BatchSpanProcessor and coordinate
    // the single SignalShutdown call after both workers have joined.
    std::shared_ptr<MetricExporter> exporter() const noexcept {
        return exporter_;
    }

    // Self-metric escape hatch — returns the ObservabilityManager pointer
    // installed at construction time, or null when constructed without
    // one (test fixtures). See batch_span_processor.h::manager() docstring
    // for the SHUTDOWN CAVEAT on sub-member usage.
    ObservabilityManager* manager() const noexcept {
        return manager_.load(std::memory_order_acquire);
    }

    // Atomically null the manager pointer so the worker's self-metric
    // emit path sees nullptr and skips. Called by ~ObservabilityManager
    // BEFORE member destruction begins. Idempotent. Mirrors
    // BatchSpanProcessor::DisarmManager — see that docstring for the
    // multi-holder safety rationale.
    void DisarmManager() noexcept {
        manager_.store(nullptr, std::memory_order_release);
    }

private:
    void WorkerLoop();

    MeterProvider*                  provider_;
    std::shared_ptr<MetricExporter> exporter_;
    // Atomic so DisarmManager()'s release-store is visible to the worker
    // and any synchronous emit path. After the tracer_provider_ reorder
    // in observability_manager.h, metric_reader_ is declared AFTER
    // catalog_ and meter_provider_ — reverse-destruction joins this
    // reader BEFORE either dies, so manager_->catalog() and
    // manager_->meter_provider() are GUARANTEED LIVE for the entire
    // worker drain on the production path. DisarmManager() is the
    // safety net for a future code path where a PMR ref outlives the
    // manager (today PMR has a single ref-holder, but mirroring BSP's
    // disarm semantics keeps the contract symmetric).
    std::atomic<ObservabilityManager*> manager_;

    std::atomic<int64_t>            interval_ns_;
    std::atomic<int64_t>            timeout_ns_;

    std::mutex                      mtx_;
    std::condition_variable         cv_;
    std::atomic<bool>               shutting_down_{false};
    std::atomic<bool>               flush_requested_{false};
    std::atomic<int64_t>            exported_cycles_{0};
    std::atomic<int64_t>            signal_shutdown_calls_{0};
    std::atomic<int64_t>            worker_loop_iterations_{0};

    // ForceFlush handshake — caller snapshots flush_completed_count_,
    // signals flush_requested_ + cv_, then waits on flush_cv_ until the
    // worker bumps the count past the snapshot OR the deadline expires.
    std::mutex                      flush_mtx_;
    std::condition_variable         flush_cv_;
    int64_t                         flush_completed_count_ = 0;

    std::thread                     worker_;
    std::atomic<bool>               worker_started_{false};
    // See BatchSpanProcessor for the same handshake — JoinWorkers
    // returns when worker_done_ is published, instead of blocking on
    // worker_.join() through a stalled exporter Export(). Destructor
    // does an unconditional fallback join.
    std::mutex                      join_mtx_;
    std::condition_variable         join_cv_;
    bool                            worker_done_ = false;
    std::atomic<bool>               exporter_shutdown_disabled_{false};

    // Live emission gate (defaults to true so the boot path doesn't have
    // to call SetEnabled before the first cycle). ObservabilityManager
    // pushes the metrics.enabled config into this on registration and on
    // every Reload — see SetEnabled().
    std::atomic<bool>               enabled_{true};
};

}  // namespace OBSERVABILITY_NAMESPACE
