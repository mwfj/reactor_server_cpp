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

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>

namespace OBSERVABILITY_NAMESPACE {

class PeriodicMetricReader {
public:
    PeriodicMetricReader(MeterProvider*                 provider,
                          std::shared_ptr<MetricExporter> exporter,
                          MeterReaderOptions             options = {});

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

    // Skip the worker-loop exporter SignalShutdown when the exporter
    // is shared with a BatchSpanProcessor — see the matching method
    // on BatchSpanProcessor for the rationale.
    void DisableExporterShutdownOnDrain() noexcept {
        exporter_shutdown_disabled_.store(true, std::memory_order_release);
    }

private:
    void WorkerLoop();

    MeterProvider*                  provider_;
    std::shared_ptr<MetricExporter> exporter_;

    std::atomic<int64_t>            interval_ns_;
    std::atomic<int64_t>            timeout_ns_;

    std::mutex                      mtx_;
    std::condition_variable         cv_;
    std::atomic<bool>               shutting_down_{false};
    std::atomic<bool>               flush_requested_{false};
    std::atomic<int64_t>            exported_cycles_{0};

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
};

}  // namespace OBSERVABILITY_NAMESPACE
