#pragma once

// PeriodicMetricReader — worker thread that calls
// `MeterProvider::Snapshot()` on a fixed interval and hands the
// resulting MetricsSnapshot to a MetricExporter.
//
// Per OPENTELEMETRY_DESIGN.md §8.4 r79: reader-side knobs are
// `export_interval_ms` AND `export_timeout_ms` only. Trace-only knobs
// (max_export_batch_size, schedule_delay) live on BatchSpanProcessor.

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

    // r84 trio mirror — same lifecycle shape as the SpanExporter trio.
    void SignalShutdown();
    void JoinWorkers(std::chrono::milliseconds deadline);

    // Live-reloadable knobs (r79). MeterProvider::reader_options()
    // remains the source of truth; this method updates the reader's
    // local atomic snapshot so the worker observes the new values
    // promptly without a Snapshot() round-trip.
    void Reload(MeterReaderOptions new_options);

    // Force a single export now, bounded by `deadline`. Idempotent
    // wakeup; the worker loop drains and exports once.
    void ForceFlush(std::chrono::milliseconds deadline);

    // Diagnostics.
    int64_t exported_cycles() const noexcept {
        return exported_cycles_.load(std::memory_order_acquire);
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
};

}  // namespace OBSERVABILITY_NAMESPACE
