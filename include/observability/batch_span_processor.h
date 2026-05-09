#pragma once

// BatchSpanProcessor — bounded-queue worker that batches finished
// SpanData and hands batches to a SpanExporter.
//
// Field classification:
//   max_queue_size:        restart-only (allocated at construction;
//                          live resize would drop or duplicate).
//   max_export_batch_size: live-reloadable (caps each export call).
//   schedule_delay:        live-reloadable (worker wakes every N ms
//                          even when the queue is below batch size).
//   export_timeout:        per-export deadline passed to the exporter.
//
// Drop-oldest on queue full: OnEnd never blocks (would stall the
// dispatcher). Drops are counted via dropped_on_overflow_.

#include "observability/span_exporter.h"
#include "observability/span_processor.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>

namespace OBSERVABILITY_NAMESPACE {

struct BatchSpanProcessorOptions {
    size_t                    max_queue_size        = 4096;   // restart-only
    size_t                    max_export_batch_size = 512;    // live-reloadable
    std::chrono::milliseconds schedule_delay        = std::chrono::milliseconds{5000};
    std::chrono::milliseconds export_timeout        = std::chrono::milliseconds{10000};
    // Retry policy for kFailedRetryable Export results. The worker
    // retries with exponential backoff capped at `max_backoff`,
    // bounded by `max_attempts` total tries (initial + retries).
    // max_attempts<=1 disables retries — Export is called once and
    // any failure drops the batch (matches the original behaviour).
    int                       retries_max_attempts   = 3;
    std::chrono::milliseconds retries_initial_backoff = std::chrono::milliseconds{1000};
    std::chrono::milliseconds retries_max_backoff    = std::chrono::milliseconds{10000};
};

class BatchSpanProcessor final : public SpanProcessor {
public:
    BatchSpanProcessor(std::shared_ptr<SpanExporter> exporter,
                        BatchSpanProcessorOptions    options = {});

    BatchSpanProcessor(const BatchSpanProcessor&) = delete;
    BatchSpanProcessor& operator=(const BatchSpanProcessor&) = delete;
    ~BatchSpanProcessor() override;

    // SpanProcessor interface.
    void OnEnd(SpanData data) override;
    void SignalShutdown() override;
    void JoinWorkers(std::chrono::milliseconds deadline) override;

    // Live-reloadable knobs.
    void Reload(size_t new_max_export_batch_size,
                std::chrono::milliseconds new_schedule_delay,
                std::chrono::milliseconds new_export_timeout);

    // Convenience overload — reloads only the two batch-shape knobs,
    // preserving the construction-time export_timeout. Used by
    // TracerProvider::Reload, where ProcessorOptions intentionally
    // omits export_timeout because it isn't surfaced as a config field.
    void Reload(size_t new_max_export_batch_size,
                std::chrono::milliseconds new_schedule_delay);

    // Reload retry policy in lockstep with batch shape. SIGHUP edits
    // to traces.batch.retries.* take effect on the next attempt
    // (already-scheduled backoffs are not preempted).
    void ReloadRetries(int new_max_attempts,
                       std::chrono::milliseconds new_initial_backoff,
                       std::chrono::milliseconds new_max_backoff);

    // Disable the worker-loop exporter SignalShutdown call. Used by
    // ObservabilityManager when this processor shares an OtlpHttpExporter
    // with a PeriodicMetricReader: signalling unilaterally from the
    // first drainer would kFail the still-active peer's final export.
    // The manager then fires SignalShutdown on the shared exporter
    // once after BOTH workers have joined. Default (not called):
    // the worker signals its own exporter — preserves the standalone
    // ownership contract every test and non-shared deployment relies on.
    void DisableExporterShutdownOnDrain() noexcept {
        exporter_shutdown_disabled_.store(true, std::memory_order_release);
    }

    // Phase 2 — exposed so ObservabilityManager::BeginShutdown can detect
    // a SpanExporter shared with the metric reader and coordinate the
    // single SignalShutdown call after both workers have joined.
    std::shared_ptr<SpanExporter> exporter() const noexcept {
        return exporter_;
    }

    // Force a flush; returns when the queue drains or `deadline`
    // expires. Idempotent.
    void ForceFlush(std::chrono::milliseconds deadline) override;

    // Diagnostics counters surfaced via self-metrics.
    size_t  queue_depth() const noexcept;
    int64_t dropped_on_overflow() const noexcept {
        return dropped_on_overflow_.load(std::memory_order_acquire);
    }
    int64_t exported_batches() const noexcept {
        return exported_batches_.load(std::memory_order_acquire);
    }

private:
    void WorkerLoop();
    std::vector<SpanData> DrainBatch(size_t cap);

    std::shared_ptr<SpanExporter>  exporter_;
    BatchSpanProcessorOptions      options_;
    // Atomic snapshot of live-reloadable fields — read-without-lock by
    // the worker on every iteration so reload visibility is immediate.
    std::atomic<size_t>            max_export_batch_size_;
    std::atomic<int64_t>           schedule_delay_ns_;
    std::atomic<int64_t>           export_timeout_ns_;
    // Retry knobs — live-reloadable. Read at the top of each retry
    // loop in WorkerLoop so a SIGHUP edits subsequent attempts.
    std::atomic<int>               retries_max_attempts_;
    std::atomic<int64_t>           retries_initial_backoff_ns_;
    std::atomic<int64_t>           retries_max_backoff_ns_;

    mutable std::mutex             mtx_;
    std::condition_variable        cv_;
    std::deque<SpanData>           queue_;

    std::atomic<bool>              shutting_down_{false};
    std::atomic<bool>              flush_requested_{false};
    std::atomic<int64_t>           dropped_on_overflow_{0};
    std::atomic<int64_t>           exported_batches_{0};
    // Set to N>0 while the worker is mid-export-cycle (a single batch's
    // entire retry sequence increments once and decrements once on
    // exit). ForceFlush polls until queue=0 AND in_flight=0 — without
    // this, a poll could see queue=0 while an in-flight POST is still
    // alive, which lets the four-phase shutdown tear down the upstream
    // pool mid-batch and lose the final spans.
    std::atomic<int>               exports_in_flight_{0};

    std::thread                    worker_;
    std::atomic<bool>              worker_started_{false};
    // Worker-exit handshake. Set under join_mtx_ + cv-notify at the
    // end of WorkerLoop so JoinWorkers can return when the worker has
    // actually finished, rather than blocking on worker_.join()
    // through a stalled exporter Export(). The destructor falls back
    // to an unconditional join after the bounded wait so a still-
    // joinable thread cannot escape into ~thread → terminate.
    std::mutex                     join_mtx_;
    std::condition_variable        join_cv_;
    bool                           worker_done_ = false;

    // When true (set by ObservabilityManager via
    // DisableExporterShutdownOnDrain), the worker loop skips the
    // post-drain exporter SignalShutdown so the manager can coordinate
    // it once across BSP + PMR sharing one exporter.
    std::atomic<bool>              exporter_shutdown_disabled_{false};
};

}  // namespace OBSERVABILITY_NAMESPACE
