#include "observability/batch_span_processor.h"

#include "common.h"
#include "log/logger.h"

namespace OBSERVABILITY_NAMESPACE {

BatchSpanProcessor::BatchSpanProcessor(
    std::shared_ptr<SpanExporter> exporter,
    BatchSpanProcessorOptions    options)
    : exporter_(std::move(exporter)),
      options_(options),
      max_export_batch_size_(options.max_export_batch_size),
      schedule_delay_ns_(options.schedule_delay.count() * 1'000'000),
      export_timeout_ns_(options.export_timeout.count() * 1'000'000) {
    if (options_.max_queue_size == 0) options_.max_queue_size = 1;
    // Publish the started flag BEFORE constructing the thread so a
    // racing JoinWorkers() (e.g. from ~BatchSpanProcessor on a partial-
    // construction unwind path) reads true and falls through to the
    // joinable() check rather than skipping the join and leaving a
    // joinable std::thread behind (which would terminate from ~thread).
    worker_started_.store(true, std::memory_order_release);
    worker_ = std::thread([this] { WorkerLoop(); });
}

BatchSpanProcessor::~BatchSpanProcessor() {
    SignalShutdown();
    JoinWorkers(std::chrono::milliseconds{2000});
}

void BatchSpanProcessor::OnEnd(SpanData data) {
    if (shutting_down_.load(std::memory_order_acquire)) {
        // Post-shutdown drop — counted as overflow for diagnostics.
        dropped_on_overflow_.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    {
        std::lock_guard<std::mutex> g(mtx_);
        if (queue_.size() >= options_.max_queue_size) {
            // Drop-oldest: pop the front so newer spans (more relevant
            // for live debugging) are preserved.
            queue_.pop_front();
            dropped_on_overflow_.fetch_add(1, std::memory_order_relaxed);
        }
        queue_.emplace_back(std::move(data));
    }
    cv_.notify_one();
}

std::vector<SpanData> BatchSpanProcessor::DrainBatch(size_t cap) {
    std::vector<SpanData> batch;
    batch.reserve(cap);
    std::lock_guard<std::mutex> g(mtx_);
    while (!queue_.empty() && batch.size() < cap) {
        batch.emplace_back(std::move(queue_.front()));
        queue_.pop_front();
    }
    return batch;
}

void BatchSpanProcessor::WorkerLoop() {
    while (true) {
        // Wait for a wake signal: queue grew past batch size, flush
        // requested, shutdown started, or schedule_delay elapsed.
        const auto delay_ns = schedule_delay_ns_.load(std::memory_order_acquire);
        const size_t batch_cap = max_export_batch_size_.load(std::memory_order_acquire);

        std::unique_lock<std::mutex> lk(mtx_);
        cv_.wait_for(lk, std::chrono::nanoseconds(delay_ns), [&] {
            return shutting_down_.load(std::memory_order_acquire) ||
                   flush_requested_.load(std::memory_order_acquire) ||
                   queue_.size() >= batch_cap;
        });
        const bool drain_all = shutting_down_.load(std::memory_order_acquire) ||
                                flush_requested_.exchange(false, std::memory_order_acq_rel);
        const bool empty = queue_.empty();
        lk.unlock();

        if (empty && !drain_all) continue;
        if (empty && drain_all) {
            // Final drain returned empty — exit.
            if (shutting_down_.load(std::memory_order_acquire)) break;
            continue;
        }

        // Drain in chunks of `batch_cap`; loop until empty or
        // (non-shutdown path) we've sent one batch.
        while (true) {
            auto batch = DrainBatch(batch_cap);
            if (batch.empty()) break;
            const auto deadline = std::chrono::steady_clock::now() +
                std::chrono::nanoseconds(export_timeout_ns_.load(std::memory_order_acquire));
            try {
                exporter_->Export(std::move(batch), deadline);
                exported_batches_.fetch_add(1, std::memory_order_relaxed);
            } catch (const std::exception& e) {
                logging::Get()->error(
                    "BatchSpanProcessor::Export threw: {}", e.what());
            } catch (...) {
                logging::Get()->error(
                    "BatchSpanProcessor::Export threw unknown exception");
            }
            if (!drain_all) break;
        }

        if (shutting_down_.load(std::memory_order_acquire)) {
            // Re-check the queue under lock: another OnEnd may have
            // raced past the shutdown flag check. The drain loop above
            // already drained what was visible; if more is queued we
            // pick it up on the next iteration's wait_for (which will
            // wake immediately because shutting_down_ is set).
            std::lock_guard<std::mutex> g(mtx_);
            if (queue_.empty()) break;
        }
    }
}

void BatchSpanProcessor::SignalShutdown() {
    bool expected = false;
    if (!shutting_down_.compare_exchange_strong(expected, true,
            std::memory_order_acq_rel)) {
        return;  // idempotent
    }
    // Wake the worker so it sees shutting_down_=true and runs its
    // drain_all loop. Do NOT signal the exporter here: that would
    // cause Export() inside the drain to return kFailedNotRetryable
    // and silently drop every queued span. The exporter is signaled
    // AFTER the worker has finished draining, in JoinWorkers().
    // Subsequent OnEnd calls already land in dropped_on_overflow_.
    cv_.notify_all();
}

void BatchSpanProcessor::JoinWorkers(std::chrono::milliseconds /*deadline*/) {
    if (!worker_started_.load(std::memory_order_acquire)) return;
    if (worker_.joinable()) worker_.join();
    // Worker has fully drained. Now safe to refuse any further
    // exports (e.g. a metric reader sharing the same exporter that
    // is still active). Idempotent on the exporter side.
    if (exporter_) exporter_->SignalShutdown();
}

void BatchSpanProcessor::Reload(size_t new_max_export_batch_size,
                                 std::chrono::milliseconds new_schedule_delay,
                                 std::chrono::milliseconds new_export_timeout) {
    if (new_max_export_batch_size == 0) new_max_export_batch_size = 1;
    max_export_batch_size_.store(new_max_export_batch_size,
                                   std::memory_order_release);
    schedule_delay_ns_.store(new_schedule_delay.count() * 1'000'000,
                              std::memory_order_release);
    export_timeout_ns_.store(new_export_timeout.count() * 1'000'000,
                              std::memory_order_release);
    cv_.notify_all();  // wake worker so the new schedule_delay applies promptly.
}

void BatchSpanProcessor::ForceFlush(std::chrono::milliseconds deadline) {
    flush_requested_.store(true, std::memory_order_release);
    cv_.notify_all();
    // Poll until queue empties or deadline expires. We do NOT block the
    // calling thread on a cv-wait because the worker thread holds the
    // mtx during Export() — a cv-wait here would just spin on the cv.
    const auto t_end = std::chrono::steady_clock::now() + deadline;
    while (std::chrono::steady_clock::now() < t_end) {
        if (queue_depth() == 0) return;
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
}

size_t BatchSpanProcessor::queue_depth() const noexcept {
    std::lock_guard<std::mutex> g(mtx_);
    return queue_.size();
}

}  // namespace OBSERVABILITY_NAMESPACE
