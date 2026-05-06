#include "observability/batch_span_processor.h"

#include "common.h"
#include "log/logger.h"

namespace OBSERVABILITY_NAMESPACE {

BatchSpanProcessor::BatchSpanProcessor(
    std::shared_ptr<SpanExporter> exporter,
    BatchSpanProcessorOptions    options)
    : exporter_(std::move(exporter)),
      options_(options),
      // Match Reload()'s clamp: a zero batch cap wedges WorkerLoop —
      // its predicate `queue_.size() >= batch_cap` is permanently true,
      // and `DrainBatch(0)` would pop nothing, so the worker never
      // exports and spins reading the empty queue. Clamp to 1 BEFORE
      // publishing to max_export_batch_size_ so the worker thread we
      // spawn below never observes the hazardous value.
      max_export_batch_size_(options.max_export_batch_size == 0
                                ? size_t{1}
                                : options.max_export_batch_size),
      schedule_delay_ns_(options.schedule_delay.count() * 1'000'000),
      export_timeout_ns_(options.export_timeout.count() * 1'000'000),
      retries_max_attempts_(options.retries_max_attempts),
      retries_initial_backoff_ns_(
          options.retries_initial_backoff.count() * 1'000'000),
      retries_max_backoff_ns_(
          options.retries_max_backoff.count() * 1'000'000) {
    if (options_.max_queue_size == 0) options_.max_queue_size = 1;
    // Mirror the clamp into the cached options_ struct so /stats and
    // /config reflect the value the worker actually uses, not the
    // hazardous zero the operator typed.
    if (options_.max_export_batch_size == 0) options_.max_export_batch_size = 1;
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
    // Final unconditional join. JoinWorkers may have returned without
    // joining if the bounded wait timed out (stalled exporter). Letting
    // ~thread fire on a still-joinable worker would call std::terminate;
    // this safety net blocks the destructor until the worker exits.
    if (worker_.joinable()) worker_.join();
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
            // Retry loop: on kFailedRetryable back off and try again
            // up to retries_max_attempts. kSuccess stops; any other
            // result (kFailedNotRetryable / kInvalidArgument) drops
            // the batch — those are non-retryable per the exporter
            // contract. Backoff doubles each attempt, capped at
            // retries_max_backoff. The first exception path counts
            // as a failure but isn't retried (preserves the original
            // best-effort drop on programmer errors / bad payloads).
            //
            // Read the live atomics (set by ReloadRetries) once per
            // batch so a SIGHUP affects subsequent attempts without
            // disturbing the in-progress batch's accounting.
            const int max_attempts = std::max(
                1, retries_max_attempts_.load(std::memory_order_acquire));
            auto backoff = std::chrono::milliseconds(
                retries_initial_backoff_ns_.load(
                    std::memory_order_acquire) / 1'000'000);
            const auto max_backoff = std::chrono::milliseconds(
                retries_max_backoff_ns_.load(
                    std::memory_order_acquire) / 1'000'000);
            int attempt = 0;
            for (; attempt < max_attempts; ++attempt) {
                const auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::nanoseconds(export_timeout_ns_.load(
                        std::memory_order_acquire));
                ExportResult result = ExportResult::kFailedNotRetryable;
                std::vector<SpanData> attempt_batch;
                if (attempt + 1 < max_attempts) {
                    // Keep a copy so a kFailedRetryable can re-export
                    // the SAME batch; only the last attempt moves.
                    attempt_batch = batch;
                } else {
                    attempt_batch = std::move(batch);
                }
                try {
                    result = exporter_->Export(std::move(attempt_batch),
                                                  deadline);
                } catch (const std::exception& e) {
                    logging::Get()->error(
                        "BatchSpanProcessor::Export threw: {}", e.what());
                    break;
                } catch (...) {
                    logging::Get()->error(
                        "BatchSpanProcessor::Export threw unknown exception");
                    break;
                }
                if (result == ExportResult::kSuccess) {
                    exported_batches_.fetch_add(1, std::memory_order_relaxed);
                    break;
                }
                if (result != ExportResult::kFailedRetryable) {
                    break;  // non-retryable — drop and move on.
                }
                if (attempt + 1 >= max_attempts) {
                    logging::Get()->warn(
                        "BatchSpanProcessor: retryable export failed after "
                        "{} attempts; dropping batch", max_attempts);
                    break;
                }
                // Exponential backoff with cap. cv_-aware sleep so a
                // mid-backoff shutdown wakes immediately and the
                // subsequent attempt still happens (best-effort
                // delivery before the worker exits).
                std::unique_lock<std::mutex> blk(mtx_);
                cv_.wait_for(blk, backoff, [&] {
                    return shutting_down_.load(std::memory_order_acquire);
                });
                blk.unlock();
                backoff *= 2;
                if (backoff > max_backoff) backoff = max_backoff;
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
    // Worker has fully drained the queue. Signal the exporter to
    // refuse subsequent exports — UNLESS the manager has flagged the
    // exporter as shared (in which case the manager handles the
    // signal once across all processors after BOTH have joined).
    if (exporter_
        && !exporter_shutdown_disabled_.load(std::memory_order_acquire)) {
        exporter_->SignalShutdown();
    }
    {
        std::lock_guard<std::mutex> g(join_mtx_);
        worker_done_ = true;
    }
    join_cv_.notify_all();
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

void BatchSpanProcessor::JoinWorkers(std::chrono::milliseconds deadline) {
    if (!worker_started_.load(std::memory_order_acquire)) return;
    if (deadline.count() <= 0) {
        // Caller asked for unbounded wait — block on join directly.
        if (worker_.joinable()) worker_.join();
        return;
    }
    // Bounded wait. The worker publishes worker_done_ AFTER signaling
    // the exporter and finishing the queue drain, so a successful
    // wait_for guarantees exporter shutdown has already fired. If the
    // wait times out (e.g. exporter Export() is stalled), return
    // without joining; the destructor's unconditional fallback join
    // catches a thread that finishes later.
    std::unique_lock<std::mutex> lk(join_mtx_);
    bool done = join_cv_.wait_for(lk, deadline,
                                      [this]{ return worker_done_; });
    lk.unlock();
    if (!done) {
        logging::Get()->warn(
            "BatchSpanProcessor::JoinWorkers timeout after {}ms — "
            "worker still in flight (exporter likely stalled); final "
            "join deferred to destructor",
            deadline.count());
        return;
    }
    if (worker_.joinable()) worker_.join();
}

void BatchSpanProcessor::Reload(size_t new_max_export_batch_size,
                                 std::chrono::milliseconds new_schedule_delay) {
    // Preserve the current export_timeout (read back from the live
    // atomic, not the construction-time value, so consecutive 2-arg
    // reloads compose).
    auto current_timeout_ns = export_timeout_ns_.load(std::memory_order_acquire);
    Reload(new_max_export_batch_size, new_schedule_delay,
           std::chrono::milliseconds(current_timeout_ns / 1'000'000));
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

void BatchSpanProcessor::ReloadRetries(int new_max_attempts,
        std::chrono::milliseconds new_initial_backoff,
        std::chrono::milliseconds new_max_backoff) {
    if (new_max_attempts < 1) new_max_attempts = 1;
    if (new_max_backoff < new_initial_backoff) {
        new_max_backoff = new_initial_backoff;
    }
    retries_max_attempts_.store(new_max_attempts,
                                  std::memory_order_release);
    retries_initial_backoff_ns_.store(
        new_initial_backoff.count() * 1'000'000,
        std::memory_order_release);
    retries_max_backoff_ns_.store(
        new_max_backoff.count() * 1'000'000,
        std::memory_order_release);
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
