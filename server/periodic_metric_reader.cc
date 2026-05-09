#include "observability/periodic_metric_reader.h"

#include "common.h"
#include "log/logger.h"

namespace OBSERVABILITY_NAMESPACE {

PeriodicMetricReader::PeriodicMetricReader(
    MeterProvider*                  provider,
    std::shared_ptr<MetricExporter> exporter,
    MeterReaderOptions              options)
    : provider_(provider),
      exporter_(std::move(exporter)),
      interval_ns_(options.export_interval.count() * 1'000'000),
      timeout_ns_(options.export_timeout.count() * 1'000'000) {
    // See BatchSpanProcessor for the rationale on publish-before-launch.
    worker_started_.store(true, std::memory_order_release);
    worker_ = std::thread([this] { WorkerLoop(); });
}

PeriodicMetricReader::~PeriodicMetricReader() {
    SignalShutdown();
    JoinWorkers(std::chrono::milliseconds{2000});
    // Final unconditional join — see BatchSpanProcessor for rationale.
    if (worker_.joinable()) worker_.join();
}

void PeriodicMetricReader::WorkerLoop() {
    while (true) {
        worker_loop_iterations_.fetch_add(1, std::memory_order_relaxed);
        const auto interval_ns = interval_ns_.load(std::memory_order_acquire);

        std::unique_lock<std::mutex> lk(mtx_);
        cv_.wait_for(lk, std::chrono::nanoseconds(interval_ns), [&] {
            return shutting_down_.load(std::memory_order_acquire) ||
                   flush_requested_.load(std::memory_order_acquire);
        });
        const bool flush = flush_requested_.exchange(false, std::memory_order_acq_rel);
        const bool shutdown = shutting_down_.load(std::memory_order_acquire);
        lk.unlock();

        if (!provider_ || !exporter_) {
            if (shutdown) break;
            continue;
        }

        // Snapshot the provider's current series state and hand to
        // exporter. The snapshot is a consistent point-in-time view
        // produced under the provider's series-map lock.
        try {
            MetricsSnapshot snap = provider_->Snapshot();
            const auto deadline = std::chrono::steady_clock::now() +
                std::chrono::nanoseconds(timeout_ns_.load(std::memory_order_acquire));
            exporter_->Export(std::move(snap), deadline);
            exported_cycles_.fetch_add(1, std::memory_order_relaxed);
        } catch (const std::exception& e) {
            logging::Get()->error(
                "PeriodicMetricReader::Export threw: {}", e.what());
        } catch (...) {
            logging::Get()->error(
                "PeriodicMetricReader::Export threw unknown exception");
        }

        if (shutdown) break;
        (void)flush;  // forced flush already handled by the loop iteration above.
    }
    // Final-flush already happened above (the last iteration with
    // shutdown=true exported once). Signal the exporter unless the
    // manager has flagged it as shared with a BatchSpanProcessor —
    // see DisableExporterShutdownOnDrain for the rationale.
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

void PeriodicMetricReader::SignalShutdown() {
    signal_shutdown_calls_.fetch_add(1, std::memory_order_relaxed);
    bool expected = false;
    if (!shutting_down_.compare_exchange_strong(expected, true,
            std::memory_order_acq_rel)) {
        return;
    }
    // Wake the worker so it can run one final export pass before
    // exiting. Defer exporter signal until JoinWorkers — see
    // BatchSpanProcessor for the rationale.
    cv_.notify_all();
}

void PeriodicMetricReader::JoinWorkers(std::chrono::milliseconds deadline) {
    if (!worker_started_.load(std::memory_order_acquire)) return;
    if (deadline.count() == 0) {
        // Operator-configured "immediate" — return without joining.
        // Mirrors BatchSpanProcessor::JoinWorkers contract; the
        // destructor's unconditional fallback join still pairs with
        // ~PeriodicMetricReader so the thread is never abandoned.
        return;
    }
    if (deadline.count() < 0) {
        if (worker_.joinable()) worker_.join();
        return;
    }
    std::unique_lock<std::mutex> lk(join_mtx_);
    bool done = join_cv_.wait_for(lk, deadline,
                                      [this]{ return worker_done_; });
    lk.unlock();
    if (!done) {
        logging::Get()->warn(
            "PeriodicMetricReader::JoinWorkers timeout after {}ms — "
            "worker still in flight (exporter likely stalled); final "
            "join deferred to destructor",
            deadline.count());
        return;
    }
    if (worker_.joinable()) worker_.join();
}

void PeriodicMetricReader::Reload(MeterReaderOptions new_options) {
    interval_ns_.store(new_options.export_interval.count() * 1'000'000,
                        std::memory_order_release);
    timeout_ns_.store(new_options.export_timeout.count() * 1'000'000,
                       std::memory_order_release);
    cv_.notify_all();
}

void PeriodicMetricReader::ForceFlush(std::chrono::milliseconds /*deadline*/) {
    flush_requested_.store(true, std::memory_order_release);
    cv_.notify_all();
}

}  // namespace OBSERVABILITY_NAMESPACE
