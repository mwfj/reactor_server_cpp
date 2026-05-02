#include "observability/periodic_metric_reader.h"

#include "log/logger.h"

namespace OBSERVABILITY_NAMESPACE {

PeriodicMetricReader::PeriodicMetricReader(
    MeterProvider*                 provider,
    std::shared_ptr<MetricExporter> exporter,
    MeterReaderOptions             options)
    : provider_(provider),
      exporter_(std::move(exporter)),
      interval_ns_(options.export_interval.count() * 1'000'000),
      timeout_ns_(options.export_timeout.count() * 1'000'000) {
    worker_ = std::thread([this] { WorkerLoop(); });
    worker_started_.store(true, std::memory_order_release);
}

PeriodicMetricReader::~PeriodicMetricReader() {
    SignalShutdown();
    JoinWorkers(std::chrono::milliseconds{2000});
}

void PeriodicMetricReader::WorkerLoop() {
    while (true) {
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
        // exporter. Per §8.4: snapshot is consistent point-in-time view.
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
}

void PeriodicMetricReader::SignalShutdown() {
    bool expected = false;
    if (!shutting_down_.compare_exchange_strong(expected, true,
            std::memory_order_acq_rel)) {
        return;
    }
    if (exporter_) exporter_->SignalShutdown();
    cv_.notify_all();
}

void PeriodicMetricReader::JoinWorkers(std::chrono::milliseconds /*deadline*/) {
    if (!worker_started_.load(std::memory_order_acquire)) return;
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
