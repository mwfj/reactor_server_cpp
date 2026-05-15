#pragma once

// MeterProvider — factory for Meters + entry point for /metrics
// snapshots. Constructed by ObservabilityManager (one per pipeline);
// holds shared Resource + a fixed shard count for every Meter it
// produces.
//
// Reload accepts new reader options (export interval / timeout) for
// the PeriodicMetricReader. Histogram bucket boundaries + cardinality
// caps are restart-only; the provider itself doesn't carry mutable
// histogram state.

#include "observability/meter.h"
#include "observability/metric_writer_context.h"
#include "observability/metrics_snapshot.h"
#include "observability/resource.h"

#include "../common.h"
// <chrono>, <memory>, <mutex>, <string>, <unordered_map> via common.h

namespace OBSERVABILITY_NAMESPACE {

class ObservabilityManager;

// Subset of PeriodicMetricReader knobs passed through Reload.
// Reader-side knobs are export_interval + export_timeout only;
// max_export_batch_size + schedule_delay are TRACE-only and live on
// BatchSpanProcessor instead.
struct MeterReaderOptions {
    std::chrono::milliseconds export_interval = std::chrono::milliseconds{60000};
    std::chrono::milliseconds export_timeout  = std::chrono::milliseconds{10000};
};

class MeterProvider {
public:
    // `manager` is forwarded into every Meter the provider constructs so
    // the cardinality-overflow self-metric can find its catalog instrument.
    // Default null retained for tests that build a raw provider outside
    // an ObservabilityManager (overflow events are silent in that case).
    explicit MeterProvider(std::shared_ptr<const Resource> resource,
                            size_t shard_count = kDefaultMetricShards,
                            ObservabilityManager* manager = nullptr);

    MeterProvider(const MeterProvider&) = delete;
    MeterProvider& operator=(const MeterProvider&) = delete;

    Meter* GetMeter(const std::string& name,
                     const std::string& version = {});

    // Reload the live-reloadable subset. Returns the new reader options
    // so the caller (ObservabilityManager) can forward them to the
    // PeriodicMetricReader.
    void Reload(MeterReaderOptions reader_options);

    MeterReaderOptions reader_options() const noexcept;

    // Snapshot every instrument across every Meter into a single
    // MetricsSnapshot. Used by the Prometheus pull handler and the
    // PeriodicMetricReader.
    MetricsSnapshot Snapshot() const;

private:
    std::shared_ptr<const Resource> resource_;
    size_t                          shard_count_;

    mutable std::mutex                                    meter_mtx_;
    std::unordered_map<std::string, std::unique_ptr<Meter>> meters_;
    MeterReaderOptions                                     reader_options_;

    // Raw pointer; manager storage outlives the provider (MeterProvider
    // destructs as part of ~ObservabilityManager's body). See
    // batch_span_processor.h::manager() docstring for the SHUTDOWN
    // CAVEAT that applies to any code path consuming manager_->
    // sub-members (catalog, meter_provider, metric_reader) — those may
    // already be destroyed by the time worker drains run.
    // (Today this dtor is default and emits nothing — caveat applies
    // only if a future dtor adds emission paths.)
    ObservabilityManager*                                  manager_ = nullptr;
};

}  // namespace OBSERVABILITY_NAMESPACE
