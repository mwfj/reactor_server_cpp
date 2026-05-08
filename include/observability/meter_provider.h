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
    explicit MeterProvider(std::shared_ptr<const Resource> resource,
                            size_t shard_count = kDefaultMetricShards);

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
};

}  // namespace OBSERVABILITY_NAMESPACE
