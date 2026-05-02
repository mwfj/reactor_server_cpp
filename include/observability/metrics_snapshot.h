#pragma once

// MetricsSnapshot — POD snapshot of every instrument's current series
// state, produced by MeterProvider::Snapshot() and consumed by the
// PrometheusExporter / OtlpHttpExporter / PeriodicMetricReader.
//
// Each instrument contributes one CounterSeries / HistogramSeries
// vector (one entry per LabelSet emitted on that instrument). The
// snapshot is a CONSISTENT POINT-IN-TIME view — the SeriesMap
// implementation produces it by acquiring a shared_lock during the
// drain so no concurrent SeriesMap::find_or_create can split a
// counter's labels and value across the snapshot boundary.

#include "observability/attr_value.h"
#include "observability/instrumentation_scope.h"
#include "observability/resource.h"

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace OBSERVABILITY_NAMESPACE {

// Instrument kind tag — preserved through to the exporter so OTLP /
// Prometheus can choose the right wire shape (counter vs gauge vs
// histogram).
enum class InstrumentKind : uint8_t {
    Counter        = 1,  // Monotonic; reported as `_total` in Prometheus.
    UpDownCounter  = 2,  // Non-monotonic gauge-like.
    Histogram      = 3,  // Bucketed distribution + sum/count.
};

struct CounterPoint {
    LabelSet labels;
    double   value = 0;
};

struct HistogramPoint {
    LabelSet            labels;
    std::vector<double> bucket_boundaries;  // explicit boundaries
    std::vector<uint64_t> bucket_counts;    // size = boundaries+1 (last = +Inf)
    double               sum   = 0;
    uint64_t             count = 0;
    double               min   = 0;
    double               max   = 0;
    bool                 has_min_max = false;
};

struct InstrumentSnapshot {
    std::string                name;
    std::string                description;
    std::string                unit;
    InstrumentKind             kind = InstrumentKind::Counter;
    std::shared_ptr<const InstrumentationScope> scope;
    // Exactly one of these is populated based on `kind`.
    std::vector<CounterPoint>   counter_points;
    std::vector<HistogramPoint> histogram_points;
};

struct MetricsSnapshot {
    std::shared_ptr<const Resource>   resource;
    std::vector<InstrumentSnapshot>   instruments;
    // Wall-clock snapshot time; collectors use this as the export point.
    std::chrono::system_clock::time_point timestamp{};
};

}  // namespace OBSERVABILITY_NAMESPACE
