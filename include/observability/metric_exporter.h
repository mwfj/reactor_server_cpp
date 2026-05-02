#pragma once

// MetricExporter — the wire-format export interface for metrics.
// Same r84 trio shape as SpanExporter (SignalShutdown /
// CancelAllActiveExports / RebindDispatcher).

#include "observability/metrics_snapshot.h"
#include "observability/span_exporter.h"  // ExportResult

#include <chrono>

class Dispatcher;

namespace OBSERVABILITY_NAMESPACE {

class MetricExporter {
public:
    virtual ~MetricExporter() = default;

    virtual ExportResult Export(MetricsSnapshot snapshot,
                                 std::chrono::steady_clock::time_point deadline =
                                     std::chrono::steady_clock::time_point::max()) = 0;

    virtual void SignalShutdown() = 0;
    virtual void CancelAllActiveExports() = 0;
    virtual void RebindDispatcher(Dispatcher* /*new_export_dispatcher*/) {}
};

}  // namespace OBSERVABILITY_NAMESPACE
