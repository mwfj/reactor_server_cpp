#pragma once

// MakeMetricsHandler — produces a sync HttpRouter::Handler that
// renders MeterProvider::Snapshot() through the PrometheusExporter on
// each scrape. Per OPENTELEMETRY_DESIGN.md §8.3:
//   - Format selection from the request's `Accept` header
//     (`application/openmetrics-text` → OpenMetrics, else exposition).
//   - Live read of `metrics.enabled`; returns 404 when disabled so the
//     route stays registered across reload toggles.
//   - Live read of `metrics.prometheus.include_target_info` so SIGHUP
//     flips take effect on the next scrape (path itself is restart-only).
//
// The returned handler captures only a `weak_ptr<ObservabilityManager>`
// so it never extends manager lifetime; callers wire it through
// `HttpRouter::Get(config.observability.metrics.prometheus.path, ...)`.

#include "http/http_router.h"
#include "observability/common.h"

#include <memory>

namespace OBSERVABILITY_NAMESPACE {

class ObservabilityManager;

HttpRouter::Handler MakeMetricsHandler(
    std::weak_ptr<ObservabilityManager> manager);

}  // namespace OBSERVABILITY_NAMESPACE
