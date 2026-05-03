#pragma once

// MakeMetricsHandler — sync HttpRouter::Handler that renders
// MeterProvider::Snapshot() through the PrometheusExporter on each
// scrape:
//   - Picks Format from the request's Accept header
//     (`application/openmetrics-text` → OpenMetrics, else exposition).
//   - Live read of `metrics.enabled`; replies 404 when disabled so the
//     route stays registered across reload toggles.
//   - Live read of `metrics.prometheus.include_target_info` so a
//     SIGHUP flip takes effect on the next scrape. (The path itself
//     is restart-only.)
//
// Captures only a weak_ptr<ObservabilityManager> so the handler never
// extends manager lifetime.

#include "http/http_router.h"
#include "observability/common.h"

#include <memory>

namespace OBSERVABILITY_NAMESPACE {

class ObservabilityManager;

HttpRouter::Handler MakeMetricsHandler(
    std::weak_ptr<ObservabilityManager> manager);

}  // namespace OBSERVABILITY_NAMESPACE
