#pragma once

// PrometheusExporter — renders MetricsSnapshot to Prometheus exposition
// or OpenMetrics text. Pull-mode only; each /metrics scrape calls
// Render() once.
//
// Sanitization (applied to BOTH metric names AND label keys):
//   every char outside [a-zA-Z0-9_] → '_'; if the result starts with a
//   digit, prepend '_'.
//
// Counter / UpDownCounter render as one sample per series; Counter gets
// the `_total` suffix per Prometheus convention. Histogram renders as
// cumulative `_bucket{le="..."}` lines plus `_sum` and `_count`.
//
// Sanitization collisions across distinct OTel names are detected on
// every Render() call; each distinct collision pair is logged at most
// once per process via an internal warned-set. The framework HTTP-
// semconv catalog is collision-free, so this fires only on operator-
// added custom names that sanitize to the same Prometheus family.

#include "observability/metrics_snapshot.h"

#include <string>
#include <string_view>

namespace OBSERVABILITY_NAMESPACE {

class PrometheusExporter {
public:
    // Output format selection. Caller picks based on the inbound
    // Accept header.
    enum class Format {
        PrometheusExposition,  // text/plain; version=0.0.4; charset=utf-8
        OpenMetrics,           // application/openmetrics-text; version=1.0.0
    };

    // Render a snapshot to text. Includes # HELP + # TYPE lines per
    // metric, one sample per series. Returns the full body string.
    static std::string Render(const MetricsSnapshot& snap,
                                Format fmt = Format::PrometheusExposition);

    // Sanitize an OTel attribute key (or metric name) into a
    // Prometheus-legal identifier. Public so MeterProvider catalog
    // initialization can warn on collisions at startup.
    static std::string SanitizeName(std::string_view name);

    // Pick a Format from the request's `Accept` header value. The
    // OpenMetrics media type takes precedence when present; otherwise
    // default to Prometheus exposition.
    static Format ChooseFormat(std::string_view accept_header) noexcept;

    // Standard Content-Type strings for the two formats.
    static const char* ContentType(Format fmt) noexcept;
};

}  // namespace OBSERVABILITY_NAMESPACE
