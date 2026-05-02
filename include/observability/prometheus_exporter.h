#pragma once

// PrometheusExporter — renders MetricsSnapshot to Prometheus
// exposition format (text/plain) or OpenMetrics text (per the
// `Accept` header). Pull-mode only — no worker thread, no scheduled
// export. Each /metrics scrape calls Render() once.
//
// Per OPENTELEMETRY_DESIGN.md §8.3:
//   - Name sanitization: every char outside [a-zA-Z0-9_] → '_';
//     leading digit → prepend '_'.
//   - Label-key sanitization: same rule applied per-key.
//   - Counter / UpDownCounter → emit name (Counter gets `_total`
//     suffix per Prometheus convention) + per-series gauge / counter
//     samples.
//   - Histogram → emit name_bucket{le="<boundary>"} ... +
//     name_sum + name_count.
//   - Collisions across distinct OTel names that sanitize to the
//     same Prometheus name are detected at first render and logged
//     as a startup warning (the §8.3 catalog is collision-free under
//     this rule, so the warning fires only on operator-added custom
//     names).

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
    // OpenMetrics media type takes precedence when present (per
    // OpenMetrics spec §6); otherwise default to Prometheus exposition.
    static Format ChooseFormat(std::string_view accept_header) noexcept;

    // Standard Content-Type strings for the two formats.
    static const char* ContentType(Format fmt) noexcept;
};

}  // namespace OBSERVABILITY_NAMESPACE
