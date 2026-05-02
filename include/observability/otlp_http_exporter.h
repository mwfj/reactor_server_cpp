#pragma once

// OtlpHttpExporter — serializes SpanData / MetricsSnapshot to OTLP/JSON
// per the v1.10 OpenTelemetry protocol spec, then hands the payload to
// a caller-supplied transport callback.
//
// Per OPENTELEMETRY_DESIGN.md §8.1 r84:
//   - Implements SpanExporter + MetricExporter (one exporter handles
//     both signal types; per-signal Options carry trace vs metric
//     routing — Tempo for traces, Prometheus-OTLP / Mimir for metrics).
//   - r84 trio: SignalShutdown / CancelAllActiveExports / RebindDispatcher.
//   - Owns NO worker thread (BatchSpanProcessor / PeriodicMetricReader
//     own worker shutdown).
//
// Transport pluggability: the exporter accepts an `OnSerializedExport`
// callback that receives the (path, headers, body) tuple. Production
// wiring (task #74/#75) installs a callback that POSTs through
// `UpstreamHttpClient::Issue`. Tests install a capture callback that
// retains the payload for inspection.

#include "observability/metric_exporter.h"
#include "observability/span_exporter.h"

#include <atomic>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace OBSERVABILITY_NAMESPACE {

class OtlpHttpExporter
    : public SpanExporter,
      public MetricExporter,
      public std::enable_shared_from_this<OtlpHttpExporter> {
public:
    // Per-signal options — operators commonly route trace and metric
    // OTLP to separate collectors. Per §8.1 r79: live-reloadable subset
    // is `headers` + `timeout_ms` ONLY (controlled merge under r79;
    // upstream_pool_name + path are restart-only).
    struct SignalOptions {
        std::string upstream_pool_name;  // e.g. "otel_traces_collector"
        std::string path;                 // "/v1/traces" or "/v1/metrics"
        std::map<std::string, std::string> headers;
        std::chrono::milliseconds timeout{10000};
    };

    struct Options {
        SignalOptions traces  = { "otel_traces_collector",  "/v1/traces", {}, std::chrono::milliseconds{10000} };
        SignalOptions metrics = { "otel_metrics_collector", "/v1/metrics", {}, std::chrono::milliseconds{10000} };
    };

    // Transport callback — receives a fully-built OTLP HTTP request.
    // Returns the export result. Production wiring uses
    // `UpstreamHttpClient::Issue`; tests use a capture lambda.
    struct ExportPayload {
        std::string upstream_pool_name;
        std::string path;
        std::map<std::string, std::string> headers;  // includes Content-Type
        std::string body;                              // OTLP/JSON serialized
        std::chrono::milliseconds timeout;
    };
    using TransportFn =
        std::function<ExportResult(ExportPayload payload,
                                     std::chrono::steady_clock::time_point deadline)>;

    // Factory — must use Create() so enable_shared_from_this seeds
    // the internal weak reference (matches the manager's pattern).
    static std::shared_ptr<OtlpHttpExporter> Create(
        Options     opts,
        TransportFn transport);

    OtlpHttpExporter(const OtlpHttpExporter&) = delete;
    OtlpHttpExporter& operator=(const OtlpHttpExporter&) = delete;
    ~OtlpHttpExporter() override = default;

    // SpanExporter interface.
    ExportResult Export(std::vector<SpanData> batch,
                         std::chrono::steady_clock::time_point deadline =
                             std::chrono::steady_clock::time_point::max()) override;
    // MetricExporter interface.
    ExportResult Export(MetricsSnapshot snapshot,
                         std::chrono::steady_clock::time_point deadline =
                             std::chrono::steady_clock::time_point::max()) override;

    // r84 trio (overrides both base interfaces).
    void SignalShutdown() override;
    void CancelAllActiveExports() override;
    void RebindDispatcher(Dispatcher* /*new_export_dispatcher*/) override {}

    // Live-reloadable: controlled merge per r79. Replaces ONLY
    // `headers` + `timeout` on the matching signal (traces or
    // metrics). Restart-only fields (upstream_pool_name, path) are
    // preserved.
    void ReloadHeaders(const std::map<std::string, std::string>& trace_headers,
                        const std::map<std::string, std::string>& metric_headers,
                        std::chrono::milliseconds trace_timeout,
                        std::chrono::milliseconds metric_timeout);

    // Diagnostics.
    int64_t exports_attempted() const noexcept {
        return exports_attempted_.load(std::memory_order_acquire);
    }
    int64_t exports_succeeded() const noexcept {
        return exports_succeeded_.load(std::memory_order_acquire);
    }
    int64_t exports_failed() const noexcept {
        return exports_failed_.load(std::memory_order_acquire);
    }
    int64_t exports_cancelled() const noexcept {
        return exports_cancelled_.load(std::memory_order_acquire);
    }

private:
    OtlpHttpExporter(Options opts, TransportFn transport);

    // OTLP/JSON serializers — per-signal builders. Produce an
    // application/json body matching the OTLP HTTP v1.10 schema:
    //   traces  → { "resourceSpans": [ ... ] }
    //   metrics → { "resourceMetrics": [ ... ] }
    static std::string SerializeSpansToJson(const std::vector<SpanData>& batch);
    static std::string SerializeMetricsToJson(const MetricsSnapshot& snap);

    // SignalOptions snapshot — atomic_load via std::atomic<shared_ptr>
    // so reload + hot-path reads don't tear.
    std::shared_ptr<const Options> Snapshot() const noexcept;

    TransportFn                    transport_;
    std::shared_ptr<const Options> options_;       // atomic-swapped on Reload
    mutable std::mutex             options_mtx_;   // Reload critical section

    std::atomic<bool>              shutting_down_{false};
    std::atomic<int64_t>           active_exports_{0};
    std::atomic<int64_t>           exports_attempted_{0};
    std::atomic<int64_t>           exports_succeeded_{0};
    std::atomic<int64_t>           exports_failed_{0};
    std::atomic<int64_t>           exports_cancelled_{0};
};

}  // namespace OBSERVABILITY_NAMESPACE
