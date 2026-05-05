#pragma once

// ObservabilityConfig — operator-facing observability schema mirrored
// onto ServerConfig::observability. Field-by-field restart vs live-
// reloadable classification:
//
// Restart-required:
//   - enabled (master switch)
//   - resource.{service_name, service_version, service_instance_id}
//   - traces.exporter
//   - traces.otlp.upstream
//   - metrics.exporter
//   - metrics.otlp.upstream
//   - metrics.prometheus.path
//   - metrics.histogram_buckets.<name>
//
// Live-reloadable (apply on next request / next scrape / next export):
//   - traces.enabled, metrics.enabled
//   - traces.sampler.{type, ratio, routes}
//   - traces.otlp.{headers, timeout_ms}
//   - traces.batch.{max_queue_size, max_export_batch_size,
//                    schedule_delay_ms, retries.*}
//   - metrics.otlp.{headers, timeout_ms, export_interval_ms}
//   - metrics.prometheus.include_target_info

#include <chrono>
#include <map>
#include <string>
#include <vector>

namespace OBSERVABILITY_NAMESPACE {

enum class SamplerType {
    AlwaysOn       = 0,
    AlwaysOff      = 1,
    TraceIdRatio   = 2,
    ParentBased    = 3,  // root sampler defaults to TraceIdRatio.
};

// Per-route sampler override. `path` is matched as a literal byte-
// prefix against `req.path` BEFORE any pattern resolution.
struct SamplerRouteOverride {
    std::string path;        // e.g. "/metrics", "/health"
    SamplerType sampler = SamplerType::AlwaysOff;
    double      ratio   = 1.0;
};

struct SamplerConfig {
    SamplerType type  = SamplerType::ParentBased;
    double      ratio = 1.0;
    std::vector<SamplerRouteOverride> routes;
};

// OTLP/HTTP transport options. The OTLP collector is modelled as a
// regular `upstreams[]` entry referenced here by name.
struct OtlpTransportConfig {
    std::string upstream;                        // upstreams[].name (cross-ref)
    std::map<std::string, std::string> headers;  // additional outbound headers
    std::chrono::milliseconds timeout_ms = std::chrono::milliseconds{10000};
};

// BatchSpanProcessor knobs — all live-reloadable.
struct BatchSpanRetriesConfig {
    int max_attempts = 3;
    std::chrono::milliseconds initial_backoff = std::chrono::milliseconds{1000};
    std::chrono::milliseconds max_backoff     = std::chrono::milliseconds{10000};
};

struct BatchSpanConfig {
    int max_queue_size           = 2048;
    int max_export_batch_size    = 512;
    std::chrono::milliseconds schedule_delay = std::chrono::milliseconds{5000};
    BatchSpanRetriesConfig retries;
};

struct TracesConfig {
    bool          enabled  = true;     // live-reloadable
    std::string   exporter;            // "otlp_http" | "" (off). RESTART.
    SamplerConfig sampler;             // live-reloadable
    OtlpTransportConfig otlp;          // upstream RESTART; headers/timeout live
    BatchSpanConfig batch;             // live-reloadable
};

struct PrometheusConfig {
    std::string path                 = "/metrics";  // RESTART
    bool        include_target_info  = true;          // live-reloadable
};

struct PeriodicReaderConfig {
    std::chrono::milliseconds export_interval = std::chrono::milliseconds{60000};
    std::chrono::milliseconds export_timeout  = std::chrono::milliseconds{10000};
};

struct MetricsConfig {
    bool        enabled  = true;       // live-reloadable
    std::string exporter;              // "otlp_http" | "prometheus_pull" | "". RESTART
    OtlpTransportConfig otlp;          // upstream RESTART; headers/timeout/interval live
    PeriodicReaderConfig reader;       // live-reloadable
    PrometheusConfig prometheus;       // path RESTART; include_target_info live
    // Per-instrument bucket overrides (instrument-name -> boundaries).
    // RESTART-only — bucket layout cannot change once Series are
    // populated without losing histogram coherency.
    std::map<std::string, std::vector<double>> histogram_buckets;
};

struct ResourceConfig {
    std::string service_name        = "reactor-server";
    std::string service_version;     // empty → omit.
    std::string service_instance_id; // empty → omit.
};

struct ObservabilityConfig {
    bool            enabled = false;   // master switch — RESTART.
    ResourceConfig  resource;          // RESTART.
    TracesConfig    traces;
    MetricsConfig   metrics;

    // Restart-required equality — only fields that cannot be hot-reloaded
    // contribute. The HttpServer::Reload outer "restart required" warn
    // fires when this differs between live and staged configs.
    bool operator==(const ObservabilityConfig& o) const {
        return enabled == o.enabled
            && resource.service_name == o.resource.service_name
            && resource.service_version == o.resource.service_version
            && resource.service_instance_id == o.resource.service_instance_id
            && traces.exporter == o.traces.exporter
            && traces.otlp.upstream == o.traces.otlp.upstream
            // BatchSpanProcessor allocates queue capacity at
            // construction; Reload() never resizes. Edits would
            // silently no-op until restart, so this is restart-only.
            && traces.batch.max_queue_size == o.traces.batch.max_queue_size
            && metrics.exporter == o.metrics.exporter
            && metrics.otlp.upstream == o.metrics.otlp.upstream
            && metrics.prometheus.path == o.metrics.prometheus.path
            && metrics.histogram_buckets == o.metrics.histogram_buckets;
    }
    bool operator!=(const ObservabilityConfig& o) const { return !(*this == o); }
};

}  // namespace OBSERVABILITY_NAMESPACE
