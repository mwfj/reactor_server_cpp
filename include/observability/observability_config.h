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
//   - metrics.enabled
//   - traces.enabled  — restart-required when traces.exporter was empty
//                       at boot (no SpanProcessor was ever installed,
//                       so the live flag stays gated to false until a
//                       restart attaches one). PublishLiveFlags warns
//                       on a stage-time flip that can't take effect.
//   - traces.sampler.{type, ratio, routes}
//   - traces.otlp.{headers, timeout_ms}
//   - traces.batch.{max_export_batch_size, schedule_delay_ms,
//                    retries.*}  — max_queue_size is RESTART (queue
//                                  capacity is allocated at ctor and
//                                  Reload never resizes).
//   - metrics.otlp.{headers, timeout_ms}
//   - metrics.reader.{export_interval_ms, export_timeout_ms}
//   - metrics.prometheus.include_target_info

#include "../common.h"

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
    BatchSpanConfig batch;             // live-reloadable except max_queue_size
    // Restart-required equality. ADDING A FIELD:
    //   - restart-only ⇒ include here AND classify in the field-by-
    //     field assignment in ObservabilityManager::Reload (omit it
    //     so the live struct keeps the boot value).
    //   - live-reloadable ⇒ omit here AND copy it through in
    //     ObservabilityManager::Reload's per-field block.
    // Skipping either leg makes the reload silently take effect on
    // restart-only fields or silently no-op on live ones.
    bool operator==(const TracesConfig& o) const {
        return exporter == o.exporter
            && otlp.upstream == o.otlp.upstream
            // BatchSpanProcessor allocates queue capacity at construction;
            // Reload never resizes, so the field is restart-only.
            && batch.max_queue_size == o.batch.max_queue_size;
    }
    bool operator!=(const TracesConfig& o) const { return !(*this == o); }
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
    // Hard cap on per-instrument histogram boundary count. Each
    // (instrument, label combination) allocates one cumulative
    // counter per boundary, so an unbounded boundary list scales
    // memory linearly with cardinality and is a denial-of-service
    // surface. Shared by config validation and any future
    // construction-time validators.
    static constexpr size_t kMaxBucketsPerInstrument = 256;

    bool        enabled  = true;       // live-reloadable
    std::string exporter;              // "otlp_http" | "prometheus_pull" | "". RESTART
    OtlpTransportConfig otlp;          // upstream RESTART; headers/timeout/interval live
    PeriodicReaderConfig reader;       // live-reloadable
    PrometheusConfig prometheus;       // path RESTART; include_target_info live
    // Per-instrument bucket overrides (instrument-name -> boundaries).
    // RESTART-only — bucket layout cannot change once Series are
    // populated without losing histogram coherency.
    std::map<std::string, std::vector<double>> histogram_buckets;
    // Restart-required equality. Same field-classification contract
    // as TracesConfig::operator== above.
    bool operator==(const MetricsConfig& o) const {
        return exporter == o.exporter
            && otlp.upstream == o.otlp.upstream
            && prometheus.path == o.prometheus.path
            && histogram_buckets == o.histogram_buckets;
    }
    bool operator!=(const MetricsConfig& o) const { return !(*this == o); }
};

struct ResourceConfig {
    std::string service_name        = "reactor-server";
    std::string service_version;     // empty → omit.
    std::string service_instance_id; // empty → omit.
    // Restart-required equality. Same field-classification contract as
    // TracesConfig::operator== — every existing field is restart-only
    // (Resource attributes are baked into spans + the Prometheus
    // target_info series at construction; runtime mutation would
    // re-key all in-flight series). Adding a future field (e.g. OTel
    // service.namespace) MUST update this comparator AND classify in
    // ObservabilityManager::Reload's per-field block.
    bool operator==(const ResourceConfig& o) const {
        return service_name == o.service_name
            && service_version == o.service_version
            && service_instance_id == o.service_instance_id;
    }
    bool operator!=(const ResourceConfig& o) const { return !(*this == o); }
};

struct ObservabilityConfig {
    bool            enabled = false;   // master switch — RESTART.
    ResourceConfig  resource;          // RESTART.
    TracesConfig    traces;
    MetricsConfig   metrics;

    // Restart-required equality — only fields that cannot be hot-reloaded
    // contribute. The HttpServer::Reload outer "restart required" warn
    // fires when this differs between live and staged configs.
    // Composition is delegated to ResourceConfig / TracesConfig /
    // MetricsConfig operator== so adding a field to one of those
    // structs forces the author to revisit the field-classification
    // contract there.
    bool operator==(const ObservabilityConfig& o) const {
        return enabled == o.enabled
            && resource == o.resource
            && traces == o.traces
            && metrics == o.metrics;
    }
    bool operator!=(const ObservabilityConfig& o) const { return !(*this == o); }
};

}  // namespace OBSERVABILITY_NAMESPACE
