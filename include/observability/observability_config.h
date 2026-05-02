#pragma once

// Minimal ObservabilityConfig for task #66 — just what
// ObservabilityManager + observability middleware need at construction
// and Reload. The full §10 schema (otlp.upstream, otlp.headers,
// metrics.prometheus.path, sampler routes, etc.) lands in task #72
// alongside ConfigLoader::Validate / ValidateHotReloadable wiring.
//
// Per OPENTELEMETRY_DESIGN.md §11.2:
//   - `enabled`               — restart-required (master switch).
//   - `traces.enabled`        — live-reloadable.
//   - `metrics.enabled`       — live-reloadable.
//   - `traces.sampler.*`      — live-reloadable.
//   - `service_name/version/instance_id` — restart-required (Resource
//                                            is built once at startup).
//
// The struct exposes the fields directly; validators (task #72)
// enforce ranges + cross-references. r78 mirroring rule:
// `live_config_.observability.enabled` is the LIVE truth — never
// overwritten by Reload, even when SIGHUP stages a flip.

#include <chrono>
#include <string>

namespace OBSERVABILITY_NAMESPACE {

enum class SamplerType {
    AlwaysOn       = 0,
    AlwaysOff      = 1,
    TraceIdRatio   = 2,
    ParentBased    = 3,  // root sampler defaults to TraceIdRatio.
};

struct SamplerConfig {
    SamplerType type  = SamplerType::ParentBased;
    double      ratio = 1.0;     // for TraceIdRatio + parent-based root.
};

struct TracesConfig {
    bool          enabled = true;
    SamplerConfig sampler;
};

struct MetricsConfig {
    bool                       enabled         = true;
    std::chrono::milliseconds  export_interval = std::chrono::milliseconds{60000};
    std::chrono::milliseconds  export_timeout  = std::chrono::milliseconds{10000};
};

struct ResourceConfig {
    std::string service_name        = "reactor-server";
    std::string service_version;     // empty → omit.
    std::string service_instance_id; // empty → omit.
};

struct ObservabilityConfig {
    bool            enabled = false;  // master switch — RESTART-REQUIRED.
    ResourceConfig  resource;          // RESTART-REQUIRED (Resource is immutable).
    TracesConfig    traces;
    MetricsConfig   metrics;
};

}  // namespace OBSERVABILITY_NAMESPACE
