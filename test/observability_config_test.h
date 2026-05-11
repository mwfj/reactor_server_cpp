#pragma once

// ObservabilityConfig schema + ConfigLoader integration tests.
// Validates JSON load, startup Validate, ValidateHotReloadable subset,
// and the MakeMetricsHandler factory live-reads.

#include "test_framework.h"
#include "config/config_loader.h"
#include "observability/metrics_handler.h"
#include "observability/observability_config.h"
#include "observability/observability_manager.h"
#include "observability/resource.h"
#include "observability/span_processor.h"
#include "observability/trace_id.h"
#include "http/http_request.h"
#include "http/http_response.h"

#include <memory>
#include <string>
#include <unordered_set>

namespace ObservabilityConfigTests {

using OBSERVABILITY_NAMESPACE::AttrValue;
using OBSERVABILITY_NAMESPACE::Attribute;
using OBSERVABILITY_NAMESPACE::ObservabilityConfig;
using OBSERVABILITY_NAMESPACE::ObservabilityManager;
using OBSERVABILITY_NAMESPACE::NoopSpanProcessor;
using OBSERVABILITY_NAMESPACE::RandomSource;
using OBSERVABILITY_NAMESPACE::Resource;
using OBSERVABILITY_NAMESPACE::SamplerType;
using OBSERVABILITY_NAMESPACE::SamplerRouteOverride;
using OBSERVABILITY_NAMESPACE::SpanProcessor;
using OBSERVABILITY_NAMESPACE::MakeMetricsHandler;

// ---- JSON load ----

void TestJsonLoadFullSchema() {
    try {
        std::string js = R"({
            "observability": {
                "enabled": true,
                "resource": {
                    "service_name": "gw",
                    "service_version": "9.9",
                    "service_instance_id": "host-1"
                },
                "traces": {
                    "enabled": true,
                    "exporter": "otlp_http",
                    "sampler": {
                        "type": "trace_id_ratio",
                        "ratio": 0.25,
                        "routes": [
                            {"path": "/metrics", "sampler": "always_off"}
                        ]
                    },
                    "otlp": {
                        "upstream": "tempo",
                        "timeout_ms": 5000,
                        "headers": {"x-tenant": "team-a"}
                    },
                    "batch": {
                        "max_queue_size": 1024,
                        "max_export_batch_size": 256,
                        "schedule_delay_ms": 2500,
                        "retries": {"max_attempts": 4, "initial_backoff_ms": 500, "max_backoff_ms": 5000}
                    }
                },
                "metrics": {
                    "enabled": true,
                    "exporter": "prometheus_pull",
                    "export_interval_ms": 30000,
                    "export_timeout_ms": 8000,
                    "prometheus": {"path": "/observability/metrics", "include_target_info": false},
                    "histogram_buckets": {
                        "http.server.request.duration": [0.005, 0.01, 0.05, 0.1]
                    }
                }
            }
        })";
        auto cfg = ConfigLoader::LoadFromString(js);
        const auto& oc = cfg.observability;
        bool pass =
            oc.enabled
            && oc.resource.service_name == "gw"
            && oc.resource.service_version == "9.9"
            && oc.traces.exporter == "otlp_http"
            && oc.traces.otlp.upstream == "tempo"
            && oc.traces.otlp.headers.count("x-tenant") == 1
            && oc.traces.sampler.type == SamplerType::TraceIdRatio
            && oc.traces.sampler.ratio == 0.25
            && !oc.traces.sampler.routes.empty()
            // Lookup-by-path rather than positional: auto-appends
            // (/observability/metrics, /health, /stats) are prepended
            // by ApplySamplerSelfNoiseDefaults so the operator-supplied
            // /metrics entry sits AFTER them in the routes vector. The
            // earlier positional check `routes[0].path == "/metrics"`
            // accidentally locked in the back-append ordering.
            && std::any_of(oc.traces.sampler.routes.begin(),
                           oc.traces.sampler.routes.end(),
                           [](const SamplerRouteOverride& r) {
                               return r.path == "/metrics" &&
                                      r.sampler == SamplerType::AlwaysOff;
                           })
            && oc.traces.batch.max_queue_size == 1024
            && oc.traces.batch.retries.max_attempts == 4
            && oc.metrics.exporter == "prometheus_pull"
            && oc.metrics.reader.export_interval.count() == 30000
            && oc.metrics.prometheus.path == "/observability/metrics"
            && oc.metrics.prometheus.include_target_info == false
            && oc.metrics.histogram_buckets.count("http.server.request.duration") == 1;
        TestFramework::RecordTest("ObsCfg: full schema JSON load",
            pass, pass ? "" : "schema field mismatch",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsCfg: full schema JSON load",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- Validate: live subset ----

void TestValidateRejectsBadInterval() {
    try {
        auto cfg = ConfigLoader::LoadFromString(R"({
            "observability": {"enabled": true, "metrics": {"export_interval_ms": 0}}
        })");
        bool threw = false;
        try {
            ConfigLoader::Validate(cfg);
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        TestFramework::RecordTest("ObsCfg: Validate rejects export_interval_ms=0",
            threw, threw ? "" : "didn't throw",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsCfg: Validate rejects export_interval_ms=0",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestValidateRejectsRatioOutOfRange() {
    try {
        auto cfg = ConfigLoader::LoadFromString(R"({
            "observability": {"enabled": true,
                "traces": {"sampler": {"type": "trace_id_ratio", "ratio": 1.5}}
            }
        })");
        bool threw = false;
        try { ConfigLoader::Validate(cfg); }
        catch (const std::invalid_argument&) { threw = true; }
        TestFramework::RecordTest("ObsCfg: Validate rejects sampler ratio > 1.0",
            threw, threw ? "" : "didn't throw",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsCfg: Validate rejects sampler ratio > 1.0",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- Validate: restart-required cross-references ----

void TestValidateRejectsUnknownOtlpUpstream() {
    try {
        auto cfg = ConfigLoader::LoadFromString(R"({
            "observability": {"enabled": true,
                "traces": {"exporter": "otlp_http", "otlp": {"upstream": "ghost"}}
            }
        })");
        bool threw = false;
        try { ConfigLoader::Validate(cfg); }
        catch (const std::invalid_argument&) { threw = true; }
        TestFramework::RecordTest("ObsCfg: Validate rejects unknown otlp.upstream",
            threw, threw ? "" : "didn't throw",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsCfg: Validate rejects unknown otlp.upstream",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestValidatePromPathMustStartWithSlash() {
    try {
        auto cfg = ConfigLoader::LoadFromString(R"({
            "observability": {"enabled": true,
                "metrics": {"exporter": "prometheus_pull",
                             "prometheus": {"path": "metrics"}}
            }
        })");
        bool threw = false;
        try { ConfigLoader::Validate(cfg); }
        catch (const std::invalid_argument&) { threw = true; }
        TestFramework::RecordTest("ObsCfg: Validate rejects prom path without leading /",
            threw, threw ? "" : "didn't throw",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsCfg: Validate rejects prom path without leading /",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestValidateRejectsPromPathSlashOnly() {
    // Regression: bare "/" would route every request via the sampler's
    // path-or-subtree prefix match, silently disabling traces site-wide.
    // The auto-append also no-ops on "/", but the silent skip was
    // operator-invisible — hard-reject at load.
    try {
        auto cfg = ConfigLoader::LoadFromString(R"({
            "observability": {"enabled": true,
                "metrics": {"exporter": "prometheus_pull",
                             "prometheus": {"path": "/"}}
            }
        })");
        bool threw = false;
        try { ConfigLoader::Validate(cfg); }
        catch (const std::invalid_argument&) { threw = true; }
        TestFramework::RecordTest(
            "ObsCfg: Validate rejects prom path == \"/\"",
            threw, threw ? "" : "didn't throw",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsCfg: Validate rejects prom path == \"/\"",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestValidateRejectsHistogramBucketsOutOfOrder() {
    try {
        auto cfg = ConfigLoader::LoadFromString(R"({
            "observability": {"enabled": true,
                "metrics": {"histogram_buckets": {"x": [0.1, 0.05, 0.2]}}
            }
        })");
        bool threw = false;
        try { ConfigLoader::Validate(cfg); }
        catch (const std::invalid_argument&) { threw = true; }
        TestFramework::RecordTest("ObsCfg: Validate rejects non-monotonic buckets",
            threw, threw ? "" : "didn't throw",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsCfg: Validate rejects non-monotonic buckets",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- ValidateHotReloadable: live-only subset rejects bad live values ----

void TestHotReloadableRejectsBadLiveValue() {
    try {
        auto cfg = ConfigLoader::LoadFromString(R"({
            "observability": {"enabled": true,
                "traces": {"batch": {"max_queue_size": 4, "max_export_batch_size": 16}}
            }
        })");
        bool threw = false;
        try {
            ConfigLoader::ValidateHotReloadable(cfg, {});
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        TestFramework::RecordTest("ObsCfg: ValidateHotReloadable rejects batch_size > queue_size",
            threw, threw ? "" : "didn't throw",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsCfg: ValidateHotReloadable rejects batch_size > queue_size",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// observability_live=false (server started with enabled=false) MUST
// NOT reject stale invalid live values in the staged file. There is no
// running ObservabilityManager to consume those fields, so failing here
// would block unrelated live-safe edits in the same SIGHUP. When the
// staged file flips enabled=true the validator runs because the
// operator is opting in (the !oc.enabled short-circuit no longer fires).
void TestHotReloadableSkipsBadLiveValueWhenNotLive() {
    try {
        // Stale live-knob value (schedule_delay_ms=0) carried over in
        // a config whose master switch is disabled. observability_live
        // is false → validator must skip the live-knob range checks.
        auto cfg = ConfigLoader::LoadFromString(R"({
            "observability": {"enabled": false,
                "traces": {"batch": {"schedule_delay_ms": 0}}
            }
        })");
        bool threw = false;
        try {
            ConfigLoader::ValidateHotReloadable(cfg, {}, {},
                /*observability_live=*/false);
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        TestFramework::RecordTest(
            "ObsCfg: ValidateHotReloadable skips bad live value when not live",
            !threw, threw ? "rejected stale live value with no live runtime" : "",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsCfg: ValidateHotReloadable skips bad live value when not live",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// observability_live=true (running manager exists, even when staged
// enabled=false) MUST reject bad live values: the live pipeline keeps
// consuming them until restart because disabling is restart-only.
void TestHotReloadableForcesLiveValidationWhenLive() {
    try {
        auto cfg = ConfigLoader::LoadFromString(R"({
            "observability": {"enabled": false,
                "traces": {"batch": {"schedule_delay_ms": 0}}
            }
        })");
        bool threw = false;
        try {
            ConfigLoader::ValidateHotReloadable(cfg, {}, {},
                /*observability_live=*/true);
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        TestFramework::RecordTest(
            "ObsCfg: ValidateHotReloadable forces live validation when live",
            threw, threw ? "" : "didn't throw on bad live value",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsCfg: ValidateHotReloadable forces live validation when live",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ValidateHotReloadable must mirror LoadFromString's checks on
// `traces.propagators` (live-reloadable). LoadFromString validates at
// JSON parse time, but a hand-built ServerConfig that bypasses the
// loader would otherwise reach ObservabilityManager::Reload, where
// CompositePropagator::Build throws AFTER earlier subsystems already
// committed — violating the atomic-reload contract. The validator
// must hard-reject empty / unknown / duplicate names at the gate.
void TestHotReloadableRejectsBadPropagators() {
    try {
        // Hand-built config bypasses LoadFromString's validation.
        ServerConfig empty_cfg;
        empty_cfg.observability.enabled = true;
        empty_cfg.observability.traces.propagators = {};
        bool threw_empty = false;
        try { ConfigLoader::ValidateHotReloadable(empty_cfg, {}); }
        catch (const std::invalid_argument&) { threw_empty = true; }

        ServerConfig unknown_cfg;
        unknown_cfg.observability.enabled = true;
        unknown_cfg.observability.traces.propagators = {"w3c", "garbage"};
        bool threw_unknown = false;
        try { ConfigLoader::ValidateHotReloadable(unknown_cfg, {}); }
        catch (const std::invalid_argument&) { threw_unknown = true; }

        ServerConfig dup_cfg;
        dup_cfg.observability.enabled = true;
        dup_cfg.observability.traces.propagators = {"w3c", "w3c"};
        bool threw_dup = false;
        try { ConfigLoader::ValidateHotReloadable(dup_cfg, {}); }
        catch (const std::invalid_argument&) { threw_dup = true; }

        bool pass = threw_empty && threw_unknown && threw_dup;
        TestFramework::RecordTest(
            "ObsCfg: ValidateHotReloadable rejects empty/unknown/duplicate propagators",
            pass, pass ? ""
                      : "empty=" + std::to_string(threw_empty)
                       + " unknown=" + std::to_string(threw_unknown)
                       + " dup=" + std::to_string(threw_dup),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsCfg: ValidateHotReloadable rejects empty/unknown/duplicate propagators",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// HotReloadable should NOT reject restart-required-only fields (those
// are surfaced by HttpServer::Reload's outer warn).
void TestHotReloadableSkipsRestartFields() {
    try {
        auto cfg = ConfigLoader::LoadFromString(R"({
            "observability": {"enabled": true,
                "traces": {"exporter": "otlp_http", "otlp": {"upstream": "missing"}}
            }
        })");
        bool threw = false;
        try {
            ConfigLoader::ValidateHotReloadable(cfg, {});
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        TestFramework::RecordTest(
            "ObsCfg: ValidateHotReloadable skips restart-only otlp.upstream cross-ref",
            !threw, threw ? "incorrectly threw on restart-only field" : "",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsCfg: ValidateHotReloadable skips restart-only otlp.upstream cross-ref",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- OTLP exporter validation (Phase 2 — pipeline now wired) ----

// Phase 1 fail-closed rejected `otlp_http` outright at Validate(). Phase 2
// wires the OTLP push pipeline, so the rejection is gone and a config that
// names a valid upstream must Validate cleanly.
void TestOtlpHttpExporterValidatesAtLoad() {
    try {
        auto cfg = ConfigLoader::LoadFromString(R"({
            "upstreams": [{"name": "otel_collector", "host": "127.0.0.1",
                            "port": 4318, "tls": {"enabled": false},
                            "pool": {"max_connections": 4, "max_idle_connections": 4}}],
            "observability": {
                "enabled": true,
                "traces":  {"exporter": "otlp_http", "otlp": {"upstream": "otel_collector"}},
                "metrics": {"exporter": "otlp_http", "otlp": {"upstream": "otel_collector"}}
            }
        })");
        std::string err;
        try { ConfigLoader::Validate(cfg); }
        catch (const std::exception& e) { err = e.what(); }
        bool pass = err.empty()
                  && cfg.observability.traces.exporter == "otlp_http"
                  && cfg.observability.traces.otlp.upstream == "otel_collector"
                  && cfg.observability.metrics.exporter == "otlp_http"
                  && cfg.observability.metrics.otlp.upstream == "otel_collector";
        TestFramework::RecordTest(
            "ObsCfg: Validate accepts otlp_http with matching upstream",
            pass, !err.empty() ? "Validate threw: " + err : (pass ? "" : "field mismatch"),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsCfg: Validate accepts otlp_http with matching upstream",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// metrics-side cross-reference: the existing TestValidateRejectsUnknownOtlpUpstream
// covers traces; this asserts the metrics path is checked too.
void TestOtlpHttpExporterRejectsUnknownMetricsUpstream() {
    try {
        auto cfg = ConfigLoader::LoadFromString(R"({
            "upstreams": [],
            "observability": {"enabled": true,
                "metrics": {"exporter": "otlp_http", "otlp": {"upstream": "missing"}}
            }
        })");
        bool threw = false;
        try { ConfigLoader::Validate(cfg); }
        catch (const std::invalid_argument&) { threw = true; }
        TestFramework::RecordTest(
            "ObsCfg: Validate rejects unknown metrics.otlp.upstream",
            threw, threw ? "" : "didn't throw on unknown metrics upstream",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsCfg: Validate rejects unknown metrics.otlp.upstream",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- traces.propagators (Phase 2 Task 8.5) ----

void TestPropagatorsListLoad() {
    try {
        auto cfg = ConfigLoader::LoadFromString(R"({
            "observability": {"enabled": true,
                "traces": {"propagators": ["jaeger", "w3c"]}}
        })");
        bool pass = cfg.observability.traces.propagators.size() == 2
                  && cfg.observability.traces.propagators[0] == "jaeger"
                  && cfg.observability.traces.propagators[1] == "w3c";
        TestFramework::RecordTest(
            "ObsCfg: traces.propagators ordered list parsed",
            pass, pass ? "" : "list mismatch",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsCfg: traces.propagators ordered list parsed",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestPropagatorsListDefaultIsW3C() {
    try {
        auto cfg = ConfigLoader::LoadFromString(R"({
            "observability": {"enabled": true}
        })");
        bool pass = cfg.observability.traces.propagators.size() == 1
                  && cfg.observability.traces.propagators[0] == "w3c";
        TestFramework::RecordTest(
            "ObsCfg: traces.propagators defaults to ['w3c']",
            pass, pass ? "" : "default mismatch",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsCfg: traces.propagators defaults to ['w3c']",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestPropagatorsListEmptyRejected() {
    try {
        bool threw = false;
        try {
            ConfigLoader::LoadFromString(R"({
                "observability": {"enabled": true,
                    "traces": {"propagators": []}}
            })");
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        TestFramework::RecordTest(
            "ObsCfg: traces.propagators empty array rejected",
            threw, threw ? "" : "didn't throw",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsCfg: traces.propagators empty array rejected",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestPropagatorsListUnknownRejected() {
    try {
        bool threw = false;
        try {
            ConfigLoader::LoadFromString(R"({
                "observability": {"enabled": true,
                    "traces": {"propagators": ["xray"]}}
            })");
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        TestFramework::RecordTest(
            "ObsCfg: traces.propagators unknown name rejected",
            threw, threw ? "" : "didn't throw",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsCfg: traces.propagators unknown name rejected",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Build({"w3c", "w3c"}) would otherwise silently construct two
// W3CPropagator children — wasteful and ambiguous about operator
// intent. Validator must reject duplicates at config load.
void TestPropagatorsListDuplicateRejected() {
    try {
        bool threw = false;
        try {
            ConfigLoader::LoadFromString(R"({
                "observability": {"enabled": true,
                    "traces": {"propagators": ["w3c", "jaeger", "w3c"]}}
            })");
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        TestFramework::RecordTest(
            "ObsCfg: traces.propagators duplicate name rejected",
            threw, threw ? "" : "didn't throw",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsCfg: traces.propagators duplicate name rejected",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- ObservabilityConfig::operator== ----

void TestOperatorEqIgnoresLiveFields() {
    try {
        ObservabilityConfig a, b;
        a.enabled = true;
        b.enabled = true;
        a.metrics.enabled = true;
        b.metrics.enabled = false;        // live-reloadable; should NOT differ
        a.traces.sampler.ratio = 0.5;
        b.traces.sampler.ratio = 0.1;     // live-reloadable; should NOT differ
        bool pass = (a == b);
        TestFramework::RecordTest("ObsCfg: operator== ignores live-reloadable fields",
            pass, pass ? "" : "live differences leak into restart equality",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsCfg: operator== ignores live-reloadable fields",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestOperatorEqDetectsRestartChange() {
    try {
        ObservabilityConfig a, b;
        a.enabled = true;
        b.enabled = true;
        a.metrics.exporter = "prometheus_pull";
        b.metrics.exporter = "otlp_http";  // restart-required → must differ
        bool pass = (a != b);
        TestFramework::RecordTest("ObsCfg: operator== detects restart-required change",
            pass, pass ? "" : "restart change not detected",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsCfg: operator== detects restart-required change",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- Sampler self-noise auto-derivation ----

void TestSamplerSelfNoisePromAutoAppended() {
    try {
        auto cfg = ConfigLoader::LoadFromString(R"({
            "observability": {
                "enabled": true,
                "metrics": {
                    "exporter": "prometheus_pull",
                    "prometheus": { "path": "/metrics" }
                }
            }
        })");
        const auto& routes = cfg.observability.traces.sampler.routes;
        bool found = false;
        for (const auto& r : routes) {
            if (r.path == "/metrics" && r.sampler == SamplerType::AlwaysOff) {
                found = true; break;
            }
        }
        TestFramework::RecordTest(
            "ObsCfg: prometheus path auto-appended as always_off",
            found, found ? "" : "no /metrics always_off route added",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsCfg: prometheus path auto-appended as always_off",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestSamplerSelfNoiseOperatorOverridePreserved() {
    try {
        auto cfg = ConfigLoader::LoadFromString(R"({
            "observability": {
                "enabled": true,
                "traces": {
                    "sampler": {
                        "routes": [{"path": "/metrics", "sampler": "always_on"}]
                    }
                },
                "metrics": {
                    "exporter": "prometheus_pull",
                    "prometheus": { "path": "/metrics" }
                }
            }
        })");
        const auto& routes = cfg.observability.traces.sampler.routes;
        int matches = 0;
        bool always_on = false;
        for (const auto& r : routes) {
            if (r.path == "/metrics") {
                ++matches;
                if (r.sampler == SamplerType::AlwaysOn) always_on = true;
            }
        }
        bool pass = matches == 1 && always_on;
        std::string err;
        if (matches != 1) err = "expected 1 entry for /metrics, got " + std::to_string(matches);
        else if (!always_on) err = "operator-supplied always_on overridden to always_off";
        TestFramework::RecordTest(
            "ObsCfg: operator-supplied sampler route not overridden",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsCfg: operator-supplied sampler route not overridden",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestSamplerSelfNoiseHealthAndStats() {
    try {
        auto cfg = ConfigLoader::LoadFromString(R"({
            "observability": { "enabled": true }
        })");
        const auto& routes = cfg.observability.traces.sampler.routes;
        bool health = false, stats = false;
        for (const auto& r : routes) {
            if (r.path == "/health" && r.sampler == SamplerType::AlwaysOff) health = true;
            if (r.path == "/stats"  && r.sampler == SamplerType::AlwaysOff) stats  = true;
        }
        bool pass = health && stats;
        std::string err;
        if (!health) err = "/health missing";
        else if (!stats) err = "/stats missing";
        TestFramework::RecordTest(
            "ObsCfg: /health and /stats auto-appended as always_off",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsCfg: /health and /stats auto-appended as always_off",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestSamplerSelfNoiseOtlpExporterSkipsPromPath() {
    try {
        auto cfg = ConfigLoader::LoadFromString(R"({
            "observability": {
                "enabled": true,
                "metrics": { "exporter": "otlp_http", "prometheus": { "path": "/metrics" } }
            }
        })");
        const auto& routes = cfg.observability.traces.sampler.routes;
        bool prom_route = false;
        for (const auto& r : routes) {
            if (r.path == "/metrics") { prom_route = true; break; }
        }
        // /health, /stats are unconditional; /metrics is only auto-added
        // when prometheus_pull is the metrics exporter.
        bool pass = !prom_route;
        TestFramework::RecordTest(
            "ObsCfg: /metrics not auto-appended for non-prometheus exporter",
            pass, pass ? "" : "/metrics route added without prometheus_pull",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsCfg: /metrics not auto-appended for non-prometheus exporter",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestSamplerSelfNoisePrependedBeforeOperatorWildcard() {
    // Regression: a bare `/` wildcard at the head of the operator's
    // sampler routes used to outvote auto-appended self-noise entries
    // because the sampler scan is first-match. Auto-defaults are now
    // PREPENDED so `/metrics`, `/health`, `/stats` win against `/`.
    try {
        auto cfg = ConfigLoader::LoadFromString(R"({
            "observability": {
                "enabled": true,
                "traces": {
                    "sampler": {
                        "routes": [{"path": "/", "sampler": "always_on"}]
                    }
                },
                "metrics": {
                    "exporter": "prometheus_pull",
                    "prometheus": { "path": "/metrics" }
                }
            }
        })");
        const auto& routes = cfg.observability.traces.sampler.routes;
        // Locate each entry; auto-defaults must come BEFORE the
        // wildcard root entry so the first-match scan picks them up.
        ssize_t pos_root = -1;
        ssize_t pos_metrics = -1, pos_health = -1, pos_stats = -1;
        for (size_t i = 0; i < routes.size(); ++i) {
            const auto& r = routes[i];
            if (r.path == "/")        pos_root    = static_cast<ssize_t>(i);
            if (r.path == "/metrics") pos_metrics = static_cast<ssize_t>(i);
            if (r.path == "/health")  pos_health  = static_cast<ssize_t>(i);
            if (r.path == "/stats")   pos_stats   = static_cast<ssize_t>(i);
        }
        bool pass = pos_root >= 0 && pos_metrics >= 0 && pos_health >= 0 &&
                    pos_stats >= 0 &&
                    pos_metrics < pos_root && pos_health < pos_root &&
                    pos_stats < pos_root;
        std::string err;
        if (!pass) {
            err = "expected metrics/health/stats BEFORE wildcard '/'; got "
                  "indices metrics=" + std::to_string(pos_metrics) +
                  " health=" + std::to_string(pos_health) +
                  " stats=" + std::to_string(pos_stats) +
                  " root=" + std::to_string(pos_root);
        }
        TestFramework::RecordTest(
            "ObsCfg: self-noise auto-defaults prepended before operator wildcard",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsCfg: self-noise auto-defaults prepended before operator wildcard",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- prometheus.path reload-warn ----

void TestPrometheusPathReloadIgnored() {
    try {
        ObservabilityConfig cfg;
        cfg.enabled = true;
        cfg.metrics.exporter = "prometheus_pull";
        cfg.metrics.prometheus.path = "/metrics";
        cfg.resource.service_name = "obs-cfg-test";
        std::vector<Attribute> attrs;
        attrs.emplace_back("service.name", AttrValue(std::string("obs-cfg-test")));
        auto m = ObservabilityManager::Create(
            std::move(cfg),
            std::make_shared<Resource>(std::move(attrs)),
            std::shared_ptr<SpanProcessor>(std::make_shared<NoopSpanProcessor>()),
            std::make_shared<RandomSource>(0xCFCF1234ULL));

        ObservabilityConfig staged;
        staged.enabled = true;
        staged.metrics.exporter = "prometheus_pull";
        staged.metrics.prometheus.path = "/observability/metrics";  // restart-only
        m->Reload(staged);

        const auto& live = m->config();
        bool path_unchanged = live.metrics.prometheus.path == "/metrics";
        TestFramework::RecordTest(
            "ObsCfg: prometheus.path reload keeps live value (restart-only)",
            path_unchanged,
            path_unchanged ? "" : ("path applied unexpectedly: " + live.metrics.prometheus.path),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsCfg: prometheus.path reload keeps live value (restart-only)",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- websocket_messages live atomic ----

void TestWebSocketMessagesDefaultOff() {
    try {
        auto cfg = ConfigLoader::LoadFromString(R"({
            "observability": { "enabled": true }
        })");
        bool pass = cfg.observability.traces.websocket_messages == false;
        TestFramework::RecordTest(
            "ObsCfg: traces.websocket_messages defaults off",
            pass, pass ? "" : "default flipped to true",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsCfg: traces.websocket_messages defaults off",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestWebSocketMessagesJsonRoundTrip() {
    try {
        auto cfg = ConfigLoader::LoadFromString(R"({
            "observability": {
                "enabled": true,
                "traces": { "websocket_messages": true }
            }
        })");
        bool pass = cfg.observability.traces.websocket_messages == true;
        TestFramework::RecordTest(
            "ObsCfg: traces.websocket_messages parses from JSON",
            pass, pass ? "" : "field not parsed",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsCfg: traces.websocket_messages parses from JSON",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestWebSocketMessagesReloadFlips() {
    try {
        ObservabilityConfig cfg;
        cfg.enabled = true;
        cfg.traces.websocket_messages = false;
        cfg.resource.service_name = "obs-ws-msg";
        std::vector<Attribute> attrs;
        attrs.emplace_back("service.name", AttrValue(std::string("obs-ws-msg")));
        auto m = ObservabilityManager::Create(
            std::move(cfg),
            std::make_shared<Resource>(std::move(attrs)),
            std::shared_ptr<SpanProcessor>(std::make_shared<NoopSpanProcessor>()),
            std::make_shared<RandomSource>(0xCFCF5678ULL));

        bool boot_off = m->WebSocketMessagesEnabled() == false;

        ObservabilityConfig staged;
        staged.enabled = true;
        staged.traces.websocket_messages = true;
        m->Reload(staged);

        bool reloaded_on = m->WebSocketMessagesEnabled() == true;

        // Flip back to off — confirm both directions.
        ObservabilityConfig staged2;
        staged2.enabled = true;
        staged2.traces.websocket_messages = false;
        m->Reload(staged2);

        bool reloaded_off = m->WebSocketMessagesEnabled() == false;

        bool pass = boot_off && reloaded_on && reloaded_off;
        std::string err;
        if (!boot_off)     err = "boot value not honored";
        else if (!reloaded_on)  err = "reload to true did not flip atomic";
        else if (!reloaded_off) err = "reload back to false did not flip atomic";
        TestFramework::RecordTest(
            "ObsCfg: traces.websocket_messages live atomic reload",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsCfg: traces.websocket_messages live atomic reload",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestWebSocketMessagesRejectsNonBool() {
    try {
        bool threw = false;
        try {
            ConfigLoader::LoadFromString(R"({
                "observability": {
                    "enabled": true,
                    "traces": { "websocket_messages": "yes" }
                }
            })");
        } catch (const std::invalid_argument&) {
            threw = true;
        } catch (const std::runtime_error&) {
            threw = true;
        }
        TestFramework::RecordTest(
            "ObsCfg: traces.websocket_messages rejects non-boolean",
            threw, threw ? "" : "non-boolean accepted",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsCfg: traces.websocket_messages rejects non-boolean",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- MakeMetricsHandler runtime gate ----

namespace {
std::shared_ptr<ObservabilityManager> BuildManager(bool metrics_enabled,
                                                       bool include_target_info) {
    ObservabilityConfig cfg;
    cfg.enabled = true;
    cfg.metrics.enabled = metrics_enabled;
    cfg.metrics.prometheus.include_target_info = include_target_info;
    cfg.resource.service_name = "obs-cfg-test";
    std::vector<Attribute> attrs;
    attrs.emplace_back("service.name", AttrValue(std::string("obs-cfg-test")));
    return ObservabilityManager::Create(
        std::move(cfg),
        std::make_shared<Resource>(std::move(attrs)),
        std::shared_ptr<SpanProcessor>(std::make_shared<NoopSpanProcessor>()),
        std::make_shared<RandomSource>(0xCFCFFEEDULL));
}
}  // namespace

void TestMetricsHandlerReturns404WhenDisabled() {
    try {
        auto m = BuildManager(/*metrics_enabled=*/false, true);
        auto h = MakeMetricsHandler(std::weak_ptr<ObservabilityManager>(m));
        HttpRequest req;
        HttpResponse resp;
        h(req, resp);
        bool pass = resp.GetStatusCode() == 404;
        TestFramework::RecordTest(
            "ObsCfg: /metrics returns 404 when metrics.enabled=false",
            pass, pass ? "" : "got status " + std::to_string(resp.GetStatusCode()),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsCfg: /metrics returns 404 when metrics.enabled=false",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestMetricsHandlerRendersWithTargetInfo() {
    try {
        auto m = BuildManager(true, /*include_target_info=*/true);
        auto h = MakeMetricsHandler(std::weak_ptr<ObservabilityManager>(m));
        HttpRequest req;
        HttpResponse resp;
        h(req, resp);
        const std::string& body = resp.GetBody();
        bool pass = resp.GetStatusCode() == 200
                  && body.find("target_info") != std::string::npos
                  && body.find("service_name=\"obs-cfg-test\"") != std::string::npos;
        TestFramework::RecordTest(
            "ObsCfg: /metrics renders target_info when include_target_info=true",
            pass, pass ? "" : "missing target_info in body",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsCfg: /metrics renders target_info when include_target_info=true",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestMetricsHandlerOmitsTargetInfoOnLiveFlip() {
    try {
        auto m = BuildManager(true, /*include_target_info=*/true);
        // Operator flips include_target_info via SIGHUP — emulate by
        // calling Reload with the flipped value.
        ObservabilityConfig staged;
        staged.enabled = true;
        staged.metrics.enabled = true;
        staged.metrics.prometheus.include_target_info = false;
        m->Reload(staged);

        auto h = MakeMetricsHandler(std::weak_ptr<ObservabilityManager>(m));
        HttpRequest req;
        HttpResponse resp;
        h(req, resp);
        bool pass = resp.GetStatusCode() == 200
                  && resp.GetBody().find("target_info") == std::string::npos;
        TestFramework::RecordTest(
            "ObsCfg: /metrics omits target_info after live flip",
            pass, pass ? "" : "target_info still present after Reload",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsCfg: /metrics omits target_info after live flip",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestMetricsHandlerContentTypeFromAccept() {
    try {
        auto m = BuildManager(true, true);
        auto h = MakeMetricsHandler(std::weak_ptr<ObservabilityManager>(m));
        HttpRequest req;
        // The HTTP parser lowercases inbound header keys; mirror that
        // here so HttpRequest::GetHeader's case-insensitive lookup hits.
        req.headers["accept"] = "application/openmetrics-text; version=1.0.0";
        HttpResponse resp;
        h(req, resp);
        bool found_om = false;
        for (const auto& kv : resp.GetHeaders()) {
            if (kv.first == "Content-Type"
                && kv.second.find("openmetrics-text") != std::string::npos) {
                found_om = true;
                break;
            }
        }
        TestFramework::RecordTest(
            "ObsCfg: /metrics content-type honors OpenMetrics Accept",
            found_om, found_om ? "" : "openmetrics content-type not set",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsCfg: /metrics content-type honors OpenMetrics Accept",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void RunAllTests() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "OBSERVABILITY CONFIG SCHEMA TESTS" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    TestJsonLoadFullSchema();
    TestValidateRejectsBadInterval();
    TestValidateRejectsRatioOutOfRange();
    TestValidateRejectsUnknownOtlpUpstream();
    TestOtlpHttpExporterValidatesAtLoad();
    TestOtlpHttpExporterRejectsUnknownMetricsUpstream();
    TestPropagatorsListLoad();
    TestPropagatorsListDefaultIsW3C();
    TestPropagatorsListEmptyRejected();
    TestPropagatorsListUnknownRejected();
    TestPropagatorsListDuplicateRejected();
    TestValidatePromPathMustStartWithSlash();
    TestValidateRejectsPromPathSlashOnly();
    TestValidateRejectsHistogramBucketsOutOfOrder();
    TestHotReloadableRejectsBadLiveValue();
    TestHotReloadableSkipsBadLiveValueWhenNotLive();
    TestHotReloadableForcesLiveValidationWhenLive();
    TestHotReloadableRejectsBadPropagators();
    TestHotReloadableSkipsRestartFields();
    TestOperatorEqIgnoresLiveFields();
    TestOperatorEqDetectsRestartChange();
    TestMetricsHandlerReturns404WhenDisabled();
    TestMetricsHandlerRendersWithTargetInfo();
    TestMetricsHandlerOmitsTargetInfoOnLiveFlip();
    TestMetricsHandlerContentTypeFromAccept();
    TestSamplerSelfNoisePromAutoAppended();
    TestSamplerSelfNoiseOperatorOverridePreserved();
    TestSamplerSelfNoiseHealthAndStats();
    TestSamplerSelfNoiseOtlpExporterSkipsPromPath();
    TestSamplerSelfNoisePrependedBeforeOperatorWildcard();
    TestPrometheusPathReloadIgnored();
    TestWebSocketMessagesDefaultOff();
    TestWebSocketMessagesJsonRoundTrip();
    TestWebSocketMessagesReloadFlips();
    TestWebSocketMessagesRejectsNonBool();
}

}  // namespace ObservabilityConfigTests
