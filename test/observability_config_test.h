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
            && oc.traces.sampler.routes.size() == 1
            && oc.traces.sampler.routes[0].path == "/metrics"
            && oc.traces.sampler.routes[0].sampler == SamplerType::AlwaysOff
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
}

}  // namespace ObservabilityConfigTests
