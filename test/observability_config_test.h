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
    TestValidatePromPathMustStartWithSlash();
    TestValidateRejectsHistogramBucketsOutOfOrder();
    TestHotReloadableRejectsBadLiveValue();
    TestHotReloadableSkipsRestartFields();
    TestOperatorEqIgnoresLiveFields();
    TestOperatorEqDetectsRestartChange();
    TestMetricsHandlerReturns404WhenDisabled();
    TestMetricsHandlerRendersWithTargetInfo();
    TestMetricsHandlerOmitsTargetInfoOnLiveFlip();
    TestMetricsHandlerContentTypeFromAccept();
}

}  // namespace ObservabilityConfigTests
