#pragma once

// PrometheusExporter unit tests (task #71).
//
// Pure-text rendering — no I/O. Builds MetricsSnapshot fixtures by hand
// and asserts on the rendered exposition / OpenMetrics output.

#include "test_framework.h"
#include "observability/metrics_snapshot.h"
#include "observability/prometheus_exporter.h"
#include "observability/resource.h"

#include <memory>
#include <string>
#include <vector>

namespace ObservabilityPrometheusTests {

using OBSERVABILITY_NAMESPACE::CounterPoint;
using OBSERVABILITY_NAMESPACE::HistogramPoint;
using OBSERVABILITY_NAMESPACE::InstrumentKind;
using OBSERVABILITY_NAMESPACE::InstrumentSnapshot;
using OBSERVABILITY_NAMESPACE::LabelSet;
using OBSERVABILITY_NAMESPACE::MetricsSnapshot;
using OBSERVABILITY_NAMESPACE::PrometheusExporter;
using OBSERVABILITY_NAMESPACE::Resource;
using OBSERVABILITY_NAMESPACE::Attribute;
using OBSERVABILITY_NAMESPACE::AttrValue;

namespace {

LabelSet MakeLabels(
    std::vector<std::pair<std::string, std::string>> kv) {
    LabelSet ls;
    ls.kv = std::move(kv);
    return ls;
}

bool ContainsLine(const std::string& body, const std::string& needle) {
    return body.find(needle) != std::string::npos;
}

}  // namespace

// ---- SanitizeName ----

void TestSanitizeReplacesDots() {
    try {
        auto out = PrometheusExporter::SanitizeName("http.request.method");
        bool pass = out == "http_request_method";
        TestFramework::RecordTest("ObsProm: SanitizeName replaces dots",
            pass, pass ? "" : "got " + out,
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsProm: SanitizeName replaces dots",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestSanitizePrependsLeadingDigit() {
    try {
        auto out = PrometheusExporter::SanitizeName("5xx_count");
        bool pass = out == "_5xx_count";
        TestFramework::RecordTest("ObsProm: SanitizeName prepends underscore for leading digit",
            pass, pass ? "" : "got " + out,
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsProm: SanitizeName prepends underscore for leading digit",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestSanitizeMixedSpecials() {
    try {
        auto out = PrometheusExporter::SanitizeName("a-b/c:d.e");
        bool pass = out == "a_b_c_d_e";
        TestFramework::RecordTest("ObsProm: SanitizeName replaces non-[a-zA-Z0-9_]",
            pass, pass ? "" : "got " + out,
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsProm: SanitizeName replaces non-[a-zA-Z0-9_]",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestSanitizeAllowedPassThrough() {
    try {
        auto out = PrometheusExporter::SanitizeName("a_B_c0");
        bool pass = out == "a_B_c0";
        TestFramework::RecordTest("ObsProm: SanitizeName preserves legal chars",
            pass, pass ? "" : "got " + out,
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsProm: SanitizeName preserves legal chars",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestSanitizeEmptyInput() {
    try {
        auto out = PrometheusExporter::SanitizeName("");
        bool pass = out.empty();
        TestFramework::RecordTest("ObsProm: SanitizeName handles empty input",
            pass, pass ? "" : "got non-empty",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsProm: SanitizeName handles empty input",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- ChooseFormat ----

void TestChooseFormatOpenMetrics() {
    try {
        auto fmt = PrometheusExporter::ChooseFormat(
            "application/openmetrics-text; version=1.0.0");
        bool pass = fmt == PrometheusExporter::Format::OpenMetrics;
        TestFramework::RecordTest("ObsProm: ChooseFormat picks OpenMetrics from Accept",
            pass, pass ? "" : "did not pick OpenMetrics",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsProm: ChooseFormat picks OpenMetrics from Accept",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestChooseFormatDefault() {
    try {
        auto fmt1 = PrometheusExporter::ChooseFormat("text/plain");
        auto fmt2 = PrometheusExporter::ChooseFormat("");
        auto fmt3 = PrometheusExporter::ChooseFormat("*/*");
        bool pass = fmt1 == PrometheusExporter::Format::PrometheusExposition
                  && fmt2 == PrometheusExporter::Format::PrometheusExposition
                  && fmt3 == PrometheusExporter::Format::PrometheusExposition;
        TestFramework::RecordTest("ObsProm: ChooseFormat defaults to PrometheusExposition",
            pass, pass ? "" : "non-default chosen",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsProm: ChooseFormat defaults to PrometheusExposition",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestContentTypeStrings() {
    try {
        std::string p = PrometheusExporter::ContentType(
            PrometheusExporter::Format::PrometheusExposition);
        std::string o = PrometheusExporter::ContentType(
            PrometheusExporter::Format::OpenMetrics);
        bool pass =
            p.find("text/plain") != std::string::npos &&
            p.find("version=0.0.4") != std::string::npos &&
            o.find("application/openmetrics-text") != std::string::npos &&
            o.find("version=1.0.0") != std::string::npos;
        TestFramework::RecordTest("ObsProm: ContentType strings",
            pass, pass ? "" : "wrong content-type strings",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsProm: ContentType strings",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- Render: Counter ----

void TestRenderCounterTotalSuffix() {
    try {
        MetricsSnapshot snap;
        InstrumentSnapshot inst;
        inst.name        = "http.server.requests";
        inst.description = "Server-side HTTP request count";
        inst.kind        = InstrumentKind::Counter;
        CounterPoint p;
        p.labels = MakeLabels({{"http.request.method", "GET"},
                                {"http.response.status_code", "200"}});
        p.value  = 7;
        inst.counter_points.push_back(std::move(p));
        snap.instruments.push_back(std::move(inst));

        std::string body = PrometheusExporter::Render(snap);
        bool has_help = ContainsLine(body, "# HELP http_server_requests_total Server-side HTTP request count");
        bool has_type = ContainsLine(body, "# TYPE http_server_requests_total counter");
        bool has_sample = ContainsLine(body,
            "http_server_requests_total{http_request_method=\"GET\",http_response_status_code=\"200\"} 7");
        bool pass = has_help && has_type && has_sample;
        TestFramework::RecordTest("ObsProm: Counter renders with _total + sanitized labels",
            pass, pass ? "" : "missing expected lines:\n" + body,
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsProm: Counter renders with _total + sanitized labels",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- Render: UpDownCounter ----

void TestRenderUpDownCounterAsGauge() {
    try {
        MetricsSnapshot snap;
        InstrumentSnapshot inst;
        inst.name = "http.server.active_requests";
        inst.kind = InstrumentKind::UpDownCounter;
        CounterPoint p;
        p.labels = MakeLabels({{"http.route", "/users"}});
        p.value  = 3;
        inst.counter_points.push_back(std::move(p));
        snap.instruments.push_back(std::move(inst));

        std::string body = PrometheusExporter::Render(snap);
        bool has_type = ContainsLine(body,
            "# TYPE http_server_active_requests gauge");
        bool no_total = !ContainsLine(body,
            "http_server_active_requests_total");
        bool has_sample = ContainsLine(body,
            "http_server_active_requests{http_route=\"/users\"} 3");
        bool pass = has_type && no_total && has_sample;
        TestFramework::RecordTest("ObsProm: UpDownCounter renders as gauge (no _total)",
            pass, pass ? "" : "wrong shape:\n" + body,
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsProm: UpDownCounter renders as gauge (no _total)",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- Render: Histogram ----

void TestRenderHistogramCumulativeBuckets() {
    try {
        MetricsSnapshot snap;
        InstrumentSnapshot inst;
        inst.name = "http.server.request.duration";
        inst.kind = InstrumentKind::Histogram;
        HistogramPoint hp;
        hp.labels = MakeLabels({{"http.route", "/api"}});
        hp.bucket_boundaries = {1.0, 5.0, 10.0};
        // Per-bucket counts (not cumulative): [bucket≤1, bucket≤5, bucket≤10, +Inf]
        // total = 2 + 3 + 1 + 0 = 6
        hp.bucket_counts = {2, 3, 1, 0};
        hp.sum   = 17.5;
        hp.count = 6;
        inst.histogram_points.push_back(std::move(hp));
        snap.instruments.push_back(std::move(inst));

        std::string body = PrometheusExporter::Render(snap);
        bool has_type = ContainsLine(body,
            "# TYPE http_server_request_duration histogram");
        bool b1 = ContainsLine(body,
            "http_server_request_duration_bucket{http_route=\"/api\",le=\"1\"} 2");
        bool b5 = ContainsLine(body,
            "http_server_request_duration_bucket{http_route=\"/api\",le=\"5\"} 5");
        bool b10 = ContainsLine(body,
            "http_server_request_duration_bucket{http_route=\"/api\",le=\"10\"} 6");
        bool binf = ContainsLine(body,
            "http_server_request_duration_bucket{http_route=\"/api\",le=\"+Inf\"} 6");
        bool s = ContainsLine(body,
            "http_server_request_duration_sum{http_route=\"/api\"} 17.5");
        bool c = ContainsLine(body,
            "http_server_request_duration_count{http_route=\"/api\"} 6");
        bool pass = has_type && b1 && b5 && b10 && binf && s && c;
        TestFramework::RecordTest("ObsProm: Histogram renders cumulative buckets + sum + count",
            pass, pass ? "" : "missing expected histogram lines:\n" + body,
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsProm: Histogram renders cumulative buckets + sum + count",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- Label escaping ----

void TestLabelValueEscaping() {
    try {
        MetricsSnapshot snap;
        InstrumentSnapshot inst;
        inst.name = "errors";
        inst.kind = InstrumentKind::Counter;
        CounterPoint p;
        p.labels = MakeLabels({{"reason", "bad \"quote\" and \\slash and\nline"}});
        p.value  = 1;
        inst.counter_points.push_back(std::move(p));
        snap.instruments.push_back(std::move(inst));

        std::string body = PrometheusExporter::Render(snap);
        // \\\" → output backslash-quote; \\\\ → output backslash-backslash
        bool pass = ContainsLine(body,
            "errors_total{reason=\"bad \\\"quote\\\" and \\\\slash and\\nline\"} 1");
        TestFramework::RecordTest("ObsProm: label values escape backslash, quote, newline",
            pass, pass ? "" : "escape mismatch:\n" + body,
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsProm: label values escape backslash, quote, newline",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- target_info gauge ----

void TestTargetInfoEmittedFromResource() {
    try {
        MetricsSnapshot snap;
        std::vector<Attribute> attrs;
        attrs.emplace_back("service.name",     AttrValue(std::string("gateway")));
        attrs.emplace_back("service.version",  AttrValue(std::string("1.2.3")));
        snap.resource = std::make_shared<Resource>(std::move(attrs));

        std::string body = PrometheusExporter::Render(snap);
        bool t = ContainsLine(body, "# TYPE target_info gauge");
        bool name = ContainsLine(body, "service_name=\"gateway\"");
        bool ver  = ContainsLine(body, "service_version=\"1.2.3\"");
        bool one  = ContainsLine(body, "} 1\n");
        bool pass = t && name && ver && one;
        TestFramework::RecordTest("ObsProm: target_info renders Resource attrs",
            pass, pass ? "" : "missing target_info lines:\n" + body,
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsProm: target_info renders Resource attrs",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestTargetInfoSkippedWhenResourceEmpty() {
    try {
        MetricsSnapshot snap;
        snap.resource = std::make_shared<Resource>();
        std::string body = PrometheusExporter::Render(snap);
        bool pass = !ContainsLine(body, "target_info");
        TestFramework::RecordTest("ObsProm: target_info skipped on empty Resource",
            pass, pass ? "" : "target_info present despite empty Resource",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsProm: target_info skipped on empty Resource",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- OpenMetrics EOF ----

void TestOpenMetricsEofMarker() {
    try {
        MetricsSnapshot snap;
        InstrumentSnapshot inst;
        inst.name = "x";
        inst.kind = InstrumentKind::Counter;
        CounterPoint p;
        p.value = 1;
        inst.counter_points.push_back(std::move(p));
        snap.instruments.push_back(std::move(inst));

        std::string body = PrometheusExporter::Render(snap,
            PrometheusExporter::Format::OpenMetrics);
        // Must end with "# EOF\n"; PrometheusExposition must NOT.
        bool om_eof = body.size() >= 6 &&
                      body.compare(body.size() - 6, 6, "# EOF\n") == 0;

        std::string body2 = PrometheusExporter::Render(snap,
            PrometheusExporter::Format::PrometheusExposition);
        bool no_eof_in_prom = body2.find("# EOF") == std::string::npos;

        bool pass = om_eof && no_eof_in_prom;
        TestFramework::RecordTest("ObsProm: OpenMetrics adds # EOF; Prometheus does not",
            pass, pass ? "" : "EOF marker logic wrong",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsProm: OpenMetrics adds # EOF; Prometheus does not",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- Empty snapshot ----

void TestEmptySnapshotRendersEmpty() {
    try {
        MetricsSnapshot snap;
        std::string body = PrometheusExporter::Render(snap);
        bool pass = body.empty();
        TestFramework::RecordTest("ObsProm: empty snapshot → empty body",
            pass, pass ? "" : "non-empty: " + body,
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsProm: empty snapshot → empty body",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- Multi-series + multi-instrument ----

void TestMultiSeriesAndMultiInstrument() {
    try {
        MetricsSnapshot snap;

        InstrumentSnapshot c;
        c.name = "errors";
        c.kind = InstrumentKind::Counter;
        CounterPoint p1, p2;
        p1.labels = MakeLabels({{"code", "500"}});
        p1.value  = 4;
        p2.labels = MakeLabels({{"code", "503"}});
        p2.value  = 2;
        c.counter_points.push_back(std::move(p1));
        c.counter_points.push_back(std::move(p2));
        snap.instruments.push_back(std::move(c));

        InstrumentSnapshot g;
        g.name = "active";
        g.kind = InstrumentKind::UpDownCounter;
        CounterPoint p3;
        p3.value = 11;
        g.counter_points.push_back(std::move(p3));
        snap.instruments.push_back(std::move(g));

        std::string body = PrometheusExporter::Render(snap);
        bool e1 = ContainsLine(body, "errors_total{code=\"500\"} 4");
        bool e2 = ContainsLine(body, "errors_total{code=\"503\"} 2");
        bool a  = ContainsLine(body, "active{} 11");
        bool single_help = body.find("# HELP errors_total")
                            == body.rfind("# HELP errors_total");
        bool single_type = body.find("# TYPE errors_total")
                            == body.rfind("# TYPE errors_total");
        bool pass = e1 && e2 && a && single_help && single_type;
        TestFramework::RecordTest("ObsProm: multi-series under one instrument shares HELP/TYPE",
            pass, pass ? "" : "header dedup wrong:\n" + body,
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsProm: multi-series under one instrument shares HELP/TYPE",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void RunAllTests() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "OBSERVABILITY PROMETHEUS EXPORTER TESTS" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    TestSanitizeReplacesDots();
    TestSanitizePrependsLeadingDigit();
    TestSanitizeMixedSpecials();
    TestSanitizeAllowedPassThrough();
    TestSanitizeEmptyInput();
    TestChooseFormatOpenMetrics();
    TestChooseFormatDefault();
    TestContentTypeStrings();
    TestRenderCounterTotalSuffix();
    TestRenderUpDownCounterAsGauge();
    TestRenderHistogramCumulativeBuckets();
    TestLabelValueEscaping();
    TestTargetInfoEmittedFromResource();
    TestTargetInfoSkippedWhenResourceEmpty();
    TestOpenMetricsEofMarker();
    TestEmptySnapshotRendersEmpty();
    TestMultiSeriesAndMultiInstrument();
}

}  // namespace ObservabilityPrometheusTests
