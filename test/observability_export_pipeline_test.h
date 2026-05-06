#pragma once

// BatchSpanProcessor + PeriodicMetricReader + OtlpHttpExporter unit
// tests. Pure in-process — uses a capture transport callback to
// retain serialized OTLP/JSON for inspection.

#include "test_framework.h"
#include "nlohmann/json.hpp"
#include "observability/batch_span_processor.h"
#include "observability/instrumentation_scope.h"
#include "observability/meter_provider.h"
#include "observability/metric_label_registry.h"
#include "observability/otlp_http_exporter.h"
#include "observability/periodic_metric_reader.h"
#include "observability/resource.h"
#include "observability/sampler.h"
#include "observability/span.h"
#include "observability/span_processor.h"
#include "observability/tracer_provider.h"

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace ObservabilityExportPipelineTests {

using OBSERVABILITY_NAMESPACE::AlwaysOnSampler;
using OBSERVABILITY_NAMESPACE::AttrValue;
using OBSERVABILITY_NAMESPACE::BatchSpanProcessor;
using OBSERVABILITY_NAMESPACE::BatchSpanProcessorOptions;
using OBSERVABILITY_NAMESPACE::ExportResult;
using OBSERVABILITY_NAMESPACE::Histogram;
using OBSERVABILITY_NAMESPACE::Counter;
using OBSERVABILITY_NAMESPACE::Meter;
using OBSERVABILITY_NAMESPACE::MeterProvider;
using OBSERVABILITY_NAMESPACE::MeterReaderOptions;
using OBSERVABILITY_NAMESPACE::MetricExporter;
using OBSERVABILITY_NAMESPACE::MetricLabelRegistry;
using OBSERVABILITY_NAMESPACE::MetricsSnapshot;
using OBSERVABILITY_NAMESPACE::OtlpHttpExporter;
using OBSERVABILITY_NAMESPACE::PeriodicMetricReader;
using OBSERVABILITY_NAMESPACE::RandomSource;
using OBSERVABILITY_NAMESPACE::Resource;
using OBSERVABILITY_NAMESPACE::SpanData;
using OBSERVABILITY_NAMESPACE::SpanExporter;
using OBSERVABILITY_NAMESPACE::SpanKind;
using OBSERVABILITY_NAMESPACE::SpanStatusCode;
using OBSERVABILITY_NAMESPACE::StartSpanOptions;
using OBSERVABILITY_NAMESPACE::Tracer;
using OBSERVABILITY_NAMESPACE::TracerProvider;

namespace {

// Capture-style SpanExporter — collects every batch into a vector.
class CaptureSpanExporter : public SpanExporter {
public:
    ExportResult Export(std::vector<SpanData> batch,
                         std::chrono::steady_clock::time_point) override {
        std::lock_guard<std::mutex> g(mtx_);
        ++calls_;
        for (auto& sd : batch) all_.emplace_back(std::move(sd));
        return ExportResult::kSuccess;
    }
    void SignalShutdown() override {
        signal_count_.fetch_add(1, std::memory_order_acq_rel);
    }
    void CancelAllActiveExports() override {
        cancel_count_.fetch_add(1, std::memory_order_acq_rel);
    }
    size_t Size() {
        std::lock_guard<std::mutex> g(mtx_);
        return all_.size();
    }
    int Calls() {
        std::lock_guard<std::mutex> g(mtx_);
        return calls_;
    }
    int signal_count() const { return signal_count_.load(); }

private:
    std::mutex mtx_;
    std::vector<SpanData> all_;
    int calls_ = 0;
    std::atomic<int> signal_count_{0};
    std::atomic<int> cancel_count_{0};
};

// Capture-style MetricExporter.
class CaptureMetricExporter : public MetricExporter {
public:
    ExportResult Export(MetricsSnapshot snap,
                         std::chrono::steady_clock::time_point) override {
        std::lock_guard<std::mutex> g(mtx_);
        ++calls_;
        last_ = std::move(snap);
        return ExportResult::kSuccess;
    }
    void SignalShutdown() override { signal_count_.fetch_add(1); }
    void CancelAllActiveExports() override {}

    int Calls() {
        std::lock_guard<std::mutex> g(mtx_);
        return calls_;
    }
    MetricsSnapshot Last() {
        std::lock_guard<std::mutex> g(mtx_);
        return last_;
    }
    int signal_count() const { return signal_count_.load(); }

private:
    std::mutex mtx_;
    MetricsSnapshot last_;
    int calls_ = 0;
    std::atomic<int> signal_count_{0};
};

}  // namespace

// ---- BatchSpanProcessor ----
void TestBatchSpanProcessorBatchesAndExports() {
    try {
        auto exporter = std::make_shared<CaptureSpanExporter>();
        BatchSpanProcessorOptions opts;
        opts.max_export_batch_size = 4;
        opts.schedule_delay = std::chrono::milliseconds{50};
        BatchSpanProcessor proc(exporter, opts);

        // Build a tracer pointing at the processor.
        auto resource = std::make_shared<Resource>();
        auto random   = std::make_shared<RandomSource>(0x1ULL);
        TracerProvider provider(
            resource,
            std::shared_ptr<OBSERVABILITY_NAMESPACE::SpanProcessor>(
                &proc, [](OBSERVABILITY_NAMESPACE::SpanProcessor*) {}),
            std::make_shared<AlwaysOnSampler>(),
            random);
        Tracer* t = provider.GetTracer("test");

        for (int i = 0; i < 8; ++i) {
            auto s = t->StartSpan("op", {});
            s->End();
        }
        // Wait for two batches (8 spans / batch_size=4).
        for (int i = 0; i < 50 && exporter->Size() < 8; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds{20});
        }
        bool pass = exporter->Size() == 8;
        TestFramework::RecordTest(
            "ObsExport: BatchSpanProcessor batches + exports 8 spans",
            pass, pass ? "" : "got " + std::to_string(exporter->Size()) + "/8",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsExport: BatchSpanProcessor batches + exports 8 spans",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Drop-oldest semantics on queue full.
void TestBatchSpanProcessorDropsOnOverflow() {
    try {
        // Block exporter so the queue fills up.
        struct BlockingExporter : public SpanExporter {
            std::atomic<bool> unblock{false};
            std::atomic<int> exports{0};
            ExportResult Export(std::vector<SpanData>,
                                 std::chrono::steady_clock::time_point) override {
                while (!unblock.load(std::memory_order_acquire)) {
                    std::this_thread::sleep_for(std::chrono::milliseconds{10});
                }
                exports.fetch_add(1);
                return ExportResult::kSuccess;
            }
            void SignalShutdown() override { unblock.store(true); }
            void CancelAllActiveExports() override { unblock.store(true); }
        };
        auto exporter = std::make_shared<BlockingExporter>();
        BatchSpanProcessorOptions opts;
        opts.max_queue_size        = 4;
        opts.max_export_batch_size = 2;
        opts.schedule_delay        = std::chrono::milliseconds{20};
        BatchSpanProcessor proc(exporter, opts);

        // Pre-build SpanData manually to avoid Tracer wiring.
        auto inject = [&](int i) {
            SpanData d;
            d.name = "op" + std::to_string(i);
            proc.OnEnd(std::move(d));
        };
        for (int i = 0; i < 20; ++i) inject(i);
        // Worker is blocked; some spans should have been dropped.
        std::this_thread::sleep_for(std::chrono::milliseconds{100});
        bool dropped = proc.dropped_on_overflow() > 0;
        // Unblock + signal shutdown so the destructor can join.
        exporter->unblock.store(true);
        proc.SignalShutdown();

        TestFramework::RecordTest(
            "ObsExport: BatchSpanProcessor drops on queue overflow",
            dropped, dropped ? "" : "no drops detected",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsExport: BatchSpanProcessor drops on queue overflow",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// SignalShutdown propagates to the exporter.
// Regression: a direct caller that constructs BatchSpanProcessorOptions
// with `max_export_batch_size == 0` must not wedge the worker. The
// worker predicate `queue_.size() >= batch_cap` would be permanently
// true and DrainBatch(0) would pop nothing, so spans would never
// export and the worker would spin. Reload() already clamps to 1; the
// constructor must do the same before publishing the cached value.
void TestBatchSpanProcessorClampsZeroBatchSize() {
    try {
        auto exporter = std::make_shared<CaptureSpanExporter>();
        BatchSpanProcessorOptions opts;
        opts.max_export_batch_size = 0;  // hazardous — must be clamped
        opts.schedule_delay        = std::chrono::milliseconds{20};
        BatchSpanProcessor proc(exporter, opts);

        for (int i = 0; i < 4; ++i) {
            SpanData sd;
            sd.name = "x";
            proc.OnEnd(std::move(sd));
        }

        // Wait up to 1s for the worker to drain. Pre-fix the worker
        // would spin without ever exporting because batch_cap=0.
        auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::seconds{1};
        size_t exported = 0;
        while (std::chrono::steady_clock::now() < deadline) {
            exported = exporter->Size();
            if (exported >= 4) break;
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
        }

        proc.SignalShutdown();
        proc.JoinWorkers(std::chrono::milliseconds{500});

        bool pass = exported == 4;
        TestFramework::RecordTest(
            "ObsExport: BatchSpanProcessor constructor clamps zero batch size",
            pass,
            pass ? "" : "exported=" + std::to_string(exported) +
                        " (expected 4) — worker likely wedged",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsExport: BatchSpanProcessor constructor clamps zero batch size",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestBatchSpanProcessorShutdownPropagates() {
    try {
        auto exporter = std::make_shared<CaptureSpanExporter>();
        BatchSpanProcessor proc(exporter, BatchSpanProcessorOptions{});
        proc.SignalShutdown();
        // Use deadline=0 (unbounded) so the worker is guaranteed to
        // finish its post-loop exporter SignalShutdown call before
        // the test reads signal_count. Bounded JoinWorkers can return
        // before the worker reaches the SignalShutdown forwarding under
        // TSan/heavy CPU contention, producing a spurious failure.
        // The bounded contract is exercised by other tests.
        proc.JoinWorkers(std::chrono::milliseconds{0});
        bool pass = exporter->signal_count() == 1;
        TestFramework::RecordTest(
            "ObsExport: BatchSpanProcessor SignalShutdown forwards to exporter",
            pass, pass ? "" : "exporter SignalShutdown count wrong",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsExport: BatchSpanProcessor SignalShutdown forwards to exporter",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- PeriodicMetricReader ----
void TestPeriodicMetricReaderExportsCycles() {
    try {
        MeterProvider provider(std::make_shared<Resource>());
        Meter* m = provider.GetMeter("test");
        MetricLabelRegistry::Catalog cat;
        cat.allowed_keys = {"http.route"};
        Counter* c = m->GetCounter("hits", "", "1", cat);
        c->Add(3, {{"http.route", "/x"}});

        auto exporter = std::make_shared<CaptureMetricExporter>();
        MeterReaderOptions ropts;
        ropts.export_interval = std::chrono::milliseconds{60};
        ropts.export_timeout  = std::chrono::milliseconds{500};
        PeriodicMetricReader reader(&provider, exporter, ropts);

        // Wait for at least 2 export cycles.
        for (int i = 0; i < 50 && reader.exported_cycles() < 2; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds{30});
        }
        bool pass = reader.exported_cycles() >= 2 && exporter->Calls() >= 2;
        // Last snapshot should contain the counter we added.
        if (pass) {
            auto last = exporter->Last();
            bool found = false;
            for (const auto& inst : last.instruments) {
                if (inst.name == "hits") { found = true; break; }
            }
            pass = found;
        }
        reader.SignalShutdown();
        reader.JoinWorkers(std::chrono::milliseconds{500});
        TestFramework::RecordTest(
            "ObsExport: PeriodicMetricReader emits cycles with snapshot data",
            pass, pass ? "" : "reader did not emit expected cycles",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsExport: PeriodicMetricReader emits cycles with snapshot data",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- OtlpHttpExporter ----
void TestOtlpExporterSerializesSpansToJson() {
    try {
        std::string captured_body;
        std::string captured_path;
        auto transport =
            [&](OtlpHttpExporter::ExportPayload p,
                std::chrono::steady_clock::time_point) -> ExportResult {
            captured_body = std::move(p.body);
            captured_path = std::move(p.path);
            return ExportResult::kSuccess;
        };
        auto exp = OtlpHttpExporter::Create(OtlpHttpExporter::Options{}, transport);

        // Build a single SpanData manually.
        SpanData sd;
        sd.context.SetTraceId(OBSERVABILITY_NAMESPACE::TraceId::FromHex(
            "0af7651916cd43dd8448eb211c80319c"));
        sd.context.SetSpanId(OBSERVABILITY_NAMESPACE::SpanId::FromHex(
            "00f067aa0ba902b7"));
        sd.name = "GET /health";
        sd.kind = SpanKind::SERVER;
        sd.start_time_system = std::chrono::system_clock::now();
        sd.end_time_system   = sd.start_time_system + std::chrono::milliseconds{42};
        sd.attributes.emplace_back(
            "http.request.method", AttrValue(std::string("GET")));
        sd.attributes.emplace_back(
            "http.response.status_code", AttrValue(int64_t{200}));

        std::vector<SpanData> batch;
        batch.push_back(std::move(sd));
        ExportResult r = exp->Export(std::move(batch));

        bool pass = r == ExportResult::kSuccess &&
                    captured_path == "/v1/traces" &&
                    !captured_body.empty();
        if (pass) {
            // Parse the JSON; ensure the required OTLP fields are present.
            auto j = nlohmann::json::parse(captured_body);
            pass = j.contains("resourceSpans") &&
                   j["resourceSpans"].is_array() &&
                   !j["resourceSpans"].empty() &&
                   j["resourceSpans"][0].contains("scopeSpans") &&
                   j["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["name"]
                       == "GET /health";
        }
        TestFramework::RecordTest(
            "ObsExport: OtlpHttpExporter serializes SpanData to OTLP/JSON",
            pass, pass ? "" : "serialization wrong: " + captured_body.substr(0, 100),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsExport: OtlpHttpExporter serializes SpanData to OTLP/JSON",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// SignalShutdown causes Export to return kFailedNotRetryable.
void TestOtlpExporterShutdownRefusesExport() {
    try {
        bool transport_called = false;
        auto transport =
            [&](OtlpHttpExporter::ExportPayload,
                std::chrono::steady_clock::time_point) -> ExportResult {
            transport_called = true;
            return ExportResult::kSuccess;
        };
        auto exp = OtlpHttpExporter::Create(OtlpHttpExporter::Options{}, transport);
        exp->SignalShutdown();

        SpanData sd;
        sd.name = "post-shutdown";
        std::vector<SpanData> batch;
        batch.push_back(std::move(sd));
        ExportResult r = exp->Export(std::move(batch));

        bool pass = r == ExportResult::kFailedNotRetryable && !transport_called &&
                    exp->exports_failed() >= 1;
        TestFramework::RecordTest(
            "ObsExport: OtlpHttpExporter post-shutdown Export returns kFailedNotRetryable",
            pass, pass ? "" : "shutdown did not refuse export",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsExport: OtlpHttpExporter post-shutdown Export returns kFailedNotRetryable",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ReloadHeaders applies live (controlled merge of headers + timeout).
void TestOtlpExporterReloadHeaders() {
    try {
        std::map<std::string, std::string> seen_headers;
        auto transport =
            [&](OtlpHttpExporter::ExportPayload p,
                std::chrono::steady_clock::time_point) -> ExportResult {
            seen_headers = std::move(p.headers);
            return ExportResult::kSuccess;
        };
        auto exp = OtlpHttpExporter::Create(OtlpHttpExporter::Options{}, transport);

        // Reload with new auth headers.
        std::map<std::string, std::string> trace_h{{"authorization", "Bearer XYZ"}};
        std::map<std::string, std::string> metric_h{{"x-tenant", "abc"}};
        exp->ReloadHeaders(trace_h, metric_h,
                            std::chrono::milliseconds{5000},
                            std::chrono::milliseconds{5000});

        SpanData sd;
        sd.name = "reload-test";
        std::vector<SpanData> batch;
        batch.push_back(std::move(sd));
        exp->Export(std::move(batch));
        bool pass = seen_headers["authorization"] == "Bearer XYZ" &&
                    seen_headers["content-type"] == "application/json";
        TestFramework::RecordTest(
            "ObsExport: OtlpHttpExporter ReloadHeaders applies live",
            pass, pass ? "" : "reload didn't propagate to wire",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsExport: OtlpHttpExporter ReloadHeaders applies live",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Metrics serialization.
void TestOtlpExporterSerializesMetricsToJson() {
    try {
        std::string captured_body;
        auto transport =
            [&](OtlpHttpExporter::ExportPayload p,
                std::chrono::steady_clock::time_point) -> ExportResult {
            captured_body = std::move(p.body);
            return ExportResult::kSuccess;
        };
        auto exp = OtlpHttpExporter::Create(OtlpHttpExporter::Options{}, transport);

        MeterProvider provider(std::make_shared<Resource>());
        Meter* m = provider.GetMeter("test");
        MetricLabelRegistry::Catalog cat;
        cat.allowed_keys = {"http.route"};
        Counter* c = m->GetCounter("requests", "", "1", cat);
        c->Add(7, {{"http.route", "/api"}});

        auto snap = provider.Snapshot();
        ExportResult r = exp->Export(std::move(snap));

        bool pass = r == ExportResult::kSuccess && !captured_body.empty();
        if (pass) {
            auto j = nlohmann::json::parse(captured_body);
            pass = j.contains("resourceMetrics") &&
                   !j["resourceMetrics"].empty();
        }
        TestFramework::RecordTest(
            "ObsExport: OtlpHttpExporter serializes MetricsSnapshot to OTLP/JSON",
            pass, pass ? "" : "metric serialization wrong",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsExport: OtlpHttpExporter serializes MetricsSnapshot to OTLP/JSON",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void RunAllTests() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "OBSERVABILITY EXPORT PIPELINE TESTS" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    TestBatchSpanProcessorBatchesAndExports();
    TestBatchSpanProcessorDropsOnOverflow();
    TestBatchSpanProcessorClampsZeroBatchSize();
    TestBatchSpanProcessorShutdownPropagates();
    TestPeriodicMetricReaderExportsCycles();
    TestOtlpExporterSerializesSpansToJson();
    TestOtlpExporterShutdownRefusesExport();
    TestOtlpExporterReloadHeaders();
    TestOtlpExporterSerializesMetricsToJson();
}

}  // namespace ObservabilityExportPipelineTests
