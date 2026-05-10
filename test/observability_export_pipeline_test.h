#pragma once

// BatchSpanProcessor + PeriodicMetricReader + OtlpHttpExporter unit
// tests. Pure in-process — uses a capture transport callback to
// retain serialized OTLP/JSON for inspection.

#include "test_framework.h"
#include "auth/upstream_http_client.h"
#include "nlohmann/json.hpp"
#include "observability/batch_span_processor.h"
#include "observability/instrumentation_scope.h"
#include "observability/meter_provider.h"
#include "observability/metric_label_registry.h"
#include "observability/otlp_http_exporter.h"
#include "observability/otlp_transport.h"
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

// Slow MetricExporter — sleeps inside Export() so tests can assert
// ForceFlush actually blocked through the export round-trip.
class SlowMetricExporter : public MetricExporter {
public:
    explicit SlowMetricExporter(std::chrono::milliseconds latency)
        : latency_(latency) {}
    ExportResult Export(MetricsSnapshot,
                         std::chrono::steady_clock::time_point) override {
        std::this_thread::sleep_for(latency_);
        export_calls_.fetch_add(1, std::memory_order_relaxed);
        return ExportResult::kSuccess;
    }
    void SignalShutdown() override {}
    void CancelAllActiveExports() override {}
    int export_calls() const {
        return export_calls_.load(std::memory_order_relaxed);
    }

private:
    std::chrono::milliseconds latency_;
    std::atomic<int> export_calls_{0};
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

// Non-retryable export failures must be observable. The worker
// previously broke out of the retry loop silently on
// kFailedNotRetryable — operators had no signal that a batch was
// permanently discarded. The fix is a warn log + a dedicated counter
// (dropped_on_export_failure) parallel to dropped_on_overflow.
void TestBatchSpanProcessorNonRetryableFailureCountedAndLogged() {
    try {
        // Exporter returns kFailedNotRetryable on every call.
        class NotRetryableExporter : public SpanExporter {
        public:
            ExportResult Export(std::vector<SpanData>,
                                 std::chrono::steady_clock::time_point) override {
                ++calls_;
                return ExportResult::kFailedNotRetryable;
            }
            void SignalShutdown() override {}
            void CancelAllActiveExports() override {}
            int calls() const { return calls_; }
        private:
            std::atomic<int> calls_{0};
        };
        auto exporter = std::make_shared<NotRetryableExporter>();
        BatchSpanProcessorOptions opts;
        opts.max_export_batch_size = 4;
        opts.schedule_delay = std::chrono::milliseconds{60'000};
        BatchSpanProcessor bsp(exporter, opts);

        auto resource = std::make_shared<Resource>();
        auto random   = std::make_shared<RandomSource>(0xBADBEEFULL);
        TracerProvider provider(
            resource,
            std::shared_ptr<OBSERVABILITY_NAMESPACE::SpanProcessor>(
                &bsp, [](OBSERVABILITY_NAMESPACE::SpanProcessor*) {}),
            std::make_shared<AlwaysOnSampler>(), random);
        Tracer* t = provider.GetTracer("notretryable_test");

        // Submit a batch of 4 spans. Worker drains, exporter returns
        // kFailedNotRetryable, batch is dropped. Counter must reflect
        // the dropped span count; exported_batches stays 0.
        for (int i = 0; i < 4; ++i) { t->StartSpan("op", {})->End(); }
        bsp.ForceFlush(std::chrono::milliseconds{1000});

        // Wait for the worker to advance past the export attempt.
        for (int i = 0; i < 50 && exporter->calls() < 1; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
        }
        // Counter should be == batch size; non-retryable means no retry.
        const int64_t dropped = bsp.dropped_on_export_failure();
        const int64_t exported = bsp.exported_batches();
        bool pass = exporter->calls() == 1 &&
                    dropped == 4 &&
                    exported == 0;
        TestFramework::RecordTest(
            "ObsExport: BSP counts spans dropped on non-retryable failure",
            pass, pass ? ""
                      : "calls=" + std::to_string(exporter->calls())
                       + " dropped=" + std::to_string(dropped)
                       + " exported=" + std::to_string(exported),
            TestFramework::TestCategory::OTHER);
        bsp.SignalShutdown();
        bsp.JoinWorkers(std::chrono::milliseconds{500});
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsExport: BSP counts spans dropped on non-retryable failure",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestBatchSpanProcessorShutdownPropagates() {
    try {
        auto exporter = std::make_shared<CaptureSpanExporter>();
        BatchSpanProcessor proc(exporter, BatchSpanProcessorOptions{});
        proc.SignalShutdown();
        // Negative deadline = unbounded join. Bounded JoinWorkers can
        // return before the worker reaches the SignalShutdown forwarding
        // under TSan/heavy CPU contention, producing a spurious failure.
        // The bounded contract is exercised by other tests; this one
        // specifically asserts the propagation occurs.
        proc.JoinWorkers(std::chrono::milliseconds{-1});
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

// Locks the new JoinWorkers(0) = "no-wait" contract. shutdown_drain_timeout_sec=0
// is documented as "immediate"; under the OLD contract `deadline.count() <= 0`
// meant unbounded join, which silently wedged shutdown on a stalled exporter.
// The fix maps 0 to no-wait (return without joining) and reserves negative
// for unbounded. The destructor's fallback join still blocks on the worker
// before the object is destroyed, so the thread is never abandoned.
void TestBatchSpanProcessorJoinWorkersZeroIsNoWait() {
    try {
        // Stalled exporter: blocks SignalShutdown for ~2s — a real
        // operator stall would block the post-loop exporter signal
        // and lock JoinWorkers under the old contract.
        class StalledExporter : public SpanExporter {
        public:
            ExportResult Export(std::vector<SpanData>,
                                 std::chrono::steady_clock::time_point) override {
                return ExportResult::kSuccess;
            }
            void SignalShutdown() override {
                // Stall the worker thread's post-loop signal forwarding
                // for long enough to demonstrate the no-wait contract.
                std::this_thread::sleep_for(std::chrono::seconds{2});
            }
            void CancelAllActiveExports() override {}
        };
        auto exporter = std::make_shared<StalledExporter>();
        BatchSpanProcessor proc(exporter, BatchSpanProcessorOptions{});
        proc.SignalShutdown();

        auto t0 = std::chrono::steady_clock::now();
        proc.JoinWorkers(std::chrono::milliseconds{0});
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0);

        // The contract is "return immediately" — give it 200ms of
        // slack for scheduler noise. If we wait the full ~2s the
        // stall imposes, the no-wait semantic is broken.
        bool pass = elapsed < std::chrono::milliseconds{200};
        TestFramework::RecordTest(
            "ObsExport: JoinWorkers(0) returns immediately (no-wait contract)",
            pass,
            pass ? "" :
                ("elapsed=" + std::to_string(elapsed.count()) +
                 "ms (expected < 200ms — JoinWorkers(0) blocked on stalled exporter)"),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsExport: JoinWorkers(0) returns immediately (no-wait contract)",
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

// ---- ForceFlush base virtual (Phase 2 Task 1.0) ----
// HttpServer::FlushObservabilityForShutdown calls ForceFlush
// polymorphically via the base interface (no dynamic_cast). Verify the
// virtual exists and that the no-op processors compile + return cleanly.
void TestNoopProcessorForceFlushIsNoop() {
    try {
        OBSERVABILITY_NAMESPACE::NoopSpanProcessor p;
        p.ForceFlush(std::chrono::milliseconds(0));
        TestFramework::RecordTest(
            "ObsExport: NoopSpanProcessor ForceFlush is no-op",
            true, "", TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsExport: NoopSpanProcessor ForceFlush is no-op",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestInMemoryProcessorForceFlushIsNoop() {
    try {
        OBSERVABILITY_NAMESPACE::InMemorySpanProcessor p;
        p.ForceFlush(std::chrono::milliseconds(0));
        TestFramework::RecordTest(
            "ObsExport: InMemorySpanProcessor ForceFlush is no-op",
            true, "", TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsExport: InMemorySpanProcessor ForceFlush is no-op",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// BatchSpanProcessor's override drains buffered spans into the exporter.
void TestBatchSpanProcessorOverridesForceFlush() {
    try {
        auto exporter = std::make_shared<CaptureSpanExporter>();
        BatchSpanProcessorOptions opts;
        opts.max_export_batch_size = 16;
        opts.schedule_delay = std::chrono::milliseconds{60'000};  // long; flush is the trigger
        BatchSpanProcessor bsp(exporter, opts);

        auto resource = std::make_shared<Resource>();
        auto random   = std::make_shared<RandomSource>(0x1ULL);
        TracerProvider provider(
            resource,
            std::shared_ptr<OBSERVABILITY_NAMESPACE::SpanProcessor>(
                &bsp, [](OBSERVABILITY_NAMESPACE::SpanProcessor*) {}),
            std::make_shared<AlwaysOnSampler>(), random);
        Tracer* t = provider.GetTracer("flush_test");
        for (int i = 0; i < 3; ++i) { t->StartSpan("op", {})->End(); }

        bsp.ForceFlush(std::chrono::milliseconds(500));
        // ForceFlush returns when the in-memory queue empties; Export()
        // may still be running on the worker. Poll until the captured
        // count catches up (small bounded wait).
        for (int i = 0; i < 50 && exporter->Size() < 3; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
        }
        bool pass = exporter->Size() == 3;
        TestFramework::RecordTest(
            "ObsExport: BatchSpanProcessor::ForceFlush drains queue via base virtual",
            pass, pass ? "" : "got " + std::to_string(exporter->Size()) + "/3",
            TestFramework::TestCategory::OTHER);
        bsp.SignalShutdown();
        bsp.JoinWorkers(std::chrono::milliseconds(500));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsExport: BatchSpanProcessor::ForceFlush drains queue via base virtual",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// PeriodicMetricReader::ForceFlush blocks until the worker completes
// at least one export cycle (or the deadline expires). Without the
// blocking handshake, ForceFlush would return near-instantly and the
// shutdown drain would race the in-flight export.
void TestPeriodicMetricReaderForceFlushBlocks() {
    try {
        MeterProvider provider(std::make_shared<Resource>(), 1);
        auto exporter = std::make_shared<SlowMetricExporter>(
            std::chrono::milliseconds(150));
        MeterReaderOptions ropts;
        // Long interval so the periodic tick can't satisfy ForceFlush
        // on its own — the export MUST be flush-driven.
        ropts.export_interval = std::chrono::milliseconds(60'000);
        PeriodicMetricReader reader(&provider, exporter, ropts);

        // Deadline + bounds chosen for sanitizer headroom. The test
        // proves two invariants:
        //   (1) ForceFlush waits AT LEAST through the slow export
        //       (lower bound > 140ms — the artificial 150ms sleep,
        //       slack for sanitizer skew on the sleep itself).
        //   (2) ForceFlush returns BEFORE the deadline, i.e. the cv
        //       handshake fires (upper bound < deadline). The cv
        //       handshake plus TSan instrumentation can add several
        //       hundred ms of overhead, so the gap between upper
        //       bound and deadline must be generous.
        const auto kDeadline    = std::chrono::milliseconds{3000};
        const auto kLowerBound  = std::chrono::milliseconds{140};
        const auto kUpperBound  = std::chrono::milliseconds{2500};

        const auto t0 = std::chrono::steady_clock::now();
        reader.ForceFlush(kDeadline);
        const auto elapsed = std::chrono::steady_clock::now() - t0;

        const bool waited = elapsed >= kLowerBound;
        const bool bounded = elapsed <= kUpperBound;
        const bool exported = exporter->export_calls() >= 1;
        const bool pass = waited && bounded && exported;

        reader.SignalShutdown();
        reader.JoinWorkers(std::chrono::milliseconds(500));

        TestFramework::RecordTest(
            "ObsExport: PeriodicMetricReader::ForceFlush blocks for export",
            pass, pass ? ""
                      : "elapsed_ms=" + std::to_string(
                          std::chrono::duration_cast<
                              std::chrono::milliseconds>(elapsed).count())
                       + " exports=" + std::to_string(exporter->export_calls()),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsExport: PeriodicMetricReader::ForceFlush blocks for export",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// BSP::ForceFlush deadline contract — must mirror PMR/JoinWorkers:
//   deadline == 0  : no-wait, return immediately.
//   deadline <  0  : unbounded wait until queue empty + no in-flight.
//   deadline >  0  : bounded wait.
// Unbounded must NOT silently truncate to no-wait — a future caller
// passing -1ms as a sentinel for "wait until done" would otherwise get
// the export-in-flight torn down by shutdown drain.
void TestBatchSpanProcessorForceFlushDeadlineContract() {
    try {
        // Slow exporter — sleeps 200ms inside Export so the queue
        // doesn't drain instantly. We can then assert BSP::ForceFlush
        // honors the deadline shape.
        class SlowSpanExporter : public SpanExporter {
        public:
            ExportResult Export(std::vector<SpanData>,
                                 std::chrono::steady_clock::time_point) override {
                std::this_thread::sleep_for(std::chrono::milliseconds{200});
                exports_.fetch_add(1, std::memory_order_acq_rel);
                return ExportResult::kSuccess;
            }
            void SignalShutdown() override {}
            void CancelAllActiveExports() override {}
            int exports() const { return exports_.load(); }
        private:
            std::atomic<int> exports_{0};
        };

        auto exporter = std::make_shared<SlowSpanExporter>();
        BatchSpanProcessorOptions opts;
        opts.max_export_batch_size = 16;
        opts.schedule_delay = std::chrono::milliseconds{60'000};
        BatchSpanProcessor bsp(exporter, opts);

        auto resource = std::make_shared<Resource>();
        auto random   = std::make_shared<RandomSource>(0x9ULL);
        TracerProvider provider(
            resource,
            std::shared_ptr<OBSERVABILITY_NAMESPACE::SpanProcessor>(
                &bsp, [](OBSERVABILITY_NAMESPACE::SpanProcessor*) {}),
            std::make_shared<AlwaysOnSampler>(), random);
        Tracer* t = provider.GetTracer("ff_contract");

        // Case 1: deadline=0 returns immediately even with a queued span.
        t->StartSpan("op", {})->End();
        const auto t0 = std::chrono::steady_clock::now();
        bsp.ForceFlush(std::chrono::milliseconds{0});
        const auto e0 = std::chrono::steady_clock::now() - t0;
        const bool zero_returns_fast =
            e0 < std::chrono::milliseconds{50};

        // Drain anything still pending under a generous deadline so
        // case 3 starts from a clean state.
        bsp.ForceFlush(std::chrono::milliseconds{2000});

        // Case 2: deadline=-1 waits unbounded — must observe the slow
        // export complete (queue empty + no in-flight).
        t->StartSpan("op2", {})->End();
        const auto t1 = std::chrono::steady_clock::now();
        bsp.ForceFlush(std::chrono::milliseconds{-1});
        const auto e1 = std::chrono::steady_clock::now() - t1;
        const auto e1_ms = std::chrono::duration_cast<
            std::chrono::milliseconds>(e1);
        // Slow exporter is 200ms; allow generous lower bound (150ms,
        // sanitizer slack) and upper bound (3000ms, scheduler skew).
        const bool unbounded_waits =
            e1_ms >= std::chrono::milliseconds{150} &&
            e1_ms <= std::chrono::milliseconds{3000};

        const bool pass = zero_returns_fast && unbounded_waits;
        TestFramework::RecordTest(
            "ObsExport: BSP::ForceFlush deadline contract (0=no-wait, -1=unbounded)",
            pass, pass ? ""
                      : ("zero_fast=" + std::to_string(zero_returns_fast)
                       + " unbounded=" + std::to_string(unbounded_waits)
                       + " e0_ms=" + std::to_string(
                             std::chrono::duration_cast<
                                 std::chrono::milliseconds>(e0).count())
                       + " e1_ms=" + std::to_string(e1_ms.count())),
            TestFramework::TestCategory::OTHER);

        bsp.SignalShutdown();
        bsp.JoinWorkers(std::chrono::milliseconds{500});
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsExport: BSP::ForceFlush deadline contract (0=no-wait, -1=unbounded)",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// MakeOtlpTransport must short-circuit to kFailedNotRetryable when
// the captured weak_ptr<UpstreamHttpClient> has expired (e.g. abnormal
// shutdown ordering tears down the client before the BSP/PMR worker's
// final export). Without the lock-and-bail check, the transport would
// dereference a null shared_ptr and crash inside the worker thread.
// An empty weak_ptr is the simplest way to drive that path: lock()
// returns null without needing a real client construction.
void TestMakeOtlpTransportNullClientShortCircuits() {
    try {
        std::weak_ptr<AUTH_NAMESPACE::UpstreamHttpClient> empty;
        auto transport = OBSERVABILITY_NAMESPACE::MakeOtlpTransport(empty);

        OtlpHttpExporter::ExportPayload payload;
        payload.upstream_pool_name = "otel-collector";
        payload.path               = "/v1/traces";
        payload.body               = "{}";
        payload.timeout            = std::chrono::milliseconds{1000};

        const auto deadline = std::chrono::steady_clock::now()
                            + std::chrono::seconds{1};
        const auto result = transport(std::move(payload), deadline);

        bool pass = (result == ExportResult::kFailedNotRetryable);
        TestFramework::RecordTest(
            "ObsExport: MakeOtlpTransport short-circuits when client weak_ptr expired",
            pass, pass ? "" : "expected kFailedNotRetryable",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsExport: MakeOtlpTransport short-circuits when client weak_ptr expired",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Sub-second OTLP timeouts must NOT truncate to zero. timeout_sec=0
// disables UpstreamHttpClient::SetDeadline; fut.get() then blocks
// indefinitely on a stalled upstream and wedges the BSP/PMR worker.
// Round-up-to-1s is the contract OtlpTimeoutCeilSeconds enforces.
void TestOtlpTimeoutCeilSeconds() {
    try {
        using ms = std::chrono::milliseconds;
        struct Case {
            const char* name;
            int64_t input_ms;
            int     expected_secs;
        };
        const Case cases[] = {
            {"zero",                0,        1},
            {"one_ms",              1,        1},
            {"sub_second_500",    500,        1},
            {"sub_second_999",    999,        1},
            {"exact_1s",         1000,        1},
            {"1001ms_rounds_up", 1001,        2},
            {"5500ms_rounds_up", 5500,        6},
            {"60s",             60000,       60},
            {"negative_clamped",   -5,        1},
        };
        bool pass = true;
        std::string err;
        for (const auto& c : cases) {
            const int got = OBSERVABILITY_NAMESPACE::OtlpTimeoutCeilSeconds(
                ms{c.input_ms});
            if (got != c.expected_secs) {
                pass = false;
                err = std::string{c.name} + ": expected "
                    + std::to_string(c.expected_secs)
                    + ", got " + std::to_string(got);
                break;
            }
            // Critical invariant: never zero — that disables SetDeadline.
            if (got <= 0) {
                pass = false;
                err = std::string{c.name} + ": timeout_sec <= 0 "
                                            "(would disable deadline)";
                break;
            }
        }
        TestFramework::RecordTest(
            "ObsExport: OtlpTimeoutCeilSeconds rounds up sub-second to >=1",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsExport: OtlpTimeoutCeilSeconds rounds up sub-second to >=1",
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
    TestBatchSpanProcessorNonRetryableFailureCountedAndLogged();
    TestBatchSpanProcessorShutdownPropagates();
    TestBatchSpanProcessorJoinWorkersZeroIsNoWait();
    TestPeriodicMetricReaderExportsCycles();
    TestOtlpExporterSerializesSpansToJson();
    TestOtlpExporterShutdownRefusesExport();
    TestOtlpExporterReloadHeaders();
    TestOtlpExporterSerializesMetricsToJson();
    TestNoopProcessorForceFlushIsNoop();
    TestInMemoryProcessorForceFlushIsNoop();
    TestBatchSpanProcessorOverridesForceFlush();
    TestPeriodicMetricReaderForceFlushBlocks();
    TestBatchSpanProcessorForceFlushDeadlineContract();
    TestMakeOtlpTransportNullClientShortCircuits();
    TestOtlpTimeoutCeilSeconds();
}

}  // namespace ObservabilityExportPipelineTests
