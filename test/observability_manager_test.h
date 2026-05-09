#pragma once

// ObservabilityManager + ObservabilityMiddleware unit tests. Covers
// snapshot register-and-count atomicity, FinalizeFromSnapshot CAS
// gate, KillOutstandingSnapshots, Reload live-flag flipping, and
// middleware end-to-end snapshot population.

#include "test_framework.h"
#include "http/http_request.h"
#include "http/http_response.h"
#include "observability/observability_manager.h"
#include "observability/observability_middleware.h"
#include "observability/observability_snapshot.h"
#include "observability/resource.h"
#include "observability/batch_span_processor.h"
#include "observability/metric_exporter.h"
#include "observability/periodic_metric_reader.h"
#include "observability/span_exporter.h"
#include "observability/sampler.h"
#include "observability/span_processor.h"
#include "observability/trace_id.h"

#include <memory>
#include <stdexcept>
#include <string>
#include <thread>

namespace ObservabilityManagerTests {

using OBSERVABILITY_NAMESPACE::AlwaysOnSampler;
using OBSERVABILITY_NAMESPACE::BatchSpanProcessor;
using OBSERVABILITY_NAMESPACE::BatchSpanProcessorOptions;
using OBSERVABILITY_NAMESPACE::ExportResult;
using OBSERVABILITY_NAMESPACE::InMemorySpanProcessor;
using OBSERVABILITY_NAMESPACE::MakeObservabilityMiddleware;
using OBSERVABILITY_NAMESPACE::MeterReaderOptions;
using OBSERVABILITY_NAMESPACE::MetricExporter;
using OBSERVABILITY_NAMESPACE::MetricsSnapshot;
using OBSERVABILITY_NAMESPACE::ObservabilityConfig;
using OBSERVABILITY_NAMESPACE::ObservabilityManager;
using OBSERVABILITY_NAMESPACE::ObservabilitySnapshot;
using OBSERVABILITY_NAMESPACE::PeriodicMetricReader;
using OBSERVABILITY_NAMESPACE::RandomSource;
using OBSERVABILITY_NAMESPACE::Resource;
using OBSERVABILITY_NAMESPACE::SamplerType;
using OBSERVABILITY_NAMESPACE::SpanData;
using OBSERVABILITY_NAMESPACE::SpanExporter;

namespace {

ObservabilityConfig DefaultConfig() {
    ObservabilityConfig c;
    c.enabled = true;
    c.traces.enabled = true;
    c.metrics.enabled = true;
    c.traces.sampler.type = SamplerType::AlwaysOn;
    c.resource.service_name = "test-service";
    return c;
}

std::shared_ptr<ObservabilityManager> MakeManager(
    std::shared_ptr<InMemorySpanProcessor> processor =
        std::make_shared<InMemorySpanProcessor>(),
    ObservabilityConfig config = DefaultConfig()) {
    return ObservabilityManager::Create(
        std::move(config),
        std::make_shared<Resource>(),
        std::move(processor),
        std::make_shared<RandomSource>(0xCAFE0001ULL));
}

std::shared_ptr<ObservabilitySnapshot> MakeSnapshot() {
    auto s = std::make_shared<ObservabilitySnapshot>();
    s->method        = "GET";
    s->route_pattern = "/users/:id";
    return s;
}

}  // namespace

// ---- Register/finalize lifecycle ----
void TestRegisterLiveSnapshotIncrementsCounter() {
    try {
        auto mgr = MakeManager();
        auto s1 = MakeSnapshot();
        auto s2 = MakeSnapshot();
        mgr->RegisterLiveSnapshot(s1);
        mgr->RegisterLiveSnapshot(s2);
        bool pass = mgr->inflight_finalizations() == 2;
        TestFramework::RecordTest(
            "ObsMgr: RegisterLiveSnapshot increments inflight counter",
            pass, pass ? "" : "counter wrong",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsMgr: RegisterLiveSnapshot increments inflight counter",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestFinalizeDecrementsCounter() {
    try {
        auto mgr = MakeManager();
        auto s   = MakeSnapshot();
        mgr->RegisterLiveSnapshot(s);
        bool won = mgr->FinalizeFromSnapshot(*s, 200, 1024, "");
        bool pass = won && mgr->inflight_finalizations() == 0;
        TestFramework::RecordTest(
            "ObsMgr: FinalizeFromSnapshot decrements inflight counter",
            pass, pass ? "" : "counter not decremented",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsMgr: FinalizeFromSnapshot decrements inflight counter",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// CAS gate: only ONE caller wins.
void TestFinalizeCASIdempotent() {
    try {
        auto mgr = MakeManager();
        auto s   = MakeSnapshot();
        mgr->RegisterLiveSnapshot(s);
        bool a = mgr->FinalizeFromSnapshot(*s, 200, 100, "");
        bool b = mgr->FinalizeFromSnapshot(*s, 500, 999, "");  // late
        bool c = mgr->FinalizeFromSnapshot(*s, 503, 0, "");    // late
        bool pass = a && !b && !c &&
                    s->status_code.load() == 200 &&
                    s->wire_body_size.load() == 100 &&
                    mgr->inflight_finalizations() == 0;
        TestFramework::RecordTest(
            "ObsMgr: Finalize CAS gate — only one wins, late callers no-op",
            pass, pass ? "" : "late finalize leaked",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsMgr: Finalize CAS gate — only one wins, late callers no-op",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Concurrent finalize race — exactly one winner under contention.
void TestFinalizeConcurrentRace() {
    try {
        constexpr int kThreads = 16;
        auto mgr = MakeManager();
        auto s = MakeSnapshot();
        mgr->RegisterLiveSnapshot(s);

        std::atomic<int> winners{0};
        std::vector<std::thread> threads;
        threads.reserve(kThreads);
        for (int i = 0; i < kThreads; ++i) {
            threads.emplace_back([&, i]() {
                if (mgr->FinalizeFromSnapshot(*s, 200 + i, i, "")) {
                    winners.fetch_add(1, std::memory_order_acq_rel);
                }
            });
        }
        for (auto& t : threads) t.join();

        bool pass = winners.load() == 1 && mgr->inflight_finalizations() == 0;
        TestFramework::RecordTest(
            "ObsMgr: Concurrent Finalize — exactly one winner",
            pass, pass ? "" : "winners=" + std::to_string(winners.load()),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsMgr: Concurrent Finalize — exactly one winner",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// KillOutstandingSnapshots: all live snapshots become finalized.
void TestKillFinalizesOutstanding() {
    try {
        auto mgr = MakeManager();
        auto s1 = MakeSnapshot();
        auto s2 = MakeSnapshot();
        auto s3 = MakeSnapshot();
        mgr->RegisterLiveSnapshot(s1);
        mgr->RegisterLiveSnapshot(s2);
        mgr->RegisterLiveSnapshot(s3);

        mgr->KillOutstandingSnapshots(std::chrono::milliseconds{100});

        bool pass = s1->finalized.load() &&
                    s2->finalized.load() &&
                    s3->finalized.load() &&
                    mgr->inflight_finalizations() == 0;
        TestFramework::RecordTest(
            "ObsMgr: KillOutstandingSnapshots finalizes every live snapshot",
            pass, pass ? "" : "kill left snapshots un-finalized",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsMgr: KillOutstandingSnapshots finalizes every live snapshot",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Kill on already-finalized snapshot is a no-op (no double-decrement).
void TestKillOnAlreadyFinalizedNoOps() {
    try {
        auto mgr = MakeManager();
        auto s = MakeSnapshot();
        mgr->RegisterLiveSnapshot(s);
        mgr->FinalizeFromSnapshot(*s, 200, 0, "");
        // Counter already at 0 — kill should not double-decrement
        // (would underflow + spam wait predicates).
        mgr->KillOutstandingSnapshots(std::chrono::milliseconds{10});
        bool pass = mgr->inflight_finalizations() == 0;
        TestFramework::RecordTest(
            "ObsMgr: Kill on finalized snapshot does not double-decrement",
            pass, pass ? "" : "counter underflowed",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsMgr: Kill on finalized snapshot does not double-decrement",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- Live-flag toggles via Reload ----
void TestReloadFlipsTracesEnabled() {
    try {
        auto mgr = MakeManager();
        bool before = mgr->TracesEnabled();

        auto cfg = DefaultConfig();
        cfg.traces.enabled = false;
        mgr->Reload(cfg);
        bool mid = mgr->TracesEnabled();

        cfg.traces.enabled = true;
        mgr->Reload(cfg);
        bool after = mgr->TracesEnabled();

        bool pass = before && !mid && after;
        TestFramework::RecordTest(
            "ObsMgr: Reload flips TracesEnabled live",
            pass, pass ? "" : "reload didn't flip flag",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsMgr: Reload flips TracesEnabled live",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestReloadFlipsMetricsEnabled() {
    try {
        auto mgr = MakeManager();
        auto cfg = DefaultConfig();
        cfg.metrics.enabled = false;
        mgr->Reload(cfg);
        bool pass = !mgr->MetricsEnabled();
        TestFramework::RecordTest(
            "ObsMgr: Reload flips MetricsEnabled live",
            pass, pass ? "" : "metrics flag didn't flip",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsMgr: Reload flips MetricsEnabled live",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- BeginShutdown idempotency ----
void TestBeginShutdownIdempotent() {
    try {
        auto mgr = MakeManager();
        mgr->BeginShutdown(std::chrono::milliseconds{50});
        mgr->BeginShutdown(std::chrono::milliseconds{50});  // no-op
        mgr->BeginShutdown(std::chrono::milliseconds{50});  // no-op
        // No assertion beyond "didn't crash / hang" — idempotency is
        // a survival check.
        TestFramework::RecordTest(
            "ObsMgr: BeginShutdown is idempotent",
            true, "", TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsMgr: BeginShutdown is idempotent",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- Phase 2: PeriodicMetricReader registration + drain ----

namespace {
class CountingMetricExporter : public MetricExporter {
public:
    ExportResult Export(MetricsSnapshot,
                         std::chrono::steady_clock::time_point) override {
        return ExportResult::kSuccess;
    }
    void SignalShutdown() override {}
    void CancelAllActiveExports() override {}
};
}  // namespace

void TestRegisterMetricReaderDrainedOnBeginShutdown() {
    try {
        auto mgr = MakeManager();
        auto exporter = std::make_shared<CountingMetricExporter>();
        MeterReaderOptions opts;
        opts.export_interval = std::chrono::milliseconds(50);
        auto reader = std::make_shared<PeriodicMetricReader>(
            mgr->meter_provider(), exporter, opts);
        mgr->RegisterMetricReader(reader);

        bool has_reader = mgr->HasMetricReader();
        // Worker auto-starts in PMR ctor; let it iterate at least once.
        for (int i = 0; i < 50 && reader->worker_loop_iterations() == 0; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        int64_t iters_before = reader->worker_loop_iterations();
        bool started = iters_before >= 1
                     && reader->signal_shutdown_calls() == 0;

        mgr->BeginShutdown(std::chrono::milliseconds(500));

        bool drained = reader->signal_shutdown_calls() == 1;
        // Worker should have stopped — counter is stable.
        int64_t iters_after = reader->worker_loop_iterations();
        std::this_thread::sleep_for(std::chrono::milliseconds(80));
        bool stable = reader->worker_loop_iterations() == iters_after;

        bool pass = has_reader && started && drained && stable;
        std::string err;
        if (!has_reader) err = "HasMetricReader was false";
        else if (!started) err = "worker did not iterate before BeginShutdown";
        else if (!drained) err = "signal_shutdown_calls != 1, got "
                                + std::to_string(reader->signal_shutdown_calls());
        else if (!stable) err = "worker_loop_iterations still increasing post-join";
        TestFramework::RecordTest(
            "ObsMgr: RegisterMetricReader drained on BeginShutdown",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsMgr: RegisterMetricReader drained on BeginShutdown",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- Phase 2: shared-exporter shutdown coordination (Task 1.1a) ----

namespace {
// Shim implementing BOTH SpanExporter AND MetricExporter — same shape
// as OtlpHttpExporter — so a single instance can sit behind both BSP
// and PMR. Counts SignalShutdown calls to verify the manager fires it
// at most once when the exporter is shared.
class SharedDualExporter
    : public SpanExporter,
      public MetricExporter {
public:
    ExportResult Export(std::vector<SpanData>,
                         std::chrono::steady_clock::time_point) override {
        return ExportResult::kSuccess;
    }
    ExportResult Export(MetricsSnapshot,
                         std::chrono::steady_clock::time_point) override {
        return ExportResult::kSuccess;
    }
    void SignalShutdown() override {
        signal_count_.fetch_add(1, std::memory_order_acq_rel);
    }
    void CancelAllActiveExports() override {}
    int signal_count() const { return signal_count_.load(); }

private:
    std::atomic<int> signal_count_{0};
};
}  // namespace

void TestSharedExporterSignalledOnceOnShutdown() {
    try {
        auto exporter = std::make_shared<SharedDualExporter>();
        std::shared_ptr<SpanExporter>   span_exp   = exporter;
        std::shared_ptr<MetricExporter> metric_exp = exporter;

        BatchSpanProcessorOptions bsp_opts;
        bsp_opts.schedule_delay = std::chrono::milliseconds(60'000);
        auto bsp = std::make_shared<BatchSpanProcessor>(span_exp, bsp_opts);

        auto mgr = ObservabilityManager::Create(
            DefaultConfig(),
            std::make_shared<Resource>(),
            bsp,
            std::make_shared<RandomSource>(0xCAFE0002ULL));

        MeterReaderOptions ropts;
        ropts.export_interval = std::chrono::milliseconds(60'000);
        auto reader = std::make_shared<PeriodicMetricReader>(
            mgr->meter_provider(), metric_exp, ropts);
        mgr->RegisterMetricReader(reader);

        mgr->BeginShutdown(std::chrono::milliseconds(500));

        bool pass = exporter->signal_count() == 1;
        TestFramework::RecordTest(
            "ObsMgr: shared exporter signalled exactly once on shutdown",
            pass, pass ? "" : "signal_count = " + std::to_string(exporter->signal_count()),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsMgr: shared exporter signalled exactly once on shutdown",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Negative case: when traces and metrics use DIFFERENT exporter
// instances, the manager must NOT cross-coordinate — each per-worker
// path signals its own exporter.
void TestSeparateExportersEachSignalledOnce() {
    try {
        auto trace_exp  = std::make_shared<SharedDualExporter>();
        auto metric_exp = std::make_shared<SharedDualExporter>();

        BatchSpanProcessorOptions bsp_opts;
        bsp_opts.schedule_delay = std::chrono::milliseconds(60'000);
        auto bsp = std::make_shared<BatchSpanProcessor>(
            std::shared_ptr<SpanExporter>(trace_exp), bsp_opts);

        auto mgr = ObservabilityManager::Create(
            DefaultConfig(),
            std::make_shared<Resource>(),
            bsp,
            std::make_shared<RandomSource>(0xCAFE0003ULL));

        MeterReaderOptions ropts;
        ropts.export_interval = std::chrono::milliseconds(60'000);
        auto reader = std::make_shared<PeriodicMetricReader>(
            mgr->meter_provider(),
            std::shared_ptr<MetricExporter>(metric_exp), ropts);
        mgr->RegisterMetricReader(reader);

        mgr->BeginShutdown(std::chrono::milliseconds(500));

        bool pass = trace_exp->signal_count()  == 1
                  && metric_exp->signal_count() == 1;
        TestFramework::RecordTest(
            "ObsMgr: separate exporters each signalled once",
            pass, pass ? ""
                      : "trace=" + std::to_string(trace_exp->signal_count())
                       + ", metric=" + std::to_string(metric_exp->signal_count()),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsMgr: separate exporters each signalled once",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- Phase 2: exporter_is_shared_for_test() ----
//
// Mirrors how MarkServerReady wires the metrics-side PMR onto the same
// OtlpHttpExporter the trace-side BSP holds: the manager detects the
// shared exporter and BeginShutdown coordinates the single signal.

void TestExporterIsSharedDetectsCoLocatedExporter() {
    try {
        auto exporter = std::make_shared<SharedDualExporter>();
        BatchSpanProcessorOptions bsp_opts;
        bsp_opts.schedule_delay = std::chrono::milliseconds(60'000);
        auto bsp = std::make_shared<BatchSpanProcessor>(
            std::shared_ptr<SpanExporter>(exporter), bsp_opts);

        auto mgr = ObservabilityManager::Create(
            DefaultConfig(), std::make_shared<Resource>(), bsp,
            std::make_shared<RandomSource>(0xCAFE0010ULL));

        bool unshared_before = !mgr->exporter_is_shared_for_test();

        MeterReaderOptions ropts;
        ropts.export_interval = std::chrono::milliseconds(60'000);
        auto reader = std::make_shared<PeriodicMetricReader>(
            mgr->meter_provider(),
            std::shared_ptr<MetricExporter>(exporter), ropts);
        mgr->RegisterMetricReader(reader);

        bool shared_after = mgr->exporter_is_shared_for_test();
        mgr->BeginShutdown(std::chrono::milliseconds(500));

        bool pass = unshared_before && shared_after;
        TestFramework::RecordTest(
            "ObsMgr: exporter_is_shared_for_test detects shared instance",
            pass, pass ? ""
                      : "before=" + std::to_string(unshared_before)
                       + " after=" + std::to_string(shared_after),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsMgr: exporter_is_shared_for_test detects shared instance",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestExporterIsSharedFalseForSeparateInstances() {
    try {
        auto trace_exp  = std::make_shared<SharedDualExporter>();
        auto metric_exp = std::make_shared<SharedDualExporter>();

        BatchSpanProcessorOptions bsp_opts;
        bsp_opts.schedule_delay = std::chrono::milliseconds(60'000);
        auto bsp = std::make_shared<BatchSpanProcessor>(
            std::shared_ptr<SpanExporter>(trace_exp), bsp_opts);

        auto mgr = ObservabilityManager::Create(
            DefaultConfig(), std::make_shared<Resource>(), bsp,
            std::make_shared<RandomSource>(0xCAFE0011ULL));

        MeterReaderOptions ropts;
        ropts.export_interval = std::chrono::milliseconds(60'000);
        auto reader = std::make_shared<PeriodicMetricReader>(
            mgr->meter_provider(),
            std::shared_ptr<MetricExporter>(metric_exp), ropts);
        mgr->RegisterMetricReader(reader);

        bool pass = !mgr->exporter_is_shared_for_test();
        mgr->BeginShutdown(std::chrono::milliseconds(500));
        TestFramework::RecordTest(
            "ObsMgr: exporter_is_shared_for_test false for separate exporters",
            pass, pass ? "" : "incorrectly reported shared",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsMgr: exporter_is_shared_for_test false for separate exporters",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- Phase 2: live traces.enabled SIGHUP without restart (Task 1.5) ----
//
// Pipeline allocation in MarkServerReady is gated on `traces.exporter`
// (restart-only), NOT on `traces.enabled` (live). A SIGHUP that flips
// `traces.enabled` from false to true must therefore emit spans on the
// next request without any process restart, since the BSP is already
// installed and ready behind the live flag.

void TestLiveTracesEnabledFlipKeepsBatchProcessor() {
    try {
        // Boot with traces.enabled=false — this is the "exporter wired,
        // emission silenced" case Task 1.5 cares about.
        ObservabilityConfig cfg = DefaultConfig();
        cfg.traces.enabled = false;
        auto mgr = ObservabilityManager::Create(
            std::move(cfg),
            std::make_shared<Resource>(),
            std::make_shared<OBSERVABILITY_NAMESPACE::NoopSpanProcessor>(),
            std::make_shared<RandomSource>(0xCAFE0020ULL));

        // Simulate MarkServerReady's wiring — swap in a BSP regardless
        // of the live `enabled` flag.
        auto exporter = std::make_shared<SharedDualExporter>();
        BatchSpanProcessorOptions bsp_opts;
        bsp_opts.schedule_delay = std::chrono::milliseconds(60'000);
        auto bsp = std::make_shared<BatchSpanProcessor>(
            std::shared_ptr<SpanExporter>(exporter), bsp_opts);
        mgr->SwapToBatchSpanProcessor(bsp);

        const bool batch_installed = mgr->span_processor_is_batch_for_test();
        const bool traces_off_before = !mgr->TracesEnabled();

        // SIGHUP flips traces.enabled to true. The BSP is already there —
        // we only flip the live flag.
        ObservabilityConfig flipped = DefaultConfig();
        flipped.traces.enabled = true;
        mgr->Reload(flipped);

        const bool traces_on_after = mgr->TracesEnabled();
        // BSP must survive the reload (no processor swap on Reload).
        const bool batch_still = mgr->span_processor_is_batch_for_test();

        mgr->BeginShutdown(std::chrono::milliseconds(500));

        const bool pass = batch_installed && traces_off_before
                       && traces_on_after && batch_still;
        TestFramework::RecordTest(
            "ObsMgr: traces.enabled SIGHUP flip preserves wired BSP",
            pass, pass ? ""
                      : "installed=" + std::to_string(batch_installed)
                       + " off_before=" + std::to_string(traces_off_before)
                       + " on_after=" + std::to_string(traces_on_after)
                       + " still=" + std::to_string(batch_still),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsMgr: traces.enabled SIGHUP flip preserves wired BSP",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- Phase 2: SwapToBatchSpanProcessor (boot-time hot-swap) ----

void TestSwapToBatchSpanProcessorReplacesNoop() {
    try {
        // Manager starts on the boot-time NoopSpanProcessor — same path
        // production takes when traces.exporter == "otlp_http" (main.cc
        // installs Noop; HttpServer::MarkServerReady performs the swap).
        ObservabilityConfig cfg = DefaultConfig();
        auto mgr = ObservabilityManager::Create(
            std::move(cfg),
            std::make_shared<Resource>(),
            std::make_shared<OBSERVABILITY_NAMESPACE::NoopSpanProcessor>(),
            std::make_shared<RandomSource>(0xCAFE0004ULL));

        bool noop_before = !mgr->span_processor_is_batch_for_test();

        auto exporter = std::make_shared<SharedDualExporter>();
        BatchSpanProcessorOptions bsp_opts;
        bsp_opts.schedule_delay = std::chrono::milliseconds(60'000);
        auto bsp = std::make_shared<BatchSpanProcessor>(
            std::shared_ptr<SpanExporter>(exporter), bsp_opts);
        mgr->SwapToBatchSpanProcessor(bsp);

        bool batch_after = mgr->span_processor_is_batch_for_test();

        // Idempotent: a second swap is rejected (logs a warn; manager
        // stays on the originally-installed BSP).
        auto bsp2 = std::make_shared<BatchSpanProcessor>(
            std::shared_ptr<SpanExporter>(exporter), bsp_opts);
        mgr->SwapToBatchSpanProcessor(bsp2);
        bool batch_still = mgr->span_processor_is_batch_for_test();

        // Drain so the BSP worker exits cleanly before destruction.
        mgr->BeginShutdown(std::chrono::milliseconds(500));

        bool pass = noop_before && batch_after && batch_still;
        TestFramework::RecordTest(
            "ObsMgr: SwapToBatchSpanProcessor replaces Noop (idempotent)",
            pass, pass ? ""
                      : "noop_before=" + std::to_string(noop_before)
                       + " after=" + std::to_string(batch_after)
                       + " still=" + std::to_string(batch_still),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsMgr: SwapToBatchSpanProcessor replaces Noop (idempotent)",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- Middleware end-to-end ----
void TestMiddlewareBuildsSnapshotAndSpan() {
    try {
        auto mgr = MakeManager();
        auto mw  = MakeObservabilityMiddleware(mgr);

        HttpRequest req;
        req.method = "GET";
        req.url = "/users/42";
        req.path = "/users/42";
        req.url_scheme = "http";
        req.network_protocol_version = "1.1";
        // route_match would be set by the router's pre-middleware
        // ResolveRouteMatch hook; in this test we set it manually.
        req.route_match.pattern             = "/users/:id";
        req.route_match.kind                = RouteKind::Sync;
        req.route_match.method_for_dispatch = "GET";

        HttpResponse resp;
        bool pass_chain = mw(req, resp);

        bool pass = pass_chain &&
                    req.obs_snapshot &&
                    req.obs_snapshot->method == "GET" &&
                    req.obs_snapshot->route_pattern == "/users/:id" &&
                    req.observability_span != nullptr &&
                    req.observability_span->IsRecording() &&
                    req.trace_ctx.has_value();

        // After the middleware: counter should be 1 (one in-flight).
        pass = pass && mgr->inflight_finalizations() == 1;

        // Now finalize via the manager directly (simulating
        // response-completion). Counter back to 0; span ends.
        mgr->FinalizeFromSnapshot(*req.obs_snapshot, 200, 0, "");
        pass = pass && mgr->inflight_finalizations() == 0 &&
               !req.observability_span->IsRecording();

        TestFramework::RecordTest(
            "ObsMgr: middleware populates snapshot + span; finalize closes",
            pass, pass ? "" : "middleware/finalize wrong",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsMgr: middleware populates snapshot + span; finalize closes",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Middleware skips Span allocation when traces are disabled, but
// still builds the snapshot (so middleware-rejection paths can finalize).
void TestMiddlewareTracesDisabledStillBuildsSnapshot() {
    try {
        auto mgr = MakeManager();
        auto cfg = DefaultConfig();
        cfg.traces.enabled = false;
        mgr->Reload(cfg);

        auto mw = MakeObservabilityMiddleware(mgr);
        HttpRequest req;
        req.method = "POST";
        req.path = "/login";
        req.route_match.pattern = "/login";
        req.route_match.kind    = RouteKind::Sync;
        HttpResponse resp;
        bool ok = mw(req, resp);

        bool pass = ok &&
                    req.obs_snapshot &&
                    req.observability_span == nullptr &&
                    mgr->inflight_finalizations() == 1;
        // Cleanup so the manager destructor doesn't see leaked counters.
        mgr->FinalizeFromSnapshot(*req.obs_snapshot, 200, 0, "");
        TestFramework::RecordTest(
            "ObsMgr: traces=false still builds snapshot, skips Span allocation",
            pass, pass ? "" : "traces-disabled path wrong",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsMgr: traces=false still builds snapshot, skips Span allocation",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Null-manager middleware is a no-op.
void TestMiddlewareNullManagerNoOp() {
    try {
        auto mw = MakeObservabilityMiddleware(nullptr);
        HttpRequest req;
        req.method = "GET";
        req.path = "/x";
        HttpResponse resp;
        bool ok = mw(req, resp);
        bool pass = ok &&
                    !req.obs_snapshot &&
                    !req.observability_span &&
                    !req.trace_ctx.has_value();
        TestFramework::RecordTest(
            "ObsMgr: null-manager middleware is a no-op",
            pass, pass ? "" : "null path mutated request",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsMgr: null-manager middleware is a no-op",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void RunAllTests() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "OBSERVABILITY MANAGER + MIDDLEWARE UNIT TESTS" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    TestRegisterLiveSnapshotIncrementsCounter();
    TestFinalizeDecrementsCounter();
    TestFinalizeCASIdempotent();
    TestFinalizeConcurrentRace();
    TestKillFinalizesOutstanding();
    TestKillOnAlreadyFinalizedNoOps();
    TestReloadFlipsTracesEnabled();
    TestReloadFlipsMetricsEnabled();
    TestBeginShutdownIdempotent();
    TestRegisterMetricReaderDrainedOnBeginShutdown();
    TestSharedExporterSignalledOnceOnShutdown();
    TestSeparateExportersEachSignalledOnce();
    TestSwapToBatchSpanProcessorReplacesNoop();
    TestExporterIsSharedDetectsCoLocatedExporter();
    TestExporterIsSharedFalseForSeparateInstances();
    TestLiveTracesEnabledFlipKeepsBatchProcessor();
    TestMiddlewareBuildsSnapshotAndSpan();
    TestMiddlewareTracesDisabledStillBuildsSnapshot();
    TestMiddlewareNullManagerNoOp();
}

}  // namespace ObservabilityManagerTests
