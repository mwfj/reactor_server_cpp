#pragma once

// ObservabilityManager + ObservabilityMiddleware unit tests (task #66).
// Covers: snapshot register-and-count atomicity, FinalizeFromSnapshot
// CAS gate, KillOutstandingSnapshots, Reload live-flag flipping,
// middleware end-to-end snapshot population.

#include "test_framework.h"
#include "http/http_request.h"
#include "http/http_response.h"
#include "observability/observability_manager.h"
#include "observability/observability_middleware.h"
#include "observability/observability_snapshot.h"
#include "observability/resource.h"
#include "observability/sampler.h"
#include "observability/span_processor.h"
#include "observability/trace_id.h"

#include <memory>
#include <stdexcept>
#include <string>
#include <thread>

namespace ObservabilityManagerTests {

using OBSERVABILITY_NAMESPACE::AlwaysOnSampler;
using OBSERVABILITY_NAMESPACE::InMemorySpanProcessor;
using OBSERVABILITY_NAMESPACE::MakeObservabilityMiddleware;
using OBSERVABILITY_NAMESPACE::ObservabilityConfig;
using OBSERVABILITY_NAMESPACE::ObservabilityManager;
using OBSERVABILITY_NAMESPACE::ObservabilitySnapshot;
using OBSERVABILITY_NAMESPACE::RandomSource;
using OBSERVABILITY_NAMESPACE::Resource;
using OBSERVABILITY_NAMESPACE::SamplerType;

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
    TestMiddlewareBuildsSnapshotAndSpan();
    TestMiddlewareTracesDisabledStillBuildsSnapshot();
    TestMiddlewareNullManagerNoOp();
}

}  // namespace ObservabilityManagerTests
