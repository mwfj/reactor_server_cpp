#pragma once

// Kill-loop invariant guards. These tests ratchet the documented safety
// contract of `KillOutstandingSnapshots`:
//
//   * Snapshots with no `owning_dispatcher` (or owned by the calling
//     thread itself) run the kill body INLINE — `kill_marshals_in_flight_`
//     is never incremented in that path.
//   * Snapshots with a cross-thread `owning_dispatcher` marshal via
//     `EnQueueDelayed(fn, 0ms)` — the counter rises during the marshal
//     window and returns to 0 once the closure runs.
//   * If `EnQueueDelayed` refuses (dispatcher already stopped), the
//     bump is rolled back and the snapshot is killed inline as a fallback.
//   * The CAS gate inside `FinalizeFromSnapshot` resolves a multi-thread
//     race between the kill loop and concurrent finalize callers — every
//     snapshot is finalized exactly once.
//   * `snapshots_killed_on_timeout_` (and the catalogued
//     `reactor.otel.snapshots_killed_on_timeout` Counter) increment by
//     exactly N for N un-finalized survivors.

#include "test_framework.h"
#include "dispatcher.h"
#include "observability/counter.h"
#include "observability/meter_provider.h"
#include "observability/metrics_catalog.h"
#include "observability/metrics_snapshot.h"
#include "observability/observability_config.h"
#include "observability/observability_manager.h"
#include "observability/observability_snapshot.h"
#include "observability/resource.h"
#include "observability/sampler.h"
#include "observability/span_processor.h"

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

namespace ObservabilityKillMarshalTests {

using OBSERVABILITY_NAMESPACE::NoopSpanProcessor;
using OBSERVABILITY_NAMESPACE::ObservabilityConfig;
using OBSERVABILITY_NAMESPACE::ObservabilityManager;
using OBSERVABILITY_NAMESPACE::ObservabilitySnapshot;
using OBSERVABILITY_NAMESPACE::RandomSource;
using OBSERVABILITY_NAMESPACE::Resource;

namespace {

std::shared_ptr<ObservabilityManager> MakeManager() {
    ObservabilityConfig cfg;
    cfg.enabled = true;
    cfg.metrics.enabled = true;
    cfg.resource.service_name = "obs-kill-marshal-test";
    return ObservabilityManager::Create(
        std::move(cfg),
        std::make_shared<Resource>(),
        std::make_shared<NoopSpanProcessor>(),
        std::make_shared<RandomSource>(0xCAFE0420ULL));
}

double KillCounterValue(ObservabilityManager& m) {
    auto snap = m.meter_provider()->Snapshot();
    double total = 0;
    for (const auto& inst : snap.instruments) {
        if (inst.name == "reactor.otel.snapshots_killed_on_timeout") {
            for (const auto& p : inst.counter_points) {
                total += p.value;
            }
        }
    }
    return total;
}

}  // namespace

inline void TestKillMarshalInlinePathStaysZero() {
    std::cout << "\n[TEST] KillMarshal: snapshot with no owning_dispatcher → "
              << "inline kill leaves counter at zero" << std::endl;
    try {
        auto m = MakeManager();
        bool zero_before = m->kill_marshals_in_flight() == 0;

        // No owning_dispatcher → kill path runs inline; the marshal
        // counter never moves.
        auto snap = std::make_shared<ObservabilitySnapshot>();
        m->RegisterLiveSnapshot(snap);
        m->KillOutstandingSnapshots(std::chrono::milliseconds(0));

        bool zero_after = m->kill_marshals_in_flight() == 0;
        bool finalized = snap->finalized.load();
        bool pass = zero_before && zero_after && finalized;
        std::string err;
        if (!zero_before) err = "counter non-zero before kill";
        else if (!zero_after) err = "counter non-zero after inline kill";
        else if (!finalized) err = "snapshot not finalized";
        TestFramework::RecordTest(
            "KillMarshal: no owning_dispatcher → inline kill, counter stays 0",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "KillMarshal: no owning_dispatcher → inline kill, counter stays 0",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

inline void TestConcurrentKillAndFinalizeRespectCASGate() {
    std::cout << "\n[TEST] KillMarshal: concurrent kill + finalize"
              << " resolved by CAS gate" << std::endl;
    try {
        auto m = MakeManager();
        constexpr int N = 256;
        std::vector<std::shared_ptr<ObservabilitySnapshot>> snaps;
        snaps.reserve(N);
        for (int i = 0; i < N; ++i) {
            auto s = std::make_shared<ObservabilitySnapshot>();
            m->RegisterLiveSnapshot(s);
            snaps.push_back(std::move(s));
        }

        // Multiple finalizer threads racing the single kill thread.
        std::atomic<int> finalize_winners{0};
        std::vector<std::thread> threads;
        for (int t = 0; t < 4; ++t) {
            threads.emplace_back([&, t] {
                for (auto& s : snaps) {
                    if (m->FinalizeFromSnapshot(*s, 200 + t, 0, "")) {
                        finalize_winners.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            });
        }
        threads.emplace_back([&] {
            m->KillOutstandingSnapshots(std::chrono::milliseconds(0));
        });
        for (auto& th : threads) th.join();

        // Every snapshot must have been finalized exactly once across
        // ALL racers — finalize_winners + kill = total finalized count.
        int finalized_total = 0;
        for (auto& s : snaps) if (s->finalized.load()) ++finalized_total;
        bool drained = m->inflight_finalizations() == 0;
        bool exactly_n_finalized = finalized_total == N;

        bool pass = drained && exactly_n_finalized;
        std::string err;
        if (!exactly_n_finalized) err = "finalized=" + std::to_string(finalized_total) +
                                          " expected=" + std::to_string(N);
        else if (!drained) err = "inflight_finalizations not zero";
        TestFramework::RecordTest(
            "KillMarshal: concurrent kill + finalize CAS resolves cleanly",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "KillMarshal: concurrent kill + finalize CAS resolves cleanly",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

inline void TestKillCounterIncrementsByN() {
    std::cout << "\n[TEST] KillMarshal: kill counter increments by N for survivors"
              << std::endl;
    try {
        auto m = MakeManager();
        const double pre = KillCounterValue(*m);

        constexpr int N = 8;
        std::vector<std::shared_ptr<ObservabilitySnapshot>> snaps;
        for (int i = 0; i < N; ++i) {
            auto s = std::make_shared<ObservabilitySnapshot>();
            m->RegisterLiveSnapshot(s);
            snaps.push_back(std::move(s));
        }
        m->KillOutstandingSnapshots(std::chrono::milliseconds(0));

        const double post = KillCounterValue(*m);
        const double delta = post - pre;
        bool pass = delta == static_cast<double>(N);
        std::string err;
        if (!pass) err = "delta=" + std::to_string(delta) +
                          " expected=" + std::to_string(N);
        TestFramework::RecordTest(
            "KillMarshal: catalogued counter bumps once per survivor",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "KillMarshal: catalogued counter bumps once per survivor",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

inline void TestKillMarshalCaseBCounterTransitions() {
    // Cross-thread marshal: the kill loop runs on the stopper thread
    // (test main thread) but the snapshot's owning_dispatcher is a
    // separate Dispatcher instance whose RunEventLoop has NOT started
    // yet. EnQueueDelayed(0ms) pushes the closure onto task_que_ and
    // wakes the dispatcher; the bump is synchronous, the decrement
    // happens once the closure runs.
    //
    // We deliberately initialise the dispatcher but defer RunEventLoop
    // so KillOutstandingSnapshots returns with closures still queued —
    // that's the only race-free way to observe a non-zero peak.
    std::cout << "\n[TEST] KillMarshal: CASE B counter rises during marshal "
              << "and returns to zero after drain" << std::endl;
    try {
        auto m = MakeManager();
        auto dispatcher = std::make_shared<Dispatcher>();
        dispatcher->Init();

        constexpr int N = 4;
        std::vector<std::shared_ptr<ObservabilitySnapshot>> snaps;
        snaps.reserve(N);
        for (int i = 0; i < N; ++i) {
            auto s = std::make_shared<ObservabilitySnapshot>();
            s->owning_dispatcher = dispatcher.get();
            m->RegisterLiveSnapshot(s);
            snaps.push_back(std::move(s));
        }

        // RunEventLoop has not started yet — thread_id_ is the default
        // id{}, so is_on_loop_thread() returns false from the main
        // thread and the cross-thread marshal branch fires.
        m->KillOutstandingSnapshots(std::chrono::milliseconds(0));

        const int64_t peak = m->kill_marshals_in_flight();
        const bool peak_seen = peak == static_cast<int64_t>(N);

        // None of the queued closures has run yet — every snapshot's
        // CAS remains un-finalized.
        int finalized_before_loop = 0;
        for (auto& s : snaps) if (s->finalized.load()) ++finalized_before_loop;

        // Start the dispatcher loop on a worker thread. The closures
        // drain (kill body runs inline on the dispatcher thread,
        // RAII guard decrements + cv.notify_all).
        std::thread loop_thread([&dispatcher]() {
            try {
                dispatcher->RunEventLoop();
            } catch (...) {
                // Suppress — RunEventLoop() exit on StopEventLoop().
            }
        });

        // Wait for the counter to drain. Use the manager's own cv so
        // the wait is signalled by the decrement path, not by polling.
        {
            std::unique_lock<std::mutex> lk(m->finalizers_done_mtx());
            m->finalizers_done_cv().wait_for(
                lk,
                std::chrono::seconds(5),
                [&]() {
                    return m->kill_marshals_in_flight() == 0;
                });
        }

        const int64_t after_drain = m->kill_marshals_in_flight();
        int finalized_after_loop = 0;
        for (auto& s : snaps) if (s->finalized.load()) ++finalized_after_loop;

        dispatcher->StopEventLoop();
        loop_thread.join();

        bool pass = peak_seen &&
                    finalized_before_loop == 0 &&
                    after_drain == 0 &&
                    finalized_after_loop == N;
        std::string err;
        if (!peak_seen) {
            err = "peak=" + std::to_string(peak) +
                  " expected=" + std::to_string(N);
        } else if (finalized_before_loop != 0) {
            err = "snapshot finalized before dispatcher ran (race)";
        } else if (after_drain != 0) {
            err = "counter not zero after drain: " +
                  std::to_string(after_drain);
        } else if (finalized_after_loop != N) {
            err = "finalized after drain=" +
                  std::to_string(finalized_after_loop) +
                  " expected=" + std::to_string(N);
        }
        TestFramework::RecordTest(
            "KillMarshal: CASE B counter rises and drains across dispatcher boundary",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "KillMarshal: CASE B counter rises and drains across dispatcher boundary",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

inline void TestKillMarshalEnQueueDelayedRefusal() {
    // Owning dispatcher already stopped before the kill loop sees it —
    // EnQueueDelayed returns false; the rollback path inlines the kill.
    // Final counter must be 0 AND every snapshot must be finalized.
    std::cout << "\n[TEST] KillMarshal: EnQueueDelayed refusal falls back to "
              << "inline kill, counter stays zero" << std::endl;
    try {
        auto m = MakeManager();
        auto dispatcher = std::make_shared<Dispatcher>();
        dispatcher->Init();
        // Stop immediately — was_stopped_ becomes true so every
        // EnQueueDelayed call from the kill loop will refuse.
        dispatcher->StopEventLoop();

        constexpr int N = 3;
        std::vector<std::shared_ptr<ObservabilitySnapshot>> snaps;
        for (int i = 0; i < N; ++i) {
            auto s = std::make_shared<ObservabilitySnapshot>();
            s->owning_dispatcher = dispatcher.get();
            m->RegisterLiveSnapshot(s);
            snaps.push_back(std::move(s));
        }

        m->KillOutstandingSnapshots(std::chrono::milliseconds(0));

        const int64_t after = m->kill_marshals_in_flight();
        int finalized_total = 0;
        for (auto& s : snaps) if (s->finalized.load()) ++finalized_total;

        bool pass = after == 0 && finalized_total == N;
        std::string err;
        if (after != 0) {
            err = "counter not zero after refusal rollback: " +
                  std::to_string(after);
        } else if (finalized_total != N) {
            err = "finalized=" + std::to_string(finalized_total) +
                  " expected=" + std::to_string(N) +
                  " (fallback inline kill did not run)";
        }
        TestFramework::RecordTest(
            "KillMarshal: EnQueueDelayed refusal rolls back bump and runs inline",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "KillMarshal: EnQueueDelayed refusal rolls back bump and runs inline",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

inline void RunAllTests() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "KILL-LOOP INVARIANT TESTS" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    TestKillMarshalInlinePathStaysZero();
    TestConcurrentKillAndFinalizeRespectCASGate();
    TestKillCounterIncrementsByN();
    TestKillMarshalCaseBCounterTransitions();
    TestKillMarshalEnQueueDelayedRefusal();
}

}  // namespace ObservabilityKillMarshalTests
