#pragma once

// Cross-cutting concurrency invariants for the observability manager
// + metric pipeline that no single per-component suite can validate
// alone (concurrent finalize CAS, register/finalize churn, kill loop
// tolerance, concurrent counter add, concurrent reload + read).

#include "test_framework.h"
#include "observability/counter.h"
#include "observability/meter_provider.h"
#include "observability/metric_label_registry.h"
#include "observability/observability_config.h"
#include "observability/observability_manager.h"
#include "observability/observability_snapshot.h"
#include "observability/resource.h"
#include "observability_test_helpers.h"

#include <atomic>
#include <chrono>
#include <memory>
#include <thread>
#include <vector>

namespace ObservabilityStressTests {

using OBSERVABILITY_NAMESPACE::Counter;
using OBSERVABILITY_NAMESPACE::CounterPoint;
using OBSERVABILITY_NAMESPACE::InstrumentKind;
using OBSERVABILITY_NAMESPACE::MeterProvider;
using OBSERVABILITY_NAMESPACE::MetricLabelRegistry;
using OBSERVABILITY_NAMESPACE::ObservabilityConfig;
using OBSERVABILITY_NAMESPACE::ObservabilityManager;
using OBSERVABILITY_NAMESPACE::ObservabilitySnapshot;
using OBSERVABILITY_NAMESPACE::Resource;

namespace {

inline std::shared_ptr<ObservabilityManager> MakeManager() {
    return ObservabilityTestHelpers::MakeManager("stress", 0xCAFEBABEULL);
}

}  // namespace

// ---- Race: concurrent finalize CAS — exactly ONE wins per snapshot ----
//
// 32 threads pile onto FinalizeFromSnapshot for the same snapshot
// simultaneously. The CAS-from-false-to-true gate must ensure exactly
// one thread wins; everyone else must observe a no-op (returns false)
// and the inflight_finalizations counter must drop by exactly one per
// snapshot regardless of thread count.

void TestConcurrentFinalizeCASExactlyOneWinner() {
    try {
        auto m = MakeManager();
        constexpr int kSnapshots = 16;
        constexpr int kThreadsPerSnap = 8;

        std::vector<std::shared_ptr<ObservabilitySnapshot>> snaps;
        for (int i = 0; i < kSnapshots; ++i) {
            auto s = std::make_shared<ObservabilitySnapshot>();
            m->RegisterLiveSnapshot(s);
            snaps.push_back(std::move(s));
        }
        bool start_count_ok =
            m->inflight_finalizations() == kSnapshots;

        std::atomic<int> wins{0};
        std::vector<std::thread> threads;
        threads.reserve(kSnapshots * kThreadsPerSnap);
        for (auto& s : snaps) {
            for (int t = 0; t < kThreadsPerSnap; ++t) {
                threads.emplace_back([&m, s, &wins]() {
                    if (m->FinalizeFromSnapshot(*s, 200, 1, "")) {
                        wins.fetch_add(1, std::memory_order_relaxed);
                    }
                });
            }
        }
        for (auto& t : threads) t.join();

        bool one_winner_per_snap =
            wins.load(std::memory_order_relaxed) == kSnapshots;
        bool counter_drained = m->inflight_finalizations() == 0;
        bool pass = start_count_ok && one_winner_per_snap && counter_drained;
        TestFramework::RecordTest(
            "ObsStress: concurrent finalize CAS — exactly one winner per snapshot",
            pass, pass ? "" :
                "wins=" + std::to_string(wins.load()) +
                " expected=" + std::to_string(kSnapshots) +
                " inflight=" + std::to_string(m->inflight_finalizations()),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsStress: concurrent finalize CAS — exactly one winner per snapshot",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- Race: register / finalize churn under concurrent load ----
//
// 8 producer threads register snapshots; 8 finalizer threads drain them.
// After everything joins, inflight_finalizations MUST equal zero —
// proves no register/finalize pair is ever lost or double-counted.

void TestRegisterFinalizeChurnDrains() {
    try {
        auto m = MakeManager();
        constexpr int kProducers = 8;
        constexpr int kPerProducer = 256;
        constexpr int kConsumers = 8;

        std::vector<std::shared_ptr<ObservabilitySnapshot>> queue;
        std::mutex q_mtx;
        std::atomic<int> produced{0};
        std::atomic<int> consumed{0};
        std::atomic<bool> done{false};

        std::vector<std::thread> producers;
        for (int p = 0; p < kProducers; ++p) {
            producers.emplace_back([&]() {
                for (int i = 0; i < kPerProducer; ++i) {
                    auto s = std::make_shared<ObservabilitySnapshot>();
                    m->RegisterLiveSnapshot(s);
                    {
                        std::lock_guard<std::mutex> g(q_mtx);
                        queue.push_back(std::move(s));
                    }
                    produced.fetch_add(1, std::memory_order_relaxed);
                }
            });
        }

        std::vector<std::thread> consumers;
        for (int c = 0; c < kConsumers; ++c) {
            consumers.emplace_back([&]() {
                while (!done.load(std::memory_order_acquire)
                       || consumed.load(std::memory_order_acquire) <
                           produced.load(std::memory_order_acquire)) {
                    std::shared_ptr<ObservabilitySnapshot> s;
                    {
                        std::lock_guard<std::mutex> g(q_mtx);
                        if (!queue.empty()) {
                            s = std::move(queue.back());
                            queue.pop_back();
                        }
                    }
                    if (s) {
                        m->FinalizeFromSnapshot(*s, 200, 0, "");
                        consumed.fetch_add(1, std::memory_order_relaxed);
                    } else {
                        std::this_thread::yield();
                    }
                }
            });
        }

        for (auto& t : producers) t.join();
        done.store(true, std::memory_order_release);
        for (auto& t : consumers) t.join();

        // Drain anything we missed (race: producer finished after the
        // consumer's last queue probe).
        {
            std::lock_guard<std::mutex> g(q_mtx);
            for (auto& s : queue) {
                m->FinalizeFromSnapshot(*s, 200, 0, "");
            }
            queue.clear();
        }

        bool pass = m->inflight_finalizations() == 0
                  && produced == kProducers * kPerProducer;
        TestFramework::RecordTest(
            "ObsStress: register/finalize churn drains counter to zero",
            pass, pass ? "" :
                "inflight=" + std::to_string(m->inflight_finalizations()),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsStress: register/finalize churn drains counter to zero",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- Lifecycle: kill loop drains snapshots that survived to shutdown ----
//
// The documented Register/Finalize-or-Kill contract: the snapshot's
// strong ref MUST outlive the call to KillOutstandingSnapshots so the
// kill path can CAS-win and decrement. This test verifies that path
// works under the documented contract — the kill loop locks the
// weak_ptr, CAS-wins, and drains the counter.

void TestKillDrainsSurvivingSnapshots() {
    try {
        auto m = MakeManager();
        // Strong ref retained until AFTER KillOutstandingSnapshots
        // (matches the runtime where HttpServer::Stop holds the
        // server-side ObservabilitySnapshot via the request slot).
        auto s1 = std::make_shared<ObservabilitySnapshot>();
        auto s2 = std::make_shared<ObservabilitySnapshot>();
        m->RegisterLiveSnapshot(s1);
        m->RegisterLiveSnapshot(s2);

        m->KillOutstandingSnapshots(std::chrono::milliseconds{50});

        bool pass = m->inflight_finalizations() == 0;
        TestFramework::RecordTest(
            "ObsStress: kill loop drains snapshots surviving to shutdown",
            pass, pass ? "" :
                "inflight=" + std::to_string(m->inflight_finalizations()),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsStress: kill loop drains snapshots surviving to shutdown",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- Race: concurrent Counter::Add across threads with sharding ----
//
// 16 threads slamming Counter::Add into a small set of LabelSets must
// produce a consistent post-snapshot total. Validates the
// SeriesMap shared_lock + per-shard read/write split under contention.

void TestConcurrentCounterAddTotalsConsistent() {
    try {
        auto resource = std::make_shared<Resource>();
        MeterProvider mp(resource, /*shard_count=*/4);
        auto* meter = mp.GetMeter("stress");
        MetricLabelRegistry::Catalog cat;
        cat.allowed_keys = {"k"};
        auto* counter = meter->GetCounter("ops", "", "", cat);

        constexpr int kThreads = 16;
        constexpr int kPerThread = 1000;

        std::vector<std::thread> threads;
        for (int t = 0; t < kThreads; ++t) {
            threads.emplace_back([counter]() {
                for (int i = 0; i < kPerThread; ++i) {
                    // Two distinct series sharing the same instrument
                    // — exercises the per-shard write path on both.
                    counter->Add(1, {{"k", (i & 1) ? "a" : "b"}});
                }
            });
        }
        for (auto& t : threads) t.join();

        auto pts = counter->SnapshotPoints();
        double total = 0;
        for (const auto& p : pts) total += p.value;

        bool pass = total == double(kThreads * kPerThread)
                  && pts.size() == 2;
        TestFramework::RecordTest(
            "ObsStress: concurrent Counter::Add totals are consistent",
            pass, pass ? "" :
                "total=" + std::to_string(total) +
                " series=" + std::to_string(pts.size()),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsStress: concurrent Counter::Add totals are consistent",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- Race: concurrent Reload + GetTracer must not crash ----
//
// SIGHUP-style: ONE writer thread keeps calling Reload while four
// reader threads fetch tracers / record metrics. Tests the live-flag
// atomic publication and the MeterProvider's reload synchronization
// against concurrent reads. NOT a multi-writer Reload race — Reload
// is documented as serialised by HttpServer::reload_mtx_; that
// invariant is not exercised here.

void TestSingleReloaderVsConcurrentReadersDoesNotCrash() {
    try {
        auto m = MakeManager();
        std::atomic<bool> stop{false};

        std::thread reloader([&]() {
            ObservabilityConfig cfg;
            cfg.enabled = true;
            for (int i = 0; i < 200 && !stop.load(); ++i) {
                cfg.metrics.enabled = (i & 1) != 0;
                cfg.metrics.prometheus.include_target_info = (i & 2) != 0;
                m->Reload(cfg);
                std::this_thread::yield();
            }
        });

        std::vector<std::thread> readers;
        for (int t = 0; t < 4; ++t) {
            readers.emplace_back([&]() {
                while (!stop.load()) {
                    (void)m->MetricsEnabled();
                    (void)m->IncludeTargetInfo();
                    (void)m->TracesEnabled();
                    (void)m->meter_provider();
                }
            });
        }

        std::this_thread::sleep_for(std::chrono::milliseconds{100});
        stop.store(true);
        reloader.join();
        for (auto& t : readers) t.join();

        TestFramework::RecordTest(
            "ObsStress: concurrent Reload+reads don't crash",
            true, "",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsStress: concurrent Reload+reads don't crash",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- Lifecycle: many manager-create/destroy cycles ----
//
// Detect pre-existing leaks / dangling threads in the manager
// destructor. Spawning + tearing down 64 managers in a single thread
// must complete without ASAN flags or hanging threads.

void TestManyManagerCreateDestroyCycles() {
    try {
        for (int i = 0; i < 64; ++i) {
            auto m = MakeManager();
            // Register + finalize a snapshot per cycle.
            auto s = std::make_shared<ObservabilitySnapshot>();
            m->RegisterLiveSnapshot(s);
            m->FinalizeFromSnapshot(*s, 200, 0, "");
            m->BeginShutdown(std::chrono::milliseconds{20});
        }
        TestFramework::RecordTest(
            "ObsStress: 64x manager create/destroy cycles",
            true, "",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsStress: 64x manager create/destroy cycles",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void RunAllTests() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "OBSERVABILITY STRESS / LIFECYCLE / RACE TESTS" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    TestConcurrentFinalizeCASExactlyOneWinner();
    TestRegisterFinalizeChurnDrains();
    TestKillDrainsSurvivingSnapshots();
    TestConcurrentCounterAddTotalsConsistent();
    TestSingleReloaderVsConcurrentReadersDoesNotCrash();
    TestManyManagerCreateDestroyCycles();
}

}  // namespace ObservabilityStressTests
