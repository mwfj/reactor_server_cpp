#pragma once

// Shutdown drain tests. Exercises WaitForAllAsyncDrain indirectly
// through the public counters on UpstreamManager and
// ObservabilityManager, plus KillOutstandingSnapshots' behavior on
// snapshots that survive the drain.

#include "test_framework.h"
#include "observability/observability_manager.h"
#include "observability/observability_snapshot.h"
#include "observability_test_helpers.h"

#include <chrono>
#include <memory>

namespace ObservabilityShutdownTests {

using OBSERVABILITY_NAMESPACE::ObservabilityManager;
using OBSERVABILITY_NAMESPACE::ObservabilitySnapshot;

namespace {
inline std::shared_ptr<ObservabilityManager> MakeManager() {
    return ObservabilityTestHelpers::MakeManager(
        "shutdown-test", 0xDEADBEEFULL);
}
}  // namespace

// inflight_finalizations starts at 0 with no live snapshots.
void TestNoLiveSnapshotsZeroCounter() {
    try {
        auto m = MakeManager();
        bool pass = m->inflight_finalizations() == 0;
        TestFramework::RecordTest(
            "ObsShutdown: zero inflight when no snapshots registered",
            pass, pass ? "" : "non-zero counter at boot",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsShutdown: zero inflight when no snapshots registered",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Registering a snapshot bumps inflight_finalizations; finalize-win
// drops it back to zero — the post-finalize state is what the
// shutdown drain waits for.
void TestRegisterFinalizeRoundTrip() {
    try {
        auto m = MakeManager();
        auto snap = std::make_shared<ObservabilitySnapshot>();
        m->RegisterLiveSnapshot(snap);
        bool incremented = m->inflight_finalizations() == 1;

        bool won = m->FinalizeFromSnapshot(*snap, 200, 7, "");
        bool decremented = m->inflight_finalizations() == 0;

        bool pass = incremented && won && decremented;
        TestFramework::RecordTest(
            "ObsShutdown: register→finalize round-trip drains counter",
            pass, pass ? "" : "counter did not drain after finalize",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsShutdown: register→finalize round-trip drains counter",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// KillOutstandingSnapshots forces a finalize on snapshots that
// survived the drain. After kill, the counter must reach zero.
void TestKillDrainsSurvivors() {
    try {
        auto m = MakeManager();
        // Two snapshots that never finalize on their own.
        auto a = std::make_shared<ObservabilitySnapshot>();
        auto b = std::make_shared<ObservabilitySnapshot>();
        m->RegisterLiveSnapshot(a);
        m->RegisterLiveSnapshot(b);
        bool start_two = m->inflight_finalizations() == 2;

        m->KillOutstandingSnapshots(std::chrono::milliseconds{200});

        bool drained_zero = m->inflight_finalizations() == 0;
        bool pass = start_two && drained_zero;
        TestFramework::RecordTest(
            "ObsShutdown: KillOutstandingSnapshots drains counter to zero",
            pass, pass ? "" : "kill did not drain survivors",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsShutdown: KillOutstandingSnapshots drains counter to zero",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// FinalizeFromSnapshot is idempotent — once any path has finalized a
// snapshot, the kill loop must skip it. (The CAS gate is what makes
// it safe to fire the kill loop AFTER protocol-drain may have already
// finalized some snapshots.)
void TestFinalizeIsIdempotent() {
    try {
        auto m = MakeManager();
        auto snap = std::make_shared<ObservabilitySnapshot>();
        m->RegisterLiveSnapshot(snap);

        bool first  = m->FinalizeFromSnapshot(*snap, 200, 1, "");
        bool second = m->FinalizeFromSnapshot(*snap, 500, 99, "x");
        // The second call must lose the CAS.
        bool pass = first && !second && m->inflight_finalizations() == 0;
        TestFramework::RecordTest(
            "ObsShutdown: FinalizeFromSnapshot is idempotent (CAS gate)",
            pass, pass ? "" : "second finalize won the CAS",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsShutdown: FinalizeFromSnapshot is idempotent (CAS gate)",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// BeginShutdown is idempotent and must not crash on a manager with no
// processor / reader workers.
void TestBeginShutdownIdempotent() {
    try {
        auto m = MakeManager();
        m->BeginShutdown(std::chrono::milliseconds{50});
        m->BeginShutdown(std::chrono::milliseconds{50});  // second call
        TestFramework::RecordTest(
            "ObsShutdown: BeginShutdown is idempotent",
            true, "",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsShutdown: BeginShutdown is idempotent",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void RunAllTests() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "OBSERVABILITY SHUTDOWN (PHASE 1c) TESTS" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    TestNoLiveSnapshotsZeroCounter();
    TestRegisterFinalizeRoundTrip();
    TestKillDrainsSurvivors();
    TestFinalizeIsIdempotent();
    TestBeginShutdownIdempotent();
}

}  // namespace ObservabilityShutdownTests
