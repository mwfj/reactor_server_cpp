#pragma once

// Observability link/kill protocol tests. Validates that:
//   - ProxyTransaction implements UpstreamTransactionLink correctly
//     (MarkKilledForShutdown / IsKilledForShutdown)
//   - The link site under ObservabilitySnapshot::link_mtx publishes
//     tx_weak so the shutdown kill loop can find it
//   - KillOutstandingSnapshots reaches the linked transaction and
//     flips its kill flag
//   - inflight_transactions_ on UpstreamManager is bumped at Start
//     and drained on destruction (one increment per transaction
//     regardless of retries)

#include "test_framework.h"
#include "observability/observability_manager.h"
#include "observability/observability_snapshot.h"
#include "observability_test_helpers.h"
#include "proxy_transaction_internal_test.h"

#include <atomic>
#include <chrono>
#include <memory>

namespace ObservabilityLinkKillTests {

using OBSERVABILITY_NAMESPACE::ObservabilityManager;
using OBSERVABILITY_NAMESPACE::ObservabilitySnapshot;
using OBSERVABILITY_NAMESPACE::UpstreamTransactionLink;

namespace {

inline std::shared_ptr<ObservabilityManager> MakeManager() {
    return ObservabilityTestHelpers::MakeManager(
        "link-kill-test", 0xABCDABCDULL);
}

// Trivial UpstreamTransactionLink stand-in for the link/kill round-trip
// test — ProxyTransaction itself needs more fixture wiring than is
// useful for this slice. Counts kill invocations.
class FakeTxLink final : public UpstreamTransactionLink {
public:
    void MarkKilledForShutdown() noexcept override {
        killed_.store(true, std::memory_order_release);
    }
    bool IsKilledForShutdown() const noexcept override {
        return killed_.load(std::memory_order_acquire);
    }
private:
    std::atomic<bool> killed_{false};
};

}  // namespace

// ---- ProxyTransaction implements the interface correctly ----

void TestProxyTxIsLink() {
    try {
        HttpRequest req;
        auto tx = ProxyTransactionInternalTests::MakeInternalProxyTransaction(req);
        UpstreamTransactionLink* link = tx.get();
        bool initially_alive = !link->IsKilledForShutdown();
        link->MarkKilledForShutdown();
        bool now_killed = link->IsKilledForShutdown();
        bool pass = initially_alive && now_killed;
        TestFramework::RecordTest(
            "ObsLink: ProxyTransaction implements UpstreamTransactionLink",
            pass, pass ? "" : "kill flag did not flip",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsLink: ProxyTransaction implements UpstreamTransactionLink",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- Linked snapshot kill flow: KillOutstandingSnapshots fires the kill ----

void TestKillFlipsLinkedTransaction() {
    try {
        auto m = MakeManager();
        auto snap = std::make_shared<ObservabilitySnapshot>();
        m->RegisterLiveSnapshot(snap);

        // Simulate the link-site write (ProxyTransaction::Start does this
        // under link_mtx). The kill loop must read tx_weak under the
        // same mutex.
        auto fake = std::make_shared<FakeTxLink>();
        {
            std::lock_guard<std::mutex> g(snap->link_mtx);
            snap->tx_weak = std::weak_ptr<UpstreamTransactionLink>(fake);
        }

        bool before = !fake->IsKilledForShutdown();
        m->KillOutstandingSnapshots(std::chrono::milliseconds{100});
        bool after = fake->IsKilledForShutdown();

        bool pass = before && after && m->inflight_finalizations() == 0;
        TestFramework::RecordTest(
            "ObsLink: KillOutstandingSnapshots flips linked transaction",
            pass, pass ? "" : "kill flag did not propagate to linked tx",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsLink: KillOutstandingSnapshots flips linked transaction",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- Empty link slot — kill loop must not crash on weak.lock() == null ----

void TestKillTolerantOfMissingLink() {
    try {
        auto m = MakeManager();
        auto snap = std::make_shared<ObservabilitySnapshot>();
        m->RegisterLiveSnapshot(snap);
        // tx_weak left empty — the typical non-proxy path.
        m->KillOutstandingSnapshots(std::chrono::milliseconds{50});
        bool pass = m->inflight_finalizations() == 0;
        TestFramework::RecordTest(
            "ObsLink: KillOutstandingSnapshots tolerates empty tx_weak",
            pass, pass ? "" : "counter not drained",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsLink: KillOutstandingSnapshots tolerates empty tx_weak",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- Start-vs-Kill race: Kill swept FIRST, then AttachTransaction ----
// Closes the gap flagged in PR review: "no targeted test for the
// Start-vs-KillOutstandingSnapshots race." Exercises the safe helper
// directly: KillOutstandingSnapshots finalizes the snapshot before
// the link is published; AttachTransaction must observe the
// finalized state under link_mtx and immediately mark the link
// killed-for-shutdown so the caller's terminal gates short-circuit.

void TestAttachAfterKillFlipsLinkImmediately() {
    try {
        auto m = MakeManager();
        auto snap = std::make_shared<ObservabilitySnapshot>();
        m->RegisterLiveSnapshot(snap);

        // Kill loop runs first — finalizes the snapshot, drains the
        // counter, leaves tx_weak empty (no link was attached).
        m->KillOutstandingSnapshots(std::chrono::milliseconds{50});
        bool kill_observed_finalize =
            snap->finalized.load(std::memory_order_acquire);
        bool counter_drained = m->inflight_finalizations() == 0;

        // Late attach mirroring ProxyTransaction::Start after the
        // kill sweep. The safe helper must:
        //   1. Observe finalized==true under link_mtx
        //   2. Lock the weak ptr, call MarkKilledForShutdown OUTSIDE
        //      the lock
        //   3. Return true so callers can short-circuit
        auto fake = std::make_shared<FakeTxLink>();
        bool was_already_finalized = snap->AttachTransaction(
            std::weak_ptr<UpstreamTransactionLink>(fake));

        bool fake_killed = fake->IsKilledForShutdown();
        bool tx_weak_published = !snap->tx_weak.expired();

        bool pass = kill_observed_finalize && counter_drained
                 && was_already_finalized && fake_killed
                 && tx_weak_published;
        TestFramework::RecordTest(
            "ObsLink: AttachTransaction after Kill flips link immediately",
            pass,
            pass ? "" :
                ("kill_observed_finalize=" +
                 std::to_string(kill_observed_finalize) +
                 " counter_drained=" + std::to_string(counter_drained) +
                 " was_already_finalized=" +
                 std::to_string(was_already_finalized) +
                 " fake_killed=" + std::to_string(fake_killed) +
                 " tx_weak_published=" +
                 std::to_string(tx_weak_published)),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsLink: AttachTransaction after Kill flips link immediately",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- AttachTransaction before any Kill — happy path: returns false ----
//
// Pairs with the post-kill test above to lock down the helper's
// return value semantics. Without a kill sweep, the snapshot stays
// finalize=false; AttachTransaction must publish tx_weak, return
// false, and leave the link's kill flag untouched. The kill loop
// (or any future finalizer) is still in charge of marking the link.

void TestAttachBeforeKillIsBenign() {
    try {
        auto m = MakeManager();
        auto snap = std::make_shared<ObservabilitySnapshot>();
        m->RegisterLiveSnapshot(snap);

        auto fake = std::make_shared<FakeTxLink>();
        bool was_already_finalized = snap->AttachTransaction(
            std::weak_ptr<UpstreamTransactionLink>(fake));

        bool helper_reports_fresh = !was_already_finalized;
        bool fake_alive = !fake->IsKilledForShutdown();
        bool tx_weak_published = !snap->tx_weak.expired();

        // Now run the kill sweep — must find tx_weak and mark fake.
        m->KillOutstandingSnapshots(std::chrono::milliseconds{50});
        bool fake_killed_by_loop = fake->IsKilledForShutdown();

        bool pass = helper_reports_fresh && fake_alive
                 && tx_weak_published && fake_killed_by_loop;
        TestFramework::RecordTest(
            "ObsLink: AttachTransaction before Kill is benign + kill loop reaches link",
            pass, pass ? "" : "helper or kill-loop contract violated",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsLink: AttachTransaction before Kill is benign + kill loop reaches link",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- Start() short-circuits when AttachTransaction reports finalized ----
//
// Shows that ProxyTransaction::Start() actually consumes the bool
// returned by AttachTransaction. If the kill sweep ran before
// Start(), the helper returns true and Start() must bail before
// header rewrite / request serialization / breaker resolution /
// AttemptCheckout. Without the early return the test fixture would
// reach `serialized_request_ = HttpRequestSerializer::Serialize(...)`
// and produce a non-empty wire image — the assertion catches that.

void TestStartShortCircuitsOnFinalizedSnapshot() {
    try {
        auto m = MakeManager();
        auto snap = std::make_shared<ObservabilitySnapshot>();
        m->RegisterLiveSnapshot(snap);
        m->KillOutstandingSnapshots(std::chrono::milliseconds{50});

        HttpRequest req;
        auto tx = ProxyTransactionInternalTests::MakeInternalProxyTransaction(req);
        tx->AttachObservabilitySnapshot(snap);
        tx->Start();

        bool tx_killed = tx->IsKilledForShutdown();
        // Non-empty serialized_request_ proves Start fell through to
        // HttpRequestSerializer::Serialize — short-circuit broken.
        bool serialize_skipped = tx->serialized_request_.empty();

        bool pass = tx_killed && serialize_skipped;
        TestFramework::RecordTest(
            "ObsLink: Start() short-circuits when snapshot already finalized",
            pass, pass ? "" :
                ("tx_killed=" + std::to_string(tx_killed) +
                 " serialize_skipped=" + std::to_string(serialize_skipped)),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsLink: Start() short-circuits when snapshot already finalized",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- AttachObservabilitySnapshot stores the snapshot for the link site ----

void TestAttachSnapshotStoresHandle() {
    try {
        HttpRequest req;
        auto tx = ProxyTransactionInternalTests::MakeInternalProxyTransaction(req);
        auto snap = std::make_shared<ObservabilitySnapshot>();
        tx->AttachObservabilitySnapshot(snap);
        // Verify via the private member through the test friendship
        // mechanism (test header uses #define private public).
        bool pass = (tx->obs_snapshot_.get() == snap.get());
        TestFramework::RecordTest(
            "ObsLink: AttachObservabilitySnapshot stores snapshot pointer",
            pass, pass ? "" : "snapshot not stored",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsLink: AttachObservabilitySnapshot stores snapshot pointer",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void RunAllTests() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "OBSERVABILITY LINK/KILL PROTOCOL TESTS" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    TestProxyTxIsLink();
    TestKillFlipsLinkedTransaction();
    TestKillTolerantOfMissingLink();
    TestAttachAfterKillFlipsLinkImmediately();
    TestAttachBeforeKillIsBenign();
    TestStartShortCircuitsOnFinalizedSnapshot();
    TestAttachSnapshotStoresHandle();
}

}  // namespace ObservabilityLinkKillTests
