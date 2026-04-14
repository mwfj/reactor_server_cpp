#pragma once

#include "test_framework.h"
#include "config/server_config.h"
#include "circuit_breaker/circuit_breaker_state.h"
#include "circuit_breaker/circuit_breaker_slice.h"
#include "circuit_breaker/retry_budget.h"
#include "circuit_breaker/circuit_breaker_host.h"
#include "circuit_breaker/circuit_breaker_manager.h"
#include "dispatcher.h"

#include <iostream>
#include <string>
#include <thread>
#include <vector>

// Phase 3 unit tests: RetryBudget, CircuitBreakerHost, CircuitBreakerManager.
//
// These tests exercise the standalone data structures introduced in Phase 3
// without any integration into the request path (that comes in Phase 4).
// Every test constructs the object under test in isolation — no live
// dispatchers, no network I/O. A minimal Dispatcher is instantiated only
// where CircuitBreakerHost::Reload needs one to enqueue per-slice Reload
// calls.
namespace CircuitBreakerPhase3Tests {

using circuit_breaker::CircuitBreakerHost;
using circuit_breaker::CircuitBreakerHostSnapshot;
using circuit_breaker::CircuitBreakerManager;
using circuit_breaker::Decision;
using circuit_breaker::FailureKind;
using circuit_breaker::RetryBudget;
using circuit_breaker::State;

static CircuitBreakerConfig DefaultCbConfig() {
    CircuitBreakerConfig cb;
    cb.enabled = true;
    cb.consecutive_failure_threshold = 5;
    cb.failure_rate_threshold = 50;
    cb.minimum_volume = 20;
    cb.window_seconds = 10;
    cb.permitted_half_open_calls = 3;
    cb.base_open_duration_ms = 5000;
    cb.max_open_duration_ms = 60000;
    cb.retry_budget_percent = 20;
    cb.retry_budget_min_concurrency = 3;
    return cb;
}

// ============================================================================
// RetryBudget tests
// ============================================================================

// Min-concurrency floor: with tiny in_flight, min_concurrency still permits
// the configured floor of concurrent retries (otherwise a 20% budget allows 0
// retries when in_flight < 5 — useless in low-volume services).
void TestRetryBudgetMinConcurrencyFloor() {
    std::cout << "\n[TEST] RetryBudget: min_concurrency floor permits retries..."
              << std::endl;
    try {
        // percent=20, min=3. Even with 0 in_flight, 3 retries allowed.
        RetryBudget rb(20, 3);

        // Without any in_flight, min floor is what gates us.
        bool r1 = rb.TryConsumeRetry();  // 1/3
        bool r2 = rb.TryConsumeRetry();  // 2/3
        bool r3 = rb.TryConsumeRetry();  // 3/3
        bool r4 = rb.TryConsumeRetry();  // over → rejected

        bool pass = r1 && r2 && r3 && !r4 &&
                    rb.RetriesInFlight() == 3 &&
                    rb.RetriesRejected() == 1;

        rb.ReleaseRetry(); rb.ReleaseRetry(); rb.ReleaseRetry();
        pass = pass && rb.RetriesInFlight() == 0;

        TestFramework::RecordTest("RetryBudget min_concurrency floor", pass,
            pass ? "" : "r1=" + std::to_string(r1) +
                        " r2=" + std::to_string(r2) +
                        " r3=" + std::to_string(r3) +
                        " r4=" + std::to_string(r4) +
                        " inflight=" + std::to_string(rb.RetriesInFlight()) +
                        " rejected=" + std::to_string(rb.RetriesRejected()),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RetryBudget min_concurrency floor", false,
            e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Percent-based cap scales with in_flight.
//   percent=20, min=0, in_flight=50 → cap = 10 retries.
void TestRetryBudgetPercentCap() {
    std::cout << "\n[TEST] RetryBudget: percent cap scales with in_flight..."
              << std::endl;
    try {
        RetryBudget rb(20, 0);  // no min floor — pure percent

        // Push in_flight to 50 via guards that we intentionally keep
        // alive. Per the documented API, callers hold TrackInFlight()
        // for BOTH first attempts and retries — but TryConsumeRetry
        // subtracts retries_in_flight from the base so the budget
        // doesn't self-inflate as retries are admitted.
        std::vector<RetryBudget::InFlightGuard> guards;
        for (int i = 0; i < 50; ++i) guards.push_back(rb.TrackInFlight());

        // With 50 non-retry in-flight and 20% budget the first
        // admission is against cap=10, but each admission shrinks the
        // non-retry base by 1. The admission count converges at r
        // where r >= floor((50-r) * 20 / 100). Solving: r = 8. The
        // pre-fix formula (cap computed from raw in_flight) would
        // admit 10, drifting the effective ratio above 20% of
        // originals.
        int admitted = 0;
        for (int i = 0; i < 20; ++i) {
            if (rb.TryConsumeRetry()) ++admitted;
        }
        bool cap_hit = admitted == 8;
        bool rejected_count = rb.RetriesRejected() == 12;

        // Release guards — in_flight drops to 0; future TryConsumeRetry with
        // min=0 and in_flight=0 rejects everything.
        for (auto& g : guards) (void)std::move(g);
        guards.clear();
        for (int i = 0; i < admitted; ++i) rb.ReleaseRetry();

        bool pass = cap_hit && rejected_count && rb.InFlight() == 0 &&
                    rb.RetriesInFlight() == 0;
        TestFramework::RecordTest("RetryBudget percent cap", pass,
            pass ? "" : "admitted=" + std::to_string(admitted) +
                        " rejected=" + std::to_string(rb.RetriesRejected()) +
                        " inflight=" + std::to_string(rb.InFlight()),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RetryBudget percent cap", false,
            e.what(), TestFramework::TestCategory::OTHER);
    }
}

// TrackInFlight guards must be RAII-safe: destroying the guard decrements
// in_flight_; moving the guard transfers ownership; self-move safe.
void TestRetryBudgetInFlightGuardRaii() {
    std::cout << "\n[TEST] RetryBudget: InFlightGuard RAII..." << std::endl;
    try {
        RetryBudget rb(20, 3);

        bool zero_init = rb.InFlight() == 0;
        {
            auto g = rb.TrackInFlight();
            bool one_after_track = rb.InFlight() == 1;

            // Move-construct: counter transfers, original is empty.
            auto g2 = std::move(g);
            bool still_one_after_move = rb.InFlight() == 1;
            // g is now empty, destroying it decrements nothing.
            (void)g;

            // g2 goes out of scope next.
            if (!zero_init || !one_after_track || !still_one_after_move) {
                TestFramework::RecordTest("RetryBudget InFlightGuard RAII",
                    false, "mid-test state wrong",
                    TestFramework::TestCategory::OTHER);
                return;
            }
        }
        bool zero_after_drop = rb.InFlight() == 0;
        TestFramework::RecordTest("RetryBudget InFlightGuard RAII",
            zero_after_drop,
            zero_after_drop ? "" : "in_flight not zero after guard drop",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RetryBudget InFlightGuard RAII",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Reload updates tuning atomically without resetting in-flight counters —
// the admission formula changes, outstanding retries keep running.
void TestRetryBudgetReloadPreservesCounters() {
    std::cout << "\n[TEST] RetryBudget: Reload preserves in-flight..."
              << std::endl;
    try {
        RetryBudget rb(20, 3);
        bool r1 = rb.TryConsumeRetry();  // 1/3

        // Tighten tuning mid-flight.
        rb.Reload(10, 1);

        // Outstanding retry is still tracked.
        bool inflight_preserved = rb.RetriesInFlight() == 1;

        // New tuning applies — min=1, so 1/1 retry allowed max.
        // Current retries_in_flight=1 already, next attempt rejects.
        bool r2 = rb.TryConsumeRetry();

        rb.ReleaseRetry();
        bool cleanup_ok = rb.RetriesInFlight() == 0;

        bool pass = r1 && inflight_preserved && !r2 && cleanup_ok;
        TestFramework::RecordTest("RetryBudget Reload preserves counters", pass,
            pass ? "" : "r1=" + std::to_string(r1) +
                        " inflight_preserved=" + std::to_string(inflight_preserved) +
                        " r2=" + std::to_string(r2) +
                        " cleanup_ok=" + std::to_string(cleanup_ok),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RetryBudget Reload preserves counters",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Clamp guards: negative percent / negative min_concurrency are clamped at
// construction (mirrors ConfigLoader::Validate — programmatic callers that
// bypass validation get safe defaults).
void TestRetryBudgetClampsInvalidTuning() {
    std::cout << "\n[TEST] RetryBudget: clamps invalid tuning..." << std::endl;
    try {
        RetryBudget rb(-50, -10);
        bool clamped = rb.percent() == 0 && rb.min_concurrency() == 0;

        // Over-max percent clamps to 100.
        RetryBudget rb2(500, 5);
        bool over_clamped = rb2.percent() == 100;

        // Reload also clamps.
        rb.Reload(-1, -1);
        bool reload_clamped = rb.percent() == 0 && rb.min_concurrency() == 0;

        bool pass = clamped && over_clamped && reload_clamped;
        TestFramework::RecordTest("RetryBudget clamps invalid tuning", pass,
            pass ? "" :
            "clamped=" + std::to_string(clamped) +
            " over_clamped=" + std::to_string(over_clamped) +
            " reload_clamped=" + std::to_string(reload_clamped),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RetryBudget clamps invalid tuning",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ============================================================================
// CircuitBreakerHost tests
// ============================================================================

// Host creates partition_count slices, GetSlice looks up by index, out-of-
// range returns nullptr (not a crash).
void TestHostCreatesSlicesAndGetSlice() {
    std::cout << "\n[TEST] CircuitBreakerHost: creates slices + GetSlice..."
              << std::endl;
    try {
        auto cb = DefaultCbConfig();
        CircuitBreakerHost host("svc", "10.0.0.1", 8080, 4, cb);

        bool count_ok = host.partition_count() == 4;
        bool slice0 = host.GetSlice(0) != nullptr;
        bool slice3 = host.GetSlice(3) != nullptr;
        bool slice4_null = host.GetSlice(4) == nullptr;  // out of range
        bool slice_big_null = host.GetSlice(100) == nullptr;

        // Retry budget always present.
        bool rb_present = host.GetRetryBudget() != nullptr;

        // Field getters.
        bool fields_ok = host.service_name() == "svc" &&
                        host.host() == "10.0.0.1" &&
                        host.port() == 8080;

        bool pass = count_ok && slice0 && slice3 && slice4_null &&
                    slice_big_null && rb_present && fields_ok;
        TestFramework::RecordTest("CircuitBreakerHost GetSlice", pass, "",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CircuitBreakerHost GetSlice", false,
            e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Host Snapshot aggregates counters across slices and rolls up states.
void TestHostSnapshotAggregates() {
    std::cout << "\n[TEST] CircuitBreakerHost: Snapshot aggregates..."
              << std::endl;
    try {
        auto cb = DefaultCbConfig();
        cb.consecutive_failure_threshold = 2;
        cb.failure_rate_threshold = 100;
        cb.minimum_volume = 1000;
        CircuitBreakerHost host("svc", "h", 80, 3, cb);

        // Trip slice 0 and 2 → 2 open_partitions, 1 closed.
        for (int p : {0, 2}) {
            auto* s = host.GetSlice(p);
            for (int i = 0; i < 2; ++i) {
                auto a = s->TryAcquire();
                s->ReportFailure(FailureKind::RESPONSE_5XX, false, a.generation);
            }
        }

        auto snap = host.Snapshot();

        bool rows_ok = snap.slices.size() == 3;
        bool total_trips = snap.total_trips == 2;
        bool open = snap.open_partitions == 2;
        bool halfopen = snap.half_open_partitions == 0;
        bool svc_ok = snap.service_name == "svc" &&
                      snap.host == "h" && snap.port == 80;

        bool pass = rows_ok && total_trips && open && halfopen && svc_ok;
        TestFramework::RecordTest("CircuitBreakerHost Snapshot aggregates", pass,
            pass ? "" :
            "rows=" + std::to_string(snap.slices.size()) +
            " trips=" + std::to_string(snap.total_trips) +
            " open=" + std::to_string(snap.open_partitions),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CircuitBreakerHost Snapshot aggregates",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Host Reload with mismatched dispatcher count logs error and does nothing.
// Uses an empty dispatcher vector — the mismatch path must NOT dereference.
void TestHostReloadDispatcherMismatchIsSafe() {
    std::cout << "\n[TEST] CircuitBreakerHost: Reload dispatcher mismatch..."
              << std::endl;
    try {
        auto cb = DefaultCbConfig();
        CircuitBreakerHost host("svc", "h", 80, 3, cb);

        auto new_cb = cb;
        new_cb.failure_rate_threshold = 80;

        // Mismatch: 0 dispatchers vs 3 slices. Must not crash, must not
        // apply (retry budget atomics should stay at old values).
        std::vector<std::shared_ptr<Dispatcher>> empty;
        host.Reload(empty, new_cb);

        // Retry budget fields should be unchanged — Reload bailed early.
        bool rb_unchanged =
            host.GetRetryBudget()->percent() == cb.retry_budget_percent &&
            host.GetRetryBudget()->min_concurrency() ==
                cb.retry_budget_min_concurrency;

        TestFramework::RecordTest("CircuitBreakerHost Reload mismatch is safe",
            rb_unchanged,
            rb_unchanged ? "" : "retry budget incorrectly updated on bail",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CircuitBreakerHost Reload mismatch is safe",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ============================================================================
// CircuitBreakerManager tests
// ============================================================================

// Manager builds one host per upstream (regardless of enabled). GetHost
// returns non-null for known names and null for unknown.
void TestManagerGetHostLookup() {
    std::cout << "\n[TEST] CircuitBreakerManager: GetHost lookup..."
              << std::endl;
    try {
        std::vector<UpstreamConfig> upstreams(2);
        upstreams[0].name = "svc-a";
        upstreams[0].host = "10.0.0.1";
        upstreams[0].port = 8080;
        upstreams[0].circuit_breaker = DefaultCbConfig();
        upstreams[1].name = "svc-b";
        upstreams[1].host = "10.0.0.2";
        upstreams[1].port = 9090;
        upstreams[1].circuit_breaker = DefaultCbConfig();
        upstreams[1].circuit_breaker.enabled = false;  // disabled still built

        CircuitBreakerManager mgr(upstreams, 4, {});

        bool count_ok = mgr.host_count() == 2;
        auto* a = mgr.GetHost("svc-a");
        auto* b = mgr.GetHost("svc-b");
        auto* unknown = mgr.GetHost("nope");

        bool a_ok = a != nullptr && a->port() == 8080 &&
                    a->partition_count() == 4;
        bool b_ok = b != nullptr && b->port() == 9090 &&
                    b->partition_count() == 4;
        bool unknown_null = unknown == nullptr;

        bool pass = count_ok && a_ok && b_ok && unknown_null;
        TestFramework::RecordTest("CircuitBreakerManager GetHost lookup", pass,
            pass ? "" :
            "count_ok=" + std::to_string(count_ok) +
            " a=" + std::to_string(a_ok) +
            " b=" + std::to_string(b_ok) +
            " unknown_null=" + std::to_string(unknown_null),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CircuitBreakerManager GetHost lookup",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// SnapshotAll returns one entry per host; topology-preserved Reload logs and
// skips new/removed names without crashing.
void TestManagerSnapshotAllAndReloadSkipsTopologyChanges() {
    std::cout << "\n[TEST] CircuitBreakerManager: SnapshotAll + Reload skips topology..."
              << std::endl;
    try {
        std::vector<UpstreamConfig> upstreams(1);
        upstreams[0].name = "svc-a";
        upstreams[0].host = "h";
        upstreams[0].port = 80;
        upstreams[0].circuit_breaker = DefaultCbConfig();

        CircuitBreakerManager mgr(upstreams, 2, {});

        auto snaps = mgr.SnapshotAll();
        bool one_snapshot = snaps.size() == 1;
        bool snap_name_ok = snaps[0].service_name == "svc-a";

        // Reload with a NEW name + REMOVED existing name — both must log
        // warn and do nothing (topology is restart-only).
        std::vector<UpstreamConfig> new_upstreams(1);
        new_upstreams[0].name = "svc-NEW";
        new_upstreams[0].host = "h";
        new_upstreams[0].port = 80;
        new_upstreams[0].circuit_breaker = DefaultCbConfig();

        mgr.Reload(new_upstreams);

        // Manager must still only know about svc-a (the original).
        bool original_preserved = mgr.GetHost("svc-a") != nullptr;
        bool new_not_added = mgr.GetHost("svc-NEW") == nullptr;
        bool count_stable = mgr.host_count() == 1;

        bool pass = one_snapshot && snap_name_ok && original_preserved &&
                    new_not_added && count_stable;
        TestFramework::RecordTest(
            "CircuitBreakerManager SnapshotAll + topology-skip", pass,
            pass ? "" :
            "one_snap=" + std::to_string(one_snapshot) +
            " name_ok=" + std::to_string(snap_name_ok) +
            " preserved=" + std::to_string(original_preserved) +
            " new_not_added=" + std::to_string(new_not_added) +
            " count=" + std::to_string(mgr.host_count()),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CircuitBreakerManager SnapshotAll + topology-skip",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Empty-name upstream is skipped defensively (ConfigLoader::Validate rejects
// empty names, but manager must not blow up if something slips through).
void TestManagerSkipsEmptyNameUpstream() {
    std::cout << "\n[TEST] CircuitBreakerManager: skips empty-name upstream..."
              << std::endl;
    try {
        std::vector<UpstreamConfig> upstreams(2);
        upstreams[0].name = "";  // defensive — should be skipped
        upstreams[0].host = "h";
        upstreams[0].port = 80;
        upstreams[0].circuit_breaker = DefaultCbConfig();
        upstreams[1].name = "svc-b";
        upstreams[1].host = "h";
        upstreams[1].port = 81;
        upstreams[1].circuit_breaker = DefaultCbConfig();

        CircuitBreakerManager mgr(upstreams, 2, {});

        bool pass = mgr.host_count() == 1 &&
                    mgr.GetHost("svc-b") != nullptr &&
                    mgr.GetHost("") == nullptr;
        TestFramework::RecordTest(
            "CircuitBreakerManager skips empty-name upstream", pass,
            pass ? "" : "count=" + std::to_string(mgr.host_count()),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CircuitBreakerManager skips empty-name upstream",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Run all Phase 3 tests.
void RunAllTests() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "CIRCUIT BREAKER PHASE 3 - UNIT TESTS" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    TestRetryBudgetMinConcurrencyFloor();
    TestRetryBudgetPercentCap();
    TestRetryBudgetInFlightGuardRaii();
    TestRetryBudgetReloadPreservesCounters();
    TestRetryBudgetClampsInvalidTuning();

    TestHostCreatesSlicesAndGetSlice();
    TestHostSnapshotAggregates();
    TestHostReloadDispatcherMismatchIsSafe();

    TestManagerGetHostLookup();
    TestManagerSnapshotAllAndReloadSkipsTopologyChanges();
    TestManagerSkipsEmptyNameUpstream();
}

}  // namespace CircuitBreakerPhase3Tests
