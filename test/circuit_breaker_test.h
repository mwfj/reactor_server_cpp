#pragma once

#include "test_framework.h"
#include "config/server_config.h"
#include "circuit_breaker/circuit_breaker_state.h"
#include "circuit_breaker/circuit_breaker_window.h"
#include "circuit_breaker/circuit_breaker_slice.h"

#include <chrono>
#include <iostream>
#include <string>

namespace CircuitBreakerTests {

using circuit_breaker::CircuitBreakerSlice;
using circuit_breaker::CircuitBreakerWindow;
using circuit_breaker::Decision;
using circuit_breaker::FailureKind;
using circuit_breaker::State;

// A simple mock clock that advances only when the test tells it to.
class MockClock {
public:
    std::chrono::steady_clock::time_point now{
        // Choose a non-zero base so 0 is distinguishable from "not OPEN".
        std::chrono::steady_clock::time_point(std::chrono::seconds(1'000'000))
    };
    void Advance(std::chrono::milliseconds ms) { now += ms; }
    void AdvanceSec(int seconds) { now += std::chrono::seconds(seconds); }
    std::chrono::steady_clock::time_point operator()() const { return now; }
};

// Build a config with default values — tests override specific fields.
static CircuitBreakerConfig DefaultEnabledConfig() {
    CircuitBreakerConfig cb;
    cb.enabled = true;
    cb.consecutive_failure_threshold = 5;
    cb.failure_rate_threshold = 50;
    cb.minimum_volume = 20;
    cb.window_seconds = 10;
    cb.permitted_half_open_calls = 5;
    cb.base_open_duration_ms = 5000;
    cb.max_open_duration_ms = 60000;
    return cb;
}

// ============================================================================
// State machine tests
// ============================================================================

void TestDisabledFastPath() {
    std::cout << "\n[TEST] CB: Disabled fast path..." << std::endl;
    try {
        CircuitBreakerConfig cb;   // enabled=false by default
        auto clock = std::make_shared<MockClock>();
        CircuitBreakerSlice slice("svc:h:p p=0", 0, cb,
            [clock]() { return clock->now; });

        bool pass = slice.TryAcquire() == Decision::ADMITTED &&
                    slice.CurrentState() == State::CLOSED;

        // Reporting 100 failures must not trip.
        for (int i = 0; i < 100; ++i) {
            slice.ReportFailure(FailureKind::CONNECT_FAILURE, false);
        }
        pass = pass && slice.CurrentState() == State::CLOSED &&
               slice.Trips() == 0;

        TestFramework::RecordTest("CB: disabled fast path", pass, "",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CB: disabled fast path", false, e.what(),
            TestFramework::TestCategory::OTHER);
    }
}

void TestClosedStaysClosedBelowConsecutiveThreshold() {
    std::cout << "\n[TEST] CB: 4 failures below threshold..." << std::endl;
    try {
        auto cb = DefaultEnabledConfig();
        auto clock = std::make_shared<MockClock>();
        CircuitBreakerSlice slice("svc:h:p p=0", 0, cb,
            [clock]() { return clock->now; });

        for (int i = 0; i < 4; ++i) {
            slice.ReportFailure(FailureKind::CONNECT_FAILURE, false);
        }
        bool pass = slice.CurrentState() == State::CLOSED &&
                    slice.TryAcquire() == Decision::ADMITTED &&
                    slice.Trips() == 0;
        TestFramework::RecordTest("CB: 4 failures below threshold", pass, "",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CB: 4 failures below threshold", false,
            e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestConsecutiveFailureTrip() {
    std::cout << "\n[TEST] CB: 5 consecutive failures trip..." << std::endl;
    try {
        auto cb = DefaultEnabledConfig();
        auto clock = std::make_shared<MockClock>();
        CircuitBreakerSlice slice("svc:h:p p=0", 0, cb,
            [clock]() { return clock->now; });

        for (int i = 0; i < 5; ++i) {
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false);
        }
        bool pass = slice.CurrentState() == State::OPEN &&
                    slice.Trips() == 1 &&
                    slice.TryAcquire() == Decision::REJECTED_OPEN;
        TestFramework::RecordTest("CB: 5 consecutive failures trip", pass, "",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CB: 5 consecutive failures trip", false,
            e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestFailureRateTrip() {
    std::cout << "\n[TEST] CB: failure-rate trip (50% of 20)..." << std::endl;
    try {
        auto cb = DefaultEnabledConfig();
        cb.consecutive_failure_threshold = 1000;  // disable consec path
        auto clock = std::make_shared<MockClock>();
        CircuitBreakerSlice slice("svc:h:p p=0", 0, cb,
            [clock]() { return clock->now; });

        // Alternate 10 failures and 10 successes within the same second —
        // ratio = 50%, total = 20 (>= minimum_volume).
        for (int i = 0; i < 10; ++i) {
            slice.ReportSuccess(false);
        }
        // A success between-failures clears consecutive_failures_, confirming
        // only rate path can trip here.
        for (int i = 0; i < 9; ++i) {
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false);
        }
        // Still CLOSED — 9/19 < 50%.
        bool pass_pre = slice.CurrentState() == State::CLOSED;
        // 10th failure brings ratio to 10/20 = 50% exactly — tripper.
        slice.ReportFailure(FailureKind::RESPONSE_5XX, false);
        bool pass = pass_pre && slice.CurrentState() == State::OPEN &&
                    slice.Trips() == 1;
        TestFramework::RecordTest("CB: failure-rate trip (50% of 20)", pass, "",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CB: failure-rate trip (50% of 20)", false,
            e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestMinimumVolumeGate() {
    std::cout << "\n[TEST] CB: minimum_volume gate..." << std::endl;
    try {
        auto cb = DefaultEnabledConfig();
        cb.consecutive_failure_threshold = 1000;  // disable consec path
        cb.minimum_volume = 20;
        auto clock = std::make_shared<MockClock>();
        CircuitBreakerSlice slice("svc:h:p p=0", 0, cb,
            [clock]() { return clock->now; });

        // 19 total calls, all failures — should NOT trip (below volume).
        for (int i = 0; i < 19; ++i) {
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false);
        }
        bool pass = slice.CurrentState() == State::CLOSED && slice.Trips() == 0;
        TestFramework::RecordTest("CB: minimum_volume gate", pass, "",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CB: minimum_volume gate", false, e.what(),
            TestFramework::TestCategory::OTHER);
    }
}

void TestOpenBeforeDurationStaysOpen() {
    std::cout << "\n[TEST] CB: OPEN rejects before elapsed..." << std::endl;
    try {
        auto cb = DefaultEnabledConfig();
        auto clock = std::make_shared<MockClock>();
        CircuitBreakerSlice slice("svc:h:p p=0", 0, cb,
            [clock]() { return clock->now; });

        for (int i = 0; i < 5; ++i) {
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false);
        }
        // Advance less than base_open_duration_ms (5000ms).
        clock->Advance(std::chrono::milliseconds(2000));
        Decision d = slice.TryAcquire();
        bool pass = d == Decision::REJECTED_OPEN &&
                    slice.CurrentState() == State::OPEN;
        TestFramework::RecordTest("CB: OPEN rejects before elapsed", pass, "",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CB: OPEN rejects before elapsed", false,
            e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestOpenToHalfOpenAfterDuration() {
    std::cout << "\n[TEST] CB: OPEN → HALF_OPEN after duration..." << std::endl;
    try {
        auto cb = DefaultEnabledConfig();
        auto clock = std::make_shared<MockClock>();
        CircuitBreakerSlice slice("svc:h:p p=0", 0, cb,
            [clock]() { return clock->now; });

        for (int i = 0; i < 5; ++i) {
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false);
        }
        clock->Advance(std::chrono::milliseconds(cb.base_open_duration_ms + 1));
        Decision d = slice.TryAcquire();
        bool pass = d == Decision::ADMITTED_PROBE &&
                    slice.CurrentState() == State::HALF_OPEN;
        TestFramework::RecordTest("CB: OPEN -> HALF_OPEN after duration", pass, "",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CB: OPEN -> HALF_OPEN after duration",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestHalfOpenAllProbesSucceed() {
    std::cout << "\n[TEST] CB: HALF_OPEN 5 probe successes close..." << std::endl;
    try {
        auto cb = DefaultEnabledConfig();
        auto clock = std::make_shared<MockClock>();
        CircuitBreakerSlice slice("svc:h:p p=0", 0, cb,
            [clock]() { return clock->now; });

        for (int i = 0; i < 5; ++i) {
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false);
        }
        clock->Advance(std::chrono::milliseconds(cb.base_open_duration_ms + 1));

        // Take 5 probes; report success on each.
        for (int i = 0; i < cb.permitted_half_open_calls; ++i) {
            Decision d = slice.TryAcquire();
            if (d != Decision::ADMITTED_PROBE) {
                TestFramework::RecordTest(
                    "CB: HALF_OPEN 5 probe successes close", false,
                    "probe " + std::to_string(i) + " not ADMITTED_PROBE",
                    TestFramework::TestCategory::OTHER);
                return;
            }
            slice.ReportSuccess(true);
        }
        bool pass = slice.CurrentState() == State::CLOSED &&
                    slice.ProbeSuccesses() == 5;
        TestFramework::RecordTest("CB: HALF_OPEN 5 probe successes close",
            pass, "", TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CB: HALF_OPEN 5 probe successes close",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestHalfOpenProbeFailureReopens() {
    std::cout << "\n[TEST] CB: HALF_OPEN single probe fail re-opens..." << std::endl;
    try {
        auto cb = DefaultEnabledConfig();
        auto clock = std::make_shared<MockClock>();
        CircuitBreakerSlice slice("svc:h:p p=0", 0, cb,
            [clock]() { return clock->now; });

        for (int i = 0; i < 5; ++i) {
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false);
        }
        clock->Advance(std::chrono::milliseconds(cb.base_open_duration_ms + 1));

        // Take 1 probe, fail it.
        Decision d = slice.TryAcquire();
        slice.ReportFailure(FailureKind::RESPONSE_5XX, true);
        bool pass = d == Decision::ADMITTED_PROBE &&
                    slice.CurrentState() == State::OPEN &&
                    slice.Trips() == 2 &&  // initial trip + re-trip
                    slice.ProbeFailures() == 1;
        TestFramework::RecordTest("CB: HALF_OPEN probe fail re-opens", pass, "",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CB: HALF_OPEN probe fail re-opens", false,
            e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestHalfOpenExhaustedSlotsRejected() {
    std::cout << "\n[TEST] CB: HALF_OPEN over capacity rejects..." << std::endl;
    try {
        auto cb = DefaultEnabledConfig();
        auto clock = std::make_shared<MockClock>();
        CircuitBreakerSlice slice("svc:h:p p=0", 0, cb,
            [clock]() { return clock->now; });

        for (int i = 0; i < 5; ++i) {
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false);
        }
        clock->Advance(std::chrono::milliseconds(cb.base_open_duration_ms + 1));
        // Take 5 probes but DON'T report outcomes yet.
        for (int i = 0; i < 5; ++i) slice.TryAcquire();
        // 6th TryAcquire must reject (all slots taken).
        Decision d = slice.TryAcquire();
        bool pass = d == Decision::REJECTED_OPEN;
        TestFramework::RecordTest("CB: HALF_OPEN over capacity rejects",
            pass, "", TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CB: HALF_OPEN over capacity rejects",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestExponentialBackoff() {
    std::cout << "\n[TEST] CB: exponential backoff progression..." << std::endl;
    try {
        auto cb = DefaultEnabledConfig();
        cb.base_open_duration_ms = 1000;
        cb.max_open_duration_ms = 8000;
        auto clock = std::make_shared<MockClock>();
        CircuitBreakerSlice slice("svc:h:p p=0", 0, cb,
            [clock]() { return clock->now; });

        auto trip_then_probe_fail = [&]() {
            // Reach OPEN.
            for (int i = 0; i < 5; ++i) {
                slice.ReportFailure(FailureKind::RESPONSE_5XX, false);
            }
        };
        auto measure_open_ms = [&]() {
            // open_until - now at the instant of the trip.
            auto open_until = slice.OpenUntil();
            auto remaining = open_until - clock->now;
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                       remaining).count();
        };

        // Trip 1 — expect ~1000ms.
        trip_then_probe_fail();
        int64_t d1 = measure_open_ms();
        // Move to HALF_OPEN and fail the probe → trip 2.
        clock->Advance(std::chrono::milliseconds(d1 + 1));
        slice.TryAcquire();  // HALF_OPEN, ADMITTED_PROBE
        slice.ReportFailure(FailureKind::RESPONSE_5XX, true);
        int64_t d2 = measure_open_ms();
        clock->Advance(std::chrono::milliseconds(d2 + 1));
        slice.TryAcquire();
        slice.ReportFailure(FailureKind::RESPONSE_5XX, true);
        int64_t d3 = measure_open_ms();
        clock->Advance(std::chrono::milliseconds(d3 + 1));
        slice.TryAcquire();
        slice.ReportFailure(FailureKind::RESPONSE_5XX, true);
        int64_t d4 = measure_open_ms();
        clock->Advance(std::chrono::milliseconds(d4 + 1));
        slice.TryAcquire();
        slice.ReportFailure(FailureKind::RESPONSE_5XX, true);
        int64_t d5 = measure_open_ms();

        // Expect 1000, 2000, 4000, 8000, 8000 (capped).
        bool pass = d1 == 1000 && d2 == 2000 && d3 == 4000 &&
                    d4 == 8000 && d5 == 8000;
        std::string err = "d1=" + std::to_string(d1) + " d2=" + std::to_string(d2) +
                          " d3=" + std::to_string(d3) + " d4=" + std::to_string(d4) +
                          " d5=" + std::to_string(d5);
        TestFramework::RecordTest("CB: exponential backoff",
            pass, pass ? "" : err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CB: exponential backoff", false, e.what(),
            TestFramework::TestCategory::OTHER);
    }
}

void TestResetOnClose() {
    std::cout << "\n[TEST] CB: consecutive_trips resets on close..." << std::endl;
    try {
        auto cb = DefaultEnabledConfig();
        cb.base_open_duration_ms = 1000;
        auto clock = std::make_shared<MockClock>();
        CircuitBreakerSlice slice("svc:h:p p=0", 0, cb,
            [clock]() { return clock->now; });

        // Trip 1.
        for (int i = 0; i < 5; ++i) {
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false);
        }
        clock->Advance(std::chrono::milliseconds(1001));
        // Move to HALF_OPEN.
        for (int i = 0; i < 5; ++i) {
            slice.TryAcquire();
            slice.ReportSuccess(true);
        }
        // Now CLOSED. Trip again — expect base_duration again (not doubled).
        for (int i = 0; i < 5; ++i) {
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false);
        }
        auto open_until = slice.OpenUntil();
        auto remaining = open_until - clock->now;
        int64_t d_after_close = std::chrono::duration_cast<
            std::chrono::milliseconds>(remaining).count();
        bool pass = d_after_close == 1000;
        TestFramework::RecordTest("CB: trips reset on close", pass,
            pass ? "" : "expected 1000ms, got " + std::to_string(d_after_close),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CB: trips reset on close", false, e.what(),
            TestFramework::TestCategory::OTHER);
    }
}

// ============================================================================
// Window tests
// ============================================================================

void TestWindowBucketByCurrentSecond() {
    std::cout << "\n[TEST] CB Window: bucket by current second..." << std::endl;
    try {
        CircuitBreakerWindow w(10);
        auto t0 = std::chrono::steady_clock::time_point(std::chrono::seconds(100));
        w.AddSuccess(t0);
        w.AddFailure(t0);
        w.AddFailure(t0);
        bool pass = w.TotalCount(t0) == 3 && w.FailureCount(t0) == 2;
        TestFramework::RecordTest("CB Window: bucket by current second", pass,
            "", TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CB Window: bucket by current second",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestWindowAdvanceSkipsStale() {
    std::cout << "\n[TEST] CB Window: advance skips stale..." << std::endl;
    try {
        CircuitBreakerWindow w(10);
        auto t0 = std::chrono::steady_clock::time_point(std::chrono::seconds(100));
        w.AddFailure(t0);  // bucket 100%10 = 0
        auto t1 = t0 + std::chrono::seconds(15);  // beyond window
        // After long idle, incoming record should see zero history.
        bool pre = w.TotalCount(t1) == 0;
        w.AddSuccess(t1);
        bool pass = pre && w.TotalCount(t1) == 1 && w.FailureCount(t1) == 0;
        TestFramework::RecordTest("CB Window: advance skips stale", pass, "",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CB Window: advance skips stale", false,
            e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestWindowPartialExpiry() {
    std::cout << "\n[TEST] CB Window: partial expiry..." << std::endl;
    try {
        CircuitBreakerWindow w(10);
        auto t0 = std::chrono::steady_clock::time_point(std::chrono::seconds(100));
        w.AddFailure(t0);               // sec 100
        auto t1 = t0 + std::chrono::seconds(5);
        w.AddFailure(t1);               // sec 105
        auto t2 = t0 + std::chrono::seconds(11);
        // sec 100 is now out of window (100 + 10 <= 111 - 1 = 110). So:
        // bucket 0 (sec 100 or sec 110) would have been zeroed when advancing
        // from head=105 past sec 110.
        bool pass = w.TotalCount(t2) == 1 && w.FailureCount(t2) == 1;
        TestFramework::RecordTest("CB Window: partial expiry", pass, "",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CB Window: partial expiry", false,
            e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestWindowReset() {
    std::cout << "\n[TEST] CB Window: reset clears..." << std::endl;
    try {
        CircuitBreakerWindow w(10);
        auto t0 = std::chrono::steady_clock::time_point(std::chrono::seconds(100));
        w.AddFailure(t0); w.AddSuccess(t0); w.AddFailure(t0);
        w.Reset();
        bool pass = w.TotalCount(t0) == 0 && w.FailureCount(t0) == 0;
        TestFramework::RecordTest("CB Window: reset clears", pass, "",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CB Window: reset clears", false, e.what(),
            TestFramework::TestCategory::OTHER);
    }
}

// ============================================================================
// Dry-run + Reload + Edge cases
// ============================================================================

void TestDryRunAdmits() {
    std::cout << "\n[TEST] CB: dry_run admits through OPEN..." << std::endl;
    try {
        auto cb = DefaultEnabledConfig();
        cb.dry_run = true;
        auto clock = std::make_shared<MockClock>();
        CircuitBreakerSlice slice("svc:h:p p=0", 0, cb,
            [clock]() { return clock->now; });

        for (int i = 0; i < 5; ++i) {
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false);
        }
        // OPEN + dry_run → REJECTED_OPEN_DRYRUN (caller proceeds).
        Decision d = slice.TryAcquire();
        bool pass = d == Decision::REJECTED_OPEN_DRYRUN &&
                    slice.CurrentState() == State::OPEN &&
                    slice.Rejected() == 1;
        TestFramework::RecordTest("CB: dry_run admits through OPEN", pass, "",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CB: dry_run admits through OPEN", false,
            e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestReloadPreservesState() {
    std::cout << "\n[TEST] CB: reload preserves live state..." << std::endl;
    try {
        auto cb = DefaultEnabledConfig();
        auto clock = std::make_shared<MockClock>();
        CircuitBreakerSlice slice("svc:h:p p=0", 0, cb,
            [clock]() { return clock->now; });

        for (int i = 0; i < 5; ++i) {
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false);
        }
        // OPEN at this point.
        auto cb2 = cb;
        cb2.consecutive_failure_threshold = 2;  // tighter
        cb2.window_seconds = 30;                // triggers ring resize
        slice.Reload(cb2);
        // Still OPEN immediately after reload — live state preserved.
        bool pass = slice.CurrentState() == State::OPEN;
        TestFramework::RecordTest("CB: reload preserves live state", pass, "",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CB: reload preserves live state", false,
            e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestConsecutiveThresholdOne() {
    std::cout << "\n[TEST] CB: threshold=1 single failure trips..." << std::endl;
    try {
        auto cb = DefaultEnabledConfig();
        cb.consecutive_failure_threshold = 1;
        auto clock = std::make_shared<MockClock>();
        CircuitBreakerSlice slice("svc:h:p p=0", 0, cb,
            [clock]() { return clock->now; });
        slice.ReportFailure(FailureKind::RESPONSE_5XX, false);
        bool pass = slice.CurrentState() == State::OPEN && slice.Trips() == 1;
        TestFramework::RecordTest("CB: threshold=1 single failure trips",
            pass, "", TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CB: threshold=1 single failure trips",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestSuccessClearsConsecutive() {
    std::cout << "\n[TEST] CB: success clears consecutive..." << std::endl;
    try {
        auto cb = DefaultEnabledConfig();
        auto clock = std::make_shared<MockClock>();
        CircuitBreakerSlice slice("svc:h:p p=0", 0, cb,
            [clock]() { return clock->now; });

        for (int i = 0; i < 4; ++i) {
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false);
        }
        slice.ReportSuccess(false);  // resets consecutive
        slice.ReportFailure(FailureKind::RESPONSE_5XX, false);
        // consecutive is back to 1, no trip.
        bool pass = slice.CurrentState() == State::CLOSED;
        TestFramework::RecordTest("CB: success clears consecutive", pass, "",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CB: success clears consecutive", false,
            e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestTransitionCallbackInvoked() {
    std::cout << "\n[TEST] CB: transition callback invoked..." << std::endl;
    try {
        auto cb = DefaultEnabledConfig();
        auto clock = std::make_shared<MockClock>();
        CircuitBreakerSlice slice("svc:h:p p=0", 0, cb,
            [clock]() { return clock->now; });

        int closed_to_open = 0;
        int open_to_halfopen = 0;
        int halfopen_to_closed = 0;
        slice.SetTransitionCallback(
            [&](State o, State n, const char*) {
                if (o == State::CLOSED && n == State::OPEN) closed_to_open++;
                else if (o == State::OPEN && n == State::HALF_OPEN) open_to_halfopen++;
                else if (o == State::HALF_OPEN && n == State::CLOSED) halfopen_to_closed++;
            });

        // Full cycle.
        for (int i = 0; i < 5; ++i) {
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false);
        }
        clock->Advance(std::chrono::milliseconds(cb.base_open_duration_ms + 1));
        for (int i = 0; i < cb.permitted_half_open_calls; ++i) {
            slice.TryAcquire();
            slice.ReportSuccess(true);
        }
        bool pass = closed_to_open == 1 && open_to_halfopen == 1 &&
                    halfopen_to_closed == 1;
        TestFramework::RecordTest("CB: transition callback invoked", pass, "",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CB: transition callback invoked", false,
            e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Run all circuit breaker unit tests.
void RunAllTests() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "CIRCUIT BREAKER - UNIT TESTS" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    TestDisabledFastPath();
    TestClosedStaysClosedBelowConsecutiveThreshold();
    TestConsecutiveFailureTrip();
    TestFailureRateTrip();
    TestMinimumVolumeGate();
    TestOpenBeforeDurationStaysOpen();
    TestOpenToHalfOpenAfterDuration();
    TestHalfOpenAllProbesSucceed();
    TestHalfOpenProbeFailureReopens();
    TestHalfOpenExhaustedSlotsRejected();
    TestExponentialBackoff();
    TestResetOnClose();
    TestWindowBucketByCurrentSecond();
    TestWindowAdvanceSkipsStale();
    TestWindowPartialExpiry();
    TestWindowReset();
    TestDryRunAdmits();
    TestReloadPreservesState();
    TestConsecutiveThresholdOne();
    TestSuccessClearsConsecutive();
    TestTransitionCallbackInvoked();
}

}  // namespace CircuitBreakerTests
