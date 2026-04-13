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

        bool pass = slice.TryAcquire().decision == Decision::ADMITTED &&
                    slice.CurrentState() == State::CLOSED;

        // Reporting 100 failures must not trip.
        for (int i = 0; i < 100; ++i) {
            slice.ReportFailure(FailureKind::CONNECT_FAILURE, false, slice.CurrentGenerationForTesting());
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
            slice.ReportFailure(FailureKind::CONNECT_FAILURE, false, slice.CurrentGenerationForTesting());
        }
        bool pass = slice.CurrentState() == State::CLOSED &&
                    slice.TryAcquire().decision == Decision::ADMITTED &&
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
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false, slice.CurrentGenerationForTesting());
        }
        bool pass = slice.CurrentState() == State::OPEN &&
                    slice.Trips() == 1 &&
                    slice.TryAcquire().decision == Decision::REJECTED_OPEN;
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
            slice.ReportSuccess(false, slice.CurrentGenerationForTesting());
        }
        // A success between-failures clears consecutive_failures_, confirming
        // only rate path can trip here.
        for (int i = 0; i < 9; ++i) {
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false, slice.CurrentGenerationForTesting());
        }
        // Still CLOSED — 9/19 < 50%.
        bool pass_pre = slice.CurrentState() == State::CLOSED;
        // 10th failure brings ratio to 10/20 = 50% exactly — tripper.
        slice.ReportFailure(FailureKind::RESPONSE_5XX, false, slice.CurrentGenerationForTesting());
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
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false, slice.CurrentGenerationForTesting());
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
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false, slice.CurrentGenerationForTesting());
        }
        // Advance less than base_open_duration_ms (5000ms).
        clock->Advance(std::chrono::milliseconds(2000));
        Decision d = slice.TryAcquire().decision;
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
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false, slice.CurrentGenerationForTesting());
        }
        clock->Advance(std::chrono::milliseconds(cb.base_open_duration_ms + 1));
        Decision d = slice.TryAcquire().decision;
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
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false, slice.CurrentGenerationForTesting());
        }
        clock->Advance(std::chrono::milliseconds(cb.base_open_duration_ms + 1));

        // Take 5 probes; report success on each.
        for (int i = 0; i < cb.permitted_half_open_calls; ++i) {
            Decision d = slice.TryAcquire().decision;
            if (d != Decision::ADMITTED_PROBE) {
                TestFramework::RecordTest(
                    "CB: HALF_OPEN 5 probe successes close", false,
                    "probe " + std::to_string(i) + " not ADMITTED_PROBE",
                    TestFramework::TestCategory::OTHER);
                return;
            }
            slice.ReportSuccess(true, slice.CurrentGenerationForTesting());
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
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false, slice.CurrentGenerationForTesting());
        }
        clock->Advance(std::chrono::milliseconds(cb.base_open_duration_ms + 1));

        // Take 1 probe, fail it.
        Decision d = slice.TryAcquire().decision;
        slice.ReportFailure(FailureKind::RESPONSE_5XX, true, slice.CurrentGenerationForTesting());
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
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false, slice.CurrentGenerationForTesting());
        }
        clock->Advance(std::chrono::milliseconds(cb.base_open_duration_ms + 1));
        // Take 5 probes but DON'T report outcomes yet.
        for (int i = 0; i < 5; ++i) slice.TryAcquire();
        // 6th TryAcquire must reject (all slots taken).
        Decision d = slice.TryAcquire().decision;
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
                slice.ReportFailure(FailureKind::RESPONSE_5XX, false, slice.CurrentGenerationForTesting());
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
        slice.ReportFailure(FailureKind::RESPONSE_5XX, true, slice.CurrentGenerationForTesting());
        int64_t d2 = measure_open_ms();
        clock->Advance(std::chrono::milliseconds(d2 + 1));
        slice.TryAcquire();
        slice.ReportFailure(FailureKind::RESPONSE_5XX, true, slice.CurrentGenerationForTesting());
        int64_t d3 = measure_open_ms();
        clock->Advance(std::chrono::milliseconds(d3 + 1));
        slice.TryAcquire();
        slice.ReportFailure(FailureKind::RESPONSE_5XX, true, slice.CurrentGenerationForTesting());
        int64_t d4 = measure_open_ms();
        clock->Advance(std::chrono::milliseconds(d4 + 1));
        slice.TryAcquire();
        slice.ReportFailure(FailureKind::RESPONSE_5XX, true, slice.CurrentGenerationForTesting());
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
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false, slice.CurrentGenerationForTesting());
        }
        clock->Advance(std::chrono::milliseconds(1001));
        // Move to HALF_OPEN.
        for (int i = 0; i < 5; ++i) {
            slice.TryAcquire();
            slice.ReportSuccess(true, slice.CurrentGenerationForTesting());
        }
        // Now CLOSED. Trip again — expect base_duration again (not doubled).
        for (int i = 0; i < 5; ++i) {
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false, slice.CurrentGenerationForTesting());
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
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false, slice.CurrentGenerationForTesting());
        }
        // OPEN + dry_run → REJECTED_OPEN_DRYRUN (caller proceeds).
        Decision d = slice.TryAcquire().decision;
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
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false, slice.CurrentGenerationForTesting());
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
        slice.ReportFailure(FailureKind::RESPONSE_5XX, false, slice.CurrentGenerationForTesting());
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
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false, slice.CurrentGenerationForTesting());
        }
        slice.ReportSuccess(false, slice.CurrentGenerationForTesting());  // resets consecutive
        slice.ReportFailure(FailureKind::RESPONSE_5XX, false, slice.CurrentGenerationForTesting());
        // consecutive is back to 1, no trip.
        bool pass = slice.CurrentState() == State::CLOSED;
        TestFramework::RecordTest("CB: success clears consecutive", pass, "",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CB: success clears consecutive", false,
            e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ============================================================================
// Regression tests — critical bugs caught in code review
// ============================================================================

// BUG: late non-probe failure after trip re-entered TripClosedToOpen, inflating
// consecutive_trips_ (→ longer backoff) and firing a spurious CLOSED→OPEN
// transition edge. Fix: guard ReportFailure(probe=false) on state_ == CLOSED.
void TestLateFailureAfterTripDoesNotInflateBackoff() {
    std::cout << "\n[TEST] CB: late failure after trip does not inflate backoff..."
              << std::endl;
    try {
        auto cb = DefaultEnabledConfig();
        cb.base_open_duration_ms = 1000;
        cb.max_open_duration_ms = 60000;
        auto clock = std::make_shared<MockClock>();
        CircuitBreakerSlice slice("svc:h:p p=0", 0, cb,
            [clock]() { return clock->now; });

        // Admit 10 requests in CLOSED. Slice state is single-threaded so
        // admission + bookkeeping is serialized by the event loop — but in
        // production the outcomes for those admitted requests can arrive after
        // the slice has already tripped.
        for (int i = 0; i < 10; ++i) {
            Decision d = slice.TryAcquire().decision;
            if (d != Decision::ADMITTED) {
                TestFramework::RecordTest("CB: late failure after trip",
                    false, "admission i=" + std::to_string(i) + " not ADMITTED",
                    TestFramework::TestCategory::OTHER);
                return;
            }
        }
        // Report 5 failures — trip at the 5th.
        for (int i = 0; i < 5; ++i) {
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false, slice.CurrentGenerationForTesting());
        }
        if (slice.CurrentState() != State::OPEN) {
            TestFramework::RecordTest("CB: late failure after trip", false,
                "expected OPEN after 5 failures",
                TestFramework::TestCategory::OTHER);
            return;
        }
        int64_t trips_after_first_trip = slice.Trips();
        // Capture open_until immediately post-trip.
        auto open_until_initial = slice.OpenUntil();

        // Now the remaining 5 in-flight requests land with late failures.
        // Before the fix, each of these would go through the CLOSED path,
        // climb consecutive_failures_, and trigger another TripClosedToOpen
        // even though state is already OPEN.
        for (int i = 0; i < 5; ++i) {
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false, slice.CurrentGenerationForTesting());
        }
        int64_t trips_after_late = slice.Trips();
        auto open_until_after_late = slice.OpenUntil();

        bool pass = slice.CurrentState() == State::OPEN &&
                    trips_after_late == trips_after_first_trip &&  // no ghost trip
                    open_until_after_late == open_until_initial;    // backoff unchanged
        TestFramework::RecordTest(
            "CB: late failure after trip does not inflate backoff",
            pass, pass ? "" :
                  "trips: " + std::to_string(trips_after_first_trip) +
                  " → " + std::to_string(trips_after_late),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB: late failure after trip does not inflate backoff",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// BUG: late non-probe success after trip would reset consecutive_failures_
// and pollute the sliding window (pretending a fresh CLOSED cycle observed
// successes). Fix: guard ReportSuccess(probe=false) on state_ == CLOSED.
void TestLateSuccessAfterTripIgnored() {
    std::cout << "\n[TEST] CB: late success after trip ignored..." << std::endl;
    try {
        auto cb = DefaultEnabledConfig();
        auto clock = std::make_shared<MockClock>();
        CircuitBreakerSlice slice("svc:h:p p=0", 0, cb,
            [clock]() { return clock->now; });

        for (int i = 0; i < 5; ++i) {
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false, slice.CurrentGenerationForTesting());
        }
        // Slice is OPEN now. A late success arrives — must not change state.
        State pre = slice.CurrentState();
        slice.ReportSuccess(false, slice.CurrentGenerationForTesting());
        bool pass = pre == State::OPEN && slice.CurrentState() == State::OPEN;
        TestFramework::RecordTest("CB: late success after trip ignored", pass,
            "", TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CB: late success after trip ignored",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// BUG: HALF_OPEN admission kept accepting probes after the first probe
// failure (only enforcing `inflight < permitted`), so under load a failed
// recovery cycle could keep leaking traffic indefinitely instead of re-OPENing
// after the in-flight probes drained. Fix: short-circuit on saw_failure.
void TestHalfOpenStopsAdmittingAfterFirstProbeFailure() {
    std::cout << "\n[TEST] CB: HALF_OPEN stops admitting after probe fail..."
              << std::endl;
    try {
        auto cb = DefaultEnabledConfig();
        cb.permitted_half_open_calls = 5;
        auto clock = std::make_shared<MockClock>();
        CircuitBreakerSlice slice("svc:h:p p=0", 0, cb,
            [clock]() { return clock->now; });

        // Trip the breaker.
        for (int i = 0; i < 5; ++i) {
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false, slice.CurrentGenerationForTesting());
        }
        clock->Advance(std::chrono::milliseconds(cb.base_open_duration_ms + 1));

        // Admit 2 probes. Report failure on the first (but NOT the second yet
        // — leave 1 in-flight so we can observe the short-circuit).
        Decision d1 = slice.TryAcquire().decision;   // ADMITTED_PROBE, inflight=1
        Decision d2 = slice.TryAcquire().decision;   // ADMITTED_PROBE, inflight=2
        if (d1 != Decision::ADMITTED_PROBE || d2 != Decision::ADMITTED_PROBE) {
            TestFramework::RecordTest(
                "CB: HALF_OPEN stops admitting after probe fail",
                false, "probes not admitted as expected",
                TestFramework::TestCategory::OTHER);
            return;
        }
        // Fail the first probe — inflight drops to 1, saw_failure=true.
        // Last-probe trip does not yet fire (inflight is still 1).
        slice.ReportFailure(FailureKind::RESPONSE_5XX, true, slice.CurrentGenerationForTesting());

        // State must still be HALF_OPEN (final probe not yet completed).
        State mid = slice.CurrentState();

        // Subsequent TryAcquire — BEFORE fix this would succeed because
        // inflight (1) < permitted (5). AFTER fix it short-circuits because
        // saw_failure is set.
        Decision d3 = slice.TryAcquire().decision;

        bool pass = mid == State::HALF_OPEN &&
                    d3 == Decision::REJECTED_OPEN;
        TestFramework::RecordTest(
            "CB: HALF_OPEN stops admitting after probe fail",
            pass, pass ? "" : "expected REJECTED_OPEN on 3rd TryAcquire",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB: HALF_OPEN stops admitting after probe fail",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Verifies the dedicated HALF_OPEN-full counter is bumped separately from the
// generic `rejected_` counter, so Phase 7 snapshots can distinguish
// "open, backoff not elapsed" from "probing, no slots left".
void TestHalfOpenFullCounterSeparate() {
    std::cout << "\n[TEST] CB: HALF_OPEN_FULL counter separate..." << std::endl;
    try {
        auto cb = DefaultEnabledConfig();
        cb.permitted_half_open_calls = 2;
        auto clock = std::make_shared<MockClock>();
        CircuitBreakerSlice slice("svc:h:p p=0", 0, cb,
            [clock]() { return clock->now; });

        // Trip → OPEN reject increments generic counter only.
        for (int i = 0; i < 5; ++i) {
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false, slice.CurrentGenerationForTesting());
        }
        slice.TryAcquire();  // REJECTED_OPEN (backoff active)
        int64_t rejected_open_only = slice.Rejected();
        int64_t half_open_full_open_only = slice.RejectedHalfOpenFull();

        // Elapse backoff → HALF_OPEN. Fill the probe budget, then a 3rd
        // TryAcquire rejects with half_open_full, incrementing both counters.
        clock->Advance(std::chrono::milliseconds(cb.base_open_duration_ms + 1));
        slice.TryAcquire();                  // probe 1 admitted
        slice.TryAcquire();                  // probe 2 admitted (budget full)
        slice.TryAcquire();                  // REJECTED (full)
        int64_t rejected_total = slice.Rejected();
        int64_t half_open_full_total = slice.RejectedHalfOpenFull();

        bool pass = rejected_open_only == 1 &&
                    half_open_full_open_only == 0 &&
                    rejected_total == 2 &&            // 1 OPEN + 1 HALF_OPEN_FULL
                    half_open_full_total == 1;        // only the HALF_OPEN one
        TestFramework::RecordTest("CB: HALF_OPEN_FULL counter separate",
            pass, pass ? "" :
                  "rej=" + std::to_string(rejected_total) +
                  " hof=" + std::to_string(half_open_full_total),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CB: HALF_OPEN_FULL counter separate",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// BUG (review round 2, P2): Reload preserved stale state across enabled
// toggles. Disabling while OPEN and re-enabling later resumed the OPEN state,
// rejecting requests despite an explicit operator off→on cycle. Disabling
// after accumulated consecutive failures would re-trip on the very next
// failure. Fix: reset state to CLOSED whenever enabled toggles.
void TestReloadResetsStateOnEnabledToggleWhileOpen() {
    std::cout << "\n[TEST] CB: reload resets state on enabled toggle (while OPEN)..."
              << std::endl;
    try {
        auto cb = DefaultEnabledConfig();
        auto clock = std::make_shared<MockClock>();
        CircuitBreakerSlice slice("svc:h:p p=0", 0, cb,
            [clock]() { return clock->now; });

        // Drive to OPEN.
        for (int i = 0; i < 5; ++i) {
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false, slice.CurrentGenerationForTesting());
        }
        if (slice.CurrentState() != State::OPEN) {
            TestFramework::RecordTest(
                "CB: reload resets state on enabled toggle (OPEN)", false,
                "precondition: slice not OPEN",
                TestFramework::TestCategory::OTHER);
            return;
        }

        // Disable via reload — state must reset to CLOSED.
        auto disabled = cb;
        disabled.enabled = false;
        slice.Reload(disabled);
        bool disabled_closed = slice.CurrentState() == State::CLOSED;

        // Re-enable via reload — state must remain CLOSED (no stale OPEN).
        slice.Reload(cb);
        bool reenabled_closed = slice.CurrentState() == State::CLOSED;

        // And the slice must NOT insta-trip on a single failure (pre-fix,
        // consecutive_failures_ could have persisted ≥ threshold).
        slice.ReportFailure(FailureKind::RESPONSE_5XX, false, slice.CurrentGenerationForTesting());
        bool one_fail_no_trip = slice.CurrentState() == State::CLOSED;

        bool pass = disabled_closed && reenabled_closed && one_fail_no_trip;
        TestFramework::RecordTest(
            "CB: reload resets state on enabled toggle (OPEN)", pass,
            pass ? "" : "disabled_closed=" + std::to_string(disabled_closed) +
                        " reenabled_closed=" + std::to_string(reenabled_closed) +
                        " one_fail_no_trip=" + std::to_string(one_fail_no_trip),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB: reload resets state on enabled toggle (OPEN)", false, e.what(),
            TestFramework::TestCategory::OTHER);
    }
}

// BUG (review round 2, P2, variant): if disable happens while
// consecutive_failures_ has accumulated but not yet tripped, re-enable would
// inherit that count and trip early on the next failure.
void TestReloadResetsConsecutiveFailuresOnEnabledToggle() {
    std::cout << "\n[TEST] CB: reload clears consecutive_failures on enable toggle..."
              << std::endl;
    try {
        auto cb = DefaultEnabledConfig();
        cb.consecutive_failure_threshold = 5;
        auto clock = std::make_shared<MockClock>();
        CircuitBreakerSlice slice("svc:h:p p=0", 0, cb,
            [clock]() { return clock->now; });

        // 4 failures — just under threshold. State still CLOSED.
        for (int i = 0; i < 4; ++i) {
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false, slice.CurrentGenerationForTesting());
        }
        if (slice.CurrentState() != State::CLOSED) {
            TestFramework::RecordTest(
                "CB: reload clears consecutive_failures", false,
                "precondition: slice not CLOSED",
                TestFramework::TestCategory::OTHER);
            return;
        }

        // Disable then re-enable.
        auto disabled = cb; disabled.enabled = false;
        slice.Reload(disabled);
        slice.Reload(cb);

        // A single failure post-reenable must NOT trip — consecutive_failures_
        // should have been reset to 0, not preserved at 4.
        slice.ReportFailure(FailureKind::RESPONSE_5XX, false, slice.CurrentGenerationForTesting());
        bool pass = slice.CurrentState() == State::CLOSED;
        TestFramework::RecordTest(
            "CB: reload clears consecutive_failures on enable toggle",
            pass,
            pass ? "" : "expected CLOSED after 1 post-reenable failure, got " +
                        std::string(circuit_breaker::StateName(slice.CurrentState())),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB: reload clears consecutive_failures on enable toggle",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Threshold-change-only reload (enabled unchanged) MUST preserve live state
// per design §10. Regression guard for fix #1.
void TestReloadThresholdChangePreservesState() {
    std::cout << "\n[TEST] CB: reload preserves state when only thresholds change..."
              << std::endl;
    try {
        auto cb = DefaultEnabledConfig();
        auto clock = std::make_shared<MockClock>();
        CircuitBreakerSlice slice("svc:h:p p=0", 0, cb,
            [clock]() { return clock->now; });

        for (int i = 0; i < 5; ++i) {
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false, slice.CurrentGenerationForTesting());
        }
        // OPEN. Reload with a tighter threshold but enabled unchanged.
        auto tighter = cb;
        tighter.consecutive_failure_threshold = 2;
        slice.Reload(tighter);
        // State must remain OPEN — live state preservation.
        bool pass = slice.CurrentState() == State::OPEN;
        TestFramework::RecordTest(
            "CB: reload preserves state on threshold-only change",
            pass, pass ? "" : "expected OPEN, got " +
                              std::string(circuit_breaker::StateName(slice.CurrentState())),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB: reload preserves state on threshold-only change", false,
            e.what(), TestFramework::TestCategory::OTHER);
    }
}

// BUG (review round 2, P3): saw_failure short-circuit incorrectly bumped the
// HALF_OPEN_FULL counter, polluting dashboards that need to distinguish
// "probing, no capacity left" from "recovery attempt is failing".
void TestSawFailureDoesNotBumpHalfOpenFullCounter() {
    std::cout << "\n[TEST] CB: saw_failure reject does not bump HALF_OPEN_FULL..."
              << std::endl;
    try {
        auto cb = DefaultEnabledConfig();
        cb.permitted_half_open_calls = 5;  // plenty of capacity
        auto clock = std::make_shared<MockClock>();
        CircuitBreakerSlice slice("svc:h:p p=0", 0, cb,
            [clock]() { return clock->now; });

        for (int i = 0; i < 5; ++i) {
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false, slice.CurrentGenerationForTesting());
        }
        clock->Advance(std::chrono::milliseconds(cb.base_open_duration_ms + 1));

        // Admit 2 probes, fail the first — saw_failure=true, inflight=1.
        slice.TryAcquire();  // probe 1 admitted
        slice.TryAcquire();  // probe 2 admitted
        slice.ReportFailure(FailureKind::RESPONSE_5XX, true, slice.CurrentGenerationForTesting());

        int64_t hof_before = slice.RejectedHalfOpenFull();
        // Reject via saw_failure short-circuit (capacity is NOT exhausted —
        // only 1 probe actually in flight, and permitted is 5).
        Decision d = slice.TryAcquire().decision;
        int64_t hof_after = slice.RejectedHalfOpenFull();

        // Still REJECTED_OPEN (same client-visible outcome), but
        // RejectedHalfOpenFull must NOT be incremented — this is a
        // "recovery failing" reject, not a capacity reject.
        bool pass = d == Decision::REJECTED_OPEN &&
                    hof_before == 0 &&
                    hof_after == 0;
        TestFramework::RecordTest(
            "CB: saw_failure reject does not bump HALF_OPEN_FULL",
            pass, pass ? "" : "hof_before=" + std::to_string(hof_before) +
                              " hof_after=" + std::to_string(hof_after),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB: saw_failure reject does not bump HALF_OPEN_FULL",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// BUG (review round 3, P2): TransitionOpenToHalfOpen deliberately left
// `open_until_steady_ns_` populated, violating the documented OpenUntil()
// contract ("zero when not OPEN"). A Phase 4 consumer computing Retry-After
// from a HALF_OPEN slice would compute (stale_deadline - now), which is
// negative once HALF_OPEN begins.
void TestOpenUntilZeroWhenHalfOpen() {
    std::cout << "\n[TEST] CB: OpenUntil() zero in HALF_OPEN..." << std::endl;
    try {
        auto cb = DefaultEnabledConfig();
        auto clock = std::make_shared<MockClock>();
        CircuitBreakerSlice slice("svc:h:p p=0", 0, cb,
            [clock]() { return clock->now; });

        // Trip → OPEN. OpenUntil() must be non-zero (contract: zero iff NOT OPEN).
        for (int i = 0; i < 5; ++i) {
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false,
                                slice.CurrentGenerationForTesting());
        }
        auto open_ns = slice.OpenUntil();
        bool open_nonzero = open_ns != std::chrono::steady_clock::time_point{};

        // Elapse backoff → HALF_OPEN via TryAcquire.
        clock->Advance(std::chrono::milliseconds(cb.base_open_duration_ms + 1));
        auto a = slice.TryAcquire();
        bool halfopen = slice.CurrentState() == State::HALF_OPEN &&
                        a.decision == Decision::ADMITTED_PROBE;

        // Contract: OpenUntil() zero now that state != OPEN.
        auto halfopen_ns = slice.OpenUntil();
        bool halfopen_zero = halfopen_ns == std::chrono::steady_clock::time_point{};

        bool pass = open_nonzero && halfopen && halfopen_zero;
        TestFramework::RecordTest(
            "CB: OpenUntil() zero in HALF_OPEN",
            pass, pass ? "" :
                  "open_nonzero=" + std::to_string(open_nonzero) +
                  " halfopen=" + std::to_string(halfopen) +
                  " halfopen_zero=" + std::to_string(halfopen_zero),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB: OpenUntil() zero in HALF_OPEN",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// BUG (review round 3, P1): Reload reset the state on enabled toggle but
// gave Report* no way to distinguish pre-toggle admissions from post-toggle
// ones. Stale completions then polluted the fresh CLOSED cycle. Fixed with
// a generation token captured at admission and checked at report.
void TestStaleGenerationReportsDroppedAfterReloadToggle() {
    std::cout << "\n[TEST] CB: stale-generation reports dropped after reload toggle..."
              << std::endl;
    try {
        auto cb = DefaultEnabledConfig();
        cb.consecutive_failure_threshold = 3;  // make insta-trip detection easy
        auto clock = std::make_shared<MockClock>();
        CircuitBreakerSlice slice("svc:h:p p=0", 0, cb,
            [clock]() { return clock->now; });

        // Admit 3 requests in the original CLOSED cycle (generation = A).
        auto a1 = slice.TryAcquire();
        auto a2 = slice.TryAcquire();
        auto a3 = slice.TryAcquire();
        uint64_t gen_A = a1.generation;
        bool same_gen_pre = a2.generation == gen_A && a3.generation == gen_A;

        // Operator toggles: disable then re-enable → fresh CLOSED cycle.
        auto disabled = cb; disabled.enabled = false;
        slice.Reload(disabled);
        slice.Reload(cb);
        // After toggle, state is CLOSED and generation has advanced.
        uint64_t gen_B = slice.CurrentGenerationForTesting();
        bool generation_advanced = gen_B != gen_A;

        // Late failures from the pre-toggle cycle arrive. Without the fix,
        // these would increment consecutive_failures_ and trip the fresh
        // cycle IMMEDIATELY (threshold=3, 3 late failures).
        slice.ReportFailure(FailureKind::RESPONSE_5XX, false, gen_A);
        slice.ReportFailure(FailureKind::RESPONSE_5XX, false, gen_A);
        slice.ReportFailure(FailureKind::RESPONSE_5XX, false, gen_A);

        // Fresh cycle must be untouched.
        bool state_still_closed = slice.CurrentState() == State::CLOSED;
        bool stale_counter_bumped = slice.ReportsStaleGeneration() == 3;

        // A fresh post-toggle admission + 3 REAL failures should still trip —
        // so the guard didn't over-drop.
        auto fresh = slice.TryAcquire();
        for (int i = 0; i < 3; ++i) {
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false, fresh.generation);
        }
        bool fresh_trips = slice.CurrentState() == State::OPEN;

        bool pass = same_gen_pre && generation_advanced &&
                    state_still_closed && stale_counter_bumped && fresh_trips;
        TestFramework::RecordTest(
            "CB: stale-generation reports dropped after reload toggle",
            pass, pass ? "" :
                  "same_gen_pre=" + std::to_string(same_gen_pre) +
                  " gen_advanced=" + std::to_string(generation_advanced) +
                  " state_closed=" + std::to_string(state_still_closed) +
                  " stale_cnt=" + std::to_string(slice.ReportsStaleGeneration()) +
                  " fresh_trips=" + std::to_string(fresh_trips),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB: stale-generation reports dropped after reload toggle",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Generation also advances across state transitions (not just Reload), so
// a report admitted in CLOSED cycle A that completes after OPEN → HALF_OPEN
// → CLOSED cycle B is dropped instead of polluting cycle B's counters.
void TestStaleGenerationReportsDroppedAcrossStateTransitions() {
    std::cout << "\n[TEST] CB: stale reports dropped across CLOSED->OPEN->CLOSED..."
              << std::endl;
    try {
        auto cb = DefaultEnabledConfig();
        auto clock = std::make_shared<MockClock>();
        CircuitBreakerSlice slice("svc:h:p p=0", 0, cb,
            [clock]() { return clock->now; });

        // CLOSED cycle A — admit a request, capture its generation.
        auto admit_A = slice.TryAcquire();
        uint64_t gen_A = admit_A.generation;

        // Drive to OPEN, then HALF_OPEN, then CLOSED (cycle B) via probe success.
        for (int i = 0; i < 5; ++i) {
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false,
                                slice.CurrentGenerationForTesting());
        }
        clock->Advance(std::chrono::milliseconds(cb.base_open_duration_ms + 1));
        for (int i = 0; i < cb.permitted_half_open_calls; ++i) {
            auto p = slice.TryAcquire();  // probe
            slice.ReportSuccess(true, p.generation);
        }
        bool cycleB_closed = slice.CurrentState() == State::CLOSED;
        uint64_t gen_B = slice.CurrentGenerationForTesting();
        bool gen_advanced = gen_B > gen_A;

        // Now the original cycle-A request finally reports a success. In a
        // world without the generation guard, this would reset cycle B's
        // (freshly-zero) consecutive_failures_ and add to cycle B's window,
        // polluting fresh telemetry.
        int64_t stale_before = slice.ReportsStaleGeneration();
        slice.ReportSuccess(false, gen_A);
        int64_t stale_after = slice.ReportsStaleGeneration();
        bool dropped = stale_after == stale_before + 1;

        bool pass = cycleB_closed && gen_advanced && dropped;
        TestFramework::RecordTest(
            "CB: stale reports dropped across CLOSED->OPEN->CLOSED",
            pass, pass ? "" :
                  "cycleB_closed=" + std::to_string(cycleB_closed) +
                  " gen_advanced=" + std::to_string(gen_advanced) +
                  " dropped=" + std::to_string(dropped),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB: stale reports dropped across CLOSED->OPEN->CLOSED",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// BUG (review round 4, P2): Reload that resizes the rolling window without
// toggling enabled cleared the window buckets but left generation_ unchanged.
// Late reports from pre-reload admissions would carry the still-current
// generation, pass the guard, and re-populate the freshly empty window —
// mixing pre-reload and post-reload traffic. A pre-reload + post-reload
// failure pair could satisfy minimum_volume / failure_rate immediately on
// what should be a fresh observation cycle.
void TestWindowResizeAdvancesGeneration() {
    std::cout << "\n[TEST] CB: window resize advances generation..." << std::endl;
    try {
        // Use rate-trip path only (high consec threshold disables that path),
        // a low minimum_volume so 2 failures suffice, and a high
        // failure_rate_threshold so the trip relies on the rate calc.
        CircuitBreakerConfig cb;
        cb.enabled = true;
        cb.consecutive_failure_threshold = 1000;  // disable consecutive path
        cb.failure_rate_threshold = 50;
        cb.minimum_volume = 2;
        cb.window_seconds = 10;
        cb.permitted_half_open_calls = 5;
        cb.base_open_duration_ms = 5000;
        cb.max_open_duration_ms = 60000;

        auto clock = std::make_shared<MockClock>();
        CircuitBreakerSlice slice("svc:h:p p=0", 0, cb,
            [clock]() { return clock->now; });

        // Pre-reload: admit a request and capture its generation.
        auto admit_pre = slice.TryAcquire();
        uint64_t gen_pre = admit_pre.generation;

        // Reload: change window_seconds but keep enabled=true. Window is
        // resized (cleared) and generation MUST advance so the pre-reload
        // admission's late report doesn't seed the new window.
        auto resized = cb;
        resized.window_seconds = 30;
        slice.Reload(resized);

        uint64_t gen_post = slice.CurrentGenerationForTesting();
        bool gen_advanced = gen_post != gen_pre;

        // The pre-reload admission completes (failure). Without the fix,
        // this would add one failure to the freshly-empty window. Then
        // a post-reload admission's failure brings total=2 >= minimum_volume,
        // failures=2/2=100% >= 50% → IMMEDIATE TRIP on a fresh window.
        // With the fix, the pre-reload report is dropped (counted as stale).
        slice.ReportFailure(FailureKind::RESPONSE_5XX, false, gen_pre);

        int64_t stale_after_pre = slice.ReportsStaleGeneration();

        // Now a real post-reload admission and failure — single failure in
        // a fresh window of size 30s. total=1, below minimum_volume=2 → no trip.
        auto admit_post = slice.TryAcquire();
        slice.ReportFailure(FailureKind::RESPONSE_5XX, false, admit_post.generation);

        bool state_still_closed = slice.CurrentState() == State::CLOSED;
        bool stale_dropped = stale_after_pre == 1;

        bool pass = gen_advanced && state_still_closed && stale_dropped;
        TestFramework::RecordTest(
            "CB: window resize advances generation",
            pass, pass ? "" :
                  "gen_advanced=" + std::to_string(gen_advanced) +
                  " state_closed=" + std::to_string(state_still_closed) +
                  " stale_count=" + std::to_string(slice.ReportsStaleGeneration()),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB: window resize advances generation",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Regression guard: a reload that changes only thresholds (no window resize,
// no enabled toggle) MUST preserve generation. Operator intent is "apply new
// thresholds to existing observations" — the round-4 fix's window-resize
// generation bump must NOT trigger here.
void TestThresholdOnlyReloadDoesNotAdvanceGeneration() {
    std::cout << "\n[TEST] CB: threshold-only reload preserves generation..."
              << std::endl;
    try {
        auto cb = DefaultEnabledConfig();
        auto clock = std::make_shared<MockClock>();
        CircuitBreakerSlice slice("svc:h:p p=0", 0, cb,
            [clock]() { return clock->now; });

        auto admit = slice.TryAcquire();
        uint64_t gen_pre = admit.generation;

        // Tighten thresholds; same enabled, same window_seconds.
        auto tightened = cb;
        tightened.consecutive_failure_threshold = 2;
        tightened.failure_rate_threshold = 30;
        slice.Reload(tightened);

        uint64_t gen_post = slice.CurrentGenerationForTesting();
        bool gen_preserved = gen_post == gen_pre;

        // The pre-reload admission's report should NOT be dropped — operator
        // wants the new thresholds applied to existing in-flight observations.
        slice.ReportFailure(FailureKind::RESPONSE_5XX, false, gen_pre);
        bool stale_zero = slice.ReportsStaleGeneration() == 0;

        bool pass = gen_preserved && stale_zero;
        TestFramework::RecordTest(
            "CB: threshold-only reload preserves generation",
            pass, pass ? "" :
                  "gen_preserved=" + std::to_string(gen_preserved) +
                  " stale_zero=" + std::to_string(stale_zero),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB: threshold-only reload preserves generation",
            false, e.what(), TestFramework::TestCategory::OTHER);
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
            slice.ReportFailure(FailureKind::RESPONSE_5XX, false, slice.CurrentGenerationForTesting());
        }
        clock->Advance(std::chrono::milliseconds(cb.base_open_duration_ms + 1));
        for (int i = 0; i < cb.permitted_half_open_calls; ++i) {
            slice.TryAcquire();
            slice.ReportSuccess(true, slice.CurrentGenerationForTesting());
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
    TestLateFailureAfterTripDoesNotInflateBackoff();
    TestLateSuccessAfterTripIgnored();
    TestHalfOpenStopsAdmittingAfterFirstProbeFailure();
    TestHalfOpenFullCounterSeparate();
    TestReloadResetsStateOnEnabledToggleWhileOpen();
    TestReloadResetsConsecutiveFailuresOnEnabledToggle();
    TestReloadThresholdChangePreservesState();
    TestSawFailureDoesNotBumpHalfOpenFullCounter();
    TestOpenUntilZeroWhenHalfOpen();
    TestStaleGenerationReportsDroppedAfterReloadToggle();
    TestStaleGenerationReportsDroppedAcrossStateTransitions();
    TestWindowResizeAdvancesGeneration();
    TestThresholdOnlyReloadDoesNotAdvanceGeneration();
    TestTransitionCallbackInvoked();
}

}  // namespace CircuitBreakerTests
