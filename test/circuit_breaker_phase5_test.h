#pragma once

// Phase 5 integration tests: retry budget wired into ProxyTransaction.
//
// Phase 3 covered the RetryBudget math (CAS, non-retry denominator,
// min-concurrency floor) as unit tests against the RetryBudget class in
// isolation. Phase 5 tests the INTEGRATION: ProxyTransaction resolves
// `retry_budget_` from the same CircuitBreakerHost as `slice_`, tracks
// every attempt's in_flight via the RAII guard, and consults
// `TryConsumeRetry` before each retry. Exhaustion emits the §12.2
// response (503 + `X-Retry-Budget-Exhausted: 1`) and does NOT feed
// back into the slice's failure math.
//
// Strategy: backends that always 502 with `retry_on_5xx=true` drive the
// retry path. A near-zero retry-budget (`percent=0, min_concurrency=0`)
// rejects every retry deterministically without needing concurrent
// client load. The circuit-breaker consecutive-failure threshold is
// raised well above the retry count so the breaker stays CLOSED — the
// budget gate is tested in isolation from the state machine.

#include "test_framework.h"
#include "test_server_runner.h"
#include "http_test_client.h"
#include "http/http_server.h"
#include "config/server_config.h"

#include <thread>
#include <chrono>
#include <atomic>
#include <vector>

namespace CircuitBreakerPhase5Tests {

// Upstream config that always proxies /fail, with the circuit breaker
// enabled so `retry_budget_` is resolved on `slice_`'s host. Breaker
// thresholds intentionally unreachable for these tests — we want the
// retry-budget gate fired in isolation, not co-tripping the state
// machine.
static UpstreamConfig MakeRetryBudgetUpstream(const std::string& name,
                                              const std::string& host,
                                              int port,
                                              int retry_budget_percent,
                                              int retry_budget_min_concurrency,
                                              bool dry_run = false) {
    UpstreamConfig u;
    u.name = name;
    u.host = host;
    u.port = port;
    u.pool.max_connections       = 16;
    u.pool.max_idle_connections  = 8;
    u.pool.connect_timeout_ms    = 3000;
    u.pool.idle_timeout_sec      = 30;
    u.pool.max_lifetime_sec      = 3600;
    u.pool.max_requests_per_conn = 0;

    u.proxy.route_prefix = "/fail";
    u.proxy.strip_prefix = false;
    u.proxy.response_timeout_ms = 2000;

    u.circuit_breaker.enabled = true;
    u.circuit_breaker.dry_run = dry_run;
    // Breaker thresholds unreachable — we don't want the state machine
    // tripping during a retry-budget test.
    u.circuit_breaker.consecutive_failure_threshold = 10000;
    u.circuit_breaker.failure_rate_threshold = 100;
    u.circuit_breaker.minimum_volume = 10000;
    u.circuit_breaker.window_seconds = 10;
    u.circuit_breaker.permitted_half_open_calls = 2;
    u.circuit_breaker.base_open_duration_ms = 30000;
    u.circuit_breaker.max_open_duration_ms  = 60000;

    u.circuit_breaker.retry_budget_percent = retry_budget_percent;
    u.circuit_breaker.retry_budget_min_concurrency = retry_budget_min_concurrency;
    return u;
}

static bool HasRetryBudgetHeader(const std::string& response) {
    return response.find("X-Retry-Budget-Exhausted: 1") != std::string::npos ||
           response.find("x-retry-budget-exhausted: 1") != std::string::npos;
}

// ---------------------------------------------------------------------------
// Test 1: A retry attempt rejected by the retry-budget gate delivers 503 +
// X-Retry-Budget-Exhausted instead of the upstream's 5xx. Verifies that
// `TryConsumeRetry` runs BEFORE the retry executes and that
// `MakeRetryBudgetResponse` is emitted through the standard DeliverResponse
// path.
//
// retry_budget_percent=0 + retry_budget_min_concurrency=0 → cap = 0. Every
// retry attempt's TryConsumeRetry returns false. First attempt is
// unaffected (budget only gates retries), so the backend is hit exactly
// once per client request; the retry is short-circuited locally.
// ---------------------------------------------------------------------------
void TestRetryBudgetRejectsRetry() {
    std::cout << "\n[TEST] CB Phase 5: retry budget rejects retry..."
              << std::endl;
    try {
        std::atomic<int> backend_hits{0};
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/fail", [&backend_hits](const HttpRequest&, HttpResponse& resp) {
            backend_hits.fetch_add(1, std::memory_order_relaxed);
            resp.Status(502).Body("upstream-err", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ServerConfig gw;
        gw.bind_host = "127.0.0.1";
        gw.bind_port = 0;
        gw.worker_threads = 1;
        gw.http2.enabled = false;

        auto u = MakeRetryBudgetUpstream("svc", "127.0.0.1", backend_port,
                                         /*percent=*/0,
                                         /*min_concurrency=*/0);
        u.proxy.retry.max_retries = 3;
        u.proxy.retry.retry_on_5xx = true;
        gw.upstreams.push_back(u);

        HttpServer gateway(gw);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        std::string r = TestHttpClient::HttpGet(gw_port, "/fail", 5000);

        bool is_503 = TestHttpClient::HasStatus(r, 503);
        bool has_budget_hdr = HasRetryBudgetHeader(r);
        // Backend should have been hit exactly once (the first attempt);
        // every retry was short-circuited by the budget gate.
        int hits = backend_hits.load(std::memory_order_relaxed);
        bool single_backend_hit = (hits == 1);

        bool pass = is_503 && has_budget_hdr && single_backend_hit;
        TestFramework::RecordTest(
            "CB Phase 5: retry budget rejects retry", pass,
            pass ? "" :
            "is_503=" + std::to_string(is_503) +
            " budget_hdr=" + std::to_string(has_budget_hdr) +
            " backend_hits=" + std::to_string(hits) +
            " body=" + r.substr(0, 256));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB Phase 5: retry budget rejects retry", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Test 2: The min-concurrency floor admits retries even when the %-based
// cap would be zero. With percent=0 + min_concurrency=5, a single sequential
// client request's retry chain (1 first + 3 retries = 4 backend hits) all
// fit under the floor and proceed normally to the upstream — no 503, no
// X-Retry-Budget-Exhausted, and the client sees the final 5xx response.
//
// This is the symmetric test to Test 1: same near-zero %-cap, but a floor
// large enough that retries aren't budget-gated. Proves the floor is
// consulted (retries admitted) instead of the %-cap (retries rejected).
// ---------------------------------------------------------------------------
void TestRetryBudgetMinConcurrencyFloor() {
    std::cout << "\n[TEST] CB Phase 5: retry budget min-concurrency floor..."
              << std::endl;
    try {
        std::atomic<int> backend_hits{0};
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/fail", [&backend_hits](const HttpRequest&, HttpResponse& resp) {
            backend_hits.fetch_add(1, std::memory_order_relaxed);
            resp.Status(502).Body("upstream-err", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ServerConfig gw;
        gw.bind_host = "127.0.0.1";
        gw.bind_port = 0;
        gw.worker_threads = 1;
        gw.http2.enabled = false;

        // percent=0 → no %-based capacity. min_concurrency=5 → floor
        // admits up to 5 concurrent retries, easily covering the 3
        // sequential retries from a single client request.
        auto u = MakeRetryBudgetUpstream("svc", "127.0.0.1", backend_port,
                                         /*percent=*/0,
                                         /*min_concurrency=*/5);
        u.proxy.retry.max_retries = 3;
        u.proxy.retry.retry_on_5xx = true;
        gw.upstreams.push_back(u);

        HttpServer gateway(gw);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        std::string r = TestHttpClient::HttpGet(gw_port, "/fail", 10000);

        // Client sees the upstream's final 502 — no local 503, no
        // X-Retry-Budget-Exhausted.
        bool is_502 = TestHttpClient::HasStatus(r, 502);
        bool no_budget_hdr = !HasRetryBudgetHeader(r);
        // 1 first attempt + 3 retries admitted by the floor = 4 backend hits.
        int hits = backend_hits.load(std::memory_order_relaxed);
        bool all_retries_proceeded = (hits == 4);

        bool pass = is_502 && no_budget_hdr && all_retries_proceeded;
        TestFramework::RecordTest(
            "CB Phase 5: retry budget min-concurrency floor", pass,
            pass ? "" :
            "is_502=" + std::to_string(is_502) +
            " no_budget_hdr=" + std::to_string(no_budget_hdr) +
            " backend_hits=" + std::to_string(hits) +
            " body=" + r.substr(0, 256));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB Phase 5: retry budget min-concurrency floor", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Test 3: Dry-run bypasses the retry-budget gate.
//
// With percent=0 + min_concurrency=0 (same as Test 1), TryConsumeRetry
// returns false for every retry. But `circuit_breaker.dry_run=true`
// switches the rejection path to a log-and-proceed: no token is
// consumed, retry_token_held_ stays false, and AttemptCheckout runs as
// though the budget was unlimited.
//
// Result: the client sees the upstream's 502 response (because the
// retries actually fire), NOT a 503 + X-Retry-Budget-Exhausted.
// ---------------------------------------------------------------------------
void TestRetryBudgetDryRunPassthrough() {
    std::cout << "\n[TEST] CB Phase 5: retry budget dry-run passthrough..."
              << std::endl;
    try {
        std::atomic<int> backend_hits{0};
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/fail", [&backend_hits](const HttpRequest&, HttpResponse& resp) {
            backend_hits.fetch_add(1, std::memory_order_relaxed);
            resp.Status(502).Body("upstream-err", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ServerConfig gw;
        gw.bind_host = "127.0.0.1";
        gw.bind_port = 0;
        gw.worker_threads = 1;
        gw.http2.enabled = false;

        auto u = MakeRetryBudgetUpstream("svc", "127.0.0.1", backend_port,
                                         /*percent=*/0,
                                         /*min_concurrency=*/0,
                                         /*dry_run=*/true);
        u.proxy.retry.max_retries = 2;
        u.proxy.retry.retry_on_5xx = true;
        gw.upstreams.push_back(u);

        HttpServer gateway(gw);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        std::string r = TestHttpClient::HttpGet(gw_port, "/fail", 10000);

        // Retries proceeded despite would-reject decisions — the client
        // sees the upstream's final 502, not our local 503.
        bool is_502 = TestHttpClient::HasStatus(r, 502);
        bool no_budget_hdr = !HasRetryBudgetHeader(r);
        int hits = backend_hits.load(std::memory_order_relaxed);
        bool all_attempts_ran = (hits == 3);  // 1 first + 2 retries

        bool pass = is_502 && no_budget_hdr && all_attempts_ran;
        TestFramework::RecordTest(
            "CB Phase 5: retry budget dry-run passthrough", pass,
            pass ? "" :
            "is_502=" + std::to_string(is_502) +
            " no_budget_hdr=" + std::to_string(no_budget_hdr) +
            " backend_hits=" + std::to_string(hits) +
            " body=" + r.substr(0, 256));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB Phase 5: retry budget dry-run passthrough", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Test 4: First attempts are NOT budget-gated.
//
// The retry-budget cap applies only to retries (attempt_ > 0). First
// attempts call TrackInFlight (which only ever increments) but skip
// TryConsumeRetry entirely. With percent=0 + min_concurrency=0 and a
// backend that always 200s, every client request must succeed — if the
// gate accidentally ran on first attempts, we'd see 503s here.
//
// Guards against a regression where TryConsumeRetry is called before
// the `attempt_ > 0` gate, or where the gate is placed in
// AttemptCheckout instead of MaybeRetry.
// ---------------------------------------------------------------------------
void TestFirstAttemptsNotGated() {
    std::cout << "\n[TEST] CB Phase 5: first attempts not gated..."
              << std::endl;
    try {
        std::atomic<int> backend_hits{0};
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/fail", [&backend_hits](const HttpRequest&, HttpResponse& resp) {
            backend_hits.fetch_add(1, std::memory_order_relaxed);
            resp.Status(200).Body("ok", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ServerConfig gw;
        gw.bind_host = "127.0.0.1";
        gw.bind_port = 0;
        gw.worker_threads = 1;
        gw.http2.enabled = false;

        auto u = MakeRetryBudgetUpstream("svc", "127.0.0.1", backend_port,
                                         /*percent=*/0,
                                         /*min_concurrency=*/0);
        // No retries — every request is a first attempt.
        u.proxy.retry.max_retries = 0;
        gw.upstreams.push_back(u);

        HttpServer gateway(gw);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        int client_count = 5;
        int successes = 0;
        for (int i = 0; i < client_count; ++i) {
            std::string r = TestHttpClient::HttpGet(gw_port, "/fail", 3000);
            if (TestHttpClient::HasStatus(r, 200)) ++successes;
            if (HasRetryBudgetHeader(r)) {
                // Any X-Retry-Budget-Exhausted on a first-attempt-only
                // path is a bug. Record and bail.
                TestFramework::RecordTest(
                    "CB Phase 5: first attempts not gated", false,
                    "unexpected X-Retry-Budget-Exhausted on first-attempt path "
                    "i=" + std::to_string(i));
                return;
            }
        }

        int hits = backend_hits.load(std::memory_order_relaxed);
        bool pass = (successes == client_count) && (hits == client_count);
        TestFramework::RecordTest(
            "CB Phase 5: first attempts not gated", pass,
            pass ? "" :
            "successes=" + std::to_string(successes) +
            "/" + std::to_string(client_count) +
            " backend_hits=" + std::to_string(hits));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB Phase 5: first attempts not gated", false, e.what());
    }
}

void RunAllTests() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "CIRCUIT BREAKER PHASE 5 - RETRY BUDGET INTEGRATION TESTS"
              << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    TestRetryBudgetRejectsRetry();
    TestRetryBudgetMinConcurrencyFloor();
    TestRetryBudgetDryRunPassthrough();
    TestFirstAttemptsNotGated();
}

}  // namespace CircuitBreakerPhase5Tests
