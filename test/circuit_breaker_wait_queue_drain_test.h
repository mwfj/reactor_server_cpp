#pragma once

// Wait-queue-drain integration tests: wait-queue drain on CLOSED → OPEN trip.
//
// The integration suite covers "new requests after a trip hit
// REJECTED_OPEN". This suite covers the orthogonal case: a request that passed ConsultBreaker
// pre-trip and is waiting in the pool's bounded wait queue when the trip
// fires. Without the drain, that waiter would sit until either the pool
// frees a slot (and then re-hit the upstream — pointless traffic) or the
// queue-timeout / open-duration elapses (up to 60s latency spike).
//
// Mechanism tested: `HttpServer::MarkServerReady` installs a transition
// callback on every slice that routes CLOSED → OPEN to the corresponding
// `PoolPartition::DrainWaitQueueOnTrip()`. Each waiter receives
// `CHECKOUT_CIRCUIT_OPEN`, which `ProxyTransaction::OnCheckoutError` maps
// to the standard circuit-open response (503 + `X-Circuit-Breaker: open`).
//
// Strategy: gate concurrency via a 1-connection pool. The first request
// hangs at the backend long enough to let a second request queue behind
// it. When the first's response lands (502), the breaker trips and the
// drain fires, causing the queued request to receive 503 + circuit-open
// headers instead of the backend's 502 (which would happen if the drain
// were missing and the queued request proceeded).

#include "test_framework.h"
#include "test_server_runner.h"
#include "http_test_client.h"
#include "http/http_server.h"
#include "config/server_config.h"

#include <thread>
#include <chrono>
#include <atomic>
#include <vector>
#include <future>

namespace CircuitBreakerWaitQueueDrainTests {

static UpstreamConfig MakeDrainTripUpstream(const std::string& name,
                                             const std::string& host,
                                             int port,
                                             bool breaker_enabled) {
    UpstreamConfig u;
    u.name = name;
    u.host = host;
    u.port = port;
    // Single connection per partition — forces the second concurrent
    // request to queue behind the first. Since tests run with
    // worker_threads=1, one partition exists and it has exactly one
    // connection slot.
    u.pool.max_connections       = 1;
    u.pool.max_idle_connections  = 1;
    u.pool.connect_timeout_ms    = 3000;
    u.pool.idle_timeout_sec      = 30;
    u.pool.max_lifetime_sec      = 3600;
    u.pool.max_requests_per_conn = 0;

    u.proxy.route_prefix = "/fail";
    u.proxy.strip_prefix = false;
    u.proxy.response_timeout_ms = 5000;
    u.proxy.retry.max_retries = 0;  // Deterministic — no retry confounds.

    u.circuit_breaker.enabled = breaker_enabled;
    u.circuit_breaker.consecutive_failure_threshold = 1;  // Trip on first 5xx.
    u.circuit_breaker.failure_rate_threshold = 100;
    u.circuit_breaker.minimum_volume = 10000;
    u.circuit_breaker.window_seconds = 10;
    u.circuit_breaker.permitted_half_open_calls = 2;
    // Long open duration so the drain is unambiguously the thing that
    // surfaces the 503 to the queued client — not a timer-driven
    // HALF_OPEN recovery admitting a subsequent attempt.
    u.circuit_breaker.base_open_duration_ms = 30000;
    u.circuit_breaker.max_open_duration_ms  = 60000;
    return u;
}

// ---------------------------------------------------------------------------
// Test 1: CLOSED→OPEN trip drains queued waiter with 503 + X-Circuit-Breaker.
//
// Request A takes the single pool slot and hangs at the backend for ~300ms.
// Request B queues (pool exhausted). At t≈300ms, A's backend response
// arrives: 502 → slice trip → transition callback → DrainWaitQueueOnTrip →
// B's error_callback fires with CHECKOUT_CIRCUIT_OPEN. B's client receives
// 503 + `X-Circuit-Breaker: open`.
//
// Pre-fix (no drain): B waits ~300ms for A's slot to free, then hits the
// backend itself, gets 502, client sees 502 — NOT 503 and NOT
// X-Circuit-Breaker: open. The assertion `is_503 && has_breaker_header`
// fails without the drain wiring.
// ---------------------------------------------------------------------------
void TestWaitQueueDrainedOnTrip() {
    std::cout << "\n[TEST] CB Wait-Queue Drain: wait queue drained on trip..."
              << std::endl;
    try {
        std::atomic<int> backend_hits{0};
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/fail", [&backend_hits](const HttpRequest&, HttpResponse& resp) {
            backend_hits.fetch_add(1, std::memory_order_relaxed);
            // Delay so the gateway's pool holds the connection long
            // enough for a second client request to queue on it.
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
            resp.Status(502).Body("upstream-err", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ServerConfig gw;
        gw.bind_host = "127.0.0.1";
        gw.bind_port = 0;
        gw.worker_threads = 1;  // Single partition → single wait queue.
        gw.http2.enabled = false;

        gw.upstreams.push_back(
            MakeDrainTripUpstream("svc", "127.0.0.1", backend_port,
                                  /*breaker_enabled=*/true));

        HttpServer gateway(gw);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        // Launch A first (takes the one connection), then B 50ms later
        // so B is guaranteed to enter the wait queue.
        std::promise<std::string> a_resp, b_resp;
        auto a_fut = a_resp.get_future();
        auto b_fut = b_resp.get_future();
        std::thread a([&]() {
            a_resp.set_value(TestHttpClient::HttpGet(gw_port, "/fail", 5000));
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        std::thread b([&]() {
            b_resp.set_value(TestHttpClient::HttpGet(gw_port, "/fail", 5000));
        });
        a.join();
        b.join();

        std::string ra = a_fut.get();
        std::string rb = b_fut.get();

        // A unambiguously hits the backend (owns the slot) and sees 502.
        bool a_is_502 = TestHttpClient::HasStatus(ra, 502);
        // B must see the circuit-open short-circuit from the drain —
        // NOT a 502 from the backend, which is what happens without
        // the drain wiring.
        bool b_is_503 = TestHttpClient::HasStatus(rb, 503);
        bool b_has_breaker_hdr =
            rb.find("X-Circuit-Breaker: open") != std::string::npos ||
            rb.find("x-circuit-breaker: open") != std::string::npos;
        // Exactly one backend hit — B was drained before making it to
        // the upstream. Without the drain, backend_hits would be 2.
        int hits = backend_hits.load(std::memory_order_relaxed);
        bool single_hit = (hits == 1);

        bool pass = a_is_502 && b_is_503 && b_has_breaker_hdr && single_hit;
        TestFramework::RecordTest(
            "CB Wait-Queue Drain: wait queue drained on trip", pass,
            pass ? "" :
            "a_is_502=" + std::to_string(a_is_502) +
            " b_is_503=" + std::to_string(b_is_503) +
            " b_breaker_hdr=" + std::to_string(b_has_breaker_hdr) +
            " backend_hits=" + std::to_string(hits) +
            " rb_head=" + rb.substr(0, 200));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB Wait-Queue Drain: wait queue drained on trip", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Test 2: With the breaker disabled, the drain does NOT fire — the queued
// waiter proceeds to the upstream as it would absent the circuit-breaker
// layer entirely.
//
// Same setup as Test 1 but `circuit_breaker.enabled=false`. Disabled slices
// short-circuit in TryAcquire and never invoke transition callbacks, so
// DrainWaitQueueOnTrip is never called. Request B must hit the backend
// (backend_hits == 2) and receive the upstream's 502 — NOT a 503.
// ---------------------------------------------------------------------------
void TestDisabledBreakerDoesNotDrain() {
    std::cout << "\n[TEST] CB Wait-Queue Drain: disabled breaker does not drain..."
              << std::endl;
    try {
        std::atomic<int> backend_hits{0};
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/fail", [&backend_hits](const HttpRequest&, HttpResponse& resp) {
            backend_hits.fetch_add(1, std::memory_order_relaxed);
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
            resp.Status(502).Body("upstream-err", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ServerConfig gw;
        gw.bind_host = "127.0.0.1";
        gw.bind_port = 0;
        gw.worker_threads = 1;
        gw.http2.enabled = false;

        gw.upstreams.push_back(
            MakeDrainTripUpstream("svc", "127.0.0.1", backend_port,
                                  /*breaker_enabled=*/false));

        HttpServer gateway(gw);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        std::promise<std::string> a_resp, b_resp;
        auto a_fut = a_resp.get_future();
        auto b_fut = b_resp.get_future();
        std::thread a([&]() {
            a_resp.set_value(TestHttpClient::HttpGet(gw_port, "/fail", 5000));
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        std::thread b([&]() {
            b_resp.set_value(TestHttpClient::HttpGet(gw_port, "/fail", 5000));
        });
        a.join();
        b.join();

        std::string ra = a_fut.get();
        std::string rb = b_fut.get();

        // Both reach the backend — disabled breaker = no drain.
        bool a_is_502 = TestHttpClient::HasStatus(ra, 502);
        bool b_is_502 = TestHttpClient::HasStatus(rb, 502);
        // Neither should carry the circuit-open header.
        bool no_breaker_on_a =
            ra.find("X-Circuit-Breaker") == std::string::npos &&
            ra.find("x-circuit-breaker") == std::string::npos;
        bool no_breaker_on_b =
            rb.find("X-Circuit-Breaker") == std::string::npos &&
            rb.find("x-circuit-breaker") == std::string::npos;
        int hits = backend_hits.load(std::memory_order_relaxed);
        bool two_hits = (hits == 2);

        bool pass = a_is_502 && b_is_502 && no_breaker_on_a &&
                    no_breaker_on_b && two_hits;
        TestFramework::RecordTest(
            "CB Wait-Queue Drain: disabled breaker does not drain", pass,
            pass ? "" :
            "a_is_502=" + std::to_string(a_is_502) +
            " b_is_502=" + std::to_string(b_is_502) +
            " no_breaker_on_a=" + std::to_string(no_breaker_on_a) +
            " no_breaker_on_b=" + std::to_string(no_breaker_on_b) +
            " backend_hits=" + std::to_string(hits));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB Wait-Queue Drain: disabled breaker does not drain", false, e.what());
    }
}

void RunAllTests() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "CIRCUIT BREAKER - WAIT-QUEUE DRAIN ON TRIP TESTS"
              << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    TestWaitQueueDrainedOnTrip();
    TestDisabledBreakerDoesNotDrain();
}

}  // namespace CircuitBreakerWaitQueueDrainTests
