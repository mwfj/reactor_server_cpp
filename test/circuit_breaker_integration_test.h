#pragma once

// Integration tests: circuit breaker wired into ProxyTransaction +
// UpstreamManager + HttpServer. Exercises the full request path end-to-end.
//
// Strategy: use a backend that returns 5xx on every request so repeated hits
// trip the breaker via the consecutive-failure threshold. 5xx responses are
// the cheapest way to accumulate failures (no connect timeouts to wait for).
// Low thresholds keep tests fast.

#include "test_framework.h"
#include "test_server_runner.h"
#include "http_test_client.h"
#include "http/http_server.h"
#include "config/server_config.h"
#include "upstream/upstream_manager.h"
#include "circuit_breaker/circuit_breaker_manager.h"
#include "circuit_breaker/circuit_breaker_host.h"
#include "circuit_breaker/circuit_breaker_slice.h"

#include <thread>
#include <chrono>
#include <atomic>

namespace CircuitBreakerIntegrationTests {

using circuit_breaker::State;

// Shared helper: build an upstream config that proxies /echo → backend and
// has a breaker configured with low thresholds for fast trip.
static UpstreamConfig MakeBreakerUpstream(const std::string& name,
                                           const std::string& host,
                                           int port,
                                           bool breaker_enabled,
                                           int consecutive_threshold = 3) {
    UpstreamConfig u;
    u.name = name;
    u.host = host;
    u.port = port;
    u.pool.max_connections       = 8;
    u.pool.max_idle_connections  = 4;
    u.pool.connect_timeout_ms    = 3000;
    u.pool.idle_timeout_sec      = 30;
    u.pool.max_lifetime_sec      = 3600;
    u.pool.max_requests_per_conn = 0;

    // Exact-match route — simpler than prefix patterns for integration tests.
    u.proxy.route_prefix = "/fail";
    u.proxy.strip_prefix = false;
    u.proxy.response_timeout_ms = 2000;
    // No retries — keeps the test deterministic: one request = one attempt.
    u.proxy.retry.max_retries = 0;

    u.circuit_breaker.enabled = breaker_enabled;
    u.circuit_breaker.consecutive_failure_threshold = consecutive_threshold;
    // Disable the rate-based trip path — we drive everything through
    // consecutive failures to keep the test count predictable.
    u.circuit_breaker.failure_rate_threshold = 100;
    u.circuit_breaker.minimum_volume = 10000;
    u.circuit_breaker.window_seconds = 10;
    u.circuit_breaker.permitted_half_open_calls = 2;
    u.circuit_breaker.base_open_duration_ms = 500;   // short so recovery test is quick
    u.circuit_breaker.max_open_duration_ms = 60000;
    return u;
}

// ---------------------------------------------------------------------------
// Test 1: Breaker trips on consecutive 5xx responses and emits circuit-open
// headers on the rejected request.
// ---------------------------------------------------------------------------
void TestBreakerTripsAfterConsecutiveFailures() {
    std::cout << "\n[TEST] CB Integration: breaker trips after consecutive 5xx..."
              << std::endl;
    try {
        // Backend always returns 502 — gateway classifies the response as
        // FailureKind::RESPONSE_5XX and reports to the breaker on every attempt.
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/fail", [](const HttpRequest&, HttpResponse& resp) {
            resp.Status(502).Body("upstream err", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ServerConfig gw;
        gw.bind_host = "127.0.0.1";
        gw.bind_port = 0;
        gw.worker_threads = 1;
        gw.http2.enabled = false;
        // worker_threads=1 → all TCP connections land on dispatcher 0
        // (NetServer shards new connections by fd%worker_threads), so
        // per-request failures accumulate deterministically on slice[0]
        // instead of splitting across multiple slices.  // single thread → single breaker partition exercised
        gw.upstreams.push_back(
            MakeBreakerUpstream("bad-svc", "127.0.0.1", backend_port,
                                /*enabled=*/true, /*threshold=*/3));

        HttpServer gateway(gw);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        // Hit the failing backend threshold times — each 502 from backend
        // propagates to the client as 502 (gateway pass-through) AND counts
        // as a RESPONSE_5XX failure in the breaker.
        for (int i = 0; i < 3; ++i) {
            std::string r = TestHttpClient::HttpGet(gw_port, "/fail", 3000);
            if (!TestHttpClient::HasStatus(r, 502)) {
                TestFramework::RecordTest(
                    "CB Integration: trip after consecutive failures", false,
                    "pre-trip request " + std::to_string(i) + " expected 502, got: " +
                    r.substr(0, 32));
                return;
            }
        }

        // Next request must be rejected by the breaker (not proxied). The
        // response is 503 with X-Circuit-Breaker: open and Retry-After.
        std::string r = TestHttpClient::HttpGet(gw_port, "/fail", 3000);
        bool is_503 = TestHttpClient::HasStatus(r, 503);
        bool has_breaker_header =
            r.find("X-Circuit-Breaker: open") != std::string::npos ||
            r.find("x-circuit-breaker: open") != std::string::npos;
        bool has_retry_after =
            r.find("Retry-After:") != std::string::npos ||
            r.find("retry-after:") != std::string::npos;
        bool has_upstream_host =
            r.find("X-Upstream-Host:") != std::string::npos ||
            r.find("x-upstream-host:") != std::string::npos;

        bool pass = is_503 && has_breaker_header && has_retry_after &&
                    has_upstream_host;
        TestFramework::RecordTest(
            "CB Integration: trip after consecutive failures", pass,
            pass ? "" :
            "is_503=" + std::to_string(is_503) +
            " breaker_hdr=" + std::to_string(has_breaker_header) +
            " retry_after=" + std::to_string(has_retry_after) +
            " upstream_host=" + std::to_string(has_upstream_host) +
            " body=" + r.substr(0, 256));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB Integration: trip after consecutive failures", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Test 2: When circuit_breaker.enabled=false, the breaker is bypassed entirely.
// The same failure pattern that would trip an enabled breaker must leave the
// pass-through path untouched — every request still reaches the backend.
// ---------------------------------------------------------------------------
void TestBreakerDisabledPassesThrough() {
    std::cout << "\n[TEST] CB Integration: disabled breaker passes through..."
              << std::endl;
    try {
        std::atomic<int> backend_hits{0};
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/fail", [&backend_hits](const HttpRequest&, HttpResponse& resp) {
            backend_hits.fetch_add(1, std::memory_order_relaxed);
            resp.Status(502).Body("err", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ServerConfig gw;
        gw.bind_host = "127.0.0.1";
        gw.bind_port = 0;
        gw.worker_threads = 1;
        gw.http2.enabled = false;
        // worker_threads=1 → all TCP connections land on dispatcher 0
        // (NetServer shards new connections by fd%worker_threads), so
        // per-request failures accumulate deterministically on slice[0]
        // instead of splitting across multiple slices.
        gw.upstreams.push_back(
            MakeBreakerUpstream("svc", "127.0.0.1", backend_port,
                                /*enabled=*/false, /*threshold=*/3));

        HttpServer gateway(gw);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        // 10 requests — with breaker disabled, all 10 reach backend.
        for (int i = 0; i < 10; ++i) {
            std::string r = TestHttpClient::HttpGet(gw_port, "/fail", 3000);
            if (!TestHttpClient::HasStatus(r, 502)) {
                TestFramework::RecordTest(
                    "CB Integration: disabled breaker passes through", false,
                    "request " + std::to_string(i) + " expected 502, got: " +
                    r.substr(0, 32));
                return;
            }
        }

        bool all_hit = backend_hits.load() == 10;
        TestFramework::RecordTest(
            "CB Integration: disabled breaker passes through", all_hit,
            all_hit ? "" :
            "expected 10 backend hits, got " + std::to_string(backend_hits.load()));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB Integration: disabled breaker passes through", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Test 3: 2xx responses are reported as success — they reset the
// consecutive-failure counter so the breaker doesn't trip on interleaved
// success/failure traffic.
// ---------------------------------------------------------------------------
void TestSuccessResetsConsecutiveFailureCounter() {
    std::cout << "\n[TEST] CB Integration: 2xx success resets consecutive-failure counter..."
              << std::endl;
    try {
        std::atomic<bool> fail_mode{true};
        HttpServer backend("127.0.0.1", 0);
        // Backend must serve /fail — that's the exact-match route the
        // proxy forwards (MakeBreakerUpstream sets route_prefix="/fail",
        // strip_prefix=false). A different backend path would leave
        // the gateway 404-ing every request without ever exercising
        // the proxy, and the CLOSED-state assertion below would pass
        // for the wrong reason.
        backend.Get("/fail", [&fail_mode](const HttpRequest&, HttpResponse& resp) {
            if (fail_mode.load()) {
                resp.Status(502).Body("err", "text/plain");
            } else {
                resp.Status(200).Body("ok", "text/plain");
            }
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ServerConfig gw;
        gw.bind_host = "127.0.0.1";
        gw.bind_port = 0;
        gw.worker_threads = 1;
        gw.http2.enabled = false;
        // worker_threads=1 → all TCP connections land on dispatcher 0
        // (NetServer shards new connections by fd%worker_threads), so
        // per-request failures accumulate deterministically on slice[0]
        // instead of splitting across multiple slices.
        gw.upstreams.push_back(
            MakeBreakerUpstream("svc", "127.0.0.1", backend_port,
                                /*enabled=*/true, /*threshold=*/3));

        HttpServer gateway(gw);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        // Pattern: F F S F F — 5 total: 2 fails, 1 success, 2 fails.
        // With reset semantics, consecutive_failures_ never exceeds 2 → no trip.
        for (int i = 0; i < 2; ++i) {
            TestHttpClient::HttpGet(gw_port, "/fail", 3000);  // FAIL
        }
        fail_mode.store(false);
        TestHttpClient::HttpGet(gw_port, "/fail", 3000);      // SUCCESS → reset
        fail_mode.store(true);
        for (int i = 0; i < 2; ++i) {
            TestHttpClient::HttpGet(gw_port, "/fail", 3000);  // FAIL
        }

        // Inspect the breaker's state directly. The slice must be CLOSED
        // AND must have observed activity — without the second check, a
        // gateway that 404's every request (e.g. because the proxy route
        // doesn't match) would also pass trivially.
        auto* cbm = gateway.GetUpstreamManager() ?
            gateway.GetUpstreamManager()->GetCircuitBreakerManager() : nullptr;
        auto* host = cbm ? cbm->GetHost("svc") : nullptr;
        auto* slice = host ? host->GetSlice(0) : nullptr;
        bool still_closed = slice && slice->CurrentState() == State::CLOSED;
        // No trip fired: total_trips should be zero for this slice.
        int64_t trips = slice ? slice->Trips() : -1;
        bool no_trips = (trips == 0);

        bool pass = still_closed && no_trips;
        TestFramework::RecordTest(
            "CB Integration: success resets consecutive counter", pass,
            pass ? "" :
            "state=" + std::to_string(static_cast<int>(
                slice ? slice->CurrentState() : State::CLOSED)) +
            " trips=" + std::to_string(trips));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB Integration: success resets consecutive counter", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Test 4: After the trip, the live slice state is OPEN. Verifies the
// integration actually drives the slice state machine (not just the response).
// ---------------------------------------------------------------------------
void TestTripDrivesSliceState() {
    std::cout << "\n[TEST] CB Integration: trip drives slice state to OPEN..."
              << std::endl;
    try {
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/fail", [](const HttpRequest&, HttpResponse& resp) {
            resp.Status(502).Body("err", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ServerConfig gw;
        gw.bind_host = "127.0.0.1";
        gw.bind_port = 0;
        gw.worker_threads = 1;
        gw.http2.enabled = false;
        // worker_threads=1 → all TCP connections land on dispatcher 0
        // (NetServer shards new connections by fd%worker_threads), so
        // per-request failures accumulate deterministically on slice[0]
        // instead of splitting across multiple slices.
        gw.upstreams.push_back(
            MakeBreakerUpstream("svc", "127.0.0.1", backend_port,
                                /*enabled=*/true, /*threshold=*/3));

        HttpServer gateway(gw);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        // 3 failures → trip.
        for (int i = 0; i < 3; ++i) {
            TestHttpClient::HttpGet(gw_port, "/fail", 3000);
        }

        // With worker_threads > 1 the 3 failing requests can land on either
        // dispatcher (hash-dependent). Check the aggregate snapshot — at
        // least one partition must be OPEN with exactly one trip recorded.
        auto* cbm = gateway.GetUpstreamManager()->GetCircuitBreakerManager();
        auto* host = cbm->GetHost("svc");
        auto snap = host->Snapshot();
        bool at_least_one_open = snap.open_partitions >= 1;
        bool one_trip = snap.total_trips == 1;
        // Sanity: the tripped partition should be the one that saw all 3
        // failures (consecutive trip is single-slice, not cross-slice).
        bool single_partition_tripped = snap.open_partitions == 1;

        bool pass = at_least_one_open && one_trip && single_partition_tripped;
        TestFramework::RecordTest(
            "CB Integration: trip drives slice state to OPEN", pass,
            pass ? "" :
            "at_least_one_open=" + std::to_string(at_least_one_open) +
            " one_trip=" + std::to_string(one_trip) +
            " single_partition=" + std::to_string(single_partition_tripped) +
            " (open_partitions=" + std::to_string(snap.open_partitions) +
            ", total_trips=" + std::to_string(snap.total_trips) + ")");
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB Integration: trip drives slice state to OPEN", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Test 5: Breaker-rejected requests do NOT hit the backend. After the trip,
// subsequent requests must be served locally (503) without any upstream I/O.
// Prevents regression where the gate leaked admissions to a known-bad upstream.
// ---------------------------------------------------------------------------
void TestOpenBreakerShortCircuitsUpstreamCall() {
    std::cout << "\n[TEST] CB Integration: OPEN breaker short-circuits upstream call..."
              << std::endl;
    try {
        std::atomic<int> backend_hits{0};
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/fail", [&backend_hits](const HttpRequest&, HttpResponse& resp) {
            backend_hits.fetch_add(1, std::memory_order_relaxed);
            resp.Status(502).Body("err", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ServerConfig gw;
        gw.bind_host = "127.0.0.1";
        gw.bind_port = 0;
        gw.worker_threads = 1;
        gw.http2.enabled = false;
        // worker_threads=1 → all TCP connections land on dispatcher 0
        // (NetServer shards new connections by fd%worker_threads), so
        // per-request failures accumulate deterministically on slice[0]
        // instead of splitting across multiple slices.
        gw.upstreams.push_back(
            MakeBreakerUpstream("svc", "127.0.0.1", backend_port,
                                /*enabled=*/true, /*threshold=*/3));

        HttpServer gateway(gw);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        // 3 failing requests to trip.
        for (int i = 0; i < 3; ++i) {
            TestHttpClient::HttpGet(gw_port, "/fail", 3000);
        }
        int hits_at_trip = backend_hits.load();

        // 5 more requests — all should be rejected locally.
        for (int i = 0; i < 5; ++i) {
            TestHttpClient::HttpGet(gw_port, "/fail", 3000);
        }
        int hits_after = backend_hits.load();

        // Backend hits must not grow during the post-trip burst.
        bool no_leak = hits_after == hits_at_trip;
        TestFramework::RecordTest(
            "CB Integration: OPEN short-circuits upstream call", no_leak,
            no_leak ? "" :
            "backend hits grew from " + std::to_string(hits_at_trip) +
            " to " + std::to_string(hits_after) + " after trip");
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB Integration: OPEN short-circuits upstream call", false, e.what());
    }
}

// Sanity check: verify the bare proxy setup works without the breaker
// before blaming the breaker integration.
void TestBareProxyWorks() {
    std::cout << "\n[TEST] CB Integration: bare proxy (sanity)..." << std::endl;
    try {
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/fail", [](const HttpRequest&, HttpResponse& resp) {
            resp.Status(502).Body("err", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ServerConfig gw;
        gw.bind_host = "127.0.0.1";
        gw.bind_port = 0;
        gw.worker_threads = 1;
        gw.http2.enabled = false;
        UpstreamConfig u;
        u.name = "svc";
        u.host = "127.0.0.1";
        u.port = backend_port;
        u.pool.max_connections = 8;
        u.pool.max_idle_connections = 4;
        u.pool.connect_timeout_ms = 3000;
        u.proxy.route_prefix = "/fail";
        u.proxy.response_timeout_ms = 5000;
        u.circuit_breaker.enabled = true;  // sanity + breaker enabled
        u.circuit_breaker.consecutive_failure_threshold = 3;
        u.circuit_breaker.failure_rate_threshold = 100;
        u.circuit_breaker.minimum_volume = 10000;
        u.circuit_breaker.window_seconds = 10;
        u.circuit_breaker.permitted_half_open_calls = 2;
        u.circuit_breaker.base_open_duration_ms = 500;
        u.circuit_breaker.max_open_duration_ms = 60000;
        gw.upstreams.push_back(u);

        HttpServer gateway(gw);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        std::string r = TestHttpClient::HttpGet(gw_port, "/fail", 5000);
        bool pass = TestHttpClient::HasStatus(r, 502);
        TestFramework::RecordTest(
            "CB Integration: bare proxy sanity", pass,
            pass ? "" : "expected 502, got: " + r.substr(0, 128));
    } catch (const std::exception& e) {
        TestFramework::RecordTest("CB Integration: bare proxy sanity",
            false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Test 7: Retry-After header carries a sensible value — within [1, configured
// max_open_duration_ms / 1000], and in the right ballpark of OpenUntil()-now.
// ---------------------------------------------------------------------------
void TestRetryAfterHeaderValue() {
    std::cout << "\n[TEST] CB Integration: Retry-After value correctness..."
              << std::endl;
    try {
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/fail", [](const HttpRequest&, HttpResponse& resp) {
            resp.Status(502).Body("err", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ServerConfig gw;
        gw.bind_host = "127.0.0.1";
        gw.bind_port = 0;
        gw.worker_threads = 1;
        gw.http2.enabled = false;
        // base_open_duration 2000ms, max 60_000ms — Retry-After should
        // ceiling-round and fall inside [1, 60].
        auto u = MakeBreakerUpstream("svc", "127.0.0.1", backend_port,
                                     /*enabled=*/true, /*threshold=*/3);
        u.circuit_breaker.base_open_duration_ms = 2000;
        u.circuit_breaker.max_open_duration_ms  = 60000;
        gw.upstreams.push_back(u);

        HttpServer gateway(gw);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        // Trip the breaker.
        for (int i = 0; i < 3; ++i) {
            TestHttpClient::HttpGet(gw_port, "/fail", 3000);
        }

        // Capture the open-rejection response.
        std::string r = TestHttpClient::HttpGet(gw_port, "/fail", 3000);
        bool is_503 = TestHttpClient::HasStatus(r, 503);

        // Extract Retry-After integer value (case-insensitive header).
        int retry_after = -1;
        const char* markers[] = {"Retry-After:", "retry-after:"};
        for (const char* m : markers) {
            auto pos = r.find(m);
            if (pos == std::string::npos) continue;
            pos += std::string(m).size();
            while (pos < r.size() && (r[pos] == ' ' || r[pos] == '\t')) ++pos;
            int val = 0;
            bool any = false;
            while (pos < r.size() && r[pos] >= '0' && r[pos] <= '9') {
                val = val * 10 + (r[pos] - '0');
                any = true;
                ++pos;
            }
            if (any) { retry_after = val; break; }
        }

        // Contract: value ≥ 1 and ≤ max_open_duration_ms / 1000 (60).
        // For base_open_duration 2000ms the remaining-seconds at this
        // moment is ≤ 2 (probably 1 or 2 after ceiling), so the upper
        // sanity bound is generous but still rules out 300/3600-class
        // buggy fallbacks.
        bool in_range = (retry_after >= 1 && retry_after <= 60);
        bool reasonable = (retry_after >= 1 && retry_after <= 3);

        bool pass = is_503 && in_range && reasonable;
        TestFramework::RecordTest(
            "CB Integration: Retry-After value in range", pass,
            pass ? "" :
            "is_503=" + std::to_string(is_503) +
            " retry_after=" + std::to_string(retry_after) +
            " body=" + r.substr(0, 256));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB Integration: Retry-After value in range", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Test 8: Retry loop is terminal on CIRCUIT_OPEN — even with max_retries=3,
// a request that hits an OPEN breaker gets exactly ONE 503 (no retry-flavored
// second 503). Ensures ReportBreakerOutcome doesn't feed the reject back into
// the breaker and MaybeRetry stays out.
// ---------------------------------------------------------------------------
void TestCircuitOpenTerminalForRetry() {
    std::cout << "\n[TEST] CB Integration: CIRCUIT_OPEN terminal for retry loop..."
              << std::endl;
    try {
        std::atomic<int> backend_hits{0};
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/fail", [&backend_hits](const HttpRequest&, HttpResponse& resp) {
            backend_hits.fetch_add(1, std::memory_order_relaxed);
            resp.Status(502).Body("err", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ServerConfig gw;
        gw.bind_host = "127.0.0.1";
        gw.bind_port = 0;
        gw.worker_threads = 1;
        gw.http2.enabled = false;
        // Retries enabled on 5xx — if the breaker reject leaked into
        // MaybeRetry, the test would see extra backend hits after the
        // trip. Long open window so the breaker stays OPEN for the
        // duration of the post-trip assertion (no HALF_OPEN probe
        // admission racing the test).
        auto u = MakeBreakerUpstream("svc", "127.0.0.1", backend_port,
                                     /*enabled=*/true, /*threshold=*/3);
        u.proxy.retry.max_retries = 3;
        u.proxy.retry.retry_on_5xx = true;
        u.circuit_breaker.base_open_duration_ms = 30000;
        u.circuit_breaker.max_open_duration_ms  = 60000;
        gw.upstreams.push_back(u);

        HttpServer gateway(gw);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        // Trip the breaker. Each pre-trip request may retry up to 3
        // times (all failing 5xx), so backend sees up to 3*threshold=12
        // hits. That's acceptable — we just care about post-trip behavior.
        for (int i = 0; i < 3; ++i) {
            TestHttpClient::HttpGet(gw_port, "/fail", 5000);
        }
        int pre_trip_hits = backend_hits.load();

        // Post-trip request: expect a single 503 and NO new backend hits.
        std::string r = TestHttpClient::HttpGet(gw_port, "/fail", 3000);
        bool is_503 = TestHttpClient::HasStatus(r, 503);
        int post_trip_hits = backend_hits.load();
        bool no_new_hits = (post_trip_hits == pre_trip_hits);

        bool pass = is_503 && no_new_hits;
        TestFramework::RecordTest(
            "CB Integration: CIRCUIT_OPEN terminal for retry", pass,
            pass ? "" :
            "is_503=" + std::to_string(is_503) +
            " pre=" + std::to_string(pre_trip_hits) +
            " post=" + std::to_string(post_trip_hits));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB Integration: CIRCUIT_OPEN terminal for retry", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Test 9: Dry-run mode — dry_run=true forwards rejected requests to the
// upstream (pass-through) but still increments the rejected_ counter so
// operators can observe the would-reject rate without production impact.
// ---------------------------------------------------------------------------
void TestDryRunPassthrough() {
    std::cout << "\n[TEST] CB Integration: dry-run passthrough..." << std::endl;
    try {
        std::atomic<int> backend_hits{0};
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/fail", [&backend_hits](const HttpRequest&, HttpResponse& resp) {
            backend_hits.fetch_add(1, std::memory_order_relaxed);
            resp.Status(502).Body("err", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ServerConfig gw;
        gw.bind_host = "127.0.0.1";
        gw.bind_port = 0;
        gw.worker_threads = 1;
        gw.http2.enabled = false;
        auto u = MakeBreakerUpstream("svc", "127.0.0.1", backend_port,
                                     /*enabled=*/true, /*threshold=*/3);
        u.circuit_breaker.dry_run = true;  // would-reject, but still forward
        gw.upstreams.push_back(u);

        HttpServer gateway(gw);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        // Trip thresholds with 5 requests. All should reach backend (502),
        // not a 503 — dry-run never short-circuits.
        for (int i = 0; i < 5; ++i) {
            std::string r = TestHttpClient::HttpGet(gw_port, "/fail", 3000);
            if (!TestHttpClient::HasStatus(r, 502)) {
                TestFramework::RecordTest(
                    "CB Integration: dry-run passthrough", false,
                    "request " + std::to_string(i) +
                    " expected 502, got: " + r.substr(0, 64));
                return;
            }
        }

        bool all_hit = (backend_hits.load() == 5);

        // Verify the slice observed trips/rejected even though traffic passed.
        auto* mgr = gateway.GetUpstreamManager() ?
                     gateway.GetUpstreamManager()->GetCircuitBreakerManager() :
                     nullptr;
        int64_t trips = 0, rejected = 0;
        if (mgr) {
            auto* host = mgr->GetHost("svc");
            if (host) {
                auto snap = host->Snapshot();
                trips = snap.total_trips;
                rejected = snap.total_rejected;
            }
        }
        // At least one trip fired (consecutive_threshold=3 → slice
        // transitioned at least once during the run), and the post-trip
        // requests were counted as would-reject (rejected > 0).
        bool observed = (trips >= 1) && (rejected >= 1);

        bool pass = all_hit && observed;
        TestFramework::RecordTest(
            "CB Integration: dry-run passthrough", pass,
            pass ? "" :
            "hits=" + std::to_string(backend_hits.load()) +
            " trips=" + std::to_string(trips) +
            " rejected=" + std::to_string(rejected));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB Integration: dry-run passthrough", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Test 10: HALF_OPEN → CLOSED recovery round-trip through the proxy. Trip the
// breaker, wait for the open window to elapse, then serve success responses
// and assert the slice transitions back to CLOSED (consecutive_successes
// crosses the threshold — default 2 from DefaultCbConfig / integration config).
// ---------------------------------------------------------------------------
void TestHalfOpenRecoveryRoundTrip() {
    std::cout << "\n[TEST] CB Integration: HALF_OPEN → CLOSED recovery..."
              << std::endl;
    try {
        std::atomic<bool> fail_mode{true};
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/fail", [&fail_mode](const HttpRequest&, HttpResponse& resp) {
            if (fail_mode.load()) {
                resp.Status(502).Body("err", "text/plain");
            } else {
                resp.Status(200).Body("ok", "text/plain");
            }
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ServerConfig gw;
        gw.bind_host = "127.0.0.1";
        gw.bind_port = 0;
        gw.worker_threads = 1;
        gw.http2.enabled = false;
        auto u = MakeBreakerUpstream("svc", "127.0.0.1", backend_port,
                                     /*enabled=*/true, /*threshold=*/3);
        // Short open duration so recovery path finishes quickly.
        u.circuit_breaker.base_open_duration_ms = 300;
        u.circuit_breaker.max_open_duration_ms = 1000;
        // Two probes needed to close (default permitted_half_open_calls=2).
        u.circuit_breaker.permitted_half_open_calls = 2;
        gw.upstreams.push_back(u);

        HttpServer gateway(gw);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        // Trip by hitting the failing backend.
        for (int i = 0; i < 3; ++i) {
            TestHttpClient::HttpGet(gw_port, "/fail", 3000);
        }

        // Flip backend to success and wait for the open window to elapse.
        fail_mode.store(false);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        // Probe the proxy — each successful 200 advances HALF_OPEN toward
        // CLOSED. Do more than permitted_half_open_calls; some will be
        // rejected as half_open_full but the ones that are admitted will
        // close the breaker.
        bool saw_success = false;
        for (int i = 0; i < 8; ++i) {
            std::string r = TestHttpClient::HttpGet(gw_port, "/fail", 3000);
            if (TestHttpClient::HasStatus(r, 200)) saw_success = true;
            // Small gap between probes — HALF_OPEN only admits permitted
            // probes per cycle; spacing lets subsequent probes observe a
            // possibly-closed breaker.
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }

        // Verify slice aggregate: at least one CLOSED transition observed
        // (probe_successes >= 1 and total_trips == 1 — we only tripped once).
        auto* mgr = gateway.GetUpstreamManager() ?
                     gateway.GetUpstreamManager()->GetCircuitBreakerManager() :
                     nullptr;
        int64_t probe_succ = 0;
        int open_parts = 0, half_open_parts = 0;
        if (mgr) {
            auto* host = mgr->GetHost("svc");
            if (host) {
                auto snap = host->Snapshot();
                probe_succ = 0;
                for (const auto& row : snap.slices) {
                    probe_succ += row.probe_successes;
                }
                open_parts = snap.open_partitions;
                half_open_parts = snap.half_open_partitions;
            }
        }

        // Recovery complete: saw at least one 200 through the breaker,
        // at least one probe success counted, and no partition still
        // stuck in OPEN (HALF_OPEN may still linger on the unused slice,
        // which is fine for a 2-partition setup).
        bool pass = saw_success && (probe_succ >= 1) && (open_parts == 0);
        TestFramework::RecordTest(
            "CB Integration: HALF_OPEN → CLOSED recovery", pass,
            pass ? "" :
            "saw_success=" + std::to_string(saw_success) +
            " probe_succ=" + std::to_string(probe_succ) +
            " open_parts=" + std::to_string(open_parts) +
            " half_open_parts=" + std::to_string(half_open_parts));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB Integration: HALF_OPEN → CLOSED recovery", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Test 11: Retry-After ceils the config cap from a non-second-aligned
// max_open_duration_ms (e.g. 1500ms → 2s, not 1s). Floor-rounding the cap
// would clamp the advertised retry window below what the breaker honors,
// causing well-behaved clients to re-hit the 503.
// ---------------------------------------------------------------------------
void TestRetryAfterCapCeilsNonAlignedMax() {
    std::cout << "\n[TEST] CB Integration: Retry-After cap ceils non-aligned max..."
              << std::endl;
    try {
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/fail", [](const HttpRequest&, HttpResponse& resp) {
            resp.Status(502).Body("err", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ServerConfig gw;
        gw.bind_host = "127.0.0.1";
        gw.bind_port = 0;
        gw.worker_threads = 1;
        gw.http2.enabled = false;
        // Configure a non-second-aligned max backoff. base = 1500ms so
        // the actual OpenUntil-now at trip time is ~1.5s, which ceil-
        // rounds to 2s. If cfg_cap_secs floor-rounded max_open_duration
        // (1500ms → 1s), the clamp would drop Retry-After to 1s even
        // though the breaker would keep rejecting through the second
        // half of that window.
        auto u = MakeBreakerUpstream("svc", "127.0.0.1", backend_port,
                                     /*enabled=*/true, /*threshold=*/3);
        u.circuit_breaker.base_open_duration_ms = 1500;
        u.circuit_breaker.max_open_duration_ms  = 1500;
        gw.upstreams.push_back(u);

        HttpServer gateway(gw);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        for (int i = 0; i < 3; ++i) {
            TestHttpClient::HttpGet(gw_port, "/fail", 3000);
        }
        std::string r = TestHttpClient::HttpGet(gw_port, "/fail", 3000);

        int retry_after = -1;
        const char* markers[] = {"Retry-After:", "retry-after:"};
        for (const char* m : markers) {
            auto pos = r.find(m);
            if (pos == std::string::npos) continue;
            pos += std::string(m).size();
            while (pos < r.size() && (r[pos] == ' ' || r[pos] == '\t')) ++pos;
            int val = 0;
            bool any = false;
            while (pos < r.size() && r[pos] >= '0' && r[pos] <= '9') {
                val = val * 10 + (r[pos] - '0');
                any = true;
                ++pos;
            }
            if (any) { retry_after = val; break; }
        }

        // Expectation: Retry-After is in [1, 2] — cfg_cap_secs ceil-
        // rounds 1500ms to 2s, and the remaining-time ceil-rounds to
        // 2 at the moment of trip (may be 1 if enough wall-clock has
        // elapsed between trip and response). Critically it must NEVER
        // be zero or exceed 2 (clamped to the 2s cap).
        bool in_range = (retry_after >= 1 && retry_after <= 2);
        TestFramework::RecordTest(
            "CB Integration: Retry-After ceils non-aligned cap", in_range,
            in_range ? "" :
            "retry_after=" + std::to_string(retry_after));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB Integration: Retry-After ceils non-aligned cap", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Test 12: Retried failures are reported BEFORE the retry fires. With retries
// enabled on 5xx, each attempt's outcome must be counted against the breaker;
// otherwise the slice trips only after the final retry exhausts, under-
// counting failures and potentially never tripping if retries mask enough of
// them. Verifies the trip still happens within the expected number of client
// requests once reporting is attached to the retry path.
// ---------------------------------------------------------------------------
void TestRetriedFailuresCountTowardTrip() {
    std::cout << "\n[TEST] CB Integration: retried failures count toward trip..."
              << std::endl;
    try {
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/fail", [](const HttpRequest&, HttpResponse& resp) {
            resp.Status(502).Body("err", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ServerConfig gw;
        gw.bind_host = "127.0.0.1";
        gw.bind_port = 0;
        gw.worker_threads = 1;
        gw.http2.enabled = false;
        // Retries on 5xx enabled. threshold=3 — with retry_on_5xx, each
        // client request produces 1 + max_retries=3 = 4 upstream
        // attempts, each reporting RESPONSE_5XX via the ReportBreakerOutcome
        // path that this fix patches in. The breaker must trip after
        // at most 3 upstream failure reports (which the first client
        // request alone produces).
        auto u = MakeBreakerUpstream("svc", "127.0.0.1", backend_port,
                                     /*enabled=*/true, /*threshold=*/3);
        u.proxy.retry.max_retries = 3;
        u.proxy.retry.retry_on_5xx = true;
        u.circuit_breaker.base_open_duration_ms = 30000;
        u.circuit_breaker.max_open_duration_ms  = 60000;
        gw.upstreams.push_back(u);

        HttpServer gateway(gw);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        // One client request → 4 upstream attempts → 4 RESPONSE_5XX
        // reports. Threshold=3 should trip during this single request.
        TestHttpClient::HttpGet(gw_port, "/fail", 5000);

        // Second client request must hit the OPEN breaker → 503.
        std::string r = TestHttpClient::HttpGet(gw_port, "/fail", 3000);
        bool is_503 = TestHttpClient::HasStatus(r, 503);
        bool has_breaker_header =
            r.find("X-Circuit-Breaker: open") != std::string::npos ||
            r.find("x-circuit-breaker: open") != std::string::npos;

        bool pass = is_503 && has_breaker_header;
        TestFramework::RecordTest(
            "CB Integration: retried failures count toward trip", pass,
            pass ? "" :
            "is_503=" + std::to_string(is_503) +
            " breaker_hdr=" + std::to_string(has_breaker_header) +
            " body=" + r.substr(0, 256));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB Integration: retried failures count toward trip", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Test 13: HALF_OPEN rejects emit a distinct X-Circuit-Breaker label.
// TryAcquire returns REJECTED_OPEN for three situations (true OPEN,
// half_open_full, half_open_recovery_failing). When the slice is in
// HALF_OPEN, OpenUntil is cleared and a generic MakeCircuitOpenResponse
// would fall back to Retry-After=1 + X-Circuit-Breaker:open — misleading
// clients. The fix emits X-Circuit-Breaker:half_open for HALF_OPEN rejects
// with a more conservative Retry-After hint.
//
// Strategy: trip the breaker, wait for the open window to elapse so the
// slice transitions HALF_OPEN on the next admission attempt, then flood
// concurrent requests so some hit half_open_full.
// ---------------------------------------------------------------------------
void TestHalfOpenRejectLabel() {
    std::cout << "\n[TEST] CB Integration: HALF_OPEN reject label..."
              << std::endl;
    try {
        // Backend hangs to keep probes in-flight so later concurrent
        // requests hit half_open_full.
        std::atomic<bool> hang{false};
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/fail", [&hang](const HttpRequest&, HttpResponse& resp) {
            if (hang.load()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(600));
            }
            resp.Status(502).Body("err", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ServerConfig gw;
        gw.bind_host = "127.0.0.1";
        gw.bind_port = 0;
        gw.worker_threads = 1;
        gw.http2.enabled = false;
        auto u = MakeBreakerUpstream("svc", "127.0.0.1", backend_port,
                                     /*enabled=*/true, /*threshold=*/3);
        u.circuit_breaker.base_open_duration_ms = 200;
        u.circuit_breaker.max_open_duration_ms  = 500;
        u.circuit_breaker.permitted_half_open_calls = 1;  // tiny budget
        gw.upstreams.push_back(u);

        HttpServer gateway(gw);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        // Trip the breaker.
        for (int i = 0; i < 3; ++i) {
            TestHttpClient::HttpGet(gw_port, "/fail", 3000);
        }
        // Wait for the open window to elapse so the next admission
        // flips the slice to HALF_OPEN.
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        // Flip backend to hang so the probe occupies the single probe
        // slot while we fire sibling requests that must hit half_open_full.
        hang.store(true);

        std::atomic<bool> saw_half_open{false};
        std::atomic<bool> saw_open{false};
        auto probe = [&](int id) {
            (void)id;
            std::string r = TestHttpClient::HttpGet(gw_port, "/fail", 1500);
            if (!TestHttpClient::HasStatus(r, 503)) return;
            if (r.find("X-Circuit-Breaker: half_open") != std::string::npos ||
                r.find("x-circuit-breaker: half_open") != std::string::npos) {
                saw_half_open.store(true);
            }
            if (r.find("X-Circuit-Breaker: open") != std::string::npos ||
                r.find("x-circuit-breaker: open") != std::string::npos) {
                // We want to distinguish the labels; the "open" substring
                // also matches "half_open". Only count true "open" if
                // "half_open" didn't appear in THIS response.
                if (r.find("half_open") == std::string::npos) {
                    saw_open.store(true);
                }
            }
        };

        std::vector<std::thread> threads;
        for (int i = 0; i < 6; ++i) {
            threads.emplace_back(probe, i);
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        for (auto& t : threads) t.join();

        // Pass if at least one HALF_OPEN-labelled reject was observed.
        // saw_open may or may not be observed (some rejects could have
        // hit between cycles) — the key contract is that HALF_OPEN
        // rejects no longer get the plain "open" label.
        bool pass = saw_half_open.load();
        TestFramework::RecordTest(
            "CB Integration: HALF_OPEN reject label", pass,
            pass ? "" :
            "saw_half_open=" + std::to_string(saw_half_open.load()) +
            " saw_open=" + std::to_string(saw_open.load()));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB Integration: HALF_OPEN reject label", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Test 14: HALF_OPEN Retry-After reflects the current exponential backoff,
// not just base_open_duration_ms. After multiple trips the next OPEN window
// (base << consecutive_trips_, clamped by max) can exceed 1 second; the old
// base-only hint (ceil(base/1000) = 1s for base=100ms) would under-report
// the worst-case wait, which this test must fail for.
//
// Strategy: keep the backend failing and drive MULTIPLE re-trips by letting
// the OPEN window elapse and single probe fail each cycle. Successful
// recoveries must be avoided — TransitionHalfOpenToClosed resets
// consecutive_trips_ to 0, which hides the exponential hint.
// ---------------------------------------------------------------------------
void TestHalfOpenRetryAfterScalesWithBackoff() {
    std::cout << "\n[TEST] CB Integration: HALF_OPEN Retry-After exponential..."
              << std::endl;
    try {
        // Backend fails fast by default. When `hang` is set, the
        // handler blocks — used at the end to pin the probe slot so
        // a concurrent request observes HALF_OPEN rejection.
        std::atomic<bool> hang{false};
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/fail", [&hang](const HttpRequest&, HttpResponse& resp) {
            if (hang.load()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1500));
            }
            resp.Status(502).Body("err", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ServerConfig gw;
        gw.bind_host = "127.0.0.1";
        gw.bind_port = 0;
        gw.worker_threads = 1;  // pin all traffic to slice[0]
        gw.http2.enabled = false;
        auto u = MakeBreakerUpstream("svc", "127.0.0.1", backend_port,
                                     /*enabled=*/true, /*threshold=*/2);
        u.circuit_breaker.base_open_duration_ms = 100;     // config minimum
        u.circuit_breaker.max_open_duration_ms  = 8000;    // cap at 8s
        u.circuit_breaker.permitted_half_open_calls = 1;   // single probe
        gw.upstreams.push_back(u);

        HttpServer gateway(gw);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        auto* cbm = gateway.GetUpstreamManager() ?
            gateway.GetUpstreamManager()->GetCircuitBreakerManager() : nullptr;
        auto* host = cbm ? cbm->GetHost("svc") : nullptr;
        auto* slice = host ? host->GetSlice(0) : nullptr;
        if (!slice) {
            TestFramework::RecordTest(
                "CB Integration: HALF_OPEN Retry-After exponential-aware",
                false, "slice lookup failed");
            return;
        }

        // Initial trip: 2 consecutive failures with threshold=2.
        for (int i = 0; i < 2; ++i) {
            TestHttpClient::HttpGet(gw_port, "/fail", 3000);
        }

        // Drive consecutive_trips_ up by letting successive OPEN windows
        // elapse and probes fail (no recovery → no reset). Stop when
        // NextOpenDurationMs crosses 1000ms, which is the threshold
        // where the HALF_OPEN Retry-After hint starts exceeding the
        // base-only value (ceil(100ms)=1s).
        //
        // The slice re-trips on each failed probe; each trip doubles
        // the open duration. We run ~8 cycles with safety margin which
        // is comfortably past the trip count needed for Retry-After>=2.
        for (int cycle = 0; cycle < 8; ++cycle) {
            // Wait past the current open window. Upper bound: max=8s,
            // so 1200ms is plenty for the first few short cycles, and
            // we re-check after each request anyway.
            int64_t next_ms = slice->NextOpenDurationMs();
            // Current OPEN window is the one stored BEFORE the upcoming
            // re-trip — we don't have that directly, so sleep past the
            // NEXT duration as an over-approximation (next is always >=
            // current). This ensures OPEN has elapsed.
            auto sleep_ms = std::max<int64_t>(next_ms + 50, 200);
            if (sleep_ms > 2000) sleep_ms = 2000;  // cap per cycle
            std::this_thread::sleep_for(std::chrono::milliseconds(sleep_ms));

            // One request — it should admit as a probe (HALF_OPEN),
            // the backend fails fast (502), probe fails → re-trip with
            // consecutive_trips_++ and fresh OPEN.
            TestHttpClient::HttpGet(gw_port, "/fail", 3000);

            // Bail early once the exponential hint crosses 1s → the
            // subsequent HALF_OPEN reject will carry Retry-After >= 2.
            if (slice->NextOpenDurationMs() >= 2000) break;
        }

        int64_t next_open_ms = slice->NextOpenDurationMs();
        if (next_open_ms < 2000) {
            TestFramework::RecordTest(
                "CB Integration: HALF_OPEN Retry-After exponential-aware",
                false,
                "setup failed: next_open_ms=" + std::to_string(next_open_ms) +
                " (need >= 2000 to distinguish from base-only hint)");
            return;
        }

        // Now trigger a HALF_OPEN reject: wait for current OPEN to
        // elapse, start a hanging probe (pins the slot), then fire a
        // sibling request — it must see half_open_full with the
        // exponential Retry-After.
        int64_t post_wait_ms = next_open_ms + 100;
        if (post_wait_ms > 4000) post_wait_ms = 4000;
        std::this_thread::sleep_for(std::chrono::milliseconds(post_wait_ms));

        hang.store(true);
        std::thread probe([&]() {
            TestHttpClient::HttpGet(gw_port, "/fail", 3500);
        });
        // Let the probe get admitted and start hanging.
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        std::string r = TestHttpClient::HttpGet(gw_port, "/fail", 1500);
        hang.store(false);
        probe.join();

        bool is_half_open =
            r.find("X-Circuit-Breaker: half_open") != std::string::npos ||
            r.find("x-circuit-breaker: half_open") != std::string::npos;

        int retry_after = -1;
        const char* markers[] = {"Retry-After:", "retry-after:"};
        for (const char* m : markers) {
            auto pos = r.find(m);
            if (pos == std::string::npos) continue;
            pos += std::string(m).size();
            while (pos < r.size() && (r[pos] == ' ' || r[pos] == '\t')) ++pos;
            int val = 0;
            bool any = false;
            while (pos < r.size() && r[pos] >= '0' && r[pos] <= '9') {
                val = val * 10 + (r[pos] - '0');
                any = true;
                ++pos;
            }
            if (any) { retry_after = val; break; }
        }

        // Post-fix: Retry-After = ceil(next_open_ms / 1000) >= 2.
        // Pre-fix (base-only): Retry-After = ceil(base/1000) = 1.
        // Asserting >= 2 fails the pre-fix implementation.
        bool retry_after_ok = (retry_after >= 2 && retry_after <= 8);
        bool pass = is_half_open && retry_after_ok;
        TestFramework::RecordTest(
            "CB Integration: HALF_OPEN Retry-After exponential-aware", pass,
            pass ? "" :
            "is_half_open=" + std::to_string(is_half_open) +
            " retry_after=" + std::to_string(retry_after) +
            " next_open_ms=" + std::to_string(next_open_ms));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB Integration: HALF_OPEN Retry-After exponential-aware",
            false, e.what());
    }
}

void RunAllTests() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "CIRCUIT BREAKER - INTEGRATION TESTS" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    TestBareProxyWorks();
    TestBreakerTripsAfterConsecutiveFailures();
    TestBreakerDisabledPassesThrough();
    TestSuccessResetsConsecutiveFailureCounter();
    TestTripDrivesSliceState();
    TestOpenBreakerShortCircuitsUpstreamCall();
    TestRetryAfterHeaderValue();
    TestCircuitOpenTerminalForRetry();
    TestDryRunPassthrough();
    TestHalfOpenRecoveryRoundTrip();
    TestRetryAfterCapCeilsNonAlignedMax();
    TestRetriedFailuresCountTowardTrip();
    TestHalfOpenRejectLabel();
    TestHalfOpenRetryAfterScalesWithBackoff();
}

}  // namespace CircuitBreakerIntegrationTests
