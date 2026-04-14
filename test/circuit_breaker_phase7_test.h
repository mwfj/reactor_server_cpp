#pragma once

// Phase 7 integration tests: observability — counter accuracy, snapshot
// API correctness, and log emission.
//
// Phases 2-6 each added counters and log lines as a side effect of their
// functional work. Phase 7 locks those in as regressions:
//
//   * Counters (§11.2): trips, rejected, probe_successes, probe_failures,
//     retries_rejected surface through CircuitBreakerManager::SnapshotAll.
//   * Snapshot API (§11.3): per-slice rows aggregate into host-level
//     totals; host-level fields (retries_in_flight / retries_rejected /
//     in_flight) reflect the owning RetryBudget.
//   * Logs (§11.1): the CLOSED→OPEN trip emits the full-context message
//     including trigger, consecutive_failures, window_total,
//     window_fail_rate, open_for_ms, and consecutive_trips.
//
// The log-emission test attaches a spdlog ring-buffer sink to the logger
// for the duration of the test, triggers a trip, then asserts the
// captured messages contain the expected fields. No log file I/O.

#include "test_framework.h"
#include "test_server_runner.h"
#include "http_test_client.h"
#include "http/http_server.h"
#include "config/server_config.h"
#include "upstream/upstream_manager.h"
#include "circuit_breaker/circuit_breaker_manager.h"
#include "circuit_breaker/circuit_breaker_host.h"
#include "circuit_breaker/circuit_breaker_slice.h"
#include "log/logger.h"
#include "spdlog/sinks/ringbuffer_sink.h"

#include <thread>
#include <chrono>
#include <atomic>
#include <string>
#include <vector>
#include <memory>

namespace CircuitBreakerPhase7Tests {

using circuit_breaker::State;

static UpstreamConfig MakeObservUpstream(const std::string& name,
                                          const std::string& host,
                                          int port,
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

    u.proxy.route_prefix = "/fail";
    u.proxy.strip_prefix = false;
    u.proxy.response_timeout_ms = 2000;
    u.proxy.retry.max_retries = 0;

    u.circuit_breaker.enabled = true;
    u.circuit_breaker.consecutive_failure_threshold = consecutive_threshold;
    u.circuit_breaker.failure_rate_threshold = 100;
    u.circuit_breaker.minimum_volume = 10000;
    u.circuit_breaker.window_seconds = 10;
    u.circuit_breaker.permitted_half_open_calls = 2;
    // Long open duration — keep the slice OPEN so post-trip assertions
    // don't race a HALF_OPEN transition.
    u.circuit_breaker.base_open_duration_ms = 30000;
    u.circuit_breaker.max_open_duration_ms  = 60000;
    return u;
}

// ---------------------------------------------------------------------------
// Test 1: Snapshot API reflects per-slice trip/rejected counters and
// host-level aggregates. Drives N+1 requests against a backend that always
// 502s (N to trip, 1 more that the OPEN slice short-circuits) and asserts
// the snapshot shows total_trips >= 1, total_rejected >= 1,
// open_partitions >= 1.
// ---------------------------------------------------------------------------
void TestSnapshotReflectsCounters() {
    std::cout << "\n[TEST] CB Phase 7: snapshot reflects counters..."
              << std::endl;
    try {
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/fail", [](const HttpRequest&, HttpResponse& resp) {
            resp.Status(502).Body("upstream-err", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ServerConfig gw;
        gw.bind_host = "127.0.0.1";
        gw.bind_port = 0;
        gw.worker_threads = 1;
        gw.http2.enabled = false;

        auto u = MakeObservUpstream("svc", "127.0.0.1", backend_port,
                                    /*threshold=*/3);
        gw.upstreams.push_back(u);

        HttpServer gateway(gw);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        // Trip (3 failures), then 2 more to accumulate rejected counter.
        for (int i = 0; i < 3; ++i) {
            TestHttpClient::HttpGet(gw_port, "/fail", 3000);
        }
        for (int i = 0; i < 2; ++i) {
            TestHttpClient::HttpGet(gw_port, "/fail", 3000);
        }

        auto* cbm = gateway.GetUpstreamManager()->GetCircuitBreakerManager();
        if (!cbm) {
            TestFramework::RecordTest(
                "CB Phase 7: snapshot reflects counters", false,
                "no circuit breaker manager attached");
            return;
        }
        auto snaps = cbm->SnapshotAll();
        bool found = false;
        int64_t trips = 0, rejected = 0, probe_s = 0, probe_f = 0;
        int open_parts = 0;
        for (const auto& s : snaps) {
            if (s.service_name == "svc") {
                trips = s.total_trips;
                rejected = s.total_rejected;
                open_parts = s.open_partitions;
                for (const auto& row : s.slices) {
                    probe_s += row.probe_successes;
                    probe_f += row.probe_failures;
                }
                found = true;
                break;
            }
        }

        bool pass = found
                    && trips >= 1
                    && rejected >= 2   // 2 post-trip short-circuits
                    && open_parts >= 1
                    && probe_s == 0    // never entered HALF_OPEN
                    && probe_f == 0;
        TestFramework::RecordTest(
            "CB Phase 7: snapshot reflects counters", pass,
            pass ? "" :
            "found=" + std::to_string(found) +
            " trips=" + std::to_string(trips) +
            " rejected=" + std::to_string(rejected) +
            " open_parts=" + std::to_string(open_parts) +
            " probe_s=" + std::to_string(probe_s) +
            " probe_f=" + std::to_string(probe_f));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB Phase 7: snapshot reflects counters", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Test 2: The CLOSED→OPEN trip log emits the §11.1 full-context message.
// Attaches a spdlog ringbuffer_sink to the shared logger, triggers a trip,
// then inspects the captured messages for the key tokens. The sink is
// removed before the test returns so it doesn't affect later tests.
// ---------------------------------------------------------------------------
void TestTripLogEmission() {
    std::cout << "\n[TEST] CB Phase 7: trip log emission..." << std::endl;
    try {
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/fail", [](const HttpRequest&, HttpResponse& resp) {
            resp.Status(502).Body("upstream-err", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ServerConfig gw;
        gw.bind_host = "127.0.0.1";
        gw.bind_port = 0;
        gw.worker_threads = 1;
        gw.http2.enabled = false;

        auto u = MakeObservUpstream("svc-log", "127.0.0.1", backend_port,
                                    /*threshold=*/2);
        gw.upstreams.push_back(u);

        // `HttpServer` construction calls `logging::Init()` which rebuilds
        // the default logger via `spdlog::set_default_logger`. Any sink
        // attached BEFORE that point lands on a stale logger. Attach the
        // ringbuffer sink AFTER the last HttpServer construction so it
        // captures the live logger's output.
        HttpServer gateway(gw);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        auto ring = std::make_shared<
            spdlog::sinks::ringbuffer_sink_mt>(1024);
        auto logger = logging::Get();
        auto prev_level = logger->level();
        logger->set_level(spdlog::level::debug);
        logger->sinks().push_back(ring);

        struct SinkGuard {
            std::shared_ptr<spdlog::logger> logger;
            std::shared_ptr<spdlog::sinks::ringbuffer_sink_mt> ring;
            spdlog::level::level_enum prev_level;
            ~SinkGuard() {
                auto& sinks = logger->sinks();
                sinks.erase(std::remove(sinks.begin(), sinks.end(),
                                        std::shared_ptr<spdlog::sinks::sink>(ring)),
                            sinks.end());
                logger->set_level(prev_level);
            }
        } guard{logger, ring, prev_level};

        // Drive exactly threshold=2 failures to trip.
        TestHttpClient::HttpGet(gw_port, "/fail", 3000);
        TestHttpClient::HttpGet(gw_port, "/fail", 3000);

        // Give the dispatcher a breath to emit + the sink to settle.
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        auto messages = ring->last_formatted();
        // Scan for the trip message. Look for the static prefix plus the
        // §11.1 field tokens.
        bool saw_tripped = false;
        bool has_trigger = false;
        bool has_consec_failures = false;
        bool has_window_total = false;
        bool has_fail_rate = false;
        bool has_open_for_ms = false;
        bool has_consec_trips = false;
        for (const auto& msg : messages) {
            if (msg.find("circuit breaker tripped") == std::string::npos) {
                continue;
            }
            saw_tripped = true;
            if (msg.find("trigger=") != std::string::npos) has_trigger = true;
            if (msg.find("consecutive_failures=") != std::string::npos)
                has_consec_failures = true;
            if (msg.find("window_total=") != std::string::npos)
                has_window_total = true;
            if (msg.find("window_fail_rate=") != std::string::npos)
                has_fail_rate = true;
            if (msg.find("open_for_ms=") != std::string::npos)
                has_open_for_ms = true;
            if (msg.find("consecutive_trips=") != std::string::npos)
                has_consec_trips = true;
        }

        bool pass = saw_tripped && has_trigger && has_consec_failures &&
                    has_window_total && has_fail_rate &&
                    has_open_for_ms && has_consec_trips;
        TestFramework::RecordTest(
            "CB Phase 7: trip log emission", pass,
            pass ? "" :
            "saw_tripped=" + std::to_string(saw_tripped) +
            " trigger=" + std::to_string(has_trigger) +
            " consec_failures=" + std::to_string(has_consec_failures) +
            " window_total=" + std::to_string(has_window_total) +
            " fail_rate=" + std::to_string(has_fail_rate) +
            " open_for_ms=" + std::to_string(has_open_for_ms) +
            " consec_trips=" + std::to_string(has_consec_trips));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB Phase 7: trip log emission", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Test 3: Retry-budget observability — the exhausted log carries the
// §11.1 fields (service, in_flight, retries_in_flight, cap), and the
// host snapshot reflects retries_rejected.
// ---------------------------------------------------------------------------
void TestRetryBudgetObservability() {
    std::cout << "\n[TEST] CB Phase 7: retry budget observability..."
              << std::endl;
    try {
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/fail", [](const HttpRequest&, HttpResponse& resp) {
            resp.Status(502).Body("upstream-err", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ServerConfig gw;
        gw.bind_host = "127.0.0.1";
        gw.bind_port = 0;
        gw.worker_threads = 1;
        gw.http2.enabled = false;

        // Budget: zero percent AND zero floor → every retry rejected.
        auto u = MakeObservUpstream("svc-budget", "127.0.0.1", backend_port,
                                    /*threshold=*/10000);
        u.proxy.retry.max_retries = 2;
        u.proxy.retry.retry_on_5xx = true;
        u.circuit_breaker.retry_budget_percent = 0;
        u.circuit_breaker.retry_budget_min_concurrency = 0;
        gw.upstreams.push_back(u);

        // Attach the ringbuffer AFTER gateway construction — see
        // TestTripLogEmission for rationale (HttpServer's ctor
        // replaces the default logger via logging::Init, detaching
        // any previously-attached sinks).
        HttpServer gateway(gw);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        auto ring = std::make_shared<
            spdlog::sinks::ringbuffer_sink_mt>(1024);
        auto logger = logging::Get();
        auto prev_level = logger->level();
        logger->set_level(spdlog::level::debug);
        logger->sinks().push_back(ring);

        struct SinkGuard {
            std::shared_ptr<spdlog::logger> logger;
            std::shared_ptr<spdlog::sinks::ringbuffer_sink_mt> ring;
            spdlog::level::level_enum prev_level;
            ~SinkGuard() {
                auto& sinks = logger->sinks();
                sinks.erase(std::remove(sinks.begin(), sinks.end(),
                                        std::shared_ptr<spdlog::sinks::sink>(ring)),
                            sinks.end());
                logger->set_level(prev_level);
            }
        } guard{logger, ring, prev_level};

        // One client request: first attempt hits backend (502), retry
        // blocked by budget → 503 + X-Retry-Budget-Exhausted.
        TestHttpClient::HttpGet(gw_port, "/fail", 5000);

        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        auto messages = ring->last_formatted();
        bool saw_exhausted = false;
        bool has_service = false;
        bool has_inflight = false;
        bool has_retries_inflight = false;
        bool has_cap = false;
        for (const auto& msg : messages) {
            if (msg.find("retry budget exhausted") == std::string::npos) {
                continue;
            }
            saw_exhausted = true;
            if (msg.find("service=") != std::string::npos) has_service = true;
            if (msg.find("in_flight=") != std::string::npos)
                has_inflight = true;
            if (msg.find("retries_in_flight=") != std::string::npos)
                has_retries_inflight = true;
            if (msg.find("cap=") != std::string::npos) has_cap = true;
        }

        // Snapshot: retries_rejected must be >= 1 (every rejection increments).
        int64_t retries_rejected = 0;
        auto* cbm = gateway.GetUpstreamManager()->GetCircuitBreakerManager();
        if (cbm) {
            for (const auto& s : cbm->SnapshotAll()) {
                if (s.service_name == "svc-budget") {
                    // Host aggregate — single host, so the sum is the
                    // host's retries_rejected. The snapshot doesn't yet
                    // expose that directly — derive from RetryBudget
                    // via the host getter.
                    auto* host = cbm->GetHost("svc-budget");
                    if (host) {
                        retries_rejected =
                            host->GetRetryBudget()->RetriesRejected();
                    }
                    break;
                }
            }
        }

        bool pass = saw_exhausted && has_service && has_inflight &&
                    has_retries_inflight && has_cap &&
                    retries_rejected >= 1;
        TestFramework::RecordTest(
            "CB Phase 7: retry budget observability", pass,
            pass ? "" :
            "saw_exhausted=" + std::to_string(saw_exhausted) +
            " service=" + std::to_string(has_service) +
            " inflight=" + std::to_string(has_inflight) +
            " retries_inflight=" + std::to_string(has_retries_inflight) +
            " cap=" + std::to_string(has_cap) +
            " retries_rejected=" + std::to_string(retries_rejected));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB Phase 7: retry budget observability", false, e.what());
    }
}

void RunAllTests() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "CIRCUIT BREAKER PHASE 7 - OBSERVABILITY TESTS" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    TestSnapshotReflectsCounters();
    TestTripLogEmission();
    TestRetryBudgetObservability();
}

}  // namespace CircuitBreakerPhase7Tests
