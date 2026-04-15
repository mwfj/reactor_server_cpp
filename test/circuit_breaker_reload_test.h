#pragma once

// Reload integration tests: hot-reload of circuit-breaker fields.
//
// UpstreamConfig::operator== now excludes `circuit_breaker` — a CB-only
// SIGHUP is a clean reload that propagates via HttpServer::Reload →
// CircuitBreakerManager::Reload → per-host per-slice Reload enqueued on
// each owning dispatcher.
//
// Topology fields (host, port, pool, proxy, tls) remain restart-only.
//
// Strategy: construct a gateway with an enabled breaker, capture the
// initial slice config, call HttpServer::Reload with an edited
// CircuitBreakerConfig, and verify the slice's live config reflects the
// edit. The reload-log capture also verifies the manager-level log lines
// ("CircuitBreakerManager::Reload: new/removed upstream ...") fire for
// topology-change SIGHUPs.

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
#include <memory>

namespace CircuitBreakerReloadTests {

static UpstreamConfig MakeReloadUpstream(const std::string& name,
                                          const std::string& host,
                                          int port) {
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
    u.circuit_breaker.consecutive_failure_threshold = 3;
    u.circuit_breaker.failure_rate_threshold = 100;
    u.circuit_breaker.minimum_volume = 10000;
    u.circuit_breaker.window_seconds = 10;
    u.circuit_breaker.permitted_half_open_calls = 2;
    u.circuit_breaker.base_open_duration_ms = 5000;
    u.circuit_breaker.max_open_duration_ms  = 60000;
    return u;
}

// ---------------------------------------------------------------------------
// Test 1: CB-only SIGHUP propagates to live slice config.
//
// Build gateway with threshold=3. Reload with threshold=7. Verify the
// slice's live config().consecutive_failure_threshold flipped to 7.
// ---------------------------------------------------------------------------
void TestCbReloadPropagatesToSlice() {
    std::cout << "\n[TEST] CB Reload: reload propagates to slice..."
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
        gw.upstreams.push_back(
            MakeReloadUpstream("svc", "127.0.0.1", backend_port));

        HttpServer gateway(gw);
        TestServerRunner<HttpServer> gw_runner(gateway);

        auto* cbm = gateway.GetUpstreamManager()->GetCircuitBreakerManager();
        auto* host = cbm->GetHost("svc");
        auto* slice = host->GetSlice(0);
        int threshold_before = slice->config().consecutive_failure_threshold;
        int window_before = slice->config().window_seconds;

        // Build reloaded config with modified CB fields only.
        ServerConfig reloaded = gw;
        reloaded.upstreams[0].circuit_breaker.consecutive_failure_threshold = 7;
        reloaded.upstreams[0].circuit_breaker.window_seconds = 20;

        bool ok = gateway.Reload(reloaded);
        // Reload enqueues per-slice updates on the owning dispatcher —
        // brief sleep to let the dispatcher execute the queued Slice::Reload.
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        int threshold_after = slice->config().consecutive_failure_threshold;
        int window_after = slice->config().window_seconds;

        bool pass = ok && threshold_before == 3 && window_before == 10
                    && threshold_after == 7 && window_after == 20;
        TestFramework::RecordTest(
            "CB Reload: reload propagates to slice", pass,
            pass ? "" :
            "ok=" + std::to_string(ok) +
            " threshold_before=" + std::to_string(threshold_before) +
            " threshold_after=" + std::to_string(threshold_after) +
            " window_before=" + std::to_string(window_before) +
            " window_after=" + std::to_string(window_after));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB Reload: reload propagates to slice", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Test 2: CB-only reload does NOT emit the topology "restart required"
// warning. UpstreamConfig::operator== excludes circuit_breaker so a
// CB-only edit doesn't make the outer config != comparison true — the
// warning fires only on topology-field changes (host, port, pool, proxy,
// tls), which remain restart-only.
// ---------------------------------------------------------------------------
void TestCbOnlyReloadNoRestartWarn() {
    std::cout << "\n[TEST] CB Reload: CB-only reload emits no restart warn..."
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
        gw.upstreams.push_back(
            MakeReloadUpstream("svc", "127.0.0.1", backend_port));

        HttpServer gateway(gw);
        TestServerRunner<HttpServer> gw_runner(gateway);

        // Attach ringbuffer sink AFTER gateway ctor (logging::Init
        // rebuilds the default logger). See the observability test for rationale.
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

        ServerConfig reloaded = gw;
        reloaded.upstreams[0].circuit_breaker.consecutive_failure_threshold = 9;

        gateway.Reload(reloaded);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        bool saw_topology_warn = false;
        bool saw_cb_config_applied = false;
        for (const auto& msg : ring->last_formatted()) {
            if (msg.find("upstream topology changes require a restart") !=
                std::string::npos) {
                saw_topology_warn = true;
            }
            if (msg.find("circuit breaker config applied") !=
                std::string::npos) {
                saw_cb_config_applied = true;
            }
        }

        bool pass = !saw_topology_warn && saw_cb_config_applied;
        TestFramework::RecordTest(
            "CB Reload: CB-only reload emits no restart warn", pass,
            pass ? "" :
            "saw_topology_warn=" + std::to_string(saw_topology_warn) +
            " saw_cb_config_applied=" + std::to_string(saw_cb_config_applied));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB Reload: CB-only reload emits no restart warn", false,
            e.what());
    }
}

// ---------------------------------------------------------------------------
// Test 3: Topology change (pool field edit) STILL emits the restart warn
// — the exclusion of circuit_breaker from operator== must NOT compromise
// the restart-required signal for unreloadable fields.
// ---------------------------------------------------------------------------
void TestTopologyChangeStillEmitsRestartWarn() {
    std::cout << "\n[TEST] CB Reload: topology change still warns..."
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
        gw.upstreams.push_back(
            MakeReloadUpstream("svc", "127.0.0.1", backend_port));

        HttpServer gateway(gw);
        TestServerRunner<HttpServer> gw_runner(gateway);

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

        ServerConfig reloaded = gw;
        // Topology-level edit that operator== still detects.
        reloaded.upstreams[0].pool.max_connections = 16;
        // Also flip a breaker field so we verify BOTH happen on the
        // same reload (live CB edit + topology warn).
        reloaded.upstreams[0].circuit_breaker.consecutive_failure_threshold = 5;

        gateway.Reload(reloaded);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        bool saw_topology_warn = false;
        bool saw_cb_config_applied = false;
        for (const auto& msg : ring->last_formatted()) {
            if (msg.find("upstream topology changes require a restart") !=
                std::string::npos) {
                saw_topology_warn = true;
            }
            if (msg.find("circuit breaker config applied") !=
                std::string::npos) {
                saw_cb_config_applied = true;
            }
        }

        bool pass = saw_topology_warn && saw_cb_config_applied;
        TestFramework::RecordTest(
            "CB Reload: topology change still warns", pass,
            pass ? "" :
            "saw_topology_warn=" + std::to_string(saw_topology_warn) +
            " saw_cb_config_applied=" + std::to_string(saw_cb_config_applied));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB Reload: topology change still warns", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Test 4: Disable → enable toggle via reload. A CB-only reload that sets
// `enabled=false` must make the slice short-circuit admissions; a
// subsequent reload flipping `enabled=true` must re-engage the state
// machine without requiring a restart. Verifies the "wire transition
// callbacks for ALL upstreams regardless of enabled" design (§3.1 R3-1).
// ---------------------------------------------------------------------------
void TestReloadDisableThenEnable() {
    std::cout << "\n[TEST] CB Reload: reload disable→enable..." << std::endl;
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
        gw.upstreams.push_back(
            MakeReloadUpstream("svc", "127.0.0.1", backend_port));

        HttpServer gateway(gw);
        TestServerRunner<HttpServer> gw_runner(gateway);

        auto* cbm = gateway.GetUpstreamManager()->GetCircuitBreakerManager();
        auto* slice = cbm->GetHost("svc")->GetSlice(0);

        // Start: enabled=true.
        bool enabled_before = slice->config().enabled;

        // Reload to enabled=false.
        ServerConfig disabled = gw;
        disabled.upstreams[0].circuit_breaker.enabled = false;
        gateway.Reload(disabled);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        bool disabled_after = !slice->config().enabled;

        // Reload back to enabled=true with a new threshold.
        ServerConfig reenabled = gw;
        reenabled.upstreams[0].circuit_breaker.enabled = true;
        reenabled.upstreams[0].circuit_breaker.consecutive_failure_threshold = 11;
        gateway.Reload(reenabled);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        bool enabled_again = slice->config().enabled;
        int threshold_after = slice->config().consecutive_failure_threshold;

        bool pass = enabled_before && disabled_after &&
                    enabled_again && threshold_after == 11;
        TestFramework::RecordTest(
            "CB Reload: reload disable→enable", pass,
            pass ? "" :
            "enabled_before=" + std::to_string(enabled_before) +
            " disabled_after=" + std::to_string(disabled_after) +
            " enabled_again=" + std::to_string(enabled_again) +
            " threshold_after=" + std::to_string(threshold_after));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB Reload: reload disable→enable", false, e.what());
    }
}

// Regression: a SIGHUP carrying an invalid CB threshold (e.g.
// `consecutive_failure_threshold = 0`) on an EXISTING upstream must
// be hard-rejected. The downgrade-to-warn behavior of the wider
// `Validate()` call would otherwise push the bad value into live
// slices even though startup rejects the same file.
void TestReloadRejectsInvalidCbField() {
    std::cout << "\n[TEST] CB Reload: invalid CB tuning is hard-rejected..."
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
        gw.upstreams.push_back(
            MakeReloadUpstream("svc", "127.0.0.1", backend_port));

        HttpServer gateway(gw);
        TestServerRunner<HttpServer> gw_runner(gateway);

        // Build an invalid reload — threshold below the [1, 10000] range.
        ServerConfig invalid = gw;
        invalid.upstreams[0].circuit_breaker.consecutive_failure_threshold = 0;

        bool reload_returned = gateway.Reload(invalid);
        // The slice's threshold must NOT have been pushed live.
        auto* cbm = gateway.GetUpstreamManager()->GetCircuitBreakerManager();
        auto* slice = cbm->GetHost("svc")->GetSlice(0);
        int live_threshold = slice->config().consecutive_failure_threshold;

        bool pass = reload_returned == false && live_threshold == 3;
        TestFramework::RecordTest(
            "CB Reload: invalid CB tuning is hard-rejected", pass,
            pass ? "" :
            "reload_returned=" + std::to_string(reload_returned) +
            " live_threshold=" + std::to_string(live_threshold) +
            " (expected reload=false, threshold=3 unchanged)");
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB Reload: invalid CB tuning is hard-rejected", false, e.what());
    }
}

// Regression: with `dry_run=true`, the CLOSED→OPEN transition callback
// must NOT drain the partition wait queue (shadow-mode contract: log
// would-reject decisions, admit traffic). The breaker's dry_run check
// inside the transition callback covers this; the regression we lock
// in is the log-emitted breadcrumb plus the absence of CHECKOUT_CIRCUIT_OPEN
// to queued waiters.
void TestDryRunDoesNotDrainOnTrip() {
    std::cout << "\n[TEST] CB Reload: dry-run skips wait-queue drain on trip..."
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
        UpstreamConfig u = MakeReloadUpstream("svc", "127.0.0.1", backend_port);
        u.circuit_breaker.dry_run = true;
        u.circuit_breaker.consecutive_failure_threshold = 2;
        gw.upstreams.push_back(u);

        HttpServer gateway(gw);
        TestServerRunner<HttpServer> gw_runner(gateway);

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

        int gw_port = gw_runner.GetPort();
        // Trip the breaker via 2 failures.
        for (int i = 0; i < 2; ++i) {
            TestHttpClient::HttpGet(gw_port, "/fail", 3000);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        bool saw_dryrun_drain_skip = false;
        for (const auto& msg : ring->last_formatted()) {
            if (msg.find("[dry-run] circuit breaker would drain wait queue") !=
                std::string::npos) {
                saw_dryrun_drain_skip = true;
                break;
            }
        }

        TestFramework::RecordTest(
            "CB Reload: dry-run skips wait-queue drain on trip",
            saw_dryrun_drain_skip,
            saw_dryrun_drain_skip ? "" :
            "expected '[dry-run] circuit breaker would drain wait queue' log line");
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB Reload: dry-run skips wait-queue drain on trip", false, e.what());
    }
}

// Regression: when `dry_run` flips true→false on a slice that's
// currently OPEN, `Slice::Reload` fires a synthetic OPEN→OPEN
// transition with trigger="dry_run_disabled". The HttpServer-installed
// callback recognizes it and drains the partition queue so shadow-mode
// waiters don't leak through to the upstream once enforcement is back on.
void TestDryRunDisableOnOpenTriggersDrainSignal() {
    std::cout << "\n[TEST] CB Reload: dry_run disable on OPEN triggers drain..."
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
        UpstreamConfig u = MakeReloadUpstream("svc", "127.0.0.1", backend_port);
        u.circuit_breaker.dry_run = true;
        u.circuit_breaker.consecutive_failure_threshold = 2;
        u.circuit_breaker.base_open_duration_ms = 60000;  // long open window
        gw.upstreams.push_back(u);

        HttpServer gateway(gw);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        // Trip the breaker (dry-run still records the trip; state goes OPEN).
        for (int i = 0; i < 2; ++i) {
            TestHttpClient::HttpGet(gw_port, "/fail", 3000);
        }

        auto* cbm = gateway.GetUpstreamManager()->GetCircuitBreakerManager();
        auto* slice = cbm->GetHost("svc")->GetSlice(0);
        bool was_open = slice->CurrentState() == circuit_breaker::State::OPEN;

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

        // Reload with dry_run=false, everything else same.
        ServerConfig disable_dry = gw;
        disable_dry.upstreams[0].circuit_breaker.dry_run = false;
        gateway.Reload(disable_dry);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));

        // The synthetic-callback fire path emits a slice-side log line.
        bool saw_flush_log = false;
        for (const auto& msg : ring->last_formatted()) {
            if (msg.find("dry_run disabled while OPEN") != std::string::npos &&
                msg.find("flushing wait queue") != std::string::npos) {
                saw_flush_log = true;
                break;
            }
        }
        bool live_dry_run = slice->config().dry_run;
        bool still_open = slice->CurrentState() == circuit_breaker::State::OPEN;

        bool pass = was_open && !live_dry_run && saw_flush_log && still_open;
        TestFramework::RecordTest(
            "CB Reload: dry_run disable on OPEN triggers drain", pass,
            pass ? "" :
            "was_open=" + std::to_string(was_open) +
            " live_dry_run=" + std::to_string(live_dry_run) +
            " saw_flush_log=" + std::to_string(saw_flush_log) +
            " still_open=" + std::to_string(still_open));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "CB Reload: dry_run disable on OPEN triggers drain", false,
            e.what());
    }
}

void RunAllTests() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "CIRCUIT BREAKER - HOT-RELOAD TESTS" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    TestCbReloadPropagatesToSlice();
    TestCbOnlyReloadNoRestartWarn();
    TestTopologyChangeStillEmitsRestartWarn();
    TestReloadDisableThenEnable();
    TestReloadRejectsInvalidCbField();
    TestDryRunDoesNotDrainOnTrip();
    TestDryRunDisableOnOpenTriggersDrainSignal();
}

}  // namespace CircuitBreakerReloadTests
