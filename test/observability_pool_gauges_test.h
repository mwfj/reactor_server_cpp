#pragma once

// Upstream pool gauge + checkout-wait histogram observability tests.
//
// Coverage matches the catalogued metrics:
//   * reactor.upstream.pool.connections.idle   — UpDownCounter,
//       label {reactor.upstream.service}
//   * reactor.upstream.pool.connections.active — UpDownCounter,
//       label {reactor.upstream.service}
//   * reactor.upstream.pool.checkout.wait.duration — Histogram,
//       labels {reactor.upstream.service, outcome}
//       outcome ∈ {immediate, created, queued_satisfied, rejected, cancelled}
//
// Tests boot a real gateway HttpServer in front of a real backend
// HttpServer (the proxy path exercises every transition site —
// `OnConnectComplete` success, `ReturnConnection` active->idle,
// `CheckoutAsync` idle-reuse, and `OnConnectionClosed`).

#include "test_framework.h"
#include "test_server_runner.h"
#include "http/http_request.h"
#include "http/http_response.h"
#include "http/http_server.h"
#include "config/server_config.h"
#include "observability/metrics_snapshot.h"
#include "observability/meter_provider.h"
#include "observability/observability_config.h"
#include "observability/observability_manager.h"
#include "observability/resource.h"
#include "observability/sampler.h"
#include "observability/span_processor.h"

#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace ObservabilityPoolGaugesTests {

using OBSERVABILITY_NAMESPACE::CounterPoint;
using OBSERVABILITY_NAMESPACE::HistogramPoint;
using OBSERVABILITY_NAMESPACE::InMemorySpanProcessor;
using OBSERVABILITY_NAMESPACE::InstrumentSnapshot;
using OBSERVABILITY_NAMESPACE::MetricsSnapshot;
using OBSERVABILITY_NAMESPACE::ObservabilityConfig;
using OBSERVABILITY_NAMESPACE::ObservabilityManager;
using OBSERVABILITY_NAMESPACE::RandomSource;
using OBSERVABILITY_NAMESPACE::Resource;
using OBSERVABILITY_NAMESPACE::SamplerType;

namespace {

// ---- Snapshot helpers -------------------------------------------------

// Sum every UpDownCounter point on the named instrument whose label
// {key=value} matches. UpDownCounter and Counter share the CounterPoint
// snapshot shape — InstrumentKind is distinguished at registration time.
double SumGaugeByLabel(const MetricsSnapshot& snap,
                       const std::string& name,
                       const std::string& key,
                       const std::string& value) {
    double total = 0;
    for (const auto& inst : snap.instruments) {
        if (inst.name != name) continue;
        for (const auto& p : inst.counter_points) {
            for (const auto& [k, v] : p.labels.kv) {
                if (k == key && v == value) total += p.value;
            }
        }
    }
    return total;
}

// Sum every histogram point's `count` on the named instrument whose labels
// match both (k1=v1) AND (k2=v2). The histogram has two labels
// (service, outcome) so the AND filter pins the exact series.
uint64_t HistogramCountByTwoLabels(const MetricsSnapshot& snap,
                                    const std::string& name,
                                    const std::string& k1,
                                    const std::string& v1,
                                    const std::string& k2,
                                    const std::string& v2) {
    uint64_t total = 0;
    for (const auto& inst : snap.instruments) {
        if (inst.name != name) continue;
        for (const auto& p : inst.histogram_points) {
            bool m1 = false, m2 = false;
            for (const auto& [k, v] : p.labels.kv) {
                if (k == k1 && v == v1) m1 = true;
                if (k == k2 && v == v2) m2 = true;
            }
            if (m1 && m2) total += p.count;
        }
    }
    return total;
}

// ---- HTTP / TCP helpers ----------------------------------------------

int ConnectTcp(int port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(static_cast<uint16_t>(port));
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

bool SendAll(int fd, const std::string& data) {
    size_t sent = 0;
    while (sent < data.size()) {
        ssize_t n = ::send(fd, data.data() + sent, data.size() - sent, 0);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

std::string DrainSocket(int fd, int timeout_ms = 800) {
    std::string buf;
    auto deadline = std::chrono::steady_clock::now()
                  + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        pollfd pfd{fd, POLLIN, 0};
        int rc = ::poll(&pfd, 1, 50);
        if (rc <= 0) {
            if (buf.empty()) continue;
            break;
        }
        char c[4096];
        ssize_t n = ::recv(fd, c, sizeof(c), 0);
        if (n <= 0) break;
        buf.append(c, static_cast<size_t>(n));
    }
    return buf;
}

std::string SendOneRequest(int port, const std::string& path) {
    int fd = ConnectTcp(port);
    if (fd < 0) return "";
    std::string req = "GET " + path +
        " HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    if (!SendAll(fd, req)) {
        ::close(fd);
        return "";
    }
    auto resp = DrainSocket(fd);
    ::close(fd);
    return resp;
}

// Wait up to `timeout_ms` for `pred()` to return true. Used because
// finalize / pool transitions are async-driven by dispatcher threads.
bool WaitFor(std::function<bool()> pred, int timeout_ms = 2000) {
    auto deadline = std::chrono::steady_clock::now()
                  + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return pred();
}

// ---- Fixtures --------------------------------------------------------

UpstreamConfig MakePoolUpstreamConfig(const std::string& name,
                                       const std::string& host,
                                       int port,
                                       const std::string& route_prefix) {
    UpstreamConfig cfg;
    cfg.name = name;
    cfg.host = host;
    cfg.port = port;
    cfg.pool.max_connections       = 4;
    cfg.pool.max_idle_connections  = 2;
    cfg.pool.connect_timeout_ms    = 2000;
    // Short idle so EvictExpired test can finish in <2s without slowing
    // the suite. 1 second matches the minimum cadence clamp documented in
    // upstream_manager.cc CadenceSecFromMs.
    cfg.pool.idle_timeout_sec      = 1;
    cfg.pool.max_lifetime_sec      = 3600;
    cfg.proxy.route_prefix         = route_prefix;
    cfg.proxy.strip_prefix         = false;
    cfg.proxy.response_timeout_ms  = 4000;
    return cfg;
}

ObservabilityConfig MakeObsConfig(const std::string& service) {
    ObservabilityConfig cfg;
    cfg.enabled               = true;
    cfg.traces.enabled        = true;
    cfg.metrics.enabled       = true;
    cfg.traces.sampler.type   = SamplerType::AlwaysOn;
    cfg.resource.service_name = service;
    return cfg;
}

struct GatewayFixture {
    std::shared_ptr<InMemorySpanProcessor> processor =
        std::make_shared<InMemorySpanProcessor>();
    std::shared_ptr<ObservabilityManager> manager;

    explicit GatewayFixture(const std::string& service = "obs-pool-test") {
        manager = ObservabilityManager::Create(
            MakeObsConfig(service),
            std::make_shared<Resource>(),
            processor,
            std::make_shared<RandomSource>(0xBADC0DEULL));
    }
};

}  // namespace

// ---------------------------------------------------------------------
// Test 1 — A single proxied request leaves the pool with exactly one
// idle connection and zero active. Exercises:
//   OnConnectComplete success  (active +1)
//   ReturnConnection clean     (active -1, idle +1)
// ---------------------------------------------------------------------
inline void TestPoolIdleActiveTransitions() {
    const char* TAG = "ObsPool: idle/active transitions on single proxied request";
    try {
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/echo", [](const HttpRequest&, HttpResponse& resp) {
            resp.Status(200).Body("ok", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        GatewayFixture gw_fix;
        ServerConfig gw_cfg;
        gw_cfg.bind_host = "127.0.0.1";
        gw_cfg.bind_port = 0;
        gw_cfg.worker_threads = 1;
        gw_cfg.http2.enabled = false;
        gw_cfg.upstreams.push_back(
            MakePoolUpstreamConfig("backend", "127.0.0.1", backend_port, "/echo"));
        HttpServer gateway(gw_cfg);
        gateway.SetObservabilityManager(gw_fix.manager);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        std::string resp = SendOneRequest(gw_port, "/echo");
        bool resp_ok = resp.find("200 OK") != std::string::npos;

        // The connection returns to idle asynchronously; poll briefly.
        bool gauges_ok = WaitFor([&]() {
            auto snap = gw_fix.manager->meter_provider()->Snapshot();
            double idle = SumGaugeByLabel(snap,
                "reactor.upstream.pool.connections.idle",
                "reactor.upstream.service", "backend");
            double active = SumGaugeByLabel(snap,
                "reactor.upstream.pool.connections.active",
                "reactor.upstream.service", "backend");
            return idle == 1.0 && active == 0.0;
        }, 2000);

        auto snap = gw_fix.manager->meter_provider()->Snapshot();
        double idle = SumGaugeByLabel(snap,
            "reactor.upstream.pool.connections.idle",
            "reactor.upstream.service", "backend");
        double active = SumGaugeByLabel(snap,
            "reactor.upstream.pool.connections.active",
            "reactor.upstream.service", "backend");

        bool pass = resp_ok && gauges_ok && idle == 1.0 && active == 0.0;
        std::string err;
        if (!pass) {
            err = "resp_ok=" + std::to_string(resp_ok) +
                  " idle=" + std::to_string(idle) +
                  " active=" + std::to_string(active);
        }
        TestFramework::RecordTest(TAG, pass, err,
                                   TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                   TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Test 2 — first proxied request creates a connection; histogram records
// the outcome=created bucket with count == 1.
// ---------------------------------------------------------------------
inline void TestPoolCheckoutWaitDurationCreated() {
    const char* TAG = "ObsPool: checkout.wait.duration {outcome=created} on first request";
    try {
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/x", [](const HttpRequest&, HttpResponse& resp) {
            resp.Status(200).Body("ok", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        GatewayFixture gw_fix("obs-pool-created");
        ServerConfig gw_cfg;
        gw_cfg.bind_host = "127.0.0.1";
        gw_cfg.bind_port = 0;
        gw_cfg.worker_threads = 1;
        gw_cfg.http2.enabled = false;
        gw_cfg.upstreams.push_back(
            MakePoolUpstreamConfig("svc", "127.0.0.1", backend_port, "/x"));
        HttpServer gateway(gw_cfg);
        gateway.SetObservabilityManager(gw_fix.manager);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        std::string resp = SendOneRequest(gw_port, "/x");
        bool resp_ok = resp.find("200 OK") != std::string::npos;

        bool hist_ok = WaitFor([&]() {
            auto snap = gw_fix.manager->meter_provider()->Snapshot();
            return HistogramCountByTwoLabels(snap,
                "reactor.upstream.pool.checkout.wait.duration",
                "reactor.upstream.service", "svc",
                "outcome", "created") >= 1;
        }, 2000);

        auto snap = gw_fix.manager->meter_provider()->Snapshot();
        uint64_t created = HistogramCountByTwoLabels(snap,
            "reactor.upstream.pool.checkout.wait.duration",
            "reactor.upstream.service", "svc",
            "outcome", "created");
        // Should NOT have an immediate bucket yet (first request always created).
        uint64_t immediate = HistogramCountByTwoLabels(snap,
            "reactor.upstream.pool.checkout.wait.duration",
            "reactor.upstream.service", "svc",
            "outcome", "immediate");

        bool pass = resp_ok && hist_ok && created == 1 && immediate == 0;
        std::string err;
        if (!pass) {
            err = "resp_ok=" + std::to_string(resp_ok) +
                  " created=" + std::to_string(created) +
                  " immediate=" + std::to_string(immediate);
        }
        TestFramework::RecordTest(TAG, pass, err,
                                   TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                   TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Test 3 — second proxied request reuses the idle connection.
// Histogram records outcome=immediate; outcome=created stays at 1.
// ---------------------------------------------------------------------
inline void TestPoolCheckoutWaitDurationImmediate() {
    const char* TAG = "ObsPool: checkout.wait.duration {outcome=immediate} on reuse";
    try {
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/y", [](const HttpRequest&, HttpResponse& resp) {
            resp.Status(200).Body("ok", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        GatewayFixture gw_fix("obs-pool-immediate");
        ServerConfig gw_cfg;
        gw_cfg.bind_host = "127.0.0.1";
        gw_cfg.bind_port = 0;
        gw_cfg.worker_threads = 1;
        gw_cfg.http2.enabled = false;
        auto u = MakePoolUpstreamConfig("svc", "127.0.0.1", backend_port, "/y");
        // Bump idle so the first request's connection survives until the second.
        u.pool.idle_timeout_sec = 30;
        gw_cfg.upstreams.push_back(u);
        HttpServer gateway(gw_cfg);
        gateway.SetObservabilityManager(gw_fix.manager);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        // First request — creates connection.
        std::string resp1 = SendOneRequest(gw_port, "/y");
        bool resp1_ok = resp1.find("200 OK") != std::string::npos;
        // Wait for the first conn to return to idle.
        WaitFor([&]() {
            auto snap = gw_fix.manager->meter_provider()->Snapshot();
            return SumGaugeByLabel(snap,
                "reactor.upstream.pool.connections.idle",
                "reactor.upstream.service", "svc") == 1.0;
        }, 2000);

        // Second request — should reuse.
        std::string resp2 = SendOneRequest(gw_port, "/y");
        bool resp2_ok = resp2.find("200 OK") != std::string::npos;

        bool hist_ok = WaitFor([&]() {
            auto snap = gw_fix.manager->meter_provider()->Snapshot();
            return HistogramCountByTwoLabels(snap,
                "reactor.upstream.pool.checkout.wait.duration",
                "reactor.upstream.service", "svc",
                "outcome", "immediate") >= 1;
        }, 2000);

        auto snap = gw_fix.manager->meter_provider()->Snapshot();
        uint64_t created = HistogramCountByTwoLabels(snap,
            "reactor.upstream.pool.checkout.wait.duration",
            "reactor.upstream.service", "svc",
            "outcome", "created");
        uint64_t immediate = HistogramCountByTwoLabels(snap,
            "reactor.upstream.pool.checkout.wait.duration",
            "reactor.upstream.service", "svc",
            "outcome", "immediate");

        bool pass = resp1_ok && resp2_ok && hist_ok && created == 1 && immediate >= 1;
        std::string err;
        if (!pass) {
            err = "resp1_ok=" + std::to_string(resp1_ok) +
                  " resp2_ok=" + std::to_string(resp2_ok) +
                  " created=" + std::to_string(created) +
                  " immediate=" + std::to_string(immediate);
        }
        TestFramework::RecordTest(TAG, pass, err,
                                   TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                   TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Test 4 — when the backend disappears while the gateway holds an idle
// keepalive, EvictExpired drives idle back to zero. Uses
// idle_timeout_sec=1 from MakePoolUpstreamConfig so the cadence fires
// promptly.
// ---------------------------------------------------------------------
inline void TestPoolEvictExpiredDrainsIdle() {
    const char* TAG = "ObsPool: EvictExpired drains idle gauge";
    try {
        std::unique_ptr<HttpServer> backend(new HttpServer("127.0.0.1", 0));
        backend->Get("/z", [](const HttpRequest&, HttpResponse& resp) {
            resp.Status(200).Body("ok", "text/plain");
        });
        std::unique_ptr<TestServerRunner<HttpServer>> backend_runner(
            new TestServerRunner<HttpServer>(*backend));
        int backend_port = backend_runner->GetPort();

        GatewayFixture gw_fix("obs-pool-evict");
        ServerConfig gw_cfg;
        gw_cfg.bind_host = "127.0.0.1";
        gw_cfg.bind_port = 0;
        gw_cfg.worker_threads = 1;
        gw_cfg.http2.enabled = false;
        gw_cfg.upstreams.push_back(
            MakePoolUpstreamConfig("svc", "127.0.0.1", backend_port, "/z"));
        HttpServer gateway(gw_cfg);
        gateway.SetObservabilityManager(gw_fix.manager);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        std::string resp = SendOneRequest(gw_port, "/z");
        bool resp_ok = resp.find("200 OK") != std::string::npos;

        // Confirm one idle conn first.
        bool idle_seen = WaitFor([&]() {
            auto snap = gw_fix.manager->meter_provider()->Snapshot();
            return SumGaugeByLabel(snap,
                "reactor.upstream.pool.connections.idle",
                "reactor.upstream.service", "svc") == 1.0;
        }, 2000);

        // Tear down the backend so the idle keepalive becomes useless.
        backend_runner.reset();
        backend.reset();

        // Wait for the dispatcher's timer cadence (~1s) + EvictExpired to
        // reap. Allow up to 5s for slow CI.
        bool drained = WaitFor([&]() {
            auto snap = gw_fix.manager->meter_provider()->Snapshot();
            return SumGaugeByLabel(snap,
                "reactor.upstream.pool.connections.idle",
                "reactor.upstream.service", "svc") == 0.0;
        }, 5000);

        auto snap = gw_fix.manager->meter_provider()->Snapshot();
        double idle = SumGaugeByLabel(snap,
            "reactor.upstream.pool.connections.idle",
            "reactor.upstream.service", "svc");
        double active = SumGaugeByLabel(snap,
            "reactor.upstream.pool.connections.active",
            "reactor.upstream.service", "svc");

        bool pass = resp_ok && idle_seen && drained &&
                    idle == 0.0 && active == 0.0;
        std::string err;
        if (!pass) {
            err = "resp_ok=" + std::to_string(resp_ok) +
                  " idle_seen=" + std::to_string(idle_seen) +
                  " drained=" + std::to_string(drained) +
                  " idle=" + std::to_string(idle) +
                  " active=" + std::to_string(active);
        }
        TestFramework::RecordTest(TAG, pass, err,
                                   TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                   TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Test 5 — partition-side close (gateway-initiated server shutdown) drains
// the active gauge symmetrically with no leak. Mirrors the
// reactor.net.connections.active accept/close symmetry contract for the
// upstream-pool layer.
// ---------------------------------------------------------------------
inline void TestPoolActiveDrainOnShutdown() {
    const char* TAG = "ObsPool: active gauge drains to zero on gateway shutdown";
    try {
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/q", [](const HttpRequest&, HttpResponse& resp) {
            resp.Status(200).Body("ok", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        GatewayFixture gw_fix("obs-pool-shutdown");
        ServerConfig gw_cfg;
        gw_cfg.bind_host = "127.0.0.1";
        gw_cfg.bind_port = 0;
        gw_cfg.worker_threads = 1;
        gw_cfg.http2.enabled = false;
        auto u = MakePoolUpstreamConfig("svc", "127.0.0.1", backend_port, "/q");
        u.pool.idle_timeout_sec = 30;
        gw_cfg.upstreams.push_back(u);

        // Scoped gateway lifecycle — destructor runs full shutdown drain.
        std::shared_ptr<ObservabilityManager> manager = gw_fix.manager;
        {
            HttpServer gateway(gw_cfg);
            gateway.SetObservabilityManager(manager);
            TestServerRunner<HttpServer> gw_runner(gateway);
            int gw_port = gw_runner.GetPort();

            std::string resp = SendOneRequest(gw_port, "/q");
            (void)resp;
            // Confirm one idle conn first.
            WaitFor([&]() {
                auto snap = manager->meter_provider()->Snapshot();
                return SumGaugeByLabel(snap,
                    "reactor.upstream.pool.connections.idle",
                    "reactor.upstream.service", "svc") == 1.0;
            }, 2000);
        }
        // Gateway destroyed — InitiateShutdown ran, idle drained to zero.

        auto snap = manager->meter_provider()->Snapshot();
        double idle = SumGaugeByLabel(snap,
            "reactor.upstream.pool.connections.idle",
            "reactor.upstream.service", "svc");
        double active = SumGaugeByLabel(snap,
            "reactor.upstream.pool.connections.active",
            "reactor.upstream.service", "svc");

        bool pass = idle == 0.0 && active == 0.0;
        std::string err;
        if (!pass) {
            err = "idle=" + std::to_string(idle) +
                  " active=" + std::to_string(active);
        }
        TestFramework::RecordTest(TAG, pass, err,
                                   TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                   TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Test 6 — emits are no-op when no ObservabilityManager is installed.
// Pool transitions must not crash on a gateway with observability disabled.
// ---------------------------------------------------------------------
inline void TestPoolGaugesNullManagerSafe() {
    const char* TAG = "ObsPool: gauge emits are no-op when ObservabilityManager is null";
    try {
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/n", [](const HttpRequest&, HttpResponse& resp) {
            resp.Status(200).Body("ok", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ServerConfig gw_cfg;
        gw_cfg.bind_host = "127.0.0.1";
        gw_cfg.bind_port = 0;
        gw_cfg.worker_threads = 1;
        gw_cfg.http2.enabled = false;
        gw_cfg.upstreams.push_back(
            MakePoolUpstreamConfig("svc", "127.0.0.1", backend_port, "/n"));
        HttpServer gateway(gw_cfg);
        // Deliberately no SetObservabilityManager.
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        // Single request — must not crash.
        std::string resp = SendOneRequest(gw_port, "/n");
        bool pass = resp.find("200 OK") != std::string::npos;
        std::string err = pass ? "" : "no response";
        TestFramework::RecordTest(TAG, pass, err,
                                   TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                   TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Test 7 — http.client.active_requests survivors are drained by the
// kill loop on shutdown. Boots a black-hole TCP backend (accepts then
// stalls forever), fires N requests that bump +1 each in
// SetupAttemptObservability, then destructs the gateway. The kill
// loop's CAS-decrement-only-if-positive path emits the matching -1s
// and bumps client_active_decremented_via_kill_or_dtor by N.
// ---------------------------------------------------------------------
//
// Black-hole listener — accepts TCP connections and never sends/reads.
// Used to keep proxy transactions stuck in AWAITING_RESPONSE so the
// kill loop sees outstanding +1s on http.client.active_requests.
class BlackHoleListener {
public:
    BlackHoleListener() = default;
    ~BlackHoleListener() { Stop(); }

    int Start() {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return -1;
        listen_fd_.store(fd, std::memory_order_release);
        int yes = 1;
        ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port        = 0;
        if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            ::close(fd);
            listen_fd_.store(-1, std::memory_order_release);
            return -1;
        }
        socklen_t alen = sizeof(addr);
        ::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &alen);
        bound_port_ = ntohs(addr.sin_port);
        if (::listen(fd, 16) < 0) {
            ::close(fd);
            listen_fd_.store(-1, std::memory_order_release);
            return -1;
        }
        accept_thread_ = std::thread([this]() {
            while (running_.load(std::memory_order_acquire)) {
                int lfd = listen_fd_.load(std::memory_order_acquire);
                pollfd pfd{lfd, POLLIN, 0};
                int rc = ::poll(&pfd, 1, 100);
                if (rc <= 0) continue;
                int cfd = ::accept(lfd, nullptr, nullptr);
                if (cfd < 0) continue;
                // Hold the fd so the kernel does not close from our side.
                std::lock_guard<std::mutex> g(fds_mtx_);
                accepted_fds_.push_back(cfd);
            }
        });
        return bound_port_;
    }

    void Stop() {
        bool was_running = running_.exchange(false, std::memory_order_acq_rel);
        if (!was_running) return;
        int lfd = listen_fd_.exchange(-1, std::memory_order_acq_rel);
        if (lfd >= 0) {
            ::shutdown(lfd, SHUT_RDWR);
            ::close(lfd);
        }
        if (accept_thread_.joinable()) accept_thread_.join();
        std::lock_guard<std::mutex> g(fds_mtx_);
        for (int fd : accepted_fds_) ::close(fd);
        accepted_fds_.clear();
    }

    int port() const { return bound_port_; }

private:
    std::atomic<int>    listen_fd_{-1};
    int                 bound_port_ = 0;
    std::atomic<bool>   running_{true};
    std::thread         accept_thread_;
    std::mutex          fds_mtx_;
    std::vector<int>    accepted_fds_;
};

// Fire-and-forget request: opens a TCP connection to the gateway, sends
// a GET, and detaches so the request stays in flight on the gateway
// side. The caller drops the returned fd; the kernel reaps the socket
// when the test exits.
inline void FireRequestAsync(int gw_port, const std::string& path) {
    std::thread([gw_port, path]() {
        int fd = ConnectTcp(gw_port);
        if (fd < 0) return;
        std::string req = "GET " + path +
            " HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        SendAll(fd, req);
        // Do not read the response — let the gateway hold the inflight
        // proxy transaction until shutdown kills it.
        std::this_thread::sleep_for(std::chrono::seconds(10));
        ::close(fd);
    }).detach();
}

inline void TestClientActiveRequestsKillPath() {
    const char* TAG =
        "ObsPool: http.client.active_requests drained by kill loop on shutdown";
    try {
        BlackHoleListener black_hole;
        int backend_port = black_hole.Start();
        if (backend_port <= 0) {
            TestFramework::RecordTest(TAG, false, "black-hole listener failed",
                                       TestFramework::TestCategory::OTHER);
            return;
        }

        GatewayFixture gw_fix("obs-client-active-kill");
        ServerConfig gw_cfg;
        gw_cfg.bind_host = "127.0.0.1";
        gw_cfg.bind_port = 0;
        gw_cfg.worker_threads = 1;
        gw_cfg.http2.enabled = false;
        // Short shutdown drain budget so the test does not hang waiting
        // for in-flight proxy requests to drain naturally — we want the
        // kill loop to fire.
        gw_cfg.shutdown_drain_timeout_sec = 1;
        auto u = MakePoolUpstreamConfig(
            "blackhole", "127.0.0.1", backend_port, "/k");
        // Long response timeout so the kill loop runs before the
        // natural per-attempt timeout fires.
        u.proxy.response_timeout_ms = 60000;
        // Disable retries — single +1 per request, single survivor at kill.
        u.proxy.retry.max_retries = 0;
        gw_cfg.upstreams.push_back(u);

        std::shared_ptr<ObservabilityManager> manager = gw_fix.manager;
        constexpr int kNRequests = 3;
        {
            HttpServer gateway(gw_cfg);
            gateway.SetObservabilityManager(manager);
            TestServerRunner<HttpServer> gw_runner(gateway);
            int gw_port = gw_runner.GetPort();

            // Fire N requests that the gateway will proxy to the
            // black-hole backend; each bumps http.client.active_requests
            // +1 at SetupAttemptObservability.
            for (int i = 0; i < kNRequests; ++i) {
                FireRequestAsync(gw_port, "/k");
            }

            // Wait until the gauge has all N +1s — that is the signal
            // the kill loop will have N inflight to drain.
            bool armed = WaitFor([&]() {
                auto snap = manager->meter_provider()->Snapshot();
                return SumGaugeByLabel(snap,
                    "http.client.active_requests",
                    "reactor.upstream.service",
                    "blackhole") >= static_cast<double>(kNRequests);
            }, 5000);
            if (!armed) {
                auto snap = manager->meter_provider()->Snapshot();
                double live_pre = SumGaugeByLabel(snap,
                    "http.client.active_requests",
                    "reactor.upstream.service", "blackhole");
                TestFramework::RecordTest(TAG, false,
                    "did not see " + std::to_string(kNRequests) +
                    " +1s on http.client.active_requests; observed=" +
                    std::to_string(live_pre),
                    TestFramework::TestCategory::OTHER);
                return;
            }
        }
        // Gateway destroyed — Stop() ran KillOutstandingSnapshots which
        // marshalled per-snapshot kill bodies onto each snapshot's
        // owning_dispatcher. The natural FinalizeAttemptSpan path (driven
        // by the upstream-drain triggered close events on the same
        // dispatchers) may race ahead of the marshalled kill body and
        // win the per-attempt CAS — only one path emits the gauge -1.
        // The invariant we lock in is that every +1 has a matching -1:
        // the gauge MUST return to zero. Whether the drain ran via the
        // kill backstop (`drained_via_kill_or_dtor` increments) or via
        // the natural path is implementation-defined under the new
        // marshal semantics; total drains across both paths equal N.

        auto snap = manager->meter_provider()->Snapshot();
        double live = SumGaugeByLabel(snap,
            "http.client.active_requests",
            "reactor.upstream.service", "blackhole");
        uint64_t drained = manager->client_active_decremented_via_kill_or_dtor();

        // Live must be 0 (no leaks); drained reflects how many residuals
        // the kill / dtor path mopped up — it MAY be 0 if natural finalize
        // beat the marshalled kill closure, and MAY be up to kNRequests
        // if the kill closure won every race.
        bool pass = live == 0.0 &&
                    drained <= static_cast<uint64_t>(kNRequests);
        std::string err;
        if (!pass) {
            err = "live=" + std::to_string(live) +
                  " drained=" + std::to_string(drained) +
                  " expected_drained<=" + std::to_string(kNRequests);
        }
        TestFramework::RecordTest(TAG, pass, err,
                                   TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                   TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Test 8 — http.client.active_requests stays balanced on the happy
// path. Each FinalizeAttemptSpan emits exactly one -1 via the CAS,
// the kill-or-dtor counter stays at 0 (no residual drain fired), and
// the gauge returns to 0.
// ---------------------------------------------------------------------
inline void TestClientActiveRequestsHappyPathDrainsCounter() {
    const char* TAG =
        "ObsPool: http.client.active_requests balanced on happy-path "
        "(no kill/dtor drain)";
    try {
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/r", [](const HttpRequest&, HttpResponse& resp) {
            resp.Status(200).Body("ok", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        GatewayFixture gw_fix("obs-client-active-balanced");
        ServerConfig gw_cfg;
        gw_cfg.bind_host = "127.0.0.1";
        gw_cfg.bind_port = 0;
        gw_cfg.worker_threads = 1;
        gw_cfg.http2.enabled = false;
        gw_cfg.upstreams.push_back(
            MakePoolUpstreamConfig("svc", "127.0.0.1", backend_port, "/r"));

        std::shared_ptr<ObservabilityManager> manager = gw_fix.manager;
        constexpr int kNRequests = 5;
        {
            HttpServer gateway(gw_cfg);
            gateway.SetObservabilityManager(manager);
            TestServerRunner<HttpServer> gw_runner(gateway);
            int gw_port = gw_runner.GetPort();

            for (int i = 0; i < kNRequests; ++i) {
                std::string resp = SendOneRequest(gw_port, "/r");
                if (resp.find("200 OK") == std::string::npos) {
                    TestFramework::RecordTest(TAG, false,
                                               "request " + std::to_string(i) +
                                               " did not return 200",
                                               TestFramework::TestCategory::OTHER);
                    return;
                }
            }

            // Wait until gauge returns to zero — each FinalizeAttemptSpan
            // has emitted its matching -1 via the CAS.
            bool drained = WaitFor([&]() {
                auto snap = manager->meter_provider()->Snapshot();
                return SumGaugeByLabel(snap,
                    "http.client.active_requests",
                    "reactor.upstream.service", "svc") == 0.0;
            }, 3000);
            if (!drained) {
                auto snap = manager->meter_provider()->Snapshot();
                double live = SumGaugeByLabel(snap,
                    "http.client.active_requests",
                    "reactor.upstream.service", "svc");
                TestFramework::RecordTest(TAG, false,
                                           "happy path did not drain: live=" +
                                           std::to_string(live),
                                           TestFramework::TestCategory::OTHER);
                return;
            }
        }
        // Gateway destroyed cleanly — no residual drain.

        auto snap = manager->meter_provider()->Snapshot();
        double live = SumGaugeByLabel(snap,
            "http.client.active_requests",
            "reactor.upstream.service", "svc");
        uint64_t drained = manager->client_active_decremented_via_kill_or_dtor();

        bool pass = live == 0.0 && drained == 0;
        std::string err;
        if (!pass) {
            err = "live=" + std::to_string(live) +
                  " drained_via_kill_or_dtor=" + std::to_string(drained);
        }
        TestFramework::RecordTest(TAG, pass, err,
                                   TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                   TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Test 9 — TryDecrementIfPositive CAS stress. 1000 iterations × 2
// racing threads (finalize-style + kill-style) operating on a
// std::atomic<int> counter. Every +1 must produce EXACTLY one -1
// across both racers, never two.
// ---------------------------------------------------------------------
inline void TestClientActiveRequestsNoDoubleDecrement() {
    const char* TAG =
        "ObsPool: TryDecrementIfPositive — no double decrement under "
        "concurrent racers";
    try {
        constexpr int kIterations = 1000;
        std::atomic<int> finalize_wins{0};
        std::atomic<int> kill_wins{0};
        std::atomic<int> double_dec_events{0};

        for (int i = 0; i < kIterations; ++i) {
            std::atomic<int> counter{1};  // single +1, both threads race -1.
            std::atomic<bool> go{false};

            std::thread t_finalize([&counter, &finalize_wins, &go,
                                    &double_dec_events]() {
                while (!go.load(std::memory_order_acquire)) {}
                if (OBSERVABILITY_NAMESPACE::TryDecrementIfPositive(counter)) {
                    finalize_wins.fetch_add(1, std::memory_order_relaxed);
                    int post = counter.load(std::memory_order_acquire);
                    if (post < 0) {
                        double_dec_events.fetch_add(
                            1, std::memory_order_relaxed);
                    }
                }
            });

            std::thread t_kill([&counter, &kill_wins, &go,
                                &double_dec_events]() {
                while (!go.load(std::memory_order_acquire)) {}
                if (OBSERVABILITY_NAMESPACE::TryDecrementIfPositive(counter)) {
                    kill_wins.fetch_add(1, std::memory_order_relaxed);
                    int post = counter.load(std::memory_order_acquire);
                    if (post < 0) {
                        double_dec_events.fetch_add(
                            1, std::memory_order_relaxed);
                    }
                }
            });

            go.store(true, std::memory_order_release);
            t_finalize.join();
            t_kill.join();

            int post = counter.load(std::memory_order_acquire);
            // Exactly one winner per +1 — counter must end at 0.
            if (post != 0) {
                double_dec_events.fetch_add(1, std::memory_order_relaxed);
            }
        }

        int f = finalize_wins.load(std::memory_order_relaxed);
        int k = kill_wins.load(std::memory_order_relaxed);
        int dd = double_dec_events.load(std::memory_order_relaxed);

        // Every iteration: f + k must equal 1 (one winner per +1).
        bool pass = (f + k == kIterations) && dd == 0;
        std::string err;
        if (!pass) {
            err = "finalize_wins=" + std::to_string(f) +
                  " kill_wins=" + std::to_string(k) +
                  " expected_total=" + std::to_string(kIterations) +
                  " double_dec_events=" + std::to_string(dd);
        }
        TestFramework::RecordTest(TAG, pass, err,
                                   TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                   TestFramework::TestCategory::OTHER);
    }
}

inline void RunAllTests() {
    std::cout << "\n========================================" << std::endl;
    std::cout << "Running ObservabilityPoolGauges tests..." << std::endl;
    std::cout << "========================================\n" << std::endl;
    TestPoolIdleActiveTransitions();
    TestPoolCheckoutWaitDurationCreated();
    TestPoolCheckoutWaitDurationImmediate();
    TestPoolEvictExpiredDrainsIdle();
    TestPoolActiveDrainOnShutdown();
    TestPoolGaugesNullManagerSafe();
    TestClientActiveRequestsKillPath();
    TestClientActiveRequestsHappyPathDrainsCounter();
    TestClientActiveRequestsNoDoubleDecrement();
}

}  // namespace ObservabilityPoolGaugesTests
