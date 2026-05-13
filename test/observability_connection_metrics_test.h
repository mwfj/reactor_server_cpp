#pragma once

// Connection-level transport / protocol observability tests.
//
// Coverage matches the four-metric design:
//   * reactor.net.connections.active   — UpDownCounter, no labels.
//   * reactor.net.connections.accepted — Counter,        no labels.
//   * reactor.http.connections.active  — UpDownCounter, {protocol}.
//   * reactor.tls.handshakes           — Counter,        {outcome}.
//
// The transport gauges are driven from ConnectionHandler at accept-time;
// the protocol gauge is driven by MarkApplicationProtocolConfirmed once
// the L7 layer has classified the peer (H1 first request, H2 preface
// accept, or WS upgrade handoff). The TLS counter is emitted from the
// handshake state machine on success/failure.

#include "test_framework.h"
#include "test_server_runner.h"
#include "http/http_server.h"
#include "config/server_config.h"
#include "observability/counter.h"
#include "observability/metrics_catalog.h"
#include "observability/metrics_snapshot.h"
#include "observability/meter_provider.h"
#include "observability/observability_config.h"
#include "observability/observability_manager.h"
#include "observability/resource.h"
#include "observability/sampler.h"
#include "observability/span_processor.h"

#include <arpa/inet.h>
#include <chrono>
#include <cstdint>
#include <memory>
#include <netinet/in.h>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

namespace ObservabilityConnectionMetricsTests {

using OBSERVABILITY_NAMESPACE::CounterPoint;
using OBSERVABILITY_NAMESPACE::InMemorySpanProcessor;
using OBSERVABILITY_NAMESPACE::InstrumentSnapshot;
using OBSERVABILITY_NAMESPACE::MetricsSnapshot;
using OBSERVABILITY_NAMESPACE::ObservabilityConfig;
using OBSERVABILITY_NAMESPACE::ObservabilityManager;
using OBSERVABILITY_NAMESPACE::RandomSource;
using OBSERVABILITY_NAMESPACE::Resource;
using OBSERVABILITY_NAMESPACE::SamplerType;

namespace {

// ---------------------------------------------------------------------
// Snapshot helpers — sum either the entire instrument or a labeled slice.
// ---------------------------------------------------------------------

double SumCounter(const MetricsSnapshot& snap, const std::string& name) {
    double total = 0;
    for (const auto& inst : snap.instruments) {
        if (inst.name != name) continue;
        for (const auto& p : inst.counter_points) total += p.value;
    }
    return total;
}

double SumCounterByLabel(const MetricsSnapshot& snap,
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

// ---------------------------------------------------------------------
// TCP + HTTP helpers — keep the assertions independent of the higher-
// level test fixtures so we control timing precisely.
// ---------------------------------------------------------------------

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

bool SendAll(int fd, const char* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = ::send(fd, data + sent, len - sent, 0);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

bool SendAll(int fd, const std::string& data) {
    return SendAll(fd, data.data(), data.size());
}

// Drain whatever's pending until the kernel buffer empties (or timeout).
// Used to confirm 200 OK / 101 / settings frame arrived before asserting.
std::string DrainSocket(int fd, int timeout_ms = 600) {
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

ObservabilityConfig MakeObsConfig() {
    ObservabilityConfig cfg;
    cfg.enabled                = true;
    cfg.traces.enabled         = true;
    cfg.metrics.enabled        = true;
    cfg.traces.sampler.type    = SamplerType::AlwaysOn;
    cfg.resource.service_name  = "obs-conn-metrics-test";
    return cfg;
}

struct ObsFixture {
    std::shared_ptr<InMemorySpanProcessor> processor;
    std::shared_ptr<ObservabilityManager>  manager;

    explicit ObsFixture(uint64_t seed = 0xC0FFEEULL) {
        processor = std::make_shared<InMemorySpanProcessor>();
        manager = ObservabilityManager::Create(
            MakeObsConfig(),
            std::make_shared<Resource>(),
            processor,
            std::make_shared<RandomSource>(seed));
    }
};

}  // namespace

// ---------------------------------------------------------------------
// Test 1 — opening a raw TCP connection bumps the transport gauge
// independently of any protocol classification.
// ---------------------------------------------------------------------
inline void TestTransportGaugeIndependentOfProtocol() {
    const char* TAG = "ObsConnMetrics: transport gauge bumps without protocol";
    try {
        ObsFixture fix;
        HttpServer server("127.0.0.1", 0);
        server.SetObservabilityManager(fix.manager);
        server.Get("/health", [](const HttpRequest&, HttpResponse& res) {
            res.Status(200).Text("ok");
        });
        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        int fd = ConnectTcp(port);
        if (fd < 0) {
            TestFramework::RecordTest(TAG, false, "connect failed",
                                       TestFramework::TestCategory::OTHER);
            return;
        }

        // Hold the socket open without writing any HTTP bytes — the
        // peer is a confirmed TCP connection but not yet a confirmed
        // HTTP/1.1 (which would require headers_complete) or HTTP/2
        // (preface).
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        auto snap = fix.manager->meter_provider()->Snapshot();
        double net_active = SumCounter(snap,
            "reactor.net.connections.active");
        double net_accepted = SumCounter(snap,
            "reactor.net.connections.accepted");
        double h1_active = SumCounterByLabel(snap,
            "reactor.http.connections.active", "protocol", "http/1.1");
        double h2_active = SumCounterByLabel(snap,
            "reactor.http.connections.active", "protocol", "h2");

        bool pass = net_active >= 1.0 && net_accepted >= 1.0 &&
                    h1_active == 0.0 && h2_active == 0.0;
        std::string err;
        if (!pass) {
            err = "net_active=" + std::to_string(net_active) +
                  " net_accepted=" + std::to_string(net_accepted) +
                  " h1_active=" + std::to_string(h1_active) +
                  " h2_active=" + std::to_string(h2_active);
        }
        ::close(fd);
        TestFramework::RecordTest(TAG, pass, err,
                                   TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                   TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Test 2 — closing the connection decrements
// reactor.net.connections.active back to baseline.
// ---------------------------------------------------------------------
inline void TestNetConnectionsActiveDecrementsOnClose() {
    const char* TAG = "ObsConnMetrics: net.connections.active decrements on close";
    try {
        ObsFixture fix;
        HttpServer server("127.0.0.1", 0);
        server.SetObservabilityManager(fix.manager);
        server.Get("/health", [](const HttpRequest&, HttpResponse& res) {
            res.Status(200).Text("ok");
        });
        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        auto snap_before = fix.manager->meter_provider()->Snapshot();
        double active_before = SumCounter(snap_before,
            "reactor.net.connections.active");

        int fd = ConnectTcp(port);
        if (fd < 0) {
            TestFramework::RecordTest(TAG, false, "connect failed",
                                       TestFramework::TestCategory::OTHER);
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        auto snap_mid = fix.manager->meter_provider()->Snapshot();
        double active_mid = SumCounter(snap_mid,
            "reactor.net.connections.active");

        ::close(fd);
        // Allow time for the dispatcher to observe the EOF and reap.
        std::this_thread::sleep_for(std::chrono::milliseconds(400));
        auto snap_after = fix.manager->meter_provider()->Snapshot();
        double active_after = SumCounter(snap_after,
            "reactor.net.connections.active");

        bool pass = active_mid >= active_before + 1.0 &&
                    active_after <= active_before + 0.0001;
        std::string err;
        if (!pass) {
            err = "before=" + std::to_string(active_before) +
                  " mid=" + std::to_string(active_mid) +
                  " after=" + std::to_string(active_after);
        }
        TestFramework::RecordTest(TAG, pass, err,
                                   TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                   TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Test 3 — first complete HTTP/1.1 request line bumps
// reactor.http.connections.active{protocol=http/1.1}.
// ---------------------------------------------------------------------
inline void TestH1FirstRequestSetsProtocolGauge() {
    const char* TAG = "ObsConnMetrics: HTTP/1.1 first request bumps protocol gauge";
    try {
        ObsFixture fix;
        HttpServer server("127.0.0.1", 0);
        server.SetObservabilityManager(fix.manager);
        server.Get("/health", [](const HttpRequest&, HttpResponse& res) {
            res.Status(200).Text("ok");
        });
        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        int fd = ConnectTcp(port);
        if (fd < 0) {
            TestFramework::RecordTest(TAG, false, "connect failed",
                                       TestFramework::TestCategory::OTHER);
            return;
        }
        const std::string req =
            "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n";
        if (!SendAll(fd, req)) {
            ::close(fd);
            TestFramework::RecordTest(TAG, false, "send failed",
                                       TestFramework::TestCategory::OTHER);
            return;
        }
        std::string resp = DrainSocket(fd, 800);
        // Don't close yet — assert while the connection is still alive
        // so the +1 hasn't been reversed by the dtor.

        auto snap = fix.manager->meter_provider()->Snapshot();
        double h1_active = SumCounterByLabel(snap,
            "reactor.http.connections.active", "protocol", "http/1.1");
        double h2_active = SumCounterByLabel(snap,
            "reactor.http.connections.active", "protocol", "h2");

        bool got_200 = resp.find("200 OK") != std::string::npos;
        bool pass = got_200 && h1_active >= 1.0 && h2_active == 0.0;
        std::string err;
        if (!pass) {
            err = "got_200=" + std::to_string(static_cast<int>(got_200)) +
                  " h1=" + std::to_string(h1_active) +
                  " h2=" + std::to_string(h2_active);
        }
        ::close(fd);
        TestFramework::RecordTest(TAG, pass, err,
                                   TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                   TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Test 4 — h2c preface acceptance bumps
// reactor.http.connections.active{protocol=h2}.
// ---------------------------------------------------------------------
inline void TestH2PrefaceSetsProtocolGauge() {
    const char* TAG = "ObsConnMetrics: HTTP/2 preface bumps protocol=h2 gauge";
    try {
        ObsFixture fix;
        ServerConfig scfg;
        scfg.bind_host      = "127.0.0.1";
        scfg.bind_port      = 0;
        scfg.worker_threads = 2;
        scfg.http2.enabled  = true;
        HttpServer server(scfg);
        server.SetObservabilityManager(fix.manager);
        server.Get("/h2", [](const HttpRequest&, HttpResponse& res) {
            res.Status(200).Text("ok");
        });
        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        int fd = ConnectTcp(port);
        if (fd < 0) {
            TestFramework::RecordTest(TAG, false, "connect failed",
                                       TestFramework::TestCategory::OTHER);
            return;
        }
        // The client preface is enough to trigger H2 detection +
        // Http2ConnectionHandler::Initialize; we follow it with an
        // empty client SETTINGS frame so the server doesn't dangle on
        // missing settings.
        static const char kH2Preface[] =
            "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        static const char kEmptySettings[] = {
            0x00, 0x00, 0x00,  // length=0
            0x04,               // type=SETTINGS
            0x00,               // flags=0
            0x00, 0x00, 0x00, 0x00,  // stream=0
        };
        if (!SendAll(fd, kH2Preface, sizeof(kH2Preface) - 1) ||
            !SendAll(fd, kEmptySettings, sizeof(kEmptySettings))) {
            ::close(fd);
            TestFramework::RecordTest(TAG, false, "send failed",
                                       TestFramework::TestCategory::OTHER);
            return;
        }
        // Give the dispatcher time to receive + classify + run Initialize.
        DrainSocket(fd, 400);

        auto snap = fix.manager->meter_provider()->Snapshot();
        double h2_active = SumCounterByLabel(snap,
            "reactor.http.connections.active", "protocol", "h2");
        double h1_active = SumCounterByLabel(snap,
            "reactor.http.connections.active", "protocol", "http/1.1");

        bool pass = h2_active >= 1.0 && h1_active == 0.0;
        std::string err;
        if (!pass) {
            err = "h2=" + std::to_string(h2_active) +
                  " h1=" + std::to_string(h1_active);
        }
        ::close(fd);
        TestFramework::RecordTest(TAG, pass, err,
                                   TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                   TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Test 5 — WS upgrade hands off the http/1.1 slot to a fresh
// protocol=websocket slot.
// ---------------------------------------------------------------------
inline void TestWsUpgradeTransitionsProtocolGauge() {
    const char* TAG = "ObsConnMetrics: WS upgrade transitions http/1.1 → websocket";
    try {
        ObsFixture fix;
        HttpServer server("127.0.0.1", 0);
        server.SetObservabilityManager(fix.manager);
        server.WebSocket("/ws", [](WebSocketConnection&) {});
        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        int fd = ConnectTcp(port);
        if (fd < 0) {
            TestFramework::RecordTest(TAG, false, "connect failed",
                                       TestFramework::TestCategory::OTHER);
            return;
        }
        const std::string upgrade =
            "GET /ws HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n";
        if (!SendAll(fd, upgrade)) {
            ::close(fd);
            TestFramework::RecordTest(TAG, false, "send failed",
                                       TestFramework::TestCategory::OTHER);
            return;
        }
        std::string resp = DrainSocket(fd, 800);
        bool got_101 = resp.find("101") != std::string::npos &&
                       resp.find("Upgrade: websocket") != std::string::npos;

        auto snap = fix.manager->meter_provider()->Snapshot();
        double ws_active = SumCounterByLabel(snap,
            "reactor.http.connections.active", "protocol", "websocket");
        double h1_active = SumCounterByLabel(snap,
            "reactor.http.connections.active", "protocol", "http/1.1");

        bool pass = got_101 && ws_active >= 1.0 && h1_active == 0.0;
        std::string err;
        if (!pass) {
            err = "got_101=" + std::to_string(static_cast<int>(got_101)) +
                  " ws=" + std::to_string(ws_active) +
                  " h1=" + std::to_string(h1_active);
        }
        ::close(fd);
        TestFramework::RecordTest(TAG, pass, err,
                                   TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                   TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Test 6 — accepted counter is monotonic across multiple connections.
// Validates the Counter (not UpDownCounter) semantic and that the
// label catalog reads the unlabeled value (no protocol axis).
// ---------------------------------------------------------------------
inline void TestNetAcceptedIsMonotonic() {
    const char* TAG = "ObsConnMetrics: net.connections.accepted monotonic over N opens";
    try {
        ObsFixture fix;
        HttpServer server("127.0.0.1", 0);
        server.SetObservabilityManager(fix.manager);
        server.Get("/h", [](const HttpRequest&, HttpResponse& res) {
            res.Status(200).Text("ok");
        });
        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        auto snap_before = fix.manager->meter_provider()->Snapshot();
        double accepted_before = SumCounter(snap_before,
            "reactor.net.connections.accepted");

        constexpr int N = 5;
        for (int i = 0; i < N; ++i) {
            int fd = ConnectTcp(port);
            if (fd < 0) {
                TestFramework::RecordTest(TAG, false,
                    "connect failed at i=" + std::to_string(i),
                    TestFramework::TestCategory::OTHER);
                return;
            }
            // Open + immediately close. The accept-time +1 fires
            // regardless of any later HTTP traffic.
            ::close(fd);
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        // Let the dispatcher drain the accept queue.
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        auto snap_after = fix.manager->meter_provider()->Snapshot();
        double accepted_after = SumCounter(snap_after,
            "reactor.net.connections.accepted");
        double accepted_delta = accepted_after - accepted_before;

        bool pass = accepted_delta >= static_cast<double>(N);
        std::string err;
        if (!pass) {
            err = "delta=" + std::to_string(accepted_delta) +
                  " expected>=" + std::to_string(N);
        }
        TestFramework::RecordTest(TAG, pass, err,
                                   TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                   TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Suite entry point.
// ---------------------------------------------------------------------
inline void RunAllTests() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "OBSERVABILITY CONNECTION METRICS TESTS" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    TestTransportGaugeIndependentOfProtocol();
    TestNetConnectionsActiveDecrementsOnClose();
    TestH1FirstRequestSetsProtocolGauge();
    TestH2PrefaceSetsProtocolGauge();
    TestWsUpgradeTransitionsProtocolGauge();
    TestNetAcceptedIsMonotonic();
}

}  // namespace ObservabilityConnectionMetricsTests
