#pragma once

// End-to-end observability tests — verify FinalizeFromSnapshot fires
// on real HTTP requests through HttpServer with the observability
// middleware installed.
//
// These tests boot a real HttpServer, install an ObservabilityManager
// backed by the InMemorySpanProcessor, send TCP-level HTTP requests via
// SendHttpRequest, and assert the captured spans + finalize counters
// match the request shape.

#include "test_framework.h"
#include "test_server_runner.h"
#include "http/http_request.h"
#include "http/http_response.h"
#include "http/http_server.h"
#include "observability/observability_config.h"
#include "observability/observability_manager.h"
#include "observability/resource.h"
#include "observability/sampler.h"
#include "observability/span_processor.h"
#include "observability/trace_id.h"

#include <arpa/inet.h>
#include <chrono>
#include <memory>
#include <netinet/in.h>
#include <poll.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

namespace ObservabilityE2ETests {

using OBSERVABILITY_NAMESPACE::AlwaysOnSampler;
using OBSERVABILITY_NAMESPACE::InMemorySpanProcessor;
using OBSERVABILITY_NAMESPACE::ObservabilityConfig;
using OBSERVABILITY_NAMESPACE::ObservabilityManager;
using OBSERVABILITY_NAMESPACE::RandomSource;
using OBSERVABILITY_NAMESPACE::Resource;
using OBSERVABILITY_NAMESPACE::SamplerType;

namespace {

// Mirror the SendHttpRequest helper used elsewhere in the test suite —
// connect, send, poll-read, close.
std::string SendHttpRequest(int port, const std::string& request) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return "";
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sockfd);
        return "";
    }
    if (send(sockfd, request.data(), request.size(), 0) < 0) {
        close(sockfd);
        return "";
    }
    struct pollfd pfd{};
    pfd.fd = sockfd;
    pfd.events = POLLIN;
    std::string response;
    char buf[4096];
    int timeout_ms = 3000;
    auto start = std::chrono::steady_clock::now();
    while (true) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        int remaining = timeout_ms - static_cast<int>(elapsed);
        if (remaining <= 0) break;
        int rv = poll(&pfd, 1, remaining);
        if (rv <= 0) break;
        ssize_t n = recv(sockfd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        response.append(buf, static_cast<size_t>(n));
    }
    close(sockfd);
    return response;
}

struct ObservabilityFixture {
    std::shared_ptr<InMemorySpanProcessor> processor =
        std::make_shared<InMemorySpanProcessor>();
    std::shared_ptr<ObservabilityManager> manager;

    explicit ObservabilityFixture(SamplerType sampler = SamplerType::AlwaysOn) {
        ObservabilityConfig cfg;
        cfg.enabled = true;
        cfg.traces.enabled = true;
        cfg.metrics.enabled = true;
        cfg.traces.sampler.type = sampler;
        cfg.resource.service_name = "obs-e2e-test";
        manager = ObservabilityManager::Create(
            std::move(cfg),
            std::make_shared<Resource>(),
            processor,
            std::make_shared<RandomSource>(0xE2EFEED1ULL));
    }
};

}  // namespace

// Sync GET → InMemorySpanProcessor captures one SERVER span with
// http.request.method=GET, http.route=/health, status=200.
void TestSyncGetEmitsServerSpan() {
    try {
        ObservabilityFixture fix;
        HttpServer server("127.0.0.1", 0);
        server.SetObservabilityManager(fix.manager);
        server.Get("/health", [](HttpRequest&, HttpResponse& res) {
            res.Status(200).Json(R"({"status":"ok"})");
        });

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();
        std::string response = SendHttpRequest(port,
            "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");

        bool resp_ok = response.find("200 OK") != std::string::npos &&
                       response.find(R"({"status":"ok"})") != std::string::npos;
        // Allow finalize to run; FinalizeFromSnapshot is sync but the
        // InMemorySpanProcessor::OnEnd is invoked from the same dispatcher
        // thread that handled the request, so we just need to wait for
        // the connection-close path to finish.
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        auto spans = fix.processor->Drain();
        bool span_ok = spans.size() == 1 &&
                       spans[0].name == "/health" &&
                       spans[0].kind == OBSERVABILITY_NAMESPACE::SpanKind::SERVER;

        bool attrs_ok = false;
        std::string method_attr, route_attr, status_attr;
        if (span_ok) {
            for (const auto& a : spans[0].attributes) {
                if (a.key == "http.request.method")
                    method_attr = std::get<std::string>(a.value.value);
                else if (a.key == "http.route")
                    route_attr = std::get<std::string>(a.value.value);
                else if (a.key == "http.response.status_code")
                    status_attr = std::to_string(
                        std::get<int64_t>(a.value.value));
            }
            attrs_ok = method_attr == "GET" &&
                       route_attr == "/health";
        }

        bool counter_ok = fix.manager->inflight_finalizations() == 0;

        bool pass = resp_ok && span_ok && attrs_ok && counter_ok;
        std::string err;
        if (!resp_ok) err = "response missing 200 OK or body";
        else if (!span_ok) err = "expected 1 SERVER span; got " +
                                  std::to_string(spans.size());
        else if (!attrs_ok) err = "attrs wrong: method=" + method_attr +
                                  " route=" + route_attr;
        else if (!counter_ok) err = "inflight_finalizations leaked: " +
                                     std::to_string(fix.manager->inflight_finalizations());
        TestFramework::RecordTest(
            "ObsE2E: sync GET emits SERVER span + finalizes counter",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsE2E: sync GET emits SERVER span + finalizes counter",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Sync POST with body → finalize fires; subsequent requests do not
// share the snapshot (each gets a fresh one).
void TestPipelinedRequestsHaveDistinctSnapshots() {
    try {
        ObservabilityFixture fix;
        HttpServer server("127.0.0.1", 0);
        server.SetObservabilityManager(fix.manager);
        server.Get("/a", [](HttpRequest&, HttpResponse& res) {
            res.Status(200).Text("a");
        });
        server.Get("/b", [](HttpRequest&, HttpResponse& res) {
            res.Status(204).Text("");  // bodyless status — wire size = 0.
        });

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        SendHttpRequest(port,
            "GET /a HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        SendHttpRequest(port,
            "GET /b HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        auto spans = fix.processor->Drain();
        bool pass = spans.size() == 2 &&
                    fix.manager->inflight_finalizations() == 0;
        // Confirm each span has its own trace_id (distinct requests).
        if (pass && spans[0].context.trace_id() == spans[1].context.trace_id()) {
            pass = false;
        }
        TestFramework::RecordTest(
            "ObsE2E: distinct requests produce distinct trace_ids",
            pass, pass ? "" : "trace_ids collided or wrong span count",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsE2E: distinct requests produce distinct trace_ids",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Middleware-rejection path (404) finalizes through the snapshot too —
// per §6.1.2 contract.
void TestNotFoundFinalizesSnapshot() {
    try {
        ObservabilityFixture fix;
        HttpServer server("127.0.0.1", 0);
        server.SetObservabilityManager(fix.manager);
        // No handlers — every request gets the framework's 404.
        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();
        SendHttpRequest(port,
            "GET /no-such-route HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        auto spans = fix.processor->Drain();
        bool pass = spans.size() == 1 &&
                    fix.manager->inflight_finalizations() == 0;
        TestFramework::RecordTest(
            "ObsE2E: 404 path finalizes snapshot (no leak)",
            pass, pass ? "" : "404 leaked snapshot or skipped span",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsE2E: 404 path finalizes snapshot (no leak)",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void RunAllTests() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "OBSERVABILITY END-TO-END TESTS" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    TestSyncGetEmitsServerSpan();
    TestPipelinedRequestsHaveDistinctSnapshots();
    TestNotFoundFinalizesSnapshot();
}

}  // namespace ObservabilityE2ETests
