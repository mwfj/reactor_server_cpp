#pragma once

// Per-attempt CLIENT span on the proxy path. Tests boot a real
// gateway HttpServer in front of a real backend HttpServer (both
// observability-enabled with InMemorySpanProcessor) and verify:
//   - Successful proxy request emits a CLIENT span (kind=3) with the
//     SERVER span as parent and the upstream attributes populated.
//   - 5xx upstream response marks the CLIENT span Error + status_code
//     attribute.
//   - Per-attempt fresh span_id — retried attempts surface as distinct
//     CLIENT spans sharing one trace_id.
//   - Observability disabled passes the inbound `traceparent` through
//     verbatim (no strip+inject) so the existing reverse-proxy
//     contract is preserved.

#include "test_framework.h"
#include "test_server_runner.h"
#include "http/http_request.h"
#include "http/http_response.h"
#include "http/http_server.h"
#include "config/server_config.h"
#include "observability/observability_config.h"
#include "observability/observability_manager.h"
#include "observability/resource.h"
#include "observability/sampler.h"
#include "observability/span_processor.h"
#include "observability/span_kind.h"
#include "observability/span_status.h"
#include "observability/trace_id.h"
#include "observability/attr_value.h"

#include <arpa/inet.h>
#include <chrono>
#include <memory>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

namespace ObservabilityProxyClientTests {

using OBSERVABILITY_NAMESPACE::AlwaysOnSampler;
using OBSERVABILITY_NAMESPACE::AlwaysOffSampler;
using OBSERVABILITY_NAMESPACE::InMemorySpanProcessor;
using OBSERVABILITY_NAMESPACE::ObservabilityConfig;
using OBSERVABILITY_NAMESPACE::ObservabilityManager;
using OBSERVABILITY_NAMESPACE::RandomSource;
using OBSERVABILITY_NAMESPACE::Resource;
using OBSERVABILITY_NAMESPACE::SamplerType;
using OBSERVABILITY_NAMESPACE::SpanKind;
using OBSERVABILITY_NAMESPACE::SpanStatusCode;

namespace {

std::string SendHttpRequest(int port, const std::string& request,
                              int timeout_ms = 5000) {
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

UpstreamConfig MakeProxyUpstreamConfig(const std::string& name,
                                        const std::string& host,
                                        int port,
                                        const std::string& route_prefix,
                                        bool strip_prefix = false) {
    UpstreamConfig cfg;
    cfg.name = name;
    cfg.host = host;
    cfg.port = port;
    cfg.pool.max_connections       = 4;
    cfg.pool.max_idle_connections  = 2;
    cfg.pool.connect_timeout_ms    = 2000;
    cfg.pool.idle_timeout_sec      = 30;
    cfg.pool.max_lifetime_sec      = 3600;
    cfg.proxy.route_prefix         = route_prefix;
    cfg.proxy.strip_prefix         = strip_prefix;
    cfg.proxy.response_timeout_ms  = 4000;
    return cfg;
}

struct ManagerFixture {
    std::shared_ptr<InMemorySpanProcessor> processor =
        std::make_shared<InMemorySpanProcessor>();
    std::shared_ptr<ObservabilityManager> manager;

    explicit ManagerFixture(SamplerType sampler = SamplerType::AlwaysOn,
                              const std::string& service = "obs-proxy-test") {
        ObservabilityConfig cfg;
        cfg.enabled = true;
        cfg.traces.enabled = true;
        cfg.metrics.enabled = false;
        cfg.traces.sampler.type = sampler;
        cfg.resource.service_name = service;
        manager = ObservabilityManager::Create(
            std::move(cfg),
            std::make_shared<Resource>(),
            processor,
            std::make_shared<RandomSource>(0xC11EFEEDULL));
    }
};

}  // namespace

inline void TestSuccessfulProxyEmitsClientSpan() {
    std::cout << "\n[TEST] Proxy CLIENT span: success path" << std::endl;
    try {
        ManagerFixture backend_fix(SamplerType::AlwaysOn, "obs-backend");
        HttpServer backend("127.0.0.1", 0);
        backend.SetObservabilityManager(backend_fix.manager);
        backend.Get("/hello", [](const HttpRequest&, HttpResponse& resp) {
            resp.Status(200).Body("world", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ManagerFixture gw_fix(SamplerType::AlwaysOn, "obs-gateway");
        ServerConfig gw_cfg;
        gw_cfg.bind_host = "127.0.0.1";
        gw_cfg.bind_port = 0;
        gw_cfg.worker_threads = 2;
        gw_cfg.http2.enabled = false;
        gw_cfg.upstreams.push_back(
            MakeProxyUpstreamConfig("backend", "127.0.0.1", backend_port, "/hello"));
        HttpServer gateway(gw_cfg);
        gateway.SetObservabilityManager(gw_fix.manager);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        std::string resp = SendHttpRequest(gw_port,
            "GET /hello HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        // Allow the dispatcher loop to drain finalize callbacks.
        std::this_thread::sleep_for(std::chrono::milliseconds(250));

        bool resp_ok = resp.find("200 OK") != std::string::npos &&
                       resp.find("world") != std::string::npos;

        auto spans = gw_fix.processor->Drain();
        // Expect: SERVER span on the inbound + CLIENT span on the outbound.
        int server_count = 0, client_count = 0;
        std::string server_trace_id, client_trace_id;
        std::string client_method, client_addr, client_proto;
        int64_t client_status = 0;
        int64_t client_resend_count = -1;
        for (const auto& s : spans) {
            if (s.kind == SpanKind::SERVER) {
                ++server_count;
                server_trace_id = s.context.trace_id().ToHex();
            } else if (s.kind == SpanKind::CLIENT) {
                ++client_count;
                client_trace_id = s.context.trace_id().ToHex();
                for (const auto& a : s.attributes) {
                    if (a.key == "http.request.method")
                        client_method = std::get<std::string>(a.value.value);
                    else if (a.key == "server.address")
                        client_addr = std::get<std::string>(a.value.value);
                    else if (a.key == "network.protocol.version")
                        client_proto = std::get<std::string>(a.value.value);
                    else if (a.key == "http.response.status_code")
                        client_status = std::get<int64_t>(a.value.value);
                    else if (a.key == "http.request.resend_count")
                        client_resend_count = std::get<int64_t>(a.value.value);
                }
            }
        }

        bool count_ok = (server_count == 1 && client_count == 1);
        bool trace_ok = !server_trace_id.empty() &&
                        server_trace_id == client_trace_id;
        bool attrs_ok = client_method == "GET" &&
                        client_addr == "127.0.0.1" &&
                        client_proto == "1.1" &&
                        client_status == 200 &&
                        client_resend_count == 0;

        bool pass = resp_ok && count_ok && trace_ok && attrs_ok;
        std::string err;
        if (!resp_ok) err = "response 200 missing";
        else if (!count_ok) err = "expected 1 SERVER + 1 CLIENT span; got " +
                                   std::to_string(server_count) + "/" +
                                   std::to_string(client_count);
        else if (!trace_ok) err = "trace_id mismatch SERVER=" + server_trace_id +
                                   " CLIENT=" + client_trace_id;
        else if (!attrs_ok) err = "attrs wrong: method=" + client_method +
                                   " addr=" + client_addr +
                                   " proto=" + client_proto +
                                   " status=" + std::to_string(client_status) +
                                   " resend=" + std::to_string(client_resend_count);
        TestFramework::RecordTest(
            "ProxyClient: successful proxy emits CLIENT span with parent + attrs",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ProxyClient: successful proxy emits CLIENT span with parent + attrs",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

inline void TestUpstream5xxMarksClientSpanError() {
    std::cout << "\n[TEST] Proxy CLIENT span: 5xx → Error" << std::endl;
    try {
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/boom", [](const HttpRequest&, HttpResponse& resp) {
            resp.Status(500).Body("bad", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ManagerFixture gw_fix(SamplerType::AlwaysOn, "obs-gateway-5xx");
        ServerConfig gw_cfg;
        gw_cfg.bind_host = "127.0.0.1";
        gw_cfg.bind_port = 0;
        gw_cfg.worker_threads = 2;
        gw_cfg.http2.enabled = false;
        auto upstream_cfg = MakeProxyUpstreamConfig(
            "backend", "127.0.0.1", backend_port, "/boom");
        // Disable retries — we want exactly one CLIENT span surfacing the 5xx.
        upstream_cfg.proxy.retry.max_retries = 0;
        upstream_cfg.proxy.retry.retry_on_5xx = false;
        gw_cfg.upstreams.push_back(std::move(upstream_cfg));
        HttpServer gateway(gw_cfg);
        gateway.SetObservabilityManager(gw_fix.manager);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        SendHttpRequest(gw_port,
            "GET /boom HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        std::this_thread::sleep_for(std::chrono::milliseconds(250));

        auto spans = gw_fix.processor->Drain();
        bool client_found = false;
        bool error_status = false;
        int64_t status_attr = 0;
        std::string error_type;
        for (const auto& s : spans) {
            if (s.kind != SpanKind::CLIENT) continue;
            client_found = true;
            error_status = (s.status_code == SpanStatusCode::ERROR);
            for (const auto& a : s.attributes) {
                if (a.key == "http.response.status_code")
                    status_attr = std::get<int64_t>(a.value.value);
                else if (a.key == "error.type")
                    error_type = std::get<std::string>(a.value.value);
            }
        }

        bool pass = client_found && error_status &&
                    status_attr == 500 && error_type == "500";
        std::string err;
        if (!client_found) err = "no CLIENT span found";
        else if (!error_status) err = "CLIENT span status not Error";
        else if (status_attr != 500)
            err = "status_code attr=" + std::to_string(status_attr);
        else if (error_type != "500") err = "error.type=" + error_type;
        TestFramework::RecordTest(
            "ProxyClient: upstream 5xx marks CLIENT span as Error",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ProxyClient: upstream 5xx marks CLIENT span as Error",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

inline void TestRetryAttemptsSurfaceDistinctClientSpans() {
    std::cout << "\n[TEST] Proxy CLIENT span: retries → distinct span_ids per attempt"
              << std::endl;
    try {
        // Backend: returns 503 every request — drives the gateway to
        // exhaust its retry budget so we see N+1 attempts on the wire.
        std::atomic<int> backend_calls{0};
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/flaky", [&backend_calls](const HttpRequest&, HttpResponse& resp) {
            backend_calls.fetch_add(1, std::memory_order_relaxed);
            resp.Status(503).Body("try-again", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ManagerFixture gw_fix(SamplerType::AlwaysOn, "obs-gateway-retry");
        ServerConfig gw_cfg;
        gw_cfg.bind_host = "127.0.0.1";
        gw_cfg.bind_port = 0;
        gw_cfg.worker_threads = 2;
        gw_cfg.http2.enabled = false;
        auto upstream_cfg = MakeProxyUpstreamConfig(
            "backend", "127.0.0.1", backend_port, "/flaky");
        upstream_cfg.proxy.retry.max_retries = 1;
        upstream_cfg.proxy.retry.retry_on_5xx = true;
        gw_cfg.upstreams.push_back(std::move(upstream_cfg));
        HttpServer gateway(gw_cfg);
        gateway.SetObservabilityManager(gw_fix.manager);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        SendHttpRequest(gw_port,
            "GET /flaky HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        // Allow retry (BASE_BACKOFF_MS=25 + jitter, MAX_BACKOFF_MS=250) +
        // finalize. 600ms covers the upper bound comfortably.
        std::this_thread::sleep_for(std::chrono::milliseconds(600));

        auto spans = gw_fix.processor->Drain();
        std::vector<std::string> client_span_ids;
        std::vector<std::string> client_trace_ids;
        std::vector<int64_t> resend_counts;
        for (const auto& s : spans) {
            if (s.kind != SpanKind::CLIENT) continue;
            client_span_ids.push_back(s.context.span_id().ToHex());
            client_trace_ids.push_back(s.context.trace_id().ToHex());
            for (const auto& a : s.attributes) {
                if (a.key == "http.request.resend_count") {
                    resend_counts.push_back(std::get<int64_t>(a.value.value));
                }
            }
        }

        bool count_ok = client_span_ids.size() >= 2;
        bool ids_distinct = count_ok &&
                            client_span_ids[0] != client_span_ids[1];
        bool trace_shared = count_ok &&
                            client_trace_ids[0] == client_trace_ids[1];
        bool resend_advanced = resend_counts.size() >= 2 &&
                               resend_counts[0] == 0 &&
                               resend_counts[1] >= 1;
        bool backend_called = backend_calls.load() >= 2;

        bool pass = count_ok && ids_distinct && trace_shared &&
                    resend_advanced && backend_called;
        std::string err;
        if (!count_ok) err = "expected >=2 CLIENT spans; got " +
                              std::to_string(client_span_ids.size());
        else if (!ids_distinct) err = "span_ids collided across retry";
        else if (!trace_shared) err = "trace_ids diverged across retry";
        else if (!resend_advanced) err = "resend_count not bumped on retry";
        else if (!backend_called) err = "backend hit only " +
                                         std::to_string(backend_calls.load()) +
                                         " times";
        TestFramework::RecordTest(
            "ProxyClient: retry attempts emit distinct CLIENT spans",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ProxyClient: retry attempts emit distinct CLIENT spans",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

inline void TestObservabilityDisabledForwardsTraceparentVerbatim() {
    std::cout << "\n[TEST] Proxy: observability OFF preserves inbound traceparent"
              << std::endl;
    try {
        std::string seen_traceparent;
        std::mutex tp_mtx;
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/echo-tp", [&](const HttpRequest& req, HttpResponse& resp) {
            std::lock_guard<std::mutex> g(tp_mtx);
            auto it = req.headers.find("traceparent");
            seen_traceparent = (it != req.headers.end()) ? it->second : "";
            resp.Status(200).Body("ok", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        // Gateway with NO observability manager attached — verbatim forward.
        ServerConfig gw_cfg;
        gw_cfg.bind_host = "127.0.0.1";
        gw_cfg.bind_port = 0;
        gw_cfg.worker_threads = 2;
        gw_cfg.http2.enabled = false;
        gw_cfg.upstreams.push_back(
            MakeProxyUpstreamConfig("backend", "127.0.0.1", backend_port, "/echo-tp"));
        HttpServer gateway(gw_cfg);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        const std::string client_tp =
            "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01";
        std::string req =
            "GET /echo-tp HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "traceparent: " + client_tp + "\r\n"
            "Connection: close\r\n\r\n";
        std::string resp = SendHttpRequest(gw_port, req);

        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        std::string captured;
        {
            std::lock_guard<std::mutex> g(tp_mtx);
            captured = seen_traceparent;
        }

        bool resp_ok = resp.find("200 OK") != std::string::npos;
        bool tp_ok = captured == client_tp;
        bool pass = resp_ok && tp_ok;
        std::string err;
        if (!resp_ok) err = "response not 200";
        else if (!tp_ok) err = "traceparent mismatch — backend saw '" +
                                captured + "'";
        TestFramework::RecordTest(
            "ProxyClient: observability disabled forwards traceparent verbatim",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ProxyClient: observability disabled forwards traceparent verbatim",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

inline void RunAllTests() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "PROXY CLIENT-SPAN OBSERVABILITY TESTS" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    TestSuccessfulProxyEmitsClientSpan();
    TestUpstream5xxMarksClientSpanError();
    TestRetryAttemptsSurfaceDistinctClientSpans();
    TestObservabilityDisabledForwardsTraceparentVerbatim();
}

}  // namespace ObservabilityProxyClientTests
