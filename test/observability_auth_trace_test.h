#pragma once

// Auth-path observability — IdP introspection POSTs receive a fresh
// `traceparent` continuing the inbound trace, and the deferred dispatch
// (when `traces.auth_idp_span` is enabled) is wrapped in an
// `auth.idp_check` INTERNAL span whose parent is the inbound SERVER
// span. Tests boot a real gateway HttpServer with auth + observability
// enabled and a MockIntrospectionServer acting as the IdP.

#include "test_framework.h"
#include "test_server_runner.h"
#include "mock_introspection_server.h"
#include "http/http_server.h"
#include "http/http_request.h"
#include "http/http_response.h"
#include "auth/auth_manager.h"
#include "auth/auth_config.h"
#include "auth/issuer.h"
#include "config/server_config.h"
#include "log/logger.h"
#include "observability/observability_config.h"
#include "observability/observability_manager.h"
#include "observability/resource.h"
#include "observability/sampler.h"
#include "observability/span_processor.h"
#include "observability/span_kind.h"
#include "observability/span_status.h"
#include "observability/trace_id.h"

#include <arpa/inet.h>
#include <cstdlib>
#include <chrono>
#include <memory>
#include <netinet/in.h>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

namespace ObservabilityAuthTraceTests {

using OBSERVABILITY_NAMESPACE::AlwaysOnSampler;
using OBSERVABILITY_NAMESPACE::InMemorySpanProcessor;
using OBSERVABILITY_NAMESPACE::ObservabilityConfig;
using OBSERVABILITY_NAMESPACE::ObservabilityManager;
using OBSERVABILITY_NAMESPACE::RandomSource;
using OBSERVABILITY_NAMESPACE::Resource;
using OBSERVABILITY_NAMESPACE::SamplerType;
using OBSERVABILITY_NAMESPACE::SpanKind;

namespace {

constexpr const char* kSecretEnvVar = "GW_OBS_AUTH_TRACE_SECRET";
constexpr const char* kSecretValue  = "obs-auth-trace-secret";

struct ScopedEnv {
    std::string name;
    std::optional<std::string> prior;
    ScopedEnv(const std::string& n, const std::string& v) : name(n) {
        if (const char* p = std::getenv(n.c_str())) prior.emplace(p);
        ::setenv(n.c_str(), v.c_str(), 1);
    }
    ~ScopedEnv() {
        if (prior) ::setenv(name.c_str(), prior->c_str(), 1);
        else ::unsetenv(name.c_str());
    }
};

bool SendAll(int fd, const std::string& data) {
    size_t sent = 0;
    while (sent < data.size()) {
        ssize_t n = ::send(fd, data.data() + sent, data.size() - sent, 0);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

std::string RecvResponse(int fd, int timeout_ms = 4000) {
    std::string out;
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        struct pollfd pfd{fd, POLLIN, 0};
        int rv;
        do { rv = ::poll(&pfd, 1, 100); } while (rv < 0 && errno == EINTR);
        if (rv < 0) break;
        if (rv == 0) continue;
        char buf[4096];
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        out.append(buf, static_cast<size_t>(n));
        auto he = out.find("\r\n\r\n");
        if (he != std::string::npos) {
            auto cl_pos = out.find("Content-Length: ");
            if (cl_pos != std::string::npos && cl_pos < he) {
                auto eol = out.find('\r', cl_pos + 16);
                int cl = std::stoi(out.substr(cl_pos + 16, eol - cl_pos - 16));
                if (static_cast<int>(out.size() - he - 4) >= cl) break;
            } else {
                break;
            }
        }
    }
    return out;
}

std::string SendBearerGet(int port, const std::string& path,
                            const std::string& bearer) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return "";
    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(static_cast<uint16_t>(port));
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return "";
    }
    std::string req = "GET " + path + " HTTP/1.1\r\n"
                      "Host: localhost\r\n"
                      "Connection: close\r\n"
                      "Authorization: Bearer " + bearer + "\r\n\r\n";
    SendAll(fd, req);
    std::string resp = RecvResponse(fd);
    ::shutdown(fd, SHUT_RDWR);
    ::close(fd);
    return resp;
}

int ExtractStatus(const std::string& resp) {
    if (resp.size() < 12) return 0;
    try { return std::stoi(resp.substr(9, 3)); } catch (...) { return 0; }
}

struct ManagerFixture {
    std::shared_ptr<InMemorySpanProcessor> processor =
        std::make_shared<InMemorySpanProcessor>();
    std::shared_ptr<ObservabilityManager> manager;

    explicit ManagerFixture(bool auth_idp_span_enabled) {
        ObservabilityConfig cfg;
        cfg.enabled = true;
        cfg.traces.enabled = true;
        cfg.metrics.enabled = false;
        cfg.traces.sampler.type = SamplerType::AlwaysOn;
        cfg.traces.auth_idp_span = auth_idp_span_enabled;
        cfg.resource.service_name = "obs-auth-trace-test";
        manager = ObservabilityManager::Create(
            std::move(cfg),
            std::make_shared<Resource>(),
            processor,
            std::make_shared<RandomSource>(0xA071FACEULL));
    }
};

AUTH_NAMESPACE::IssuerConfig MakeIntrospectionIssuer(
        const std::string& issuer_name,
        const std::string& upstream_pool_name,
        const std::string& endpoint_url) {
    AUTH_NAMESPACE::IssuerConfig ic;
    ic.name       = issuer_name;
    ic.issuer_url = "https://idp.test";
    ic.discovery  = false;
    ic.mode       = "introspection";
    ic.upstream   = upstream_pool_name;
    ic.introspection.endpoint           = endpoint_url;
    ic.introspection.client_id          = "test-client-id";
    ic.introspection.client_secret_env  = kSecretEnvVar;
    ic.introspection.auth_style         = "basic";
    ic.introspection.timeout_sec        = 3;
    ic.introspection.cache_sec          = 60;
    ic.introspection.negative_cache_sec = 10;
    ic.introspection.stale_grace_sec    = 30;
    ic.introspection.max_entries        = 256;
    ic.introspection.shards             = 4;
    return ic;
}

ServerConfig BuildAuthGatewayConfig(
        const MockIntrospectionServerNS::MockIntrospectionServer& mock,
        const std::string& issuer_name,
        const std::string& upstream_pool_name) {
    ServerConfig cfg;
    cfg.bind_host = "127.0.0.1";
    cfg.bind_port = 0;
    cfg.worker_threads = 2;
    cfg.http2.enabled  = false;

    UpstreamConfig upstream;
    upstream.name = upstream_pool_name;
    upstream.host = mock.host();
    upstream.port = mock.port();
    upstream.pool.connect_timeout_ms = 2000;
    cfg.upstreams.push_back(std::move(upstream));

    cfg.auth.enabled = true;
    const std::string endpoint =
        "https://" + mock.host() + ":" + std::to_string(mock.port()) + "/introspect";
    cfg.auth.issuers[issuer_name] = MakeIntrospectionIssuer(
        issuer_name, upstream_pool_name, endpoint);

    AUTH_NAMESPACE::AuthPolicy policy;
    policy.name             = "p_protected";
    policy.enabled          = true;
    policy.applies_to       = {"/protected"};
    policy.issuers          = {issuer_name};
    policy.required_scopes  = {};
    policy.on_undetermined  = "deny";
    cfg.auth.policies.push_back(std::move(policy));
    return cfg;
}

}  // namespace

inline void TestIntrospectionInjectsTraceparent() {
    std::cout << "\n[TEST] Auth: introspection injects traceparent" << std::endl;
    try {
        ScopedEnv env(kSecretEnvVar, kSecretValue);

        MockIntrospectionServerNS::MockIntrospectionServer mock;
        if (!mock.Start()) {
            TestFramework::RecordTest(
                "AuthTrace: introspection injects traceparent", false,
                "mock IdP failed to start");
            return;
        }
        mock.EnqueueActiveTrue("user1", {});

        const std::string issuer_name = "test_iss";
        const std::string upstream    = "mock_idp";
        ServerConfig cfg = BuildAuthGatewayConfig(mock, issuer_name, upstream);

        ManagerFixture fix(/*auth_idp_span_enabled=*/true);
        HttpServer server(cfg);
        server.SetObservabilityManager(fix.manager);
        server.Get("/protected", [](const HttpRequest&, HttpResponse& resp) {
            resp.Status(200).Body("ok", "text/plain");
        });
        TestServerRunner<HttpServer> runner(server);
        // Issuer wire-up is non-blocking — give it a moment so the
        // first request hits the introspection path rather than
        // racing the issuer-not-ready short-circuit.
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        std::string resp = SendBearerGet(runner.GetPort(), "/protected",
                                           "tok-12345");
        std::this_thread::sleep_for(std::chrono::milliseconds(250));

        bool resp_ok = ExtractStatus(resp) == 200;
        std::string idp_traceparent = mock.received_header("traceparent");

        bool count_ok = mock.request_count() >= 1;
        bool tp_present = !idp_traceparent.empty();
        // W3C `traceparent` shape: version(2)-traceid(32)-spanid(16)-flags(2),
        // total 55 chars with 4 dashes.
        bool tp_shape_ok = idp_traceparent.size() == 55;

        bool pass = resp_ok && count_ok && tp_present && tp_shape_ok;
        std::string err;
        if (!resp_ok) err = "response status " + std::to_string(ExtractStatus(resp));
        else if (!count_ok) err = "mock IdP not called";
        else if (!tp_present) err = "no traceparent on IdP request";
        else if (!tp_shape_ok) err = "traceparent malformed: " + idp_traceparent;

        TestFramework::RecordTest(
            "AuthTrace: introspection injects traceparent",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "AuthTrace: introspection injects traceparent",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

inline void TestAuthIdpCheckSpanAllocated() {
    std::cout << "\n[TEST] Auth: auth.idp_check INTERNAL span allocated" << std::endl;
    try {
        ScopedEnv env(kSecretEnvVar, kSecretValue);

        MockIntrospectionServerNS::MockIntrospectionServer mock;
        if (!mock.Start()) {
            TestFramework::RecordTest(
                "AuthTrace: auth.idp_check INTERNAL span allocated", false,
                "mock IdP failed to start");
            return;
        }
        mock.EnqueueActiveTrue("user1", {});

        const std::string issuer_name = "test_iss";
        const std::string upstream    = "mock_idp";
        ServerConfig cfg = BuildAuthGatewayConfig(mock, issuer_name, upstream);

        ManagerFixture fix(/*auth_idp_span_enabled=*/true);
        HttpServer server(cfg);
        server.SetObservabilityManager(fix.manager);
        server.Get("/protected", [](const HttpRequest&, HttpResponse& resp) {
            resp.Status(200).Body("ok", "text/plain");
        });
        TestServerRunner<HttpServer> runner(server);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        SendBearerGet(runner.GetPort(), "/protected", "tok-abc");
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        auto spans = fix.processor->Drain();
        int internal_count = 0;
        int server_count = 0;
        std::string idp_check_trace_id;
        std::string server_trace_id;
        std::string idp_outcome;
        std::string idp_cache;
        for (const auto& s : spans) {
            if (s.kind == SpanKind::SERVER) {
                ++server_count;
                server_trace_id = s.context.trace_id().ToHex();
            } else if (s.kind == SpanKind::INTERNAL &&
                        s.name == "auth.idp_check") {
                ++internal_count;
                idp_check_trace_id = s.context.trace_id().ToHex();
                for (const auto& a : s.attributes) {
                    if (a.key == "auth.outcome")
                        idp_outcome = std::get<std::string>(a.value.value);
                    else if (a.key == "auth.cache_outcome")
                        idp_cache = std::get<std::string>(a.value.value);
                }
            }
        }

        bool count_ok = (server_count == 1 && internal_count == 1);
        bool trace_ok = !server_trace_id.empty() &&
                        idp_check_trace_id == server_trace_id;
        bool outcome_ok = idp_outcome == "allow";
        bool cache_ok = idp_cache == "miss";

        bool pass = count_ok && trace_ok && outcome_ok && cache_ok;
        std::string err;
        if (!count_ok) err = "expected 1 SERVER + 1 auth.idp_check INTERNAL; got " +
                              std::to_string(server_count) + "/" +
                              std::to_string(internal_count);
        else if (!trace_ok) err = "trace_id mismatch SERVER=" + server_trace_id +
                                   " IDP=" + idp_check_trace_id;
        else if (!outcome_ok) err = "auth.outcome=" + idp_outcome;
        else if (!cache_ok) err = "auth.cache_outcome=" + idp_cache;

        TestFramework::RecordTest(
            "AuthTrace: auth.idp_check INTERNAL span allocated with parent + outcome",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "AuthTrace: auth.idp_check INTERNAL span allocated with parent + outcome",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

inline void TestAuthIdpSpanDisabledFallsBackToEvents() {
    std::cout << "\n[TEST] Auth: auth_idp_span=false → pending_* events" << std::endl;
    try {
        ScopedEnv env(kSecretEnvVar, kSecretValue);

        MockIntrospectionServerNS::MockIntrospectionServer mock;
        if (!mock.Start()) {
            TestFramework::RecordTest(
                "AuthTrace: auth_idp_span=false emits pending_*",
                false, "mock IdP failed to start");
            return;
        }
        mock.EnqueueActiveTrue("user1", {});

        const std::string issuer_name = "test_iss";
        const std::string upstream    = "mock_idp";
        ServerConfig cfg = BuildAuthGatewayConfig(mock, issuer_name, upstream);

        ManagerFixture fix(/*auth_idp_span_enabled=*/false);
        HttpServer server(cfg);
        server.SetObservabilityManager(fix.manager);
        server.Get("/protected", [](const HttpRequest&, HttpResponse& resp) {
            resp.Status(200).Body("ok", "text/plain");
        });
        TestServerRunner<HttpServer> runner(server);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        SendBearerGet(runner.GetPort(), "/protected", "tok-xyz");
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        auto spans = fix.processor->Drain();
        int internal_count = 0;
        bool saw_pending_start = false;
        bool saw_pending_end = false;
        for (const auto& s : spans) {
            if (s.kind == SpanKind::INTERNAL && s.name == "auth.idp_check") {
                ++internal_count;
            }
            if (s.kind == SpanKind::SERVER) {
                for (const auto& ev : s.events) {
                    if (ev.name == "auth.pending_start") saw_pending_start = true;
                    if (ev.name == "auth.pending_end")   saw_pending_end = true;
                }
            }
        }

        bool no_internal = (internal_count == 0);
        bool both_events = saw_pending_start && saw_pending_end;
        bool pass = no_internal && both_events;
        std::string err;
        if (!no_internal) err = "auth.idp_check span emitted despite flag off";
        else if (!both_events) err = std::string("missing events: start=") +
                                      (saw_pending_start ? "yes" : "no") +
                                      " end=" + (saw_pending_end ? "yes" : "no");

        TestFramework::RecordTest(
            "AuthTrace: auth_idp_span=false emits pending_start + pending_end",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "AuthTrace: auth_idp_span=false emits pending_start + pending_end",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

inline void RunAllTests() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "AUTH-PATH TRACE OBSERVABILITY TESTS" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    TestIntrospectionInjectsTraceparent();
    TestAuthIdpCheckSpanAllocated();
    TestAuthIdpSpanDisabledFallsBackToEvents();
}

}  // namespace ObservabilityAuthTraceTests
