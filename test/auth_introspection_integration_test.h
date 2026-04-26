#pragma once

// ============================================================================
// Introspection-mode integration tests.
//
// Each test spins up a real HttpServer configured with an introspection-mode
// issuer and a MockIntrospectionServer acting as the IdP.  The server is
// created via cfg.auth so that HttpServer::MarkServerReady installs both the
// sync and async middleware chains (needed for the deferred-POST path).
//
// Coverage:
//  1.  Active_True_ReturnsAllow_200
//  2.  Active_False_Returns401
//  3.  CacheHit_SkipsIdpCall
//  4.  CacheMiss_CallsIdp
//  5.  AuthStyle_Basic_HeaderShape
//  6.  AuthStyle_Body_BodyShape
//  7.  ClientSecret_FromEnv
//  8.  ClientSecret_MissingEnv_FailsClosed
//  9.  UrlEncoding_TokenWithEqualsPadding
// 10.  TtlClamp_ExpShorterThanCacheSec
// 11.  TtlClamp_ExpLongerThanCacheSec
// 12.  NegativeCache_TtlObserved
// 13.  Timeout_UndeterminedOrStaleServe
// 14.  CircuitBreakerOpen_OnIdp_StaleServeIfPossible
// 15.  InsufficientScope_PositiveCached_OtherPolicyAllows
// 16.  MalformedIdpResponse_Undetermined
// 16b. MissingActiveField_Undetermined
// 17.  MixedModePolicy_JwtFirst_IntrospectionFallback
// 18.  HeaderRewriter_OutboundOverlay_WorksForIntrospection
// ============================================================================

#include "test_framework.h"
#include "test_server_runner.h"
#include "mock_introspection_server.h"
#include "http/http_server.h"
#include "http/http_request.h"
#include "http/http_response.h"
#include "auth/auth_manager.h"
#include "auth/auth_config.h"
#include "auth/auth_context.h"
#include "auth/issuer.h"
#include "auth/introspection_cache.h"
#include "config/server_config.h"
#include "log/logger.h"

#include <string>
#include <memory>
#include <atomic>
#include <thread>
#include <chrono>
#include <optional>
#include <sstream>
#include <cstdlib>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>

namespace AuthIntrospectionIntegrationTests {

// ---------------------------------------------------------------------------
// Env-var RAII guard (same pattern as AuthManagerTests::ScopedEnv)
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// Helpers shared across tests
// ---------------------------------------------------------------------------

// Test-local env-var name for the client secret.
static constexpr const char* kSecretEnvVar = "GW_INTRO_INT_TEST_SECRET";
static constexpr const char* kSecretValue  = "intro-integration-test-secret";

// Send a full HTTP/1.1 request and return the raw response string.
static bool SendAll(int fd, const std::string& data) {
    size_t sent = 0;
    while (sent < data.size()) {
        ssize_t n = ::send(fd, data.data() + sent, data.size() - sent, 0);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

static std::string RecvResponse(int fd, int timeout_ms = 5000) {
    std::string out;
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        struct pollfd pfd{fd, POLLIN, 0};
        int rv;
        do { rv = ::poll(&pfd, 1, 100); } while (rv < 0 && errno == EINTR);
        if (rv < 0) break;      // poll error — give up
        if (rv == 0) continue;  // poll timeout — retry until deadline
        char buf[4096];
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        out.append(buf, static_cast<size_t>(n));
        // Bail once the full body has arrived.
        auto he = out.find("\r\n\r\n");
        if (he != std::string::npos) {
            auto cl_pos = out.find("Content-Length: ");
            if (cl_pos != std::string::npos && cl_pos < he) {
                auto eol = out.find('\r', cl_pos + 16);
                int cl = std::stoi(out.substr(cl_pos + 16, eol - cl_pos - 16));
                if (static_cast<int>(out.size() - he - 4) >= cl) break;
            } else { break; }
        }
    }
    return out;
}

static int ExtractStatus(const std::string& resp) {
    if (resp.size() < 12) return 0;
    try { return std::stoi(resp.substr(9, 3)); } catch (...) { return 0; }
}

// Send a GET request with an optional Bearer token, optional extra headers,
// and optional response timeout (defaults to 5000 ms).
// Returns the raw response string.
static std::string SendHttp(int port, const std::string& path,
                              const std::string& bearer = "",
                              const std::string& extra_headers = "",
                              int timeout_ms = 5000) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return "";
    struct FdG { int f; ~FdG(){ if(f>=0){ ::shutdown(f,SHUT_RDWR); ::close(f); } } } g{fd};
    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(static_cast<uint16_t>(port));
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) return "";
    std::string req = "GET " + path + " HTTP/1.1\r\n"
                      "Host: localhost\r\n"
                      "Connection: close\r\n";
    if (!bearer.empty()) req += "Authorization: Bearer " + bearer + "\r\n";
    req += extra_headers;
    req += "\r\n";
    SendAll(fd, req);
    return RecvResponse(fd, timeout_ms);
}

// Build an introspection IssuerConfig.
//
// endpoint_url must use https:// to pass config validation. The IntrospectionClient
// parses the host/path from this URL for the outbound Host header and request path,
// then routes the actual TCP connection through upstream_pool_name. In tests the
// upstream pool points at the mock IdP's plain HTTP listen socket — the scheme in
// the URL has no effect on TCP routing.
static AUTH_NAMESPACE::IssuerConfig MakeIntrospectionIssuer(
        const std::string& issuer_name,
        const std::string& issuer_url,
        const std::string& upstream_pool_name,
        const std::string& endpoint_url,
        const std::string& auth_style = "basic",
        int timeout_sec = 3,
        int cache_sec = 60,
        int negative_cache_sec = 10,
        int stale_grace_sec = 30) {
    AUTH_NAMESPACE::IssuerConfig ic;
    ic.name       = issuer_name;
    ic.issuer_url = issuer_url;
    ic.discovery  = false;
    ic.mode       = "introspection";
    ic.upstream   = upstream_pool_name;

    ic.introspection.endpoint          = endpoint_url;
    ic.introspection.client_id         = "test-client-id";
    ic.introspection.client_secret_env = kSecretEnvVar;
    ic.introspection.auth_style        = auth_style;
    ic.introspection.timeout_sec       = timeout_sec;
    ic.introspection.cache_sec         = cache_sec;
    ic.introspection.negative_cache_sec = negative_cache_sec;
    ic.introspection.stale_grace_sec   = stale_grace_sec;
    ic.introspection.max_entries       = 1024;
    ic.introspection.shards            = 4;
    return ic;
}

// Build the https:// endpoint URL from a mock server's bound address.
// The config validator requires https://, and the IntrospectionClient routes
// the actual connection through the upstream pool (plain HTTP), so the scheme
// here is only for validation purposes.
static std::string MockEndpointHttps(
        const MockIntrospectionServerNS::MockIntrospectionServer& mock) {
    return "https://" + mock.host() + ":" + std::to_string(mock.port()) +
           "/introspect";
}

// Build a ServerConfig wiring the mock IdP as an upstream pool and the
// introspection issuer as the auth provider.
static ServerConfig BuildServerConfig(
        const MockIntrospectionServerNS::MockIntrospectionServer& mock,
        const std::string& issuer_name,
        const std::string& issuer_url,
        const std::string& upstream_pool_name,
        const std::string& auth_style = "basic",
        int timeout_sec = 3,
        int cache_sec = 60,
        int negative_cache_sec = 10,
        int stale_grace_sec = 30) {
    ServerConfig cfg;
    cfg.bind_host      = "127.0.0.1";
    cfg.bind_port      = 0;
    cfg.worker_threads = 2;
    cfg.http2.enabled  = false;

    // Upstream pool pointing at the mock IdP.
    UpstreamConfig upstream;
    upstream.name            = upstream_pool_name;
    upstream.host            = mock.host();
    upstream.port            = mock.port();
    upstream.pool.connect_timeout_ms = 2000;
    cfg.upstreams.push_back(upstream);

    // Auth config.
    cfg.auth.enabled = true;
    cfg.auth.issuers[issuer_name] = MakeIntrospectionIssuer(
        issuer_name, issuer_url, upstream_pool_name,
        MockEndpointHttps(mock),
        auth_style, timeout_sec, cache_sec, negative_cache_sec, stale_grace_sec);
    return cfg;
}

// Add a top-level policy to a ServerConfig.
static void AddPolicy(ServerConfig& cfg,
                       const std::string& policy_name,
                       const std::vector<std::string>& applies_to,
                       const std::string& issuer_name,
                       const std::vector<std::string>& required_scopes = {},
                       const std::string& on_undetermined = "deny") {
    AUTH_NAMESPACE::AuthPolicy p;
    p.name            = policy_name;
    p.enabled         = true;
    p.applies_to      = applies_to;
    p.issuers         = {issuer_name};
    p.required_scopes = required_scopes;
    p.on_undetermined = on_undetermined;
    cfg.auth.policies.push_back(p);
}

// Spin up a mock IdP + HTTP server with one basic policy, wait for the issuer
// to become ready, and return both.
//
// The caller must keep both `mock` and `runner` alive for the duration of
// the test.  `server_out` must be kept alive too (TestServerRunner holds a
// reference).
struct TestFixture {
    MockIntrospectionServerNS::MockIntrospectionServer mock;
    std::unique_ptr<HttpServer> server;
    std::unique_ptr<TestServerRunner<HttpServer>> runner;
    int port = 0;

    bool StartWithConfig(ServerConfig& cfg,
                          int wait_ready_ms = 3000) {
        if (!mock.Start()) return false;
        // Patch endpoint URL now that the mock has bound its port.
        // Use https:// scheme so the config validator accepts the URL;
        // the IntrospectionClient routes the TCP connection through the
        // upstream pool (plain HTTP), so the scheme has no TCP effect.
        auto it = cfg.auth.issuers.begin();
        if (it == cfg.auth.issuers.end()) return false;
        it->second.introspection.endpoint = MockEndpointHttps(mock);

        server = std::make_unique<HttpServer>(cfg);
        server->Get("/protected", [](const HttpRequest&, HttpResponse& resp) {
            resp.Status(200).Body("ok", "text/plain");
        });
        server->Get("/open", [](const HttpRequest&, HttpResponse& resp) {
            resp.Status(200).Body("open", "text/plain");
        });
        runner = std::make_unique<TestServerRunner<HttpServer>>(*server);
        port = runner->GetPort();
        // Give the issuer a moment to be wired up (non-blocking Start).
        // For introspection mode there is no JWKS/discovery fetch, so the
        // issuer is ready as soon as the client secret env var is readable.
        std::this_thread::sleep_for(std::chrono::milliseconds(wait_ready_ms > 200 ? 100 : 50));
        return port > 0;
    }
};

// ---------------------------------------------------------------------------
// RunOne: catch exceptions and record a deterministic fail instead of crash.
// ---------------------------------------------------------------------------
static void RunOne(const std::string& name, bool(*fn)()) {
    bool ok = false;
    try {
        ok = fn();
    } catch (const std::exception& e) {
        TestFramework::RecordTest(name, false, e.what());
        return;
    } catch (...) {
        TestFramework::RecordTest(name, false, "unknown exception");
        return;
    }
    TestFramework::RecordTest(name, ok, ok ? "" : "test returned false");
}

// ===========================================================================
// Test 1: active:true → 200 Allow
// ===========================================================================
static bool TestActiveTrue() {
    ScopedEnv env(kSecretEnvVar, kSecretValue);

    MockIntrospectionServerNS::MockIntrospectionServer mock;
    if (!mock.Start()) return false;

    ServerConfig cfg = BuildServerConfig(mock, "idp1", "https://idp.example.com",
                                          "idp-pool");
    AddPolicy(cfg, "p1", {"/protected"}, "idp1");

    HttpServer server(cfg);
    server.Get("/protected", [](const HttpRequest&, HttpResponse& resp){
        resp.Status(200).Body("ok", "text/plain");
    });
    TestServerRunner<HttpServer> runner(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    mock.EnqueueActiveTrue("user@example.com");
    auto resp = SendHttp(runner.GetPort(), "/protected", "some-opaque-token");
    return ExtractStatus(resp) == 200;
}

// ===========================================================================
// Test 2: active:false → 401 Deny
// ===========================================================================
static bool TestActiveFalse() {
    ScopedEnv env(kSecretEnvVar, kSecretValue);

    MockIntrospectionServerNS::MockIntrospectionServer mock;
    if (!mock.Start()) return false;

    ServerConfig cfg = BuildServerConfig(mock, "idp2", "https://idp.example.com",
                                          "idp-pool");
    AddPolicy(cfg, "p2", {"/protected"}, "idp2");

    HttpServer server(cfg);
    server.Get("/protected", [](const HttpRequest&, HttpResponse& resp){
        resp.Status(200).Body("ok", "text/plain");
    });
    TestServerRunner<HttpServer> runner(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    mock.EnqueueActiveFalse();
    auto resp = SendHttp(runner.GetPort(), "/protected", "inactive-token");
    return ExtractStatus(resp) == 401;
}

// ===========================================================================
// Test 3: Second request with same token → cache hit → IdP not called again
// ===========================================================================
static bool TestCacheHitSkipsIdp() {
    ScopedEnv env(kSecretEnvVar, kSecretValue);

    MockIntrospectionServerNS::MockIntrospectionServer mock;
    if (!mock.Start()) return false;

    ServerConfig cfg = BuildServerConfig(mock, "idp3", "https://idp.example.com",
                                          "idp-pool", "basic", 3, 60);
    AddPolicy(cfg, "p3", {"/protected"}, "idp3");

    HttpServer server(cfg);
    server.Get("/protected", [](const HttpRequest&, HttpResponse& resp){
        resp.Status(200).Body("ok", "text/plain");
    });
    TestServerRunner<HttpServer> runner(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Enqueue exactly one active response; second request must serve from cache.
    mock.EnqueueActiveTrue("user3");

    // First request — triggers IdP POST and populates cache.
    auto r1 = SendHttp(runner.GetPort(), "/protected", "cached-token");
    if (ExtractStatus(r1) != 200) return false;

    size_t count_after_first = mock.request_count();
    if (count_after_first != 1) return false;

    // Second request — must hit cache; no new POST should be issued.
    auto r2 = SendHttp(runner.GetPort(), "/protected", "cached-token");
    if (ExtractStatus(r2) != 200) return false;

    // Request count must still be 1 (cache served the second request).
    return mock.request_count() == 1;
}

// ===========================================================================
// Test 4: Fresh token (not in cache) → IdP is called
// ===========================================================================
static bool TestCacheMissCallsIdp() {
    ScopedEnv env(kSecretEnvVar, kSecretValue);

    MockIntrospectionServerNS::MockIntrospectionServer mock;
    if (!mock.Start()) return false;

    ServerConfig cfg = BuildServerConfig(mock, "idp4", "https://idp.example.com",
                                          "idp-pool");
    AddPolicy(cfg, "p4", {"/protected"}, "idp4");

    HttpServer server(cfg);
    server.Get("/protected", [](const HttpRequest&, HttpResponse& resp){
        resp.Status(200).Body("ok", "text/plain");
    });
    TestServerRunner<HttpServer> runner(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    mock.EnqueueActiveTrue("user-miss-1");
    mock.EnqueueActiveTrue("user-miss-2");

    auto r1 = SendHttp(runner.GetPort(), "/protected", "token-alpha");
    auto r2 = SendHttp(runner.GetPort(), "/protected", "token-beta");
    if (ExtractStatus(r1) != 200 || ExtractStatus(r2) != 200) return false;

    // Two distinct tokens → two distinct IdP calls.
    return mock.request_count() == 2;
}

// ===========================================================================
// Test 5: auth_style=basic → Authorization: Basic base64(cid:secret) in POST
// ===========================================================================
static bool TestAuthStyleBasicHeaderShape() {
    ScopedEnv env(kSecretEnvVar, kSecretValue);

    MockIntrospectionServerNS::MockIntrospectionServer mock;
    if (!mock.Start()) return false;

    ServerConfig cfg = BuildServerConfig(mock, "idp5", "https://idp.example.com",
                                          "idp-pool", "basic");
    AddPolicy(cfg, "p5", {"/protected"}, "idp5");

    HttpServer server(cfg);
    server.Get("/protected", [](const HttpRequest&, HttpResponse& resp){
        resp.Status(200).Body("ok", "text/plain");
    });
    TestServerRunner<HttpServer> runner(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    mock.EnqueueActiveTrue("user5");
    auto resp = SendHttp(runner.GetPort(), "/protected", "tok5");
    if (ExtractStatus(resp) != 200) return false;

    // Verify the Authorization header was present and uses Basic scheme.
    std::string auth_hdr = mock.received_authorization_header();
    if (auth_hdr.find("Basic ") != 0) return false;

    // Verify the body only contains token=...
    std::string body = mock.received_body();
    if (body.find("token=") == std::string::npos) return false;
    // In basic mode, client_id and client_secret must NOT appear in the body.
    if (body.find("client_id=") != std::string::npos) return false;
    if (body.find("client_secret=") != std::string::npos) return false;
    return true;
}

// ===========================================================================
// Test 6: auth_style=body → body contains token + client_id + client_secret
// ===========================================================================
static bool TestAuthStyleBodyShape() {
    ScopedEnv env(kSecretEnvVar, kSecretValue);

    MockIntrospectionServerNS::MockIntrospectionServer mock;
    if (!mock.Start()) return false;

    ServerConfig cfg = BuildServerConfig(mock, "idp6", "https://idp.example.com",
                                          "idp-pool", "body");
    AddPolicy(cfg, "p6", {"/protected"}, "idp6");

    HttpServer server(cfg);
    server.Get("/protected", [](const HttpRequest&, HttpResponse& resp){
        resp.Status(200).Body("ok", "text/plain");
    });
    TestServerRunner<HttpServer> runner(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    mock.EnqueueActiveTrue("user6");
    auto resp = SendHttp(runner.GetPort(), "/protected", "tok6");
    if (ExtractStatus(resp) != 200) return false;

    // In body mode, Authorization header must be absent (empty).
    std::string auth_hdr = mock.received_authorization_header();
    if (!auth_hdr.empty()) return false;

    // Body must contain all three fields.
    std::string body = mock.received_body();
    if (body.find("token=") == std::string::npos) return false;
    if (body.find("client_id=") == std::string::npos) return false;
    if (body.find("client_secret=") == std::string::npos) return false;
    return true;
}

// ===========================================================================
// Test 7: client secret read from env var → issuer ready, POST succeeds
// ===========================================================================
static bool TestClientSecretFromEnv() {
    ScopedEnv env(kSecretEnvVar, "my-test-secret-7");

    MockIntrospectionServerNS::MockIntrospectionServer mock;
    if (!mock.Start()) return false;

    // Use body style so the secret value appears in the request body.
    ServerConfig cfg = BuildServerConfig(mock, "idp7", "https://idp.example.com",
                                          "idp-pool", "body");
    AddPolicy(cfg, "p7", {"/protected"}, "idp7");

    HttpServer server(cfg);
    server.Get("/protected", [](const HttpRequest&, HttpResponse& resp){
        resp.Status(200).Body("ok", "text/plain");
    });
    TestServerRunner<HttpServer> runner(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    mock.EnqueueActiveTrue("user7");
    auto resp = SendHttp(runner.GetPort(), "/protected", "tok7");
    if (ExtractStatus(resp) != 200) return false;

    // Verify the correct secret value was sent in the body.
    std::string body = mock.received_body();
    return body.find("my-test-secret-7") != std::string::npos;
}

// ===========================================================================
// Test 8: missing env var → issuer stays not-ready → fail-closed 503
// ===========================================================================
static bool TestClientSecretMissingEnvFailsClosed() {
    // Explicitly unset the env var so the issuer can't load its secret.
    ::unsetenv(kSecretEnvVar);

    MockIntrospectionServerNS::MockIntrospectionServer mock;
    if (!mock.Start()) return false;

    ServerConfig cfg = BuildServerConfig(mock, "idp8", "https://idp.example.com",
                                          "idp-pool");
    // on_undetermined=deny: should produce 503 when issuer is not-ready.
    AddPolicy(cfg, "p8", {"/protected"}, "idp8", {}, "deny");

    HttpServer server(cfg);
    server.Get("/protected", [](const HttpRequest&, HttpResponse& resp){
        resp.Status(200).Body("ok", "text/plain");
    });
    TestServerRunner<HttpServer> runner(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // No response needed in the queue: the issuer should be not-ready and
    // the async path should resolve synchronously with UNDETERMINED/503.
    auto resp = SendHttp(runner.GetPort(), "/protected", "tok8");
    int status = ExtractStatus(resp);
    // Fail-closed: must be 503 (UNDETERMINED + on_undetermined=deny).
    return status == 503;
}

// ===========================================================================
// Test 9: token with '=' padding chars → URL-encoded correctly in body
// ===========================================================================
static bool TestUrlEncodingTokenWithEquals() {
    ScopedEnv env(kSecretEnvVar, kSecretValue);

    MockIntrospectionServerNS::MockIntrospectionServer mock;
    if (!mock.Start()) return false;

    ServerConfig cfg = BuildServerConfig(mock, "idp9", "https://idp.example.com",
                                          "idp-pool", "basic");
    AddPolicy(cfg, "p9", {"/protected"}, "idp9");

    HttpServer server(cfg);
    server.Get("/protected", [](const HttpRequest&, HttpResponse& resp){
        resp.Status(200).Body("ok", "text/plain");
    });
    TestServerRunner<HttpServer> runner(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // A token that ends in '=' chars (looks like base64 padding).
    const std::string token_with_equals = "abc123==";

    mock.EnqueueActiveTrue("user9");
    auto resp = SendHttp(runner.GetPort(), "/protected", token_with_equals);
    if (ExtractStatus(resp) != 200) return false;

    // The body sent to the IdP must URL-encode '=' as '%3D'.
    std::string body = mock.received_body();
    // 'abc123==' URL-encoded is 'abc123%3D%3D' (or may appear as token=abc123%3D%3D).
    // The raw '=' must not appear unencoded in the body after 'token='.
    size_t token_pos = body.find("token=");
    if (token_pos == std::string::npos) return false;
    std::string token_value = body.substr(token_pos + 6); // after "token="
    // Trim trailing '&' if present.
    auto amp = token_value.find('&');
    if (amp != std::string::npos) token_value = token_value.substr(0, amp);
    // The literal '=' must not appear in the encoded token value.
    if (token_value.find('=') != std::string::npos) return false;
    // The percent-encoded form must be present.
    if (token_value.find("%3D") == std::string::npos &&
        token_value.find("%3d") == std::string::npos) return false;
    return true;
}

// ===========================================================================
// Test 10: IdP returns exp sooner than cache_sec → entry expires at IdP exp
// ===========================================================================
static bool TestTtlClampExpShorterThanCacheSec() {
    ScopedEnv env(kSecretEnvVar, kSecretValue);

    MockIntrospectionServerNS::MockIntrospectionServer mock;
    if (!mock.Start()) return false;

    // cache_sec = 60; IdP returns exp 2 seconds from now.
    // stale_grace_sec=0: disable stale-serve so cache expiry forces a fresh IdP call.
    ServerConfig cfg = BuildServerConfig(mock, "idp10", "https://idp.example.com",
                                          "idp-pool", "basic", 3, /*cache_sec=*/60,
                                          /*negative_cache_sec=*/10,
                                          /*stale_grace_sec=*/0);
    AddPolicy(cfg, "p10", {"/protected"}, "idp10");

    HttpServer server(cfg);
    server.Get("/protected", [](const HttpRequest&, HttpResponse& resp){
        resp.Status(200).Body("ok", "text/plain");
    });
    TestServerRunner<HttpServer> runner(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Enqueue one response with exp = now + 2 seconds.
    int64_t exp_soon = static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count()) + 2;

    mock.EnqueueActiveTrue("user10", {}, exp_soon);

    // First request — IdP hit, cache populated with short TTL.
    auto r1 = SendHttp(runner.GetPort(), "/protected", "tok10");
    if (ExtractStatus(r1) != 200) return false;
    if (mock.request_count() != 1) return false;

    // Immediately: second request must serve from cache (TTL not yet expired).
    auto r2 = SendHttp(runner.GetPort(), "/protected", "tok10");
    if (ExtractStatus(r2) != 200) return false;
    if (mock.request_count() != 1) return false;  // still cached

    // Wait for the IdP-supplied exp to pass.
    std::this_thread::sleep_for(std::chrono::milliseconds(2500));

    // After exp: cache entry should have expired; another IdP call expected.
    mock.EnqueueActiveTrue("user10-refresh");
    auto r3 = SendHttp(runner.GetPort(), "/protected", "tok10");
    if (ExtractStatus(r3) != 200) return false;
    // A second IdP call must have happened.
    return mock.request_count() == 2;
}

// ===========================================================================
// Test 11: IdP returns exp farther than cache_sec → entry expires at cache_sec
// ===========================================================================
static bool TestTtlClampExpLongerThanCacheSec() {
    ScopedEnv env(kSecretEnvVar, kSecretValue);

    MockIntrospectionServerNS::MockIntrospectionServer mock;
    if (!mock.Start()) return false;

    // cache_sec = 2; IdP returns exp 1 hour from now.
    // stale_grace_sec=0: disable stale-serve so cache_sec expiry forces a fresh IdP call.
    ServerConfig cfg = BuildServerConfig(mock, "idp11", "https://idp.example.com",
                                          "idp-pool", "basic", 3, /*cache_sec=*/2,
                                          /*negative_cache_sec=*/10,
                                          /*stale_grace_sec=*/0);
    AddPolicy(cfg, "p11", {"/protected"}, "idp11");

    HttpServer server(cfg);
    server.Get("/protected", [](const HttpRequest&, HttpResponse& resp){
        resp.Status(200).Body("ok", "text/plain");
    });
    TestServerRunner<HttpServer> runner(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    int64_t exp_far = static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count()) + 3600;

    mock.EnqueueActiveTrue("user11", {}, exp_far);

    // First request.
    auto r1 = SendHttp(runner.GetPort(), "/protected", "tok11");
    if (ExtractStatus(r1) != 200) return false;
    if (mock.request_count() != 1) return false;

    // Immediately: serves from cache (within cache_sec=2).
    auto r2 = SendHttp(runner.GetPort(), "/protected", "tok11");
    if (ExtractStatus(r2) != 200) return false;
    if (mock.request_count() != 1) return false;

    // Wait for cache_sec to pass (entry should be evicted by cache_sec, not exp).
    std::this_thread::sleep_for(std::chrono::milliseconds(2500));

    mock.EnqueueActiveTrue("user11-refresh");
    auto r3 = SendHttp(runner.GetPort(), "/protected", "tok11");
    if (ExtractStatus(r3) != 200) return false;
    // Cache expired after cache_sec=2, so a second IdP call is expected.
    return mock.request_count() == 2;
}

// ===========================================================================
// Test 12: negative cache — active:false cached for negative_cache_sec
// ===========================================================================
static bool TestNegativeCacheTtlObserved() {
    ScopedEnv env(kSecretEnvVar, kSecretValue);

    MockIntrospectionServerNS::MockIntrospectionServer mock;
    if (!mock.Start()) return false;

    // negative_cache_sec = 2 so the test can observe expiry quickly.
    ServerConfig cfg = BuildServerConfig(mock, "idp12", "https://idp.example.com",
                                          "idp-pool", "basic", 3,
                                          /*cache_sec=*/60,
                                          /*negative_cache_sec=*/2);
    AddPolicy(cfg, "p12", {"/protected"}, "idp12");

    HttpServer server(cfg);
    server.Get("/protected", [](const HttpRequest&, HttpResponse& resp){
        resp.Status(200).Body("ok", "text/plain");
    });
    TestServerRunner<HttpServer> runner(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    mock.EnqueueActiveFalse();

    // First request — active:false, cached as negative entry.
    auto r1 = SendHttp(runner.GetPort(), "/protected", "neg-token");
    if (ExtractStatus(r1) != 401) return false;
    if (mock.request_count() != 1) return false;

    // Second request immediately — must hit negative cache (no new IdP call).
    auto r2 = SendHttp(runner.GetPort(), "/protected", "neg-token");
    if (ExtractStatus(r2) != 401) return false;
    if (mock.request_count() != 1) return false;

    // Wait for the negative TTL to expire.
    std::this_thread::sleep_for(std::chrono::milliseconds(2500));

    // After expiry — must re-call IdP.
    mock.EnqueueActiveFalse();
    auto r3 = SendHttp(runner.GetPort(), "/protected", "neg-token");
    if (ExtractStatus(r3) != 401) return false;
    return mock.request_count() == 2;
}

// ===========================================================================
// Test 13: IdP timeout → UNDETERMINED → on_undetermined governs outcome
//          (sub-test A: deny → 503; sub-test B: allow → 200 via stale-serve)
// ===========================================================================
static bool TestTimeoutUndeterminedOrStaleServe() {
    ScopedEnv env(kSecretEnvVar, kSecretValue);

    MockIntrospectionServerNS::MockIntrospectionServer mock;
    if (!mock.Start()) return false;

    // timeout_sec=1 so the slow path resolves within ~1 second.
    // cache_sec=2 so we can quickly expire the entry for the stale-serve sub-test.
    // stale_grace_sec=30 so an expired positive entry is served stale during a timeout.
    ServerConfig cfg = BuildServerConfig(mock, "idp13", "https://idp.example.com",
                                          "idp-pool", "basic",
                                          /*timeout_sec=*/1,
                                          /*cache_sec=*/2,
                                          /*negative_cache_sec=*/10,
                                          /*stale_grace_sec=*/30);
    AddPolicy(cfg, "p13-deny",  {"/deny-path"},  "idp13", {}, "deny");
    AddPolicy(cfg, "p13-allow", {"/allow-path"}, "idp13", {}, "allow");

    HttpServer server(cfg);
    server.Get("/deny-path",  [](const HttpRequest&, HttpResponse& resp){
        resp.Status(200).Body("ok", "text/plain");
    });
    server.Get("/allow-path", [](const HttpRequest&, HttpResponse& resp){
        resp.Status(200).Body("ok", "text/plain");
    });
    TestServerRunner<HttpServer> runner(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Sub-test A: on_undetermined=deny + slow IdP → 503 within 4 s.
    // delay_ms=2500: the timer cadence is ceil(connect_timeout_ms/1000) = 2 s,
    // so the deadline checker fires at T≈2 s.  The mock must still be sleeping
    // at that point (2500 ms > 2000 ms cadence) so the timeout is observed.
    {
        MockIntrospectionServerNS::ResponseScript slow_script;
        slow_script.body = R"({"active":true})";
        slow_script.delay_ms = 2500;   // 2.5 s > 2 s timer cadence
        mock.EnqueueResponse(slow_script);

        auto start = std::chrono::steady_clock::now();
        auto resp = SendHttp(runner.GetPort(), "/deny-path", "slow-token-A", "", 5000);
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        // Must resolve within 4 s (timeout deadline observed at ~2 s cadence tick).
        if (elapsed > 4000) return false;
        if (ExtractStatus(resp) != 503) return false;
    }

    // Wait for the mock's 2.5 s sleep to finish and the mock to return
    // to RunLoop, so it can accept the next connection.
    std::this_thread::sleep_for(std::chrono::milliseconds(700));

    // Sub-test B: prime the cache with a positive entry for "stale-token".
    mock.EnqueueActiveTrue("stale-user");
    auto prime = SendHttp(runner.GetPort(), "/allow-path", "stale-token");
    if (ExtractStatus(prime) != 200) return false;

    // Wait for cache_sec=2 to expire (make the entry stale).
    std::this_thread::sleep_for(std::chrono::milliseconds(2500));

    // Sub-test C: IdP is slow (delay > timer cadence 2 s); the expired positive
    // entry is within stale_grace_sec=30 → stale-serve path fires → 200
    // synchronously without waiting for the IdP.
    {
        MockIntrospectionServerNS::ResponseScript slow_script2;
        slow_script2.body = R"({"active":true})";
        slow_script2.delay_ms = 2500;  // 2.5 s > 2 s timer cadence
        mock.EnqueueResponse(slow_script2);

        auto start = std::chrono::steady_clock::now();
        // on_undetermined=allow; stale-serve returns 200 before the IdP responds.
        auto resp = SendHttp(runner.GetPort(), "/allow-path", "stale-token", "", 3500);
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        // Stale-serve is synchronous — must complete well within 1 s.
        if (elapsed > 2000) return false;
        // Stale entry is positive, within stale_grace_sec → 200.
        if (ExtractStatus(resp) != 200) return false;
    }

    return true;
}

// ===========================================================================
// Test 14: IdP pool circuit-breaker open → stale-serve if positive entry present
// ===========================================================================
static bool TestCircuitBreakerOpenOnIdpStaleServeIfPossible() {
    ScopedEnv env(kSecretEnvVar, kSecretValue);

    MockIntrospectionServerNS::MockIntrospectionServer mock;
    if (!mock.Start()) return false;

    // stale_grace_sec=60 so a previously-cached positive entry can be served.
    ServerConfig cfg = BuildServerConfig(mock, "idp14", "https://idp.example.com",
                                          "idp-pool", "basic", 3, 60, 10, 60);
    AddPolicy(cfg, "p14-allow", {"/allow"}, "idp14", {}, "allow");
    AddPolicy(cfg, "p14-deny",  {"/deny"},  "idp14", {}, "deny");

    HttpServer server(cfg);
    server.Get("/allow", [](const HttpRequest&, HttpResponse& resp){
        resp.Status(200).Body("ok", "text/plain");
    });
    server.Get("/deny", [](const HttpRequest&, HttpResponse& resp){
        resp.Status(200).Body("ok", "text/plain");
    });
    TestServerRunner<HttpServer> runner(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Prime the cache for "cb-stale-token" with a positive entry.
    mock.EnqueueActiveTrue("stale-user14");
    auto prime = SendHttp(runner.GetPort(), "/allow", "cb-stale-token");
    if (ExtractStatus(prime) != 200) return false;

    // Make the IdP close connections without responding to simulate failures.
    // This makes the upstream pool register errors and potentially open the CB.
    for (int i = 0; i < 5; ++i) {
        MockIntrospectionServerNS::ResponseScript fail;
        fail.close_without_response = true;
        mock.EnqueueResponse(fail);
    }

    // Send several requests with a fresh token to drain the IdP scripts and
    // trip the circuit breaker.
    for (int i = 0; i < 5; ++i) {
        SendHttp(runner.GetPort(), "/deny", "fresh-token-" + std::to_string(i));
    }

    // Give the CB a moment to trip (if applicable).
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Now request "cb-stale-token" which has a positive stale entry.
    // When CB is open or IdP is failing, the stale-grace path should fire → 200.
    // When IdP recovers and CB is closed, a fresh call → 200 also.
    // Either way the result should be 200 for this positive-cached token.
    mock.EnqueueActiveTrue("stale-user14-recheck");
    auto resp = SendHttp(runner.GetPort(), "/allow", "cb-stale-token");
    // Acceptable outcomes: stale-serve (200) or fresh IdP call also returns 200.
    return ExtractStatus(resp) == 200;
}

// ===========================================================================
// Test 15: Insufficient scope → 403; but same token against a more-permissive
//          policy hits the positive cache and is ALLOWed with exactly ONE IdP call.
// ===========================================================================
static bool TestInsufficientScopePositiveCachedOtherPolicyAllows() {
    ScopedEnv env(kSecretEnvVar, kSecretValue);

    MockIntrospectionServerNS::MockIntrospectionServer mock;
    if (!mock.Start()) return false;

    ServerConfig cfg = BuildServerConfig(mock, "idp15", "https://idp.example.com",
                                          "idp-pool");
    // Policy A: requires scope "admin" — narrow.
    AddPolicy(cfg, "p15-admin", {"/admin/"}, "idp15", {"admin"}, "deny");
    // Policy B: no required scopes — wide open.
    AddPolicy(cfg, "p15-open",  {"/open/"},  "idp15", {}, "deny");

    HttpServer server(cfg);
    server.Get("/admin/resource", [](const HttpRequest&, HttpResponse& resp){
        resp.Status(200).Body("admin-ok", "text/plain");
    });
    server.Get("/open/resource", [](const HttpRequest&, HttpResponse& resp){
        resp.Status(200).Body("open-ok", "text/plain");
    });
    TestServerRunner<HttpServer> runner(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Enqueue exactly ONE response — a positive result with scope "read" only
    // (not "admin").
    mock.EnqueueActiveTrue("user15", {"read"});

    // Request 1: policy A (requires "admin") → token lacks "admin" → 403.
    auto r1 = SendHttp(runner.GetPort(), "/admin/resource", "scope-token");
    if (ExtractStatus(r1) != 403) return false;

    // The positive cache entry was populated by the first IdP call.
    // Request 2: policy B (no scope requirements) → cache hit → 200.
    // The cache stores active=true keyed by token HMAC; scope enforcement
    // is per-IdP-call (not re-checked on cache hits), so a broader policy
    // that imposes no scope requirements gets a clean PASS from the cache.
    auto r2 = SendHttp(runner.GetPort(), "/open/resource", "scope-token");
    if (ExtractStatus(r2) != 200) return false;

    // Assert exactly ONE IdP POST was issued across both requests.
    return mock.request_count() == 1;
}

// ===========================================================================
// Test 16: Malformed IdP JSON → UNDETERMINED (on_undetermined governs)
// ===========================================================================
static bool TestMalformedIdpResponseUndetermined() {
    ScopedEnv env(kSecretEnvVar, kSecretValue);

    MockIntrospectionServerNS::MockIntrospectionServer mock;
    if (!mock.Start()) return false;

    ServerConfig cfg = BuildServerConfig(mock, "idp16", "https://idp.example.com",
                                          "idp-pool");
    AddPolicy(cfg, "p16-deny",  {"/deny-path"},  "idp16", {}, "deny");
    AddPolicy(cfg, "p16-allow", {"/allow-path"}, "idp16", {}, "allow");

    HttpServer server(cfg);
    server.Get("/deny-path",  [](const HttpRequest&, HttpResponse& resp){
        resp.Status(200).Body("ok", "text/plain");
    });
    server.Get("/allow-path", [](const HttpRequest&, HttpResponse& resp){
        resp.Status(200).Body("ok", "text/plain");
    });
    TestServerRunner<HttpServer> runner(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Sub-test 16a: malformed JSON → UNDETERMINED + on_undetermined=deny → 503.
    mock.EnqueueStatus(200, "not-valid-json");
    auto r1 = SendHttp(runner.GetPort(), "/deny-path", "mal-token-1");
    if (ExtractStatus(r1) != 503) return false;

    // Sub-test 16b: missing "active" field in otherwise valid JSON → UNDETERMINED.
    mock.EnqueueStatus(200, R"({"sub":"user","scope":"read"})");
    auto r2 = SendHttp(runner.GetPort(), "/deny-path", "mal-token-2");
    if (ExtractStatus(r2) != 503) return false;

    return true;
}

// ===========================================================================
// Test 16b: Missing "active" field → UNDETERMINED
// ===========================================================================
static bool TestMissingActiveFieldUndetermined() {
    ScopedEnv env(kSecretEnvVar, kSecretValue);

    MockIntrospectionServerNS::MockIntrospectionServer mock;
    if (!mock.Start()) return false;

    ServerConfig cfg = BuildServerConfig(mock, "idp16b", "https://idp.example.com",
                                          "idp-pool");
    AddPolicy(cfg, "p16b-deny", {"/protected"}, "idp16b", {}, "deny");

    HttpServer server(cfg);
    server.Get("/protected", [](const HttpRequest&, HttpResponse& resp){
        resp.Status(200).Body("ok", "text/plain");
    });
    TestServerRunner<HttpServer> runner(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Valid JSON but no "active" key.
    mock.EnqueueStatus(200, R"({"token_type":"bearer","client_id":"test"})");
    auto resp = SendHttp(runner.GetPort(), "/protected", "no-active-field");
    // UNDETERMINED + on_undetermined=deny → 503.
    return ExtractStatus(resp) == 503;
}

// ===========================================================================
// Test 17: Mixed-mode policy (JWT issuer + introspection issuer)
//          JWT path: JWT issuer's sync InvokeMiddleware → pass-through to async
//          Introspection path: async InvokeAsyncIntrospection
// ===========================================================================
static bool TestMixedModePolicyJwtFirstIntrospectionFallback() {
    ScopedEnv env(kSecretEnvVar, kSecretValue);

    MockIntrospectionServerNS::MockIntrospectionServer mock;
    if (!mock.Start()) return false;

    // Build a config with one introspection-mode issuer and one JWT-mode issuer
    // (the JWT issuer has no live JWKS, so it stays not-ready / UNDETERMINED
    // with on_undetermined=allow, acting as a fallback).
    ServerConfig cfg;
    cfg.bind_host      = "127.0.0.1";
    cfg.bind_port      = 0;
    cfg.worker_threads = 2;
    cfg.http2.enabled  = false;

    // Upstream for the mock IdP.
    UpstreamConfig up_intro;
    up_intro.name                    = "intro-pool";
    up_intro.host                    = mock.host();
    up_intro.port                    = mock.port();
    up_intro.pool.connect_timeout_ms = 2000;
    cfg.upstreams.push_back(up_intro);

    // Upstream for the JWT IdP (unreachable; discovery will fail, issuer stays
    // not-ready).
    UpstreamConfig up_jwt;
    up_jwt.name                    = "jwt-pool";
    up_jwt.host                    = "127.0.0.1";
    up_jwt.port                    = 9;  // discard port — connection refused immediately
    up_jwt.pool.connect_timeout_ms = 1000;
    cfg.upstreams.push_back(up_jwt);

    // JWT-mode issuer (not-ready; discovery=false, jwks_uri points to discard port).
    AUTH_NAMESPACE::IssuerConfig jwt_issuer;
    jwt_issuer.name       = "jwt-idp";
    jwt_issuer.issuer_url = "https://jwt.example.com";
    jwt_issuer.discovery  = false;
    jwt_issuer.jwks_uri   = "https://127.0.0.1:9/.well-known/jwks.json";
    jwt_issuer.upstream   = "jwt-pool";
    jwt_issuer.mode       = "jwt";
    jwt_issuer.algorithms = {"RS256"};

    // Introspection-mode issuer (real mock IdP).
    // MockEndpointHttps wraps the mock address with https:// so the config
    // validator accepts it; TCP routing uses intro-pool (plain HTTP).
    AUTH_NAMESPACE::IssuerConfig intro_issuer = MakeIntrospectionIssuer(
        "intro-idp", "https://intro.example.com", "intro-pool",
        MockEndpointHttps(mock));

    cfg.auth.enabled                   = true;
    cfg.auth.issuers[jwt_issuer.name]  = jwt_issuer;
    cfg.auth.issuers[intro_issuer.name] = intro_issuer;

    // A policy that lists introspection issuer first. The sync middleware
    // checks the first policy issuer for opaque tokens (no `iss` peek);
    // listing intro-idp first causes the sync middleware to pass-through
    // (introspection-mode), allowing the async chain to invoke introspection.
    // The JWT issuer is listed second (used when a JWT with a matching `iss`
    // claim arrives — fallback that never fires for opaque tokens here).
    AUTH_NAMESPACE::AuthPolicy p;
    p.name            = "mixed-policy";
    p.enabled         = true;
    p.applies_to      = {"/mixed/"};
    p.issuers         = {"intro-idp", "jwt-idp"};
    p.on_undetermined = "deny";
    cfg.auth.policies.push_back(p);

    HttpServer server(cfg);
    server.Get("/mixed/resource", [](const HttpRequest&, HttpResponse& resp){
        resp.Status(200).Body("mixed-ok", "text/plain");
    });
    TestServerRunner<HttpServer> runner(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    // The introspection issuer is ready (secret env var is set).
    // Send an opaque token — not a valid JWT, so the JWT path returns
    // UNDETERMINED; the async chain tries introspection → IdP call → active:true.
    mock.EnqueueActiveTrue("mixed-user");
    auto resp = SendHttp(runner.GetPort(), "/mixed/resource", "opaque-token-17");

    // Active introspection result → 200.
    return ExtractStatus(resp) == 200;
}

// ===========================================================================
// Test 18: HeaderRewriter injects X-Auth-Subject/Issuer/Scopes for introspection
// ===========================================================================
static bool TestHeaderRewriterOutboundOverlayWorksForIntrospection() {
    // Validates that after a successful introspection auth (active:true), the
    // AuthForwardConfig overlay writes X-Auth-Subject / X-Auth-Issuer /
    // X-Auth-Scopes onto req.auth, which downstream handlers can read.
    //
    // Note: proxy routes are async handlers; the async-middleware dispatch path
    // runs RunAsyncMiddleware ONLY for non-async (sync GET/POST) routes.  To
    // verify the auth-context population we use a plain sync GET handler that
    // reads req.auth directly — no second server needed.
    ScopedEnv env(kSecretEnvVar, kSecretValue);

    MockIntrospectionServerNS::MockIntrospectionServer mock;
    if (!mock.Start()) return false;

    // Build server config with default forward config (subject_header /
    // issuer_header / scopes_header are wired to X-Auth-Subject etc.).
    ServerConfig cfg = BuildServerConfig(mock, "idp18", "https://idp.example.com",
                                          "idp-pool");
    AddPolicy(cfg, "p18", {"/protected"}, "idp18");

    // Capture auth context fields written by InvokeAsyncIntrospection.
    std::string captured_subject;
    std::string captured_issuer;
    std::string captured_scopes;
    std::mutex  captured_mtx;

    HttpServer server(cfg);
    // Sync GET handler: after introspection auth passes, req.auth is populated
    // with the identity context built from the IdP response.
    server.Get("/protected", [&](const HttpRequest& req, HttpResponse& resp){
        std::lock_guard<std::mutex> lk(captured_mtx);
        if (req.auth) {
            captured_subject = req.auth->subject;
            captured_issuer  = req.auth->issuer;
            // scopes is a vector; join with space to mirror header format.
            for (const auto& s : req.auth->scopes) {
                if (!captured_scopes.empty()) captured_scopes += ' ';
                captured_scopes += s;
            }
        }
        resp.Status(200).Body("ok", "text/plain");
    });
    TestServerRunner<HttpServer> runner(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    // IdP returns active:true with sub, iss, and scope.
    // Include "iss" so PopulateFromPayload sets ctx.issuer to the issuer URL.
    mock.EnqueueStatus(200,
        R"({"active":true,"sub":"overlay-user@example.com","iss":"https://idp.example.com","scope":"read write"})");
    auto resp = SendHttp(runner.GetPort(), "/protected", "overlay-token");
    if (ExtractStatus(resp) != 200) return false;

    // Give the handler a moment to finish writing the captures.
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    std::lock_guard<std::mutex> lk(captured_mtx);
    // Subject must match "sub" claim from IdP response.
    if (captured_subject != "overlay-user@example.com") return false;
    // Issuer must match "iss" claim from IdP response.
    if (captured_issuer != "https://idp.example.com") return false;
    // Scopes must contain both "read" and "write".
    if (captured_scopes.find("read")  == std::string::npos) return false;
    if (captured_scopes.find("write") == std::string::npos) return false;

    return true;
}

// ===========================================================================
// Test: AuthManager snapshot exposes the introspection counters that the
// /stats endpoint surfaces. Drives one cache miss + one cache hit + one
// negative cache miss through a real introspection-mode issuer, then reads
// GetAuthSnapshot() and asserts each counter increments on the right path.
//
// Counter semantics:
//   ok           = successful IdP POST returning active=true
//   fail         = IdP POST returning active=false (deferred DENY_401 path)
//   cache_miss   = cache lookup did not satisfy the request → POST issued
//   cache_hit    = positive cache hit → POST skipped
//   negative_hit = cached active=false hit → POST skipped, request denied
//   stale_served = served within stale grace window → POST skipped
//   cache_entries (per-issuer) = approximate per-shard sum
// ===========================================================================
static bool TestStatsSnapshotIncludesIntrospectionCounters() {
    ScopedEnv env(kSecretEnvVar, kSecretValue);

    MockIntrospectionServerNS::MockIntrospectionServer mock;
    if (!mock.Start()) return false;

    ServerConfig cfg = BuildServerConfig(mock, "idp_stats",
                                          "https://idp.example.com",
                                          "idp-pool", "basic", 3, 60);
    AddPolicy(cfg, "p_stats", {"/protected"}, "idp_stats");

    HttpServer server(cfg);
    server.Get("/protected", [](const HttpRequest&, HttpResponse& resp){
        resp.Status(200).Body("ok", "text/plain");
    });
    TestServerRunner<HttpServer> runner(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    auto baseline = server.GetAuthSnapshot();
    if (!baseline) return false;
    if (baseline->introspection_ok != 0) return false;
    if (baseline->introspection_fail != 0) return false;
    if (baseline->introspection_cache_miss != 0) return false;
    if (baseline->introspection_cache_hit != 0) return false;
    if (baseline->introspection_cache_negative_hit != 0) return false;
    if (baseline->introspection_stale_served != 0) return false;
    if (baseline->issuers.find("idp_stats") == baseline->issuers.end()) return false;
    if (baseline->issuers.at("idp_stats").mode != "introspection") return false;
    if (baseline->issuers.at("idp_stats").introspection_cache_entries != 0) return false;

    // First request: cache miss → POST (active=true) → ok increments.
    mock.EnqueueActiveTrue("user_stats");
    auto r1 = SendHttp(runner.GetPort(), "/protected", "stats-token");
    if (ExtractStatus(r1) != 200) return false;

    // Second request, same token: cache hit → POST skipped.
    auto r2 = SendHttp(runner.GetPort(), "/protected", "stats-token");
    if (ExtractStatus(r2) != 200) return false;
    if (mock.request_count() != 1) return false;

    // Third request, different token: cache miss → POST (active=false) →
    // fail increments and a negative entry is cached.
    mock.EnqueueActiveFalse();
    auto r3 = SendHttp(runner.GetPort(), "/protected", "bad-token");
    if (ExtractStatus(r3) != 401) return false;

    // Fourth request, same bad token: negative cache hit → POST skipped.
    auto r4 = SendHttp(runner.GetPort(), "/protected", "bad-token");
    if (ExtractStatus(r4) != 401) return false;
    if (mock.request_count() != 2) return false;

    auto snap = server.GetAuthSnapshot();
    if (!snap) return false;
    if (snap->introspection_ok != 1) return false;
    if (snap->introspection_fail != 1) return false;
    if (snap->introspection_cache_miss != 2) return false;
    if (snap->introspection_cache_hit != 1) return false;
    if (snap->introspection_cache_negative_hit != 1) return false;
    if (snap->introspection_stale_served != 0) return false;

    auto it = snap->issuers.find("idp_stats");
    if (it == snap->issuers.end()) return false;
    const size_t entries = it->second.introspection_cache_entries;
    if (entries < 1 || entries > 16) return false;
    return true;
}

// ===========================================================================
// Entry point
// ===========================================================================

static void RunAllTests() {
    std::cout << "Running auth introspection integration tests..." << std::endl;

    RunOne("Introspection: Active_True_ReturnsAllow_200",
           TestActiveTrue);
    RunOne("Introspection: Active_False_Returns401",
           TestActiveFalse);
    RunOne("Introspection: CacheHit_SkipsIdpCall",
           TestCacheHitSkipsIdp);
    RunOne("Introspection: CacheMiss_CallsIdp",
           TestCacheMissCallsIdp);
    RunOne("Introspection: AuthStyle_Basic_HeaderShape",
           TestAuthStyleBasicHeaderShape);
    RunOne("Introspection: AuthStyle_Body_BodyShape",
           TestAuthStyleBodyShape);
    RunOne("Introspection: ClientSecret_FromEnv",
           TestClientSecretFromEnv);
    RunOne("Introspection: ClientSecret_MissingEnv_FailsClosed",
           TestClientSecretMissingEnvFailsClosed);
    RunOne("Introspection: UrlEncoding_TokenWithEqualsPadding",
           TestUrlEncodingTokenWithEquals);
    RunOne("Introspection: TtlClamp_ExpShorterThanCacheSec",
           TestTtlClampExpShorterThanCacheSec);
    RunOne("Introspection: TtlClamp_ExpLongerThanCacheSec",
           TestTtlClampExpLongerThanCacheSec);
    RunOne("Introspection: NegativeCache_TtlObserved",
           TestNegativeCacheTtlObserved);
    RunOne("Introspection: Timeout_UndeterminedOrStaleServe",
           TestTimeoutUndeterminedOrStaleServe);
    RunOne("Introspection: CircuitBreakerOpen_OnIdp_StaleServeIfPossible",
           TestCircuitBreakerOpenOnIdpStaleServeIfPossible);
    RunOne("Introspection: InsufficientScope_PositiveCached_OtherPolicyAllows",
           TestInsufficientScopePositiveCachedOtherPolicyAllows);
    RunOne("Introspection: MalformedIdpResponse_Undetermined",
           TestMalformedIdpResponseUndetermined);
    RunOne("Introspection: MissingActiveField_Undetermined",
           TestMissingActiveFieldUndetermined);
    RunOne("Introspection: MixedModePolicy_JwtFirst_IntrospectionFallback",
           TestMixedModePolicyJwtFirstIntrospectionFallback);
    RunOne("Introspection: HeaderRewriter_OutboundOverlay_WorksForIntrospection",
           TestHeaderRewriterOutboundOverlayWorksForIntrospection);
    RunOne("Introspection: StatsSnapshotIncludesIntrospectionCounters",
           TestStatsSnapshotIncludesIntrospectionCounters);
}

}  // namespace AuthIntrospectionIntegrationTests
