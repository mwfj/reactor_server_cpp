#pragma once

// ============================================================================
// Auth WebSocket upgrade tests — Phase 2 test suite.
//
// WebSocket upgrade requests pass through the HTTP middleware chain before
// the 101 Switching Protocols response is sent. These tests verify that
// the AuthManager middleware correctly enforces token validation on WS
// upgrade requests, that invalid/missing tokens produce 401/403 on the
// upgrade response (not a 101), and that a valid token produces 101.
//
// Architecture note: auth enforcement happens in InvokeMiddleware before
// the WS upgrade route handler runs. If InvokeMiddleware returns false
// (deny), the response is already set and the route handler is not called.
// The tests exercise this by sending raw HTTP upgrade requests over TCP
// and checking the response status line.
//
// Tests covered:
//   1.  WS upgrade request without Authorization → 401
//   2.  WS upgrade with invalid JWT → 401
//   3.  WS upgrade with valid JWT on unprotected route → 101
//   4.  WS upgrade with valid JWT on protected route → 101
//   5.  WS upgrade with missing required scope → 403
//   6.  WS upgrade with expired token → 401
// ============================================================================

#include "test_framework.h"
#include "test_server_runner.h"
#include "http_test_client.h"
#include "http/http_server.h"
#include "http/http_request.h"
#include "http/http_response.h"
#include "auth/auth_manager.h"
#include "auth/auth_config.h"
#include "auth/auth_context.h"
#include "auth/auth_result.h"
#include "auth/jwks_cache.h"
#include "auth/issuer.h"
#include "ws/websocket_connection.h"
#include "config/server_config.h"
#include "log/logger.h"

#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/nlohmann-json/traits.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>

#include <string>
#include <memory>
#include <atomic>
#include <thread>
#include <chrono>
#include <sstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>

namespace AuthWebSocketUpgradeTests {

// ---------------------------------------------------------------------------
// Key / JWT helpers
// ---------------------------------------------------------------------------

struct RsaKeyPair {
    std::string public_pem;
    std::string private_pem;
};

static RsaKeyPair GenRsa() {
    RsaKeyPair kp;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) return kp;
    struct CG { EVP_PKEY_CTX* p; ~CG(){ if(p) EVP_PKEY_CTX_free(p); } } cg{ctx};
    if (EVP_PKEY_keygen_init(ctx) <= 0) return kp;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) return kp;
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) return kp;
    struct KG { EVP_PKEY* k; ~KG(){ if(k) EVP_PKEY_free(k); } } kg{pkey};

    BIO* bio = BIO_new(BIO_s_mem());
    if (PEM_write_bio_PUBKEY(bio, pkey)) {
        char* d = nullptr; long l = BIO_get_mem_data(bio, &d);
        kp.public_pem.assign(d, static_cast<size_t>(l));
    }
    BIO_free(bio);
    bio = BIO_new(BIO_s_mem());
    if (PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
        char* d = nullptr; long l = BIO_get_mem_data(bio, &d);
        kp.private_pem.assign(d, static_cast<size_t>(l));
    }
    BIO_free(bio);
    return kp;
}

static std::string BuildJwt(
        const std::string& private_pem,
        const std::string& kid,
        const std::string& iss,
        const std::string& sub = "user1",
        const std::vector<std::string>& scopes = {},
        int exp_offset_sec = 3600) {
    if (private_pem.empty()) return "";
    auto now = std::chrono::system_clock::now();
    auto builder = jwt::create<jwt::traits::nlohmann_json>()
        .set_issuer(iss)
        .set_subject(sub)
        .set_issued_at(now)
        .set_expires_at(now + std::chrono::seconds(exp_offset_sec))
        .set_key_id(kid);
    if (!scopes.empty()) {
        std::string sc;
        for (const auto& s : scopes) { if (!sc.empty()) sc += ' '; sc += s; }
        builder = builder.set_payload_claim("scope",
            jwt::basic_claim<jwt::traits::nlohmann_json>(sc));
    }
    try {
        auto alg = jwt::algorithm::rs256("", private_pem, "", "");
        return builder.sign(alg);
    } catch (...) { return ""; }
}

// ---------------------------------------------------------------------------
// Network helpers for sending raw WS upgrade requests
// ---------------------------------------------------------------------------

static int ConnectTcp(int port) {
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

static bool SendAll(int fd, const std::string& data) {
    size_t sent = 0;
    while (sent < data.size()) {
        ssize_t n = ::send(fd, data.data() + sent, data.size() - sent, 0);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

// Receive the response status line (up to first \r\n).
static std::string RecvStatusLine(int fd, int timeout_ms = 3000) {
    std::string buf;
    buf.reserve(64);
    auto deadline = std::chrono::steady_clock::now()
                  + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        pollfd pfd{fd, POLLIN, 0};
        int rc = ::poll(&pfd, 1, 50);
        if (rc <= 0) continue;
        char c;
        ssize_t n = ::recv(fd, &c, 1, 0);
        if (n <= 0) break;
        buf += c;
        if (buf.size() >= 2 &&
            buf[buf.size()-2] == '\r' && buf[buf.size()-1] == '\n') {
            break;
        }
    }
    return buf;
}

// Build an HTTP/1.1 WebSocket upgrade request string.
static std::string MakeUpgradeRequest(
        const std::string& path,
        const std::string& auth_header = "") {
    std::ostringstream oss;
    oss << "GET " << path << " HTTP/1.1\r\n"
        << "Host: localhost\r\n"
        << "Upgrade: websocket\r\n"
        << "Connection: Upgrade\r\n"
        << "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        << "Sec-WebSocket-Version: 13\r\n";
    if (!auth_header.empty()) {
        oss << "Authorization: " << auth_header << "\r\n";
    }
    oss << "\r\n";
    return oss.str();
}

// Extract the HTTP status code from a status line like "HTTP/1.1 401 ..."
static int ParseStatus(const std::string& status_line) {
    if (status_line.size() < 12) return 0;
    try { return std::stoi(status_line.substr(9, 3)); }
    catch (...) { return 0; }
}

// ---------------------------------------------------------------------------
// Server setup helpers
// ---------------------------------------------------------------------------

static AUTH_NAMESPACE::IssuerConfig MakeIssuerCfg(
        const std::string& name,
        const std::string& url,
        int leeway_sec = 0) {
    AUTH_NAMESPACE::IssuerConfig ic;
    ic.name        = name;
    ic.issuer_url  = url;
    ic.discovery   = false;
    ic.jwks_uri    = "https://" + name + ".example.com/jwks.json";
    ic.upstream    = "";
    ic.mode        = "jwt";
    ic.algorithms  = {"RS256"};
    ic.leeway_sec  = leeway_sec;
    ic.jwks_cache_sec = 300;
    return ic;
}

// Attach an AuthManager with the given policy to `server` via Use().
// Returns the AuthManager so the caller can install keys.
static std::shared_ptr<AUTH_NAMESPACE::AuthManager> AttachAuth(
        HttpServer& server,
        const std::string& iss_name,
        const std::string& iss_url,
        const std::string& protected_prefix,
        const std::vector<std::string>& required_scopes = {},
        const std::string& on_undetermined = "deny") {
    AUTH_NAMESPACE::AuthConfig cfg;
    cfg.enabled = true;
    cfg.issuers[iss_name] = MakeIssuerCfg(iss_name, iss_url);

    auto mgr = std::make_shared<AUTH_NAMESPACE::AuthManager>(
        cfg, nullptr, std::vector<std::shared_ptr<Dispatcher>>{});

    AUTH_NAMESPACE::AuthPolicy p;
    p.name            = "ws-policy";
    p.enabled         = true;
    p.applies_to      = {protected_prefix};
    p.issuers         = {iss_name};
    p.required_scopes = required_scopes;
    p.on_undetermined = on_undetermined;
    mgr->RegisterPolicy(p.applies_to, p);
    mgr->Start();

    std::weak_ptr<AUTH_NAMESPACE::AuthManager> weak_mgr = mgr;
    server.Use([weak_mgr](const HttpRequest& req, HttpResponse& resp) -> bool {
        auto m = weak_mgr.lock();
        if (!m) return true;  // manager gone — pass through
        return m->InvokeMiddleware(req, resp);
    });
    return mgr;
}

// ---------------------------------------------------------------------------
// Test 1: WS upgrade request without Authorization → 401
// Rationale: The auth middleware runs before the WS route handler; a missing
// Authorization header should produce 401, not 101 Switching Protocols.
// ---------------------------------------------------------------------------
static bool TestWsUpgradeNoAuthToken() {
    auto kp = GenRsa();
    if (kp.private_pem.empty()) return true;

    const std::string iss_name = "ws-issuer-1";
    const std::string iss_url  = "https://ws-idp-1.example.com";

    ServerConfig cfg;
    cfg.bind_host = "127.0.0.1";
    cfg.bind_port = 0;
    cfg.worker_threads = 1;
    cfg.http2.enabled = false;
    HttpServer server(cfg);

    auto mgr = AttachAuth(server, iss_name, iss_url, "/ws/");
    mgr->GetIssuer(iss_name)->jwks_cache()->InstallKeys({{"kid1", kp.public_pem}});

    // Register a WS route so the middleware has somewhere to route to
    server.WebSocket("/ws/chat",
        [](WebSocketConnection&) { /* auth should block before this */ });

    TestServerRunner<HttpServer> runner(server);
    int port = runner.GetPort();

    int fd = ConnectTcp(port);
    if (fd < 0) return false;
    struct FdG { int f; ~FdG(){ if(f>=0) ::close(f); } } fdg{fd};

    SendAll(fd, MakeUpgradeRequest("/ws/chat"));
    std::string status_line = RecvStatusLine(fd);
    int status = ParseStatus(status_line);

    return status == 401;
}

// ---------------------------------------------------------------------------
// Test 2: WS upgrade with invalid JWT signature → 401
// Rationale: A syntactically-valid JWT with a wrong signature must be
// rejected before the WS handshake completes.
// ---------------------------------------------------------------------------
static bool TestWsUpgradeInvalidJwt() {
    auto kp  = GenRsa();
    auto kp2 = GenRsa();  // wrong key
    if (kp.private_pem.empty() || kp2.private_pem.empty()) return true;

    const std::string iss_name = "ws-issuer-2";
    const std::string iss_url  = "https://ws-idp-2.example.com";

    ServerConfig cfg;
    cfg.bind_host = "127.0.0.1";
    cfg.bind_port = 0;
    cfg.worker_threads = 1;
    cfg.http2.enabled = false;
    HttpServer server(cfg);

    auto mgr = AttachAuth(server, iss_name, iss_url, "/ws/");
    // Install kp's PUBLIC key but sign with kp2's PRIVATE key → signature mismatch
    mgr->GetIssuer(iss_name)->jwks_cache()->InstallKeys({{"kid2", kp.public_pem}});

    server.WebSocket("/ws/chat",
        [](WebSocketConnection&) {});

    TestServerRunner<HttpServer> runner(server);
    int port = runner.GetPort();

    std::string token = BuildJwt(kp2.private_pem, "kid2", iss_url, "attacker");
    if (token.empty()) return false;

    int fd = ConnectTcp(port);
    if (fd < 0) return false;
    struct FdG { int f; ~FdG(){ if(f>=0) ::close(f); } } fdg{fd};

    SendAll(fd, MakeUpgradeRequest("/ws/chat", "Bearer " + token));
    std::string status_line = RecvStatusLine(fd);
    int status = ParseStatus(status_line);

    return status == 401;
}

// ---------------------------------------------------------------------------
// Test 3: WS upgrade on unprotected route → 101 (auth middleware passes)
// Rationale: The "/pub/chat" prefix is NOT protected by any auth policy;
// the upgrade should succeed without any Authorization header.
// ---------------------------------------------------------------------------
static bool TestWsUpgradeUnprotectedRoute() {
    const std::string iss_name = "ws-issuer-3";
    const std::string iss_url  = "https://ws-idp-3.example.com";

    ServerConfig cfg;
    cfg.bind_host = "127.0.0.1";
    cfg.bind_port = 0;
    cfg.worker_threads = 1;
    cfg.http2.enabled = false;
    HttpServer server(cfg);

    // Auth only on /ws/secured/ — not on /pub/
    AttachAuth(server, iss_name, iss_url, "/ws/secured/");

    // Register an unprotected WS route
    server.WebSocket("/pub/chat",
        [](WebSocketConnection&) { /* unprotected */ });

    TestServerRunner<HttpServer> runner(server);
    int port = runner.GetPort();

    int fd = ConnectTcp(port);
    if (fd < 0) return false;
    struct FdG { int f; ~FdG(){ if(f>=0) ::close(f); } } fdg{fd};

    // No Authorization header needed on unprotected route
    SendAll(fd, MakeUpgradeRequest("/pub/chat"));
    std::string status_line = RecvStatusLine(fd);
    int status = ParseStatus(status_line);

    return status == 101;
}

// ---------------------------------------------------------------------------
// Test 4: WS upgrade with valid JWT on protected route → 101
// Rationale: A properly-signed token with valid claims should result in a
// 101 Switching Protocols response (auth passed, WS handshake completes).
// ---------------------------------------------------------------------------
static bool TestWsUpgradeValidJwt() {
    auto kp = GenRsa();
    if (kp.private_pem.empty()) return true;

    const std::string iss_name = "ws-issuer-4";
    const std::string iss_url  = "https://ws-idp-4.example.com";

    ServerConfig cfg;
    cfg.bind_host = "127.0.0.1";
    cfg.bind_port = 0;
    cfg.worker_threads = 1;
    cfg.http2.enabled = false;
    HttpServer server(cfg);

    auto mgr = AttachAuth(server, iss_name, iss_url, "/ws/");
    mgr->GetIssuer(iss_name)->jwks_cache()->InstallKeys({{"kid4", kp.public_pem}});

    server.WebSocket("/ws/chat",
        [](WebSocketConnection&) {});

    TestServerRunner<HttpServer> runner(server);
    int port = runner.GetPort();

    std::string token = BuildJwt(kp.private_pem, "kid4", iss_url, "alice");
    if (token.empty()) return false;

    int fd = ConnectTcp(port);
    if (fd < 0) return false;
    struct FdG { int f; ~FdG(){ if(f>=0) ::close(f); } } fdg{fd};

    SendAll(fd, MakeUpgradeRequest("/ws/chat", "Bearer " + token));
    std::string status_line = RecvStatusLine(fd);
    int status = ParseStatus(status_line);

    return status == 101;
}

// ---------------------------------------------------------------------------
// Test 5: WS upgrade with missing required scope → 403
// Rationale: Token is valid but lacks the required "ws:connect" scope;
// auth middleware should return 403 before 101 is sent.
// ---------------------------------------------------------------------------
static bool TestWsUpgradeMissingScope() {
    auto kp = GenRsa();
    if (kp.private_pem.empty()) return true;

    const std::string iss_name = "ws-issuer-5";
    const std::string iss_url  = "https://ws-idp-5.example.com";

    ServerConfig cfg;
    cfg.bind_host = "127.0.0.1";
    cfg.bind_port = 0;
    cfg.worker_threads = 1;
    cfg.http2.enabled = false;
    HttpServer server(cfg);

    // Policy requires "ws:connect" scope
    auto mgr = AttachAuth(server, iss_name, iss_url, "/ws/", {"ws:connect"});
    mgr->GetIssuer(iss_name)->jwks_cache()->InstallKeys({{"kid5", kp.public_pem}});

    server.WebSocket("/ws/chat",
        [](WebSocketConnection&) {});

    TestServerRunner<HttpServer> runner(server);
    int port = runner.GetPort();

    // Token has no scopes
    std::string token = BuildJwt(kp.private_pem, "kid5", iss_url, "alice", {});
    if (token.empty()) return false;

    int fd = ConnectTcp(port);
    if (fd < 0) return false;
    struct FdG { int f; ~FdG(){ if(f>=0) ::close(f); } } fdg{fd};

    SendAll(fd, MakeUpgradeRequest("/ws/chat", "Bearer " + token));
    std::string status_line = RecvStatusLine(fd);
    int status = ParseStatus(status_line);

    return status == 403;
}

// ---------------------------------------------------------------------------
// Test 6: WS upgrade with expired token → 401
// Rationale: Even for WS upgrade, an expired token must be rejected with 401
// (same as regular HTTP request).
// ---------------------------------------------------------------------------
static bool TestWsUpgradeExpiredToken() {
    auto kp = GenRsa();
    if (kp.private_pem.empty()) return true;

    const std::string iss_name = "ws-issuer-6";
    const std::string iss_url  = "https://ws-idp-6.example.com";

    ServerConfig cfg;
    cfg.bind_host = "127.0.0.1";
    cfg.bind_port = 0;
    cfg.worker_threads = 1;
    cfg.http2.enabled = false;
    HttpServer server(cfg);

    auto mgr = AttachAuth(server, iss_name, iss_url, "/ws/");
    mgr->GetIssuer(iss_name)->jwks_cache()->InstallKeys({{"kid6", kp.public_pem}});

    server.WebSocket("/ws/chat",
        [](WebSocketConnection&) {});

    TestServerRunner<HttpServer> runner(server);
    int port = runner.GetPort();

    // Token expired 1 second ago, leeway=0
    std::string token = BuildJwt(kp.private_pem, "kid6", iss_url, "alice", {}, -1);
    if (token.empty()) return false;

    int fd = ConnectTcp(port);
    if (fd < 0) return false;
    struct FdG { int f; ~FdG(){ if(f>=0) ::close(f); } } fdg{fd};

    SendAll(fd, MakeUpgradeRequest("/ws/chat", "Bearer " + token));
    std::string status_line = RecvStatusLine(fd);
    int status = ParseStatus(status_line);

    return status == 401;
}

// ---------------------------------------------------------------------------
// Test runner
// ---------------------------------------------------------------------------

static void RunOne(const std::string& name, bool(*fn)()) {
    bool ok = false;
    try { ok = fn(); } catch (const std::exception& e) {
        TestFramework::RecordTest(name, false, e.what());
        return;
    } catch (...) {
        TestFramework::RecordTest(name, false, "unknown exception");
        return;
    }
    TestFramework::RecordTest(name, ok, ok ? "" : "test returned false");
}

static void RunAllTests() {
    RunOne("AuthWebSocketUpgrade: no Authorization -> 401 (not 101)",
           TestWsUpgradeNoAuthToken);
    RunOne("AuthWebSocketUpgrade: invalid JWT signature -> 401",
           TestWsUpgradeInvalidJwt);
    RunOne("AuthWebSocketUpgrade: unprotected route -> 101",
           TestWsUpgradeUnprotectedRoute);
    RunOne("AuthWebSocketUpgrade: valid JWT -> 101 Switching Protocols",
           TestWsUpgradeValidJwt);
    RunOne("AuthWebSocketUpgrade: missing required scope -> 403",
           TestWsUpgradeMissingScope);
    RunOne("AuthWebSocketUpgrade: expired token -> 401",
           TestWsUpgradeExpiredToken);
}

}  // namespace AuthWebSocketUpgradeTests
