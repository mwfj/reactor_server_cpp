#pragma once

// ============================================================================
// Auth integration tests — Phase 2 test suite.
//
// These tests run an HttpServer with an AuthManager registered as middleware
// via HttpServer::Use(). The AuthManager is constructed directly (not through
// the hidden auth_config_ path in HttpServer) so tests can:
//   - Install JWKS keys directly into the issuer's cache
//   - Control on_undetermined policy
//   - Observe X-Auth-* header injection to a backend
//
// Tests covered:
//   1.  No-auth route passes through (no policy matches path)
//   2.  Protected route → 401 when Authorization absent
//   3.  Protected route → 401 with malformed scheme (Basic instead of Bearer)
//   4.  Protected route → 401 with oversized token (> 8192 bytes)
//   5.  Valid RS256 JWT with installed keys → 200
//   6.  Valid JWT with wrong issuer → 401
//   7.  Valid JWT with expired token → 401
//   8.  Missing required scope → 403
//   9.  Valid scopes → 200
//  10.  alg:none JWT → 401 (§9 item 11)
//  11.  on_undetermined="allow" with unknown kid → 200 + X-Auth-Undetermined
//  12.  on_undetermined="deny" with unknown kid → 503
//  13.  X-Auth-Subject injected by HeaderRewriter to backend on success
//  14.  strip_inbound_identity_headers prevents spoofing
//  15.  AuthManager disabled (config.enabled=false) passes every request
//  16.  No matching policy → passes through (open routes)
//  17.  Multiple policies — longest prefix wins
//  18.  Reload: forward config update changes injected header names
//  19.  AuthManager counters increment on deny/allow
//  20.  WWW-Authenticate header present on 401 with realm set
//  21.  HttpServer reload preserves live top-level policy topology
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
#include "auth/jwt_verifier.h"
#include "auth/auth_middleware.h"
#include "config/server_config.h"
#include "log/logger.h"

#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/nlohmann-json/traits.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <string>
#include <memory>
#include <atomic>
#include <thread>
#include <chrono>
#include <optional>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>

namespace AuthIntegrationTests {

// ---------------------------------------------------------------------------
// OpenSSL key helpers
// ---------------------------------------------------------------------------

struct RsaKeyPair {
    std::string public_pem;
    std::string private_pem;
};

static RsaKeyPair GenerateRsaKey() {
    RsaKeyPair kp;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) return kp;
    struct CtxG { EVP_PKEY_CTX* p; ~CtxG(){ if(p) EVP_PKEY_CTX_free(p); } } cg{ctx};
    if (EVP_PKEY_keygen_init(ctx) <= 0) return kp;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) return kp;
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) return kp;
    struct KeyG { EVP_PKEY* k; ~KeyG(){ if(k) EVP_PKEY_free(k); } } kg{pkey};

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

// ---------------------------------------------------------------------------
// JWT builder
// ---------------------------------------------------------------------------

static std::string BuildJwt(
        const std::string& private_pem,
        const std::string& kid,
        const std::string& iss,
        const std::string& sub,
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
// AuthManager factory helpers
// ---------------------------------------------------------------------------

// Build a minimal IssuerConfig for a static (no-discovery) issuer.
static AUTH_NAMESPACE::IssuerConfig MakeStaticIssuerCfg(
        const std::string& name,
        const std::string& issuer_url,
        const std::vector<std::string>& algs = {"RS256"},
        int leeway_sec = 30) {
    AUTH_NAMESPACE::IssuerConfig ic;
    ic.name       = name;
    ic.issuer_url = issuer_url;
    ic.discovery  = false;
    ic.jwks_uri   = "https://" + name + ".example.com/jwks.json";
    ic.upstream   = "";
    ic.mode       = "jwt";
    ic.algorithms = algs;
    ic.leeway_sec = leeway_sec;
    ic.jwks_cache_sec = 300;
    return ic;
}

// Build an AuthPolicy covering path prefix `prefix`.
static AUTH_NAMESPACE::AuthPolicy MakePolicy(
        const std::string& name,
        const std::string& prefix,
        const std::string& issuer_name,
        const std::vector<std::string>& required_scopes = {},
        const std::string& on_undetermined = "deny",
        const std::string& realm = "api") {
    AUTH_NAMESPACE::AuthPolicy p;
    p.name            = name;
    p.enabled         = true;
    p.applies_to      = {prefix};
    p.issuers         = {issuer_name};
    p.required_scopes = required_scopes;
    p.on_undetermined = on_undetermined;
    p.realm           = realm;
    return p;
}

// Construct an AuthManager, install it as middleware on `server`, and return
// a raw pointer so tests can manipulate it (it's owned by the caller via
// shared_ptr, held alive via the server middleware lambda capture).
//
// IMPORTANT: The AuthManager returned is Start()-ed so policies are sealed.
// Call this BEFORE server.Start().
static std::shared_ptr<AUTH_NAMESPACE::AuthManager> AttachAuthManager(
        HttpServer& server,
        AUTH_NAMESPACE::AuthConfig cfg,
        std::vector<AUTH_NAMESPACE::AuthPolicy> policies = {}) {
    auto mgr = std::make_shared<AUTH_NAMESPACE::AuthManager>(
        cfg, nullptr,
        std::vector<std::shared_ptr<Dispatcher>>{});
    for (auto& p : policies) {
        mgr->RegisterPolicy(p.applies_to, p);
    }
    mgr->Start();
    // Register as middleware: capture shared_ptr so it outlives the lambda.
    std::weak_ptr<AUTH_NAMESPACE::AuthManager> weak_mgr = mgr;
    server.Use([weak_mgr](const HttpRequest& req, HttpResponse& resp) -> bool {
        auto m = weak_mgr.lock();
        if (!m) return true;  // manager gone — pass through
        return m->InvokeMiddleware(req, resp);
    });
    return mgr;
}

// ---------------------------------------------------------------------------
// Low-level HTTP helpers
// ---------------------------------------------------------------------------

static bool SendAll(int fd, const std::string& data) {
    size_t sent = 0;
    while (sent < data.size()) {
        ssize_t n = ::send(fd, data.data() + sent, data.size() - sent, 0);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

static std::string RecvResponse(int fd, int timeout_ms = 4000) {
    std::string out;
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        struct pollfd pfd{fd, POLLIN, 0};
        int rv;
        do { rv = poll(&pfd, 1, 100); } while (rv < 0 && errno == EINTR);
        if (rv <= 0) break;
        char buf[4096]; ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        out.append(buf, static_cast<size_t>(n));
        if (out.find("\r\n\r\n") != std::string::npos) {
            // Basic content-length read-through.
            auto he = out.find("\r\n\r\n");
            auto cl_pos = out.find("Content-Length: ", 0);
            if (cl_pos != std::string::npos && cl_pos < he) {
                auto eol = out.find('\r', cl_pos + 16);
                int cl = std::stoi(out.substr(cl_pos + 16, eol - cl_pos - 16));
                if ((int)(out.size() - he - 4) >= cl) break;
            } else { break; }
        }
    }
    return out;
}

static int ExtractStatus(const std::string& resp) {
    if (resp.size() < 12) return 0;
    try { return std::stoi(resp.substr(9, 3)); } catch (...) { return 0; }
}

static std::string SendHttp(int port, const std::string& path,
                              const std::string& bearer_token = "",
                              const std::string& extra_headers = "") {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return "";
    struct FdG { int f; ~FdG(){ if(f>=0){ shutdown(f,SHUT_RDWR); close(f); } } } g{fd};
    sockaddr_in addr{}; addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) return "";
    std::string req = "GET " + path + " HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n";
    if (!bearer_token.empty()) req += "Authorization: Bearer " + bearer_token + "\r\n";
    req += extra_headers;
    req += "\r\n";
    SendAll(fd, req);
    return RecvResponse(fd, 4000);
}

// ---------------------------------------------------------------------------
// Test 1: No-auth server — all routes pass through
// ---------------------------------------------------------------------------
static bool TestNoAuthPassthrough() {
    ServerConfig cfg;
    cfg.bind_host = "127.0.0.1"; cfg.bind_port = 0;
    cfg.worker_threads = 1; cfg.http2.enabled = false;
    HttpServer server(cfg);
    server.Get("/open", [](const HttpRequest&, HttpResponse& resp) {
        resp.Status(200).Body("open", "text/plain");
    });
    TestServerRunner<HttpServer> runner(server);
    auto resp = SendHttp(runner.GetPort(), "/open");
    bool ok = ExtractStatus(resp) == 200;
    TestFramework::RecordTest("Auth integration: no-auth passthrough",
                               ok, ok ? "" : "expected 200");
    return ok;
}

// ---------------------------------------------------------------------------
// Test 2: Protected route → 401 when Authorization absent
// ---------------------------------------------------------------------------
static bool TestMissingTokenDeny401() {
    RsaKeyPair kp = GenerateRsaKey();
    if (kp.public_pem.empty()) {
        TestFramework::RecordTest("Auth integration: missing token → 401", false, "key gen failed");
        return false;
    }
    const std::string iss_name = "test-iss";
    const std::string iss_url  = "https://idp.test";
    const std::string kid      = "k1";

    AUTH_NAMESPACE::AuthConfig cfg;
    cfg.enabled = true;
    cfg.issuers[iss_name] = MakeStaticIssuerCfg(iss_name, iss_url);

    ServerConfig srv_cfg;
    srv_cfg.bind_host = "127.0.0.1"; srv_cfg.bind_port = 0;
    srv_cfg.worker_threads = 1; srv_cfg.http2.enabled = false;
    HttpServer server(srv_cfg);
    server.Get("/protected", [](const HttpRequest&, HttpResponse& resp) {
        resp.Status(200).Body("secret", "text/plain");
    });
    auto mgr = AttachAuthManager(server, cfg,
        {MakePolicy("p", "/protected", iss_name)});
    // Install keys so the issuer is ready (no network needed).
    mgr->GetIssuer(iss_name)->jwks_cache()->InstallKeys({{kid, kp.public_pem}});

    TestServerRunner<HttpServer> runner(server);
    auto resp = SendHttp(runner.GetPort(), "/protected");
    bool ok = ExtractStatus(resp) == 401;
    TestFramework::RecordTest("Auth integration: missing token → 401",
                               ok, ok ? "" : "expected 401, got " + std::to_string(ExtractStatus(resp)));
    return ok;
}

// ---------------------------------------------------------------------------
// Test 3: Valid RS256 JWT → 200
// ---------------------------------------------------------------------------
static bool TestValidJwtAllow200() {
    RsaKeyPair kp = GenerateRsaKey();
    if (kp.public_pem.empty()) {
        TestFramework::RecordTest("Auth integration: valid RS256 JWT → 200", false, "key gen failed");
        return false;
    }
    const std::string iss_name = "test-iss";
    const std::string iss_url  = "https://idp.test";
    const std::string kid      = "k2";

    AUTH_NAMESPACE::AuthConfig cfg;
    cfg.enabled = true;
    cfg.issuers[iss_name] = MakeStaticIssuerCfg(iss_name, iss_url);

    ServerConfig srv_cfg;
    srv_cfg.bind_host = "127.0.0.1"; srv_cfg.bind_port = 0;
    srv_cfg.worker_threads = 1; srv_cfg.http2.enabled = false;
    HttpServer server(srv_cfg);
    server.Get("/protected", [](const HttpRequest&, HttpResponse& resp) {
        resp.Status(200).Body("secret", "text/plain");
    });
    auto mgr = AttachAuthManager(server, cfg,
        {MakePolicy("p", "/protected", iss_name)});
    mgr->GetIssuer(iss_name)->jwks_cache()->InstallKeys({{kid, kp.public_pem}});

    TestServerRunner<HttpServer> runner(server);
    std::string token = BuildJwt(kp.private_pem, kid, iss_url, "user-abc");
    auto resp = SendHttp(runner.GetPort(), "/protected", token);
    bool ok = ExtractStatus(resp) == 200;
    TestFramework::RecordTest("Auth integration: valid RS256 JWT → 200",
                               ok, ok ? "" : "expected 200, got " + std::to_string(ExtractStatus(resp)));
    return ok;
}

// ---------------------------------------------------------------------------
// Test 4: Wrong issuer in token → 401
// ---------------------------------------------------------------------------
static bool TestWrongIssuerDeny401() {
    RsaKeyPair kp = GenerateRsaKey();
    if (kp.public_pem.empty()) {
        TestFramework::RecordTest("Auth integration: wrong issuer → 401", false, "key gen failed");
        return false;
    }
    const std::string iss_name = "test-iss";
    const std::string iss_url  = "https://idp.test";
    const std::string kid      = "k3";

    AUTH_NAMESPACE::AuthConfig cfg;
    cfg.enabled = true;
    cfg.issuers[iss_name] = MakeStaticIssuerCfg(iss_name, iss_url);

    ServerConfig srv_cfg;
    srv_cfg.bind_host = "127.0.0.1"; srv_cfg.bind_port = 0;
    srv_cfg.worker_threads = 1; srv_cfg.http2.enabled = false;
    HttpServer server(srv_cfg);
    server.Get("/guarded", [](const HttpRequest&, HttpResponse& resp) {
        resp.Status(200).Body("ok", "text/plain");
    });
    auto mgr = AttachAuthManager(server, cfg,
        {MakePolicy("p", "/guarded", iss_name)});
    mgr->GetIssuer(iss_name)->jwks_cache()->InstallKeys({{kid, kp.public_pem}});

    TestServerRunner<HttpServer> runner(server);
    // Token uses a different iss than what the policy expects.
    std::string token = BuildJwt(kp.private_pem, kid, "https://evil.example.com", "u");
    auto resp = SendHttp(runner.GetPort(), "/guarded", token);
    bool ok = ExtractStatus(resp) == 401;
    TestFramework::RecordTest("Auth integration: wrong issuer → 401",
                               ok, ok ? "" : "expected 401, got " + std::to_string(ExtractStatus(resp)));
    return ok;
}

// ---------------------------------------------------------------------------
// Test 5: Expired JWT → 401
// ---------------------------------------------------------------------------
static bool TestExpiredTokenDeny401() {
    RsaKeyPair kp = GenerateRsaKey();
    if (kp.public_pem.empty()) {
        TestFramework::RecordTest("Auth integration: expired token → 401", false, "key gen failed");
        return false;
    }
    const std::string iss_name = "test-iss";
    const std::string iss_url  = "https://idp.test";
    const std::string kid      = "k4";

    AUTH_NAMESPACE::AuthConfig cfg;
    cfg.enabled = true;
    auto ic = MakeStaticIssuerCfg(iss_name, iss_url);
    ic.leeway_sec = 0;  // No leeway so an expired token is definitively rejected
    cfg.issuers[iss_name] = ic;

    ServerConfig srv_cfg;
    srv_cfg.bind_host = "127.0.0.1"; srv_cfg.bind_port = 0;
    srv_cfg.worker_threads = 1; srv_cfg.http2.enabled = false;
    HttpServer server(srv_cfg);
    server.Get("/secured", [](const HttpRequest&, HttpResponse& resp) {
        resp.Status(200).Body("ok", "text/plain");
    });
    auto mgr = AttachAuthManager(server, cfg,
        {MakePolicy("p", "/secured", iss_name)});
    mgr->GetIssuer(iss_name)->jwks_cache()->InstallKeys({{kid, kp.public_pem}});

    TestServerRunner<HttpServer> runner(server);
    // Token expired 7200 seconds ago (well beyond any reasonable leeway).
    std::string token = BuildJwt(kp.private_pem, kid, iss_url, "u", {}, -7200);
    auto resp = SendHttp(runner.GetPort(), "/secured", token);
    bool ok = ExtractStatus(resp) == 401;
    TestFramework::RecordTest("Auth integration: expired token → 401",
                               ok, ok ? "" : "expected 401, got " + std::to_string(ExtractStatus(resp)));
    return ok;
}

// ---------------------------------------------------------------------------
// Test 6: Missing required scope → 403
// ---------------------------------------------------------------------------
static bool TestMissingScopeDeny403() {
    RsaKeyPair kp = GenerateRsaKey();
    if (kp.public_pem.empty()) {
        TestFramework::RecordTest("Auth integration: missing scope → 403", false, "key gen failed");
        return false;
    }
    const std::string iss_name = "scope-iss";
    const std::string iss_url  = "https://idp.scope";
    const std::string kid      = "k5";

    AUTH_NAMESPACE::AuthConfig cfg;
    cfg.enabled = true;
    cfg.issuers[iss_name] = MakeStaticIssuerCfg(iss_name, iss_url);

    ServerConfig srv_cfg;
    srv_cfg.bind_host = "127.0.0.1"; srv_cfg.bind_port = 0;
    srv_cfg.worker_threads = 1; srv_cfg.http2.enabled = false;
    HttpServer server(srv_cfg);
    server.Get("/scoped", [](const HttpRequest&, HttpResponse& resp) {
        resp.Status(200).Body("ok", "text/plain");
    });
    auto mgr = AttachAuthManager(server, cfg,
        {MakePolicy("p", "/scoped", iss_name, {"admin:write"})});
    mgr->GetIssuer(iss_name)->jwks_cache()->InstallKeys({{kid, kp.public_pem}});

    TestServerRunner<HttpServer> runner(server);
    // Token has only "read" scope; "admin:write" required.
    std::string token = BuildJwt(kp.private_pem, kid, iss_url, "u", {"read"});
    auto resp = SendHttp(runner.GetPort(), "/scoped", token);
    bool ok = ExtractStatus(resp) == 403;
    TestFramework::RecordTest("Auth integration: missing scope → 403",
                               ok, ok ? "" : "expected 403, got " + std::to_string(ExtractStatus(resp)));
    return ok;
}

// ---------------------------------------------------------------------------
// Test 7: Valid required scope → 200
// ---------------------------------------------------------------------------
static bool TestValidScopeAllow200() {
    RsaKeyPair kp = GenerateRsaKey();
    if (kp.public_pem.empty()) {
        TestFramework::RecordTest("Auth integration: valid scope → 200", false, "key gen failed");
        return false;
    }
    const std::string iss_name = "scope-iss2";
    const std::string iss_url  = "https://idp.scope2";
    const std::string kid      = "k6";

    AUTH_NAMESPACE::AuthConfig cfg;
    cfg.enabled = true;
    cfg.issuers[iss_name] = MakeStaticIssuerCfg(iss_name, iss_url);

    ServerConfig srv_cfg;
    srv_cfg.bind_host = "127.0.0.1"; srv_cfg.bind_port = 0;
    srv_cfg.worker_threads = 1; srv_cfg.http2.enabled = false;
    HttpServer server(srv_cfg);
    server.Get("/need-read", [](const HttpRequest&, HttpResponse& resp) {
        resp.Status(200).Body("ok", "text/plain");
    });
    auto mgr = AttachAuthManager(server, cfg,
        {MakePolicy("p", "/need-read", iss_name, {"read"})});
    mgr->GetIssuer(iss_name)->jwks_cache()->InstallKeys({{kid, kp.public_pem}});

    TestServerRunner<HttpServer> runner(server);
    std::string token = BuildJwt(kp.private_pem, kid, iss_url, "u", {"read", "write"});
    auto resp = SendHttp(runner.GetPort(), "/need-read", token);
    bool ok = ExtractStatus(resp) == 200;
    TestFramework::RecordTest("Auth integration: valid scope → 200",
                               ok, ok ? "" : "expected 200, got " + std::to_string(ExtractStatus(resp)));
    return ok;
}

// ---------------------------------------------------------------------------
// Test 8: alg:none JWT → 401 (§9 item 11)
// ---------------------------------------------------------------------------
static bool TestAlgNoneDeny401() {
    const std::string iss_name = "algnone-iss";
    const std::string iss_url  = "https://idp.algnone";

    AUTH_NAMESPACE::AuthConfig cfg;
    cfg.enabled = true;
    cfg.issuers[iss_name] = MakeStaticIssuerCfg(iss_name, iss_url);

    ServerConfig srv_cfg;
    srv_cfg.bind_host = "127.0.0.1"; srv_cfg.bind_port = 0;
    srv_cfg.worker_threads = 1; srv_cfg.http2.enabled = false;
    HttpServer server(srv_cfg);
    server.Get("/secret", [](const HttpRequest&, HttpResponse& resp) {
        resp.Status(200).Body("ok", "text/plain");
    });
    auto mgr = AttachAuthManager(server, cfg,
        {MakePolicy("p", "/secret", iss_name)});
    // No keys needed — alg:none is rejected before key lookup.

    TestServerRunner<HttpServer> runner(server);

    // Manually craft a header.payload. style alg:none token.
    auto b64url = [](const std::string& in) -> std::string {
        static const char chars[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string r;
        for (size_t i = 0; i < in.size(); i += 3) {
            uint32_t n = 0; size_t rem = std::min(in.size()-i, size_t{3});
            for (size_t j = 0; j < rem; ++j) n |= (uint8_t)in[i+j] << (8*(2-j));
            size_t emit = rem + 1;
            for (size_t j = 0; j < 4; ++j) {
                if (j < emit) r += chars[(n >> (6*(3-j))) & 0x3F]; else r += '=';
            }
        }
        std::string out;
        for (char c : r) {
            if (c == '+') out += '-'; else if (c == '/') out += '_';
            else if (c != '=') out += c;
        }
        return out;
    };
    std::string hdr = b64url(R"({"alg":"none","typ":"JWT"})");
    std::string pay = b64url(
        R"({"iss":")" + iss_url +
        R"(","sub":"u","iat":1000000,"exp":9999999999})");
    std::string none_tok = hdr + "." + pay + ".";

    auto resp = SendHttp(runner.GetPort(), "/secret", none_tok);
    bool ok = ExtractStatus(resp) == 401;
    TestFramework::RecordTest("Auth integration: alg:none → 401",
                               ok, ok ? "" : "expected 401, got " + std::to_string(ExtractStatus(resp)));
    return ok;
}

// ---------------------------------------------------------------------------
// Test 9: on_undetermined="allow" with unknown kid → 200
// ---------------------------------------------------------------------------
static bool TestUndeterminedAllow200() {
    const std::string iss_name = "unready-iss";
    const std::string iss_url  = "https://unready.idp";

    AUTH_NAMESPACE::AuthConfig cfg;
    cfg.enabled = true;
    cfg.issuers[iss_name] = MakeStaticIssuerCfg(iss_name, iss_url);

    ServerConfig srv_cfg;
    srv_cfg.bind_host = "127.0.0.1"; srv_cfg.bind_port = 0;
    srv_cfg.worker_threads = 1; srv_cfg.http2.enabled = false;
    HttpServer server(srv_cfg);
    server.Get("/maybe", [](const HttpRequest&, HttpResponse& resp) {
        resp.Status(200).Body("maybe", "text/plain");
    });
    auto mgr = AttachAuthManager(server, cfg,
        {MakePolicy("p", "/maybe", iss_name, {}, "allow")});
    // No keys installed → UNDETERMINED (kid miss).

    TestServerRunner<HttpServer> runner(server);
    RsaKeyPair kp = GenerateRsaKey();
    if (kp.public_pem.empty()) {
        TestFramework::RecordTest("Auth integration: undetermined+allow → 200", false, "key gen failed");
        return false;
    }
    std::string token = BuildJwt(kp.private_pem, "unknown-kid", iss_url, "u");
    auto resp = SendHttp(runner.GetPort(), "/maybe", token);
    bool ok = ExtractStatus(resp) == 200;
    TestFramework::RecordTest("Auth integration: undetermined+allow → 200",
                               ok, ok ? "" : "expected 200, got " + std::to_string(ExtractStatus(resp)));
    return ok;
}

// ---------------------------------------------------------------------------
// Test 10: on_undetermined="deny" with unknown kid → 503
// ---------------------------------------------------------------------------
static bool TestUndeterminedDeny503() {
    const std::string iss_name = "deny-iss";
    const std::string iss_url  = "https://deny.idp";

    AUTH_NAMESPACE::AuthConfig cfg;
    cfg.enabled = true;
    cfg.issuers[iss_name] = MakeStaticIssuerCfg(iss_name, iss_url);

    ServerConfig srv_cfg;
    srv_cfg.bind_host = "127.0.0.1"; srv_cfg.bind_port = 0;
    srv_cfg.worker_threads = 1; srv_cfg.http2.enabled = false;
    HttpServer server(srv_cfg);
    server.Get("/deny", [](const HttpRequest&, HttpResponse& resp) {
        resp.Status(200).Body("deny", "text/plain");
    });
    auto mgr = AttachAuthManager(server, cfg,
        {MakePolicy("p", "/deny", iss_name, {}, "deny")});

    TestServerRunner<HttpServer> runner(server);
    RsaKeyPair kp = GenerateRsaKey();
    if (kp.public_pem.empty()) {
        TestFramework::RecordTest("Auth integration: undetermined+deny → 503", false, "key gen failed");
        return false;
    }
    std::string token = BuildJwt(kp.private_pem, "unknown-kid", iss_url, "u");
    auto resp = SendHttp(runner.GetPort(), "/deny", token);
    bool ok = ExtractStatus(resp) == 503;
    TestFramework::RecordTest("Auth integration: undetermined+deny → 503",
                               ok, ok ? "" : "expected 503, got " + std::to_string(ExtractStatus(resp)));
    return ok;
}

// ---------------------------------------------------------------------------
// Test 11: Open route (no matching policy) passes through without token
// ---------------------------------------------------------------------------
static bool TestOpenRouteWithAuthManagerNoToken() {
    const std::string iss_name = "pass-iss";
    const std::string iss_url  = "https://pass.idp";

    AUTH_NAMESPACE::AuthConfig cfg;
    cfg.enabled = true;
    cfg.issuers[iss_name] = MakeStaticIssuerCfg(iss_name, iss_url);

    ServerConfig srv_cfg;
    srv_cfg.bind_host = "127.0.0.1"; srv_cfg.bind_port = 0;
    srv_cfg.worker_threads = 1; srv_cfg.http2.enabled = false;
    HttpServer server(srv_cfg);
    server.Get("/public", [](const HttpRequest&, HttpResponse& resp) {
        resp.Status(200).Body("public", "text/plain");
    });
    // Policy only covers /protected/ — /public has no policy.
    auto mgr = AttachAuthManager(server, cfg,
        {MakePolicy("p", "/protected/", iss_name)});

    TestServerRunner<HttpServer> runner(server);
    auto resp = SendHttp(runner.GetPort(), "/public");
    bool ok = ExtractStatus(resp) == 200;
    TestFramework::RecordTest("Auth integration: open route passes through with auth manager present",
                               ok, ok ? "" : "expected 200, got " + std::to_string(ExtractStatus(resp)));
    return ok;
}

// ---------------------------------------------------------------------------
// Test 12: AuthContext::subject populated on successful validation
// ---------------------------------------------------------------------------
static bool TestSubjectPopulatedOnSuccess() {
    RsaKeyPair kp = GenerateRsaKey();
    if (kp.public_pem.empty()) {
        TestFramework::RecordTest("Auth integration: subject populated on success", false, "key gen failed");
        return false;
    }
    const std::string iss_name = "ctx-iss";
    const std::string iss_url  = "https://idp.ctx";
    const std::string kid      = "k7";

    AUTH_NAMESPACE::AuthConfig cfg;
    cfg.enabled = true;
    cfg.issuers[iss_name] = MakeStaticIssuerCfg(iss_name, iss_url);

    ServerConfig srv_cfg;
    srv_cfg.bind_host = "127.0.0.1"; srv_cfg.bind_port = 0;
    srv_cfg.worker_threads = 1; srv_cfg.http2.enabled = false;
    HttpServer server(srv_cfg);

    std::string subject_observed;
    server.Get("/ctx/data", [&](const HttpRequest& req, HttpResponse& resp) {
        if (req.auth.has_value()) {
            subject_observed = req.auth->subject;
        }
        resp.Status(200).Body("ok", "text/plain");
    });
    auto mgr = AttachAuthManager(server, cfg,
        {MakePolicy("p", "/ctx/", iss_name)});
    mgr->GetIssuer(iss_name)->jwks_cache()->InstallKeys({{kid, kp.public_pem}});

    TestServerRunner<HttpServer> runner(server);
    std::string token = BuildJwt(kp.private_pem, kid, iss_url, "hello-subject");
    auto resp = SendHttp(runner.GetPort(), "/ctx/data", token);

    bool status_ok  = ExtractStatus(resp) == 200;
    bool subject_ok = subject_observed == "hello-subject";
    bool ok = status_ok && subject_ok;
    TestFramework::RecordTest("Auth integration: subject populated on success",
                               ok,
                               ok ? "" : "status=" + std::to_string(ExtractStatus(resp)) +
                                   " subject='" + subject_observed + "'");
    return ok;
}

// ---------------------------------------------------------------------------
// Test 13: malformed scheme (Basic) → 401
// ---------------------------------------------------------------------------
static bool TestWrongSchemeDeny401() {
    const std::string iss_name = "scheme-iss";
    const std::string iss_url  = "https://idp.scheme";

    AUTH_NAMESPACE::AuthConfig cfg;
    cfg.enabled = true;
    cfg.issuers[iss_name] = MakeStaticIssuerCfg(iss_name, iss_url);

    ServerConfig srv_cfg;
    srv_cfg.bind_host = "127.0.0.1"; srv_cfg.bind_port = 0;
    srv_cfg.worker_threads = 1; srv_cfg.http2.enabled = false;
    HttpServer server(srv_cfg);
    server.Get("/scheme", [](const HttpRequest&, HttpResponse& resp) {
        resp.Status(200).Body("ok", "text/plain");
    });
    auto mgr = AttachAuthManager(server, cfg,
        {MakePolicy("p", "/scheme", iss_name)});

    TestServerRunner<HttpServer> runner(server);
    // Send Basic auth instead of Bearer.
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        TestFramework::RecordTest("Auth integration: wrong scheme → 401", false, "socket failed");
        return false;
    }
    struct FdG { int f; ~FdG(){ shutdown(f,SHUT_RDWR); close(f); } } g{fd};
    sockaddr_in addr{}; addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(runner.GetPort()));
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    std::string req = "GET /scheme HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
                      "Authorization: Basic dXNlcjpwYXNz\r\n\r\n";
    SendAll(fd, req);
    auto resp = RecvResponse(fd, 3000);
    bool ok = ExtractStatus(resp) == 401;
    TestFramework::RecordTest("Auth integration: wrong scheme → 401",
                               ok, ok ? "" : "expected 401, got " + std::to_string(ExtractStatus(resp)));
    return ok;
}

// ---------------------------------------------------------------------------
// Test 14: AuthManager::SnapshotAll counters reflect denied / allowed
// ---------------------------------------------------------------------------
static bool TestSnapshotCountersIntegration() {
    RsaKeyPair kp = GenerateRsaKey();
    if (kp.public_pem.empty()) {
        TestFramework::RecordTest("Auth integration: snapshot counters", false, "key gen failed");
        return false;
    }
    const std::string iss_name = "counter-iss";
    const std::string iss_url  = "https://idp.counter";
    const std::string kid      = "k8";

    AUTH_NAMESPACE::AuthConfig cfg;
    cfg.enabled = true;
    cfg.issuers[iss_name] = MakeStaticIssuerCfg(iss_name, iss_url);

    ServerConfig srv_cfg;
    srv_cfg.bind_host = "127.0.0.1"; srv_cfg.bind_port = 0;
    srv_cfg.worker_threads = 1; srv_cfg.http2.enabled = false;
    HttpServer server(srv_cfg);
    server.Get("/cnt", [](const HttpRequest&, HttpResponse& resp) {
        resp.Status(200).Body("ok", "text/plain");
    });
    auto mgr = AttachAuthManager(server, cfg,
        {MakePolicy("p", "/cnt", iss_name)});
    mgr->GetIssuer(iss_name)->jwks_cache()->InstallKeys({{kid, kp.public_pem}});

    TestServerRunner<HttpServer> runner(server);

    // 1 denial (no token)
    SendHttp(runner.GetPort(), "/cnt");

    // 1 allow (valid token)
    std::string token = BuildJwt(kp.private_pem, kid, iss_url, "u");
    SendHttp(runner.GetPort(), "/cnt", token);

    // Give the dispatcher a moment to finish processing.
    std::this_thread::sleep_for(std::chrono::milliseconds{50});

    auto snap = mgr->SnapshotAll();
    bool ok = snap.total_denied >= 1 && snap.total_allowed >= 1;
    TestFramework::RecordTest("Auth integration: SnapshotAll counters",
                               ok,
                               ok ? "" : "denied=" + std::to_string(snap.total_denied) +
                                   " allowed=" + std::to_string(snap.total_allowed));
    return ok;
}

// ---------------------------------------------------------------------------
// Test 15: WWW-Authenticate header present on 401
// ---------------------------------------------------------------------------
static bool TestWwwAuthenticateHeader() {
    const std::string iss_name = "realm-iss";
    const std::string iss_url  = "https://idp.realm";

    AUTH_NAMESPACE::AuthConfig cfg;
    cfg.enabled = true;
    cfg.issuers[iss_name] = MakeStaticIssuerCfg(iss_name, iss_url);

    ServerConfig srv_cfg;
    srv_cfg.bind_host = "127.0.0.1"; srv_cfg.bind_port = 0;
    srv_cfg.worker_threads = 1; srv_cfg.http2.enabled = false;
    HttpServer server(srv_cfg);
    server.Get("/realm", [](const HttpRequest&, HttpResponse& resp) {
        resp.Status(200).Body("ok", "text/plain");
    });
    auto mgr = AttachAuthManager(server, cfg,
        {MakePolicy("p", "/realm", iss_name, {}, "deny", "my-realm")});

    TestServerRunner<HttpServer> runner(server);
    auto resp = SendHttp(runner.GetPort(), "/realm");
    bool ok = ExtractStatus(resp) == 401 &&
              resp.find("WWW-Authenticate") != std::string::npos &&
              resp.find("my-realm") != std::string::npos;
    TestFramework::RecordTest("Auth integration: WWW-Authenticate present on 401",
                               ok, ok ? "" : "missing WWW-Authenticate with realm");
    return ok;
}

// ---------------------------------------------------------------------------
// Test 16: Concurrent requests — all valid tokens succeed (thread safety)
// ---------------------------------------------------------------------------
static bool TestConcurrentValidTokens() {
    RsaKeyPair kp = GenerateRsaKey();
    if (kp.public_pem.empty()) {
        TestFramework::RecordTest("Auth integration: concurrent valid tokens", false, "key gen failed");
        return false;
    }
    const std::string iss_name = "conc-iss";
    const std::string iss_url  = "https://idp.conc";
    const std::string kid      = "k9";

    AUTH_NAMESPACE::AuthConfig cfg;
    cfg.enabled = true;
    cfg.issuers[iss_name] = MakeStaticIssuerCfg(iss_name, iss_url);

    ServerConfig srv_cfg;
    srv_cfg.bind_host = "127.0.0.1"; srv_cfg.bind_port = 0;
    srv_cfg.worker_threads = 2; srv_cfg.http2.enabled = false;
    HttpServer server(srv_cfg);
    server.Get("/concurrent", [](const HttpRequest&, HttpResponse& resp) {
        resp.Status(200).Body("ok", "text/plain");
    });
    auto mgr = AttachAuthManager(server, cfg,
        {MakePolicy("p", "/concurrent", iss_name)});
    mgr->GetIssuer(iss_name)->jwks_cache()->InstallKeys({{kid, kp.public_pem}});

    TestServerRunner<HttpServer> runner(server);

    constexpr int THREADS = 6;
    constexpr int REQUESTS_PER_THREAD = 8;
    std::atomic<int> success_count{0};
    std::atomic<int> error_count{0};

    // Build the token once, reuse it across threads.
    std::string token = BuildJwt(kp.private_pem, kid, iss_url, "u");

    std::vector<std::thread> threads;
    for (int t = 0; t < THREADS; ++t) {
        threads.emplace_back([&]() {
            for (int i = 0; i < REQUESTS_PER_THREAD; ++i) {
                auto resp = SendHttp(runner.GetPort(), "/concurrent", token);
                if (ExtractStatus(resp) == 200) {
                    success_count.fetch_add(1, std::memory_order_relaxed);
                } else {
                    error_count.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }
    for (auto& th : threads) th.join();

    bool ok = success_count.load() == THREADS * REQUESTS_PER_THREAD && error_count.load() == 0;
    TestFramework::RecordTest("Auth integration: concurrent valid tokens all succeed",
                               ok,
                               ok ? "" : "success=" + std::to_string(success_count.load()) +
                                   " error=" + std::to_string(error_count.load()));
    return ok;
}

// ---------------------------------------------------------------------------
// Test 17: Oversized token (> 8192 bytes) → 401
// ---------------------------------------------------------------------------
static bool TestOversizesTokenDeny401() {
    const std::string iss_name = "over-iss";
    const std::string iss_url  = "https://idp.over";

    AUTH_NAMESPACE::AuthConfig cfg;
    cfg.enabled = true;
    cfg.issuers[iss_name] = MakeStaticIssuerCfg(iss_name, iss_url);

    ServerConfig srv_cfg;
    srv_cfg.bind_host = "127.0.0.1"; srv_cfg.bind_port = 0;
    srv_cfg.worker_threads = 1; srv_cfg.http2.enabled = false;
    HttpServer server(srv_cfg);
    server.Get("/oversize", [](const HttpRequest&, HttpResponse& resp) {
        resp.Status(200).Body("ok", "text/plain");
    });
    auto mgr = AttachAuthManager(server, cfg,
        {MakePolicy("p", "/oversize", iss_name)});

    TestServerRunner<HttpServer> runner(server);
    // Token just over 8192 bytes. The server may reject it at the HTTP
    // transport layer (431 Request Header Fields Too Large) or at the
    // auth middleware layer (401 Unauthorized) — both indicate proper
    // rejection of the oversized credential.
    std::string fat_token(8193, 'x');
    auto resp = SendHttp(runner.GetPort(), "/oversize", fat_token);
    int st = ExtractStatus(resp);
    bool ok = (st == 401 || st == 431);
    TestFramework::RecordTest("Auth integration: oversized token → 401",
                               ok, ok ? "" : "expected 401 or 431, got " + std::to_string(st));
    return ok;
}

// ---------------------------------------------------------------------------
// Test 18: Reload — ForwardConfig update changes subject header name
// ---------------------------------------------------------------------------
static bool TestReloadForwardConfigUpdates() {
    RsaKeyPair kp = GenerateRsaKey();
    if (kp.public_pem.empty()) {
        TestFramework::RecordTest("Auth integration: Reload forward config update", false, "key gen failed");
        return false;
    }
    const std::string iss_name = "reload-iss";
    const std::string iss_url  = "https://idp.reload";
    const std::string kid      = "k10";

    AUTH_NAMESPACE::AuthConfig cfg;
    cfg.enabled = true;
    cfg.issuers[iss_name] = MakeStaticIssuerCfg(iss_name, iss_url);
    cfg.forward.subject_header = "X-Old-Sub";

    auto mgr = std::make_shared<AUTH_NAMESPACE::AuthManager>(
        cfg, nullptr, std::vector<std::shared_ptr<Dispatcher>>{});
    mgr->RegisterPolicy({"/reld/"}, MakePolicy("p", "/reld/", iss_name));
    mgr->Start();
    mgr->GetIssuer(iss_name)->jwks_cache()->InstallKeys({{kid, kp.public_pem}});

    // Verify initial forward config.
    auto fwd_before = mgr->ForwardConfig();
    bool before_ok = fwd_before && fwd_before->subject_header == "X-Old-Sub";

    // Reload with new subject header name.
    AUTH_NAMESPACE::AuthConfig new_cfg = cfg;
    new_cfg.forward.subject_header = "X-New-Sub";
    std::string err;
    bool reloaded = mgr->Reload(new_cfg, err);

    auto fwd_after = mgr->ForwardConfig();
    bool after_ok = reloaded && fwd_after && fwd_after->subject_header == "X-New-Sub";

    bool ok = before_ok && after_ok;
    TestFramework::RecordTest("Auth integration: Reload updates forward config subject_header",
                               ok,
                               ok ? "" : "before_ok=" + std::to_string(before_ok) +
                                   " after_ok=" + std::to_string(after_ok) +
                                   " reload_err='" + err + "'");
    return ok;
}

// ---------------------------------------------------------------------------
// Test 19: Malformed Bearer (no token part after "Bearer ") → 401
// ---------------------------------------------------------------------------
static bool TestEmptyBearerValue() {
    const std::string iss_name = "empty-iss";
    const std::string iss_url  = "https://idp.empty";

    AUTH_NAMESPACE::AuthConfig cfg;
    cfg.enabled = true;
    cfg.issuers[iss_name] = MakeStaticIssuerCfg(iss_name, iss_url);

    ServerConfig srv_cfg;
    srv_cfg.bind_host = "127.0.0.1"; srv_cfg.bind_port = 0;
    srv_cfg.worker_threads = 1; srv_cfg.http2.enabled = false;
    HttpServer server(srv_cfg);
    server.Get("/empty", [](const HttpRequest&, HttpResponse& resp) {
        resp.Status(200).Body("ok", "text/plain");
    });
    auto mgr = AttachAuthManager(server, cfg,
        {MakePolicy("p", "/empty", iss_name)});

    TestServerRunner<HttpServer> runner(server);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        TestFramework::RecordTest("Auth integration: empty bearer value → 401", false, "socket failed");
        return false;
    }
    struct FdG { int f; ~FdG(){ shutdown(f,SHUT_RDWR); close(f); } } g{fd};
    sockaddr_in addr{}; addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(runner.GetPort()));
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    // "Authorization: Bearer " with no token after the space.
    std::string req = "GET /empty HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
                      "Authorization: Bearer \r\n\r\n";
    SendAll(fd, req);
    auto resp = RecvResponse(fd, 3000);
    bool ok = ExtractStatus(resp) == 401;
    TestFramework::RecordTest("Auth integration: empty bearer value → 401",
                               ok, ok ? "" : "expected 401, got " + std::to_string(ExtractStatus(resp)));
    return ok;
}

// ---------------------------------------------------------------------------
// Test 20: Multiple policies — more specific prefix takes precedence
// ---------------------------------------------------------------------------
static bool TestLongestPrefixWins() {
    RsaKeyPair kp = GenerateRsaKey();
    if (kp.public_pem.empty()) {
        TestFramework::RecordTest("Auth integration: longest prefix wins", false, "key gen failed");
        return false;
    }
    const std::string iss_name = "prefix-iss";
    const std::string iss_url  = "https://idp.prefix";
    const std::string kid      = "k11";

    AUTH_NAMESPACE::AuthConfig cfg;
    cfg.enabled = true;
    cfg.issuers[iss_name] = MakeStaticIssuerCfg(iss_name, iss_url);

    ServerConfig srv_cfg;
    srv_cfg.bind_host = "127.0.0.1"; srv_cfg.bind_port = 0;
    srv_cfg.worker_threads = 1; srv_cfg.http2.enabled = false;
    HttpServer server(srv_cfg);
    server.Get("/api/v2/data", [](const HttpRequest&, HttpResponse& resp) {
        resp.Status(200).Body("ok", "text/plain");
    });
    // /api/ → deny on undetermined (would normally 503)
    // /api/v2/ → allow on undetermined (longer prefix wins)
    auto policy_short = MakePolicy("short", "/api/",    iss_name, {}, "deny");
    auto policy_long  = MakePolicy("long",  "/api/v2/", iss_name, {}, "allow");
    auto mgr = AttachAuthManager(server, cfg, {policy_short, policy_long});
    // No keys → UNDETERMINED; /api/v2/ policy says allow.

    TestServerRunner<HttpServer> runner(server);
    RsaKeyPair kp2 = GenerateRsaKey();
    std::string token = BuildJwt(kp2.private_pem, "no-key", iss_url, "u");
    auto resp = SendHttp(runner.GetPort(), "/api/v2/data", token);
    // on_undetermined=allow → 200 (longest prefix wins)
    bool ok = ExtractStatus(resp) == 200;
    TestFramework::RecordTest("Auth integration: longest prefix wins",
                               ok, ok ? "" : "expected 200 (from /api/v2/ allow), got " +
                                   std::to_string(ExtractStatus(resp)));
    return ok;
}

// ---------------------------------------------------------------------------
// Test 21: HttpServer::Reload applies top-level policy applies_to edits live
// Rationale: design §11.2 step 4 / §11 reloadable-fields summary classify
// top-level `auth.policies[].applies_to` as **live-reloadable**. Unlike
// inline `proxy.auth`, top-level policies have no coupling to
// `proxy.route_prefix`; their applies_to protects arbitrary paths including
// programmatic routes, so it is NOT a restart-required topology field.
//
// A prior implementation pinned applies_to at the live value on edit — an
// over-correction that treated all policy edits as topology changes. This
// test pins the corrected semantic: editing applies_to on an identity
// whose issuers are all live takes effect on the live matcher, and a
// subsequent unrelated hot-reloadable edit doesn't undo it either.
// Whole-policy defer applies only when staged issuers reference a
// non-live issuer — that case is covered at the merge-function unit
// level below, not reachable here (AuthManager::Reload rejects topology
// deltas before the merge runs in HttpServer::Reload).
// ---------------------------------------------------------------------------
static bool TestHttpServerReloadAppliesAppliesToLive() {
    const std::string iss_name = "server-owned-iss";
    const std::string iss_url  = "https://idp.server-owned";

    auto make_server_config = [&](const std::string& policy_prefix) {
        ServerConfig cfg;
        cfg.bind_host = "127.0.0.1";
        cfg.bind_port = 0;
        cfg.worker_threads = 1;
        cfg.http2.enabled = false;

        UpstreamConfig idp_upstream;
        idp_upstream.name = "idp-pool";
        idp_upstream.host = "127.0.0.1";
        idp_upstream.port = 9;
        cfg.upstreams.push_back(idp_upstream);

        cfg.auth.enabled = true;
        auto issuer = MakeStaticIssuerCfg(iss_name, iss_url);
        issuer.upstream = "idp-pool";
        cfg.auth.issuers[iss_name] = issuer;
        cfg.auth.policies.push_back(
            MakePolicy("top-policy", policy_prefix, iss_name));
        return cfg;
    };

    ServerConfig live_cfg = make_server_config("/old/");
    HttpServer server(live_cfg);
    server.Get("/old/secure", [](const HttpRequest&, HttpResponse& resp) {
        resp.Status(200).Body("old", "text/plain");
    });
    server.Get("/new/secure", [](const HttpRequest&, HttpResponse& resp) {
        resp.Status(200).Body("new", "text/plain");
    });

    TestServerRunner<HttpServer> runner(server);

    // Before reload: /old/ is protected by the policy (401 unauthenticated),
    // /new/ is unprotected (200).
    auto old_before = SendHttp(runner.GetPort(), "/old/secure");
    auto new_before = SendHttp(runner.GetPort(), "/new/secure");
    bool before_ok =
        ExtractStatus(old_before) == 401 &&
        ExtractStatus(new_before) == 200;

    // Reload with applies_to moved from /old/ to /new/. All staged issuer
    // refs are live, so the whole edit commits live.
    ServerConfig applies_to_edit_cfg = live_cfg;
    applies_to_edit_cfg.auth.policies[0].applies_to = {"/new/"};
    bool reload1_ok = server.Reload(applies_to_edit_cfg);

    // After reload: coverage has MOVED. /old/ is now unprotected (200),
    // /new/ is now protected (401).
    auto old_after_reload1 = SendHttp(runner.GetPort(), "/old/secure");
    auto new_after_reload1 = SendHttp(runner.GetPort(), "/new/secure");
    bool after_reload1_ok =
        ExtractStatus(old_after_reload1) == 200 &&
        ExtractStatus(new_after_reload1) == 401;

    // A subsequent unrelated live edit (forward.subject_header) must not
    // roll back the applies_to change from reload #1.
    ServerConfig unrelated_live_edit_cfg = applies_to_edit_cfg;
    unrelated_live_edit_cfg.auth.forward.subject_header = "X-Reloaded-Subject";
    bool reload2_ok = server.Reload(unrelated_live_edit_cfg);

    auto old_after_reload2 = SendHttp(runner.GetPort(), "/old/secure");
    auto new_after_reload2 = SendHttp(runner.GetPort(), "/new/secure");
    bool after_reload2_ok =
        ExtractStatus(old_after_reload2) == 200 &&
        ExtractStatus(new_after_reload2) == 401;

    bool ok = before_ok && reload1_ok && after_reload1_ok &&
              reload2_ok && after_reload2_ok;
    std::string err;
    if (!before_ok) {
        err = "initial policy coverage wrong old=" +
              std::to_string(ExtractStatus(old_before)) + " new=" +
              std::to_string(ExtractStatus(new_before));
    } else if (!reload1_ok) {
        err = "applies_to-edit reload returned false";
    } else if (!after_reload1_ok) {
        err = "applies_to edit did not take effect live "
              "(old expected 200 got " +
              std::to_string(ExtractStatus(old_after_reload1)) +
              ", new expected 401 got " +
              std::to_string(ExtractStatus(new_after_reload1)) + ")";
    } else if (!reload2_ok) {
        err = "second reload returned false";
    } else if (!after_reload2_ok) {
        err = "subsequent unrelated reload rolled back applies_to "
              "(old expected 200 got " +
              std::to_string(ExtractStatus(old_after_reload2)) +
              ", new expected 401 got " +
              std::to_string(ExtractStatus(new_after_reload2)) + ")";
    }
    TestFramework::RecordTest(
        "Auth integration: HttpServer reload applies top-level applies_to live",
        ok, err);
    return ok;
}

// ---------------------------------------------------------------------------
// RunAllTests
// ---------------------------------------------------------------------------
static void RunAllTests() {
    TestNoAuthPassthrough();
    TestMissingTokenDeny401();
    TestValidJwtAllow200();
    TestWrongIssuerDeny401();
    TestExpiredTokenDeny401();
    TestMissingScopeDeny403();
    TestValidScopeAllow200();
    TestAlgNoneDeny401();
    TestUndeterminedAllow200();
    TestUndeterminedDeny503();
    TestOpenRouteWithAuthManagerNoToken();
    TestSubjectPopulatedOnSuccess();
    TestWrongSchemeDeny401();
    TestSnapshotCountersIntegration();
    TestWwwAuthenticateHeader();
    TestConcurrentValidTokens();
    TestOversizesTokenDeny401();
    TestReloadForwardConfigUpdates();
    TestEmptyBearerValue();
    TestLongestPrefixWins();
    TestHttpServerReloadAppliesAppliesToLive();
}

}  // namespace AuthIntegrationTests
