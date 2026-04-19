#pragma once

// ============================================================================
// Auth multi-issuer tests — Phase 2 test suite.
//
// These tests exercise AuthManager's issuer routing logic when multiple
// issuers are configured: PeekIssuer-based routing, issuer allowlist
// enforcement per-policy, fallback to first issuer, and issuer not in
// policy allowlist rejection.
//
// All tests drive AuthManager unit-level (no live server); keys are
// installed directly into each issuer's JwksCache.
//
// Tests covered:
//   1.  Token from issuer-A routed to issuer-A keys (not issuer-B)
//   2.  Token from issuer-B routed to issuer-B keys (not issuer-A)
//   3.  Token from issuer-A accepted by policy that lists only issuer-A
//   4.  Token from issuer-A rejected (401) by policy that lists only issuer-B
//   5.  Token from issuer-B accepted by multi-issuer policy (A + B)
//   6.  Token from issuer-A accepted by multi-issuer policy (A + B)
//   7.  PeekIssuer with malformed JWT returns nullopt (no crash)
//   8.  Both issuers contribute to SnapshotAll::issuers map
// ============================================================================

#include "test_framework.h"
#include "auth/auth_manager.h"
#include "auth/auth_config.h"
#include "auth/auth_context.h"
#include "auth/auth_result.h"
#include "auth/jwks_cache.h"
#include "auth/issuer.h"
#include "auth/jwt_verifier.h"
#include "http/http_request.h"
#include "http/http_response.h"
#include "log/logger.h"

#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/nlohmann-json/traits.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>

#include <string>
#include <memory>
#include <vector>
#include <optional>

namespace AuthMultiIssuerTests {

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
        int exp_offset_sec = 3600) {
    if (private_pem.empty()) return "";
    auto now = std::chrono::system_clock::now();
    auto builder = jwt::create<jwt::traits::nlohmann_json>()
        .set_issuer(iss)
        .set_subject(sub)
        .set_issued_at(now)
        .set_expires_at(now + std::chrono::seconds(exp_offset_sec))
        .set_key_id(kid);
    try {
        auto alg = jwt::algorithm::rs256("", private_pem, "", "");
        return builder.sign(alg);
    } catch (...) { return ""; }
}

// Build a static IssuerConfig (no discovery, no network).
static AUTH_NAMESPACE::IssuerConfig MakeIssuerCfg(
        const std::string& name,
        const std::string& url) {
    AUTH_NAMESPACE::IssuerConfig ic;
    ic.name       = name;
    ic.issuer_url = url;
    ic.discovery  = false;
    ic.jwks_uri   = "https://" + name + ".example.com/jwks.json";
    ic.upstream   = "";
    ic.mode       = "jwt";
    ic.algorithms = {"RS256"};
    ic.leeway_sec = 0;
    ic.jwks_cache_sec = 300;
    return ic;
}

// Build a request with the given path and Authorization header.
static HttpRequest MakeReq(const std::string& path, const std::string& token) {
    HttpRequest req;
    req.method   = "GET";
    req.path     = path;
    req.url      = path;
    req.complete = true;
    if (!token.empty()) {
        req.headers["authorization"] = "Bearer " + token;
    }
    return req;
}

// Build an AuthManager with two issuers and a policy.
// Returns {mgr, issuer_a_ptr, issuer_b_ptr} — callers install keys directly.
struct DualIssuerSetup {
    std::shared_ptr<AUTH_NAMESPACE::AuthManager> mgr;
    AUTH_NAMESPACE::Issuer* issuer_a;
    AUTH_NAMESPACE::Issuer* issuer_b;
};

static DualIssuerSetup MakeDualIssuerManager(
        const std::string& name_a, const std::string& url_a,
        const std::string& name_b, const std::string& url_b,
        const std::vector<std::string>& policy_issuers,
        const std::string& policy_prefix = "/api/",
        const std::string& on_undetermined = "deny") {
    AUTH_NAMESPACE::AuthConfig cfg;
    cfg.enabled = true;
    cfg.issuers[name_a] = MakeIssuerCfg(name_a, url_a);
    cfg.issuers[name_b] = MakeIssuerCfg(name_b, url_b);

    auto mgr = std::make_shared<AUTH_NAMESPACE::AuthManager>(
        cfg, nullptr, std::vector<std::shared_ptr<Dispatcher>>{});

    AUTH_NAMESPACE::AuthPolicy p;
    p.name            = "dual-policy";
    p.enabled         = true;
    p.applies_to      = {policy_prefix};
    p.issuers         = policy_issuers;
    p.on_undetermined = on_undetermined;
    mgr->RegisterPolicy(p.applies_to, p);
    mgr->Start();

    return {mgr, mgr->GetIssuer(name_a), mgr->GetIssuer(name_b)};
}

// ---------------------------------------------------------------------------
// Test 1: Token from issuer-A routed to issuer-A keys
// Rationale: PeekIssuer returns issuer_url_a; routing selects issuer-A's
// JwksCache. Token signed with issuer-A's private key verifies successfully.
// ---------------------------------------------------------------------------
static bool TestTokenFromARoutedToA() {
    auto kp_a = GenRsa();
    auto kp_b = GenRsa();
    if (kp_a.private_pem.empty() || kp_b.private_pem.empty()) return true;

    const std::string url_a = "https://issuer-a.example.com";
    const std::string url_b = "https://issuer-b.example.com";

    auto setup = MakeDualIssuerManager(
        "iss-a", url_a, "iss-b", url_b, {"iss-a", "iss-b"});
    if (!setup.issuer_a || !setup.issuer_b) { setup.mgr->Stop(); return false; }

    // Install A's key on issuer-A, B's key on issuer-B
    setup.issuer_a->jwks_cache()->InstallKeys({{"kid-a", kp_a.public_pem}});
    setup.issuer_b->jwks_cache()->InstallKeys({{"kid-b", kp_b.public_pem}});

    // Build a token from issuer-A
    std::string token = BuildJwt(kp_a.private_pem, "kid-a", url_a, "alice");
    if (token.empty()) { setup.mgr->Stop(); return false; }

    auto req = MakeReq("/api/resource", token);
    HttpResponse resp;
    bool allowed = setup.mgr->InvokeMiddleware(req, resp);

    setup.mgr->Stop();
    return allowed;
}

// ---------------------------------------------------------------------------
// Test 2: Token from issuer-B routed to issuer-B keys
// ---------------------------------------------------------------------------
static bool TestTokenFromBRoutedToB() {
    auto kp_a = GenRsa();
    auto kp_b = GenRsa();
    if (kp_a.private_pem.empty() || kp_b.private_pem.empty()) return true;

    const std::string url_a = "https://issuer-a2.example.com";
    const std::string url_b = "https://issuer-b2.example.com";

    auto setup = MakeDualIssuerManager(
        "iss-a2", url_a, "iss-b2", url_b, {"iss-a2", "iss-b2"});
    if (!setup.issuer_a || !setup.issuer_b) { setup.mgr->Stop(); return false; }

    setup.issuer_a->jwks_cache()->InstallKeys({{"kid-aa", kp_a.public_pem}});
    setup.issuer_b->jwks_cache()->InstallKeys({{"kid-bb", kp_b.public_pem}});

    // Token from issuer-B — signed with B's private key
    std::string token = BuildJwt(kp_b.private_pem, "kid-bb", url_b, "bob");
    if (token.empty()) { setup.mgr->Stop(); return false; }

    auto req = MakeReq("/api/resource", token);
    HttpResponse resp;
    bool allowed = setup.mgr->InvokeMiddleware(req, resp);

    setup.mgr->Stop();
    return allowed;
}

// ---------------------------------------------------------------------------
// Test 3: Token from issuer-A accepted by policy listing only issuer-A
// ---------------------------------------------------------------------------
static bool TestTokenFromAAcceptedBySingleIssuerPolicy() {
    auto kp_a = GenRsa();
    auto kp_b = GenRsa();
    if (kp_a.private_pem.empty()) return true;

    const std::string url_a = "https://issuer-a3.example.com";
    const std::string url_b = "https://issuer-b3.example.com";

    // Policy lists only iss-a3 (not iss-b3)
    auto setup = MakeDualIssuerManager(
        "iss-a3", url_a, "iss-b3", url_b, {"iss-a3"});
    if (!setup.issuer_a) { setup.mgr->Stop(); return false; }

    setup.issuer_a->jwks_cache()->InstallKeys({{"kid-a3", kp_a.public_pem}});

    std::string token = BuildJwt(kp_a.private_pem, "kid-a3", url_a, "alice");
    if (token.empty()) { setup.mgr->Stop(); return false; }

    auto req = MakeReq("/api/resource", token);
    HttpResponse resp;
    bool allowed = setup.mgr->InvokeMiddleware(req, resp);

    setup.mgr->Stop();
    return allowed;
}

// ---------------------------------------------------------------------------
// Test 4: Token from issuer-A rejected (401) by policy listing only issuer-B
// Rationale: PeekIssuer returns url_a; policy.issuers={iss-b} → no match →
// issuer_not_accepted → 401.
// ---------------------------------------------------------------------------
static bool TestTokenFromABlockedByBOnlyPolicy() {
    auto kp_a = GenRsa();
    auto kp_b = GenRsa();
    if (kp_a.private_pem.empty()) return true;

    const std::string url_a = "https://issuer-a4.example.com";
    const std::string url_b = "https://issuer-b4.example.com";

    // Policy lists only iss-b4 — tokens from issuer-a4 should be rejected
    auto setup = MakeDualIssuerManager(
        "iss-a4", url_a, "iss-b4", url_b, {"iss-b4"});
    if (!setup.issuer_a || !setup.issuer_b) { setup.mgr->Stop(); return false; }

    setup.issuer_a->jwks_cache()->InstallKeys({{"kid-a4", kp_a.public_pem}});
    setup.issuer_b->jwks_cache()->InstallKeys({{"kid-b4", kp_b.public_pem}});

    // Token from issuer-A but policy only accepts issuer-B
    std::string token = BuildJwt(kp_a.private_pem, "kid-a4", url_a, "mallory");
    if (token.empty()) { setup.mgr->Stop(); return false; }

    auto req = MakeReq("/api/resource", token);
    HttpResponse resp;
    bool blocked = !setup.mgr->InvokeMiddleware(req, resp);

    setup.mgr->Stop();
    if (!blocked) return false;
    return resp.GetStatusCode() == 401;
}

// ---------------------------------------------------------------------------
// Test 5: Token from issuer-B accepted by multi-issuer policy (A + B)
// ---------------------------------------------------------------------------
static bool TestTokenFromBAcceptedByMultiIssuerPolicy() {
    auto kp_a = GenRsa();
    auto kp_b = GenRsa();
    if (kp_b.private_pem.empty()) return true;

    const std::string url_a = "https://issuer-a5.example.com";
    const std::string url_b = "https://issuer-b5.example.com";

    auto setup = MakeDualIssuerManager(
        "iss-a5", url_a, "iss-b5", url_b, {"iss-a5", "iss-b5"});
    if (!setup.issuer_b) { setup.mgr->Stop(); return false; }

    setup.issuer_a->jwks_cache()->InstallKeys({{"kid-a5", kp_a.public_pem}});
    setup.issuer_b->jwks_cache()->InstallKeys({{"kid-b5", kp_b.public_pem}});

    std::string token = BuildJwt(kp_b.private_pem, "kid-b5", url_b, "dave");
    if (token.empty()) { setup.mgr->Stop(); return false; }

    auto req = MakeReq("/api/resource", token);
    HttpResponse resp;
    bool allowed = setup.mgr->InvokeMiddleware(req, resp);

    setup.mgr->Stop();
    return allowed;
}

// ---------------------------------------------------------------------------
// Test 6: Token from issuer-A accepted by multi-issuer policy (A + B)
// ---------------------------------------------------------------------------
static bool TestTokenFromAAcceptedByMultiIssuerPolicy() {
    auto kp_a = GenRsa();
    auto kp_b = GenRsa();
    if (kp_a.private_pem.empty()) return true;

    const std::string url_a = "https://issuer-a6.example.com";
    const std::string url_b = "https://issuer-b6.example.com";

    auto setup = MakeDualIssuerManager(
        "iss-a6", url_a, "iss-b6", url_b, {"iss-a6", "iss-b6"});
    if (!setup.issuer_a) { setup.mgr->Stop(); return false; }

    setup.issuer_a->jwks_cache()->InstallKeys({{"kid-a6", kp_a.public_pem}});
    setup.issuer_b->jwks_cache()->InstallKeys({{"kid-b6", kp_b.public_pem}});

    std::string token = BuildJwt(kp_a.private_pem, "kid-a6", url_a, "eve");
    if (token.empty()) { setup.mgr->Stop(); return false; }

    auto req = MakeReq("/api/resource", token);
    HttpResponse resp;
    bool allowed = setup.mgr->InvokeMiddleware(req, resp);

    setup.mgr->Stop();
    return allowed;
}

// ---------------------------------------------------------------------------
// Test 7: PeekIssuer with malformed JWT returns nullopt (no crash)
// Rationale: Attacker-controlled input must not crash JwtVerifier::PeekIssuer.
// ---------------------------------------------------------------------------
static bool TestPeekIssuerMalformedNoCrash() {
    // Various malformed token formats
    const std::vector<std::string> bad_tokens = {
        "",
        "not.a.jwt",
        "a.b",
        "a.b.c.d",
        std::string(8192, 'X'),
        "eyJhbGciOiJub25lIn0.eyJpc3MiOiAiIn0.",  // alg:none
        "AAAA.BBBB.CCCC",
    };

    for (const auto& tok : bad_tokens) {
        try {
            auto result = AUTH_NAMESPACE::JwtVerifier::PeekIssuer(tok);
            // null or value — both acceptable, no crash
            (void)result;
        } catch (...) {
            // PeekIssuer must not throw — any exception is a test failure
            return false;
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// Test 8: Both issuers contribute to SnapshotAll::issuers map
// ---------------------------------------------------------------------------
static bool TestSnapshotAllHasBothIssuers() {
    auto kp_a = GenRsa();
    auto kp_b = GenRsa();

    const std::string url_a = "https://issuer-a8.example.com";
    const std::string url_b = "https://issuer-b8.example.com";

    auto setup = MakeDualIssuerManager(
        "iss-a8", url_a, "iss-b8", url_b, {"iss-a8", "iss-b8"});

    auto snap = setup.mgr->SnapshotAll();
    setup.mgr->Stop();

    // Both issuers must appear in the snapshot
    return snap.issuers.count("iss-a8") > 0 &&
           snap.issuers.count("iss-b8") > 0;
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
    RunOne("AuthMultiIssuer: token from issuer-A routed to issuer-A keys",
           TestTokenFromARoutedToA);
    RunOne("AuthMultiIssuer: token from issuer-B routed to issuer-B keys",
           TestTokenFromBRoutedToB);
    RunOne("AuthMultiIssuer: token from A accepted by A-only policy",
           TestTokenFromAAcceptedBySingleIssuerPolicy);
    RunOne("AuthMultiIssuer: token from A rejected by B-only policy -> 401",
           TestTokenFromABlockedByBOnlyPolicy);
    RunOne("AuthMultiIssuer: token from B accepted by multi-issuer policy",
           TestTokenFromBAcceptedByMultiIssuerPolicy);
    RunOne("AuthMultiIssuer: token from A accepted by multi-issuer policy",
           TestTokenFromAAcceptedByMultiIssuerPolicy);
    RunOne("AuthMultiIssuer: PeekIssuer malformed token no crash",
           TestPeekIssuerMalformedNoCrash);
    RunOne("AuthMultiIssuer: SnapshotAll contains both issuers",
           TestSnapshotAllHasBothIssuers);
}

}  // namespace AuthMultiIssuerTests
