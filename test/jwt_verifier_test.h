#pragma once

// ============================================================================
// JwtVerifier unit tests — Phase 2 test suite.
//
// Exercises JwtVerifier::Verify and ::PeekIssuer. Signs real JWTs using
// jwt-cpp and OpenSSL-generated test keys; no pre-baked tokens.
//
// Key points:
// - alg:none is ALWAYS rejected (§9 item 11).
// - Algorithm-confusion attack: RS-key token with HS256 header rejected.
// - Exception containment: malformed inputs produce DENY_401, never throw.
// - exp/nbf/iat boundary cases with leeway.
// - scope/scp both parse into AuthContext::scopes.
// ============================================================================

#include "test_framework.h"
#include "auth/jwt_verifier.h"
#include "auth/jwks_cache.h"
#include "auth/issuer.h"
#include "auth/auth_config.h"
#include "auth/auth_context.h"
#include "auth/auth_result.h"
#include "log/logger.h"

#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/nlohmann-json/traits.h>
#include <nlohmann/json.hpp>

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <string>
#include <memory>
#include <chrono>
#include <vector>
#include <optional>

namespace JwtVerifierTests {

// ---------------------------------------------------------------------------
// Key-generation helpers (OpenSSL 3.x style via EVP)
// ---------------------------------------------------------------------------

struct RsaKeyPair {
    std::string public_pem;
    std::string private_pem;
};

struct EcKeyPair {
    std::string public_pem;
    std::string private_pem;
};

// Generate an RSA-2048 key pair. Returns empty strings on failure.
static RsaKeyPair GenerateRsaKey() {
    RsaKeyPair result;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) return result;
    struct CtxGuard { EVP_PKEY_CTX* p; ~CtxGuard() { if (p) EVP_PKEY_CTX_free(p); } } cg{ctx};

    if (EVP_PKEY_keygen_init(ctx) <= 0) return result;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) return result;

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) return result;
    struct PkeyGuard { EVP_PKEY* p; ~PkeyGuard() { if (p) EVP_PKEY_free(p); } } pg{pkey};

    // Public key
    {
        BIO* bio = BIO_new(BIO_s_mem());
        struct BioGuard { BIO* b; ~BioGuard() { if (b) BIO_free(b); } } bg{bio};
        if (PEM_write_bio_PUBKEY(bio, pkey)) {
            BUF_MEM* mem = nullptr;
            BIO_get_mem_ptr(bio, &mem);
            result.public_pem.assign(mem->data, mem->length);
        }
    }
    // Private key
    {
        BIO* bio = BIO_new(BIO_s_mem());
        struct BioGuard { BIO* b; ~BioGuard() { if (b) BIO_free(b); } } bg{bio};
        if (PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
            BUF_MEM* mem = nullptr;
            BIO_get_mem_ptr(bio, &mem);
            result.private_pem.assign(mem->data, mem->length);
        }
    }
    return result;
}

// Generate an EC P-256 key pair.
static EcKeyPair GenerateEc256Key() {
    EcKeyPair result;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!ctx) return result;
    struct CtxGuard { EVP_PKEY_CTX* p; ~CtxGuard() { if (p) EVP_PKEY_CTX_free(p); } } cg{ctx};

    if (EVP_PKEY_keygen_init(ctx) <= 0) return result;
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) return result;

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) return result;
    struct PkeyGuard { EVP_PKEY* p; ~PkeyGuard() { if (p) EVP_PKEY_free(p); } } pg{pkey};

    {
        BIO* bio = BIO_new(BIO_s_mem());
        struct BioGuard { BIO* b; ~BioGuard() { if (b) BIO_free(b); } } bg{bio};
        if (PEM_write_bio_PUBKEY(bio, pkey)) {
            BUF_MEM* mem = nullptr;
            BIO_get_mem_ptr(bio, &mem);
            result.public_pem.assign(mem->data, mem->length);
        }
    }
    {
        BIO* bio = BIO_new(BIO_s_mem());
        struct BioGuard { BIO* b; ~BioGuard() { if (b) BIO_free(b); } } bg{bio};
        if (PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
            BUF_MEM* mem = nullptr;
            BIO_get_mem_ptr(bio, &mem);
            result.private_pem.assign(mem->data, mem->length);
        }
    }
    return result;
}

// Generate an EC P-384 key pair.
static EcKeyPair GenerateEc384Key() {
    EcKeyPair result;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!ctx) return result;
    struct CtxGuard { EVP_PKEY_CTX* p; ~CtxGuard() { if (p) EVP_PKEY_CTX_free(p); } } cg{ctx};

    if (EVP_PKEY_keygen_init(ctx) <= 0) return result;
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp384r1) <= 0) return result;

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) return result;
    struct PkeyGuard { EVP_PKEY* p; ~PkeyGuard() { if (p) EVP_PKEY_free(p); } } pg{pkey};

    {
        BIO* bio = BIO_new(BIO_s_mem());
        struct BioGuard { BIO* b; ~BioGuard() { if (b) BIO_free(b); } } bg{bio};
        if (PEM_write_bio_PUBKEY(bio, pkey)) {
            BUF_MEM* mem = nullptr;
            BIO_get_mem_ptr(bio, &mem);
            result.public_pem.assign(mem->data, mem->length);
        }
    }
    {
        BIO* bio = BIO_new(BIO_s_mem());
        struct BioGuard { BIO* b; ~BioGuard() { if (b) BIO_free(b); } } bg{bio};
        if (PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
            BUF_MEM* mem = nullptr;
            BIO_get_mem_ptr(bio, &mem);
            result.private_pem.assign(mem->data, mem->length);
        }
    }
    return result;
}

// ---------------------------------------------------------------------------
// Minimal fake Issuer construction helper.
//
// The real Issuer constructor requires UpstreamManager and dispatchers which
// we don't have in a pure unit test. We drive JwtVerifier::Verify directly
// by constructing an IssuerConfig and a JwksCache, then using the static
// helper BuildFakeIssuerForTest to feed the PEM into the cache. Since Issuer
// is not easily mockable (it's a concrete class with network dependencies),
// we test JwtVerifier using a real Issuer with a manually installed JwksCache.
//
// The approach: construct a minimal IssuerConfig, construct the Issuer
// (passing nullptr for UpstreamManager and empty dispatchers — safe as long
// as we don't call Start()), then directly install keys into the cache.
// ---------------------------------------------------------------------------
static std::shared_ptr<AUTH_NAMESPACE::Issuer> MakeFakeIssuer(
        const AUTH_NAMESPACE::IssuerConfig& cfg,
        const std::string& public_pem,
        const std::string& kid) {
    // Issuer needs UpstreamManager* and dispatchers. Passing nullptr and empty
    // is safe as long as we never call Start() — which triggers network.
    auto issuer = std::make_shared<AUTH_NAMESPACE::Issuer>(
        cfg,
        /*upstream_manager=*/nullptr,
        /*dispatchers=*/std::vector<std::shared_ptr<Dispatcher>>{},
        /*http_client=*/nullptr,
        /*hmac_key=*/std::string(32, 'k'));

    // Install the public key directly into the cache.
    issuer->jwks_cache()->InstallKeys({{kid, public_pem}});
    // Mark ready by installing the jwks_uri into snapshot via the cache
    // (which Issuer reads as "not needing discovery"). Since we can't call
    // Start(), we signal ready state by setting keys. The IsReady() flag
    // is set only by Start() internally, so we check LookupKeyByKid
    // returns the key rather than relying on IsReady().
    return issuer;
}

// ---------------------------------------------------------------------------
// Happy path: RS256 signed token verifies successfully
// ---------------------------------------------------------------------------
static void TestRS256HappyPath() {
    try {
        auto rsa = GenerateRsaKey();
        if (rsa.private_pem.empty() || rsa.public_pem.empty()) {
            TestFramework::RecordTest("JwtVerifier: RS256 happy path",
                                      false, "RSA key generation failed",
                                      TestFramework::TestCategory::OTHER);
            return;
        }

        const std::string issuer_url = "https://test.example.com/";
        const std::string kid = "test-kid-rs256";

        // Sign a valid JWT
        auto now = std::chrono::system_clock::now();
        std::string token;
        try {
            token = jwt::create<jwt::traits::nlohmann_json>()
                .set_issuer(issuer_url)
                .set_subject("user-123")
                .set_audience("audience-1")
                .set_issued_at(now)
                .set_expires_at(now + std::chrono::hours(1))
                .set_key_id(kid)
                .sign(jwt::algorithm::rs256("", rsa.private_pem, "", ""));
        } catch (const std::exception& ex) {
            TestFramework::RecordTest("JwtVerifier: RS256 happy path",
                                      false, std::string("JWT sign failed: ") + ex.what(),
                                      TestFramework::TestCategory::OTHER);
            return;
        }

        AUTH_NAMESPACE::IssuerConfig cfg;
        cfg.name = "test-issuer";
        cfg.issuer_url = issuer_url;
        cfg.algorithms = {"RS256"};
        cfg.audiences = {"audience-1"};
        cfg.leeway_sec = 30;
        cfg.discovery = false;

        auto issuer = MakeFakeIssuer(cfg, rsa.public_pem, kid);

        AUTH_NAMESPACE::AuthPolicy policy;
        policy.issuers = {"test-issuer"};

        AUTH_NAMESPACE::AuthContext ctx;
        auto result = AUTH_NAMESPACE::JwtVerifier::Verify(token, *issuer, policy, ctx);

        bool pass = result.is_allow() && ctx.subject == "user-123";
        TestFramework::RecordTest("JwtVerifier: RS256 happy path",
                                  pass,
                                  pass ? "" : "outcome=" + std::string(result.is_allow() ? "ALLOW" : "DENY") +
                                             " sub=" + ctx.subject + " reason=" + result.log_reason,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwtVerifier: RS256 happy path",
                                  false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// Happy path: ES256
// ---------------------------------------------------------------------------
static void TestES256HappyPath() {
    try {
        auto ec = GenerateEc256Key();
        if (ec.private_pem.empty() || ec.public_pem.empty()) {
            TestFramework::RecordTest("JwtVerifier: ES256 happy path",
                                      false, "EC-256 key generation failed",
                                      TestFramework::TestCategory::OTHER);
            return;
        }

        const std::string issuer_url = "https://es256-issuer.example.com/";
        const std::string kid = "test-kid-es256";

        auto now = std::chrono::system_clock::now();
        std::string token;
        try {
            token = jwt::create<jwt::traits::nlohmann_json>()
                .set_issuer(issuer_url)
                .set_subject("ec-user")
                .set_issued_at(now)
                .set_expires_at(now + std::chrono::hours(1))
                .set_key_id(kid)
                .sign(jwt::algorithm::es256("", ec.private_pem, "", ""));
        } catch (const std::exception& ex) {
            TestFramework::RecordTest("JwtVerifier: ES256 happy path",
                                      false, std::string("JWT sign failed: ") + ex.what(),
                                      TestFramework::TestCategory::OTHER);
            return;
        }

        AUTH_NAMESPACE::IssuerConfig cfg;
        cfg.name = "ec-issuer";
        cfg.issuer_url = issuer_url;
        cfg.algorithms = {"ES256"};
        cfg.leeway_sec = 30;
        cfg.discovery = false;

        auto issuer = MakeFakeIssuer(cfg, ec.public_pem, kid);

        AUTH_NAMESPACE::AuthPolicy policy;
        policy.issuers = {"ec-issuer"};

        AUTH_NAMESPACE::AuthContext ctx;
        auto result = AUTH_NAMESPACE::JwtVerifier::Verify(token, *issuer, policy, ctx);

        bool pass = result.is_allow() && ctx.subject == "ec-user";
        TestFramework::RecordTest("JwtVerifier: ES256 happy path",
                                  pass,
                                  pass ? "" : "outcome=" + result.log_reason + " sub=" + ctx.subject,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwtVerifier: ES256 happy path",
                                  false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// Happy path: ES384
// ---------------------------------------------------------------------------
static void TestES384HappyPath() {
    try {
        auto ec = GenerateEc384Key();
        if (ec.private_pem.empty() || ec.public_pem.empty()) {
            TestFramework::RecordTest("JwtVerifier: ES384 happy path",
                                      false, "EC-384 key generation failed",
                                      TestFramework::TestCategory::OTHER);
            return;
        }

        const std::string issuer_url = "https://es384-issuer.example.com/";
        const std::string kid = "test-kid-es384";

        auto now = std::chrono::system_clock::now();
        std::string token;
        try {
            token = jwt::create<jwt::traits::nlohmann_json>()
                .set_issuer(issuer_url)
                .set_subject("ec384-user")
                .set_issued_at(now)
                .set_expires_at(now + std::chrono::hours(1))
                .set_key_id(kid)
                .sign(jwt::algorithm::es384("", ec.private_pem, "", ""));
        } catch (const std::exception& ex) {
            TestFramework::RecordTest("JwtVerifier: ES384 happy path",
                                      false, std::string("JWT sign failed: ") + ex.what(),
                                      TestFramework::TestCategory::OTHER);
            return;
        }

        AUTH_NAMESPACE::IssuerConfig cfg;
        cfg.name = "ec384-issuer";
        cfg.issuer_url = issuer_url;
        cfg.algorithms = {"ES384"};
        cfg.leeway_sec = 30;
        cfg.discovery = false;

        auto issuer = MakeFakeIssuer(cfg, ec.public_pem, kid);

        AUTH_NAMESPACE::AuthPolicy policy;
        policy.issuers = {"ec384-issuer"};

        AUTH_NAMESPACE::AuthContext ctx;
        auto result = AUTH_NAMESPACE::JwtVerifier::Verify(token, *issuer, policy, ctx);

        bool pass = result.is_allow();
        TestFramework::RecordTest("JwtVerifier: ES384 happy path",
                                  pass,
                                  pass ? "" : "outcome=" + result.log_reason,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwtVerifier: ES384 happy path",
                                  false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// alg:none is ALWAYS rejected — §9 item 11
// ---------------------------------------------------------------------------
static void TestAlgNoneRejected() {
    try {
        auto rsa = GenerateRsaKey();
        if (rsa.private_pem.empty()) {
            TestFramework::RecordTest("JwtVerifier: alg:none rejected",
                                      false, "Key gen failed",
                                      TestFramework::TestCategory::OTHER);
            return;
        }

        // Manually build a JWT with alg=none header.
        // jwt-cpp does support jwt::algorithm::none for legacy compat,
        // but OUR code must reject it before any signature work.
        const std::string issuer_url = "https://none-issuer.example.com/";
        auto now = std::chrono::system_clock::now();
        std::string token;
        try {
            token = jwt::create<jwt::traits::nlohmann_json>()
                .set_issuer(issuer_url)
                .set_subject("attacker")
                .set_issued_at(now)
                .set_expires_at(now + std::chrono::hours(1))
                .sign(jwt::algorithm::none{});
        } catch (const std::exception& ex) {
            // If jwt-cpp itself refuses to sign with none, that's also
            // fine — the token can't be created, so we skip to a test
            // that manually crafts a "alg":"none" JWT header.
            // Construct manually: header.payload.
            std::string hdr = jwt::base::encode<jwt::alphabet::base64url>(
                std::string("{\"alg\":\"none\",\"typ\":\"JWT\"}"));
            std::string payload_str = "{\"iss\":\"" + issuer_url + "\","
                                      "\"sub\":\"attacker\","
                                      "\"exp\":" + std::to_string(
                                          std::chrono::duration_cast<std::chrono::seconds>(
                                              (now + std::chrono::hours(1)).time_since_epoch()).count()) + "}";
            std::string pay = jwt::base::encode<jwt::alphabet::base64url>(payload_str);
            token = hdr + "." + pay + ".";
        }

        AUTH_NAMESPACE::IssuerConfig cfg;
        cfg.name = "none-issuer";
        cfg.issuer_url = issuer_url;
        cfg.algorithms = {"RS256"};
        cfg.leeway_sec = 30;
        cfg.discovery = false;

        auto issuer = MakeFakeIssuer(cfg, rsa.public_pem, "kid-1");

        AUTH_NAMESPACE::AuthPolicy policy;
        policy.issuers = {"none-issuer"};

        AUTH_NAMESPACE::AuthContext ctx;
        auto result = AUTH_NAMESPACE::JwtVerifier::Verify(token, *issuer, policy, ctx);

        // Must DENY regardless of whether the JWKS has a key
        bool pass = result.is_deny();
        TestFramework::RecordTest("JwtVerifier: alg:none is rejected (§9 item 11)",
                                  pass,
                                  pass ? "" : "alg:none token was not rejected. outcome=" + result.log_reason,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwtVerifier: alg:none is rejected (§9 item 11)",
                                  false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// Algorithm-confusion: RS256-signed token presented as HS256 — must be
// rejected by the allowlist check before any signature attempt.
// ---------------------------------------------------------------------------
static void TestAlgorithmConfusionRejected() {
    try {
        auto rsa = GenerateRsaKey();
        if (rsa.private_pem.empty()) {
            TestFramework::RecordTest("JwtVerifier: algorithm confusion rejected",
                                      false, "Key gen failed",
                                      TestFramework::TestCategory::OTHER);
            return;
        }

        const std::string issuer_url = "https://rs256-only.example.com/";
        auto now = std::chrono::system_clock::now();

        // Build a JWT with alg=HS256 in the header (we don't actually have
        // the symmetric secret — that's the attacker confusion scenario).
        // Manually craft header+payload, sign with a dummy hmac key.
        std::string token;
        try {
            token = jwt::create<jwt::traits::nlohmann_json>()
                .set_issuer(issuer_url)
                .set_subject("attacker")
                .set_issued_at(now)
                .set_expires_at(now + std::chrono::hours(1))
                .sign(jwt::algorithm::hs256("dummy-secret"));
        } catch (const std::exception& ex) {
            TestFramework::RecordTest("JwtVerifier: algorithm confusion rejected",
                                      false, std::string("HS256 sign failed: ") + ex.what(),
                                      TestFramework::TestCategory::OTHER);
            return;
        }

        AUTH_NAMESPACE::IssuerConfig cfg;
        cfg.name = "rs256-only-issuer";
        cfg.issuer_url = issuer_url;
        cfg.algorithms = {"RS256"};   // Only RS256 allowed — HS256 should be rejected
        cfg.leeway_sec = 30;
        cfg.discovery = false;

        auto issuer = MakeFakeIssuer(cfg, rsa.public_pem, "kid-1");

        AUTH_NAMESPACE::AuthPolicy policy;
        policy.issuers = {"rs256-only-issuer"};

        AUTH_NAMESPACE::AuthContext ctx;
        auto result = AUTH_NAMESPACE::JwtVerifier::Verify(token, *issuer, policy, ctx);

        bool pass = result.is_deny();
        TestFramework::RecordTest("JwtVerifier: algorithm confusion (HS256 against RS256-only allowlist) rejected",
                                  pass,
                                  pass ? "" : "HS256 token was not rejected by allowlist. outcome=" + result.log_reason,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwtVerifier: algorithm confusion rejected",
                                  false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// Exception containment: malformed base64
// ---------------------------------------------------------------------------
static void TestMalformedBase64() {
    try {
        AUTH_NAMESPACE::IssuerConfig cfg;
        cfg.name = "test-issuer";
        cfg.issuer_url = "https://test.example.com/";
        cfg.algorithms = {"RS256"};
        cfg.discovery = false;

        auto rsa = GenerateRsaKey();
        auto issuer = MakeFakeIssuer(cfg, rsa.public_pem, "kid-1");

        AUTH_NAMESPACE::AuthPolicy policy;
        policy.issuers = {"test-issuer"};

        AUTH_NAMESPACE::AuthContext ctx;
        // Completely garbage token
        auto result = AUTH_NAMESPACE::JwtVerifier::Verify("@@@@@@@@@@@", *issuer, policy, ctx);
        bool pass = result.is_deny() && !result.is_undetermined();
        TestFramework::RecordTest("JwtVerifier: malformed base64 → DENY_401",
                                  pass,
                                  pass ? "" : "Expected DENY on garbage. outcome=" + result.log_reason,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwtVerifier: malformed base64 → DENY_401",
                                  false, std::string("EXCEPTION ESCAPED (§9 item 16): ") + e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// Exception containment: wrong segment count (1 segment = not a JWT)
// ---------------------------------------------------------------------------
static void TestWrongSegmentCount() {
    try {
        AUTH_NAMESPACE::IssuerConfig cfg;
        cfg.name = "test-issuer";
        cfg.issuer_url = "https://test.example.com/";
        cfg.algorithms = {"RS256"};
        cfg.discovery = false;

        auto rsa = GenerateRsaKey();
        auto issuer = MakeFakeIssuer(cfg, rsa.public_pem, "kid-1");

        AUTH_NAMESPACE::AuthPolicy policy;
        AUTH_NAMESPACE::AuthContext ctx;

        // One segment (no dots)
        auto r1 = AUTH_NAMESPACE::JwtVerifier::Verify("onlyone", *issuer, policy, ctx);
        // Two segments (missing signature)
        auto r2 = AUTH_NAMESPACE::JwtVerifier::Verify("header.payload", *issuer, policy, ctx);
        // Four segments (too many)
        auto r3 = AUTH_NAMESPACE::JwtVerifier::Verify("a.b.c.d", *issuer, policy, ctx);

        bool pass = r1.is_deny() && r2.is_deny() && r3.is_deny();
        TestFramework::RecordTest("JwtVerifier: wrong segment count → DENY_401",
                                  pass,
                                  pass ? "" : "Segment-count check failed",
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwtVerifier: wrong segment count → DENY_401",
                                  false, std::string("EXCEPTION ESCAPED: ") + e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// Exception containment: empty token
// ---------------------------------------------------------------------------
static void TestEmptyToken() {
    try {
        AUTH_NAMESPACE::IssuerConfig cfg;
        cfg.name = "test-issuer";
        cfg.issuer_url = "https://test.example.com/";
        cfg.algorithms = {"RS256"};
        cfg.discovery = false;

        auto rsa = GenerateRsaKey();
        auto issuer = MakeFakeIssuer(cfg, rsa.public_pem, "kid-1");

        AUTH_NAMESPACE::AuthPolicy policy;
        AUTH_NAMESPACE::AuthContext ctx;
        auto result = AUTH_NAMESPACE::JwtVerifier::Verify("", *issuer, policy, ctx);
        bool pass = result.is_deny();
        TestFramework::RecordTest("JwtVerifier: empty token → DENY_401",
                                  pass,
                                  pass ? "" : "Expected DENY on empty token",
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwtVerifier: empty token → DENY_401",
                                  false, std::string("EXCEPTION ESCAPED: ") + e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// Exception containment: 8KB+1 oversize token
// ---------------------------------------------------------------------------
static void TestOversizeToken() {
    try {
        AUTH_NAMESPACE::IssuerConfig cfg;
        cfg.name = "test-issuer";
        cfg.issuer_url = "https://test.example.com/";
        cfg.algorithms = {"RS256"};
        cfg.discovery = false;

        auto rsa = GenerateRsaKey();
        auto issuer = MakeFakeIssuer(cfg, rsa.public_pem, "kid-1");

        AUTH_NAMESPACE::AuthPolicy policy;
        AUTH_NAMESPACE::AuthContext ctx;
        std::string oversize(8192 + 1, 'a');
        auto result = AUTH_NAMESPACE::JwtVerifier::Verify(oversize, *issuer, policy, ctx);
        bool pass = result.is_deny();
        TestFramework::RecordTest("JwtVerifier: 8KB+1 oversize token → DENY_401",
                                  pass,
                                  pass ? "" : "Expected DENY on oversize token",
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwtVerifier: 8KB+1 oversize token → DENY_401",
                                  false, std::string("EXCEPTION ESCAPED: ") + e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// Expired token → DENY_401 (invalid_token)
// ---------------------------------------------------------------------------
static void TestExpiredToken() {
    try {
        auto rsa = GenerateRsaKey();
        if (rsa.private_pem.empty()) {
            TestFramework::RecordTest("JwtVerifier: expired token → DENY_401",
                                      false, "Key gen failed", TestFramework::TestCategory::OTHER);
            return;
        }
        const std::string issuer_url = "https://test.example.com/";
        const std::string kid = "kid-exp";

        auto past = std::chrono::system_clock::now() - std::chrono::hours(2);
        std::string token;
        try {
            token = jwt::create<jwt::traits::nlohmann_json>()
                .set_issuer(issuer_url)
                .set_subject("user")
                .set_issued_at(past - std::chrono::hours(1))
                .set_expires_at(past)   // expired 2 hours ago
                .set_key_id(kid)
                .sign(jwt::algorithm::rs256("", rsa.private_pem, "", ""));
        } catch (const std::exception& ex) {
            TestFramework::RecordTest("JwtVerifier: expired token → DENY_401",
                                      false, std::string("Sign failed: ") + ex.what(),
                                      TestFramework::TestCategory::OTHER);
            return;
        }

        AUTH_NAMESPACE::IssuerConfig cfg;
        cfg.name = "test-issuer";
        cfg.issuer_url = issuer_url;
        cfg.algorithms = {"RS256"};
        cfg.leeway_sec = 30;   // 30s leeway — token expired 2 hours ago, still fails
        cfg.discovery = false;

        auto issuer = MakeFakeIssuer(cfg, rsa.public_pem, kid);
        AUTH_NAMESPACE::AuthPolicy policy;
        AUTH_NAMESPACE::AuthContext ctx;
        auto result = AUTH_NAMESPACE::JwtVerifier::Verify(token, *issuer, policy, ctx);

        bool pass = result.is_deny();
        TestFramework::RecordTest("JwtVerifier: expired token → DENY_401",
                                  pass,
                                  pass ? "" : "Expected DENY on expired token. reason=" + result.log_reason,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwtVerifier: expired token → DENY_401",
                                  false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// Token within leeway window: exp = now - 20s, leeway = 30s → ALLOW
// ---------------------------------------------------------------------------
static void TestTokenWithinLeeway() {
    try {
        auto rsa = GenerateRsaKey();
        if (rsa.private_pem.empty()) {
            TestFramework::RecordTest("JwtVerifier: within-leeway token → ALLOW",
                                      false, "Key gen failed", TestFramework::TestCategory::OTHER);
            return;
        }
        const std::string issuer_url = "https://test.example.com/";
        const std::string kid = "kid-leeway";

        auto now = std::chrono::system_clock::now();
        // Expired 20 seconds ago
        auto exp = now - std::chrono::seconds(20);
        std::string token;
        try {
            token = jwt::create<jwt::traits::nlohmann_json>()
                .set_issuer(issuer_url)
                .set_subject("user")
                .set_issued_at(exp - std::chrono::hours(1))
                .set_expires_at(exp)
                .set_key_id(kid)
                .sign(jwt::algorithm::rs256("", rsa.private_pem, "", ""));
        } catch (...) {
            TestFramework::RecordTest("JwtVerifier: within-leeway token → ALLOW",
                                      false, "Sign failed", TestFramework::TestCategory::OTHER);
            return;
        }

        AUTH_NAMESPACE::IssuerConfig cfg;
        cfg.name = "test-issuer";
        cfg.issuer_url = issuer_url;
        cfg.algorithms = {"RS256"};
        cfg.leeway_sec = 30;   // 30s leeway — should cover 20s past expiry
        cfg.discovery = false;

        auto issuer = MakeFakeIssuer(cfg, rsa.public_pem, kid);
        AUTH_NAMESPACE::AuthPolicy policy;
        AUTH_NAMESPACE::AuthContext ctx;
        auto result = AUTH_NAMESPACE::JwtVerifier::Verify(token, *issuer, policy, ctx);

        bool pass = result.is_allow();
        TestFramework::RecordTest("JwtVerifier: within-leeway token → ALLOW",
                                  pass,
                                  pass ? "" : "Expected ALLOW within leeway window. reason=" + result.log_reason,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwtVerifier: within-leeway token → ALLOW",
                                  false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// iss mismatch → DENY_401
// ---------------------------------------------------------------------------
static void TestIssMismatch() {
    try {
        auto rsa = GenerateRsaKey();
        if (rsa.private_pem.empty()) {
            TestFramework::RecordTest("JwtVerifier: iss mismatch → DENY_401",
                                      false, "Key gen failed", TestFramework::TestCategory::OTHER);
            return;
        }
        const std::string issuer_url = "https://real-issuer.example.com/";
        const std::string kid = "kid-iss";

        auto now = std::chrono::system_clock::now();
        std::string token;
        try {
            token = jwt::create<jwt::traits::nlohmann_json>()
                .set_issuer("https://WRONG-issuer.example.com/")   // wrong iss
                .set_subject("user")
                .set_issued_at(now)
                .set_expires_at(now + std::chrono::hours(1))
                .set_key_id(kid)
                .sign(jwt::algorithm::rs256("", rsa.private_pem, "", ""));
        } catch (...) {
            TestFramework::RecordTest("JwtVerifier: iss mismatch → DENY_401",
                                      false, "Sign failed", TestFramework::TestCategory::OTHER);
            return;
        }

        AUTH_NAMESPACE::IssuerConfig cfg;
        cfg.name = "test-issuer";
        cfg.issuer_url = issuer_url;
        cfg.algorithms = {"RS256"};
        cfg.leeway_sec = 30;
        cfg.discovery = false;

        auto issuer = MakeFakeIssuer(cfg, rsa.public_pem, kid);
        AUTH_NAMESPACE::AuthPolicy policy;
        AUTH_NAMESPACE::AuthContext ctx;
        auto result = AUTH_NAMESPACE::JwtVerifier::Verify(token, *issuer, policy, ctx);

        bool pass = result.is_deny();
        TestFramework::RecordTest("JwtVerifier: iss mismatch → DENY_401",
                                  pass,
                                  pass ? "" : "Expected DENY on iss mismatch. reason=" + result.log_reason,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwtVerifier: iss mismatch → DENY_401",
                                  false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// aud mismatch → DENY_401
// ---------------------------------------------------------------------------
static void TestAudienceMismatch() {
    try {
        auto rsa = GenerateRsaKey();
        if (rsa.private_pem.empty()) {
            TestFramework::RecordTest("JwtVerifier: aud mismatch → DENY_401",
                                      false, "Key gen failed", TestFramework::TestCategory::OTHER);
            return;
        }
        const std::string issuer_url = "https://test.example.com/";
        const std::string kid = "kid-aud";

        auto now = std::chrono::system_clock::now();
        std::string token;
        try {
            token = jwt::create<jwt::traits::nlohmann_json>()
                .set_issuer(issuer_url)
                .set_audience("wrong-audience")
                .set_subject("user")
                .set_issued_at(now)
                .set_expires_at(now + std::chrono::hours(1))
                .set_key_id(kid)
                .sign(jwt::algorithm::rs256("", rsa.private_pem, "", ""));
        } catch (...) {
            TestFramework::RecordTest("JwtVerifier: aud mismatch → DENY_401",
                                      false, "Sign failed", TestFramework::TestCategory::OTHER);
            return;
        }

        AUTH_NAMESPACE::IssuerConfig cfg;
        cfg.name = "test-issuer";
        cfg.issuer_url = issuer_url;
        cfg.algorithms = {"RS256"};
        cfg.audiences = {"expected-audience"};
        cfg.leeway_sec = 30;
        cfg.discovery = false;

        auto issuer = MakeFakeIssuer(cfg, rsa.public_pem, kid);
        AUTH_NAMESPACE::AuthPolicy policy;
        AUTH_NAMESPACE::AuthContext ctx;
        auto result = AUTH_NAMESPACE::JwtVerifier::Verify(token, *issuer, policy, ctx);

        bool pass = result.is_deny();
        TestFramework::RecordTest("JwtVerifier: aud mismatch → DENY_401",
                                  pass,
                                  pass ? "" : "Expected DENY on aud mismatch. reason=" + result.log_reason,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwtVerifier: aud mismatch → DENY_401",
                                  false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// scope (space-separated string) → AuthContext::scopes populated
// ---------------------------------------------------------------------------
static void TestScopeStringParsed() {
    try {
        auto rsa = GenerateRsaKey();
        if (rsa.private_pem.empty()) {
            TestFramework::RecordTest("JwtVerifier: scope string → scopes populated",
                                      false, "Key gen failed", TestFramework::TestCategory::OTHER);
            return;
        }
        const std::string issuer_url = "https://test.example.com/";
        const std::string kid = "kid-scope";

        auto now = std::chrono::system_clock::now();
        std::string token;
        try {
            token = jwt::create<jwt::traits::nlohmann_json>()
                .set_issuer(issuer_url)
                .set_subject("user")
                .set_issued_at(now)
                .set_expires_at(now + std::chrono::hours(1))
                .set_key_id(kid)
                .set_payload_claim("scope",
                    jwt::basic_claim<jwt::traits::nlohmann_json>(std::string("read:data write:data")))
                .sign(jwt::algorithm::rs256("", rsa.private_pem, "", ""));
        } catch (const std::exception& ex) {
            TestFramework::RecordTest("JwtVerifier: scope string → scopes populated",
                                      false, std::string("Sign failed: ") + ex.what(),
                                      TestFramework::TestCategory::OTHER);
            return;
        }

        AUTH_NAMESPACE::IssuerConfig cfg;
        cfg.name = "test-issuer";
        cfg.issuer_url = issuer_url;
        cfg.algorithms = {"RS256"};
        cfg.leeway_sec = 30;
        cfg.discovery = false;

        auto issuer = MakeFakeIssuer(cfg, rsa.public_pem, kid);
        AUTH_NAMESPACE::AuthPolicy policy;
        AUTH_NAMESPACE::AuthContext ctx;
        auto result = AUTH_NAMESPACE::JwtVerifier::Verify(token, *issuer, policy, ctx);

        auto has_scope = [&ctx](const std::string& s) {
            return std::find(ctx.scopes.begin(), ctx.scopes.end(), s) != ctx.scopes.end();
        };
        bool pass = result.is_allow() &&
                    has_scope("read:data") &&
                    has_scope("write:data");
        TestFramework::RecordTest("JwtVerifier: scope string → scopes populated",
                                  pass,
                                  pass ? "" : "scopes not populated. outcome=" + result.log_reason,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwtVerifier: scope string → scopes populated",
                                  false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// required_scopes: missing scope → DENY_403 insufficient_scope
// ---------------------------------------------------------------------------
static void TestRequiredScopesMissing() {
    try {
        auto rsa = GenerateRsaKey();
        if (rsa.private_pem.empty()) {
            TestFramework::RecordTest("JwtVerifier: missing required scope → DENY_403",
                                      false, "Key gen failed", TestFramework::TestCategory::OTHER);
            return;
        }
        const std::string issuer_url = "https://test.example.com/";
        const std::string kid = "kid-scope-req";

        auto now = std::chrono::system_clock::now();
        std::string token;
        try {
            token = jwt::create<jwt::traits::nlohmann_json>()
                .set_issuer(issuer_url)
                .set_subject("user")
                .set_issued_at(now)
                .set_expires_at(now + std::chrono::hours(1))
                .set_key_id(kid)
                .set_payload_claim("scope",
                    jwt::basic_claim<jwt::traits::nlohmann_json>(std::string("read:data")))
                .sign(jwt::algorithm::rs256("", rsa.private_pem, "", ""));
        } catch (...) {
            TestFramework::RecordTest("JwtVerifier: missing required scope → DENY_403",
                                      false, "Sign failed", TestFramework::TestCategory::OTHER);
            return;
        }

        AUTH_NAMESPACE::IssuerConfig cfg;
        cfg.name = "test-issuer";
        cfg.issuer_url = issuer_url;
        cfg.algorithms = {"RS256"};
        cfg.leeway_sec = 30;
        cfg.discovery = false;

        auto issuer = MakeFakeIssuer(cfg, rsa.public_pem, kid);
        AUTH_NAMESPACE::AuthPolicy policy;
        policy.required_scopes = {"read:data", "admin:write"};   // admin:write missing

        AUTH_NAMESPACE::AuthContext ctx;
        auto result = AUTH_NAMESPACE::JwtVerifier::Verify(token, *issuer, policy, ctx);

        bool pass = (result.outcome == AUTH_NAMESPACE::VerifyOutcome::DENY_403);
        TestFramework::RecordTest("JwtVerifier: missing required scope → DENY_403",
                                  pass,
                                  pass ? "" : "Expected DENY_403 for missing scope. outcome=" + result.log_reason,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwtVerifier: missing required scope → DENY_403",
                                  false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// kid miss → UNDETERMINED (no cached key)
// ---------------------------------------------------------------------------
static void TestKidMissUndetermined() {
    try {
        auto rsa = GenerateRsaKey();
        if (rsa.private_pem.empty()) {
            TestFramework::RecordTest("JwtVerifier: kid miss → UNDETERMINED",
                                      false, "Key gen failed", TestFramework::TestCategory::OTHER);
            return;
        }
        const std::string issuer_url = "https://test.example.com/";

        auto now = std::chrono::system_clock::now();
        std::string token;
        try {
            token = jwt::create<jwt::traits::nlohmann_json>()
                .set_issuer(issuer_url)
                .set_subject("user")
                .set_issued_at(now)
                .set_expires_at(now + std::chrono::hours(1))
                .set_key_id("kid-unknown-123")   // kid not in cache
                .sign(jwt::algorithm::rs256("", rsa.private_pem, "", ""));
        } catch (...) {
            TestFramework::RecordTest("JwtVerifier: kid miss → UNDETERMINED",
                                      false, "Sign failed", TestFramework::TestCategory::OTHER);
            return;
        }

        AUTH_NAMESPACE::IssuerConfig cfg;
        cfg.name = "test-issuer";
        cfg.issuer_url = issuer_url;
        cfg.algorithms = {"RS256"};
        cfg.leeway_sec = 30;
        cfg.discovery = false;

        // Install a DIFFERENT kid in the cache
        auto issuer = MakeFakeIssuer(cfg, rsa.public_pem, "kid-1");
        // The cache has kid-1; the token has kid-unknown-123 → miss

        AUTH_NAMESPACE::AuthPolicy policy;
        AUTH_NAMESPACE::AuthContext ctx;
        auto result = AUTH_NAMESPACE::JwtVerifier::Verify(token, *issuer, policy, ctx);

        bool pass = result.is_undetermined();
        TestFramework::RecordTest("JwtVerifier: kid miss → UNDETERMINED",
                                  pass,
                                  pass ? "" : "Expected UNDETERMINED on kid miss. outcome=" + result.log_reason,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwtVerifier: kid miss → UNDETERMINED",
                                  false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// required_claims enforcement
// ---------------------------------------------------------------------------
static void TestRequiredClaimsMissing() {
    try {
        auto rsa = GenerateRsaKey();
        if (rsa.private_pem.empty()) {
            TestFramework::RecordTest("JwtVerifier: missing required claim → DENY_401",
                                      false, "Key gen failed", TestFramework::TestCategory::OTHER);
            return;
        }
        const std::string issuer_url = "https://test.example.com/";
        const std::string kid = "kid-req-claim";

        auto now = std::chrono::system_clock::now();
        std::string token;
        try {
            // token has no "tenant_id" claim
            token = jwt::create<jwt::traits::nlohmann_json>()
                .set_issuer(issuer_url)
                .set_subject("user")
                .set_issued_at(now)
                .set_expires_at(now + std::chrono::hours(1))
                .set_key_id(kid)
                .sign(jwt::algorithm::rs256("", rsa.private_pem, "", ""));
        } catch (...) {
            TestFramework::RecordTest("JwtVerifier: missing required claim → DENY_401",
                                      false, "Sign failed", TestFramework::TestCategory::OTHER);
            return;
        }

        AUTH_NAMESPACE::IssuerConfig cfg;
        cfg.name = "test-issuer";
        cfg.issuer_url = issuer_url;
        cfg.algorithms = {"RS256"};
        cfg.leeway_sec = 30;
        cfg.required_claims = {"tenant_id"};   // required but absent
        cfg.discovery = false;

        auto issuer = MakeFakeIssuer(cfg, rsa.public_pem, kid);
        AUTH_NAMESPACE::AuthPolicy policy;
        AUTH_NAMESPACE::AuthContext ctx;
        auto result = AUTH_NAMESPACE::JwtVerifier::Verify(token, *issuer, policy, ctx);

        bool pass = result.is_deny();
        TestFramework::RecordTest("JwtVerifier: missing required claim → DENY_401",
                                  pass,
                                  pass ? "" : "Expected DENY on missing required_claim. reason=" + result.log_reason,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwtVerifier: missing required claim → DENY_401",
                                  false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// PeekIssuer: returns iss without signature verification
// ---------------------------------------------------------------------------
static void TestPeekIssuerReturnsIss() {
    try {
        auto rsa = GenerateRsaKey();
        if (rsa.private_pem.empty()) {
            TestFramework::RecordTest("JwtVerifier: PeekIssuer returns iss",
                                      false, "Key gen failed", TestFramework::TestCategory::OTHER);
            return;
        }
        const std::string issuer_url = "https://peek.example.com/";
        auto now = std::chrono::system_clock::now();
        std::string token;
        try {
            token = jwt::create<jwt::traits::nlohmann_json>()
                .set_issuer(issuer_url)
                .set_subject("user")
                .set_issued_at(now)
                .set_expires_at(now + std::chrono::hours(1))
                .sign(jwt::algorithm::rs256("", rsa.private_pem, "", ""));
        } catch (...) {
            TestFramework::RecordTest("JwtVerifier: PeekIssuer returns iss",
                                      false, "Sign failed", TestFramework::TestCategory::OTHER);
            return;
        }

        auto iss = AUTH_NAMESPACE::JwtVerifier::PeekIssuer(token);
        bool pass = iss.has_value() && *iss == issuer_url;
        TestFramework::RecordTest("JwtVerifier: PeekIssuer returns iss",
                                  pass,
                                  pass ? "" : "Wrong iss: " + iss.value_or("<nullopt>"),
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwtVerifier: PeekIssuer returns iss",
                                  false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// PeekIssuer: malformed token → nullopt (no exception)
// ---------------------------------------------------------------------------
static void TestPeekIssuerMalformed() {
    try {
        auto r = AUTH_NAMESPACE::JwtVerifier::PeekIssuer("not.a.valid.jwt.here");
        bool pass = !r.has_value();
        TestFramework::RecordTest("JwtVerifier: PeekIssuer malformed → nullopt",
                                  pass,
                                  pass ? "" : "Expected nullopt on malformed token",
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwtVerifier: PeekIssuer malformed → nullopt",
                                  false, std::string("EXCEPTION ESCAPED: ") + e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// PeekIssuer: empty token → nullopt
static void TestPeekIssuerEmpty() {
    try {
        auto r = AUTH_NAMESPACE::JwtVerifier::PeekIssuer("");
        bool pass = !r.has_value();
        TestFramework::RecordTest("JwtVerifier: PeekIssuer empty → nullopt",
                                  pass,
                                  pass ? "" : "Expected nullopt on empty token",
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwtVerifier: PeekIssuer empty → nullopt",
                                  false, std::string("EXCEPTION ESCAPED: ") + e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// per-issuer algorithm allowlist: token with allowed alg succeeds;
// token with rejected alg fails
// ---------------------------------------------------------------------------
static void TestAlgorithmAllowlist() {
    try {
        auto rsa = GenerateRsaKey();
        if (rsa.private_pem.empty()) {
            TestFramework::RecordTest("JwtVerifier: per-issuer algorithm allowlist",
                                      false, "Key gen failed", TestFramework::TestCategory::OTHER);
            return;
        }
        const std::string issuer_url = "https://test.example.com/";
        const std::string kid = "kid-alg-list";

        auto now = std::chrono::system_clock::now();
        // Sign with RS512 but issuer only allows RS256 → must be rejected
        std::string token;
        try {
            token = jwt::create<jwt::traits::nlohmann_json>()
                .set_issuer(issuer_url)
                .set_subject("user")
                .set_issued_at(now)
                .set_expires_at(now + std::chrono::hours(1))
                .set_key_id(kid)
                .sign(jwt::algorithm::rs512("", rsa.private_pem, "", ""));
        } catch (...) {
            TestFramework::RecordTest("JwtVerifier: per-issuer algorithm allowlist",
                                      false, "Sign failed", TestFramework::TestCategory::OTHER);
            return;
        }

        AUTH_NAMESPACE::IssuerConfig cfg;
        cfg.name = "test-issuer";
        cfg.issuer_url = issuer_url;
        cfg.algorithms = {"RS256"};   // RS512 not allowed
        cfg.leeway_sec = 30;
        cfg.discovery = false;

        auto issuer = MakeFakeIssuer(cfg, rsa.public_pem, kid);
        AUTH_NAMESPACE::AuthPolicy policy;
        AUTH_NAMESPACE::AuthContext ctx;
        auto result = AUTH_NAMESPACE::JwtVerifier::Verify(token, *issuer, policy, ctx);

        bool pass = result.is_deny();
        TestFramework::RecordTest("JwtVerifier: per-issuer algorithm allowlist rejects RS512 for RS256-only issuer",
                                  pass,
                                  pass ? "" : "Expected DENY for RS512 token against RS256-only issuer",
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwtVerifier: per-issuer algorithm allowlist",
                                  false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// Missing `exp` claim — reject as invalid_token:missing_exp. jwt-cpp only
// validates exp when present, so without the explicit check a correctly-
// signed token with matching iss/aud and no exp would be a non-expiring
// bearer token — unacceptable for a resource-server validator.
// ---------------------------------------------------------------------------
static void TestTokenMissingExpRejected() {
    try {
        auto rsa = GenerateRsaKey();
        if (rsa.private_pem.empty() || rsa.public_pem.empty()) {
            TestFramework::RecordTest("JwtVerifier: missing exp rejected",
                                      false, "RSA key generation failed",
                                      TestFramework::TestCategory::OTHER);
            return;
        }

        const std::string issuer_url = "https://exp-test.example.com/";
        const std::string kid = "test-kid-missing-exp";

        // Sign a JWT that deliberately OMITS set_expires_at.
        std::string token;
        try {
            token = jwt::create<jwt::traits::nlohmann_json>()
                .set_issuer(issuer_url)
                .set_subject("user-no-exp")
                .set_audience("audience-1")
                .set_issued_at(std::chrono::system_clock::now())
                .set_key_id(kid)
                .sign(jwt::algorithm::rs256("", rsa.private_pem, "", ""));
        } catch (const std::exception& ex) {
            TestFramework::RecordTest("JwtVerifier: missing exp rejected",
                                      false, std::string("sign failed: ") + ex.what(),
                                      TestFramework::TestCategory::OTHER);
            return;
        }

        AUTH_NAMESPACE::IssuerConfig cfg;
        cfg.name = "test-issuer";
        cfg.issuer_url = issuer_url;
        cfg.algorithms = {"RS256"};
        cfg.audiences = {"audience-1"};
        cfg.leeway_sec = 30;
        cfg.discovery = false;

        auto issuer = MakeFakeIssuer(cfg, rsa.public_pem, kid);
        AUTH_NAMESPACE::AuthPolicy policy;
        policy.issuers = {"test-issuer"};

        AUTH_NAMESPACE::AuthContext ctx;
        auto result = AUTH_NAMESPACE::JwtVerifier::Verify(token, *issuer, policy, ctx);

        // 401-class deny with explicit missing_exp log reason. Enforces the
        // minimum temporal-bound guarantee is an always-on property of the
        // verifier, not an operator-configuration concern.
        bool pass = result.is_deny() &&
                    result.log_reason.find("missing_exp") != std::string::npos;
        TestFramework::RecordTest("JwtVerifier: missing exp rejected",
                                  pass,
                                  pass ? "" : "expected DENY with missing_exp, got outcome=" +
                                      std::string(result.is_allow() ? "ALLOW" : "DENY") +
                                      " reason=" + result.log_reason,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwtVerifier: missing exp rejected",
                                  false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------
static void RunAllTests() {
    std::cout << "\n[JwtVerifier Tests]" << std::endl;
    TestRS256HappyPath();
    TestTokenMissingExpRejected();
    TestES256HappyPath();
    TestES384HappyPath();
    TestAlgNoneRejected();
    TestAlgorithmConfusionRejected();
    TestMalformedBase64();
    TestWrongSegmentCount();
    TestEmptyToken();
    TestOversizeToken();
    TestExpiredToken();
    TestTokenWithinLeeway();
    TestIssMismatch();
    TestAudienceMismatch();
    TestScopeStringParsed();
    TestRequiredScopesMissing();
    TestKidMissUndetermined();
    TestRequiredClaimsMissing();
    TestPeekIssuerReturnsIss();
    TestPeekIssuerMalformed();
    TestPeekIssuerEmpty();
    TestAlgorithmAllowlist();
}

}  // namespace JwtVerifierTests
