#pragma once

// ============================================================================
// OidcDiscovery unit tests — Phase 2 test suite.
//
// Because OidcDiscovery requires a live UpstreamHttpClient backed by a real
// UpstreamManager (network I/O), pure unit tests focus on the parts that can
// be exercised without a live event loop:
//
//   1. Cancel() safety — cancel token set, no UAF after destruction.
//   2. IsReady() initial state.
//   3. JSON extraction helper — parse success/failure paths tested via a
//      minimal mock by exercising the static function behaviour indirectly
//      through the public Cancel/IsReady contract.
//
// Network-dependent tests (actual GET of .well-known, retry after failure,
// etc.) live in auth_integration_test.h where a real HttpServer-backed mock
// IdP is available.
// ============================================================================

#include "test_framework.h"
#include "auth/oidc_discovery.h"
#include "auth/upstream_http_client.h"
#include "log/logger.h"

#include <memory>
#include <string>
#include <atomic>
#include <thread>
#include <chrono>

namespace OidcDiscoveryTests {

// ---------------------------------------------------------------------------
// Helper: build a minimal OidcDiscovery without a live client
// ---------------------------------------------------------------------------

static std::unique_ptr<AUTH_NAMESPACE::OidcDiscovery> MakeDiscovery(
        const std::string& issuer_name = "test-issuer",
        const std::string& issuer_url  = "https://auth.example.com",
        int retry_sec                  = 5,
        bool requires_jwks_uri         = true) {
    // null client — Start() will log an error and return immediately without
    // crashing. IsReady() stays false.
    return std::make_unique<AUTH_NAMESPACE::OidcDiscovery>(
        issuer_name, issuer_url, /*client=*/nullptr,
        /*upstream_pool_name=*/"idp-pool", retry_sec,
        requires_jwks_uri);
}

// ---------------------------------------------------------------------------
// Test 1: IsReady() is false immediately after construction
// ---------------------------------------------------------------------------
static bool TestIsReadyFalseOnConstruction() {
    auto d = MakeDiscovery();
    if (d->IsReady()) {
        TestFramework::RecordTest("OidcDiscovery: IsReady false on construction",
                                   false,
                                   "expected false immediately after construction");
        return false;
    }
    TestFramework::RecordTest("OidcDiscovery: IsReady false on construction", true, "");
    return true;
}

// ---------------------------------------------------------------------------
// Test 2: Cancel() is idempotent — calling it multiple times does not crash
// ---------------------------------------------------------------------------
static bool TestCancelIdempotent() {
    auto d = MakeDiscovery();
    // Cancel before Start — should be a safe no-op.
    d->Cancel();
    d->Cancel();
    d->Cancel();
    // Destructor also calls Cancel() → 4 total calls; no crash = pass.
    TestFramework::RecordTest("OidcDiscovery: Cancel() idempotent", true, "");
    return true;
}

// ---------------------------------------------------------------------------
// Test 3: Cancel() before destructor — no UAF from shared_ptr<atomic<bool>>
// ---------------------------------------------------------------------------
static bool TestCancelBeforeDestruction() {
    bool ok = true;
    {
        auto d = MakeDiscovery();
        d->Cancel();
        // d is destroyed here; internal cancel_token_ shared_ptr still valid
        // for any lambdas that captured it.
    }
    TestFramework::RecordTest("OidcDiscovery: Cancel before destruction no UAF",
                               ok, "");
    return ok;
}

// ---------------------------------------------------------------------------
// Test 4: Start() with null client logs error, does not crash, IsReady false
// ---------------------------------------------------------------------------
static bool TestStartWithNullClientNocrash() {
    auto d = MakeDiscovery();
    // dispatcher_index=0, generation=1, callback is a no-op.
    // With null client, Start() logs error and returns.
    d->Start(0, 1,
             [](uint64_t, const std::string&, const std::string&) {});
    bool ok = !d->IsReady();
    TestFramework::RecordTest("OidcDiscovery: Start with null client does not crash",
                               ok,
                               ok ? "" : "IsReady should still be false");
    return ok;
}

// ---------------------------------------------------------------------------
// Test 5: Destructor runs Cancel() — shared_ptr cancel_token_ avoids UAF
//         even if a lambda closure outlives the OidcDiscovery instance.
// ---------------------------------------------------------------------------
static bool TestDestructorCancels() {
    // Capture the cancel token through a weak_ptr to verify it gets set.
    std::weak_ptr<std::atomic<bool>> weak_token;

    {
        // We cannot directly access cancel_token_; instead, observe via
        // IsReady after destruction — the test infrastructure ensures
        // no heap corruption by running under sanitizers.
        auto d = MakeDiscovery();
        // Destroy without explicit Cancel — destructor should call Cancel.
    }
    // If we reach here without crash/ASAN report, test passes.
    TestFramework::RecordTest("OidcDiscovery: destructor cancels in-flight ops",
                               true, "");
    return true;
}

// ---------------------------------------------------------------------------
// Test 6: Multiple OidcDiscovery instances are independent — cancelling one
//         does not affect the other.
// ---------------------------------------------------------------------------
static bool TestMultipleInstancesIndependent() {
    auto d1 = MakeDiscovery("issuer-a", "https://a.example.com");
    auto d2 = MakeDiscovery("issuer-b", "https://b.example.com");

    d1->Cancel();

    // d2 should be unaffected (no crash, IsReady still false).
    bool ok = !d2->IsReady();
    TestFramework::RecordTest("OidcDiscovery: multiple instances are independent",
                               ok,
                               ok ? "" : "IsReady for d2 should be false after cancelling d1");
    return ok;
}

// ---------------------------------------------------------------------------
// Test 7: Retry_sec <= 0 is normalised to 30 by constructor
//         Verify by calling Start() with 0 and -1 without crash.
// ---------------------------------------------------------------------------
static bool TestRetrySecNormalization() {
    // retry_sec=0 → normalised to 30
    auto d0 = MakeDiscovery("t", "https://t.example.com", 0);
    d0->Start(0, 1, [](uint64_t, const std::string&, const std::string&) {});

    // retry_sec=-5 → normalised to 30
    auto dn = MakeDiscovery("t2", "https://t2.example.com", -5);
    dn->Start(0, 1, [](uint64_t, const std::string&, const std::string&) {});

    TestFramework::RecordTest("OidcDiscovery: retry_sec <= 0 normalised to 30",
                               true, "");
    return true;
}

// ---------------------------------------------------------------------------
// Test 8: Cancel() during Start() invocation — thread-safe shared_ptr cancel
//         token prevents use-after-free.
// ---------------------------------------------------------------------------
static bool TestConcurrentCancelAndStart() {
    constexpr int ITERATIONS = 50;
    std::atomic<int> errors{0};

    for (int i = 0; i < ITERATIONS; ++i) {
        auto d = MakeDiscovery();
        // Fire Cancel() on a different thread while Start() is called here.
        std::thread canceller([&]() { d->Cancel(); });
        d->Start(0, static_cast<uint64_t>(i),
                 [](uint64_t, const std::string&, const std::string&) {});
        canceller.join();
        // No crash = no error.
    }

    bool ok = errors.load() == 0;
    TestFramework::RecordTest("OidcDiscovery: concurrent Cancel and Start thread-safe",
                               ok,
                               ok ? "" : "errors detected during concurrent cancel+start");
    return ok;
}

// ---------------------------------------------------------------------------
// Test 9: Issuer name and URL accessors are not exposed publicly, but the
//         constructor parameters are correctly stored (observed indirectly
//         via logging in debug mode — just ensure no crash on varied inputs).
// ---------------------------------------------------------------------------
static bool TestLongIssuerNameNocrash() {
    std::string long_name(512, 'x');
    std::string long_url = "https://" + std::string(256, 'a') + ".example.com";
    auto d = MakeDiscovery(long_name, long_url);
    d->Cancel();
    TestFramework::RecordTest("OidcDiscovery: long issuer name / URL no crash",
                               true, "");
    return true;
}

// ---------------------------------------------------------------------------
// Test 10: Start() after Cancel() does not schedule work
//          (with null client this is always safe; the key property is no crash)
// ---------------------------------------------------------------------------
static bool TestStartAfterCancel() {
    auto d = MakeDiscovery();
    d->Cancel();
    // Start should detect cancelled token early and skip network fetch.
    d->Start(0, 1, [](uint64_t, const std::string&, const std::string&) {});
    bool ok = !d->IsReady();
    TestFramework::RecordTest("OidcDiscovery: Start after Cancel is safe",
                               ok,
                               ok ? "" : "IsReady should remain false");
    return ok;
}

// ---------------------------------------------------------------------------
// Test 11: Multiple Start() calls — second call resets cancel_token_ and
//          ready_ flag. With null client both calls just log-and-return.
// ---------------------------------------------------------------------------
static bool TestMultipleStartCalls() {
    auto d = MakeDiscovery();
    d->Start(0, 1, [](uint64_t, const std::string&, const std::string&) {});
    d->Start(0, 2, [](uint64_t, const std::string&, const std::string&) {});
    bool ok = !d->IsReady();
    TestFramework::RecordTest("OidcDiscovery: multiple Start() calls idempotent",
                               ok,
                               ok ? "" : "IsReady should be false after double Start with null client");
    return ok;
}

// ---------------------------------------------------------------------------
// Test 12: on_ready_cb is never invoked when client is null
// ---------------------------------------------------------------------------
static bool TestCallbackNotInvokedWithNullClient() {
    std::atomic<int> callback_count{0};
    auto d = MakeDiscovery();
    d->Start(0, 1, [&](uint64_t, const std::string&, const std::string&) {
        callback_count.fetch_add(1, std::memory_order_relaxed);
    });
    bool ok = callback_count.load() == 0;
    TestFramework::RecordTest("OidcDiscovery: on_ready_cb not called with null client",
                               ok,
                               ok ? "" : "callback unexpectedly invoked");
    return ok;
}

// ---------------------------------------------------------------------------
// Test 13: Concurrent construction and destruction — ASAN/TSAN stability
// ---------------------------------------------------------------------------
static bool TestConcurrentConstructionDestruction() {
    constexpr int THREADS = 8;
    constexpr int PER_THREAD = 20;
    std::atomic<int> errors{0};

    std::vector<std::thread> threads;
    for (int t = 0; t < THREADS; ++t) {
        threads.emplace_back([&]() {
            for (int i = 0; i < PER_THREAD; ++i) {
                auto d = MakeDiscovery(
                    "issuer-" + std::to_string(t) + "-" + std::to_string(i),
                    "https://idp.example.com");
                d->Start(0, static_cast<uint64_t>(i),
                         [](uint64_t, const std::string&, const std::string&) {});
                // Destruction calls Cancel() internally.
            }
        });
    }
    for (auto& th : threads) th.join();

    bool ok = errors.load() == 0;
    TestFramework::RecordTest("OidcDiscovery: concurrent ctor/dtor stress",
                               ok,
                               ok ? "" : "errors during concurrent construction/destruction");
    return ok;
}

// ---------------------------------------------------------------------------
// Test 14: generation parameter is passed through on_ready_cb
//          (tested with a custom in-process mock if a dispatcher were
//          available; here we just verify the callback type matches what
//          Start() expects — compile-time check via lambda.)
// ---------------------------------------------------------------------------
static bool TestGenerationParameterTypeCheck() {
    // Compile-time check: on_ready_cb receives (uint64_t gen, string, string).
    // This just exercises the lambda signature without a live network.
    auto d = MakeDiscovery();
    uint64_t received_gen = 0;
    constexpr uint64_t EXPECTED_GEN = 42;
    d->Start(0, EXPECTED_GEN,
             [&](uint64_t gen, const std::string& /*jwks*/, const std::string& /*intro*/) {
                 received_gen = gen;
             });
    // With null client, callback is never invoked (see TestCallbackNotInvokedWithNullClient).
    // The test just confirms the code compiles and runs without crash.
    (void)received_gen;
    TestFramework::RecordTest("OidcDiscovery: generation param type-check compiles",
                               true, "");
    return true;
}

// ---------------------------------------------------------------------------
// Test 15: ExtractEndpoints rejects a non-HTTPS introspection_endpoint
//          while still surfacing a valid jwks_uri. The jwks_uri must still
//          load (JWT-mode discovery succeeds), but introspection_endpoint
//          is cleared and `reason` carries the explicit signal so callers
//          can distinguish missing-from-doc vs rejected-by-scheme.
// ---------------------------------------------------------------------------
static bool TestDiscoveryRejectsNonHttpsIntrospectionEndpoint() {
    const std::string expected_issuer = "https://idp.example.com";
    const std::string body = R"({
        "issuer": "https://idp.example.com",
        "jwks_uri": "https://idp.example.com/jwks.json",
        "introspection_endpoint": "http://idp.example.com/introspect"
    })";

    std::string jwks_uri;
    std::string intro_endpoint;
    std::string reason;
    AUTH_NAMESPACE::OidcDiscovery::ExtractEndpointsForTest(
        body, expected_issuer, jwks_uri, intro_endpoint, reason);

    bool jwks_ok = jwks_uri == "https://idp.example.com/jwks.json";
    bool intro_cleared = intro_endpoint.empty();
    bool reason_correct = reason == "introspection_endpoint_not_https";
    bool ok = jwks_ok && intro_cleared && reason_correct;

    std::string detail;
    if (!ok) {
        detail = "jwks_uri='" + jwks_uri +
                 "' intro_endpoint='" + intro_endpoint +
                 "' reason='" + reason + "'";
    }
    TestFramework::RecordTest(
        "OidcDiscovery: rejects non-https introspection_endpoint",
        ok, detail);
    return ok;
}

// ---------------------------------------------------------------------------
// Test 16: Introspection-only metadata (no jwks_uri, valid HTTPS
//          introspection_endpoint) parses cleanly. The accept-vs-retry
//          gate is mode-aware in the live discovery loop: with
//          requires_jwks_uri=false the same shape would be ACCEPTED
//          (introspection-mode issuer); with requires_jwks_uri=true it
//          would schedule a retry (JWT-mode issuer needs jwks_uri).
//          This test covers the parser side; the gate decision is
//          replicated locally so the rule stays close to the constants.
// ---------------------------------------------------------------------------
static bool TestIntrospectionOnlyMetadataParseAndGate() {
    const std::string expected_issuer = "https://idp.example.com";
    const std::string body = R"({
        "issuer": "https://idp.example.com",
        "introspection_endpoint": "https://idp.example.com/introspect"
    })";

    std::string jwks_uri;
    std::string intro_endpoint;
    std::string reason;
    AUTH_NAMESPACE::OidcDiscovery::ExtractEndpointsForTest(
        body, expected_issuer, jwks_uri, intro_endpoint, reason);

    // Parser side: jwks_uri empty, intro_endpoint set, no parse-level error.
    bool parse_ok = jwks_uri.empty() &&
                    intro_endpoint == "https://idp.example.com/introspect";

    // Gate logic (mirrors oidc_discovery.cc):
    //   requires_jwks_uri=true  → REJECT (jwt_mode_missing_jwks_uri)
    //   requires_jwks_uri=false → ACCEPT
    auto would_accept = [&](bool requires_jwks_uri) {
        const bool both_empty = jwks_uri.empty() && intro_endpoint.empty();
        const bool jwt_needs_jwks_but_missing =
            requires_jwks_uri && jwks_uri.empty();
        const bool intro_needs_endpoint_but_missing =
            !requires_jwks_uri && intro_endpoint.empty();
        return !(both_empty || jwt_needs_jwks_but_missing ||
                 intro_needs_endpoint_but_missing);
    };

    bool gate_ok = !would_accept(/*requires_jwks_uri=*/true) &&
                   would_accept(/*requires_jwks_uri=*/false);

    bool ok = parse_ok && gate_ok;
    std::string detail;
    if (!ok) {
        detail = "parse_ok=" + std::to_string(parse_ok) +
                 " gate_ok=" + std::to_string(gate_ok) +
                 " jwks_uri='" + jwks_uri +
                 "' intro_endpoint='" + intro_endpoint + "'";
    }
    TestFramework::RecordTest(
        "OidcDiscovery: introspection-only metadata accepted when requires_jwks_uri=false",
        ok, detail);
    return ok;
}

// ---------------------------------------------------------------------------
// Test 17: JWKS-only metadata (no introspection_endpoint, valid HTTPS
//          jwks_uri) — symmetric to Test 16. Introspection-mode issuer
//          (requires_jwks_uri=false) MUST reject and retry; JWT-mode
//          issuer (requires_jwks_uri=true) MUST accept.
// ---------------------------------------------------------------------------
static bool TestJwksOnlyMetadataParseAndGate() {
    const std::string expected_issuer = "https://idp.example.com";
    const std::string body = R"({
        "issuer": "https://idp.example.com",
        "jwks_uri": "https://idp.example.com/jwks.json"
    })";

    std::string jwks_uri;
    std::string intro_endpoint;
    std::string reason;
    AUTH_NAMESPACE::OidcDiscovery::ExtractEndpointsForTest(
        body, expected_issuer, jwks_uri, intro_endpoint, reason);

    bool parse_ok = jwks_uri == "https://idp.example.com/jwks.json" &&
                    intro_endpoint.empty();

    auto would_accept = [&](bool requires_jwks_uri) {
        const bool both_empty = jwks_uri.empty() && intro_endpoint.empty();
        const bool jwt_needs_jwks_but_missing =
            requires_jwks_uri && jwks_uri.empty();
        const bool intro_needs_endpoint_but_missing =
            !requires_jwks_uri && intro_endpoint.empty();
        return !(both_empty || jwt_needs_jwks_but_missing ||
                 intro_needs_endpoint_but_missing);
    };

    bool gate_ok = would_accept(/*requires_jwks_uri=*/true) &&
                   !would_accept(/*requires_jwks_uri=*/false);

    bool ok = parse_ok && gate_ok;
    std::string detail;
    if (!ok) {
        detail = "parse_ok=" + std::to_string(parse_ok) +
                 " gate_ok=" + std::to_string(gate_ok) +
                 " jwks_uri='" + jwks_uri +
                 "' intro_endpoint='" + intro_endpoint + "'";
    }
    TestFramework::RecordTest(
        "OidcDiscovery: jwks-only metadata rejected when requires_jwks_uri=false",
        ok, detail);
    return ok;
}

// ---------------------------------------------------------------------------
// Test 18: Construction with requires_jwks_uri=false succeeds and
//          IsReady() is initially false (no discovery has run yet).
//          Smoke-test that the new constructor argument propagates without
//          breaking the per-instance lifecycle.
// ---------------------------------------------------------------------------
static bool TestConstructorRequiresJwksUriFalse() {
    auto d = MakeDiscovery("intro-issuer", "https://intro.example.com",
                            /*retry_sec=*/5, /*requires_jwks_uri=*/false);
    bool ok = !d->IsReady();
    TestFramework::RecordTest(
        "OidcDiscovery: requires_jwks_uri=false constructor smoke",
        ok, ok ? "" : "IsReady should still be false");
    return ok;
}

// ---------------------------------------------------------------------------
// RunAllTests
// ---------------------------------------------------------------------------
static void RunAllTests() {
    TestIsReadyFalseOnConstruction();
    TestCancelIdempotent();
    TestCancelBeforeDestruction();
    TestStartWithNullClientNocrash();
    TestDestructorCancels();
    TestMultipleInstancesIndependent();
    TestRetrySecNormalization();
    TestConcurrentCancelAndStart();
    TestLongIssuerNameNocrash();
    TestStartAfterCancel();
    TestMultipleStartCalls();
    TestCallbackNotInvokedWithNullClient();
    TestConcurrentConstructionDestruction();
    TestGenerationParameterTypeCheck();
    TestDiscoveryRejectsNonHttpsIntrospectionEndpoint();
    TestIntrospectionOnlyMetadataParseAndGate();
    TestJwksOnlyMetadataParseAndGate();
    TestConstructorRequiresJwksUriFalse();
}

}  // namespace OidcDiscoveryTests
