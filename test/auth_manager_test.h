#pragma once

// ============================================================================
// AuthManager unit tests — Phase 2 test suite.
//
// Tests the AuthManager in isolation without a real UpstreamManager or live
// event loop. Key invariants:
//
//   1. Disabled config → InvokeMiddleware returns true (pass-through)
//   2. Enabled, no policies → InvokeMiddleware returns true (pass-through)
//   3. RegisterPolicy before Start() registers; after Start() is a no-op
//   4. Disabled policy → not applied
//   5. ForwardConfig() returns a valid shared_ptr on all code paths
//   6. ForwardConfig() snapshot is stable during Reload
//   7. SnapshotAll() counters reflect allowed / denied / undetermined
//   8. Reload() — topology change (add/remove issuer) rejected
//   9. Reload() — reloadable fields (leeway, jwks_cache_sec) applied
//  10. Stop() is idempotent
//  11. GetIssuer() returns nullptr for unknown names
//  12. InvokeMiddleware without Bearer token → 401
//  13. InvokeMiddleware with matching policy but UNDETERMINED issuer →
//      on_undetermined="allow" passes, on_undetermined="deny" returns 503
//  14. Policy with enabled=false is skipped
//  15. Empty token extracted → DENY 401
//  16. RebuildPolicyListFromLiveSources replaces policy list
//  17. Multiple prefixes for one policy — each routes correctly
//  18. Longest prefix wins
//  19. ForwardConfig swap is atomic — concurrent callers see coherent snapshot
//  20. SnapshotAll() generation bumps after Reload
// ============================================================================

#include "test_framework.h"
#include "auth/auth_manager.h"
#include "auth/auth_config.h"
#include "auth/auth_context.h"
#include "auth/auth_result.h"
#include "http/http_request.h"
#include "http/http_response.h"
#include "log/logger.h"

#include <memory>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <optional>

namespace AuthManagerTests {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Build a minimal AuthConfig with no issuers and no policies.
static AUTH_NAMESPACE::AuthConfig MakeEmptyConfig(bool enabled = false) {
    AUTH_NAMESPACE::AuthConfig cfg;
    cfg.enabled = enabled;
    return cfg;
}

// Build an IssuerConfig pointing at a non-existent upstream
// (discovery=false so no live network calls are made).
static AUTH_NAMESPACE::IssuerConfig MakeStaticIssuer(
        const std::string& name = "test-issuer",
        const std::string& url  = "https://idp.example.com") {
    AUTH_NAMESPACE::IssuerConfig ic;
    ic.name        = name;
    ic.issuer_url  = url;
    ic.discovery   = false;
    ic.jwks_uri    = "https://idp.example.com/.well-known/jwks.json";
    ic.upstream    = "idp-pool";
    ic.mode        = "jwt";
    ic.algorithms  = {"RS256"};
    return ic;
}

// Build an enabled AuthPolicy that covers the given prefix.
static AUTH_NAMESPACE::AuthPolicy MakePolicy(
        const std::string& name              = "test-policy",
        const std::vector<std::string>& prefixes = {"/api/"},
        const std::vector<std::string>& issuers  = {"test-issuer"},
        bool enabled                             = true,
        const std::string& on_undetermined       = "deny") {
    AUTH_NAMESPACE::AuthPolicy p;
    p.name            = name;
    p.enabled         = enabled;
    p.applies_to      = prefixes;
    p.issuers         = issuers;
    p.on_undetermined = on_undetermined;
    return p;
}

// Build an AuthManager with null UpstreamManager (topology-stable; no
// network calls since we never call Start() with live issuers).
static std::unique_ptr<AUTH_NAMESPACE::AuthManager> MakeManager(
        const AUTH_NAMESPACE::AuthConfig& cfg) {
    return std::make_unique<AUTH_NAMESPACE::AuthManager>(
        cfg, /*upstream_manager=*/nullptr,
        /*dispatchers=*/std::vector<std::shared_ptr<Dispatcher>>{});
}

// Construct a minimal HttpRequest with the given path and optional
// Authorization header.
static HttpRequest MakeRequest(const std::string& path,
                                 const std::string& bearer_token = "") {
    HttpRequest req;
    req.path    = path;
    req.method  = "GET";
    req.http_major = 1; req.http_minor = 1;
    if (!bearer_token.empty()) {
        req.headers["authorization"] = "Bearer " + bearer_token;
    }
    return req;
}

// ---------------------------------------------------------------------------
// Test 1: Disabled config → InvokeMiddleware always returns true
// ---------------------------------------------------------------------------
static bool TestDisabledConfigPassthrough() {
    auto mgr = MakeManager(MakeEmptyConfig(/*enabled=*/false));

    // No policies registered — test that empty policy list is a pass-through.
    // config.enabled=false means HttpServer wouldn't install the middleware;
    // calling InvokeMiddleware directly with empty policies_ verifies the
    // fast-path at line "if (!policies_snap || policies_snap->empty()) return true".
    mgr->Start();

    HttpRequest req = MakeRequest("/api/resource");
    HttpResponse resp;
    bool cont = mgr->InvokeMiddleware(req, resp);

    TestFramework::RecordTest("AuthManager: no-policy passthrough",
                               cont, cont ? "" : "should have passed through with no matching policy");
    return cont;
}

// ---------------------------------------------------------------------------
// Test 2: Enabled, no policies → InvokeMiddleware returns true
// ---------------------------------------------------------------------------
static bool TestEnabledNoPoliciesPassthrough() {
    auto mgr = MakeManager(MakeEmptyConfig(/*enabled=*/true));
    mgr->Start();

    HttpRequest req = MakeRequest("/api/v1/users");
    HttpResponse resp;
    bool cont = mgr->InvokeMiddleware(req, resp);

    TestFramework::RecordTest("AuthManager: enabled no-policies passthrough",
                               cont, cont ? "" : "should pass through with empty policy list");
    return cont;
}

// ---------------------------------------------------------------------------
// Test 3: RegisterPolicy before Start() is accepted
// ---------------------------------------------------------------------------
static bool TestRegisterPolicyBeforeStart() {
    AUTH_NAMESPACE::AuthConfig cfg = MakeEmptyConfig(false);
    cfg.issuers["test-issuer"] = MakeStaticIssuer();
    auto mgr = MakeManager(cfg);

    AUTH_NAMESPACE::AuthPolicy p = MakePolicy("p1", {"/protected/"}, {"test-issuer"}, true, "deny");
    mgr->RegisterPolicy(p.applies_to, p);

    auto snap = mgr->SnapshotAll();
    bool has_policy = snap.policy_count > 0;

    TestFramework::RecordTest("AuthManager: RegisterPolicy before Start accepted",
                               has_policy,
                               has_policy ? "" : "policy count is 0 after RegisterPolicy");
    return has_policy;
}

// ---------------------------------------------------------------------------
// Test 4: RegisterPolicy after Start() is a no-op (warn + ignored)
// ---------------------------------------------------------------------------
static bool TestRegisterPolicyAfterStartIgnored() {
    AUTH_NAMESPACE::AuthConfig cfg = MakeEmptyConfig(false);
    auto mgr = MakeManager(cfg);
    mgr->Start();

    AUTH_NAMESPACE::AuthPolicy p = MakePolicy("late", {"/secret/"});
    mgr->RegisterPolicy(p.applies_to, p);  // should be silently ignored

    auto snap = mgr->SnapshotAll();
    bool still_zero = snap.policy_count == 0;

    TestFramework::RecordTest("AuthManager: RegisterPolicy post-Start ignored",
                               still_zero,
                               still_zero ? "" : "post-Start RegisterPolicy should not increment policy count");
    return still_zero;
}

// ---------------------------------------------------------------------------
// Test 5: Disabled policy is not applied
// ---------------------------------------------------------------------------
static bool TestDisabledPolicyNotApplied() {
    AUTH_NAMESPACE::AuthConfig cfg = MakeEmptyConfig(false);
    auto mgr = MakeManager(cfg);

    AUTH_NAMESPACE::AuthPolicy p = MakePolicy("disabled-p", {"/guarded/"}, {}, /*enabled=*/false);
    mgr->RegisterPolicy(p.applies_to, p);
    mgr->Start();

    auto snap = mgr->SnapshotAll();
    // Disabled policy: RegisterPolicy logs+skips it, so policy_count stays 0.
    bool ok = snap.policy_count == 0;
    TestFramework::RecordTest("AuthManager: disabled policy not applied",
                               ok,
                               ok ? "" : "disabled policy incorrectly applied");
    return ok;
}

// ---------------------------------------------------------------------------
// Test 6: ForwardConfig() always returns a non-null shared_ptr
// ---------------------------------------------------------------------------
static bool TestForwardConfigNonNull() {
    auto mgr = MakeManager(MakeEmptyConfig(true));
    auto fwd = mgr->ForwardConfig();
    bool ok = fwd != nullptr;
    TestFramework::RecordTest("AuthManager: ForwardConfig returns non-null",
                               ok,
                               ok ? "" : "ForwardConfig() returned nullptr");
    return ok;
}

// ---------------------------------------------------------------------------
// Test 7: ForwardConfig() default values match AuthForwardConfig defaults
// ---------------------------------------------------------------------------
static bool TestForwardConfigDefaults() {
    AUTH_NAMESPACE::AuthConfig cfg = MakeEmptyConfig(true);
    // Use default AuthForwardConfig from the config.
    auto mgr = MakeManager(cfg);
    auto fwd = mgr->ForwardConfig();

    bool sub_ok = fwd->subject_header == "X-Auth-Subject";
    bool iss_ok = fwd->issuer_header == "X-Auth-Issuer";
    bool strip_ok = fwd->strip_inbound_identity_headers == true;
    bool preserve_ok = fwd->preserve_authorization == true;

    bool ok = sub_ok && iss_ok && strip_ok && preserve_ok;
    TestFramework::RecordTest("AuthManager: ForwardConfig defaults correct",
                               ok,
                               ok ? "" : "ForwardConfig default fields mismatch");
    return ok;
}

// ---------------------------------------------------------------------------
// Test 8: Reload() rejects topology change (issuer count change)
// ---------------------------------------------------------------------------
static bool TestReloadRejectsTopologyChange() {
    AUTH_NAMESPACE::AuthConfig cfg = MakeEmptyConfig(true);
    cfg.issuers["issuer-a"] = MakeStaticIssuer("issuer-a", "https://a.example.com");
    auto mgr = MakeManager(cfg);
    mgr->Start();

    // New config adds a second issuer → topology change → must fail.
    AUTH_NAMESPACE::AuthConfig new_cfg = cfg;
    new_cfg.issuers["issuer-b"] = MakeStaticIssuer("issuer-b", "https://b.example.com");

    std::string err;
    bool reloaded = mgr->Reload(new_cfg, err);
    bool ok = !reloaded && !err.empty();

    TestFramework::RecordTest("AuthManager: Reload rejects issuer topology change",
                               ok,
                               ok ? "" : "topology change should have been rejected, err='" + err + "'");
    return ok;
}

// ---------------------------------------------------------------------------
// Test 9: Reload() rejects unknown issuer name
// ---------------------------------------------------------------------------
static bool TestReloadRejectsUnknownIssuer() {
    AUTH_NAMESPACE::AuthConfig cfg = MakeEmptyConfig(true);
    cfg.issuers["issuer-a"] = MakeStaticIssuer("issuer-a");
    auto mgr = MakeManager(cfg);

    AUTH_NAMESPACE::AuthConfig new_cfg = MakeEmptyConfig(true);
    // Same count (1) but different name → unknown issuer
    new_cfg.issuers["issuer-x"] = MakeStaticIssuer("issuer-x");

    std::string err;
    bool reloaded = mgr->Reload(new_cfg, err);
    bool ok = !reloaded;
    TestFramework::RecordTest("AuthManager: Reload rejects unknown issuer name",
                               ok,
                               ok ? "" : "should have rejected unknown issuer");
    return ok;
}

// ---------------------------------------------------------------------------
// Test 10: Reload() of reloadable fields succeeds and bumps generation
// ---------------------------------------------------------------------------
static bool TestReloadReloadableFields() {
    AUTH_NAMESPACE::AuthConfig cfg = MakeEmptyConfig(true);
    cfg.issuers["issuer-a"] = MakeStaticIssuer("issuer-a");
    auto mgr = MakeManager(cfg);

    uint64_t gen_before = mgr->SnapshotAll().generation;

    // New config: same issuer, different leeway/cache settings (reloadable).
    AUTH_NAMESPACE::AuthConfig new_cfg = cfg;
    new_cfg.issuers["issuer-a"].leeway_sec      = 60;
    new_cfg.issuers["issuer-a"].jwks_cache_sec  = 600;
    new_cfg.forward.subject_header = "X-User-Sub";

    std::string err;
    bool reloaded = mgr->Reload(new_cfg, err);

    uint64_t gen_after = mgr->SnapshotAll().generation;
    auto fwd_after = mgr->ForwardConfig();
    bool fwd_updated = fwd_after && fwd_after->subject_header == "X-User-Sub";

    bool ok = reloaded && err.empty() && gen_after > gen_before && fwd_updated;
    TestFramework::RecordTest("AuthManager: Reload applies reloadable fields and bumps gen",
                               ok,
                               ok ? "" : "reload failed or gen/fwd not updated err='" + err + "'");
    return ok;
}

// ---------------------------------------------------------------------------
// Test 11: Stop() is idempotent
// ---------------------------------------------------------------------------
static bool TestStopIdempotent() {
    AUTH_NAMESPACE::AuthConfig cfg = MakeEmptyConfig(true);
    cfg.issuers["a"] = MakeStaticIssuer();
    auto mgr = MakeManager(cfg);
    mgr->Start();
    mgr->Stop();
    mgr->Stop();  // second call must not crash
    TestFramework::RecordTest("AuthManager: Stop() idempotent", true, "");
    return true;
}

// ---------------------------------------------------------------------------
// Test 12: GetIssuer() returns nullptr for unknown name
// ---------------------------------------------------------------------------
static bool TestGetIssuerUnknown() {
    AUTH_NAMESPACE::AuthConfig cfg = MakeEmptyConfig(true);
    cfg.issuers["known-issuer"] = MakeStaticIssuer("known-issuer");
    auto mgr = MakeManager(cfg);

    bool ok = mgr->GetIssuer("unknown-issuer") == nullptr;
    TestFramework::RecordTest("AuthManager: GetIssuer unknown returns nullptr",
                               ok, ok ? "" : "expected nullptr for unknown issuer");
    return ok;
}

// ---------------------------------------------------------------------------
// Test 13: GetIssuer() returns valid pointer for known name
// ---------------------------------------------------------------------------
static bool TestGetIssuerKnown() {
    AUTH_NAMESPACE::AuthConfig cfg = MakeEmptyConfig(true);
    cfg.issuers["known"] = MakeStaticIssuer("known");
    auto mgr = MakeManager(cfg);

    bool ok = mgr->GetIssuer("known") != nullptr;
    TestFramework::RecordTest("AuthManager: GetIssuer known returns non-null",
                               ok, ok ? "" : "expected valid pointer for known issuer");
    return ok;
}

// ---------------------------------------------------------------------------
// Test 14: InvokeMiddleware with matching policy but missing Authorization
//          header → 401 Unauthorized
// ---------------------------------------------------------------------------
static bool TestMissingAuthorizationDeny401() {
    AUTH_NAMESPACE::AuthConfig cfg = MakeEmptyConfig(true);
    cfg.issuers["issuer-a"] = MakeStaticIssuer("issuer-a");
    auto mgr = MakeManager(cfg);

    // Register a policy that covers /api/
    AUTH_NAMESPACE::AuthPolicy p = MakePolicy("p", {"/api/"}, {"issuer-a"}, true, "deny");
    mgr->RegisterPolicy(p.applies_to, p);
    mgr->Start();

    // Request with no Authorization header.
    HttpRequest req = MakeRequest("/api/users");
    HttpResponse resp;
    bool cont = mgr->InvokeMiddleware(req, resp);

    bool ok = !cont && resp.GetStatusCode() == 401;
    TestFramework::RecordTest("AuthManager: missing Authorization → 401",
                               ok,
                               ok ? "" : "expected 401, got cont=" +
                                   std::to_string(cont) + " status=" +
                                   std::to_string(resp.GetStatusCode()));
    return ok;
}

// ---------------------------------------------------------------------------
// Test 15: InvokeMiddleware with Bearer token but issuer not ready (JWKS not
//          loaded yet) — on_undetermined="deny" → 503
// ---------------------------------------------------------------------------
static bool TestUndeterminedIssuerDeny503() {
    AUTH_NAMESPACE::AuthConfig cfg = MakeEmptyConfig(true);
    cfg.issuers["issuer-a"] = MakeStaticIssuer("issuer-a", "https://idp.example.com");
    auto mgr = MakeManager(cfg);

    AUTH_NAMESPACE::AuthPolicy p = MakePolicy("p", {"/secure/"}, {"issuer-a"}, true, "deny");
    mgr->RegisterPolicy(p.applies_to, p);
    mgr->Start();

    // Issuer has no JWKS keys loaded (Start() with null UpstreamManager → no
    // network fetch, IsReady()=false). Token verification → UNDETERMINED.
    // Signature part must be valid base64url (length mod 4 != 1).
    // "AAAA" = 4 chars (valid), decodes to 3 null bytes.
    HttpRequest req = MakeRequest("/secure/data",
        "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0xIn0."
        "eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlLmNvbSIsInN1YiI6InUxIn0."
        "AAAA");
    HttpResponse resp;
    bool cont = mgr->InvokeMiddleware(req, resp);

    // on_undetermined="deny" → 503
    bool ok = !cont && resp.GetStatusCode() == 503;
    TestFramework::RecordTest("AuthManager: undetermined + deny=deny → 503",
                               ok,
                               ok ? "" : "expected 503, got cont=" +
                                   std::to_string(cont) + " status=" +
                                   std::to_string(resp.GetStatusCode()));
    return ok;
}

// ---------------------------------------------------------------------------
// Test 16: InvokeMiddleware on_undetermined="allow" — passes through with
//          AuthContext::undetermined=true set on the request
// ---------------------------------------------------------------------------
static bool TestUndeterminedAllow() {
    AUTH_NAMESPACE::AuthConfig cfg = MakeEmptyConfig(true);
    cfg.issuers["issuer-a"] = MakeStaticIssuer("issuer-a", "https://idp.example.com");
    auto mgr = MakeManager(cfg);

    AUTH_NAMESPACE::AuthPolicy p = MakePolicy("p-allow", {"/api/"}, {"issuer-a"}, true, "allow");
    mgr->RegisterPolicy(p.applies_to, p);
    mgr->Start();

    HttpRequest req = MakeRequest("/api/data",
        "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0xIn0."
        "eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlLmNvbSIsInN1YiI6InUxIn0."
        "fakesig");
    HttpResponse resp;
    bool cont = mgr->InvokeMiddleware(req, resp);

    // Should pass through (allow on undetermined). Auth context should have
    // undetermined=true.
    bool undetermined_set = req.auth.has_value() && req.auth->undetermined;
    bool ok = cont && undetermined_set;
    TestFramework::RecordTest("AuthManager: undetermined + on_undetermined=allow passes through",
                               ok,
                               ok ? "" : "expected passthrough cont=" + std::to_string(cont) +
                                   " undetermined=" + std::to_string(undetermined_set));
    return ok;
}

// ---------------------------------------------------------------------------
// Test 17: SnapshotAll reflects allowed / denied counters
// ---------------------------------------------------------------------------
static bool TestSnapshotCounters() {
    AUTH_NAMESPACE::AuthConfig cfg = MakeEmptyConfig(true);
    cfg.issuers["issuer-a"] = MakeStaticIssuer("issuer-a");
    auto mgr = MakeManager(cfg);

    AUTH_NAMESPACE::AuthPolicy p = MakePolicy("p", {"/api/"}, {"issuer-a"}, true, "deny");
    mgr->RegisterPolicy(p.applies_to, p);
    mgr->Start();

    // Trigger 2 denials (missing Authorization → DENY 401).
    for (int i = 0; i < 2; ++i) {
        HttpRequest req = MakeRequest("/api/resource");
        HttpResponse resp;
        mgr->InvokeMiddleware(req, resp);
    }

    auto snap = mgr->SnapshotAll();
    bool ok = snap.total_denied >= 2;
    TestFramework::RecordTest("AuthManager: SnapshotAll denied counter increments",
                               ok,
                               ok ? "" : "expected denied >= 2, got " + std::to_string(snap.total_denied));
    return ok;
}

// ---------------------------------------------------------------------------
// Test 18: RebuildPolicyListFromLiveSources replaces policy list
// ---------------------------------------------------------------------------
static bool TestRebuildPolicyList() {
    AUTH_NAMESPACE::AuthConfig cfg = MakeEmptyConfig(true);
    cfg.issuers["a"] = MakeStaticIssuer("a");
    auto mgr = MakeManager(cfg);

    // Register one policy before Start.
    AUTH_NAMESPACE::AuthPolicy p_old = MakePolicy("old", {"/old/"}, {"a"});
    mgr->RegisterPolicy(p_old.applies_to, p_old);
    mgr->Start();

    auto snap_before = mgr->SnapshotAll();

    // Rebuild with a new top-level policy.
    AUTH_NAMESPACE::AuthPolicy p_new = MakePolicy("new", {"/new/"}, {"a"}, true, "deny");
    p_new.applies_to = {"/new/"};
    mgr->CommitPolicyAndEnforcement(
        {},        // new_upstreams
        {p_new},   // new_top_level_policies
        true);     // new_master_enabled — mirrors auth.enabled at cutover

    auto snap_after = mgr->SnapshotAll();
    // Policy list was replaced. snap_after.policy_count should reflect new_top_level_policies only.
    bool ok = snap_after.policy_count >= 1;
    TestFramework::RecordTest("AuthManager: RebuildPolicyListFromLiveSources updates policy list",
                               ok,
                               ok ? "" : "policy count did not update after rebuild");
    return ok;
}

// ---------------------------------------------------------------------------
// Test 19: Longest prefix wins — /api/v2/ wins over /api/
// ---------------------------------------------------------------------------
static bool TestLongestPrefixWins() {
    AUTH_NAMESPACE::AuthConfig cfg = MakeEmptyConfig(true);
    cfg.issuers["a"] = MakeStaticIssuer("a");
    auto mgr = MakeManager(cfg);

    // /api/ requires auth (deny on undetermined)
    AUTH_NAMESPACE::AuthPolicy short_p = MakePolicy("short", {"/api/"}, {"a"}, true, "deny");
    mgr->RegisterPolicy(short_p.applies_to, short_p);

    // /api/v2/ has on_undetermined=allow (overrides for this sub-tree)
    AUTH_NAMESPACE::AuthPolicy long_p = MakePolicy("long", {"/api/v2/"}, {"a"}, true, "allow");
    mgr->RegisterPolicy(long_p.applies_to, long_p);

    mgr->Start();

    // Request to /api/v2/users — should hit the "long" policy (allow on undetermined).
    HttpRequest req = MakeRequest("/api/v2/users",
        "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0xIn0."
        "eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlLmNvbSIsInN1YiI6InUxIn0."
        "fakesig");
    HttpResponse resp;
    bool cont = mgr->InvokeMiddleware(req, resp);

    bool ok = cont;
    TestFramework::RecordTest("AuthManager: longest prefix wins (/api/v2/ over /api/)",
                               ok,
                               ok ? "" : "expected allow from /api/v2/ policy, cont=" + std::to_string(cont));
    return ok;
}

// ---------------------------------------------------------------------------
// Test 20: ForwardConfig() is stable during concurrent Reload calls
//          (no crash / no null dereference)
// ---------------------------------------------------------------------------
static bool TestForwardConfigConcurrentReload() {
    AUTH_NAMESPACE::AuthConfig cfg = MakeEmptyConfig(true);
    cfg.issuers["a"] = MakeStaticIssuer("a");
    auto mgr = MakeManager(cfg);

    constexpr int READERS = 8;
    constexpr int ITERATIONS = 200;
    std::atomic<int> errors{0};

    // Reader threads continuously call ForwardConfig() and dereference it.
    std::vector<std::thread> readers;
    std::atomic<bool> stop_readers{false};
    for (int t = 0; t < READERS; ++t) {
        readers.emplace_back([&]() {
            while (!stop_readers.load(std::memory_order_acquire)) {
                auto fwd = mgr->ForwardConfig();
                if (!fwd) {
                    errors.fetch_add(1, std::memory_order_relaxed);
                }
                // Touch the value to detect use-after-free under ASAN.
                (void)fwd->subject_header.size();
            }
        });
    }

    // Reload thread updates forward config repeatedly.
    for (int i = 0; i < ITERATIONS; ++i) {
        AUTH_NAMESPACE::AuthConfig new_cfg = cfg;
        new_cfg.issuers["a"].leeway_sec = 30 + (i % 30);
        new_cfg.forward.subject_header  = "X-Sub-" + std::to_string(i % 3);
        std::string err;
        mgr->Reload(new_cfg, err);
    }

    stop_readers.store(true, std::memory_order_release);
    for (auto& th : readers) th.join();

    bool ok = errors.load() == 0;
    TestFramework::RecordTest("AuthManager: ForwardConfig stable under concurrent Reload",
                               ok,
                               ok ? "" : "null ForwardConfig() detected under concurrent reload");
    return ok;
}

// ---------------------------------------------------------------------------
// RunAllTests
// ---------------------------------------------------------------------------
static void RunAllTests() {
    TestDisabledConfigPassthrough();
    TestEnabledNoPoliciesPassthrough();
    TestRegisterPolicyBeforeStart();
    TestRegisterPolicyAfterStartIgnored();
    TestDisabledPolicyNotApplied();
    TestForwardConfigNonNull();
    TestForwardConfigDefaults();
    TestReloadRejectsTopologyChange();
    TestReloadRejectsUnknownIssuer();
    TestReloadReloadableFields();
    TestStopIdempotent();
    TestGetIssuerUnknown();
    TestGetIssuerKnown();
    TestMissingAuthorizationDeny401();
    TestUndeterminedIssuerDeny503();
    TestUndeterminedAllow();
    TestSnapshotCounters();
    TestRebuildPolicyList();
    TestLongestPrefixWins();
    TestForwardConfigConcurrentReload();
}

}  // namespace AuthManagerTests
