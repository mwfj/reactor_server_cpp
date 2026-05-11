#pragma once

// ============================================================================
// Auth observability tests — debug-response-headers flag, per-policy counters,
// and widened SnapshotView fields.
//
// All tests run in process with no live network (null UpstreamManager, no Dispatcher).
//
// Test organisation:
//   Tier A (A1–A5): debug-response-headers emission on the sync JWT path.
//   Tier B (B1–B4): per-(issuer, policy) counter bucketing and reconciliation.
//   Tier C (C1–C3): SnapshotView struct shape (new fields present + correct).
//   Tier D (D1)   : concurrent BumpPerPolicy under 8 threads (TSan target).
// ============================================================================

#include "test_framework.h"
#include "auth/auth_manager.h"
#include "auth/auth_config.h"
#include "auth/auth_context.h"
#include "auth/auth_result.h"
#include "auth/issuer.h"
#include "http/http_request.h"
#include "http/http_response.h"
#include "http/http_router.h"
#include "log/logger.h"

#include "common.h"

namespace AuthObservabilityTests {

// ---------------------------------------------------------------------------
// Private helpers (mirror auth_manager_test.h style)
// ---------------------------------------------------------------------------

static AUTH_NAMESPACE::AuthConfig MakeEmptyConfig(bool enabled = false,
                                                   bool debug_headers = false) {
    AUTH_NAMESPACE::AuthConfig cfg;
    cfg.enabled = enabled;
    cfg.debug_response_headers = debug_headers;
    return cfg;
}

static AUTH_NAMESPACE::IssuerConfig MakeStaticIssuer(
        const std::string& name = "test-issuer",
        const std::string& url  = "https://idp.example.com") {
    AUTH_NAMESPACE::IssuerConfig ic;
    ic.name       = name;
    ic.issuer_url = url;
    ic.discovery  = false;
    ic.jwks_uri   = "https://idp.example.com/.well-known/jwks.json";
    ic.upstream   = "idp-pool";
    ic.mode       = "jwt";
    ic.algorithms = {"RS256"};
    return ic;
}

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

static std::unique_ptr<AUTH_NAMESPACE::AuthManager> MakeManager(
        const AUTH_NAMESPACE::AuthConfig& cfg) {
    return std::make_unique<AUTH_NAMESPACE::AuthManager>(
        cfg, /*upstream_manager=*/nullptr,
        /*dispatchers=*/std::vector<std::shared_ptr<Dispatcher>>{});
}

static HttpRequest MakeRequest(const std::string& path,
                                const std::string& bearer_token = "") {
    HttpRequest req;
    req.path       = path;
    req.method     = "GET";
    req.http_major = 1;
    req.http_minor = 1;
    if (!bearer_token.empty()) {
        req.headers["authorization"] = "Bearer " + bearer_token;
    }
    return req;
}

// Case-insensitive header lookup in HttpResponse (GetHeaders returns pairs).
static std::string FindHeader(const HttpResponse& resp, const std::string& name) {
    for (const auto& kv : resp.GetHeaders()) {
        std::string key = kv.first;
        std::transform(key.begin(), key.end(), key.begin(), ::tolower);
        std::string target = name;
        std::transform(target.begin(), target.end(), target.begin(), ::tolower);
        if (key == target) return kv.second;
    }
    return {};
}

// CommitPolicyAndEnforcement wrapper that mirrors the production caller's
// pattern (HttpServer::Reload): runs after AuthManager::Reload has applied
// issuer snapshots.
static void DoCommit(AUTH_NAMESPACE::AuthManager& mgr,
                     const std::vector<AUTH_NAMESPACE::AuthPolicy>& policies,
                     bool master_enabled,
                     bool debug_headers) {
    AUTH_NAMESPACE::AuthForwardConfig fwd;
    mgr.CommitPolicyAndEnforcement(
        /*new_upstreams=*/{},
        /*new_top_level_policies=*/policies,
        /*new_forward=*/fwd,
        /*new_master_enabled=*/master_enabled,
        /*new_debug_response_headers=*/debug_headers);
}

// ---------------------------------------------------------------------------
// Tier A — debug response headers (sync JWT path, fixtures-only, no network)
// ---------------------------------------------------------------------------

// A1: debug_response_headers=false (default) — no debug headers emitted.
static bool TestDebugHeadersOff_NoEmission() {
    AUTH_NAMESPACE::AuthConfig cfg = MakeEmptyConfig(/*enabled=*/true, /*debug_headers=*/false);
    cfg.issuers["test-issuer"] = MakeStaticIssuer();
    auto mgr = MakeManager(cfg);
    AUTH_NAMESPACE::AuthPolicy p = MakePolicy("P", {"/api/x/"}, {"test-issuer"}, true, "deny");
    mgr->RegisterPolicy(p.applies_to, p);
    mgr->Start();

    // Missing-bearer request → 401 DENY.
    HttpRequest req = MakeRequest("/api/x/resource");
    HttpResponse resp;
    bool cont = mgr->InvokeMiddleware(req, resp);

    bool no_decision = FindHeader(resp, "X-Auth-Decision").empty();
    bool no_issuer   = FindHeader(resp, "X-Auth-Issuer").empty();
    bool no_cache    = FindHeader(resp, "X-Auth-Cache").empty();
    bool status_ok   = resp.GetStatusCode() == 401;

    bool ok = !cont && status_ok && no_decision && no_issuer && no_cache;
    TestFramework::RecordTest(
        "AuthObservability: debug off — no debug headers emitted",
        ok,
        ok ? "" :
            "cont=" + std::to_string(cont) +
            " status=" + std::to_string(resp.GetStatusCode()) +
            " decision='" + FindHeader(resp, "X-Auth-Decision") + "'"
            " issuer='"   + FindHeader(resp, "X-Auth-Issuer") + "'"
            " cache='"    + FindHeader(resp, "X-Auth-Cache") + "'");
    return ok;
}

// A2: debug_response_headers=true + missing-bearer → X-Auth-Decision: deny
// emitted, X-Auth-Issuer omitted (no issuer matched), X-Auth-Cache omitted.
static bool TestDebugHeadersOn_PreIssuerDeny_NoIssuerHeader() {
    AUTH_NAMESPACE::AuthConfig cfg = MakeEmptyConfig(/*enabled=*/true, /*debug_headers=*/false);
    cfg.issuers["test-issuer"] = MakeStaticIssuer();
    auto mgr = MakeManager(cfg);
    AUTH_NAMESPACE::AuthPolicy p = MakePolicy("P", {"/api/"}, {"test-issuer"}, true, "deny");
    mgr->RegisterPolicy(p.applies_to, p);
    mgr->Start();

    // Enable debug via live reload cutover.
    DoCommit(*mgr, {p}, /*master_enabled=*/true, /*debug_headers=*/true);

    HttpRequest req = MakeRequest("/api/resource");
    HttpResponse resp;
    bool cont = mgr->InvokeMiddleware(req, resp);

    std::string decision = FindHeader(resp, "X-Auth-Decision");
    std::string issuer   = FindHeader(resp, "X-Auth-Issuer");
    std::string cache    = FindHeader(resp, "X-Auth-Cache");

    // Pre-issuer deny: decision=deny, no issuer header, no cache header.
    bool ok = !cont
           && resp.GetStatusCode() == 401
           && decision == "deny"
           && issuer.empty()
           && cache.empty();
    TestFramework::RecordTest(
        "AuthObservability: debug on — pre-issuer deny stamps decision, no issuer/cache headers",
        ok,
        ok ? "" :
            "cont=" + std::to_string(cont) +
            " status=" + std::to_string(resp.GetStatusCode()) +
            " decision='" + decision + "'"
            " issuer='"   + issuer + "'"
            " cache='"    + cache + "'");
    return ok;
}

// A3: debug=true + oversized token → X-Auth-Decision: deny, no issuer, no cache.
static bool TestDebugHeadersOn_TokenTooLargeDeny() {
    AUTH_NAMESPACE::AuthConfig cfg = MakeEmptyConfig(/*enabled=*/true, /*debug_headers=*/false);
    cfg.issuers["test-issuer"] = MakeStaticIssuer();
    auto mgr = MakeManager(cfg);
    AUTH_NAMESPACE::AuthPolicy p = MakePolicy("P", {"/api/"}, {"test-issuer"}, true, "deny");
    mgr->RegisterPolicy(p.applies_to, p);
    mgr->Start();
    DoCommit(*mgr, {p}, /*master_enabled=*/true, /*debug_headers=*/true);

    // Build a 9000-char token (cap is 8192).
    std::string oversized(9000, 'a');
    HttpRequest req = MakeRequest("/api/resource", oversized);
    HttpResponse resp;
    bool cont = mgr->InvokeMiddleware(req, resp);

    std::string decision = FindHeader(resp, "X-Auth-Decision");
    std::string issuer   = FindHeader(resp, "X-Auth-Issuer");
    std::string cache    = FindHeader(resp, "X-Auth-Cache");

    bool ok = !cont
           && resp.GetStatusCode() == 401
           && decision == "deny"
           && issuer.empty()
           && cache.empty();
    TestFramework::RecordTest(
        "AuthObservability: debug on — oversized token stamps deny, no issuer/cache",
        ok,
        ok ? "" :
            "cont=" + std::to_string(cont) +
            " status=" + std::to_string(resp.GetStatusCode()) +
            " decision='" + decision + "'"
            " issuer='"   + issuer + "'");
    return ok;
}

// A4: hot-reload flip — debug off → on → off, verify emission follows.
static bool TestDebugHeadersHotReloadFlip() {
    AUTH_NAMESPACE::AuthConfig cfg = MakeEmptyConfig(/*enabled=*/true, /*debug_headers=*/false);
    cfg.issuers["test-issuer"] = MakeStaticIssuer();
    auto mgr = MakeManager(cfg);
    AUTH_NAMESPACE::AuthPolicy p = MakePolicy("P", {"/api/"}, {"test-issuer"}, true, "deny");
    mgr->RegisterPolicy(p.applies_to, p);
    mgr->Start();

    // Round 1: debug=false → no debug headers.
    {
        HttpRequest req = MakeRequest("/api/resource");
        HttpResponse resp;
        mgr->InvokeMiddleware(req, resp);
        if (!FindHeader(resp, "X-Auth-Decision").empty()) {
            TestFramework::RecordTest(
                "AuthObservability: hot-reload flip — debug headers not present before enable",
                false, "unexpected X-Auth-Decision before debug flag enabled");
            return false;
        }
    }

    // Round 2: debug=true → decision header present.
    DoCommit(*mgr, {p}, /*master_enabled=*/true, /*debug_headers=*/true);
    {
        HttpRequest req = MakeRequest("/api/resource");
        HttpResponse resp;
        mgr->InvokeMiddleware(req, resp);
        if (FindHeader(resp, "X-Auth-Decision").empty()) {
            TestFramework::RecordTest(
                "AuthObservability: hot-reload flip — debug headers present after enable",
                false, "X-Auth-Decision missing after enabling debug headers");
            return false;
        }
    }

    // Round 3: debug=false → decision header gone again.
    DoCommit(*mgr, {p}, /*master_enabled=*/true, /*debug_headers=*/false);
    {
        HttpRequest req = MakeRequest("/api/resource");
        HttpResponse resp;
        mgr->InvokeMiddleware(req, resp);
        if (!FindHeader(resp, "X-Auth-Decision").empty()) {
            TestFramework::RecordTest(
                "AuthObservability: hot-reload flip — debug headers absent after disable",
                false, "unexpected X-Auth-Decision after disabling debug headers");
            return false;
        }
    }

    TestFramework::RecordTest(
        "AuthObservability: hot-reload flip — debug flag follows live reload",
        true, "");
    return true;
}

// A5: debug=true + issuer matched but UNDETERMINED (JWKS not loaded) +
//     on_undetermined=deny → X-Auth-Decision: undetermined, X-Auth-Issuer set.
static bool TestDebugHeadersUndeterminedHasIssuerName() {
    AUTH_NAMESPACE::AuthConfig cfg = MakeEmptyConfig(/*enabled=*/true, /*debug_headers=*/false);
    cfg.issuers["test-issuer"] = MakeStaticIssuer("test-issuer", "https://idp.example.com");
    auto mgr = MakeManager(cfg);
    AUTH_NAMESPACE::AuthPolicy p = MakePolicy("P", {"/secure/"}, {"test-issuer"}, true, "deny");
    mgr->RegisterPolicy(p.applies_to, p);
    mgr->Start();
    DoCommit(*mgr, {p}, /*master_enabled=*/true, /*debug_headers=*/true);

    // A JWT-format token whose iss matches the configured issuer URL.
    // Issuer is NOT ready (no JWKS) so verification returns UNDETERMINED.
    // The token must be valid base64url in all three parts.
    HttpRequest req = MakeRequest("/secure/data",
        "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0xIn0."
        "eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlLmNvbSIsInN1YiI6InUxIiwiZXhwIjo5OTk5OTk5OTk5fQ."
        "AAAA");
    HttpResponse resp;
    bool cont = mgr->InvokeMiddleware(req, resp);

    std::string decision = FindHeader(resp, "X-Auth-Decision");
    std::string issuer   = FindHeader(resp, "X-Auth-Issuer");
    std::string cache    = FindHeader(resp, "X-Auth-Cache");

    // on_undetermined=deny + UNDETERMINED → 503.
    // decision=undetermined, issuer=test-issuer (was matched), no cache (JWT mode).
    bool ok = !cont
           && resp.GetStatusCode() == 503
           && decision == "undetermined"
           && !issuer.empty()
           && cache.empty();
    TestFramework::RecordTest(
        "AuthObservability: debug on — UNDETERMINED stamps issuer header, no cache header",
        ok,
        ok ? "" :
            "cont=" + std::to_string(cont) +
            " status=" + std::to_string(resp.GetStatusCode()) +
            " decision='" + decision + "'"
            " issuer='"   + issuer + "'"
            " cache='"    + cache + "'");
    return ok;
}

// ---------------------------------------------------------------------------
// Tier B — per-policy counter bucketing
// ---------------------------------------------------------------------------

// Helper: find a PerPolicyCountersView in the snapshot by (issuer, policy).
static const AUTH_NAMESPACE::AuthManager::PerPolicyCountersView*
FindBucket(const AUTH_NAMESPACE::AuthManager::SnapshotView& snap,
           const std::string& issuer,
           const std::string& policy) {
    for (const auto& pp : snap.per_policy) {
        if (pp.issuer == issuer && pp.policy == policy) return &pp;
    }
    return nullptr;
}

// B1: Missing-bearer → per-policy counter bucket (issuer="", policy="P") increments.
static bool TestPerPolicyCounter_AllowDenyUndetermined() {
    AUTH_NAMESPACE::AuthConfig cfg = MakeEmptyConfig(/*enabled=*/true);
    cfg.issuers["test-issuer"] = MakeStaticIssuer();
    auto mgr = MakeManager(cfg);
    AUTH_NAMESPACE::AuthPolicy p = MakePolicy("P", {"/api/"}, {"test-issuer"}, true, "deny");
    mgr->RegisterPolicy(p.applies_to, p);
    mgr->Start();

    // Drive 3 missing-bearer requests — each should hit (issuer="", policy="P").
    for (int i = 0; i < 3; ++i) {
        HttpRequest req = MakeRequest("/api/resource");
        HttpResponse resp;
        mgr->InvokeMiddleware(req, resp);
    }

    auto snap = mgr->SnapshotAll();
    const auto* bucket = FindBucket(snap, "", "P");

    bool bucket_found = bucket != nullptr;
    bool denied_ok    = bucket_found && bucket->denied >= 3;

    bool ok = bucket_found && denied_ok;
    TestFramework::RecordTest(
        "AuthObservability: per-policy counter — missing-bearer DENYs bucketed under (issuer='', policy='P')",
        ok,
        ok ? "" :
            "bucket_found=" + std::to_string(bucket_found) +
            (bucket_found ? " denied=" + std::to_string(bucket->denied) : ""));
    return ok;
}

// B2: Two policies isolated — counters don't bleed between policy "A" and "B".
static bool TestPerPolicyCounter_TwoPoliciesIsolated() {
    AUTH_NAMESPACE::AuthConfig cfg = MakeEmptyConfig(/*enabled=*/true);
    cfg.issuers["test-issuer"] = MakeStaticIssuer();
    auto mgr = MakeManager(cfg);

    AUTH_NAMESPACE::AuthPolicy pa = MakePolicy("A", {"/a/"}, {"test-issuer"}, true, "deny");
    AUTH_NAMESPACE::AuthPolicy pb = MakePolicy("B", {"/b/"}, {"test-issuer"}, true, "deny");
    mgr->RegisterPolicy(pa.applies_to, pa);
    mgr->RegisterPolicy(pb.applies_to, pb);
    mgr->Start();

    // 4 requests to /a/, 1 to /b/.
    for (int i = 0; i < 4; ++i) {
        HttpRequest req = MakeRequest("/a/resource");
        HttpResponse resp;
        mgr->InvokeMiddleware(req, resp);
    }
    {
        HttpRequest req = MakeRequest("/b/resource");
        HttpResponse resp;
        mgr->InvokeMiddleware(req, resp);
    }

    auto snap = mgr->SnapshotAll();
    const auto* ba = FindBucket(snap, "", "A");
    const auto* bb = FindBucket(snap, "", "B");

    bool ok = ba && bb
           && ba->denied == 4
           && bb->denied == 1;
    TestFramework::RecordTest(
        "AuthObservability: per-policy counter — two policies isolated (A=4 B=1)",
        ok,
        ok ? "" :
            "A denied=" + (ba ? std::to_string(ba->denied) : "null") +
            " B denied=" + (bb ? std::to_string(bb->denied) : "null"));
    return ok;
}

// B3: Counter preserved across same-name reload; dropped when name removed.
static bool TestPerPolicyCounter_PreservedAcrossSameNameReload() {
    AUTH_NAMESPACE::AuthConfig cfg = MakeEmptyConfig(/*enabled=*/true);
    cfg.issuers["test-issuer"] = MakeStaticIssuer();
    auto mgr = MakeManager(cfg);
    AUTH_NAMESPACE::AuthPolicy p = MakePolicy("P", {"/api/"}, {"test-issuer"}, true, "deny");
    mgr->RegisterPolicy(p.applies_to, p);
    mgr->Start();

    // Accumulate 5 denials.
    for (int i = 0; i < 5; ++i) {
        HttpRequest req = MakeRequest("/api/resource");
        HttpResponse resp;
        mgr->InvokeMiddleware(req, resp);
    }

    auto snap1 = mgr->SnapshotAll();
    const auto* b1 = FindBucket(snap1, "", "P");
    bool initial_ok = b1 && b1->denied == 5;

    // Same-name reload (policy "P" survives) — counter must be preserved.
    AUTH_NAMESPACE::AuthPolicy p_same = MakePolicy("P", {"/api/v2/"}, {"test-issuer"}, true, "deny");
    DoCommit(*mgr, {p_same}, /*master_enabled=*/true, /*debug_headers=*/false);

    auto snap2 = mgr->SnapshotAll();
    const auto* b2 = FindBucket(snap2, "", "P");
    bool preserved_ok = b2 && b2->denied == 5;

    // Reload with different name "Q" — "P" bucket must be dropped (reconciled out).
    // "Q" bucket is lazily created on the first verdict; we only verify "P" is gone.
    AUTH_NAMESPACE::AuthPolicy q = MakePolicy("Q", {"/api/"}, {"test-issuer"}, true, "deny");
    DoCommit(*mgr, {q}, /*master_enabled=*/true, /*debug_headers=*/false);

    auto snap3 = mgr->SnapshotAll();
    const auto* b3_p = FindBucket(snap3, "", "P");
    // "P" bucket must have been reconciled out; "Q" is not yet created (no verdict yet).
    bool removed_ok = (b3_p == nullptr);

    bool ok = initial_ok && preserved_ok && removed_ok;
    TestFramework::RecordTest(
        "AuthObservability: per-policy counter preserved on same-name reload; dropped on name removal",
        ok,
        ok ? "" :
            "initial_ok=" + std::to_string(initial_ok) +
            " preserved_ok=" + std::to_string(preserved_ok) +
            " removed_ok=" + std::to_string(removed_ok) +
            " b3_p=" + (b3_p ? std::to_string(b3_p->denied) : "null"));
    return ok;
}

// B4: Removed-then-readded policy resets counter to zero (no accumulation
//     across the gap).
static bool TestPerPolicyCounter_RemovedThenReadded_ResetsToZero() {
    AUTH_NAMESPACE::AuthConfig cfg = MakeEmptyConfig(/*enabled=*/true);
    cfg.issuers["test-issuer"] = MakeStaticIssuer();
    auto mgr = MakeManager(cfg);
    AUTH_NAMESPACE::AuthPolicy p = MakePolicy("P", {"/api/"}, {"test-issuer"}, true, "deny");
    mgr->RegisterPolicy(p.applies_to, p);
    mgr->Start();

    // Accumulate 3 denials.
    for (int i = 0; i < 3; ++i) {
        HttpRequest req = MakeRequest("/api/resource");
        HttpResponse resp;
        mgr->InvokeMiddleware(req, resp);
    }

    // Commit with policy "Q" only — drops "P".
    AUTH_NAMESPACE::AuthPolicy q = MakePolicy("Q", {"/other/"}, {"test-issuer"}, true, "deny");
    DoCommit(*mgr, {q}, /*master_enabled=*/true, /*debug_headers=*/false);

    // Now readd "P".
    DoCommit(*mgr, {p}, /*master_enabled=*/true, /*debug_headers=*/false);

    // Trigger 1 deny against the fresh "P" bucket.
    {
        HttpRequest req = MakeRequest("/api/resource");
        HttpResponse resp;
        mgr->InvokeMiddleware(req, resp);
    }

    auto snap = mgr->SnapshotAll();
    const auto* bp = FindBucket(snap, "", "P");

    // The readded "P" bucket should start from zero — only 1 deny recorded.
    bool ok = bp && bp->denied == 1;
    TestFramework::RecordTest(
        "AuthObservability: per-policy counter resets to zero when policy removed then readded",
        ok,
        ok ? "" :
            "bucket=" + (bp ? std::to_string(bp->denied) : "null") +
            " (expected 1)");
    return ok;
}

// ---------------------------------------------------------------------------
// Tier C — SnapshotView struct shape
// ---------------------------------------------------------------------------

// C1: No issuers, no policies, debug=false, master_enabled=false — verify
//     new fields present with expected defaults.
static bool TestStatsShape_NoIssuers() {
    AUTH_NAMESPACE::AuthConfig cfg = MakeEmptyConfig(/*enabled=*/false, /*debug_headers=*/false);
    auto mgr = MakeManager(cfg);
    mgr->Start();

    auto snap = mgr->SnapshotAll();

    bool enabled_ok     = snap.enabled == false;
    bool debug_ok       = snap.debug_response_headers == false;
    bool policy_cnt_ok  = snap.policy_count == 0;
    bool gen_ok         = snap.generation >= 1;
    bool per_policy_ok  = snap.per_policy.empty();
    bool issuers_ok     = snap.issuers.empty();

    bool ok = enabled_ok && debug_ok && policy_cnt_ok && gen_ok
           && per_policy_ok && issuers_ok;
    TestFramework::RecordTest(
        "AuthObservability: SnapshotView shape — no issuers / no policies / defaults",
        ok,
        ok ? "" :
            "enabled=" + std::to_string(snap.enabled) +
            " debug=" + std::to_string(snap.debug_response_headers) +
            " policy_count=" + std::to_string(snap.policy_count) +
            " generation=" + std::to_string(snap.generation) +
            " per_policy.size=" + std::to_string(snap.per_policy.size()) +
            " issuers.size=" + std::to_string(snap.issuers.size()));
    return ok;
}

// C2: After Reload() + CommitPolicyAndEnforcement with debug=true — verify
//     enabled, debug_response_headers, generation, policy_count are reflected.
//
// Note: generation_ is bumped by Reload() (not by CommitPolicyAndEnforcement).
// Production callers always call Reload() then CommitPolicyAndEnforcement
// together (via HttpServer::Reload). This test mirrors that sequence.
static bool TestStatsShape_AfterReload() {
    AUTH_NAMESPACE::AuthConfig cfg = MakeEmptyConfig(/*enabled=*/true, /*debug_headers=*/false);
    cfg.issuers["test-issuer"] = MakeStaticIssuer();
    auto mgr = MakeManager(cfg);
    AUTH_NAMESPACE::AuthPolicy p = MakePolicy("P", {"/api/"}, {"test-issuer"}, true, "deny");
    mgr->RegisterPolicy(p.applies_to, p);
    mgr->Start();

    uint64_t gen_before = mgr->SnapshotAll().generation;

    // Reload() bumps the generation; CommitPolicyAndEnforcement publishes
    // debug_response_headers + master_enabled + policy list atomically.
    AUTH_NAMESPACE::AuthConfig new_cfg = cfg;
    new_cfg.debug_response_headers = true;
    new_cfg.enabled = true;
    std::string err;
    mgr->Reload(new_cfg, err);
    DoCommit(*mgr, {p}, /*master_enabled=*/true, /*debug_headers=*/true);

    auto snap = mgr->SnapshotAll();

    bool enabled_ok      = snap.enabled == true;
    bool debug_ok        = snap.debug_response_headers == true;
    bool gen_bumped      = snap.generation > gen_before;
    bool policy_count_ok = snap.policy_count >= 1;

    bool ok = enabled_ok && debug_ok && gen_bumped && policy_count_ok;
    TestFramework::RecordTest(
        "AuthObservability: SnapshotView shape — enabled/debug/generation/policy_count after reload",
        ok,
        ok ? "" :
            "enabled=" + std::to_string(snap.enabled) +
            " debug=" + std::to_string(snap.debug_response_headers) +
            " gen_before=" + std::to_string(gen_before) +
            " gen_after=" + std::to_string(snap.generation) +
            " policy_count=" + std::to_string(snap.policy_count) +
            " reload_err='" + err + "'");
    return ok;
}

// C3: Drive 2 denies on policy "X" — snap.per_policy must contain the bucket.
static bool TestStatsShape_PerPolicyVectorShape() {
    AUTH_NAMESPACE::AuthConfig cfg = MakeEmptyConfig(/*enabled=*/true);
    cfg.issuers["test-issuer"] = MakeStaticIssuer();
    auto mgr = MakeManager(cfg);
    AUTH_NAMESPACE::AuthPolicy p = MakePolicy("X", {"/x/"}, {"test-issuer"}, true, "deny");
    mgr->RegisterPolicy(p.applies_to, p);
    mgr->Start();

    for (int i = 0; i < 2; ++i) {
        HttpRequest req = MakeRequest("/x/resource");
        HttpResponse resp;
        mgr->InvokeMiddleware(req, resp);
    }

    auto snap = mgr->SnapshotAll();
    const auto* bx = FindBucket(snap, "", "X");

    bool found     = bx != nullptr;
    bool denied_ok = found && bx->denied == 2;
    bool allowed_zero = found && bx->allowed == 0;
    bool undet_zero   = found && bx->undetermined == 0;

    bool ok = found && denied_ok && allowed_zero && undet_zero;
    TestFramework::RecordTest(
        "AuthObservability: SnapshotView per_policy vector shape — (issuer='', policy='X') denied=2",
        ok,
        ok ? "" :
            "found=" + std::to_string(found) +
            (found ? " denied=" + std::to_string(bx->denied)
                     + " allowed=" + std::to_string(bx->allowed)
                     + " undetermined=" + std::to_string(bx->undetermined) : ""));
    return ok;
}

// ---------------------------------------------------------------------------
// Tier D — concurrent BumpPerPolicy (TSan target)
// ---------------------------------------------------------------------------

// D1: 8 threads × 100 missing-bearer requests all hitting policy "P".
//     After join, (issuer="", policy="P").denied must equal 800 exactly.
static bool TestPerPolicyCounter_ConcurrentNoTearing() {
    AUTH_NAMESPACE::AuthConfig cfg = MakeEmptyConfig(/*enabled=*/true);
    cfg.issuers["test-issuer"] = MakeStaticIssuer();
    auto mgr = MakeManager(cfg);
    AUTH_NAMESPACE::AuthPolicy p = MakePolicy("P", {"/api/"}, {"test-issuer"}, true, "deny");
    mgr->RegisterPolicy(p.applies_to, p);
    mgr->Start();

    static constexpr int kThreads    = 8;
    static constexpr int kPerThread  = 100;

    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&mgr]() {
            for (int i = 0; i < kPerThread; ++i) {
                HttpRequest req = MakeRequest("/api/resource");
                HttpResponse resp;
                mgr->InvokeMiddleware(req, resp);
            }
        });
    }
    for (auto& th : threads) th.join();

    auto snap = mgr->SnapshotAll();
    const auto* bp = FindBucket(snap, "", "P");

    bool ok = bp && bp->denied == static_cast<uint64_t>(kThreads * kPerThread);
    TestFramework::RecordTest(
        "AuthObservability: concurrent per-policy counter — 8×100 denies = 800 exactly",
        ok,
        ok ? "" :
            "denied=" + (bp ? std::to_string(bp->denied) : "null") +
            " expected=800");
    return ok;
}

// ---------------------------------------------------------------------------
// RunAllTests
// ---------------------------------------------------------------------------

inline void RunAllTests() {
    // Tier A — debug response headers
    TestDebugHeadersOff_NoEmission();
    TestDebugHeadersOn_PreIssuerDeny_NoIssuerHeader();
    TestDebugHeadersOn_TokenTooLargeDeny();
    TestDebugHeadersHotReloadFlip();
    TestDebugHeadersUndeterminedHasIssuerName();

    // Tier B — per-policy counters
    TestPerPolicyCounter_AllowDenyUndetermined();
    TestPerPolicyCounter_TwoPoliciesIsolated();
    TestPerPolicyCounter_PreservedAcrossSameNameReload();
    TestPerPolicyCounter_RemovedThenReadded_ResetsToZero();

    // Tier C — SnapshotView shape
    TestStatsShape_NoIssuers();
    TestStatsShape_AfterReload();
    TestStatsShape_PerPolicyVectorShape();

    // Tier D — concurrent counter integrity
    TestPerPolicyCounter_ConcurrentNoTearing();
}

}  // namespace AuthObservabilityTests
