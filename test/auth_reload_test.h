#pragma once

// ============================================================================
// Auth reload tests — Phase 2 test suite.
//
// These tests exercise the AuthManager::Reload() path without starting a live
// server: forward config field updates, leeway_sec changes, algorithm list
// updates, generation counter bumps, topology rejection, and concurrent
// ForwardConfig snapshot stability during reload.
//
// Tests covered:
//   1.  Reload: forward subject_header update takes effect
//   2.  Reload: forward scopes_header update takes effect
//   3.  Reload: forward raw_jwt_header enabled after initial off
//   4.  Reload: leeway_sec updated on issuer (reloadable field)
//   5.  Reload: algorithms update accepted (RS256→RS384)
//   6.  Reload: generation counter bumps on each Reload call
//   7.  Reload: topology change (issuer added) rejected with err_out
//   8.  Reload: topology change (issuer removed) rejected with err_out
//   9.  Reload: mismatched issuer name (same count, wrong name) rejected
//  10.  Reload: issuer_url change (topology field) rejected
//  11.  Reload: discovery flag change (topology field) rejected
//  12.  Reload: mode field change (topology field) rejected
//  13.  Reload: forward config stable under concurrent readers
//  14.  Reload: policy list rebuilt by RebuildPolicyListFromLiveSources
// ============================================================================

#include "test_framework.h"
#include "auth/auth_manager.h"
#include "auth/auth_config.h"
#include "auth/auth_context.h"
#include "auth/auth_result.h"
#include "auth/jwks_cache.h"
#include "auth/issuer.h"
#include "http/http_request.h"
#include "http/http_response.h"
#include "config/server_config.h"
#include "log/logger.h"

#include <string>
#include <memory>
#include <atomic>
#include <thread>
#include <chrono>
#include <vector>

namespace AuthReloadTests {

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// Build a minimal static IssuerConfig (no discovery, no upstream network calls).
static AUTH_NAMESPACE::IssuerConfig MakeStaticIssuer(
        const std::string& name,
        const std::string& url,
        const std::vector<std::string>& algs = {"RS256"},
        int leeway_sec = 30,
        bool discovery = false) {
    AUTH_NAMESPACE::IssuerConfig ic;
    ic.name        = name;
    ic.issuer_url  = url;
    ic.discovery   = discovery;
    ic.jwks_uri    = "https://" + name + ".example.com/jwks.json";
    ic.upstream    = "";
    ic.mode        = "jwt";
    ic.algorithms  = algs;
    ic.leeway_sec  = leeway_sec;
    ic.jwks_cache_sec = 300;
    return ic;
}

// Build a minimal AuthConfig with one issuer and a forward config.
static AUTH_NAMESPACE::AuthConfig MakeConfig(
        const std::string& iss_name,
        const std::string& iss_url,
        const AUTH_NAMESPACE::AuthForwardConfig& fwd_cfg = {},
        const std::vector<std::string>& algs = {"RS256"},
        int leeway_sec = 30) {
    AUTH_NAMESPACE::AuthConfig cfg;
    cfg.enabled = true;
    cfg.issuers[iss_name] = MakeStaticIssuer(iss_name, iss_url, algs, leeway_sec);
    cfg.forward = fwd_cfg;
    return cfg;
}

// Construct an AuthManager and Start() it.
static std::shared_ptr<AUTH_NAMESPACE::AuthManager> MakeManager(
        const AUTH_NAMESPACE::AuthConfig& cfg) {
    auto mgr = std::make_shared<AUTH_NAMESPACE::AuthManager>(
        cfg, nullptr, std::vector<std::shared_ptr<Dispatcher>>{});
    mgr->Start();
    return mgr;
}

// Reload + final cutover. forward_ is published only at the cutover (per
// design §11.2 step 4 — single-snapshot publication of forward + policies +
// master_enabled), so tests that observe forward changes after a reload
// must invoke both stages. HttpServer::Reload is the production caller
// that ties them together; this helper mirrors that for unit tests that
// use AuthManager directly.
static bool ReloadAndCommit(
        AUTH_NAMESPACE::AuthManager& mgr,
        const AUTH_NAMESPACE::AuthConfig& new_cfg,
        std::string& err_out) {
    if (!mgr.Reload(new_cfg, err_out)) return false;
    mgr.CommitPolicyAndEnforcement(
        /*new_upstreams=*/{},
        new_cfg.policies,
        new_cfg.forward,
        new_cfg.enabled);
    return true;
}

// ---------------------------------------------------------------------------
// Test 1: forward subject_header update takes effect after Reload
// ---------------------------------------------------------------------------
static bool TestReloadForwardSubjectHeader() {
    const std::string iss_name = "issuer-subj";
    const std::string iss_url  = "https://subj.example.com";

    AUTH_NAMESPACE::AuthForwardConfig fwd0;
    fwd0.subject_header = "X-Auth-Subject";
    auto cfg0 = MakeConfig(iss_name, iss_url, fwd0);
    auto mgr  = MakeManager(cfg0);

    // Confirm initial subject_header
    {
        auto fwd = mgr->ForwardConfig();
        if (!fwd || fwd->subject_header != "X-Auth-Subject") {
            mgr->Stop();
            return false;
        }
    }

    // Reload with updated subject_header
    AUTH_NAMESPACE::AuthForwardConfig fwd1;
    fwd1.subject_header = "X-Custom-Subject";
    auto cfg1 = MakeConfig(iss_name, iss_url, fwd1);
    std::string err;
    bool ok = ReloadAndCommit(*mgr, cfg1, err);
    if (!ok) {
        mgr->Stop();
        return false;
    }

    // New subject_header must be visible
    auto fwd_after = mgr->ForwardConfig();
    mgr->Stop();
    return fwd_after && fwd_after->subject_header == "X-Custom-Subject";
}

// ---------------------------------------------------------------------------
// Test 2: forward scopes_header update takes effect after Reload
// ---------------------------------------------------------------------------
static bool TestReloadForwardScopesHeader() {
    const std::string iss_name = "issuer-scope";
    const std::string iss_url  = "https://scope.example.com";

    AUTH_NAMESPACE::AuthForwardConfig fwd0;
    fwd0.scopes_header = "X-Auth-Scopes";
    auto cfg0 = MakeConfig(iss_name, iss_url, fwd0);
    auto mgr  = MakeManager(cfg0);

    AUTH_NAMESPACE::AuthForwardConfig fwd1;
    fwd1.scopes_header = "X-Permissions";
    auto cfg1 = MakeConfig(iss_name, iss_url, fwd1);
    std::string err;
    bool ok = ReloadAndCommit(*mgr, cfg1, err);

    auto fwd_after = mgr->ForwardConfig();
    mgr->Stop();
    return ok && fwd_after && fwd_after->scopes_header == "X-Permissions";
}

// ---------------------------------------------------------------------------
// Test 3: raw_jwt_header enabled after initial off
// ---------------------------------------------------------------------------
static bool TestReloadRawJwtHeaderEnabled() {
    const std::string iss_name = "issuer-rawjwt";
    const std::string iss_url  = "https://rawjwt.example.com";

    AUTH_NAMESPACE::AuthForwardConfig fwd0;
    fwd0.raw_jwt_header = "";   // disabled
    auto cfg0 = MakeConfig(iss_name, iss_url, fwd0);
    auto mgr  = MakeManager(cfg0);

    {
        auto fwd = mgr->ForwardConfig();
        if (!fwd || !fwd->raw_jwt_header.empty()) {
            mgr->Stop();
            return false;
        }
    }

    AUTH_NAMESPACE::AuthForwardConfig fwd1;
    fwd1.raw_jwt_header = "X-Raw-Jwt";
    auto cfg1 = MakeConfig(iss_name, iss_url, fwd1);
    std::string err;
    bool ok = ReloadAndCommit(*mgr, cfg1, err);

    auto fwd_after = mgr->ForwardConfig();
    mgr->Stop();
    return ok && fwd_after && fwd_after->raw_jwt_header == "X-Raw-Jwt";
}

// ---------------------------------------------------------------------------
// Test 4: leeway_sec updated on issuer (reloadable field)
// Rationale: leeway_sec is a reloadable field per the design spec (§11).
// ApplyReload should accept it without error.
// ---------------------------------------------------------------------------
static bool TestReloadLeewaySec() {
    const std::string iss_name = "issuer-leeway";
    const std::string iss_url  = "https://leeway.example.com";

    auto cfg0 = MakeConfig(iss_name, iss_url, {}, {"RS256"}, 30);
    auto mgr  = MakeManager(cfg0);

    auto cfg1 = MakeConfig(iss_name, iss_url, {}, {"RS256"}, 60);
    std::string err;
    bool ok = mgr->Reload(cfg1, err);

    mgr->Stop();
    if (!ok) {
        logging::Get()->warn("AuthReloadTests: leeway_sec reload failed: {}", err);
    }
    return ok;
}

// ---------------------------------------------------------------------------
// Test 5: algorithms update RS256 → RS384 accepted
// Rationale: algorithm list is a reloadable field.
// ---------------------------------------------------------------------------
static bool TestReloadAlgorithmsUpdate() {
    const std::string iss_name = "issuer-alg";
    const std::string iss_url  = "https://alg.example.com";

    auto cfg0 = MakeConfig(iss_name, iss_url, {}, {"RS256"}, 30);
    auto mgr  = MakeManager(cfg0);

    auto cfg1 = MakeConfig(iss_name, iss_url, {}, {"RS256", "RS384"}, 30);
    std::string err;
    bool ok = mgr->Reload(cfg1, err);

    mgr->Stop();
    if (!ok) {
        logging::Get()->warn("AuthReloadTests: algorithms reload failed: {}", err);
    }
    return ok;
}

// ---------------------------------------------------------------------------
// Test 6: generation counter bumps on each Reload call
// ---------------------------------------------------------------------------
static bool TestReloadBumpsGeneration() {
    const std::string iss_name = "issuer-gen";
    const std::string iss_url  = "https://gen.example.com";

    auto cfg = MakeConfig(iss_name, iss_url);
    auto mgr = MakeManager(cfg);

    auto snap0 = mgr->SnapshotAll();
    uint64_t gen0 = snap0.generation;

    std::string err;
    mgr->Reload(cfg, err);
    auto snap1 = mgr->SnapshotAll();
    uint64_t gen1 = snap1.generation;

    mgr->Reload(cfg, err);
    auto snap2 = mgr->SnapshotAll();
    uint64_t gen2 = snap2.generation;

    mgr->Stop();
    return gen1 > gen0 && gen2 > gen1;
}

// ---------------------------------------------------------------------------
// Test 7: topology change (issuer added) is rejected
// ---------------------------------------------------------------------------
static bool TestReloadRejectsIssuerAdded() {
    const std::string iss_name = "issuer-add";
    const std::string iss_url  = "https://add.example.com";

    auto cfg0 = MakeConfig(iss_name, iss_url);
    auto mgr  = MakeManager(cfg0);

    // Add a second issuer in the reloaded config
    AUTH_NAMESPACE::AuthConfig cfg1 = cfg0;
    cfg1.issuers["another-issuer"] =
        MakeStaticIssuer("another-issuer", "https://another.example.com");

    std::string err;
    bool ok = mgr->Reload(cfg1, err);
    mgr->Stop();

    // Must be rejected
    return !ok && !err.empty();
}

// ---------------------------------------------------------------------------
// Test 8: topology change (issuer removed) is rejected
// ---------------------------------------------------------------------------
static bool TestReloadRejectsIssuerRemoved() {
    const std::string iss_name = "issuer-rem";
    const std::string iss_url  = "https://rem.example.com";

    AUTH_NAMESPACE::AuthConfig cfg0;
    cfg0.enabled = true;
    cfg0.issuers["issuer-A"] = MakeStaticIssuer("issuer-A", "https://a.example.com");
    cfg0.issuers["issuer-B"] = MakeStaticIssuer("issuer-B", "https://b.example.com");

    auto mgr = MakeManager(cfg0);

    // Remove issuer-B from the reloaded config
    AUTH_NAMESPACE::AuthConfig cfg1;
    cfg1.enabled = true;
    cfg1.issuers["issuer-A"] = MakeStaticIssuer("issuer-A", "https://a.example.com");

    std::string err;
    bool ok = mgr->Reload(cfg1, err);
    mgr->Stop();

    return !ok && !err.empty();
}

// ---------------------------------------------------------------------------
// Test 9: same count but different issuer name → rejected
// ---------------------------------------------------------------------------
static bool TestReloadRejectsMismatchedIssuerName() {
    const std::string iss_name = "issuer-mismatch";
    const std::string iss_url  = "https://mismatch.example.com";

    auto cfg0 = MakeConfig(iss_name, iss_url);
    auto mgr  = MakeManager(cfg0);

    // Same count (1), but the issuer is renamed
    AUTH_NAMESPACE::AuthConfig cfg1;
    cfg1.enabled = true;
    cfg1.issuers["totally-different-name"] =
        MakeStaticIssuer("totally-different-name", iss_url);

    std::string err;
    bool ok = mgr->Reload(cfg1, err);
    mgr->Stop();

    return !ok && !err.empty();
}

// ---------------------------------------------------------------------------
// Test 10: issuer_url change is rejected (topology field)
// ---------------------------------------------------------------------------
static bool TestReloadRejectsIssuerUrlChange() {
    const std::string iss_name = "issuer-url-change";
    const std::string iss_url  = "https://original.example.com";

    auto cfg0 = MakeConfig(iss_name, iss_url);
    auto mgr  = MakeManager(cfg0);

    // Same name, different issuer_url
    AUTH_NAMESPACE::AuthConfig cfg1;
    cfg1.enabled = true;
    cfg1.issuers[iss_name] = MakeStaticIssuer(iss_name, "https://new-url.example.com");

    std::string err;
    bool ok = mgr->Reload(cfg1, err);
    mgr->Stop();

    // Issuer URL is topology-stable → reload must be rejected
    return !ok && !err.empty();
}

// ---------------------------------------------------------------------------
// Test 11: discovery flag change is rejected (topology field)
// ---------------------------------------------------------------------------
static bool TestReloadRejectsDiscoveryChange() {
    const std::string iss_name = "issuer-disco";
    const std::string iss_url  = "https://disco.example.com";

    // Initial: discovery=false
    AUTH_NAMESPACE::AuthConfig cfg0;
    cfg0.enabled = true;
    cfg0.issuers[iss_name] = MakeStaticIssuer(iss_name, iss_url,
                                               {"RS256"}, 30, /*discovery=*/false);
    auto mgr = MakeManager(cfg0);

    // Reload with discovery=true (topology change)
    AUTH_NAMESPACE::AuthConfig cfg1;
    cfg1.enabled = true;
    cfg1.issuers[iss_name] = MakeStaticIssuer(iss_name, iss_url,
                                               {"RS256"}, 30, /*discovery=*/true);

    std::string err;
    bool ok = mgr->Reload(cfg1, err);
    mgr->Stop();

    return !ok && !err.empty();
}

// ---------------------------------------------------------------------------
// Test 11b: static jwks_uri change on discovery=false issuer rejected
// Rationale: for static-configured issuers, jwks_uri IS the issuer
// topology — changing it silently points future key refreshes at a
// different JWKS source (either rejecting current tokens or trusting
// an unintended IdP). AuthManager::Reload must preserve live state;
// the operator restarts with the new URL intentionally. For
// discovery=true issuers, the operator-supplied jwks_uri is ignored at
// runtime (OIDC discovery overwrites on every fetch), so the gate
// applies only to discovery=false.
// ---------------------------------------------------------------------------
static bool TestReloadRejectsStaticJwksUriChange() {
    const std::string iss_name = "issuer-static-jwks";
    const std::string iss_url  = "https://static-jwks.example.com";

    AUTH_NAMESPACE::AuthConfig cfg0;
    cfg0.enabled = true;
    cfg0.issuers[iss_name] = MakeStaticIssuer(
        iss_name, iss_url, {"RS256"}, 30, /*discovery=*/false);
    cfg0.issuers[iss_name].jwks_uri =
        "https://static-jwks.example.com/jwks.json";

    auto mgr = MakeManager(cfg0);

    AUTH_NAMESPACE::AuthConfig cfg1 = cfg0;
    cfg1.issuers[iss_name].jwks_uri =
        "https://attacker.example.com/jwks.json";

    std::string err;
    bool ok = mgr->Reload(cfg1, err);
    mgr->Stop();

    return !ok && err.find("jwks_uri") != std::string::npos;
}

// ---------------------------------------------------------------------------
// Test 12: mode field change (jwt → introspection) rejected
// Rationale: mode is topology-stable; switching between jwt and introspection
// requires restarting the server.
// ---------------------------------------------------------------------------
static bool TestReloadRejectsModeChange() {
    const std::string iss_name = "issuer-mode";
    const std::string iss_url  = "https://mode.example.com";

    AUTH_NAMESPACE::AuthConfig cfg0;
    cfg0.enabled = true;
    AUTH_NAMESPACE::IssuerConfig ic0 = MakeStaticIssuer(iss_name, iss_url);
    ic0.mode = "jwt";
    cfg0.issuers[iss_name] = ic0;

    auto mgr = MakeManager(cfg0);

    AUTH_NAMESPACE::AuthConfig cfg1;
    cfg1.enabled = true;
    AUTH_NAMESPACE::IssuerConfig ic1 = MakeStaticIssuer(iss_name, iss_url);
    ic1.mode = "introspection";
    cfg1.issuers[iss_name] = ic1;

    std::string err;
    bool ok = mgr->Reload(cfg1, err);
    mgr->Stop();

    return !ok && !err.empty();
}

// ---------------------------------------------------------------------------
// Test 13: ForwardConfig snapshot stable under concurrent readers
// Rationale: Multiple reader threads continuously call ForwardConfig() while
// the main thread fires rapid Reload calls. No crash or corrupted header
// name should occur (shared_ptr atomic swap is the race-safety mechanism).
// ---------------------------------------------------------------------------
static bool TestForwardConfigStableUnderConcurrentReload() {
    const std::string iss_name = "issuer-concurrent";
    const std::string iss_url  = "https://concurrent.example.com";

    auto cfg = MakeConfig(iss_name, iss_url);
    auto mgr = MakeManager(cfg);

    constexpr int NUM_READERS  = 8;
    constexpr int RELOAD_ITERS = 200;

    std::atomic<bool> stop_readers{false};
    std::atomic<int>  corrupt_count{0};

    // Readers continuously snapshot ForwardConfig and validate the header name
    // is non-empty and doesn't contain garbage.
    std::vector<std::thread> readers;
    for (int i = 0; i < NUM_READERS; i++) {
        readers.emplace_back([&](){
            while (!stop_readers.load(std::memory_order_relaxed)) {
                auto fwd = mgr->ForwardConfig();
                if (!fwd) {
                    corrupt_count.fetch_add(1, std::memory_order_relaxed);
                    continue;
                }
                // subject_header must be non-empty and start with "X-"
                const auto& sh = fwd->subject_header;
                if (sh.empty() || sh.substr(0,2) != "X-") {
                    corrupt_count.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }

    // Writer alternates between two valid configurations
    for (int i = 0; i < RELOAD_ITERS; i++) {
        AUTH_NAMESPACE::AuthForwardConfig fwd;
        fwd.subject_header = (i % 2 == 0) ? "X-Auth-Subject" : "X-User-Id";
        auto reload_cfg = MakeConfig(iss_name, iss_url, fwd);
        std::string err;
        ReloadAndCommit(*mgr, reload_cfg, err);
    }

    stop_readers.store(true, std::memory_order_release);
    for (auto& t : readers) t.join();

    mgr->Stop();
    return corrupt_count.load() == 0;
}

// ---------------------------------------------------------------------------
// Test 14: RebuildPolicyListFromLiveSources updates the policy list
// Rationale: After calling Reload, HttpServer calls
// RebuildPolicyListFromLiveSources with the new upstream list. Policy count
// should reflect the new top-level policies.
// ---------------------------------------------------------------------------
static bool TestRebuildPolicyListFromLiveSources() {
    const std::string iss_name = "issuer-rebuild";
    const std::string iss_url  = "https://rebuild.example.com";

    // Create manager with one top-level policy
    AUTH_NAMESPACE::AuthPolicy p0;
    p0.name       = "initial-policy";
    p0.enabled    = true;
    p0.applies_to = {"/api/"};
    p0.issuers    = {iss_name};

    AUTH_NAMESPACE::AuthConfig cfg;
    cfg.enabled = true;
    cfg.issuers[iss_name] = MakeStaticIssuer(iss_name, iss_url);
    cfg.policies.push_back(p0);

    auto mgr = MakeManager(cfg);
    mgr->RegisterPolicy(p0.applies_to, p0);  // will be no-op post-Start; just for coverage

    auto snap0 = mgr->SnapshotAll();
    size_t count0 = snap0.policy_count;

    // Rebuild with 2 top-level policies
    AUTH_NAMESPACE::AuthPolicy p1;
    p1.name       = "second-policy";
    p1.enabled    = true;
    p1.applies_to = {"/admin/"};
    p1.issuers    = {iss_name};

    std::vector<UpstreamConfig> empty_upstreams;
    AUTH_NAMESPACE::AuthForwardConfig fwd;
    mgr->CommitPolicyAndEnforcement(
        empty_upstreams, {p0, p1}, fwd, /*new_master_enabled=*/true);

    auto snap1 = mgr->SnapshotAll();
    mgr->Stop();

    // Policy count should now be 2 (both enabled top-level policies have 1 prefix each)
    return snap1.policy_count > count0;
}

// ---------------------------------------------------------------------------
// Test 15: ConfigLoader::ValidateAuthPrefixCollisions rejects exact-prefix
// collisions across inline and top-level. The reload path strips upstreams
// before calling Validate(), so collision detection has to be invoked
// separately on the full new_config — this test pins the helper itself.
// ---------------------------------------------------------------------------
static bool TestValidateAuthPrefixCollisionsRejectsCollisions() {
    // Inline + top-level on the same prefix.
    auto build_collision_cfg = []() {
        ServerConfig cfg;
        UpstreamConfig u;
        u.name = "api";
        u.host = "127.0.0.1";
        u.port = 8080;
        u.proxy.route_prefix = "/api/";
        u.proxy.auth.enabled = true;
        u.proxy.auth.issuers = {"google"};
        cfg.upstreams.push_back(u);

        AUTH_NAMESPACE::IssuerConfig ic;
        ic.name = "google";
        ic.issuer_url = "https://issuer.example";
        ic.upstream = "api";
        ic.mode = "jwt";
        ic.algorithms = {"RS256"};
        cfg.auth.issuers["google"] = ic;

        AUTH_NAMESPACE::AuthPolicy p;
        p.name = "top-clash";
        p.enabled = true;
        p.applies_to = {"/api/"};
        p.issuers = {"google"};
        cfg.auth.policies.push_back(p);
        return cfg;
    };

    bool collision_rejected = false;
    try {
        ConfigLoader::ValidateAuthPrefixCollisions(build_collision_cfg());
    } catch (const std::invalid_argument&) {
        collision_rejected = true;
    }

    // Same shape but disabled inline — collision check ignores it.
    bool disabled_accepted = true;
    try {
        ServerConfig cfg = build_collision_cfg();
        cfg.upstreams[0].proxy.auth.enabled = false;
        ConfigLoader::ValidateAuthPrefixCollisions(cfg);
    } catch (const std::exception&) {
        disabled_accepted = false;
    }

    return collision_rejected && disabled_accepted;
}

// ---------------------------------------------------------------------------
// Test 16: removed top-level policy is dropped from the live matcher.
// Per design §11.2 step 4, removal is the operator's explicit intent and
// is live-reloadable — the matcher must shrink, not preserve the live
// entry. Verified via SnapshotAll().policy_count.
// ---------------------------------------------------------------------------
static bool TestReloadDropsRemovedTopLevelPolicy() {
    const std::string iss_name = "issuer-rm";
    const std::string iss_url  = "https://rm.example.com";

    AUTH_NAMESPACE::AuthConfig cfg0 = MakeConfig(iss_name, iss_url);
    AUTH_NAMESPACE::AuthPolicy p0;
    p0.name = "to-remove";
    p0.enabled = true;
    p0.applies_to = {"/protected/"};
    p0.issuers = {iss_name};
    cfg0.policies.push_back(p0);
    cfg0.enabled = true;

    auto mgr = MakeManager(cfg0);

    // Commit so policies_ reflects the initial top-level entry.
    {
        std::string err;
        if (!ReloadAndCommit(*mgr, cfg0, err)) { mgr->Stop(); return false; }
    }
    auto snap_before = mgr->SnapshotAll();
    if (snap_before.policy_count == 0) { mgr->Stop(); return false; }

    // Reload with the policy REMOVED — same issuer set so AuthManager::
    // Reload accepts. Merge should drop the removed name.
    AUTH_NAMESPACE::AuthConfig cfg1 = MakeConfig(iss_name, iss_url);
    cfg1.enabled = true;  // empty policies vector
    std::string err;
    bool ok = ReloadAndCommit(*mgr, cfg1, err);

    auto snap_after = mgr->SnapshotAll();
    mgr->Stop();
    return ok && snap_after.policy_count == 0;
}

// ---------------------------------------------------------------------------
// Test 17: collision-scope gate on reload. An inline prefix on a NOT-YET-
// LIVE upstream must not trigger the collision reject — the reload path
// would otherwise block unrelated live-safe edits even though
// ValidateProxyAuth and the applied-policy rebuild both ignore that
// upstream this cycle.
// ---------------------------------------------------------------------------
static bool TestValidateAuthPrefixCollisionsScopedByLive() {
    auto build_cfg = []() {
        ServerConfig cfg;
        // Live upstream (present in live_upstream_names below).
        UpstreamConfig live;
        live.name = "live-up";
        live.host = "127.0.0.1";
        live.port = 8080;
        cfg.upstreams.push_back(live);

        // Staged-only upstream — an inline prefix here would otherwise
        // collide with the top-level policy's applies_to.
        UpstreamConfig staged;
        staged.name = "staged-up";
        staged.host = "127.0.0.1";
        staged.port = 9090;
        staged.proxy.route_prefix = "/api/";
        staged.proxy.auth.enabled = true;
        staged.proxy.auth.issuers = {"google"};
        cfg.upstreams.push_back(staged);

        AUTH_NAMESPACE::IssuerConfig ic;
        ic.name = "google";
        ic.issuer_url = "https://issuer.example";
        ic.upstream = "live-up";
        ic.mode = "jwt";
        ic.algorithms = {"RS256"};
        cfg.auth.issuers["google"] = ic;

        // Top-level policy with same prefix as the staged inline.
        AUTH_NAMESPACE::AuthPolicy p;
        p.name = "top-on-api";
        p.enabled = true;
        p.applies_to = {"/api/"};
        p.issuers = {"google"};
        cfg.auth.policies.push_back(p);
        return cfg;
    };

    // Reload-scoped: live_upstream_names = {"live-up"}. The staged
    // inline entry on "staged-up" must be skipped → NO collision.
    bool reload_accepted = true;
    try {
        ConfigLoader::ValidateAuthPrefixCollisions(
            build_cfg(),
            /*live_upstream_names=*/{"live-up"});
    } catch (const std::exception&) {
        reload_accepted = false;
    }

    // Startup-scoped (empty set = check all): SAME config rejects
    // because the staged inline will become live at startup.
    bool startup_rejected = false;
    try {
        ConfigLoader::ValidateAuthPrefixCollisions(build_cfg());
    } catch (const std::invalid_argument&) {
        startup_rejected = true;
    }

    return reload_accepted && startup_rejected;
}

// ---------------------------------------------------------------------------
// Test 18: mixed-case HTTPS scheme accepted (RFC 3986 §3.1). Operator
// configs using HTTPS://..., HttpS://..., etc. should load cleanly.
// ---------------------------------------------------------------------------
static bool TestConfigLoaderAcceptsMixedCaseHttpsScheme() {
    auto build_cfg = [](const std::string& scheme_prefix) {
        ServerConfig cfg;
        UpstreamConfig u;
        u.name = "idp";
        u.host = "127.0.0.1";
        u.port = 8080;
        cfg.upstreams.push_back(u);

        AUTH_NAMESPACE::IssuerConfig ic;
        ic.name = "primary";
        ic.issuer_url = scheme_prefix + "issuer.example";
        ic.jwks_uri = scheme_prefix + "issuer.example/jwks";
        ic.upstream = "idp";
        ic.mode = "jwt";
        ic.algorithms = {"RS256"};
        cfg.auth.issuers["primary"] = ic;
        return cfg;
    };

    // Positive: uppercase scheme must load.
    try {
        ConfigLoader::Validate(build_cfg("HTTPS://"));
    } catch (const std::exception&) {
        return false;
    }
    // Positive: mixed-case scheme must load.
    try {
        ConfigLoader::Validate(build_cfg("HttPs://"));
    } catch (const std::exception&) {
        return false;
    }
    // Negative: lowercase http:// must still reject (not HTTPS).
    try {
        ConfigLoader::Validate(build_cfg("http://"));
        return false;
    } catch (const std::invalid_argument&) {
        // expected
    }
    // Negative: mixed-case HTTP:// must also reject (still not HTTPS).
    try {
        ConfigLoader::Validate(build_cfg("HTTP://"));
        return false;
    } catch (const std::invalid_argument&) {
        // expected
    }
    return true;
}

// ---------------------------------------------------------------------------
// Test 19: rename-with-non-live-issuer preserves live coverage. When a
// reload removes policy A AND adds policy B whose issuers reference an
// issuer that isn't yet live, the merge MUST preserve A until restart
// so the protected prefix doesn't silently lose auth.
// ---------------------------------------------------------------------------
static bool TestReloadPreservesLiveOnRenameWithNonLiveIssuer() {
    const std::string iss_name = "live-iss";
    const std::string iss_url  = "https://live-iss.example.com";

    AUTH_NAMESPACE::AuthConfig cfg0 = MakeConfig(iss_name, iss_url);
    AUTH_NAMESPACE::AuthPolicy p_old;
    p_old.name = "policy-old";
    p_old.enabled = true;
    p_old.applies_to = {"/secure/"};
    p_old.issuers = {iss_name};
    cfg0.policies.push_back(p_old);
    cfg0.enabled = true;

    auto mgr = MakeManager(cfg0);
    {
        std::string err;
        if (!ReloadAndCommit(*mgr, cfg0, err)) { mgr->Stop(); return false; }
    }
    auto snap0 = mgr->SnapshotAll();
    if (snap0.policy_count == 0) { mgr->Stop(); return false; }

    // Staged config: same live issuer (topology unchanged so AuthManager::
    // Reload accepts) but operator has renamed "policy-old" → "policy-new"
    // AND references a non-live issuer name. The ADD defers; the REMOVE
    // must preserve live coverage for /secure/.
    AUTH_NAMESPACE::AuthConfig cfg1 = MakeConfig(iss_name, iss_url);
    cfg1.enabled = true;
    AUTH_NAMESPACE::AuthPolicy p_new;
    p_new.name = "policy-new";
    p_new.enabled = true;
    p_new.applies_to = {"/secure/"};
    p_new.issuers = {"staged-only-issuer"};  // NOT in live issuer set
    cfg1.policies.push_back(p_new);

    std::string err;
    bool ok = ReloadAndCommit(*mgr, cfg1, err);
    auto snap1 = mgr->SnapshotAll();
    mgr->Stop();

    // Live policy preserved (policy_count >= 1) instead of dropping to 0.
    return ok && snap1.policy_count >= 1;
}

// ---------------------------------------------------------------------------
// Test 20: pure removal still drops. A reload that ONLY removes a policy
// (no deferred add in the same cycle) must drop the live entry — the
// migration-preserve heuristic must not regress the pure-removal path.
// ---------------------------------------------------------------------------
static bool TestReloadPureRemovalStillDrops() {
    const std::string iss_name = "live-iss-rm2";
    const std::string iss_url  = "https://rm2.example.com";

    AUTH_NAMESPACE::AuthConfig cfg0 = MakeConfig(iss_name, iss_url);
    AUTH_NAMESPACE::AuthPolicy p;
    p.name = "to-remove";
    p.enabled = true;
    p.applies_to = {"/x/"};
    p.issuers = {iss_name};
    cfg0.policies.push_back(p);
    cfg0.enabled = true;

    auto mgr = MakeManager(cfg0);
    {
        std::string err;
        if (!ReloadAndCommit(*mgr, cfg0, err)) { mgr->Stop(); return false; }
    }

    // No adds, no deferred — pure removal.
    AUTH_NAMESPACE::AuthConfig cfg1 = MakeConfig(iss_name, iss_url);
    cfg1.enabled = true;  // empty policies

    std::string err;
    bool ok = ReloadAndCommit(*mgr, cfg1, err);
    auto snap = mgr->SnapshotAll();
    mgr->Stop();

    return ok && snap.policy_count == 0;
}

// ---------------------------------------------------------------------------
// Test 21: ValidateHotReloadable hard-rejects auth.forward with a
// reserved header name. Without this, a SIGHUP that typed a reserved
// subject_header would warn via the outer Validate catch-all and STILL
// commit a live snapshot — startup would have rejected the same config.
// ---------------------------------------------------------------------------
static bool TestValidateHotReloadableRejectsAuthForward() {
    const std::string json = R"({
        "upstreams": [{"name":"x","host":"127.0.0.1","port":80}],
        "auth": {
            "enabled": false,
            "issuers": {
                "a": {
                    "issuer_url": "https://a.example",
                    "upstream": "x",
                    "mode": "jwt",
                    "algorithms": ["RS256"]
                }
            },
            "forward": { "subject_header": "Via" }
        }
    })";
    ServerConfig cfg = ConfigLoader::LoadFromString(json);
    bool threw = false;
    std::string msg;
    try {
        ConfigLoader::ValidateHotReloadable(cfg, {"x"}, {"a"});
    } catch (const std::invalid_argument& e) {
        threw = true;
        msg = e.what();
    }
    return threw && msg.find("reserved") != std::string::npos;
}

// ---------------------------------------------------------------------------
// Test 22: ValidateHotReloadable hard-rejects duplicate top-level policy
// names. A SIGHUP that introduces a duplicate must not slip to Commit.
// ---------------------------------------------------------------------------
static bool TestValidateHotReloadableRejectsDuplicatePolicyName() {
    ServerConfig cfg;
    UpstreamConfig u;
    u.name = "x";
    u.host = "127.0.0.1";
    u.port = 80;
    cfg.upstreams.push_back(u);

    AUTH_NAMESPACE::IssuerConfig ic;
    ic.name = "a";
    ic.issuer_url = "https://a.example";
    ic.upstream = "x";
    ic.mode = "jwt";
    ic.algorithms = {"RS256"};
    cfg.auth.issuers["a"] = ic;

    AUTH_NAMESPACE::AuthPolicy p1;
    p1.name = "dup";
    p1.enabled = true;
    p1.applies_to = {"/one/"};
    p1.issuers = {"a"};
    cfg.auth.policies.push_back(p1);

    AUTH_NAMESPACE::AuthPolicy p2;
    p2.name = "dup";  // duplicate name
    p2.enabled = true;
    p2.applies_to = {"/two/"};
    p2.issuers = {"a"};
    cfg.auth.policies.push_back(p2);

    bool threw = false;
    std::string msg;
    try {
        ConfigLoader::ValidateHotReloadable(cfg, {"x"}, {"a"});
    } catch (const std::invalid_argument& e) {
        threw = true;
        msg = e.what();
    }
    return threw && msg.find("duplicated") != std::string::npos;
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
    RunOne("AuthReload: forward subject_header update takes effect",
           TestReloadForwardSubjectHeader);
    RunOne("AuthReload: forward scopes_header update takes effect",
           TestReloadForwardScopesHeader);
    RunOne("AuthReload: forward raw_jwt_header enabled via Reload",
           TestReloadRawJwtHeaderEnabled);
    RunOne("AuthReload: leeway_sec is a reloadable field",
           TestReloadLeewaySec);
    RunOne("AuthReload: algorithms list update accepted",
           TestReloadAlgorithmsUpdate);
    RunOne("AuthReload: generation counter bumps on each Reload",
           TestReloadBumpsGeneration);
    RunOne("AuthReload: issuer added - topology change rejected",
           TestReloadRejectsIssuerAdded);
    RunOne("AuthReload: issuer removed - topology change rejected",
           TestReloadRejectsIssuerRemoved);
    RunOne("AuthReload: mismatched issuer name - rejected",
           TestReloadRejectsMismatchedIssuerName);
    RunOne("AuthReload: issuer_url change - topology rejected",
           TestReloadRejectsIssuerUrlChange);
    RunOne("AuthReload: discovery flag change - topology rejected",
           TestReloadRejectsDiscoveryChange);
    RunOne("AuthReload: static jwks_uri change - topology rejected",
           TestReloadRejectsStaticJwksUriChange);
    RunOne("AuthReload: mode field change - topology rejected",
           TestReloadRejectsModeChange);
    RunOne("AuthReload: ForwardConfig stable under concurrent Reload",
           TestForwardConfigStableUnderConcurrentReload);
    RunOne("AuthReload: RebuildPolicyListFromLiveSources updates entries",
           TestRebuildPolicyListFromLiveSources);
    RunOne("AuthReload: ValidateAuthPrefixCollisions rejects collisions",
           TestValidateAuthPrefixCollisionsRejectsCollisions);
    RunOne("AuthReload: removed top-level policy dropped from matcher",
           TestReloadDropsRemovedTopLevelPolicy);
    RunOne("AuthReload: collision check scoped to live upstreams",
           TestValidateAuthPrefixCollisionsScopedByLive);
    RunOne("AuthReload: accepts mixed-case HTTPS scheme",
           TestConfigLoaderAcceptsMixedCaseHttpsScheme);
    RunOne("AuthReload: preserves live on rename with non-live issuer",
           TestReloadPreservesLiveOnRenameWithNonLiveIssuer);
    RunOne("AuthReload: pure removal still drops",
           TestReloadPureRemovalStillDrops);
    RunOne("AuthReload: ValidateHotReloadable rejects auth.forward reserved",
           TestValidateHotReloadableRejectsAuthForward);
    RunOne("AuthReload: ValidateHotReloadable rejects duplicate policy name",
           TestValidateHotReloadableRejectsDuplicatePolicyName);
}

}  // namespace AuthReloadTests
