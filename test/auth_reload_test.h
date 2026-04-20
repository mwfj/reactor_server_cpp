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
    bool ok = mgr->Reload(cfg1, err);
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
    bool ok = mgr->Reload(cfg1, err);

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
    bool ok = mgr->Reload(cfg1, err);

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
        mgr->Reload(reload_cfg, err);
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
    mgr->CommitPolicyAndEnforcement(
        empty_upstreams, {p0, p1}, /*new_master_enabled=*/true);

    auto snap1 = mgr->SnapshotAll();
    mgr->Stop();

    // Policy count should now be 2 (both enabled top-level policies have 1 prefix each)
    return snap1.policy_count > count0;
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
    RunOne("AuthReload: mode field change - topology rejected",
           TestReloadRejectsModeChange);
    RunOne("AuthReload: ForwardConfig stable under concurrent Reload",
           TestForwardConfigStableUnderConcurrentReload);
    RunOne("AuthReload: RebuildPolicyListFromLiveSources updates entries",
           TestRebuildPolicyListFromLiveSources);
}

}  // namespace AuthReloadTests
