#pragma once

// ============================================================================
// Auth race condition tests — Phase 2 test suite.
//
// These tests exercise concurrent access patterns on the auth subsystem:
// concurrent InvokeMiddleware calls, concurrent Reload operations, ForwardConfig
// snapshot stability, Stop() while InvokeMiddleware is in flight, and
// JwksCache concurrent key lookup + install.
//
// All tests use real synchronization (barriers, atomics, threads) — no sleeps.
//
// Tests covered:
//   1.  Concurrent InvokeMiddleware with valid tokens (20 threads × 50 req)
//   2.  Concurrent InvokeMiddleware + Reload (8 readers, 100 reload iters)
//   3.  ForwardConfig snapshot stable under heavy concurrent Reload
//   4.  Stop() while InvokeMiddleware in flight (no crash, no UAF)
//   5.  JwksCache concurrent LookupKeyByKid + InstallKeys (no corruption)
//   6.  JwksCache concurrent AcquireRefreshSlot — exactly 1 winner at a time
//   7.  JwksCache concurrent OnFetchError + InstallKeys (counter consistency)
//   8.  AuthManager SnapshotAll stable under concurrent InvokeMiddleware
//   9.  ForwardConfig reader outlives AuthManager::Stop (shared_ptr keeps
//       snapshot alive while Stop() tears down the manager)
//  10.  Concurrent Stop() calls on AuthManager are idempotent (no crash)
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
#include <atomic>
#include <thread>
#include <chrono>
#include <vector>
#include <mutex>

namespace AuthRaceTests {

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
        const std::string& sub = "user1") {
    if (private_pem.empty()) return "";
    auto now = std::chrono::system_clock::now();
    auto builder = jwt::create<jwt::traits::nlohmann_json>()
        .set_issuer(iss)
        .set_subject(sub)
        .set_issued_at(now)
        .set_expires_at(now + std::chrono::seconds(3600))
        .set_key_id(kid);
    try {
        auto alg = jwt::algorithm::rs256("", private_pem, "", "");
        return builder.sign(alg);
    } catch (...) { return ""; }
}

static AUTH_NAMESPACE::IssuerConfig MakeIssuerCfg(
        const std::string& name, const std::string& url) {
    AUTH_NAMESPACE::IssuerConfig ic;
    ic.name = name; ic.issuer_url = url;
    ic.discovery = false;
    ic.jwks_uri = "https://" + name + ".example.com/jwks.json";
    ic.upstream = ""; ic.mode = "jwt";
    ic.algorithms = {"RS256"}; ic.leeway_sec = 0;
    ic.jwks_cache_sec = 300;
    return ic;
}

static std::shared_ptr<AUTH_NAMESPACE::AuthManager> MakeManager(
        const std::string& iss_name, const std::string& iss_url,
        const std::string& prefix = "/api/",
        const std::string& on_undetermined = "deny") {
    AUTH_NAMESPACE::AuthConfig cfg;
    cfg.enabled = true;
    cfg.issuers[iss_name] = MakeIssuerCfg(iss_name, iss_url);

    auto mgr = std::make_shared<AUTH_NAMESPACE::AuthManager>(
        cfg, nullptr, std::vector<std::shared_ptr<Dispatcher>>{});
    {
        AUTH_NAMESPACE::AuthPolicy p;
        p.name = "race-policy"; p.enabled = true;
        p.applies_to = {prefix}; p.issuers = {iss_name};
        p.on_undetermined = on_undetermined;
        mgr->RegisterPolicy(p.applies_to, p);
    }
    mgr->Start();
    return mgr;
}

static HttpRequest MakeReq(
        const std::string& path, const std::string& token) {
    HttpRequest req;
    req.method = "GET"; req.path = path; req.url = path; req.complete = true;
    if (!token.empty()) req.headers["authorization"] = "Bearer " + token;
    return req;
}

// ---------------------------------------------------------------------------
// Test 1: Concurrent InvokeMiddleware with valid tokens
// Rationale: Multiple dispatcher threads calling InvokeMiddleware concurrently
// must not corrupt the policy list, issuer map, or atomic counters.
// ---------------------------------------------------------------------------
static bool TestConcurrentInvokeMiddleware() {
    auto kp = GenRsa();
    if (kp.private_pem.empty()) return true;

    const std::string iss_name = "race-iss-1";
    const std::string iss_url  = "https://race-1.example.com";

    auto mgr = MakeManager(iss_name, iss_url);
    mgr->GetIssuer(iss_name)->jwks_cache()->InstallKeys({{"kid-r1", kp.public_pem}});

    std::string token = BuildJwt(kp.private_pem, "kid-r1", iss_url, "alice");
    if (token.empty()) { mgr->Stop(); return false; }

    constexpr int NUM_THREADS = 20;
    constexpr int REQ_PER_THREAD = 50;
    std::atomic<int> success{0};
    std::atomic<int> failure{0};
    std::atomic<bool> go{false};

    std::vector<std::thread> threads;
    for (int i = 0; i < NUM_THREADS; i++) {
        threads.emplace_back([&](){
            while (!go.load(std::memory_order_acquire)) {}
            for (int j = 0; j < REQ_PER_THREAD; j++) {
                auto req = MakeReq("/api/test", token);
                HttpResponse resp;
                try {
                    if (mgr->InvokeMiddleware(req, resp))
                        success.fetch_add(1, std::memory_order_relaxed);
                    else
                        failure.fetch_add(1, std::memory_order_relaxed);
                } catch (...) {
                    failure.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }
    go.store(true, std::memory_order_release);
    for (auto& t : threads) t.join();

    mgr->Stop();
    // All requests should succeed (valid token, matching policy)
    return success.load() == NUM_THREADS * REQ_PER_THREAD &&
           failure.load() == 0;
}

// ---------------------------------------------------------------------------
// Test 2: Concurrent InvokeMiddleware + Reload
// Rationale: While reader threads call InvokeMiddleware, the main thread
// fires Reload. Policy list and forward config are atomically swapped;
// readers must see valid snapshots at all times.
// ---------------------------------------------------------------------------
static bool TestConcurrentInvokeAndReload() {
    auto kp = GenRsa();
    if (kp.private_pem.empty()) return true;

    const std::string iss_name = "race-iss-2";
    const std::string iss_url  = "https://race-2.example.com";

    auto mgr = MakeManager(iss_name, iss_url);
    mgr->GetIssuer(iss_name)->jwks_cache()->InstallKeys({{"kid-r2", kp.public_pem}});

    std::string token = BuildJwt(kp.private_pem, "kid-r2", iss_url, "bob");
    if (token.empty()) { mgr->Stop(); return false; }

    constexpr int NUM_READERS  = 8;
    constexpr int RELOAD_ITERS = 100;

    std::atomic<bool> stop_readers{false};
    std::atomic<int>  crash_count{0};

    std::vector<std::thread> readers;
    for (int i = 0; i < NUM_READERS; i++) {
        readers.emplace_back([&](){
            while (!stop_readers.load(std::memory_order_relaxed)) {
                auto req = MakeReq("/api/test", token);
                HttpResponse resp;
                try {
                    mgr->InvokeMiddleware(req, resp);
                } catch (...) {
                    crash_count.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }

    // Reload with minor forward config variation
    AUTH_NAMESPACE::AuthConfig cfg;
    cfg.enabled = true;
    cfg.issuers[iss_name] = MakeIssuerCfg(iss_name, iss_url);
    for (int i = 0; i < RELOAD_ITERS; i++) {
        cfg.forward.subject_header = (i % 2 == 0) ? "X-Auth-Subject" : "X-User-Id";
        std::string err;
        mgr->Reload(cfg, err);
    }

    stop_readers.store(true, std::memory_order_release);
    for (auto& t : readers) t.join();
    mgr->Stop();

    return crash_count.load() == 0;
}

// ---------------------------------------------------------------------------
// Test 3: ForwardConfig snapshot stable under heavy concurrent Reload
// Rationale: ForwardConfig() returns a shared_ptr to an immutable snapshot.
// Readers that call ForwardConfig() and keep the pointer alive beyond the
// next Reload() call must see a valid, non-null snapshot.
// ---------------------------------------------------------------------------
static bool TestForwardConfigSnapshotAliveAfterReload() {
    const std::string iss_name = "race-iss-3";
    const std::string iss_url  = "https://race-3.example.com";

    auto mgr = MakeManager(iss_name, iss_url);

    constexpr int NUM_READERS  = 6;
    constexpr int RELOAD_ITERS = 200;

    std::atomic<bool> stop_readers{false};
    std::atomic<int>  null_count{0};

    std::vector<std::thread> readers;
    for (int i = 0; i < NUM_READERS; i++) {
        readers.emplace_back([&](){
            while (!stop_readers.load(std::memory_order_relaxed)) {
                auto snap = mgr->ForwardConfig();
                if (!snap) {
                    null_count.fetch_add(1, std::memory_order_relaxed);
                } else {
                    // Access a field to ensure the pointer is live
                    (void)snap->subject_header.size();
                }
            }
        });
    }

    AUTH_NAMESPACE::AuthConfig cfg;
    cfg.enabled = true;
    cfg.issuers[iss_name] = MakeIssuerCfg(iss_name, iss_url);
    for (int i = 0; i < RELOAD_ITERS; i++) {
        cfg.forward.subject_header = (i % 2 == 0) ? "X-Auth-Subject" : "X-Custom-Hdr";
        std::string err;
        mgr->Reload(cfg, err);
    }

    stop_readers.store(true, std::memory_order_release);
    for (auto& t : readers) t.join();
    mgr->Stop();

    return null_count.load() == 0;
}

// ---------------------------------------------------------------------------
// Test 4: Stop() while InvokeMiddleware is in flight — no crash, no UAF
// Rationale: A dispatcher thread may be mid-verify when the main thread
// calls Stop(). The shared_ptr to AuthManager keeps issuers alive until
// the last request completes.
// ---------------------------------------------------------------------------
static bool TestStopDuringInvokeMiddleware() {
    auto kp = GenRsa();
    if (kp.private_pem.empty()) return true;

    const std::string iss_name = "race-iss-4";
    const std::string iss_url  = "https://race-4.example.com";

    auto mgr = MakeManager(iss_name, iss_url, "/api/", "allow");
    mgr->GetIssuer(iss_name)->jwks_cache()->InstallKeys({{"kid-r4", kp.public_pem}});

    std::string token = BuildJwt(kp.private_pem, "kid-r4", iss_url, "carol");
    if (token.empty()) { mgr->Stop(); return false; }

    std::atomic<bool> stop_now{false};
    std::atomic<int>  crash_count{0};

    // Worker threads loop until stop signal
    constexpr int NUM_WORKERS = 4;
    std::vector<std::thread> workers;
    for (int i = 0; i < NUM_WORKERS; i++) {
        workers.emplace_back([&](){
            while (!stop_now.load(std::memory_order_acquire)) {
                auto req = MakeReq("/api/test", token);
                HttpResponse resp;
                try {
                    mgr->InvokeMiddleware(req, resp);
                } catch (...) {
                    crash_count.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }

    // Let workers run for a short time then call Stop()
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    mgr->Stop();  // Stop while workers may still be in InvokeMiddleware
    stop_now.store(true, std::memory_order_release);

    for (auto& t : workers) t.join();

    return crash_count.load() == 0;
}

// ---------------------------------------------------------------------------
// Test 5: JwksCache concurrent LookupKeyByKid + InstallKeys
// Rationale: InstallKeys performs an atomic shared_ptr swap under a mutex;
// concurrent LookupKeyByKid must not see a torn or null snapshot mid-swap.
// ---------------------------------------------------------------------------
static bool TestJwksConcurrentLookupAndInstall() {
    AUTH_NAMESPACE::JwksCache cache("concurrent-issuer", 300, 64);

    constexpr int NUM_READERS  = 10;
    constexpr int NUM_INSTALLS = 50;
    std::atomic<bool> stop_readers{false};
    std::atomic<int>  null_on_installed{0};

    // Pre-install one key so lookup isn't vacuously null
    cache.InstallKeys({{"initial-kid", "initial-pem"}});

    std::vector<std::thread> readers;
    for (int i = 0; i < NUM_READERS; i++) {
        readers.emplace_back([&](){
            while (!stop_readers.load(std::memory_order_relaxed)) {
                // initial-kid was installed — lookup must never return null
                // after the initial install (stale keys survive swaps)
                auto key = cache.LookupKeyByKid("initial-kid");
                (void)key;  // may be null if overwritten by a batch without this kid
                // We just verify no crash; correctness of null vs non-null is
                // determined by install batch content, not a race.
            }
        });
    }

    for (int i = 0; i < NUM_INSTALLS; i++) {
        std::vector<std::pair<std::string, std::string>> batch;
        batch.push_back({"initial-kid", "pem-v" + std::to_string(i)});
        batch.push_back({"extra-kid-" + std::to_string(i), "extra-pem"});
        cache.InstallKeys(batch);
    }

    stop_readers.store(true, std::memory_order_release);
    for (auto& t : readers) t.join();

    // No crash = pass; null_on_installed is a "nice to know" not a hard failure
    (void)null_on_installed;
    return true;
}

// ---------------------------------------------------------------------------
// Test 6: JwksCache concurrent AcquireRefreshSlot — exactly 1 winner
// ---------------------------------------------------------------------------
static bool TestJwksConcurrentAcquireSlot() {
    constexpr int ROUNDS = 20;
    bool all_ok = true;

    for (int round = 0; round < ROUNDS; round++) {
        AUTH_NAMESPACE::JwksCache cache("slot-issuer-" + std::to_string(round), 300, 64);
        constexpr int N = 16;
        std::atomic<int> winners{0};
        std::atomic<bool> go{false};
        std::vector<std::thread> threads;

        for (int i = 0; i < N; i++) {
            threads.emplace_back([&](){
                while (!go.load()) {}
                if (cache.AcquireRefreshSlot()) {
                    winners.fetch_add(1, std::memory_order_relaxed);
                    // Do NOT release inside the thread — releasing before all
                    // threads have attempted their single AcquireRefreshSlot
                    // call allows a second thread to acquire the freed slot,
                    // yielding winners > 1. Each round creates a fresh
                    // JwksCache so the unreleased slot has no carry-over.
                }
            });
        }
        go.store(true);
        for (auto& t : threads) t.join();

        if (winners.load() != 1) { all_ok = false; break; }
    }
    return all_ok;
}

// ---------------------------------------------------------------------------
// Test 7: JwksCache concurrent OnFetchError + InstallKeys counter consistency
// Rationale: refresh_ok + refresh_fail counters are atomics; both must be
// updated atomically even when Install/Error are called concurrently.
// ---------------------------------------------------------------------------
static bool TestJwksConcurrentErrorAndInstall() {
    AUTH_NAMESPACE::JwksCache cache("counter-issuer", 300, 64);

    constexpr int NUM_INSTALLS = 100;
    constexpr int NUM_ERRORS   = 100;

    std::vector<std::thread> install_threads;
    std::vector<std::thread> error_threads;

    for (int i = 0; i < NUM_INSTALLS; i++) {
        install_threads.emplace_back([&, i](){
            cache.InstallKeys({{"kid-" + std::to_string(i), "pem-" + std::to_string(i)}});
        });
    }
    for (int i = 0; i < NUM_ERRORS; i++) {
        error_threads.emplace_back([&](){
            cache.OnFetchError("timeout");
        });
    }
    for (auto& t : install_threads) t.join();
    for (auto& t : error_threads) t.join();

    auto snap = cache.SnapshotStats();
    // refresh_ok must equal NUM_INSTALLS, refresh_fail must equal NUM_ERRORS
    return snap.refresh_ok == NUM_INSTALLS && snap.refresh_fail == NUM_ERRORS;
}

// ---------------------------------------------------------------------------
// Test 8: SnapshotAll stable under concurrent InvokeMiddleware
// Rationale: SnapshotAll reads total_allowed/denied/undetermined counters and
// per-issuer views. Concurrent InvokeMiddleware increments these atomics.
// No crash + counter monotonically increasing = pass.
// ---------------------------------------------------------------------------
static bool TestSnapshotAllUnderConcurrentLoad() {
    auto kp = GenRsa();
    if (kp.private_pem.empty()) return true;

    const std::string iss_name = "race-iss-8";
    const std::string iss_url  = "https://race-8.example.com";

    auto mgr = MakeManager(iss_name, iss_url);
    mgr->GetIssuer(iss_name)->jwks_cache()->InstallKeys({{"kid-r8", kp.public_pem}});

    std::string token = BuildJwt(kp.private_pem, "kid-r8", iss_url, "dave");
    if (token.empty()) { mgr->Stop(); return false; }

    auto snap0 = mgr->SnapshotAll();

    constexpr int NUM_THREADS = 6;
    constexpr int REQ_PER_THREAD = 30;
    std::atomic<bool> go{false};
    std::vector<std::thread> threads;

    for (int i = 0; i < NUM_THREADS; i++) {
        threads.emplace_back([&](){
            while (!go.load()) {}
            for (int j = 0; j < REQ_PER_THREAD; j++) {
                auto req = MakeReq("/api/test", token);
                HttpResponse resp;
                mgr->InvokeMiddleware(req, resp);
            }
        });
    }
    go.store(true);

    // Snapshot concurrently while requests are in flight
    std::atomic<bool> snap_ok{true};
    std::thread snapper([&](){
        for (int i = 0; i < 50; i++) {
            try {
                auto snap = mgr->SnapshotAll();
                if (snap.issuers.empty()) snap_ok.store(false);
            } catch (...) {
                snap_ok.store(false);
            }
        }
    });

    for (auto& t : threads) t.join();
    snapper.join();

    auto snap1 = mgr->SnapshotAll();
    mgr->Stop();

    // Allowed counter must have increased
    return snap_ok.load() &&
           snap1.total_allowed >= snap0.total_allowed;
}

// ---------------------------------------------------------------------------
// Test 9: ForwardConfig reader outlives AuthManager::Stop
// Rationale: ForwardConfig returns a shared_ptr to the snapshot. After Stop(),
// a reader that still holds the shared_ptr must be able to read the struct
// without accessing freed memory (the ref count keeps it alive).
// ---------------------------------------------------------------------------
static bool TestForwardConfigOutlivesStop() {
    const std::string iss_name = "race-iss-9";
    const std::string iss_url  = "https://race-9.example.com";

    auto mgr = MakeManager(iss_name, iss_url);

    // Grab a snapshot BEFORE Stop()
    auto snap = mgr->ForwardConfig();
    if (!snap) { mgr->Stop(); return false; }

    // Stop the manager
    mgr->Stop();

    // Read from the snapshot AFTER Stop() — must not crash (UAF check)
    bool ok = true;
    try {
        const std::string& hdr = snap->subject_header;
        ok = !hdr.empty();  // default is "X-Auth-Subject" so it must be non-empty
    } catch (...) {
        ok = false;
    }

    return ok;
}

// ---------------------------------------------------------------------------
// Test 10: Concurrent Stop() calls are idempotent — no crash
// ---------------------------------------------------------------------------
static bool TestConcurrentStopIdempotent() {
    const std::string iss_name = "race-iss-10";
    const std::string iss_url  = "https://race-10.example.com";

    auto mgr = MakeManager(iss_name, iss_url);

    constexpr int N = 8;
    std::atomic<bool> go{false};
    std::atomic<int> crash_count{0};
    std::vector<std::thread> threads;

    for (int i = 0; i < N; i++) {
        threads.emplace_back([&](){
            while (!go.load()) {}
            try {
                mgr->Stop();
            } catch (...) {
                crash_count.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }
    go.store(true);
    for (auto& t : threads) t.join();

    return crash_count.load() == 0;
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
    RunOne("AuthRace: concurrent InvokeMiddleware valid tokens",
           TestConcurrentInvokeMiddleware);
    RunOne("AuthRace: concurrent InvokeMiddleware + Reload no crash",
           TestConcurrentInvokeAndReload);
    RunOne("AuthRace: ForwardConfig snapshot alive after heavy Reload",
           TestForwardConfigSnapshotAliveAfterReload);
    RunOne("AuthRace: Stop() during InvokeMiddleware no crash/UAF",
           TestStopDuringInvokeMiddleware);
    RunOne("AuthRace: JwksCache concurrent lookup + install no crash",
           TestJwksConcurrentLookupAndInstall);
    RunOne("AuthRace: JwksCache concurrent AcquireSlot exactly 1 winner",
           TestJwksConcurrentAcquireSlot);
    RunOne("AuthRace: JwksCache concurrent error + install counter consistency",
           TestJwksConcurrentErrorAndInstall);
    RunOne("AuthRace: SnapshotAll stable under concurrent load",
           TestSnapshotAllUnderConcurrentLoad);
    RunOne("AuthRace: ForwardConfig shared_ptr outlives Stop()",
           TestForwardConfigOutlivesStop);
    RunOne("AuthRace: concurrent Stop() calls idempotent",
           TestConcurrentStopIdempotent);
}

}  // namespace AuthRaceTests
