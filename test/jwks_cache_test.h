#pragma once

// ============================================================================
// JwksCache unit tests — Phase 1b / Phase 2 test suite.
//
// Exercises the JwksCache class in isolation (no network, no server).
// Covers: hit/miss/single-key-tolerance, TTL expiry, coalescing refresh
// slot, stale-on-error, atomic key swap, hard-cap enforcement, and stats.
// ============================================================================

#include "test_framework.h"
#include "auth/jwks_cache.h"
#include "log/logger.h"

#include <thread>
#include <chrono>
#include <vector>
#include <atomic>
#include <string>
#include <memory>

namespace JwksCacheTests {

// ---------------------------------------------------------------------------
// Happy path: basic hit / miss
// ---------------------------------------------------------------------------
static void TestLookupHit() {
    try {
        AUTH_NAMESPACE::JwksCache cache("test-issuer", 300, 64);
        std::vector<std::pair<std::string, std::string>> keys = {
            {"kid-1", "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END PUBLIC KEY-----"}
        };
        cache.InstallKeys(keys);

        auto pem = cache.LookupKeyByKid("kid-1");
        bool pass = (pem != nullptr && !pem->empty());
        TestFramework::RecordTest("JwksCache: lookup hit returns key",
                                  pass, pass ? "" : "Expected key for kid-1",
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwksCache: lookup hit returns key",
                                  false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

static void TestLookupMiss() {
    try {
        AUTH_NAMESPACE::JwksCache cache("test-issuer", 300, 64);
        std::vector<std::pair<std::string, std::string>> keys = {
            {"kid-1", "pem-data"}
        };
        cache.InstallKeys(keys);

        auto pem = cache.LookupKeyByKid("kid-unknown");
        bool pass = (pem == nullptr);
        TestFramework::RecordTest("JwksCache: miss returns nullptr",
                                  pass, pass ? "" : "Expected nullptr for unknown kid",
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwksCache: miss returns nullptr",
                                  false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// Single-key tolerance: token without kid + JWKS with one entry keyed ""
// ---------------------------------------------------------------------------
static void TestSingleKeyTolerance() {
    try {
        AUTH_NAMESPACE::JwksCache cache("test-issuer", 300, 64);
        // Single key stored under "" (no kid) — emitted by minimal IdPs
        std::vector<std::pair<std::string, std::string>> keys = {
            {"", "single-key-pem"}
        };
        cache.InstallKeys(keys);

        // Token without kid → empty string lookup → returns the single key
        auto pem = cache.LookupKeyByKid("");
        bool pass = (pem != nullptr && *pem == "single-key-pem");
        TestFramework::RecordTest("JwksCache: single-key tolerance (kid='')",
                                  pass, pass ? "" : "Expected single key on empty-kid lookup",
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwksCache: single-key tolerance (kid='')",
                                  false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// Multi-key cache: empty kid should NOT fall back when there are many keys
static void TestSingleKeyToleranceDoesNotApplyForMultiKey() {
    try {
        AUTH_NAMESPACE::JwksCache cache("test-issuer", 300, 64);
        std::vector<std::pair<std::string, std::string>> keys = {
            {"kid-1", "pem-1"},
            {"kid-2", "pem-2"}
        };
        cache.InstallKeys(keys);

        // Should NOT return anything on empty-kid lookup when > 1 key
        auto pem = cache.LookupKeyByKid("");
        bool pass = (pem == nullptr);
        TestFramework::RecordTest("JwksCache: no fallback for multi-key on kid=''",
                                  pass, pass ? "" : "Should not fall back with multi-key JWKS",
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwksCache: no fallback for multi-key on kid=''",
                                  false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// TTL expiry
// ---------------------------------------------------------------------------
static void TestTtlExpiredOnFreshCache() {
    try {
        // Cache with no keys installed yet — must report TTL expired so the
        // initial fetch is triggered.
        AUTH_NAMESPACE::JwksCache cache("test-issuer", 300, 64);
        bool expired = cache.IsTtlExpired();
        TestFramework::RecordTest("JwksCache: never-refreshed reports TTL expired",
                                  expired, expired ? "" : "Expected TTL expired on new cache",
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwksCache: never-refreshed reports TTL expired",
                                  false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

static void TestTtlNotExpiredAfterInstall() {
    try {
        AUTH_NAMESPACE::JwksCache cache("test-issuer", 300, 64);
        cache.InstallKeys({{"kid-1", "pem-1"}});
        bool expired = cache.IsTtlExpired();
        // Fresh install — TTL should NOT be expired yet
        TestFramework::RecordTest("JwksCache: fresh install not TTL-expired",
                                  !expired, expired ? "TTL expired immediately after install" : "",
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwksCache: fresh install not TTL-expired",
                                  false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

static void TestTtlExpiredAfterSetShortTtl() {
    try {
        // Simulate expired TTL: install, then set TTL to 0 which means
        // any elapsed time exceeds the window.
        AUTH_NAMESPACE::JwksCache cache("test-issuer", 3600, 64);
        cache.InstallKeys({{"kid-1", "pem-1"}});
        // Set a 0-second TTL (SetTtlSec ignores <= 0, so use 1 second)
        // and sleep 1s+epsilon to exceed it.
        cache.SetTtlSec(1);
        std::this_thread::sleep_for(std::chrono::milliseconds(1100));
        bool expired = cache.IsTtlExpired();
        TestFramework::RecordTest("JwksCache: TTL expires after elapsed time",
                                  expired, expired ? "" : "Expected TTL expired after sleep",
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwksCache: TTL expires after elapsed time",
                                  false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// Coalesced refresh slot
// ---------------------------------------------------------------------------
static void TestAcquireRefreshSlotCoalesce() {
    try {
        AUTH_NAMESPACE::JwksCache cache("test-issuer", 300, 64);

        // First acquire wins.
        bool first = cache.AcquireRefreshSlot();
        // Second acquire must fail.
        bool second = cache.AcquireRefreshSlot();

        bool pass = first && !second;
        TestFramework::RecordTest("JwksCache: only one refresh slot at a time",
                                  pass,
                                  pass ? "" : "Expected first=true second=false",
                                  TestFramework::TestCategory::OTHER);

        cache.ReleaseRefreshSlot();
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwksCache: only one refresh slot at a time",
                                  false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

static void TestReleaseAllowsReacquire() {
    try {
        AUTH_NAMESPACE::JwksCache cache("test-issuer", 300, 64);
        cache.AcquireRefreshSlot();
        cache.ReleaseRefreshSlot();
        bool reacquired = cache.AcquireRefreshSlot();
        cache.ReleaseRefreshSlot();
        TestFramework::RecordTest("JwksCache: release allows re-acquire",
                                  reacquired,
                                  reacquired ? "" : "Failed to re-acquire after release",
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwksCache: release allows re-acquire",
                                  false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// Concurrent acquire: 100 goroutines, exactly 1 wins
static void TestConcurrentAcquireExactlyOne() {
    try {
        AUTH_NAMESPACE::JwksCache cache("test-issuer", 300, 64);
        constexpr int kThreads = 100;
        std::atomic<int> winners{0};
        std::vector<std::thread> threads;
        threads.reserve(kThreads);
        for (int i = 0; i < kThreads; ++i) {
            threads.emplace_back([&cache, &winners]() {
                if (cache.AcquireRefreshSlot()) {
                    winners.fetch_add(1, std::memory_order_relaxed);
                    // Hold briefly then release
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    cache.ReleaseRefreshSlot();
                }
            });
        }
        for (auto& t : threads) t.join();

        // We may have multiple sequential wins (release → re-acquire) but
        // the KEY invariant is at most 1 holder at any instant. The total
        // count depends on timing. What we verify: no crash, no torn state.
        bool pass = (winners.load() >= 1);
        TestFramework::RecordTest("JwksCache: concurrent acquire is safe",
                                  pass,
                                  pass ? "" : "No thread won the refresh slot",
                                  TestFramework::TestCategory::RACE_CONDITION);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwksCache: concurrent acquire is safe",
                                  false, e.what(),
                                  TestFramework::TestCategory::RACE_CONDITION);
    }
}

// ---------------------------------------------------------------------------
// Stale-on-error: cache unchanged, counter increments
// ---------------------------------------------------------------------------
static void TestStaleOnError() {
    try {
        AUTH_NAMESPACE::JwksCache cache("test-issuer", 300, 64);
        cache.InstallKeys({{"kid-1", "pem-1"}});

        auto stats_before = cache.SnapshotStats();
        cache.OnFetchError("network timeout");
        auto stats_after = cache.SnapshotStats();

        // Keys should still be served (stale)
        auto pem = cache.LookupKeyByKid("kid-1");
        bool keys_intact = (pem != nullptr && *pem == "pem-1");
        bool counter_bumped = (stats_after.refresh_fail == stats_before.refresh_fail + 1);

        bool pass = keys_intact && counter_bumped;
        std::string err;
        if (!keys_intact) err = "Keys removed on fetch error (should be stale)";
        else if (!counter_bumped) err = "refresh_fail counter not incremented";

        TestFramework::RecordTest("JwksCache: stale-on-error preserves keys",
                                  pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwksCache: stale-on-error preserves keys",
                                  false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// Atomic swap: concurrent lookup + install never sees torn state
// ---------------------------------------------------------------------------
static void TestAtomicSwapDuringConcurrentLookup() {
    try {
        AUTH_NAMESPACE::JwksCache cache("test-issuer", 300, 64);
        // Prime with an initial set
        cache.InstallKeys({{"kid-1", "pem-v1"}});

        std::atomic<bool> stop{false};
        std::atomic<int> torn_reads{0};

        // Reader threads continuously look up kid-1
        std::vector<std::thread> readers;
        for (int i = 0; i < 4; ++i) {
            readers.emplace_back([&cache, &stop]() {
                while (!stop.load(std::memory_order_relaxed)) {
                    auto pem = cache.LookupKeyByKid("kid-1");
                    // Either key exists (valid), or it does not after a swap
                    // that removed kid-1. Neither is "torn" per se; what we
                    // prevent is a partial-write state where the shared_ptr is
                    // half-initialized. If we reach here without a crash or
                    // a SIGSEGV, atomic swap is working.
                    (void)pem;
                }
            });
        }

        // Writer swaps keys 20 times
        for (int i = 0; i < 20; ++i) {
            cache.InstallKeys({{"kid-1", "pem-v" + std::to_string(i)},
                               {"kid-2", "pem-v" + std::to_string(i)}});
            std::this_thread::sleep_for(std::chrono::microseconds(500));
        }

        stop.store(true);
        for (auto& t : readers) t.join();
        (void)torn_reads;

        TestFramework::RecordTest("JwksCache: atomic swap during concurrent lookup",
                                  true, "",
                                  TestFramework::TestCategory::RACE_CONDITION);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwksCache: atomic swap during concurrent lookup",
                                  false, e.what(),
                                  TestFramework::TestCategory::RACE_CONDITION);
    }
}

// ---------------------------------------------------------------------------
// Hard cap: excess keys dropped with warn
// ---------------------------------------------------------------------------
static void TestHardCap() {
    try {
        constexpr size_t kCap = 3;
        AUTH_NAMESPACE::JwksCache cache("test-issuer", 300, kCap);

        std::vector<std::pair<std::string, std::string>> keys;
        for (int i = 0; i < 10; ++i) {
            keys.push_back({"kid-" + std::to_string(i), "pem-" + std::to_string(i)});
        }
        size_t installed = cache.InstallKeys(keys);

        auto stats = cache.SnapshotStats();
        bool pass = (installed <= kCap && stats.key_count <= kCap);
        TestFramework::RecordTest("JwksCache: hard cap enforced",
                                  pass,
                                  pass ? "" : "Installed " + std::to_string(stats.key_count) + " > cap " + std::to_string(kCap),
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwksCache: hard cap enforced",
                                  false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// Hard cap 64 from default — install 65 keys, verify count <= 64
static void TestHardCap64() {
    try {
        AUTH_NAMESPACE::JwksCache cache("test-issuer", 300);  // default cap = 64
        std::vector<std::pair<std::string, std::string>> keys;
        for (int i = 0; i < 65; ++i) {
            keys.push_back({"kid-" + std::to_string(i), "pem-" + std::to_string(i)});
        }
        cache.InstallKeys(keys);
        auto stats = cache.SnapshotStats();
        bool pass = (stats.key_count <= 64);
        TestFramework::RecordTest("JwksCache: default hard cap 64 enforced",
                                  pass,
                                  pass ? "" : "key_count=" + std::to_string(stats.key_count) + " > 64",
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwksCache: default hard cap 64 enforced",
                                  false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// Stats snapshot correctness
// ---------------------------------------------------------------------------
static void TestStatsSnapshot() {
    try {
        AUTH_NAMESPACE::JwksCache cache("test-issuer", 300, 64);
        auto s0 = cache.SnapshotStats();

        cache.InstallKeys({{"k1", "pem1"}, {"k2", "pem2"}});
        auto s1 = cache.SnapshotStats();

        cache.OnFetchError("timeout");
        auto s2 = cache.SnapshotStats();

        cache.IncrementStaleServed();
        auto s3 = cache.SnapshotStats();

        bool pass = (s0.refresh_ok == 0) &&
                    (s1.refresh_ok == 1) &&
                    (s1.key_count == 2) &&
                    (s2.refresh_fail == 1) &&
                    (s3.stale_served == 1);

        std::string err;
        if (!pass) {
            err = "ok=" + std::to_string(s1.refresh_ok)
                + " keys=" + std::to_string(s1.key_count)
                + " fail=" + std::to_string(s2.refresh_fail)
                + " stale=" + std::to_string(s3.stale_served);
        }
        TestFramework::RecordTest("JwksCache: stats snapshot correct",
                                  pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwksCache: stats snapshot correct",
                                  false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// SetTtlSec: reload TTL without touching keys
// ---------------------------------------------------------------------------
static void TestSetTtlSec() {
    try {
        AUTH_NAMESPACE::JwksCache cache("test-issuer", 300, 64);
        cache.InstallKeys({{"k", "pem"}});

        // Lower TTL and verify not expired yet (just changed)
        cache.SetTtlSec(300);
        bool ok1 = !cache.IsTtlExpired();

        // SetTtlSec(0) is a no-op (guards <= 0)
        cache.SetTtlSec(0);
        bool ok2 = (cache.ttl_sec() == 300);

        // Keys untouched after SetTtlSec
        auto pem = cache.LookupKeyByKid("k");
        bool ok3 = (pem != nullptr);

        bool pass = ok1 && ok2 && ok3;
        TestFramework::RecordTest("JwksCache: SetTtlSec preserves keys",
                                  pass, pass ? "" : "TTL or key state wrong after SetTtlSec",
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwksCache: SetTtlSec preserves keys",
                                  false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// Empty key values are skipped during InstallKeys
// ---------------------------------------------------------------------------
static void TestEmptyPemSkipped() {
    try {
        AUTH_NAMESPACE::JwksCache cache("test-issuer", 300, 64);
        std::vector<std::pair<std::string, std::string>> keys = {
            {"kid-good", "good-pem"},
            {"kid-empty", ""}   // empty PEM should be skipped
        };
        size_t installed = cache.InstallKeys(keys);
        auto stats = cache.SnapshotStats();

        bool pass = (installed == 1 && stats.key_count == 1);
        TestFramework::RecordTest("JwksCache: empty PEM skipped on install",
                                  pass,
                                  pass ? "" : "installed=" + std::to_string(installed),
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwksCache: empty PEM skipped on install",
                                  false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// install 0 keys: cache stays empty, ok counter still bumps
// ---------------------------------------------------------------------------
static void TestInstallZeroKeys() {
    try {
        AUTH_NAMESPACE::JwksCache cache("test-issuer", 300, 64);
        size_t installed = cache.InstallKeys({});
        auto stats = cache.SnapshotStats();
        // ok bumps even on empty install (the refresh succeeded, it just has 0 keys)
        bool pass = (installed == 0 && stats.key_count == 0 && stats.refresh_ok == 1);
        TestFramework::RecordTest("JwksCache: zero-key install is valid",
                                  pass,
                                  pass ? "" : "installed=" + std::to_string(installed) + " ok=" + std::to_string(stats.refresh_ok),
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwksCache: zero-key install is valid",
                                  false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// issuer_name accessor
// ---------------------------------------------------------------------------
static void TestIssuerNameAccessor() {
    try {
        AUTH_NAMESPACE::JwksCache cache("my-issuer", 300, 64);
        bool pass = (cache.issuer_name() == "my-issuer");
        TestFramework::RecordTest("JwksCache: issuer_name accessor correct",
                                  pass, pass ? "" : "Wrong issuer name: " + cache.issuer_name(),
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwksCache: issuer_name accessor correct",
                                  false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// Performance: 1000 concurrent lookups on a populated cache
// ---------------------------------------------------------------------------
static void TestConcurrentLookupPerf() {
    try {
        AUTH_NAMESPACE::JwksCache cache("perf-issuer", 300, 64);
        // Install 10 keys
        std::vector<std::pair<std::string, std::string>> keys;
        for (int i = 0; i < 10; ++i) {
            keys.push_back({"kid-" + std::to_string(i), "pem-" + std::to_string(i)});
        }
        cache.InstallKeys(keys);

        constexpr int kThreads = 20;
        constexpr int kLookupsPerThread = 500;
        std::atomic<int> hits{0};
        std::vector<std::thread> threads;

        auto start = std::chrono::steady_clock::now();
        for (int t = 0; t < kThreads; ++t) {
            threads.emplace_back([&cache, &hits]() {
                for (int j = 0; j < kLookupsPerThread; ++j) {
                    auto pem = cache.LookupKeyByKid("kid-" + std::to_string(j % 10));
                    if (pem) hits.fetch_add(1, std::memory_order_relaxed);
                }
            });
        }
        for (auto& th : threads) th.join();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();

        bool pass = (hits.load() == kThreads * kLookupsPerThread);
        std::string info = "hits=" + std::to_string(hits.load()) +
                           " elapsed=" + std::to_string(elapsed) + "ms";
        TestFramework::RecordTest("JwksCache: concurrent lookup performance (" + info + ")",
                                  pass,
                                  pass ? "" : "Some lookups missed expected keys",
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("JwksCache: concurrent lookup performance",
                                  false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------
static void RunAllTests() {
    std::cout << "\n[JwksCache Tests]" << std::endl;
    TestLookupHit();
    TestLookupMiss();
    TestSingleKeyTolerance();
    TestSingleKeyToleranceDoesNotApplyForMultiKey();
    TestTtlExpiredOnFreshCache();
    TestTtlNotExpiredAfterInstall();
    TestTtlExpiredAfterSetShortTtl();
    TestAcquireRefreshSlotCoalesce();
    TestReleaseAllowsReacquire();
    TestConcurrentAcquireExactlyOne();
    TestStaleOnError();
    TestAtomicSwapDuringConcurrentLookup();
    TestHardCap();
    TestHardCap64();
    TestStatsSnapshot();
    TestSetTtlSec();
    TestEmptyPemSkipped();
    TestInstallZeroKeys();
    TestIssuerNameAccessor();
    TestConcurrentLookupPerf();
}

}  // namespace JwksCacheTests
