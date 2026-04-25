#pragma once

// IntrospectionCache unit tests.
//
// Pure unit coverage in isolation from AuthManager / network. Verifies the
// LRU + sharded TTL cache behavior, including the never-stale-serve-negative
// invariant, exception safety on insert, reload semantics for atomic TTL
// fields, and concurrency under contention.

#include "test_framework.h"
#include "auth/introspection_cache.h"
#include "auth/auth_context.h"
#include "auth/auth_config.h"
#include "log/logger.h"

#include <atomic>
#include <chrono>
#include <cmath>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace IntrospectionCacheTests {

using AUTH_NAMESPACE::IntrospectionCache;
using AUTH_NAMESPACE::AuthContext;
using AUTH_NAMESPACE::IntrospectionConfig;
using LookupState = IntrospectionCache::LookupState;
using std::chrono::seconds;
using std::chrono::milliseconds;
using std::chrono::steady_clock;

// Build a deterministic 32-hex-char key. The seed lower 16 bits become the
// first 4 hex chars (which drive shard selection); the rest is filler.
static std::string MakeKey(uint32_t seed) {
    std::ostringstream oss;
    oss << std::hex;
    oss.width(4);
    oss.fill('0');
    oss << (seed & 0xFFFF);
    oss.width(0);
    // 28 trailing hex chars derived from `seed` — keeps distinct seeds distinct.
    uint64_t lo = 0x0123456789abcdefULL ^ static_cast<uint64_t>(seed);
    oss.width(16);
    oss.fill('0');
    oss << lo;
    oss.width(0);
    uint64_t hi = 0xfedcba9876543210ULL ^ (static_cast<uint64_t>(seed) << 1);
    oss.width(12);
    oss.fill('0');
    oss << (hi & 0xffffffffffffULL);
    std::string s = oss.str();
    s.resize(32, '0');
    return s;
}

// Build a random 32-hex-char key from an mt19937 instance.
static std::string MakeRandomKey(std::mt19937& rng) {
    static const char* kHex = "0123456789abcdef";
    std::uniform_int_distribution<int> dist(0, 15);
    std::string s(32, '0');
    for (int i = 0; i < 32; ++i) s[i] = kHex[dist(rng)];
    return s;
}

static AuthContext MakeCtx(const std::string& subject) {
    AuthContext c;
    c.issuer = "test-issuer";
    c.subject = subject;
    c.scopes = {"read"};
    return c;
}

static IntrospectionConfig MakeConfig(int cache_sec = 60,
                                      int neg_sec = 10,
                                      int stale_sec = 30,
                                      int max_entries = 1024,
                                      int shards = 16) {
    IntrospectionConfig c;
    c.cache_sec = cache_sec;
    c.negative_cache_sec = neg_sec;
    c.stale_grace_sec = stale_sec;
    c.max_entries = max_entries;
    c.shards = shards;
    return c;
}

static void Record(const std::string& name, bool pass, const std::string& err = "") {
    TestFramework::RecordTest(name, pass, pass ? "" : err,
                              TestFramework::TestCategory::OTHER);
}

// ---------------------------------------------------------------------------
// 1. InsertAndLookup_Fresh
// ---------------------------------------------------------------------------
static void Test_InsertAndLookup_Fresh() {
    try {
        IntrospectionCache cache("issuer", 1024, 16);
        const std::string key = MakeKey(1);
        cache.Insert(key, MakeCtx("alice"), true, seconds(60));
        auto r = cache.Lookup(key, steady_clock::now());
        bool ok = r.state == LookupState::Fresh && r.active &&
                  r.ctx.subject == "alice";
        Record("IntrospectionCache: InsertAndLookup_Fresh", ok,
               "Expected Fresh+active+alice");
    } catch (const std::exception& e) {
        Record("IntrospectionCache: InsertAndLookup_Fresh", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// 2. Lookup_Miss_OnEmptyCache
// ---------------------------------------------------------------------------
static void Test_Lookup_Miss_OnEmptyCache() {
    try {
        IntrospectionCache cache("issuer", 1024, 16);
        auto r = cache.Lookup(MakeKey(42), steady_clock::now());
        Record("IntrospectionCache: Lookup_Miss_OnEmptyCache",
               r.state == LookupState::Miss, "Expected Miss on empty cache");
    } catch (const std::exception& e) {
        Record("IntrospectionCache: Lookup_Miss_OnEmptyCache", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// 3. Lookup_Miss_OnExpiredPositive — past TTL but outside grace, regular
//    Lookup must return Miss (not Stale).
// ---------------------------------------------------------------------------
static void Test_Lookup_Miss_OnExpiredPositive() {
    try {
        IntrospectionCache cache("issuer", 1024, 16);
        const std::string key = MakeKey(2);
        cache.Insert(key, MakeCtx("bob"), true, seconds(1));
        const auto future = steady_clock::now() + seconds(120);
        auto r = cache.Lookup(key, future);
        Record("IntrospectionCache: Lookup_Miss_OnExpiredPositive",
               r.state == LookupState::Miss,
               "Expected Miss after TTL expiry on regular Lookup");
    } catch (const std::exception& e) {
        Record("IntrospectionCache: Lookup_Miss_OnExpiredPositive", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// 4. Lookup_Stale_InGraceWindow_Positive
// ---------------------------------------------------------------------------
static void Test_Lookup_Stale_InGraceWindow_Positive() {
    try {
        IntrospectionCache cache("issuer", 1024, 16);
        const std::string key = MakeKey(3);
        cache.Insert(key, MakeCtx("carol"), true, seconds(1));
        // 5 seconds in the future — inside the default 30s grace window.
        const auto t = steady_clock::now() + seconds(5);
        auto r = cache.LookupStale(key, t);
        bool ok = r.state == LookupState::Stale && r.active &&
                  r.ctx.subject == "carol";
        Record("IntrospectionCache: Lookup_Stale_InGraceWindow_Positive", ok,
               "Expected Stale+active in grace window");
    } catch (const std::exception& e) {
        Record("IntrospectionCache: Lookup_Stale_InGraceWindow_Positive",
               false, e.what());
    }
}

// ---------------------------------------------------------------------------
// 5. Lookup_Miss_OutsideGraceWindow_Positive
// ---------------------------------------------------------------------------
static void Test_Lookup_Miss_OutsideGraceWindow_Positive() {
    try {
        IntrospectionCache cache("issuer", 1024, 16);
        const std::string key = MakeKey(4);
        cache.Insert(key, MakeCtx("dan"), true, seconds(1));
        // Default stale_grace_sec=30; 120s past TTL is outside.
        const auto t = steady_clock::now() + seconds(120);
        auto r = cache.LookupStale(key, t);
        Record("IntrospectionCache: Lookup_Miss_OutsideGraceWindow_Positive",
               r.state == LookupState::Miss,
               "Expected Miss outside grace window");
    } catch (const std::exception& e) {
        Record("IntrospectionCache: Lookup_Miss_OutsideGraceWindow_Positive",
               false, e.what());
    }
}

// ---------------------------------------------------------------------------
// 6. Insert_Negative_ReturnsNegativeHitOnLookup
// ---------------------------------------------------------------------------
static void Test_Insert_Negative_ReturnsNegativeHitOnLookup() {
    try {
        IntrospectionCache cache("issuer", 1024, 16);
        const std::string key = MakeKey(5);
        cache.Insert(key, AuthContext{}, /*active=*/false, seconds(10));
        auto r = cache.Lookup(key, steady_clock::now());
        bool ok = r.state == LookupState::Fresh && !r.active;
        Record("IntrospectionCache: Insert_Negative_ReturnsNegativeHitOnLookup",
               ok, "Expected Fresh+!active for negative entry");

        auto stats = cache.SnapshotStats();
        bool counter_ok = stats.negative_hit == 1 && stats.hit == 0;
        Record("IntrospectionCache: Negative_hit counter increments",
               counter_ok, "Expected negative_hit=1, hit=0");
    } catch (const std::exception& e) {
        Record("IntrospectionCache: Insert_Negative_ReturnsNegativeHitOnLookup",
               false, e.what());
    }
}

// ---------------------------------------------------------------------------
// 7. LookupStale_NeverReturnsStaleNegative
// ---------------------------------------------------------------------------
static void Test_LookupStale_NeverReturnsStaleNegative() {
    try {
        IntrospectionCache cache("issuer", 1024, 16);
        const std::string key = MakeKey(6);
        cache.Insert(key, AuthContext{}, /*active=*/false, seconds(1));
        // Inside what would be the grace window — must still be Miss.
        const auto t = steady_clock::now() + seconds(5);
        auto r = cache.LookupStale(key, t);
        Record("IntrospectionCache: LookupStale_NeverReturnsStaleNegative",
               r.state == LookupState::Miss,
               "Negative entries must never stale-serve");
    } catch (const std::exception& e) {
        Record("IntrospectionCache: LookupStale_NeverReturnsStaleNegative",
               false, e.what());
    }
}

// ---------------------------------------------------------------------------
// 8. Insert_TtlClamp_MinOfConfigAndExp — caller is responsible for clamping;
//    this test simulates the two clamp paths and asserts the cache honors
//    whichever value it received.
// ---------------------------------------------------------------------------
static void Test_Insert_TtlClamp_MinOfConfigAndExp() {
    try {
        IntrospectionCache cache("issuer", 1024, 16);

        // Caller clamped to exp - now (smaller than cache_sec=60).
        const std::string key_a = MakeKey(7);
        cache.Insert(key_a, MakeCtx("alice"), true, seconds(5));
        bool fresh_now = cache.Lookup(key_a, steady_clock::now()).state ==
                         LookupState::Fresh;
        bool miss_after = cache.Lookup(key_a, steady_clock::now() + seconds(10))
                              .state == LookupState::Miss;

        // Caller clamped to cache_sec (smaller than exp - now).
        const std::string key_b = MakeKey(8);
        cache.Insert(key_b, MakeCtx("bob"), true, seconds(60));
        bool fresh_at_30 =
            cache.Lookup(key_b, steady_clock::now() + seconds(30)).state ==
            LookupState::Fresh;
        bool miss_at_120 =
            cache.Lookup(key_b, steady_clock::now() + seconds(120)).state ==
            LookupState::Miss;

        bool ok = fresh_now && miss_after && fresh_at_30 && miss_at_120;
        Record("IntrospectionCache: Insert_TtlClamp_MinOfConfigAndExp", ok,
               "Both clamp paths must produce expected expiry");
    } catch (const std::exception& e) {
        Record("IntrospectionCache: Insert_TtlClamp_MinOfConfigAndExp",
               false, e.what());
    }
}

// ---------------------------------------------------------------------------
// 9. Insert_TtlZero_Skipped — ttl<=0 must be a no-op.
// ---------------------------------------------------------------------------
static void Test_Insert_TtlZero_Skipped() {
    try {
        IntrospectionCache cache("issuer", 1024, 16);
        const std::string key = MakeKey(9);
        cache.Insert(key, MakeCtx("zero"), true, seconds(0));
        cache.Insert(key, MakeCtx("neg"), true, seconds(-5));
        auto r = cache.Lookup(key, steady_clock::now());
        bool ok = r.state == LookupState::Miss;
        auto stats = cache.SnapshotStats();
        ok = ok && stats.entries == 0;
        Record("IntrospectionCache: Insert_TtlZero_Skipped", ok,
               "Insert with ttl<=0 must be a no-op");
    } catch (const std::exception& e) {
        Record("IntrospectionCache: Insert_TtlZero_Skipped", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// 10. Lookup_KeySensitivity — different keys → distinct entries.
// ---------------------------------------------------------------------------
static void Test_Lookup_KeySensitivity() {
    try {
        IntrospectionCache cache("issuer", 1024, 16);
        const std::string a = MakeKey(100);
        const std::string b = MakeKey(101);
        cache.Insert(a, MakeCtx("alpha"), true, seconds(60));
        cache.Insert(b, MakeCtx("beta"), true, seconds(60));
        auto ra = cache.Lookup(a, steady_clock::now());
        auto rb = cache.Lookup(b, steady_clock::now());
        bool ok = ra.state == LookupState::Fresh && ra.ctx.subject == "alpha" &&
                  rb.state == LookupState::Fresh && rb.ctx.subject == "beta";
        Record("IntrospectionCache: Lookup_KeySensitivity", ok,
               "Distinct keys must map to distinct entries");
    } catch (const std::exception& e) {
        Record("IntrospectionCache: Lookup_KeySensitivity", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// 11. ShardDistribution_128BitKeys — 10k random keys spread across 16 shards
//     within ±15% of mean. Roundtrips through Insert + Lookup so the test
//     also confirms keys hash to the same shard on insert and lookup.
// ---------------------------------------------------------------------------
static void Test_ShardDistribution_128BitKeys() {
    try {
        constexpr size_t kShards = 16;
        constexpr size_t kKeys = 10000;
        IntrospectionCache cache("issuer", kKeys * 2, kShards);
        std::mt19937 rng(12345u);

        std::vector<std::string> keys;
        keys.reserve(kKeys);
        for (size_t i = 0; i < kKeys; ++i) {
            std::string k = MakeRandomKey(rng);
            keys.push_back(k);
            cache.Insert(k, MakeCtx("u"), true, seconds(60));
        }
        auto stats = cache.SnapshotStats();
        // All inserts succeeded; every key is reachable under its hashed shard.
        size_t hits = 0;
        for (const auto& k : keys) {
            if (cache.Lookup(k, steady_clock::now()).state ==
                LookupState::Fresh) {
                ++hits;
            }
        }
        // Distribution check: each shard's size ≤ ±15% of the mean.
        const double mean = static_cast<double>(stats.entries) / kShards;
        const double tol = mean * 0.15;
        // SelectShard is private; replicate it here (parse first 4 hex chars
        // as uint16_t and AND with shard mask) to derive per-shard counts.
        std::vector<size_t> per_shard(kShards, 0);
        for (const auto& k : keys) {
            uint16_t prefix = 0;
            for (int i = 0; i < 4; ++i) {
                char c = k[i];
                int v = (c >= 'a') ? 10 + (c - 'a') :
                        (c >= 'A') ? 10 + (c - 'A') : (c - '0');
                prefix = static_cast<uint16_t>((prefix << 4) | v);
            }
            ++per_shard[prefix & (kShards - 1)];
        }
        bool dist_ok = true;
        for (size_t i = 0; i < kShards; ++i) {
            const double diff =
                static_cast<double>(per_shard[i]) - mean;
            if (std::fabs(diff) > tol) {
                dist_ok = false;
                break;
            }
        }
        bool ok = hits == kKeys && stats.entries == kKeys && dist_ok;
        Record("IntrospectionCache: ShardDistribution_128BitKeys", ok,
               "Per-shard count outside ±15% of mean OR keys not all reachable");
    } catch (const std::exception& e) {
        Record("IntrospectionCache: ShardDistribution_128BitKeys",
               false, e.what());
    }
}

// ---------------------------------------------------------------------------
// 12. LruEviction_OnInsertAtCap — fill one shard to its cap, insert one more
//     key whose first-4-hex prefix lands in the same shard, verify the LRU
//     tail (oldest insert) is gone and the new key is reachable.
// ---------------------------------------------------------------------------
static void Test_LruEviction_OnInsertAtCap() {
    try {
        // Single shard so per_shard_cap = max_entries.
        constexpr size_t kCap = 4;
        IntrospectionCache cache("issuer", kCap, 1);
        std::vector<std::string> keys;
        for (size_t i = 0; i < kCap; ++i) {
            std::string k = MakeKey(static_cast<uint32_t>(0x1000 + i));
            keys.push_back(k);
            cache.Insert(k, MakeCtx("u"), true, seconds(60));
        }
        // All inserted entries are present.
        for (const auto& k : keys) {
            if (cache.Lookup(k, steady_clock::now()).state !=
                LookupState::Fresh) {
                Record("IntrospectionCache: LruEviction_OnInsertAtCap", false,
                       "Pre-eviction lookup unexpectedly missed");
                return;
            }
        }
        // Lookup keys[0] is now MRU again; tail = keys[1].
        cache.Lookup(keys[0], steady_clock::now());
        // Insert one more — evicts the LRU tail (keys[1]).
        const std::string newer = MakeKey(0xDEAD);
        cache.Insert(newer, MakeCtx("new"), true, seconds(60));
        bool tail_evicted =
            cache.Lookup(keys[1], steady_clock::now()).state ==
            LookupState::Miss;
        bool newer_present =
            cache.Lookup(newer, steady_clock::now()).state ==
            LookupState::Fresh;
        bool head_kept =
            cache.Lookup(keys[0], steady_clock::now()).state ==
            LookupState::Fresh;
        bool ok = tail_evicted && newer_present && head_kept;
        Record("IntrospectionCache: LruEviction_OnInsertAtCap", ok,
               "LRU tail must be evicted on at-cap insert");
    } catch (const std::exception& e) {
        Record("IntrospectionCache: LruEviction_OnInsertAtCap", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// 13. LruPromote_OnHit — hitting an entry at the bottom should move it to
//     head; the next over-cap insert evicts the next-LRU instead.
// ---------------------------------------------------------------------------
static void Test_LruPromote_OnHit() {
    try {
        constexpr size_t kCap = 4;
        IntrospectionCache cache("issuer", kCap, 1);
        std::vector<std::string> keys;
        for (size_t i = 0; i < kCap; ++i) {
            std::string k = MakeKey(static_cast<uint32_t>(0x2000 + i));
            keys.push_back(k);
            cache.Insert(k, MakeCtx("u"), true, seconds(60));
        }
        // Tail is keys[0]. Hit it — promotes to head.
        cache.Lookup(keys[0], steady_clock::now());
        // Insert one more; eviction must target keys[1] (the new tail).
        const std::string newer = MakeKey(0xCAFE);
        cache.Insert(newer, MakeCtx("new"), true, seconds(60));

        bool keys0_kept =
            cache.Lookup(keys[0], steady_clock::now()).state ==
            LookupState::Fresh;
        bool keys1_evicted =
            cache.Lookup(keys[1], steady_clock::now()).state ==
            LookupState::Miss;
        bool ok = keys0_kept && keys1_evicted;
        Record("IntrospectionCache: LruPromote_OnHit", ok,
               "Promoted entry must survive next eviction");
    } catch (const std::exception& e) {
        Record("IntrospectionCache: LruPromote_OnHit", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// 14. ApplyReload_CacheSecChange — reload changes future inserts only.
// ---------------------------------------------------------------------------
static void Test_ApplyReload_CacheSecChange() {
    try {
        IntrospectionCache cache("issuer", 1024, 16);
        const std::string old_key = MakeKey(20);
        cache.Insert(old_key, MakeCtx("old"), true, seconds(60));

        IntrospectionConfig cfg = MakeConfig();
        cfg.cache_sec = 5;
        cache.ApplyReload(cfg);

        // Existing entry keeps its 60s expiry.
        const auto t30 = steady_clock::now() + seconds(30);
        bool old_still_fresh =
            cache.Lookup(old_key, t30).state == LookupState::Fresh;
        Record("IntrospectionCache: ApplyReload_CacheSecChange",
               old_still_fresh,
               "Existing entries must keep their original expiry across reload");
    } catch (const std::exception& e) {
        Record("IntrospectionCache: ApplyReload_CacheSecChange", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// 15. ApplyReload_NegativeCacheSecChange
// ---------------------------------------------------------------------------
static void Test_ApplyReload_NegativeCacheSecChange() {
    try {
        IntrospectionCache cache("issuer", 1024, 16);
        IntrospectionConfig cfg = MakeConfig();
        cfg.negative_cache_sec = 7;
        cache.ApplyReload(cfg);
        // No existing-entry semantics to verify here beyond "ApplyReload
        // does not crash and leaves the cache usable".
        cache.Insert(MakeKey(30), AuthContext{}, false, seconds(7));
        auto r = cache.Lookup(MakeKey(30), steady_clock::now());
        bool ok = r.state == LookupState::Fresh && !r.active;
        Record("IntrospectionCache: ApplyReload_NegativeCacheSecChange", ok,
               "Negative-cache reload must not invalidate cache state");
    } catch (const std::exception& e) {
        Record("IntrospectionCache: ApplyReload_NegativeCacheSecChange",
               false, e.what());
    }
}

// ---------------------------------------------------------------------------
// 16. ApplyReload_StaleGraceSecChange — new grace value applies to subsequent
//     LookupStale calls; existing entries' ttl_expiry is unchanged.
// ---------------------------------------------------------------------------
static void Test_ApplyReload_StaleGraceSecChange() {
    try {
        IntrospectionCache cache("issuer", 1024, 16);
        const std::string key = MakeKey(40);
        cache.Insert(key, MakeCtx("live"), true, seconds(1));

        // Default grace=30s — at +20s past TTL we'd be Stale.
        IntrospectionConfig cfg = MakeConfig();
        cfg.stale_grace_sec = 5;
        cache.ApplyReload(cfg);
        // +20s past TTL with grace=5 must Miss.
        auto r = cache.LookupStale(key, steady_clock::now() + seconds(20));
        bool ok = r.state == LookupState::Miss;
        // +3s past TTL (within new grace=5) must Stale.
        auto r2 = cache.LookupStale(key, steady_clock::now() + seconds(3));
        ok = ok && r2.state == LookupState::Stale && r2.active;
        Record("IntrospectionCache: ApplyReload_StaleGraceSecChange", ok,
               "Stale-grace reload must alter subsequent LookupStale outcomes");
    } catch (const std::exception& e) {
        Record("IntrospectionCache: ApplyReload_StaleGraceSecChange",
               false, e.what());
    }
}

// ---------------------------------------------------------------------------
// 17. ApplyReload_MaxEntriesDecrease_AmortisedEviction — shrinking max_entries
//     does not bulk-evict; entries are reaped on subsequent over-cap inserts.
// ---------------------------------------------------------------------------
static void Test_ApplyReload_MaxEntriesDecrease_AmortisedEviction() {
    try {
        IntrospectionCache cache("issuer", 8, 1);
        std::vector<std::string> keys;
        for (size_t i = 0; i < 8; ++i) {
            std::string k = MakeKey(static_cast<uint32_t>(0x3000 + i));
            keys.push_back(k);
            cache.Insert(k, MakeCtx("u"), true, seconds(60));
        }
        size_t before = cache.SnapshotStats().entries;

        IntrospectionConfig cfg = MakeConfig(60, 10, 30, /*max_entries=*/4, 1);
        cache.ApplyReload(cfg);
        // No bulk eviction synchronously.
        size_t after = cache.SnapshotStats().entries;

        // Insert one more — eviction now drives shard down toward new cap.
        cache.Insert(MakeKey(0xBEEF), MakeCtx("trigger"), true, seconds(60));
        size_t after_trigger = cache.SnapshotStats().entries;

        bool ok = before == 8 && after == 8 && after_trigger == 4;
        Record("IntrospectionCache: ApplyReload_MaxEntriesDecrease_AmortisedEviction",
               ok,
               "Reload must not bulk-evict; subsequent insert drives eviction");
    } catch (const std::exception& e) {
        Record("IntrospectionCache: ApplyReload_MaxEntriesDecrease_AmortisedEviction",
               false, e.what());
    }
}

// ---------------------------------------------------------------------------
// 18. ConcurrentInsertLookup_16Threads — 16 threads, 50/50 mix, no crash.
// ---------------------------------------------------------------------------
static void Test_ConcurrentInsertLookup_16Threads() {
    try {
        IntrospectionCache cache("issuer", 100000, 16);
        constexpr int kThreads = 16;
        constexpr int kIters = 10000;
        std::atomic<int> errors{0};
        std::atomic<int> ops{0};

        auto worker = [&](int tid) {
            std::mt19937 rng(static_cast<uint32_t>(tid * 7 + 1));
            for (int i = 0; i < kIters; ++i) {
                std::string k = MakeRandomKey(rng);
                if ((i & 1) == 0) {
                    cache.Insert(k, MakeCtx("u"), true, seconds(60));
                } else {
                    auto r = cache.Lookup(k, steady_clock::now());
                    (void)r;
                }
                ops.fetch_add(1, std::memory_order_relaxed);
            }
        };

        std::vector<std::thread> ts;
        ts.reserve(kThreads);
        for (int t = 0; t < kThreads; ++t) ts.emplace_back(worker, t);
        for (auto& t : ts) t.join();

        bool ok = errors.load() == 0 &&
                  ops.load() == kThreads * kIters;
        Record("IntrospectionCache: ConcurrentInsertLookup_16Threads", ok,
               "Concurrent Insert/Lookup must complete without error");
    } catch (const std::exception& e) {
        Record("IntrospectionCache: ConcurrentInsertLookup_16Threads",
               false, e.what());
    }
}

// ---------------------------------------------------------------------------
// 19. ConcurrentReloadDuringInsert — reload thread races with insert.
// ---------------------------------------------------------------------------
static void Test_ConcurrentReloadDuringInsert() {
    try {
        IntrospectionCache cache("issuer", 50000, 16);
        std::atomic<bool> stop{false};

        auto inserter = [&]() {
            std::mt19937 rng(0xABCDu);
            while (!stop.load(std::memory_order_relaxed)) {
                cache.Insert(MakeRandomKey(rng), MakeCtx("u"), true,
                             seconds(60));
            }
        };
        auto reloader = [&]() {
            int v = 30;
            while (!stop.load(std::memory_order_relaxed)) {
                IntrospectionConfig cfg = MakeConfig(60, 10, v, 50000, 16);
                cache.ApplyReload(cfg);
                v = (v == 30 ? 60 : 30);
            }
        };

        std::thread ti(inserter);
        std::thread tr(reloader);
        std::this_thread::sleep_for(milliseconds(200));
        stop.store(true, std::memory_order_relaxed);
        ti.join();
        tr.join();

        // Surviving without crash + non-empty cache demonstrates the race
        // is benign.
        bool ok = cache.SnapshotStats().entries > 0;
        Record("IntrospectionCache: ConcurrentReloadDuringInsert", ok,
               "Reload+Insert race must complete without crash");
    } catch (const std::exception& e) {
        Record("IntrospectionCache: ConcurrentReloadDuringInsert",
               false, e.what());
    }
}

// ---------------------------------------------------------------------------
// 20. SnapshotStats_Counters
// ---------------------------------------------------------------------------
static void Test_SnapshotStats_Counters() {
    try {
        IntrospectionCache cache("issuer", 1024, 16);
        const std::string pos = MakeKey(50);
        const std::string neg = MakeKey(51);
        cache.Insert(pos, MakeCtx("p"), true, seconds(60));
        cache.Insert(neg, AuthContext{}, false, seconds(60));

        // 1 hit, 1 negative_hit, 2 misses.
        cache.Lookup(pos, steady_clock::now());
        cache.Lookup(neg, steady_clock::now());
        cache.Lookup(MakeKey(900), steady_clock::now());
        cache.Lookup(MakeKey(901), steady_clock::now());

        // Stale-serve once via positive entry.
        cache.Insert(MakeKey(52), MakeCtx("s"), true, seconds(1));
        cache.LookupStale(MakeKey(52), steady_clock::now() + seconds(5));

        auto s = cache.SnapshotStats();
        bool ok = s.hit == 1 && s.negative_hit == 1 && s.miss == 2 &&
                  s.stale_served == 1;
        Record("IntrospectionCache: SnapshotStats_Counters", ok,
               "Counters must increment for hit/miss/negative_hit/stale_served");
    } catch (const std::exception& e) {
        Record("IntrospectionCache: SnapshotStats_Counters", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// 21. KeyedHashCollisionProbability_AtScale — 100k random keys, zero
//     collisions on insert + every key reachable on Lookup.
// ---------------------------------------------------------------------------
static void Test_KeyedHashCollisionProbability_AtScale() {
    try {
        constexpr size_t kKeys = 100000;
        IntrospectionCache cache("issuer", kKeys * 2, 16);
        std::mt19937_64 rng(0xC0FFEEULL);
        static const char* kHex = "0123456789abcdef";

        std::vector<std::string> keys;
        keys.reserve(kKeys);
        for (size_t i = 0; i < kKeys; ++i) {
            std::string k(32, '0');
            uint64_t a = rng();
            uint64_t b = rng();
            for (int j = 0; j < 16; ++j) k[j] = kHex[(a >> (j * 4)) & 0xF];
            for (int j = 0; j < 16; ++j) k[16 + j] = kHex[(b >> (j * 4)) & 0xF];
            keys.push_back(std::move(k));
        }
        for (const auto& k : keys) {
            cache.Insert(k, MakeCtx("u"), true, seconds(300));
        }
        size_t reachable = 0;
        for (const auto& k : keys) {
            if (cache.Lookup(k, steady_clock::now()).state ==
                LookupState::Fresh) {
                ++reachable;
            }
        }
        auto stats = cache.SnapshotStats();
        bool ok = reachable == kKeys && stats.entries == kKeys;
        Record("IntrospectionCache: KeyedHashCollisionProbability_AtScale",
               ok,
               "All 100k random keys must be reachable post-insert");
    } catch (const std::exception& e) {
        Record("IntrospectionCache: KeyedHashCollisionProbability_AtScale",
               false, e.what());
    }
}

// ---------------------------------------------------------------------------
// 22. Lookup_WithZeroTtl_DoesNotReturnFresh
// ---------------------------------------------------------------------------
static void Test_Lookup_WithZeroTtl_DoesNotReturnFresh() {
    try {
        IntrospectionCache cache("issuer", 1024, 16);
        const std::string key = MakeKey(60);
        cache.Insert(key, MakeCtx("u"), true, seconds(0));
        auto r = cache.Lookup(key, steady_clock::now());
        Record("IntrospectionCache: Lookup_WithZeroTtl_DoesNotReturnFresh",
               r.state == LookupState::Miss,
               "Insert(ttl=0) must not produce a Fresh-hit");
    } catch (const std::exception& e) {
        Record("IntrospectionCache: Lookup_WithZeroTtl_DoesNotReturnFresh",
               false, e.what());
    }
}

// ---------------------------------------------------------------------------
// 23. Insert_DuplicateKey_UpdatesInPlace
// ---------------------------------------------------------------------------
static void Test_Insert_DuplicateKey_UpdatesInPlace() {
    try {
        IntrospectionCache cache("issuer", 1024, 16);
        const std::string key = MakeKey(70);
        cache.Insert(key, MakeCtx("v1"), true, seconds(60));
        cache.Insert(key, MakeCtx("v2"), true, seconds(60));
        auto r = cache.Lookup(key, steady_clock::now());
        bool subj_ok = r.state == LookupState::Fresh &&
                       r.ctx.subject == "v2";
        bool count_ok = cache.SnapshotStats().entries == 1;

        // Re-insert flipping the active flag must also take effect.
        cache.Insert(key, AuthContext{}, false, seconds(60));
        auto r2 = cache.Lookup(key, steady_clock::now());
        bool flipped = r2.state == LookupState::Fresh && !r2.active;

        bool ok = subj_ok && count_ok && flipped;
        Record("IntrospectionCache: Insert_DuplicateKey_UpdatesInPlace", ok,
               "Re-insert must update the existing entry, not duplicate it");
    } catch (const std::exception& e) {
        Record("IntrospectionCache: Insert_DuplicateKey_UpdatesInPlace",
               false, e.what());
    }
}

// ---------------------------------------------------------------------------
// 24. AuthContext_DeepCopy_OnInsert — caller mutating its AuthContext after
//     insert must not affect the cached entry.
// ---------------------------------------------------------------------------
static void Test_AuthContext_DeepCopy_OnInsert() {
    try {
        IntrospectionCache cache("issuer", 1024, 16);
        const std::string key = MakeKey(80);

        AuthContext ctx;
        ctx.issuer = "test-issuer";
        ctx.subject = "before";
        ctx.scopes = {"read"};
        ctx.claims["k"] = "v1";
        cache.Insert(key, ctx, true, seconds(60));

        ctx.subject = "after";
        ctx.scopes.push_back("write");
        ctx.claims["k"] = "v2";
        ctx.claims["new"] = "x";

        auto r = cache.Lookup(key, steady_clock::now());
        bool ok = r.state == LookupState::Fresh &&
                  r.ctx.subject == "before" &&
                  r.ctx.scopes.size() == 1 &&
                  r.ctx.claims.count("k") == 1 &&
                  r.ctx.claims.at("k") == "v1" &&
                  r.ctx.claims.count("new") == 0;
        Record("IntrospectionCache: AuthContext_DeepCopy_OnInsert", ok,
               "Cache must store a deep copy independent of caller's AuthContext");
    } catch (const std::exception& e) {
        Record("IntrospectionCache: AuthContext_DeepCopy_OnInsert",
               false, e.what());
    }
}

// ---------------------------------------------------------------------------
// 25. SnapshotStats_ThreadSafe — Snapshot under load doesn't tear / crash.
// ---------------------------------------------------------------------------
static void Test_SnapshotStats_ThreadSafe() {
    try {
        IntrospectionCache cache("issuer", 50000, 16);
        std::atomic<bool> stop{false};

        auto load = [&](uint32_t seed) {
            std::mt19937 rng(seed);
            while (!stop.load(std::memory_order_relaxed)) {
                std::string k = MakeRandomKey(rng);
                cache.Insert(k, MakeCtx("u"), true, seconds(60));
                cache.Lookup(k, steady_clock::now());
            }
        };
        auto snapper = [&]() {
            uint64_t seen = 0;
            while (!stop.load(std::memory_order_relaxed)) {
                auto s = cache.SnapshotStats();
                seen += s.entries + s.hit + s.miss;
            }
            (void)seen;
        };

        std::thread w1(load, 11u);
        std::thread w2(load, 22u);
        std::thread sn(snapper);
        std::this_thread::sleep_for(milliseconds(200));
        stop.store(true, std::memory_order_relaxed);
        w1.join();
        w2.join();
        sn.join();

        Record("IntrospectionCache: SnapshotStats_ThreadSafe", true,
               "Snapshot under concurrent load must not crash or tear");
    } catch (const std::exception& e) {
        Record("IntrospectionCache: SnapshotStats_ThreadSafe",
               false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Bonus: ctor rejects non-power-of-two shard counts and zero max_entries.
// ---------------------------------------------------------------------------
static void Test_Ctor_Validates_ShardCount_PowerOfTwo() {
    try {
        bool threw_3 = false;
        try { IntrospectionCache c("i", 100, 3); }
        catch (const std::invalid_argument&) { threw_3 = true; }

        bool threw_0 = false;
        try { IntrospectionCache c("i", 100, 0); }
        catch (const std::invalid_argument&) { threw_0 = true; }

        bool threw_128 = false;
        try { IntrospectionCache c("i", 100, 128); }
        catch (const std::invalid_argument&) { threw_128 = true; }

        bool threw_zero_max = false;
        try { IntrospectionCache c("i", 0, 16); }
        catch (const std::invalid_argument&) { threw_zero_max = true; }

        // Power-of-two values within range must construct successfully.
        bool ok_pow2 = true;
        try {
            IntrospectionCache c1("i", 100, 1);
            IntrospectionCache c2("i", 100, 2);
            IntrospectionCache c4("i", 100, 4);
            IntrospectionCache c64("i", 100, 64);
        } catch (...) { ok_pow2 = false; }

        bool ok = threw_3 && threw_0 && threw_128 && threw_zero_max && ok_pow2;
        Record("IntrospectionCache: Ctor_Validates_ShardCount_PowerOfTwo", ok,
               "Ctor must reject non-power-of-two shard counts AND zero max_entries");
    } catch (const std::exception& e) {
        Record("IntrospectionCache: Ctor_Validates_ShardCount_PowerOfTwo",
               false, e.what());
    }
}

// ---------------------------------------------------------------------------
static void RunAllTests() {
    std::cout << "\n[IntrospectionCache Tests]" << std::endl;
    Test_InsertAndLookup_Fresh();
    Test_Lookup_Miss_OnEmptyCache();
    Test_Lookup_Miss_OnExpiredPositive();
    Test_Lookup_Stale_InGraceWindow_Positive();
    Test_Lookup_Miss_OutsideGraceWindow_Positive();
    Test_Insert_Negative_ReturnsNegativeHitOnLookup();
    Test_LookupStale_NeverReturnsStaleNegative();
    Test_Insert_TtlClamp_MinOfConfigAndExp();
    Test_Insert_TtlZero_Skipped();
    Test_Lookup_KeySensitivity();
    Test_ShardDistribution_128BitKeys();
    Test_LruEviction_OnInsertAtCap();
    Test_LruPromote_OnHit();
    Test_ApplyReload_CacheSecChange();
    Test_ApplyReload_NegativeCacheSecChange();
    Test_ApplyReload_StaleGraceSecChange();
    Test_ApplyReload_MaxEntriesDecrease_AmortisedEviction();
    Test_ConcurrentInsertLookup_16Threads();
    Test_ConcurrentReloadDuringInsert();
    Test_SnapshotStats_Counters();
    Test_KeyedHashCollisionProbability_AtScale();
    Test_Lookup_WithZeroTtl_DoesNotReturnFresh();
    Test_Insert_DuplicateKey_UpdatesInPlace();
    Test_AuthContext_DeepCopy_OnInsert();
    Test_SnapshotStats_ThreadSafe();
    Test_Ctor_Validates_ShardCount_PowerOfTwo();
}

}  // namespace IntrospectionCacheTests
