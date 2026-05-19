#pragma once

// ShardedLruCache unit tests.
//
// Pure unit coverage with no external dependencies. Exercises all five
// test dimensions: correctness, Handle move semantics, LRU invariants,
// sharding behavior, boundary/edge cases, and concurrent stress.

#include "test_framework.h"
#include "sharded_lru_cache.h"

#include <atomic>
#include <chrono>
#include <random>
#include <string>
#include <thread>
#include <vector>

namespace ShardedLruCacheTests {

using UTIL_NAMESPACE::ShardedLruCache;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static void Record(const std::string& name, bool pass, const std::string& err = "") {
    TestFramework::RecordTest(name, pass, pass ? "" : err,
                              TestFramework::TestCategory::OTHER);
}

// ---------------------------------------------------------------------------
// Section 1: Happy-path correctness
// ---------------------------------------------------------------------------

static void Test_Find_Miss() {
    try {
        ShardedLruCache<std::string, int> cache(4, 10);
        auto h = cache.Find("absent");
        bool ok = !h;
        Record("ShardedLruCache: Find_Miss returns empty Handle", ok,
               "Find on absent key must return empty Handle");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: Find_Miss returns empty Handle", false, e.what());
    }
}

// Find must NOT promote: insert k1 then k2, Find(k1) but don't touch,
// then insert k3 at cap=2. k1 should be evicted (still the LRU tail).
static void Test_Find_Hit_NoPromotion() {
    try {
        // Single shard, cap=2 so we control eviction order exactly.
        ShardedLruCache<std::string, int> cache(1, 2);
        // Fill: insert order LRU→MRU is k1, k2.
        cache.Insert("k1", 1);
        cache.Insert("k2", 2);

        // Find k1 — must NOT promote it to MRU.
        auto h = cache.Find("k1");
        bool found = bool(h) && *h == 1;
        h = {};  // release lock

        // Insert k3: this triggers eviction. If Find promoted k1, k2 would be
        // evicted; if Find did NOT promote, k1 (still at tail) is evicted.
        cache.Insert("k3", 3);
        bool k1_gone = !cache.Find("k1");
        bool k2_present = bool(cache.Find("k2"));
        bool k3_present = bool(cache.Find("k3"));

        bool ok = found && k1_gone && k2_present && k3_present;
        Record("ShardedLruCache: Find_Hit_NoPromotion",
               ok, "Find must not promote; oldest (tail) must be evicted next");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: Find_Hit_NoPromotion", false, e.what());
    }
}

// FindAndTouch must promote: insert k1 then k2, FindAndTouch(k1) to promote
// it to MRU, then insert k3 — k2 (now tail) must be evicted.
static void Test_FindAndTouch_Promotes() {
    try {
        ShardedLruCache<std::string, int> cache(1, 2);
        cache.Insert("k1", 1);
        cache.Insert("k2", 2);

        // FindAndTouch k1: promotes it to MRU. Order becomes k2(tail), k1(head).
        auto h = cache.FindAndTouch("k1");
        bool found = bool(h) && *h == 1;
        h = {};

        cache.Insert("k3", 3);
        // k2 (tail after promotion) must be evicted; k1 must survive.
        bool k2_gone = !cache.Find("k2");
        bool k1_present = bool(cache.Find("k1"));

        bool ok = found && k2_gone && k1_present;
        Record("ShardedLruCache: FindAndTouch_Promotes",
               ok, "FindAndTouch must promote hit to MRU");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: FindAndTouch_Promotes", false, e.what());
    }
}

static void Test_Touch_EmptyHandle_NoOp() {
    try {
        ShardedLruCache<std::string, int> cache(1, 5);
        ShardedLruCache<std::string, int>::Handle empty;
        // Must not crash.
        cache.Touch(empty);
        Record("ShardedLruCache: Touch_EmptyHandle_NoOp", true, "");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: Touch_EmptyHandle_NoOp", false, e.what());
    }
}

static void Test_FindOrCreate_Miss_FactoryRuns() {
    try {
        ShardedLruCache<std::string, int> cache(1, 5);
        int factory_calls = 0;
        auto h = cache.FindOrCreate("new-key", [&]() {
            ++factory_calls;
            return 42;
        });
        bool ok = bool(h) && *h == 42 && factory_calls == 1;
        h = {};
        // Store the Handle before checking value to avoid holding the shard lock
        // across a second Find() call on the same shard (same-thread deadlock).
        auto h2 = cache.Find("new-key");
        bool reachable = bool(h2) && *h2 == 42;
        ok = ok && reachable;
        Record("ShardedLruCache: FindOrCreate_Miss_FactoryRuns",
               ok, "On miss, factory must run and value must be reachable");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: FindOrCreate_Miss_FactoryRuns", false, e.what());
    }
}

static void Test_FindOrCreate_Hit_FactoryNotCalled() {
    try {
        ShardedLruCache<std::string, int> cache(1, 5);
        cache.Insert("existing", 10);
        int factory_calls = 0;
        auto h = cache.FindOrCreate("existing", [&]() {
            ++factory_calls;
            return 99;
        });
        bool ok = bool(h) && *h == 10 && factory_calls == 0;
        Record("ShardedLruCache: FindOrCreate_Hit_FactoryNotCalled",
               ok, "On hit, factory must not be invoked");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: FindOrCreate_Hit_FactoryNotCalled", false, e.what());
    }
}

// Insert on new key: goes to MRU head. Verify by eviction order.
static void Test_Insert_New_AtMru() {
    try {
        ShardedLruCache<std::string, int> cache(1, 2);
        cache.Insert("k1", 1);
        cache.Insert("k2", 2);  // k2 at MRU, k1 at LRU
        cache.Insert("k3", 3);  // evicts k1; k3 is MRU
        bool k1_gone = !cache.Find("k1");
        bool k2_present = bool(cache.Find("k2"));
        bool k3_mru = bool(cache.Find("k3"));
        bool ok = k1_gone && k2_present && k3_mru;
        Record("ShardedLruCache: Insert_New_AtMru",
               ok, "Newly inserted key must be at MRU and oldest key evicted");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: Insert_New_AtMru", false, e.what());
    }
}

// Insert on existing key must replace value and promote to MRU.
static void Test_Insert_Existing_ReplacesValue() {
    try {
        ShardedLruCache<std::string, int> cache(1, 3);
        cache.Insert("k1", 1);
        cache.Insert("k2", 2);
        cache.Insert("k3", 3);  // order: k1(tail), k2, k3(head)

        // Re-insert k1 with new value: must update + promote to head.
        cache.Insert("k1", 100);

        // Verify value updated.
        auto h = cache.Find("k1");
        bool value_ok = bool(h) && *h == 100;
        h = {};

        // Verify size stays at 3 (no duplicate entry).
        bool size_ok = (cache.ShardSize(0) == 3);

        // k2 is now tail; inserting k4 must evict k2 (not k1).
        cache.Insert("k4", 4);
        bool k2_gone = !cache.Find("k2");
        bool k1_present = bool(cache.Find("k1"));

        bool ok = value_ok && size_ok && k2_gone && k1_present;
        Record("ShardedLruCache: Insert_Existing_ReplacesValue",
               ok, "Re-insert must update value and promote to MRU");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: Insert_Existing_ReplacesValue", false, e.what());
    }
}

static void Test_Erase_Present() {
    try {
        ShardedLruCache<std::string, int> cache(4, 10);
        cache.Insert("target", 7);
        bool erased = cache.Erase("target");
        bool gone = !cache.Find("target");
        bool ok = erased && gone;
        Record("ShardedLruCache: Erase_Present",
               ok, "Erase must return true and remove existing entry");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: Erase_Present", false, e.what());
    }
}

static void Test_Erase_Absent() {
    try {
        ShardedLruCache<std::string, int> cache(4, 10);
        bool erased = cache.Erase("no-such-key");
        Record("ShardedLruCache: Erase_Absent",
               !erased, "Erase must return false for absent key");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: Erase_Absent", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Section 2: Handle move semantics
// ---------------------------------------------------------------------------

static void Test_Handle_MoveConstruct() {
    try {
        ShardedLruCache<std::string, int> cache(1, 5);
        cache.Insert("key", 77);
        auto h1 = cache.Find("key");
        bool h1_valid = bool(h1);

        auto h2 = std::move(h1);
        // h1 must be empty; h2 must be valid and hold the value.
        bool h1_empty = !h1;
        bool h2_valid = bool(h2) && *h2 == 77;
        // operator-> on moved-from h1 must return nullptr (not crash).
        bool ptr_null = (h1.operator->() == nullptr);

        bool ok = h1_valid && h1_empty && h2_valid && ptr_null;
        Record("ShardedLruCache: Handle_MoveConstruct",
               ok, "Move-construct: source empty, dest valid");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: Handle_MoveConstruct", false, e.what());
    }
}

static void Test_Handle_MoveAssign() {
    try {
        ShardedLruCache<std::string, int> cache(1, 5);
        cache.Insert("key", 55);
        auto h1 = cache.Find("key");
        ShardedLruCache<std::string, int>::Handle h2;
        h2 = std::move(h1);
        bool h1_empty = !h1;
        bool h2_valid = bool(h2) && *h2 == 55;
        bool ok = h1_empty && h2_valid;
        Record("ShardedLruCache: Handle_MoveAssign",
               ok, "Move-assign: source empty, dest valid");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: Handle_MoveAssign", false, e.what());
    }
}

// Self-move must leave the Handle in a consistent state (no crash, value
// unchanged). The standard permits self-move to produce a valid-but-unspecified
// state; we only assert no crash and no double-unlock.
static void Test_Handle_SelfMove_NocrashNodouble() {
    try {
        ShardedLruCache<std::string, int> cache(1, 5);
        cache.Insert("key", 33);
        auto h = cache.Find("key");
        // Suppress the self-move-detection compiler warning explicitly.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wself-move"
        h = std::move(h);
#pragma GCC diagnostic pop
        // No assertion on value — post-self-move state is unspecified.
        // What matters: no crash, no double-unlock.
        Record("ShardedLruCache: Handle_SelfMove_NoCrashNoDouble",
               true, "Self-move must not crash or double-unlock");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: Handle_SelfMove_NoCrashNoDouble", false, e.what());
    }
}

static void Test_Handle_MoveEmpty() {
    try {
        ShardedLruCache<std::string, int> cache(1, 5);
        ShardedLruCache<std::string, int>::Handle empty;
        auto moved = std::move(empty);
        bool ok = !empty && !moved;
        Record("ShardedLruCache: Handle_MoveEmpty",
               ok, "Move-constructing an empty Handle must leave both empty");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: Handle_MoveEmpty", false, e.what());
    }
}

// After a Handle is destroyed, the shard lock is released and a new Find
// on the same shard from the same thread must succeed (no deadlock).
static void Test_Handle_MovedFrom_LockReleased() {
    try {
        ShardedLruCache<std::string, int> cache(1, 5);
        cache.Insert("key", 9);
        {
            auto h1 = cache.Find("key");
            auto h2 = std::move(h1);
            // h1 moved-from: its lock is transferred to h2. h2 still holds the
            // shard lock — we must let h2 go out of scope before taking a new lock.
            (void)h2;
        }  // h2 destroyed here, shard lock released.
        // Now safe to Find again: no Handle alive on this shard.
        auto h3 = cache.Find("key");
        bool ok = bool(h3) && *h3 == 9;
        Record("ShardedLruCache: Handle_MovedFrom_LockReleased",
               ok, "After Handle destruction, same-shard Find must succeed");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: Handle_MovedFrom_LockReleased", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Section 3: LRU invariants
// ---------------------------------------------------------------------------

// Fill a shard to cap N, then insert N+1. The oldest entry must be evicted.
static void Test_Lru_Eviction_OldestGone() {
    try {
        ShardedLruCache<std::string, int> cache(1, 4);
        cache.Insert("a", 1);
        cache.Insert("b", 2);
        cache.Insert("c", 3);
        cache.Insert("d", 4);  // full at cap=4
        cache.Insert("e", 5);  // evicts "a" (oldest)
        bool a_gone = !cache.Find("a");
        bool e_present = bool(cache.Find("e"));
        bool ok = a_gone && e_present;
        Record("ShardedLruCache: Lru_Eviction_OldestGone",
               ok, "Inserting past cap must evict the LRU tail");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: Lru_Eviction_OldestGone", false, e.what());
    }
}

// Touch explicitly promotes a held Handle. Verify via EvictFromTailWhile order.
static void Test_Touch_Promotes_ExplicitOrder() {
    try {
        // Use cap=3 so inserting a 4th entry forces exactly one eviction.
        ShardedLruCache<std::string, int> cache(1, 3);

        // Fill to capacity. LRU order (tail→head): k1, k2, k3.
        cache.Insert("k1", 1);
        cache.Insert("k2", 2);
        cache.Insert("k3", 3);

        // Touch k1 (no-promote Find + explicit Touch). k1 → MRU.
        // New order (tail→head): k2, k3, k1.
        {
            auto h = cache.Find("k1");
            cache.Touch(h);
        }

        // Inserting k4 must evict the tail, which is k2.
        cache.Insert("k4", 4);
        auto hk2 = cache.Find("k2");
        bool k2_gone = !hk2;
        hk2 = {};  // release shard lock before next Find
        auto hk1 = cache.Find("k1");
        bool k1_present = bool(hk1);
        hk1 = {};  // release shard lock
        bool ok = k2_gone && k1_present;
        Record("ShardedLruCache: Touch_Promotes_ExplicitOrder",
               ok, "Touch must move the entry to MRU so it survives next eviction");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: Touch_Promotes_ExplicitOrder", false, e.what());
    }
}

// EvictFromTailWhile stops on the first false from the predicate.
static void Test_EvictFromTailWhile_StopsOnFalse() {
    try {
        ShardedLruCache<std::string, int> cache(1, 10);
        // Insert 5 entries: values 1..5, order tail→head: k1(1), k2(2), ... k5(5).
        for (int i = 1; i <= 5; ++i) {
            cache.Insert("k" + std::to_string(i), i);
        }
        // Evict only while value < 3 (stops when it encounters value=3).
        std::size_t evicted = cache.EvictFromTailWhile(
            0, [](const int& v, std::size_t) { return v < 3; });
        // k1(1) and k2(2) should be evicted (values 1, 2 < 3). k3 triggers
        // false and stops. Remaining: k3, k4, k5.
        bool evict_count_ok = (evicted == 2);
        bool k1_gone = !cache.Find("k1");
        bool k2_gone = !cache.Find("k2");
        bool k3_present = bool(cache.Find("k3"));
        bool k4_present = bool(cache.Find("k4"));
        bool k5_present = bool(cache.Find("k5"));
        bool ok = evict_count_ok && k1_gone && k2_gone &&
                  k3_present && k4_present && k5_present;
        Record("ShardedLruCache: EvictFromTailWhile_StopsOnFalse",
               ok, "EvictFromTailWhile must stop at first predicate=false");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: EvictFromTailWhile_StopsOnFalse", false, e.what());
    }
}

// VisitShardLruToMru walks tail→head (oldest first) and passes correct key/value.
static void Test_VisitShardLruToMru_Order() {
    try {
        ShardedLruCache<std::string, int> cache(1, 10);
        // Insert in ascending order; tail is the first-inserted.
        for (int i = 1; i <= 4; ++i) {
            cache.Insert("k" + std::to_string(i), i);
        }
        // k1 is LRU (tail), k4 is MRU (head).
        std::vector<int> visited_values;
        cache.VisitShardLruToMru(0, [&](const std::string&, int& v) {
            visited_values.push_back(v);
            return true;  // continue
        });
        bool order_ok = (visited_values == std::vector<int>{1, 2, 3, 4});
        Record("ShardedLruCache: VisitShardLruToMru_Order",
               order_ok, "VisitShardLruToMru must walk tail→head (LRU→MRU)");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: VisitShardLruToMru_Order", false, e.what());
    }
}

// VisitShardLruToMru stops when the visitor returns false.
static void Test_VisitShardLruToMru_EarlyStop() {
    try {
        ShardedLruCache<std::string, int> cache(1, 10);
        for (int i = 1; i <= 5; ++i) {
            cache.Insert("k" + std::to_string(i), i);
        }
        int seen = 0;
        cache.VisitShardLruToMru(0, [&](const std::string&, int& v) {
            ++seen;
            return v < 3;  // stop after value=3 becomes the current entry
        });
        // Visits k1(1) → continue, k2(2) → continue, k3(3) → false → stops.
        bool ok = (seen == 3);
        Record("ShardedLruCache: VisitShardLruToMru_EarlyStop",
               ok, "VisitShardLruToMru must stop when visitor returns false");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: VisitShardLruToMru_EarlyStop", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Section 4: Sharding behavior
// ---------------------------------------------------------------------------

static void Test_ShardCount_Reported() {
    try {
        ShardedLruCache<std::string, int> cache(8, 100);
        bool ok = (cache.ShardCount() == 8);
        Record("ShardedLruCache: ShardCount_Reported",
               ok, "ShardCount() must return the configured shard_count");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: ShardCount_Reported", false, e.what());
    }
}

// Insert 10000 keys with std::hash<string>, verify no shard exceeds 2x the mean.
static void Test_ShardDistribution_UniformHash() {
    try {
        constexpr std::size_t kShards = 16;
        constexpr std::size_t kKeys = 10000;
        ShardedLruCache<std::string, int> cache(kShards, kKeys + 1);
        for (std::size_t i = 0; i < kKeys; ++i) {
            cache.Insert("key-" + std::to_string(i), static_cast<int>(i));
        }
        std::size_t total = cache.Size();
        bool size_ok = (total == kKeys);
        // Sum of ShardSize must equal Size.
        std::size_t sum = 0;
        for (std::size_t s = 0; s < kShards; ++s) sum += cache.ShardSize(s);
        bool sum_ok = (sum == total);
        // No shard should exceed 2x the mean.
        const double mean = static_cast<double>(total) / kShards;
        bool dist_ok = true;
        for (std::size_t s = 0; s < kShards; ++s) {
            if (cache.ShardSize(s) > static_cast<std::size_t>(mean * 2.0 + 1)) {
                dist_ok = false;
                break;
            }
        }
        bool ok = size_ok && sum_ok && dist_ok;
        Record("ShardedLruCache: ShardDistribution_UniformHash",
               ok, "10k keys must distribute uniformly: no shard > 2x mean");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: ShardDistribution_UniformHash", false, e.what());
    }
}

static void Test_Size_EqualsSumOfShardSizes() {
    try {
        ShardedLruCache<std::string, int> cache(4, 50);
        for (int i = 0; i < 20; ++i) {
            cache.Insert("k" + std::to_string(i), i);
        }
        std::size_t total = cache.Size();
        std::size_t sum = 0;
        for (std::size_t s = 0; s < 4; ++s) sum += cache.ShardSize(s);
        bool ok = (total == sum);
        Record("ShardedLruCache: Size_EqualsSumOfShardSizes",
               ok, "Size() must equal sum of ShardSize(0..N-1)");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: Size_EqualsSumOfShardSizes", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Section 5: Boundary / edge cases
// ---------------------------------------------------------------------------

static void Test_Ctor_SingleShard() {
    try {
        bool ok = false;
        try {
            ShardedLruCache<std::string, int> cache(1, 5);
            cache.Insert("x", 1);
            auto hx = cache.Find("x");
            ok = bool(hx) && *hx == 1;
        } catch (...) {
            ok = false;
        }
        Record("ShardedLruCache: Ctor_SingleShard",
               ok, "shard_count=1 must construct and work correctly");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: Ctor_SingleShard", false, e.what());
    }
}

static void Test_Ctor_MaxShards_64() {
    try {
        bool ok = false;
        try {
            ShardedLruCache<std::string, int> cache(64, 10);
            cache.Insert("x", 99);
            auto hx64 = cache.Find("x");
            ok = bool(hx64) && *hx64 == 99;
        } catch (...) {
            ok = false;
        }
        Record("ShardedLruCache: Ctor_MaxShards_64",
               ok, "shard_count=64 (max) must construct and operate correctly");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: Ctor_MaxShards_64", false, e.what());
    }
}

static void Test_Ctor_CapOne_EvictsOnEachInsert() {
    try {
        ShardedLruCache<std::string, int> cache(1, 1);
        cache.Insert("a", 1);
        cache.Insert("b", 2);
        bool a_gone = !cache.Find("a");
        bool b_present = bool(cache.Find("b"));
        cache.Insert("c", 3);
        bool b_gone = !cache.Find("b");
        bool c_present = bool(cache.Find("c"));
        bool ok = a_gone && b_present && b_gone && c_present;
        Record("ShardedLruCache: Ctor_CapOne_EvictsOnEachInsert",
               ok, "per_shard_cap=1 must evict on every new-key insert");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: Ctor_CapOne_EvictsOnEachInsert", false, e.what());
    }
}

static void Test_Ctor_ThrowsOnZeroShardCount() {
    try {
        bool threw = false;
        try {
            ShardedLruCache<std::string, int> cache(0, 10);
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        Record("ShardedLruCache: Ctor_ThrowsOnZeroShardCount",
               threw, "shard_count=0 must throw std::invalid_argument");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: Ctor_ThrowsOnZeroShardCount", false, e.what());
    }
}

static void Test_Ctor_ThrowsOnZeroPerShardCap() {
    try {
        bool threw = false;
        try {
            ShardedLruCache<std::string, int> cache(4, 0);
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        Record("ShardedLruCache: Ctor_ThrowsOnZeroPerShardCap",
               threw, "per_shard_cap=0 must throw std::invalid_argument");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: Ctor_ThrowsOnZeroPerShardCap", false, e.what());
    }
}

static void Test_Ctor_ThrowsOnNonPowerOfTwoShardCount() {
    try {
        bool threw_3 = false;
        bool threw_5 = false;
        bool threw_7 = false;
        try { ShardedLruCache<std::string, int> c(3, 5); }
        catch (const std::invalid_argument&) { threw_3 = true; }
        try { ShardedLruCache<std::string, int> c(5, 5); }
        catch (const std::invalid_argument&) { threw_5 = true; }
        try { ShardedLruCache<std::string, int> c(7, 5); }
        catch (const std::invalid_argument&) { threw_7 = true; }
        bool ok = threw_3 && threw_5 && threw_7;
        Record("ShardedLruCache: Ctor_ThrowsOnNonPowerOfTwo",
               ok, "Non-power-of-two shard_count must throw std::invalid_argument");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: Ctor_ThrowsOnNonPowerOfTwo", false, e.what());
    }
}

static void Test_Ctor_ThrowsOnShardCountAboveMax() {
    try {
        bool threw = false;
        try {
            ShardedLruCache<std::string, int> cache(128, 10);
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        Record("ShardedLruCache: Ctor_ThrowsOnShardCountAboveMax",
               threw, "shard_count=128 (>64) must throw std::invalid_argument");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: Ctor_ThrowsOnShardCountAboveMax", false, e.what());
    }
}

// All power-of-two shard counts in [1, 64] must construct without throwing.
static void Test_Ctor_ValidPowerOfTwoCountsSucceed() {
    try {
        bool ok = true;
        for (std::size_t sc : {1u, 2u, 4u, 8u, 16u, 32u, 64u}) {
            try {
                ShardedLruCache<std::string, int> c(sc, 5);
                (void)c;
            } catch (...) {
                ok = false;
            }
        }
        Record("ShardedLruCache: Ctor_ValidPowerOfTwoCountsSucceed",
               ok, "All power-of-two shard counts in [1,64] must construct");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: Ctor_ValidPowerOfTwoCountsSucceed", false, e.what());
    }
}

// Factory throws: cache state must be unchanged (no eviction, no insertion).
static void Test_FindOrCreate_FactoryThrows_CacheUnchanged() {
    try {
        ShardedLruCache<std::string, int> cache(1, 3);
        cache.Insert("existing", 5);
        std::size_t size_before = cache.Size();

        bool factory_threw = false;
        bool exception_propagated = false;
        try {
            cache.FindOrCreate("new-key", []() -> int {
                throw std::runtime_error("factory-error");
            });
        } catch (const std::runtime_error&) {
            exception_propagated = true;
        }

        factory_threw = exception_propagated;
        // Cache must be unchanged: size same, existing key still present, new key absent.
        bool size_ok = (cache.Size() == size_before);
        bool existing_present = bool(cache.Find("existing"));
        bool new_absent = !cache.Find("new-key");

        bool ok = factory_threw && size_ok && existing_present && new_absent;
        Record("ShardedLruCache: FindOrCreate_FactoryThrows_CacheUnchanged",
               ok, "Factory exception must propagate and leave cache unchanged");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: FindOrCreate_FactoryThrows_CacheUnchanged",
               false, e.what());
    }
}

// ResizePerShardCap(0) must throw; cache state and existing entries survive.
static void Test_ResizePerShardCap_ZeroThrows() {
    try {
        ShardedLruCache<std::string, int> cache(1, 10);
        cache.Insert("a", 1);
        bool threw = false;
        try {
            cache.ResizePerShardCap(0);
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        auto ha = cache.Find("a");
        bool a_ok = bool(ha) && *ha == 1;
        bool ok = threw && a_ok;
        Record("ShardedLruCache: ResizePerShardCap_ZeroThrows",
               ok, "ResizePerShardCap(0) must throw, leaving cache intact");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: ResizePerShardCap_ZeroThrows", false, e.what());
    }
}

// ResizePerShardCap to smaller value: multi-evict on the next insert.
// Fill 10 entries at cap=10, then shrink to cap=5. The next Insert must
// evict down to 4 before inserting the new key, resulting in 5 total.
static void Test_ResizePerShardCap_Shrink_MultiEvict() {
    try {
        ShardedLruCache<std::string, int> cache(1, 10);
        for (int i = 0; i < 10; ++i) {
            cache.Insert("k" + std::to_string(i), i);
        }
        bool full_ok = (cache.ShardSize(0) == 10);

        cache.ResizePerShardCap(5);

        // No bulk eviction immediately — size must still be 10.
        bool no_bulk_evict = (cache.ShardSize(0) == 10);

        // A single new insert triggers multi-evict (loop runs while size >= cap=5).
        cache.Insert("trigger", 99);
        // After evict-while-over-cap, size was 10 → loop evicts until size < 5,
        // meaning it evicts while size >= 5: evicts entries 0..5 (6 evictions),
        // reducing size to 4. Then inserts "trigger" → size = 5.
        bool final_ok = (cache.ShardSize(0) == 5);

        bool ok = full_ok && no_bulk_evict && final_ok;
        Record("ShardedLruCache: ResizePerShardCap_Shrink_MultiEvict",
               ok, "Shrinking cap must multi-evict on next insert to bring size to cap");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: ResizePerShardCap_Shrink_MultiEvict", false, e.what());
    }
}

// Clear on empty is a no-op; Clear on populated drops all entries and allows
// subsequent inserts.
static void Test_Clear() {
    try {
        ShardedLruCache<std::string, int> cache(4, 20);

        // Clear on empty — must not crash.
        cache.Clear();
        bool empty_clear_ok = (cache.Size() == 0);

        for (int i = 0; i < 8; ++i) {
            cache.Insert("k" + std::to_string(i), i);
        }
        cache.Clear();
        bool all_gone = (cache.Size() == 0);
        for (int i = 0; i < 8; ++i) {
            if (cache.Find("k" + std::to_string(i))) {
                all_gone = false;
                break;
            }
        }

        // Post-Clear inserts must work (LRU list not corrupted).
        cache.Insert("after", 77);
        auto hafter = cache.Find("after");
        bool reinsert_ok = bool(hafter) && *hafter == 77;

        bool ok = empty_clear_ok && all_gone && reinsert_ok;
        Record("ShardedLruCache: Clear",
               ok, "Clear must drop all entries; empty before + re-insert after must work");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: Clear", false, e.what());
    }
}

// FindOrCreate correctly promotes the hit entry to MRU.
static void Test_FindOrCreate_Hit_Promotes() {
    try {
        ShardedLruCache<std::string, int> cache(1, 3);
        cache.Insert("k1", 1);
        cache.Insert("k2", 2);
        cache.Insert("k3", 3);
        // Order tail→head: k1, k2, k3.

        // FindOrCreate k1 on hit → promotes k1 to MRU.
        {
            auto h = cache.FindOrCreate("k1", []() { return 99; });
            (void)h;
        }
        // Order now: k2(tail), k3, k1(head).
        // Insert k4 → evicts k2 (tail).
        cache.Insert("k4", 4);
        bool k2_gone = !cache.Find("k2");
        bool k1_present = bool(cache.Find("k1"));
        bool ok = k2_gone && k1_present;
        Record("ShardedLruCache: FindOrCreate_Hit_Promotes",
               ok, "FindOrCreate on hit must promote the entry to MRU");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: FindOrCreate_Hit_Promotes", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Section 6: Concurrent stress (TSan signal)
// ---------------------------------------------------------------------------

// Reduce iteration count under TSan to keep CI fast. The LRU shard mutex is
// held for the full duration of every operation, so this cache is
// intentionally more contention-bound than sharded atomics. 20k ops per
// thread is sufficient for race-condition signal without excessive wall time.
#if defined(__has_feature) && __has_feature(thread_sanitizer)
static constexpr int kOpsPerThread = 5000;
#else
static constexpr int kOpsPerThread = 20000;
#endif

// 16 threads doing a random mix of Find / FindAndTouch / FindOrCreate /
// Insert / Erase / Touch. Asserts: no torn reads, no crash.
static void Test_Concurrent_RandomMix() {
    try {
        constexpr int kThreads = 16;
        constexpr int kKeyRange = 64;

        ShardedLruCache<std::string, int> cache(8, 16);
        std::atomic<bool> any_error{false};

        auto worker = [&](int tid) {
            std::mt19937 rng(static_cast<unsigned>(tid * 31 + 7));
            std::uniform_int_distribution<int> key_dist(0, kKeyRange - 1);
            std::uniform_int_distribution<int> op_dist(0, 5);

            for (int i = 0; i < kOpsPerThread && !any_error.load(std::memory_order_relaxed); ++i) {
                std::string k = "k" + std::to_string(key_dist(rng));
                int op = op_dist(rng);
                try {
                    switch (op) {
                        case 0: cache.Find(k); break;
                        case 1: cache.FindAndTouch(k); break;
                        case 2: cache.FindOrCreate(k, [&]() { return tid; }); break;
                        case 3: cache.Insert(k, tid); break;
                        case 4: cache.Erase(k); break;
                        case 5: {
                            auto h = cache.Find(k);
                            if (h) cache.Touch(h);
                            break;
                        }
                    }
                } catch (...) {
                    any_error.store(true, std::memory_order_relaxed);
                }
            }
        };

        std::vector<std::thread> threads;
        threads.reserve(kThreads);
        for (int t = 0; t < kThreads; ++t) {
            threads.emplace_back(worker, t);
        }
        for (auto& t : threads) t.join();

        bool ok = !any_error.load();
        Record("ShardedLruCache: Concurrent_RandomMix",
               ok, "16-thread random-op mix must complete without error");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: Concurrent_RandomMix", false, e.what());
    }
}

// Eviction storm: many threads inserting distinct keys with a small cap.
// After all threads finish, no shard may exceed its cap.
static void Test_Concurrent_EvictionStormBoundedSize() {
    try {
        constexpr int kThreads = 16;
        constexpr std::size_t kCap = 10;
        // Each op inserts a unique string key; use a lower per-thread budget so
        // the 16-thread × unique-key workload completes in bounded time on all
        // sanitizer configurations. The invariant (no shard exceeds cap) is fully
        // covered with 5000 distinct keys per thread.
        constexpr int kStormOps = 5000;

        ShardedLruCache<std::string, int> cache(8, kCap);
        std::atomic<int> errors{0};

        auto worker = [&](int tid) {
            for (int i = 0; i < kStormOps; ++i) {
                std::string k = "t" + std::to_string(tid) + "-k" + std::to_string(i);
                cache.Insert(k, i);
            }
        };

        std::vector<std::thread> threads;
        threads.reserve(kThreads);
        for (int t = 0; t < kThreads; ++t) {
            threads.emplace_back(worker, t);
        }
        for (auto& t : threads) t.join();

        bool size_bounded = true;
        for (std::size_t s = 0; s < cache.ShardCount(); ++s) {
            if (cache.ShardSize(s) > kCap) {
                size_bounded = false;
                break;
            }
        }
        bool ok = (errors.load() == 0) && size_bounded;
        Record("ShardedLruCache: Concurrent_EvictionStormBoundedSize",
               ok, "Each shard must not exceed cap under concurrent eviction storm");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: Concurrent_EvictionStormBoundedSize", false, e.what());
    }
}

// VisitShardLruToMru with concurrent FindOrCreate on the same shard must
// provide a consistent snapshot: the visitor callback must not observe
// torn entries or crash.
static void Test_Concurrent_VisitWhileInserting() {
    try {
        ShardedLruCache<std::string, int> cache(1, 64);
        std::atomic<bool> stop{false};

        auto inserter = [&](int tid) {
            std::mt19937 rng(static_cast<unsigned>(tid));
            std::uniform_int_distribution<int> d(0, 127);
            while (!stop.load(std::memory_order_relaxed)) {
                std::string k = "ik" + std::to_string(d(rng));
                cache.FindOrCreate(k, []() { return 1; });
            }
        };

        auto visitor = [&]() {
            while (!stop.load(std::memory_order_relaxed)) {
                int count = 0;
                cache.VisitShardLruToMru(0, [&](const std::string&, int&) {
                    ++count;
                    return true;
                });
                (void)count;
            }
        };

        std::vector<std::thread> threads;
        threads.emplace_back(inserter, 1);
        threads.emplace_back(inserter, 2);
        threads.emplace_back(visitor);

        // Run for a bounded time.
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        stop.store(true, std::memory_order_relaxed);
        for (auto& t : threads) t.join();

        Record("ShardedLruCache: Concurrent_VisitWhileInserting",
               true, "Concurrent Visit + FindOrCreate must not crash or tear");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: Concurrent_VisitWhileInserting", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Section 7: Additional correctness
// ---------------------------------------------------------------------------

// ResizePerShardCap to larger value: no immediate eviction, subsequent
// inserts fill the new cap before evicting again.
static void Test_ResizePerShardCap_Grow() {
    try {
        ShardedLruCache<std::string, int> cache(1, 3);
        cache.Insert("a", 1);
        cache.Insert("b", 2);
        cache.Insert("c", 3);
        bool full_at_3 = (cache.ShardSize(0) == 3);

        cache.ResizePerShardCap(5);

        // Should be able to insert 2 more without eviction.
        cache.Insert("d", 4);
        cache.Insert("e", 5);
        bool no_eviction = (cache.ShardSize(0) == 5);
        // Check each key individually — handles must be released before the next
        // Find on the same shard to avoid same-thread mutex deadlock.
        bool all_present = bool(cache.Find("a"));
        all_present = all_present && bool(cache.Find("b"));
        all_present = all_present && bool(cache.Find("c"));
        all_present = all_present && bool(cache.Find("d"));
        all_present = all_present && bool(cache.Find("e"));

        // Now at new cap=5: next insert evicts.
        cache.Insert("f", 6);
        bool a_gone = !cache.Find("a");  // a was inserted first (LRU tail)
        bool f_present = bool(cache.Find("f"));

        bool ok = full_at_3 && no_eviction && all_present && a_gone && f_present;
        Record("ShardedLruCache: ResizePerShardCap_Grow",
               ok, "Growing the cap must allow more entries before evicting");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: ResizePerShardCap_Grow", false, e.what());
    }
}

// The Size() method returns 0 on a freshly constructed empty cache.
static void Test_EmptyCache_SizeIsZero() {
    try {
        ShardedLruCache<std::string, int> cache(4, 10);
        bool ok = (cache.Size() == 0);
        Record("ShardedLruCache: EmptyCache_SizeIsZero",
               ok, "Freshly constructed cache must have Size()=0");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: EmptyCache_SizeIsZero", false, e.what());
    }
}

// EvictFromTailWhile returns the eviction count.
static void Test_EvictFromTailWhile_ReturnCount() {
    try {
        ShardedLruCache<std::string, int> cache(1, 10);
        for (int i = 0; i < 5; ++i) {
            cache.Insert("k" + std::to_string(i), i);
        }
        std::size_t n = cache.EvictFromTailWhile(
            0, [](const int&, std::size_t) { return true; });
        bool ok = (n == 5) && (cache.ShardSize(0) == 0);
        Record("ShardedLruCache: EvictFromTailWhile_ReturnCount",
               ok, "EvictFromTailWhile must return correct eviction count");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: EvictFromTailWhile_ReturnCount", false, e.what());
    }
}

// Predicate receives the current post-eviction size of the shard.
static void Test_EvictFromTailWhile_SizeArg() {
    try {
        ShardedLruCache<std::string, int> cache(1, 10);
        for (int i = 0; i < 5; ++i) {
            cache.Insert("k" + std::to_string(i), i);
        }
        // Evict while size > 3 (i.e. stop when size reaches 3).
        std::vector<std::size_t> sizes_seen;
        cache.EvictFromTailWhile(0, [&](const int&, std::size_t sz) {
            sizes_seen.push_back(sz);
            return sz > 3;
        });
        // First call: size=5 (before eviction of k0), predicate gets 5 → evict → size=4.
        // Second call: predicate gets 4 → evict → size=3.
        // Third call: predicate gets 3 → false → stops.
        bool ok = (sizes_seen.size() == 3) &&
                  sizes_seen[0] == 5 &&
                  sizes_seen[1] == 4 &&
                  sizes_seen[2] == 3 &&
                  cache.ShardSize(0) == 3;
        Record("ShardedLruCache: EvictFromTailWhile_SizeArg",
               ok, "EvictFromTailWhile predicate must receive current shard size");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: EvictFromTailWhile_SizeArg", false, e.what());
    }
}

// EvictFromTailWhile on empty shard returns 0.
static void Test_EvictFromTailWhile_EmptyShard() {
    try {
        ShardedLruCache<std::string, int> cache(1, 10);
        std::size_t n = cache.EvictFromTailWhile(
            0, [](const int&, std::size_t) { return true; });
        bool ok = (n == 0);
        Record("ShardedLruCache: EvictFromTailWhile_EmptyShard",
               ok, "EvictFromTailWhile on empty shard must return 0");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: EvictFromTailWhile_EmptyShard", false, e.what());
    }
}

// Insert followed by Erase, then re-Insert of the same key must work.
static void Test_Erase_ThenReinsert() {
    try {
        ShardedLruCache<std::string, int> cache(1, 5);
        cache.Insert("key", 1);
        cache.Erase("key");
        cache.Insert("key", 2);
        // Check value and size separately — Size() locks all shards so the
        // Handle must be released first to avoid same-thread deadlock.
        auto h = cache.Find("key");
        bool found_ok = bool(h) && *h == 2;
        h = {};
        bool ok = found_ok && cache.Size() == 1;
        Record("ShardedLruCache: Erase_ThenReinsert",
               ok, "Erase then re-Insert of same key must work correctly");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: Erase_ThenReinsert", false, e.what());
    }
}

// Integer key type to verify the template works with non-string keys.
static void Test_IntegerKey() {
    try {
        ShardedLruCache<int, std::string> cache(4, 10);
        cache.Insert(1, "one");
        cache.Insert(2, "two");
        auto h1 = cache.Find(1);
        auto h2 = cache.Find(3);
        bool ok = bool(h1) && *h1 == "one" && !h2;
        Record("ShardedLruCache: IntegerKey",
               ok, "Cache with integer key type must operate correctly");
    } catch (const std::exception& e) {
        Record("ShardedLruCache: IntegerKey", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

static void RunAllTests() {
    std::cout << "\n[ShardedLruCache Tests]" << std::endl;

    // Section 1: Happy-path correctness
    Test_Find_Miss();
    Test_Find_Hit_NoPromotion();
    Test_FindAndTouch_Promotes();
    Test_Touch_EmptyHandle_NoOp();
    Test_FindOrCreate_Miss_FactoryRuns();
    Test_FindOrCreate_Hit_FactoryNotCalled();
    Test_FindOrCreate_Hit_Promotes();
    Test_Insert_New_AtMru();
    Test_Insert_Existing_ReplacesValue();
    Test_Erase_Present();
    Test_Erase_Absent();

    // Section 2: Handle move semantics
    Test_Handle_MoveConstruct();
    Test_Handle_MoveAssign();
    Test_Handle_SelfMove_NocrashNodouble();
    Test_Handle_MoveEmpty();
    Test_Handle_MovedFrom_LockReleased();

    // Section 3: LRU invariants
    Test_Lru_Eviction_OldestGone();
    Test_Touch_Promotes_ExplicitOrder();
    Test_EvictFromTailWhile_StopsOnFalse();
    Test_EvictFromTailWhile_ReturnCount();
    Test_EvictFromTailWhile_SizeArg();
    Test_EvictFromTailWhile_EmptyShard();
    Test_VisitShardLruToMru_Order();
    Test_VisitShardLruToMru_EarlyStop();

    // Section 4: Sharding behavior
    Test_ShardCount_Reported();
    Test_ShardDistribution_UniformHash();
    Test_Size_EqualsSumOfShardSizes();
    Test_EmptyCache_SizeIsZero();

    // Section 5: Boundary / edge cases
    Test_Ctor_SingleShard();
    Test_Ctor_MaxShards_64();
    Test_Ctor_CapOne_EvictsOnEachInsert();
    Test_Ctor_ThrowsOnZeroShardCount();
    Test_Ctor_ThrowsOnZeroPerShardCap();
    Test_Ctor_ThrowsOnNonPowerOfTwoShardCount();
    Test_Ctor_ThrowsOnShardCountAboveMax();
    Test_Ctor_ValidPowerOfTwoCountsSucceed();
    Test_FindOrCreate_FactoryThrows_CacheUnchanged();
    Test_ResizePerShardCap_ZeroThrows();
    Test_ResizePerShardCap_Shrink_MultiEvict();
    Test_ResizePerShardCap_Grow();
    Test_Clear();
    Test_Erase_ThenReinsert();
    Test_IntegerKey();

    // Section 6: Concurrent stress (TSan signal)
    Test_Concurrent_RandomMix();
    Test_Concurrent_EvictionStormBoundedSize();
    Test_Concurrent_VisitWhileInserting();
}

}  // namespace ShardedLruCacheTests
