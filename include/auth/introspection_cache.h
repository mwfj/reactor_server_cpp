#pragma once

#include "common.h"
#include "auth/auth_context.h"
#include "auth/auth_config.h"
// <string>, <vector>, <memory>, <atomic>, <mutex>, <chrono>,
// <unordered_map> via common.h

namespace AUTH_NAMESPACE {

// Per-issuer cache of RFC 7662 introspection results, keyed by HMAC-SHA256
// of the bearer token (32 hex chars from TokenHasher::Hash).
//
// Thread-safe. Each lookup/insert acquires only the selected shard's mutex,
// so independent shards do not contend. Stale-grace is honored ONLY for
// positive (active=true) entries — negative entries are never stale-served.
//
// The reloadable TTL fields (cache_sec, negative_cache_sec, stale_grace_sec)
// are atomic and consulted on every Insert/Lookup; ApplyReload mutates them
// without taking any shard lock. shard_count is fixed at construction
// (restart-required); changing it would require rehashing every entry.
class IntrospectionCache {
 public:
    enum class LookupState { Miss, Fresh, Stale };

    struct LookupResult {
        LookupState state = LookupState::Miss;
        bool active = false;     // Meaningful only on Fresh/Stale
        AuthContext ctx;         // Meaningful only on Fresh/Stale && active
    };

    struct Stats {
        size_t entries = 0;      // Sum of per-shard sizes (relaxed)
        uint64_t hit = 0;
        uint64_t miss = 0;
        uint64_t negative_hit = 0;
        uint64_t stale_served = 0;
    };

    // shard_count must be a power of two in [1, 64]; max_entries must be > 0.
    // Throws std::invalid_argument otherwise.
    IntrospectionCache(std::string issuer_name,
                       size_t max_entries,
                       size_t shard_count);
    ~IntrospectionCache();

    IntrospectionCache(const IntrospectionCache&) = delete;
    IntrospectionCache& operator=(const IntrospectionCache&) = delete;
    IntrospectionCache(IntrospectionCache&&) = delete;
    IntrospectionCache& operator=(IntrospectionCache&&) = delete;

    // Hot-path lookup. Returns Fresh+active+ctx on a non-expired hit (and
    // promotes the entry to MRU); returns Miss on absence or TTL expiry.
    // `key` is the 32-hex-char output of TokenHasher::Hash.
    LookupResult Lookup(const std::string& key,
                        std::chrono::steady_clock::time_point now);

    // Stale-grace variant. Returns Stale+active+ctx ONLY when the entry is
    // positive (active=true) AND now is in [ttl_expiry, ttl_expiry +
    // stale_grace_sec_]. Returns Miss for negative entries regardless of
    // grace window — the never-stale-serve-negative invariant.
    LookupResult LookupStale(const std::string& key,
                             std::chrono::steady_clock::time_point now);

    // Insert or update. `ttl` is already clamped by the caller (per the
    // min(cache_sec, max(0, exp - now)) rule); ttl <= 0 is a no-op. On
    // at-cap insert into a shard, evicts the LRU tail. Exception-safe
    // against std::bad_alloc — failure is logged at warn level and the
    // insert is dropped.
    void Insert(const std::string& key,
                AuthContext ctx,
                bool active,
                std::chrono::seconds ttl);

    // Apply reloadable config. Updates atomic TTL fields and per-shard cap;
    // does NOT touch existing entries or trigger bulk eviction. shard_count
    // is restart-required and ignored here.
    void ApplyReload(const IntrospectionConfig& new_cfg);

    // Drop every entry across all shards. Used by AuthManager / Issuer
    // reload paths when the operator-requested claim-key set
    // (forward.claim_keys ∪ issuer.required_claims) changes — existing
    // positive entries were populated using the OLD claim_keys list, so
    // their cached `ctx.claims` / `ctx.non_scalar_claims` are missing
    // newly-requested keys. Subsequent live POSTs repopulate against the
    // new key set; the only cost is a temporary cache-hit-rate dip. Each
    // shard's mutex is acquired in turn so concurrent Lookup/Insert calls
    // for unrelated shards remain unblocked.
    void Clear();

    // Snapshot stats counters for /stats observability. Approximate entry
    // count under relaxed ordering.
    Stats SnapshotStats() const;

    const std::string& issuer_name() const noexcept { return issuer_name_; }
    size_t shard_count() const noexcept { return shard_count_; }

 private:
    struct Entry;
    struct Shard;

    // Parses the first 4 hex chars of key as a uint16_t and ANDs with
    // (shard_count_ - 1). Power-of-two shard counts make this a single
    // mask operation. Returns shard 0 with an error log if the key prefix
    // is not 4 valid hex chars (a programmer bug — TokenHasher::Hash
    // always produces well-formed output).
    size_t SelectShard(const std::string& key) const;

    std::string issuer_name_;
    const size_t shard_count_;
    std::vector<std::unique_ptr<Shard>> shards_;
    std::atomic<size_t> per_shard_cap_;

    std::atomic<uint64_t> hit_{0};
    std::atomic<uint64_t> miss_{0};
    std::atomic<uint64_t> negative_hit_{0};
    std::atomic<uint64_t> stale_served_{0};

    std::atomic<int> cache_sec_{60};
    std::atomic<int> negative_cache_sec_{10};
    std::atomic<int> stale_grace_sec_{30};
};

}  // namespace AUTH_NAMESPACE
