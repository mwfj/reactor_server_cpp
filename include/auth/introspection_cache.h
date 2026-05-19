#pragma once

#include "common.h"
#include "auth/auth_context.h"
#include "auth/auth_config.h"
#include "sharded_lru_cache.h"
// <string>, <vector>, <memory>, <atomic>, <mutex>, <chrono>,
// <unordered_map> via common.h

namespace AUTH_NAMESPACE {

// Per-issuer cache of RFC 7662 introspection results, keyed by HMAC-SHA256
// of the bearer token (32 hex chars from TokenHasher::Hash).
//
// Thread-safe via per-shard mutex inside the underlying ShardedLruCache.
// Stale-grace is honored ONLY for positive (active=true) entries — negative
// entries are never stale-served.
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
    // Expired entries are NOT promoted — they stay at their LRU position so
    // LookupStale can serve them within grace and they get reaped naturally
    // when the shard fills.
    // `key` is the 32-hex-char output of TokenHasher::Hash.
    LookupResult Lookup(const std::string& key,
                        std::chrono::steady_clock::time_point now);

    // Stale-grace variant. Returns Stale+active+ctx ONLY when the entry is
    // positive (active=true) AND now is in [ttl_expiry, ttl_expiry +
    // stale_grace_sec_]. Returns Miss for negative entries regardless of
    // grace window — the never-stale-serve-negative invariant. Does NOT
    // promote — stale entries are kept stale-discoverable until evicted.
    LookupResult LookupStale(const std::string& key,
                             std::chrono::steady_clock::time_point now);

    // Insert or update. `ttl` is already clamped by the caller (per the
    // min(cache_sec, max(0, exp - now)) rule); ttl <= 0 is a no-op.
    //
    // Exception-safe against std::bad_alloc — failure is logged at warn
    // level and the insert is dropped. (The underlying cache propagates
    // bad_alloc; this wrapper swallows it to preserve the documented
    // best-effort insert semantic.)
    void Insert(const std::string& key,
                AuthContext ctx,
                bool active,
                std::chrono::seconds ttl);

    // Apply reloadable config. Updates atomic TTL fields and propagates the
    // new per-shard cap to the cache. Existing entries are NOT proactively
    // shed — the next over-cap insert evicts down to the new cap.
    // shard_count is restart-required and ignored here.
    void ApplyReload(const IntrospectionConfig& new_cfg);

    // Drop every entry across all shards. Used by AuthManager / Issuer
    // reload paths when the operator-requested claim-key set changes —
    // existing positive entries were populated using the OLD claim_keys
    // list, so their cached ctx is missing newly-requested keys.
    void Clear();

    // Snapshot stats counters for /stats observability. Approximate entry
    // count under relaxed ordering.
    Stats SnapshotStats() const;

    const std::string& issuer_name() const noexcept { return issuer_name_; }
    size_t shard_count() const noexcept { return shard_count_; }

 private:
    // Cached introspection result. For negative entries (active=false), `ctx`
    // is empty — only the active flag + ttl_expiry are meaningful.
    struct AuthEntry {
        AuthContext ctx;
        bool active = false;
        std::chrono::steady_clock::time_point ttl_expiry{};
    };

    // Hash functor that maps a 32-hex-char HMAC key to a shard index by
    // parsing the first 4 hex chars as a uint16_t. TokenHasher::Hash is
    // documented to always produce well-formed 32-hex-char output, so the
    // silent fallback to 0 on malformed input is only reachable on
    // programmer error — TokenHasher misbehavior surfaces in auth verify
    // before reaching this code.
    struct HexPrefixHash {
        std::size_t operator()(const std::string& key) const noexcept {
            if (key.size() < 4) return 0;
            std::size_t prefix = 0;
            for (size_t i = 0; i < 4; ++i) {
                const char c = key[i];
                int v;
                if (c >= '0' && c <= '9') v = c - '0';
                else if (c >= 'a' && c <= 'f') v = 10 + (c - 'a');
                else if (c >= 'A' && c <= 'F') v = 10 + (c - 'A');
                else return 0;
                prefix = (prefix << 4) | static_cast<std::size_t>(v);
            }
            return prefix;
        }
    };

    std::string issuer_name_;
    const size_t shard_count_;

    UTIL_NAMESPACE::ShardedLruCache<std::string, AuthEntry, HexPrefixHash> cache_;

    std::atomic<uint64_t> hit_{0};
    std::atomic<uint64_t> miss_{0};
    std::atomic<uint64_t> negative_hit_{0};
    std::atomic<uint64_t> stale_served_{0};

    std::atomic<int> cache_sec_{60};
    std::atomic<int> negative_cache_sec_{10};
    std::atomic<int> stale_grace_sec_{30};
};

}  // namespace AUTH_NAMESPACE
