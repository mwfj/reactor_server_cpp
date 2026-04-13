#pragma once

#include "rate_limit/token_bucket.h"
#include "http/http_request.h"
#include "config/server_config.h"
// <string>, <vector>, <functional>, <memory>, <mutex>, <unordered_map>
// provided by common.h (via http_request.h)

class RateLimitZone {
public:
    using KeyExtractor = std::function<std::string(const HttpRequest&)>;

    // Immutable policy snapshot — swapped atomically on reload.
    struct ZonePolicy {
        double rate;
        int64_t capacity;
        int max_entries;
        std::vector<std::string> applies_to;
    };

    // Result of a Check() call — consumed by the middleware layer.
    struct Result {
        bool allowed;
        bool applicable;     // False when zone was skipped (applies_to miss,
                             // empty key, etc.) — no bucket was touched and
                             // the caller should not use this result to
                             // populate RateLimit-* headers.
        int64_t limit;       // Bucket capacity (for RateLimit-Limit header)
        int64_t remaining;   // Tokens remaining (for RateLimit-Remaining header)
        double retry_after_sec; // Seconds until a token is available (for Retry-After header)
        double rate;         // Sustained rate in req/sec (for RateLimit-Policy window)
    };

    // Construct a zone from config with the given key extractor.
    RateLimitZone(const std::string& name,
                  const RateLimitZoneConfig& config,
                  KeyExtractor extractor);
    ~RateLimitZone();

    RateLimitZone(const RateLimitZone&) = delete;
    RateLimitZone& operator=(const RateLimitZone&) = delete;

    // Check whether a request is allowed under this zone's rate limit.
    // Thread-safe: acquires the target shard lock internally.
    Result Check(const HttpRequest& request);

    // Evict expired entries from shards assigned to this dispatcher.
    // Stride pattern: processes shards [dispatcher_index, dispatcher_index + dispatcher_count, ...].
    // Called periodically from the dispatcher timer handler.
    void EvictExpired(size_t dispatcher_index, size_t dispatcher_count);

    // Hot-reload: update the zone policy from new config.
    // Thread-safe: swaps the policy snapshot atomically.
    void UpdateConfig(const RateLimitZoneConfig& config);

    // Return total entry count across all shards (diagnostic/stats).
    size_t EntryCount() const;

    const std::string& name() const { return name_; }
    const std::string& key_type() const { return key_type_; }

private:
    // --- Policy snapshot (atomic swap via shared_ptr) ---
    std::shared_ptr<const ZonePolicy> policy_;
    mutable std::mutex policy_mtx_;

    std::shared_ptr<const ZonePolicy> LoadPolicy() const {
        std::lock_guard<std::mutex> lk(policy_mtx_);
        return policy_;
    }
    void StorePolicy(std::shared_ptr<const ZonePolicy> p) {
        std::lock_guard<std::mutex> lk(policy_mtx_);
        policy_ = std::move(p);
    }

    // --- Per-key entry with intrusive LRU pointers ---
    struct Entry {
        TokenBucket bucket;
        std::chrono::steady_clock::time_point last_access;
        Entry* lru_prev = nullptr;
        Entry* lru_next = nullptr;
        std::string key;  // Stored for eviction (need to erase from map by key)

        Entry(double rate, int64_t capacity)
            : bucket(rate, capacity),
              last_access(std::chrono::steady_clock::now()) {}
    };

    // --- Sharded hash map with per-shard LRU list ---
    struct Shard {
        mutable std::mutex mutex;
        std::unordered_map<std::string, std::unique_ptr<Entry>> buckets;
        Entry* lru_head = nullptr;  // Most recently accessed
        Entry* lru_tail = nullptr;  // Least recently accessed
        size_t count = 0;

        // Move entry to front of LRU (called under lock).
        void TouchLru(Entry* e);
        // Unlink entry from LRU list (called under lock).
        void RemoveLru(Entry* e);
        // Insert entry at head of LRU list (called under lock).
        void PushFrontLru(Entry* e);
    };

public:
    // Shard count — exposed publicly so config_loader can validate
    // max_entries against it (enforcing max_entries >= SHARD_COUNT keeps
    // the documented cap meaningful). Changing this value requires updating
    // the memory-cap documentation too.
    static constexpr size_t SHARD_COUNT = 16;

private:
    std::string name_;
    std::string key_type_;
    KeyExtractor key_extractor_;
    std::vector<Shard> shards_;

    // Hash key to shard index.
    size_t ShardIndex(const std::string& key) const;

    // Find existing entry or create a new one (called under shard lock).
    Entry* FindOrCreate(Shard& shard, const std::string& key,
                        const ZonePolicy& policy);

    // Shards are sized at construction and never resized. std::vector<Shard>
    // works because Shard contains std::mutex (non-movable), but any future
    // push_back / resize would fail to compile. This is intentional — shard
    // count is a compile-time constant (DEFAULT_SHARD_COUNT).
};

// Factory: build a KeyExtractor from a key_type string.
// Supported key types:
//   "client_ip"               - Client IP address
//   "path"                    - Request path
//   "header:{name}"           - Value of the named header
//   "client_ip+path"          - Client IP + "|" + path
//   "client_ip+header:{name}" - Client IP + "|" + header value
// Returns a lambda that returns empty string for unknown key types.
RateLimitZone::KeyExtractor MakeKeyExtractor(const std::string& key_type);
