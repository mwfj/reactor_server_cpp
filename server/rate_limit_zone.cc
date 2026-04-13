#include "rate_limit/rate_limit_zone.h"
#include "log/logger.h"

// ---------------------------------------------------------------------------
// MakeKeyExtractor — factory for key extraction lambdas
// ---------------------------------------------------------------------------

static constexpr size_t HEADER_PREFIX_LEN = 7;           // strlen("header:")
static constexpr size_t COMPOSITE_HEADER_PREFIX_LEN = 17; // strlen("client_ip+header:")

RateLimitZone::KeyExtractor MakeKeyExtractor(const std::string& key_type) {
    if (key_type == "client_ip") {
        return [](const HttpRequest& req) -> std::string {
            return req.client_ip;
        };
    }
    if (key_type == "path") {
        return [](const HttpRequest& req) -> std::string {
            return req.path;
        };
    }
    if (key_type.size() > HEADER_PREFIX_LEN &&
        key_type.substr(0, HEADER_PREFIX_LEN) == "header:") {
        std::string header_name = key_type.substr(HEADER_PREFIX_LEN);
        return [header_name](const HttpRequest& req) -> std::string {
            return req.GetHeader(header_name);
        };
    }
    if (key_type == "client_ip+path") {
        return [](const HttpRequest& req) -> std::string {
            if (req.client_ip.empty()) return "";
            return req.client_ip + "|" + req.path;
        };
    }
    if (key_type.size() > COMPOSITE_HEADER_PREFIX_LEN &&
        key_type.substr(0, COMPOSITE_HEADER_PREFIX_LEN) == "client_ip+header:") {
        std::string header_name = key_type.substr(COMPOSITE_HEADER_PREFIX_LEN);
        return [header_name](const HttpRequest& req) -> std::string {
            if (req.client_ip.empty()) return "";
            std::string hval = req.GetHeader(header_name);
            if (hval.empty()) return "";
            return req.client_ip + "|" + hval;
        };
    }

    // Unknown key type — log warning and return extractor that always yields empty.
    logging::Get()->warn("Unknown rate limit key_type '{}', zone will pass all requests",
                         key_type);
    return [](const HttpRequest&) -> std::string {
        return "";
    };
}

// ---------------------------------------------------------------------------
// Shard LRU helpers (all called under shard lock)
// ---------------------------------------------------------------------------

void RateLimitZone::Shard::TouchLru(Entry* e) {
    if (e == lru_head) return;  // Already most-recent
    RemoveLru(e);
    PushFrontLru(e);
}

void RateLimitZone::Shard::RemoveLru(Entry* e) {
    if (e->lru_prev) {
        e->lru_prev->lru_next = e->lru_next;
    } else {
        lru_head = e->lru_next;
    }
    if (e->lru_next) {
        e->lru_next->lru_prev = e->lru_prev;
    } else {
        lru_tail = e->lru_prev;
    }
    e->lru_prev = nullptr;
    e->lru_next = nullptr;
}

void RateLimitZone::Shard::PushFrontLru(Entry* e) {
    e->lru_prev = nullptr;
    e->lru_next = lru_head;
    if (lru_head) {
        lru_head->lru_prev = e;
    }
    lru_head = e;
    if (!lru_tail) {
        lru_tail = e;
    }
}

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------

RateLimitZone::RateLimitZone(const std::string& name,
                             const RateLimitZoneConfig& config,
                             KeyExtractor extractor)
    : name_(name),
      key_type_(config.key_type),
      key_extractor_(std::move(extractor)),
      shards_(SHARD_COUNT)
{
    auto policy = std::make_shared<ZonePolicy>();
    policy->rate = config.rate;
    policy->capacity = config.capacity;
    policy->max_entries = config.max_entries;
    policy->applies_to = config.applies_to;
    StorePolicy(std::move(policy));

    logging::Get()->debug("RateLimitZone '{}' created: rate={} capacity={} key_type={} "
                          "max_entries={} shards={}",
                          name_, config.rate, config.capacity, config.key_type,
                          config.max_entries, SHARD_COUNT);
}

RateLimitZone::~RateLimitZone() {
    logging::Get()->debug("RateLimitZone '{}' destroyed", name_);
}

// ---------------------------------------------------------------------------
// ShardIndex
// ---------------------------------------------------------------------------

size_t RateLimitZone::ShardIndex(const std::string& key) const {
    return std::hash<std::string>{}(key) % shards_.size();
}

// ---------------------------------------------------------------------------
// FindOrCreate (called under shard lock)
// ---------------------------------------------------------------------------

RateLimitZone::Entry* RateLimitZone::FindOrCreate(Shard& shard,
                                                   const std::string& key,
                                                   const ZonePolicy& policy) {
    auto it = shard.buckets.find(key);
    if (it != shard.buckets.end()) {
        return it->second.get();
    }

    // Enforce max_entries synchronously on insert. Relying on the periodic
    // timer sweep alone lets high-cardinality bursts (many unique keys per
    // interval) grow the shard far beyond the configured cap, which makes
    // max_entries useless as a RAM guard under adversarial traffic.
    //
    // max_per_shard: floor(max_entries / SHARD_COUNT), minimum 1 so we
    // never produce a zero-capacity shard. Matches the EvictExpired math.
    //
    // Tradeoff: drastic reductions via Reload() (e.g., 100k → 16) will
    // cause the first insert into an over-capacity shard to evict many
    // entries under the shard lock. Extreme reductions are rare and the
    // memory guarantee is considered worth the one-time latency spike.
    size_t max_per_shard = static_cast<size_t>(policy.max_entries) / shards_.size();
    if (max_per_shard == 0) max_per_shard = 1;
    // Evict LRU tail until there's room for the new entry.
    while (shard.count >= max_per_shard && shard.lru_tail != nullptr) {
        Entry* victim = shard.lru_tail;
        std::string victim_key = std::move(victim->key);
        shard.RemoveLru(victim);
        shard.buckets.erase(victim_key);
        shard.count--;
    }

    // Create new entry
    auto entry = std::make_unique<Entry>(policy.rate, policy.capacity);
    entry->key = key;
    Entry* raw = entry.get();
    shard.buckets.emplace(key, std::move(entry));
    shard.PushFrontLru(raw);
    shard.count++;
    return raw;
}

// ---------------------------------------------------------------------------
// Check
// ---------------------------------------------------------------------------

RateLimitZone::Result RateLimitZone::Check(const HttpRequest& request) {
    // 1. Load immutable policy snapshot
    auto policy = LoadPolicy();

    // "Not applicable" result — zone didn't apply to this request.
    // applicable=false tells the manager to skip this zone when building
    // response headers (so RateLimit-* headers reflect the actual zones
    // that governed the request, not skipped zones).
    Result not_applicable{
        /*allowed=*/true,
        /*applicable=*/false,
        /*limit=*/policy->capacity,
        /*remaining=*/policy->capacity,
        /*retry_after_sec=*/0.0,
        /*rate=*/policy->rate
    };

    // 2. Check applies_to filter: if non-empty, request path must match
    //    at least one prefix on a segment boundary. "/api" matches
    //    "/api", "/api/", "/api/users" but NOT "/apis" or "/api2".
    if (!policy->applies_to.empty()) {
        bool matched = false;
        for (const auto& prefix : policy->applies_to) {
            if (request.path.size() >= prefix.size() &&
                request.path.compare(0, prefix.size(), prefix) == 0) {
                // Ensure the match ends at a segment boundary:
                // prefix already ends with '/', OR path matches exactly,
                // OR the next character is '/'.
                if (prefix.back() == '/' ||
                    request.path.size() == prefix.size() ||
                    request.path[prefix.size()] == '/') {
                    matched = true;
                    break;
                }
            }
        }
        if (!matched) {
            return not_applicable;
        }
    }

    // 3. Extract key from request
    std::string key = key_extractor_(request);
    if (key.empty()) {
        // No key extracted (e.g., missing header) — zone doesn't apply.
        return not_applicable;
    }

    // 4. Hash to shard and lock
    size_t idx = ShardIndex(key);
    Shard& shard = shards_[idx];
    std::lock_guard<std::mutex> lk(shard.mutex);

    // 5. Find or create entry
    Entry* entry = FindOrCreate(shard, key, *policy);

    // 6. Update access time and LRU position
    entry->last_access = std::chrono::steady_clock::now();
    shard.TouchLru(entry);

    // 7. Lazy config update: sync bucket with current policy if rate or
    //    capacity changed. UpdateConfig calls Refill() first to materialize
    //    tokens accrued under the old rate before switching.
    //
    //    Compare rate as millitokens (integer) to avoid spurious mismatches
    //    from floating-point round-trip (e.g., rate=0.3 stored as 299 mt
    //    reads back as 0.299, which != 0.3 and would trigger UpdateConfig
    //    on every request on the hot path).
    int64_t policy_rate_mt = static_cast<int64_t>(policy->rate * 1000);
    if (entry->bucket.Capacity() != policy->capacity ||
        entry->bucket.RateMillitokens() != policy_rate_mt) {
        entry->bucket.UpdateConfig(policy->rate, policy->capacity);
    }

    // 8. Attempt to consume a token
    bool allowed = entry->bucket.TryConsume();
    int64_t remaining = entry->bucket.AvailableTokens();
    double retry_after = entry->bucket.SecondsUntilAvailable();

    return {allowed, /*applicable=*/true, policy->capacity, remaining,
            retry_after, policy->rate};
}

// ---------------------------------------------------------------------------
// EvictExpired
// ---------------------------------------------------------------------------

void RateLimitZone::EvictExpired(size_t dispatcher_index, size_t dispatcher_count) {
    if (dispatcher_count == 0) return;

    auto policy = LoadPolicy();

    // Compute per-shard capacity limit (minimum 1 to avoid zero-cap)
    size_t shard_count = shards_.size();
    size_t max_per_shard = static_cast<size_t>(policy->max_entries) / shard_count;
    if (max_per_shard == 0) max_per_shard = 1;

    // Compute idle cutoff: 4 full refill cycles (capacity / rate * 4 seconds).
    // An entry idle for this long has fully refilled and is wasting memory.
    auto now = std::chrono::steady_clock::now();
    double refill_sec = (policy->rate > 0.0)
        ? (static_cast<double>(policy->capacity) / policy->rate)
        : 60.0;  // Fallback: 60 seconds if rate is zero
    static constexpr int IDLE_REFILL_CYCLES = 4;
    auto cutoff = std::chrono::steady_clock::time_point::min();
    long double idle_window_sec =
        static_cast<long double>(refill_sec) *
        static_cast<long double>(IDLE_REFILL_CYCLES);
    long double max_duration_sec = std::chrono::duration<long double>(
        std::chrono::steady_clock::duration::max()).count();
    if (idle_window_sec < max_duration_sec) {
        auto cutoff_duration =
            std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                std::chrono::duration<long double>(idle_window_sec));
        if (cutoff_duration <= now.time_since_epoch()) {
            cutoff = now - cutoff_duration;
        }
    }

    // Stride across shards assigned to this dispatcher
    for (size_t i = dispatcher_index; i < shard_count; i += dispatcher_count) {
        Shard& shard = shards_[i];
        std::lock_guard<std::mutex> lk(shard.mutex);

        // Evict from tail (LRU = least recently used)
        while (shard.lru_tail != nullptr &&
               (shard.count > max_per_shard ||
                shard.lru_tail->last_access < cutoff)) {
            Entry* victim = shard.lru_tail;
            std::string victim_key = std::move(victim->key);
            shard.RemoveLru(victim);
            shard.buckets.erase(victim_key);
            shard.count--;
        }
    }
}

// ---------------------------------------------------------------------------
// UpdateConfig
// ---------------------------------------------------------------------------

void RateLimitZone::UpdateConfig(const RateLimitZoneConfig& config) {
    auto policy = std::make_shared<ZonePolicy>();
    policy->rate = config.rate;
    policy->capacity = config.capacity;
    policy->max_entries = config.max_entries;
    policy->applies_to = config.applies_to;
    StorePolicy(std::move(policy));

    logging::Get()->debug("RateLimitZone '{}' config updated: rate={} capacity={} max_entries={}",
                          name_, config.rate, config.capacity, config.max_entries);
}

// ---------------------------------------------------------------------------
// EntryCount
// ---------------------------------------------------------------------------

size_t RateLimitZone::EntryCount() const {
    size_t total = 0;
    for (const auto& shard : shards_) {
        std::lock_guard<std::mutex> lk(shard.mutex);
        total += shard.count;
    }
    return total;
}
