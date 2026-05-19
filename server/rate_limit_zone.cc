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
// Per-shard cap rounding helper
// ---------------------------------------------------------------------------
//
// Floor with min-1: enforces a hard RAM cap while never producing a
// zero-capacity shard (which the cache constructor rejects).

namespace {

size_t ComputeRateLimitPerShardCap(int max_entries) {
    size_t cap = static_cast<size_t>(max_entries) / RateLimitZone::SHARD_COUNT;
    return cap == 0 ? 1u : cap;
}

}  // namespace

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------

RateLimitZone::RateLimitZone(const std::string& name,
                             const RateLimitZoneConfig& config,
                             KeyExtractor extractor)
    : name_(name),
      key_type_(config.key_type),
      key_extractor_(std::move(extractor)),
      cache_(SHARD_COUNT, ComputeRateLimitPerShardCap(config.max_entries))
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
// Check
// ---------------------------------------------------------------------------

RateLimitZone::Result RateLimitZone::Check(const HttpRequest& request) {
    auto policy = LoadPolicy();

    // applicable=false skips this zone when building RateLimit-* response
    // headers so client-facing headers reflect only zones that governed
    // the request.
    Result not_applicable{
        /*allowed=*/true,
        /*applicable=*/false,
        /*limit=*/policy->capacity,
        /*remaining=*/policy->capacity,
        /*retry_after_sec=*/0.0,
        /*rate=*/policy->rate
    };

    if (!policy->applies_to.empty()) {
        bool matched = false;
        for (const auto& prefix : policy->applies_to) {
            if (request.path.size() >= prefix.size() &&
                request.path.compare(0, prefix.size(), prefix) == 0) {
                // Segment-boundary match: "/api" matches "/api", "/api/",
                // "/api/users" but NOT "/apis" or "/api2".
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

    std::string key = key_extractor_(request);
    if (key.empty()) {
        return not_applicable;
    }

    const auto now = std::chrono::steady_clock::now();
    auto handle = cache_.FindOrCreate(key, [&]() -> RateLimitZone::RateLimitEntry {
        return RateLimitZone::RateLimitEntry{TokenBucket(policy->rate, policy->capacity), now};
    });
    handle->last_access = now;

    // Compare rate as millitokens (integer) to avoid spurious mismatches
    // from floating-point round-trip (rate=0.3 stored as 299 mt reads
    // back as 0.299, which != 0.3 and would trigger UpdateConfig on every
    // request on the hot path).
    int64_t policy_rate_mt = static_cast<int64_t>(policy->rate * 1000);
    if (handle->bucket.Capacity() != policy->capacity ||
        handle->bucket.RateMillitokens() != policy_rate_mt) {
        handle->bucket.UpdateConfig(policy->rate, policy->capacity);
    }

    bool allowed = handle->bucket.TryConsume();
    int64_t remaining = handle->bucket.AvailableTokens();
    double retry_after = handle->bucket.SecondsUntilAvailable();

    return {allowed, /*applicable=*/true, policy->capacity, remaining,
            retry_after, policy->rate};
}

// ---------------------------------------------------------------------------
// EvictExpired
// ---------------------------------------------------------------------------

void RateLimitZone::EvictExpired(size_t dispatcher_index, size_t dispatcher_count) {
    if (dispatcher_count == 0) return;

    auto policy = LoadPolicy();
    const size_t max_per_shard = ComputeRateLimitPerShardCap(policy->max_entries);

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

    // Stride across shards assigned to this dispatcher. Predicate combines
    // over-cap and idle-cutoff into one tail walk; the cache stops at the
    // first entry that satisfies neither.
    const size_t shard_count = cache_.ShardCount();
    for (size_t i = dispatcher_index; i < shard_count; i += dispatcher_count) {
        cache_.EvictFromTailWhile(i,
            [cutoff, max_per_shard](const RateLimitZone::RateLimitEntry& entry, std::size_t size) {
                return size > max_per_shard || entry.last_access < cutoff;
            });
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

    // Propagate the new per-shard cap to the cache. Existing entries are
    // NOT proactively shed — the next EvictExpired tick or the first
    // over-cap insert evicts down to the new cap.
    cache_.ResizePerShardCap(ComputeRateLimitPerShardCap(config.max_entries));

    logging::Get()->debug("RateLimitZone '{}' config updated: rate={} capacity={} max_entries={}",
                          name_, config.rate, config.capacity, config.max_entries);
}

// ---------------------------------------------------------------------------
// EntryCount
// ---------------------------------------------------------------------------

size_t RateLimitZone::EntryCount() const {
    return cache_.Size();
}
