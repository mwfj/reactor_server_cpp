#include "auth/introspection_cache.h"

#include "log/logger.h"

#include <new>
#include <utility>

namespace AUTH_NAMESPACE {

namespace {

constexpr size_t MAX_SHARD_COUNT = 64;

// Validates both args before computing the ceil-divided per-shard cap; the
// shard_count check must run before division to avoid divide-by-zero.
size_t ComputeIntrospectionPerShardCap(size_t max_entries, size_t shard_count) {
    if (shard_count == 0 || shard_count > MAX_SHARD_COUNT ||
        (shard_count & (shard_count - 1)) != 0) {
        throw std::invalid_argument(
            "IntrospectionCache: shard_count must be a power of two in [1, 64]");
    }
    if (max_entries == 0) {
        throw std::invalid_argument(
            "IntrospectionCache: max_entries must be > 0");
    }
    return (max_entries + shard_count - 1) / shard_count;
}

}  // namespace

IntrospectionCache::IntrospectionCache(std::string issuer_name,
                                       size_t max_entries,
                                       size_t shard_count)
    : issuer_name_(std::move(issuer_name)),
      shard_count_(shard_count),
      cache_(shard_count,
             ComputeIntrospectionPerShardCap(max_entries, shard_count)) {}

IntrospectionCache::~IntrospectionCache() = default;

IntrospectionCache::LookupResult IntrospectionCache::Lookup(
    const std::string& key,
    std::chrono::steady_clock::time_point now) {
    auto handle = cache_.Find(key);  // no touch
    if (!handle) {
        miss_.fetch_add(1, std::memory_order_relaxed);
        return {};
    }
    if (now >= handle->ttl_expiry) {
        // Expired entries are not promoted; LookupStale can still serve them
        // within grace, and LRU eviction reaps them when the shard fills.
        miss_.fetch_add(1, std::memory_order_relaxed);
        return {};
    }
    cache_.Touch(handle);  // promote only on fresh hit

    LookupResult r;
    r.state = LookupState::Fresh;
    r.active = handle->active;
    if (handle->active) {
        r.ctx = handle->ctx;
        hit_.fetch_add(1, std::memory_order_relaxed);
    } else {
        negative_hit_.fetch_add(1, std::memory_order_relaxed);
    }
    return r;
}

IntrospectionCache::LookupResult IntrospectionCache::LookupStale(
    const std::string& key,
    std::chrono::steady_clock::time_point now) {
    auto handle = cache_.Find(key);  // no touch
    if (!handle) return {};

    if (!handle->active) {
        // Never stale-serve a negative cache entry.
        return {};
    }
    const auto grace = std::chrono::seconds(
        stale_grace_sec_.load(std::memory_order_relaxed));
    if (now < handle->ttl_expiry || now > handle->ttl_expiry + grace) {
        return {};
    }

    LookupResult r;
    r.state = LookupState::Stale;
    r.active = true;
    r.ctx = handle->ctx;
    stale_served_.fetch_add(1, std::memory_order_relaxed);
    return r;
}

void IntrospectionCache::Insert(const std::string& key,
                                AuthContext ctx,
                                bool active,
                                std::chrono::seconds ttl) {
    if (ttl <= std::chrono::seconds::zero()) {
        return;
    }
    const auto expiry = std::chrono::steady_clock::now() + ttl;
    IntrospectionCache::AuthEntry entry{std::move(ctx), active, expiry};

    try {
        cache_.Insert(key, std::move(entry));
    } catch (const std::bad_alloc&) {
        logging::Get()->warn(
            "IntrospectionCache[{}]: insert dropped on bad_alloc",
            issuer_name_);
    } catch (const std::exception& e) {
        logging::Get()->warn(
            "IntrospectionCache[{}]: insert dropped on exception: {}",
            issuer_name_, e.what());
    }
}

void IntrospectionCache::ApplyReload(const IntrospectionConfig& new_cfg) {
    stale_grace_sec_.store(new_cfg.stale_grace_sec,
                           std::memory_order_relaxed);
    if (new_cfg.max_entries > 0) {
        const size_t max_entries = static_cast<size_t>(new_cfg.max_entries);
        const size_t per_shard =
            (max_entries + shard_count_ - 1) / shard_count_;
        cache_.ResizePerShardCap(per_shard);
    }
}

void IntrospectionCache::Clear() {
    cache_.Clear();
}

IntrospectionCache::Stats IntrospectionCache::SnapshotStats() const {
    Stats s;
    s.hit = hit_.load(std::memory_order_relaxed);
    s.miss = miss_.load(std::memory_order_relaxed);
    s.negative_hit = negative_hit_.load(std::memory_order_relaxed);
    s.stale_served = stale_served_.load(std::memory_order_relaxed);
    s.entries = cache_.Size();
    return s;
}

}  // namespace AUTH_NAMESPACE
