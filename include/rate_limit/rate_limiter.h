#pragma once

#include "rate_limit/rate_limit_zone.h"
#include "http/http_request.h"
#include "http/http_response.h"
#include "config/server_config.h"
// <atomic>, <memory>, <mutex>, <vector> provided by common.h (via http_request.h)

class RateLimitManager {
public:
    explicit RateLimitManager(const RateLimitConfig& config);
    ~RateLimitManager();

    RateLimitManager(const RateLimitManager&) = delete;
    RateLimitManager& operator=(const RateLimitManager&) = delete;

    // Check whether a request is allowed under all configured rate limit zones.
    // Sets RateLimit-Policy, RateLimit, and Retry-After response headers as
    // appropriate. Returns true if allowed, false if denied.
    // Thread-safe: reads atomic scalars + snapshot of zone list.
    bool Check(const HttpRequest& request, HttpResponse& response);

    // Evict expired entries from zone shards assigned to this dispatcher.
    // Called periodically from the dispatcher timer handler.
    void EvictExpired(size_t dispatcher_index, size_t dispatcher_count);

    // Hot-reload: update all policy fields and zone list from new config.
    // Reuses existing zones by name+key_type match; creates new zones otherwise.
    // Thread-safe: swaps atomic scalars + zone list snapshot.
    void Reload(const RateLimitConfig& config);

    // Return total entry count across all zones (diagnostic/stats).
    size_t TotalEntryCount() const;

    // Scalar policy accessors (lock-free, acquire semantics).
    bool enabled() const { return enabled_.load(std::memory_order_acquire); }
    bool dry_run() const { return dry_run_.load(std::memory_order_acquire); }
    int status_code() const { return status_code_.load(std::memory_order_acquire); }
    bool include_headers() const { return include_headers_.load(std::memory_order_acquire); }

    // Stats accessors (relaxed — tolerate slightly stale snapshots).
    int64_t total_allowed() const { return total_allowed_.load(std::memory_order_relaxed); }
    int64_t total_denied() const { return total_denied_.load(std::memory_order_relaxed); }

private:
    // --- Scalar policy fields (atomic, no mutex needed) ---
    std::atomic<bool> enabled_{false};
    std::atomic<bool> dry_run_{false};
    std::atomic<int>  status_code_{429};
    std::atomic<bool> include_headers_{true};

    // --- Zone list (shared_ptr snapshot, guarded by mutex) ---
    using ZoneList = std::vector<std::shared_ptr<RateLimitZone>>;
    std::shared_ptr<ZoneList> zones_;
    mutable std::mutex zones_mtx_;

    std::shared_ptr<ZoneList> LoadZones() const {
        std::lock_guard<std::mutex> lk(zones_mtx_);
        return zones_;
    }
    void StoreZones(std::shared_ptr<ZoneList> z) {
        std::lock_guard<std::mutex> lk(zones_mtx_);
        zones_ = std::move(z);
    }

    // --- Stats counters (relaxed atomics) ---
    std::atomic<int64_t> total_allowed_{0};
    std::atomic<int64_t> total_denied_{0};
};
