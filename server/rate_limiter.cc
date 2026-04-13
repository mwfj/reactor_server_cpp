#include "rate_limit/rate_limiter.h"
#include "log/logger.h"
#include <cmath>

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------

RateLimitManager::RateLimitManager(const RateLimitConfig& config) {
    enabled_.store(config.enabled, std::memory_order_release);
    dry_run_.store(config.dry_run, std::memory_order_release);
    status_code_.store(config.status_code, std::memory_order_release);
    include_headers_.store(config.include_headers, std::memory_order_release);

    auto zone_list = std::make_shared<ZoneList>();
    zone_list->reserve(config.zones.size());
    for (const auto& zc : config.zones) {
        auto extractor = MakeKeyExtractor(zc.key_type);
        zone_list->push_back(
            std::make_shared<RateLimitZone>(zc.name, zc, std::move(extractor)));
    }
    StoreZones(std::move(zone_list));

    logging::Get()->info("RateLimitManager created: enabled={} dry_run={} "
                         "status_code={} include_headers={} zones={}",
                         config.enabled, config.dry_run,
                         config.status_code, config.include_headers,
                         config.zones.size());
}

RateLimitManager::~RateLimitManager() {
    logging::Get()->debug("RateLimitManager destroyed");
}

// ---------------------------------------------------------------------------
// Check
// ---------------------------------------------------------------------------

bool RateLimitManager::Check(const HttpRequest& request,
                             HttpResponse& response) {
    auto zones = LoadZones();
    if (!zones || zones->empty()) {
        return true;
    }

    // Track the most restrictive zone across all checks.
    std::string best_name;
    int64_t best_limit = 0;
    int64_t best_remaining = INT64_MAX;
    double best_retry_after = 0.0;
    bool denied = false;

    for (const auto& zone : *zones) {
        RateLimitZone::Result result = zone->Check(request);

        if (!result.allowed) {
            // Denied: record this zone for headers and stop evaluating
            // remaining zones. Continuing would debit tokens in zones
            // whose outcome cannot change the final decision — the
            // request is already rejected.
            // Matches Nginx's behavior (first-deny wins, later zones
            // are not consulted).
            best_name = zone->name();
            best_limit = result.limit;
            best_remaining = result.remaining;
            best_retry_after = result.retry_after_sec;
            denied = true;
            break;
        }

        // Allowed: track the most restrictive zone by remaining/limit ratio.
        // Lower ratio = more restrictive.
        double ratio = (result.limit > 0)
            ? static_cast<double>(result.remaining) / static_cast<double>(result.limit)
            : 1.0;
        double best_ratio = (best_limit > 0)
            ? static_cast<double>(best_remaining) / static_cast<double>(best_limit)
            : 1.0;

        if (best_name.empty() || ratio < best_ratio) {
            best_name = zone->name();
            best_limit = result.limit;
            best_remaining = result.remaining;
            best_retry_after = result.retry_after_sec;
        }
    }

    // Set RateLimit-Policy and RateLimit headers per IETF draft
    // (draft-ietf-httpapi-ratelimit-headers-10).
    //   RateLimit-Policy: {limit};w={window}
    //   RateLimit: limit={limit}, remaining={remaining}, reset={reset}
    bool want_headers = include_headers();
    if (want_headers && !best_name.empty()) {
        // RateLimit-Policy: {limit};w=1
        // w=1 (1-second window) matches the token bucket's per-second rate.
        response.Header("RateLimit-Policy",
                        std::to_string(best_limit) + ";w=1");

        // RateLimit: limit={L}, remaining={R}, reset={T}
        int reset_ceil = (best_retry_after > 0.0)
            ? static_cast<int>(std::ceil(best_retry_after))
            : 0;
        response.Header("RateLimit",
                        "limit=" + std::to_string(best_limit) + ", " +
                        "remaining=" + std::to_string(best_remaining) + ", " +
                        "reset=" + std::to_string(reset_ceil));
    }

    if (denied) {
        total_denied_.fetch_add(1, std::memory_order_relaxed);

        if (want_headers) {
            // Retry-After: minimum 1 second
            int retry_sec = static_cast<int>(std::ceil(best_retry_after));
            if (retry_sec < 1) retry_sec = 1;
            response.Header("Retry-After", std::to_string(retry_sec));
        }

        logging::Get()->debug("Rate limit denied: zone='{}' client_ip={} path={} "
                              "retry_after={}s",
                              best_name, request.client_ip, request.path,
                              best_retry_after);
        return false;
    }

    total_allowed_.fetch_add(1, std::memory_order_relaxed);
    return true;
}

// ---------------------------------------------------------------------------
// EvictExpired
// ---------------------------------------------------------------------------

void RateLimitManager::EvictExpired(size_t dispatcher_index,
                                    size_t dispatcher_count) {
    auto zones = LoadZones();
    if (!zones) return;

    for (const auto& zone : *zones) {
        zone->EvictExpired(dispatcher_index, dispatcher_count);
    }
}

// ---------------------------------------------------------------------------
// Reload
// ---------------------------------------------------------------------------

void RateLimitManager::Reload(const RateLimitConfig& config) {
    // 1. Store scalar atomics
    enabled_.store(config.enabled, std::memory_order_release);
    dry_run_.store(config.dry_run, std::memory_order_release);
    status_code_.store(config.status_code, std::memory_order_release);
    include_headers_.store(config.include_headers, std::memory_order_release);

    // 2. Load old zone list snapshot
    auto old_zones = LoadZones();

    // 3. Build new zone list, reusing existing zones where name+key_type match
    auto new_zones = std::make_shared<ZoneList>();
    new_zones->reserve(config.zones.size());

    for (const auto& zc : config.zones) {
        std::shared_ptr<RateLimitZone> reused;

        if (old_zones) {
            for (const auto& old_zone : *old_zones) {
                if (old_zone->name() == zc.name &&
                    old_zone->key_type() == zc.key_type) {
                    old_zone->UpdateConfig(zc);
                    reused = old_zone;
                    break;
                }
            }
        }

        if (reused) {
            new_zones->push_back(std::move(reused));
        } else {
            auto extractor = MakeKeyExtractor(zc.key_type);
            new_zones->push_back(
                std::make_shared<RateLimitZone>(zc.name, zc, std::move(extractor)));
        }
    }

    // 4. Swap the zone list atomically
    StoreZones(std::move(new_zones));

    logging::Get()->info("RateLimitManager reloaded: enabled={} dry_run={} "
                         "status_code={} zones={}",
                         config.enabled, config.dry_run,
                         config.status_code, config.zones.size());
}

// ---------------------------------------------------------------------------
// TotalEntryCount
// ---------------------------------------------------------------------------

size_t RateLimitManager::TotalEntryCount() const {
    auto zones = LoadZones();
    if (!zones) return 0;

    size_t total = 0;
    for (const auto& zone : *zones) {
        total += zone->EntryCount();
    }
    return total;
}
