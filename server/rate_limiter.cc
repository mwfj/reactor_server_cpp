#include "rate_limit/rate_limiter.h"
#include "log/logger.h"
#include "observability/counter.h"
#include "observability/histogram.h"
#include "observability/metrics_catalog.h"
#include "observability/observability_manager.h"
#include <cmath>
#include <limits>

namespace {

// Closed-set decision vocabulary for reactor.rate_limit.decisions. Kept
// next to RateLimitManager::Check so the emit-site label strings and
// the decision branches stay locally co-located.
constexpr const char* kDecisionAdmit       = "admit";
constexpr const char* kDecisionReject      = "reject";
constexpr const char* kDecisionDryRunReject = "dry_run_reject";

// Emit a single zone's decision + tokens-after-decision pair. Null-safe
// against manager / catalog instrument unavailability. Catches every
// exception — observability emit must not propagate into the request
// hot path.
void EmitRateLimitDecision(
    OBSERVABILITY_NAMESPACE::ObservabilityManager* mgr,
    const std::string& zone_name,
    const char* decision,
    int64_t tokens_after_decision) noexcept
{
    if (mgr == nullptr || decision == nullptr || zone_name.empty()) return;
    const auto& cat = mgr->catalog();
    try {
        if (cat.reactor_rate_limit_decisions != nullptr) {
            cat.reactor_rate_limit_decisions->Add(
                1.0,
                {{"zone", zone_name},
                 {"decision", decision}});
        }
        if (cat.reactor_rate_limit_tokens != nullptr) {
            double tokens = static_cast<double>(tokens_after_decision);
            if (tokens < 0.0) tokens = 0.0;
            cat.reactor_rate_limit_tokens->Record(
                tokens,
                {{"zone", zone_name}});
        }
    } catch (...) {
        // Defensive: observability is best-effort; never propagate.
    }
}

}  // namespace

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

bool RateLimitManager::Check(HttpRequest& request,
                             HttpResponse& response) {
    auto zones = LoadZones();
    if (!zones || zones->empty()) {
        return true;
    }

    // Snapshot obs_manager_ once per Check so every per-zone emit (and
    // the final denied/admitted emit) routes through the same manager
    // pointer. Acquire pairs with SetObservabilityManager's release.
    auto* mgr = obs_manager_.load(std::memory_order_acquire);
    const bool dry_run_mode = dry_run();

    // Track the most restrictive *applicable* zone across all checks.
    // Non-applicable zones (applies_to miss, empty key, etc.) are ignored
    // for header purposes — they did not govern this request.
    //
    // Note on multi-zone denial semantics: when a zone denies, we stop
    // evaluating later zones (match Nginx's "first deny wins"). This means
    // the emitted Retry-After reflects the first denying zone in config
    // order, not the longest wait across all zones. Operators should put
    // tighter (narrower, shorter-retry) zones first. If two zones would
    // both deny the same request, only the first is reported — the second
    // is not consulted to avoid unnecessary token debit.
    std::string best_name;
    int64_t best_limit = 0;
    int64_t best_remaining = INT64_MAX;
    double best_retry_after = 0.0;
    double best_rate = 0.0;
    bool denied = false;

    for (const auto& zone : *zones) {
        RateLimitZone::Result result = zone->Check(request);

        // Skip zones that didn't apply to this request — they must not
        // drive response headers (would incorrectly advertise limits on
        // requests those zones never actually governed). Non-applicable
        // zones are also excluded from the decisions counter — the zone
        // never governed this request, so there is no "decision" to
        // record.
        if (!result.applicable) {
            continue;
        }

        if (!result.allowed) {
            // Denied: record this zone for headers and stop evaluating
            // remaining zones. Continuing would debit tokens in zones
            // whose outcome cannot change the final decision — the
            // request is already rejected.
            best_name = zone->name();
            best_limit = result.limit;
            best_remaining = result.remaining;
            best_retry_after = result.retry_after_sec;
            best_rate = result.rate;
            denied = true;
            // Emit the denying zone's decision: `reject` under enforcement,
            // `dry_run_reject` under shadow mode. The middleware layer
            // converts dry_run-Check-false into a let-through, so the
            // metric must distinguish "would have rejected" from a real
            // reject for accurate shadow-mode dashboards.
            EmitRateLimitDecision(
                mgr, best_name,
                dry_run_mode ? kDecisionDryRunReject : kDecisionReject,
                result.remaining);
            break;
        }

        // Allowed: emit the admit decision for this zone, with tokens
        // remaining after debit so operators can see bucket-pressure
        // distribution per zone. Then track the most restrictive zone by
        // remaining/limit ratio. Lower ratio = more restrictive.
        EmitRateLimitDecision(mgr, zone->name(), kDecisionAdmit,
                              result.remaining);

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
            best_rate = result.rate;
        }
    }

    // Set RateLimit-Policy and RateLimit headers per IETF draft
    // (draft-ietf-httpapi-ratelimit-headers-10).
    //   RateLimit-Policy: {quota};w={window_seconds}
    //   RateLimit: limit={limit}, remaining={remaining}, reset={reset}
    //
    // For a token bucket with sustained rate R and burst capacity C, the
    // effective quota is C requests over a window of (C/R) seconds (the
    // time to refill from empty to full). Reporting w=1 with quota=C
    // misleads clients into thinking they can send C requests per second,
    // when the actual sustained rate is R.
    bool want_headers = include_headers();
    if (want_headers && !best_name.empty()) {
        // window_sec = ceil(capacity / rate). Minimum 1 to satisfy the
        // IETF draft's requirement that w is a positive integer.
        int64_t window_sec = 1;
        if (best_rate > 0.0 && best_limit > 0) {
            long double w = static_cast<long double>(best_limit) /
                            static_cast<long double>(best_rate);
            constexpr long double MAX_WINDOW_SEC =
                static_cast<long double>(std::numeric_limits<int64_t>::max());
            if (w >= MAX_WINDOW_SEC) {
                window_sec = std::numeric_limits<int64_t>::max();
            } else {
                window_sec = std::max<int64_t>(
                    1, static_cast<int64_t>(std::ceil(w)));
            }
        }

        // RateLimit-Policy: {quota};w={window}
        response.Header("RateLimit-Policy",
                        std::to_string(best_limit) + ";w=" +
                        std::to_string(window_sec));

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
    // 1. Store scalar atomics. Apply the enabled flag with transition-aware
    // ordering: disabling goes first so requests stop checking immediately,
    // enabling goes last so no request can observe enabled=true with the old
    // zone snapshot.
    if (!config.enabled) {
        enabled_.store(false, std::memory_order_release);
    }
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

    if (config.enabled) {
        enabled_.store(true, std::memory_order_release);
    }

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

// ---------------------------------------------------------------------------
// SetObservabilityManager
// ---------------------------------------------------------------------------

void RateLimitManager::SetObservabilityManager(
    OBSERVABILITY_NAMESPACE::ObservabilityManager* obs_manager) noexcept
{
    obs_manager_.store(obs_manager, std::memory_order_release);
}
