#include "auth/jwks_cache.h"
#include "log/logger.h"

// JWKS parsing (jwt::parse_jwks) lives in JwksFetcher, not here — that
// keeps exception containment at the jwt-cpp boundary owned by one file
// (design §9 item 16). The real parse path is invoked from JwksFetcher.
// The jwks_cache unit tests in Phase I use `InstallKeys` directly.

namespace AUTH_NAMESPACE {

JwksCache::JwksCache(std::string issuer_name, int ttl_sec, size_t hard_cap)
    : issuer_name_(std::move(issuer_name)),
      ttl_sec_(ttl_sec > 0 ? ttl_sec : 300),
      hard_cap_(hard_cap > 0 ? hard_cap : kDefaultJwksHardCap),
      keys_(std::make_shared<KeyMap>()) {
    logging::Get()->debug(
        "JwksCache created issuer={} ttl_sec={} hard_cap={}",
        issuer_name_, ttl_sec_.load(std::memory_order_relaxed), hard_cap_);
}

std::shared_ptr<const std::string> JwksCache::LookupKeyByKid(
        const std::string& kid) const {
    std::shared_ptr<const KeyMap> snap;
    {
        std::lock_guard<std::mutex> lk(keys_mtx_);
        snap = keys_;
    }
    if (!snap || snap->empty()) return nullptr;

    // Exact kid lookup first.
    auto it = snap->find(kid);
    if (it != snap->end()) return it->second;

    // Single-key-tolerant fallback: RFC 7515 §4.1.4 allows the header
    // `kid` to be omitted when the JWKS has exactly one key, and some
    // minimal IdPs don't emit a kid field on the JWK itself — our
    // installer stores it under "" in that case. If the token header was
    // missing a kid AND the JWKS is single-entry, return that entry.
    if (kid.empty() && snap->size() == 1) {
        return snap->begin()->second;
    }
    return nullptr;
}

size_t JwksCache::InstallKeys(
        std::vector<std::pair<std::string, std::string>> keys) {
    auto new_map = std::make_shared<KeyMap>();
    size_t installed = 0;
    bool trimmed = false;
    for (auto& [kid, pem] : keys) {
        if (installed >= hard_cap_) {
            trimmed = true;
            break;
        }
        if (pem.empty()) continue;
        auto pem_sp = std::make_shared<const std::string>(std::move(pem));
        (*new_map)[std::move(kid)] = std::move(pem_sp);
        ++installed;
    }
    if (trimmed) {
        logging::Get()->warn(
            "JwksCache issuer={} trimmed JWKS to {} keys (hard_cap exceeded)",
            issuer_name_, hard_cap_);
    }

    const auto now = std::chrono::system_clock::now();
    {
        std::lock_guard<std::mutex> lk(keys_mtx_);
        keys_ = std::move(new_map);
    }
    {
        std::lock_guard<std::mutex> lk(stats_mtx_);
        last_refresh_ = now;
    }
    refresh_ok_.fetch_add(1, std::memory_order_relaxed);
    // Success resets stale_served counter's "since last success" meaning
    // only at the caller's convenience — we deliberately do NOT clear it
    // so operators can see cumulative stale-serve activity.
    logging::Get()->info(
        "JwksCache refresh ok issuer={} keys={}",
        issuer_name_, installed);
    return installed;
}

void JwksCache::OnFetchError(const std::string& reason) {
    refresh_fail_.fetch_add(1, std::memory_order_relaxed);
    // Rate-limit the warn so a dead IdP doesn't spam the log. One warn
    // per TTL is enough for operator awareness; the counter is available
    // via SnapshotStats for precise monitoring.
    bool should_warn = false;
    {
        std::lock_guard<std::mutex> lk(stats_mtx_);
        const auto now = std::chrono::steady_clock::now();
        if (last_stale_warn_.time_since_epoch().count() == 0 ||
            now - last_stale_warn_ >= std::chrono::seconds(
                ttl_sec_.load(std::memory_order_relaxed))) {
            last_stale_warn_ = now;
            should_warn = true;
        }
    }
    if (should_warn) {
        logging::Get()->warn(
            "JwksCache refresh failed issuer={} reason={} — serving stale keys",
            issuer_name_, reason);
    } else {
        logging::Get()->debug(
            "JwksCache refresh failed issuer={} reason={} (suppressed)",
            issuer_name_, reason);
    }
}

JwksCache::Snapshot JwksCache::SnapshotStats() const {
    Snapshot out;
    {
        std::shared_ptr<const KeyMap> snap;
        {
            std::lock_guard<std::mutex> lk(keys_mtx_);
            snap = keys_;
        }
        out.key_count = snap ? snap->size() : 0;
    }
    out.refresh_ok = refresh_ok_.load(std::memory_order_relaxed);
    out.refresh_fail = refresh_fail_.load(std::memory_order_relaxed);
    out.stale_served = stale_served_.load(std::memory_order_relaxed);
    {
        std::lock_guard<std::mutex> lk(stats_mtx_);
        out.last_refresh = last_refresh_;
    }
    return out;
}

bool JwksCache::IsTtlExpired() const {
    std::chrono::system_clock::time_point last;
    {
        std::lock_guard<std::mutex> lk(stats_mtx_);
        last = last_refresh_;
    }
    if (last.time_since_epoch().count() == 0) {
        // No refresh ever — treat as expired so Issuer triggers initial fetch.
        return true;
    }
    const auto now = std::chrono::system_clock::now();
    return (now - last) >= std::chrono::seconds(
        ttl_sec_.load(std::memory_order_relaxed));
}

bool JwksCache::AcquireRefreshSlot() {
    bool expected = false;
    return refresh_in_flight_.compare_exchange_strong(
        expected, true, std::memory_order_acq_rel, std::memory_order_acquire);
}

void JwksCache::ReleaseRefreshSlot() {
    refresh_in_flight_.store(false, std::memory_order_release);
}

void JwksCache::IncrementStaleServed() {
    stale_served_.fetch_add(1, std::memory_order_relaxed);
}

void JwksCache::SetTtlSec(int new_ttl_sec) {
    if (new_ttl_sec <= 0) return;
    if (new_ttl_sec == ttl_sec_.load(std::memory_order_relaxed)) return;
    ttl_sec_.store(new_ttl_sec, std::memory_order_relaxed);
}

}  // namespace AUTH_NAMESPACE
