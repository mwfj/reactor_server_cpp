#pragma once

#include "common.h"
// <string>, <unordered_map>, <memory>, <atomic>, <mutex>, <chrono> via common.h

namespace AUTH_NAMESPACE {

// ---------------------------------------------------------------------------
// Per-issuer JWKS cache. Stores PEM-encoded public keys keyed by JWT `kid`.
//
// Design (§7.1):
// - Small map (2–5 keys typical, hard cap 64 per issuer).
// - TTL = `jwks_cache_sec` (caller drives refresh triggers; cache stores
//   timestamps for observability).
// - Refresh triggers: TTL expiry OR kid miss on a live request.
// - Coalescing: only one in-flight refresh per issuer, guarded by an
//   atomic<bool> CAS (`refresh_in_flight_`). N concurrent kid-misses
//   produce exactly 1 fetch.
// - Stale-on-error: if the refresh fails, existing entries remain served
//   indefinitely with `stale_served_++` and a rate-limited warn log.
// - Atomic swap: on success the new KeyMap replaces the old via a
//   `shared_ptr` store under a short-critical-section mutex. Readers take
//   a `shared_ptr` snapshot and keep it alive for the lookup duration.
// - JWKS parsing itself (jwt-cpp boundary) lives in JwksFetcher; the cache
//   accepts already-parsed JWK material via InstallKeys.
//
// Thread-safety envelope (§19):
// - `LookupKeyByKid`: any dispatcher thread. Uses a `shared_ptr` snapshot
//   under a short lock.
// - `InstallKeys`, `OnFetchError`: dispatcher thread that initiated the
//   fetch (JwksFetcher's response callback runs on its originating
//   dispatcher via UpstreamHttpClient).
// - `AcquireRefreshSlot` / `ReleaseRefreshSlot`: lock-free CAS on the
//   atomic<bool>.
// - `SnapshotStats`: any thread.
// ---------------------------------------------------------------------------
class JwksCache {
 public:
    using KeyMap = std::unordered_map<std::string,
                                        std::shared_ptr<const std::string>>;

    // Defense-in-depth cap on JWKS key count. Real IdPs publish 2–5 keys;
    // a pathological response with thousands of entries would otherwise
    // bloat the per-issuer lookup map. Override via the ctor `hard_cap`
    // parameter for tests.
    static constexpr size_t kDefaultJwksHardCap = 64;

    JwksCache(std::string issuer_name,
              int ttl_sec,
              size_t hard_cap = kDefaultJwksHardCap);

    // Lookup the PEM for a given kid. Returns nullptr on miss. Dispatcher-
    // thread safe. Empty kid is supported: when the installed map has
    // exactly one entry keyed under the empty string (operator declared
    // the IdP as single-key), a request without a `kid` header maps to
    // that single key. Otherwise returns nullptr.
    std::shared_ptr<const std::string> LookupKeyByKid(const std::string& kid) const;

    // Accept a batch of (kid → PEM) pairs — typically produced by
    // JwksFetcher after jwt::parse_jwks. Trims to `hard_cap` with a warn
    // if the IdP returned more keys. Bumps `refresh_ok_` and
    // `last_refresh_`. Does NOT clear `stale_served_` counter — operators
    // rely on it as a running total of how often stale-on-error served a
    // response; resetting would hide a degraded-issuer trend. Returns the
    // number of keys installed.
    size_t InstallKeys(std::vector<std::pair<std::string,
                                               std::string>> keys);

    // Called on network / TLS / timeout / CB-open failures. Bumps
    // `refresh_fail_` and logs a rate-limited warn. Leaves the cache
    // untouched — stale-on-error semantics per §7.1.
    void OnFetchError(const std::string& reason);

    struct Snapshot {
        size_t key_count = 0;
        int64_t refresh_ok = 0;
        int64_t refresh_fail = 0;
        int64_t stale_served = 0;
        std::chrono::system_clock::time_point last_refresh{};
    };
    Snapshot SnapshotStats() const;

    // True if `last_refresh_ + ttl_sec_` has elapsed. Called by the caller
    // (Issuer) to decide whether to trigger a periodic refresh alongside
    // per-request misses.
    bool IsTtlExpired() const;

    // Coalescing CAS: returns true if THIS caller won the slot. Caller
    // MUST call ReleaseRefreshSlot exactly once when their fetch
    // terminates (success, error, cancel — every terminal path).
    bool AcquireRefreshSlot();
    void ReleaseRefreshSlot();

    // Increment the stale-served counter. Called by Issuer when it serves
    // a keys-cached result while the TTL has expired and the refresh is
    // still in flight. Exposed so the counter is symmetric with
    // InstallKeys / OnFetchError.
    void IncrementStaleServed();

    const std::string& issuer_name() const noexcept { return issuer_name_; }
    int ttl_sec() const noexcept {
        return ttl_sec_.load(std::memory_order_relaxed);
    }

    // Reload the TTL. Only value-updates the TTL — the key map and
    // counters are preserved. Thread-safe: ttl_sec_ is atomic<int>.
    void SetTtlSec(int new_ttl_sec);

 private:
    std::string issuer_name_;
    std::atomic<int> ttl_sec_;
    size_t hard_cap_;

    // Shared-ptr swap for the hot-path KeyMap.
    std::shared_ptr<const KeyMap> keys_;
    mutable std::mutex keys_mtx_;

    std::atomic<bool> refresh_in_flight_{false};
    std::atomic<int64_t> refresh_ok_{0};
    std::atomic<int64_t> refresh_fail_{0};
    std::atomic<int64_t> stale_served_{0};

    mutable std::mutex stats_mtx_;
    std::chrono::system_clock::time_point last_refresh_{};
    // Rate-limit for stale-serve warn logs so a dead IdP doesn't fill the
    // log; one warn per TTL is enough.
    std::chrono::steady_clock::time_point last_stale_warn_{};
};

}  // namespace AUTH_NAMESPACE
