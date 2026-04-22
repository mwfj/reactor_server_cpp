#pragma once

#include "common.h"
// <string>, <memory>, <functional>, <atomic> via common.h

namespace AUTH_NAMESPACE {

class UpstreamHttpClient;
class JwksCache;

// ---------------------------------------------------------------------------
// Issues async HTTPS GET(jwks_uri) via UpstreamHttpClient. On success,
// parses the JWKS body with jwt::parse_jwks (exception-contained per §9
// item 16) and installs the resulting (kid, PEM) pairs into the provided
// JwksCache. On failure, delegates to JwksCache::OnFetchError for stale-
// on-error semantics.
//
// Responsibilities:
//   - Fetch lifecycle (timeout, cancel, coalescing)
//   - jwt::parse_jwks exception containment
//   - JWK → PEM key material conversion (RSA: n/e → PEM; EC: x/y/crv → PEM)
//   - Generation tracking so reload / Stop drops stale completions
//
// Dispatcher affinity: the completion callback runs on the dispatcher
// that owns the UpstreamHttpClient::Issue call.
// ---------------------------------------------------------------------------
class JwksFetcher {
 public:
    // `issuer_name` is for log correlation only; the cache already carries it.
    // `client` is shared ownership so lifetime is bounded by the Issuer.
    //
    // `cache` and `owner_generation` use SHARED ownership, not raw
    // pointers. The completion lambda passed to UpstreamHttpClient::Issue
    // captures both by value, so they keep the underlying resources
    // alive even if `~JwksFetcher` (and transitively `~Issuer`) runs
    // while a dispatcher-thread completion is mid-execution. Without
    // this, the lambda's raw-pointer dereferences at the cancelled /
    // error / success paths would be use-after-free once the owner's
    // members destructed. Mirrors the OidcDiscovery heap-owned-cycle-
    // state pattern documented in design §9.
    //
    // `owner_generation` is nullable so legacy test fixtures that don't
    // thread a generation still work; production callers (Issuer)
    // always provide it. When set, completion compares the captured
    // fetch generation against `owner_generation->load()` and drops
    // the install on mismatch — stale-drop semantic for reload/Stop.
    //
    // `upstream_pool_name` is the UpstreamHostPool name for outbound traffic.
    JwksFetcher(std::string issuer_name,
                 std::shared_ptr<UpstreamHttpClient> client,
                 std::shared_ptr<JwksCache> cache,
                 std::string upstream_pool_name,
                 std::shared_ptr<std::atomic<uint64_t>> owner_generation
                     = nullptr);
    ~JwksFetcher();

    JwksFetcher(const JwksFetcher&) = delete;
    JwksFetcher& operator=(const JwksFetcher&) = delete;

    // Issue a GET for the JWKS. `generation` is captured and compared on
    // completion so reload / Stop can invalidate in-flight work. Optional
    // `after_cb` fires on the completion dispatcher after the cache has
    // been updated (success or failure) with the generation argument so
    // the caller can key its own state on a fresh cycle.
    //
    // Caller MUST hold a refresh slot via JwksCache::AcquireRefreshSlot
    // before calling; this method releases the slot on every terminal
    // path.
    void StartFetch(const std::string& jwks_uri,
                     size_t dispatcher_index,
                     int timeout_sec,
                     uint64_t generation,
                     std::function<void(uint64_t)> after_cb = {});

    // Cancel any in-flight request. Idempotent. Safe to call from the
    // dispatcher that owns the fetcher.
    void CancelInflight();

 private:
    std::string issuer_name_;
    std::shared_ptr<UpstreamHttpClient> client_;
    std::shared_ptr<JwksCache> cache_;
    std::string upstream_pool_name_;
    std::shared_ptr<std::atomic<uint64_t>> owner_generation_;

    // Cancel token for the in-flight call (per current cycle).
    std::shared_ptr<std::atomic<bool>> cancel_token_;
};

}  // namespace AUTH_NAMESPACE
