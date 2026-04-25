#pragma once

#include "common.h"
#include "auth/auth_config.h"
#include "auth/auth_result.h"
// <string>, <memory>, <atomic>, <vector>, <mutex> via common.h

class UpstreamManager;
class Dispatcher;

namespace AUTH_NAMESPACE {

class JwksCache;
class JwksFetcher;       // Defined in jwks_fetcher.h (Phase B)
class OidcDiscovery;     // Defined in oidc_discovery.h (Phase B)
class UpstreamHttpClient;
class IntrospectionCache;

// ---------------------------------------------------------------------------
// Reloadable per-issuer snapshot. Held inside Issuer as
// `shared_ptr<const IssuerSnapshot>` and atomically swapped on Reload.
// Readers take a `shared_ptr` copy on the stack for the duration of one
// verify call — reload-safe and cheap.
// ---------------------------------------------------------------------------
struct IssuerSnapshot {
    std::vector<std::string> audiences;
    std::vector<std::string> algorithms;
    int leeway_sec = 30;
    std::vector<std::string> required_claims;
    int jwks_cache_sec = 300;
    int jwks_refresh_timeout_sec = 5;
    int discovery_retry_sec = 30;
    // Phase 3 introspection settings stored here so the snapshot is
    // complete; JWT-mode Phase 2 ignores them.
    IntrospectionConfig introspection;
    // Populated by OIDC discovery once it succeeds, OR copied from the
    // static `jwks_uri` override when discovery=false. Consumed by
    // JwksFetcher to locate the JWKS endpoint path.
    std::string jwks_uri;
    // Populated by OIDC discovery; used by Phase 3 introspection only.
    std::string introspection_endpoint;
};

// Observability-oriented view on an Issuer, exported by
// `AuthManager::SnapshotAll`. Kept separate from IssuerSnapshot because
// IssuerSnapshot is config-only (reload-safe) while this view captures
// runtime counters.
struct IssuerSnapshotView {
    std::string issuer_id;
    std::string mode;
    bool ready = false;
    uint64_t jwks_refresh_ok = 0;
    uint64_t jwks_refresh_fail = 0;
    uint64_t jwks_stale_served = 0;
    size_t jwks_key_count = 0;
    std::chrono::system_clock::time_point last_jwks_refresh{};
};

// ---------------------------------------------------------------------------
// Per-issuer state container. Owns the JWKS cache, OIDC discovery (if
// enabled), and JWKS fetcher. Topology-stable — constructed once by
// AuthManager in ctor and never added/removed post-Start. Reloadable
// fields flow in via ApplyReload, which atomically swaps the
// IssuerSnapshot under a mutex.
//
// Thread-safety envelope (§19):
//   - `LookupKeyByKid`, `LoadSnapshot`, `IsReady` — any dispatcher thread.
//   - `Start`, `Stop`, `ApplyReload` — caller-serialised (reload mutex
//     held by AuthManager). Each bumps `generation_` so in-flight
//     fetches drop cleanly.
// ---------------------------------------------------------------------------
class Issuer : public std::enable_shared_from_this<Issuer> {
 public:
    Issuer(const IssuerConfig& config,
           UpstreamManager* upstream_manager,
           std::vector<std::shared_ptr<Dispatcher>> dispatchers,
           std::shared_ptr<UpstreamHttpClient> http_client,
           const std::string& hmac_key);
    ~Issuer();

    Issuer(const Issuer&) = delete;
    Issuer& operator=(const Issuer&) = delete;
    Issuer(Issuer&&) = delete;
    Issuer& operator=(Issuer&&) = delete;

    // Non-blocking. Kicks off OIDC discovery (if discovery=true) or
    // installs the static jwks_uri override and schedules the first JWKS
    // fetch on one of the configured dispatchers.
    void Start();

    // Halts in-flight fetches by bumping the generation token.
    // Idempotent. Called during AuthManager::Stop or before destruction.
    void Stop();

    // Pure validation — no mutation. Returns true when the incoming config
    // would be accepted by ApplyReload. Used by AuthManager::Reload to
    // check every issuer BEFORE committing any of them (F5: avoid partial
    // commits when a later issuer fails validation). Topology-restart-only
    // mismatches also fail here so the caller sees them before any state
    // is touched.
    bool ValidateReload(const IssuerConfig& new_config,
                         std::string& err_out) const;

    // Apply reloadable fields. Topology-restart-only fields (issuer_url,
    // mode, upstream, discovery) must match the current values — if not,
    // returns false with a message in err_out and the caller is expected
    // to log and preserve the existing state. Also runs the same range
    // checks as ValidateReload for defence-in-depth.
    bool ApplyReload(const IssuerConfig& new_config, std::string& err_out);

    // Atomic-load the snapshot. Safe from any dispatcher thread.
    std::shared_ptr<const IssuerSnapshot> LoadSnapshot() const;

    const std::string& name() const noexcept { return name_; }
    const std::string& issuer_url() const noexcept { return issuer_url_; }
    const std::string& mode() const noexcept { return mode_; }
    const std::string& upstream() const noexcept { return upstream_; }
    bool discovery() const noexcept { return discovery_; }

    // PEM-encoded public key lookup by JWT `kid`. Returns nullptr on miss.
    // When kid is not cached, schedules an async JWKS refresh (coalesced
    // via `JwksCache::refresh_in_flight_`) IF the issuer is ready.
    // Dispatcher-thread safe.
    std::shared_ptr<const std::string> LookupKeyByKid(const std::string& kid,
                                                      size_t dispatcher_index);

    bool IsReady() const noexcept {
        return ready_.load(std::memory_order_acquire);
    }

    uint64_t generation() const noexcept {
        return generation_->load(std::memory_order_acquire);
    }

    // True after Stop() has begun. Late completions check this to drop
    // results that would otherwise race with shutdown teardown.
    bool stopping() const noexcept {
        return stopping_.load(std::memory_order_acquire);
    }

    JwksCache* jwks_cache() noexcept { return jwks_cache_.get(); }

    // Returns nullptr for JWT-mode issuers (cache is constructed in Start()
    // only when mode == "introspection").
    IntrospectionCache* introspection_cache() noexcept {
        return introspection_cache_.get();
    }

    // Loaded once at Start() from the configured env var. Empty for
    // JWT-mode issuers and for introspection-mode issuers whose env var
    // was unset/empty (in which case ready_ is false).
    const std::string& client_secret() const noexcept { return client_secret_; }

    // Fill an observability view. Dispatcher-thread safe.
    IssuerSnapshotView BuildView() const;

 private:
    const std::string name_;
    const std::string issuer_url_;
    const std::string mode_;
    const std::string upstream_;
    const bool discovery_;

    // Captured at construction so ValidateReload can compare incoming
    // restart-required introspection fields against the original values.
    // Never overwritten — a reload that would change them is rejected.
    const std::string client_id_;
    const std::string client_secret_env_;
    const int shards_;

    // Atomic-swapped on Reload. Readers copy the shared_ptr onto the stack
    // and keep it alive for the duration of one verify call.
    std::shared_ptr<const IssuerSnapshot> snapshot_;
    mutable std::mutex snapshot_mtx_;

    std::atomic<bool> ready_{false};
    std::atomic<bool> stopping_{false};
    // Generation bumped on Stop() and on every successful ApplyReload.
    // Heap-owned via shared_ptr so JwksFetcher / OidcDiscovery completion
    // callbacks can safely capture it by value — if the Issuer is destroyed
    // while a dispatcher completion is in flight, the atomic stays alive
    // as long as any lambda holds a shared_ptr copy. Without this, the
    // lambda's raw pointer would dangle after ~Issuer (UAF on the
    // completion's generation comparison). Same protection as
    // OidcDiscovery's cycle_state_ pattern.
    std::shared_ptr<std::atomic<uint64_t>> generation_ =
        std::make_shared<std::atomic<uint64_t>>(1);

    // Heap-owned for the same lifetime reason as `generation_`:
    // JwksFetcher's completion lambda calls `cache->InstallKeys` /
    // `ReleaseRefreshSlot` on any terminal path. If a completion fires
    // after ~Issuer destroys a unique_ptr-owned cache, those calls are
    // UAF. Shared ownership lets the lambda keep the cache alive across
    // the race.
    std::shared_ptr<JwksCache> jwks_cache_;
    std::unique_ptr<JwksFetcher> jwks_fetcher_;
    std::unique_ptr<OidcDiscovery> oidc_discovery_;
    std::shared_ptr<UpstreamHttpClient> upstream_http_client_;

    // Constructed in Start() only when mode_ == "introspection". Held by
    // unique_ptr so JWT-mode issuers pay zero memory cost.
    std::unique_ptr<IntrospectionCache> introspection_cache_;
    // Loaded once in Start() from getenv(client_secret_env_). Empty for
    // JWT mode and for introspection mode with missing/empty env (in
    // which case ready_ stays false — fail-closed).
    std::string client_secret_;

    UpstreamManager* upstream_manager_;                    // non-owning
    std::vector<std::shared_ptr<Dispatcher>> dispatchers_;

    // Pick a dispatcher to issue a fetch from. Returns 0 when no
    // preference is available. Kept as a small helper so both Start() and
    // LookupKeyByKid's refresh trigger use the same policy.
    size_t PickDispatcherForFetch(size_t caller_dispatcher_index) const noexcept;

    // Kick off (or restart) OIDC discovery with a fresh generation. Used
    // by Start() and by ApplyReload() when reload bumps the generation
    // while discovery is still retrying — without a restart, the old
    // retry's callback carries a stale `cb_gen` and gets rejected by the
    // ready-callback's generation gate, wedging the issuer permanently.
    void KickOffOidcDiscovery(size_t dispatcher_index, uint64_t generation);

    // Apply the effective jwks_uri (from discovery or static override)
    // into the snapshot. Called under snapshot_mtx_ — used by both Start
    // (static override) and the OIDC discovery completion callback.
    void InstallJwksUriLocked(const std::string& uri,
                               const std::string& introspection_endpoint);

    // Triggers the first JWKS fetch on a chosen dispatcher. Called after
    // the effective jwks_uri is known. Coalesced via refresh_in_flight_.
    void ScheduleInitialFetch(size_t dispatcher_index);
};

}  // namespace AUTH_NAMESPACE
