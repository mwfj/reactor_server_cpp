#include "auth/issuer.h"

#include "auth/jwks_cache.h"
#include "auth/jwks_fetcher.h"
#include "auth/jws_algorithms.h"
#include "auth/oidc_discovery.h"
#include "auth/upstream_http_client.h"
#include "upstream/upstream_manager.h"
#include "dispatcher.h"
#include "log/logger.h"
#include "log/log_utils.h"

namespace AUTH_NAMESPACE {

namespace {

// Shared range + algorithm check used by ValidateReload and ApplyReload.
// `mode` is the issuer's live mode (immutable post-construction) so callers
// can run the same check pre-apply (validation pass) and mid-apply (defence
// in depth).
bool ValidateReloadableFields(const IssuerConfig& cfg,
                               const std::string& live_mode,
                               std::string& err_out) {
    if (cfg.leeway_sec < 0) {
        err_out = "leeway_sec must be >= 0";
        return false;
    }
    if (cfg.jwks_cache_sec <= 0) {
        err_out = "jwks_cache_sec must be > 0";
        return false;
    }
    if (cfg.jwks_refresh_timeout_sec <= 0) {
        err_out = "jwks_refresh_timeout_sec must be > 0";
        return false;
    }
    if (cfg.discovery_retry_sec <= 0) {
        err_out = "discovery_retry_sec must be > 0";
        return false;
    }
    if (live_mode == "jwt" && cfg.algorithms.empty()) {
        err_out = "algorithms must contain at least one entry for mode=\"jwt\"";
        return false;
    }
    for (const auto& a : cfg.algorithms) {
        if (!IsSupportedJwsAlg(a)) {
            err_out = "algorithm '" + a + "' is not supported (v1: "
                      "RS256/RS384/RS512/ES256/ES384). HS256/none/PS* are "
                      "rejected per spec §5.3.";
            return false;
        }
    }
    return true;
}

// Builds a fresh mutable IssuerSnapshot. Caller is responsible for
// converting to `shared_ptr<const IssuerSnapshot>` before swapping into
// Issuer::snapshot_ — IssuerSnapshot is immutable once published.
std::shared_ptr<IssuerSnapshot> BuildMutableSnapshotFromConfig(
        const IssuerConfig& cfg) {
    auto snap = std::make_shared<IssuerSnapshot>();
    snap->audiences = cfg.audiences;
    snap->algorithms = cfg.algorithms;
    snap->leeway_sec = cfg.leeway_sec;
    snap->required_claims = cfg.required_claims;
    snap->jwks_cache_sec = cfg.jwks_cache_sec;
    snap->jwks_refresh_timeout_sec = cfg.jwks_refresh_timeout_sec;
    snap->discovery_retry_sec = cfg.discovery_retry_sec;
    snap->introspection = cfg.introspection;
    // Populate static override if the operator provided one — OIDC
    // discovery overwrites this when it succeeds.
    if (!cfg.discovery) {
        snap->jwks_uri = cfg.jwks_uri;
    }
    return snap;
}

}  // namespace

Issuer::Issuer(const IssuerConfig& config,
               UpstreamManager* upstream_manager,
               std::vector<std::shared_ptr<Dispatcher>> dispatchers,
               std::shared_ptr<UpstreamHttpClient> http_client,
               const std::string& hmac_key)
    : name_(config.name),
      issuer_url_(config.issuer_url),
      mode_(config.mode),
      upstream_(config.upstream),
      discovery_(config.discovery),
      snapshot_(BuildMutableSnapshotFromConfig(config)),
      jwks_cache_(std::make_shared<JwksCache>(config.name,
                                                config.jwks_cache_sec)),
      upstream_http_client_(std::move(http_client)),
      upstream_manager_(upstream_manager),
      dispatchers_(std::move(dispatchers)) {
    (void)hmac_key;  // Reserved for introspection cache wiring.
    // Construct the helper objects now so dependencies are stable; Start
    // kicks off the async work on the caller's chosen dispatcher. Both
    // helpers hold shared ownership of upstream_http_client_.
    jwks_fetcher_ = std::make_unique<JwksFetcher>(
        config.name, upstream_http_client_, jwks_cache_, upstream_,
        /*owner_generation=*/generation_);
    if (discovery_) {
        oidc_discovery_ = std::make_unique<OidcDiscovery>(
            config.name, issuer_url_, upstream_http_client_, upstream_,
            config.discovery_retry_sec);
    }
    logging::Get()->debug(
        "Issuer constructed name={} issuer_url={} mode={} upstream={} "
        "discovery={}",
        name_, issuer_url_, mode_, upstream_, discovery_);
}

Issuer::~Issuer() {
    Stop();
}

void Issuer::Start() {
    if (!upstream_manager_ ||
        !upstream_manager_->HasUpstream(upstream_)) {
        // Fail-closed per §20 risk #2 (validator-vs-manager drift):
        // if the operator referenced an upstream that is absent at
        // runtime, mark not-ready and log — the verifier will drop back
        // to UNDETERMINED for this issuer until the state is repaired.
        logging::Get()->error(
            "Issuer start failed — upstream '{}' unknown to UpstreamManager "
            "issuer={}", upstream_, name_);
        ready_.store(false, std::memory_order_release);
        return;
    }

    auto snap = LoadSnapshot();
    const size_t disp_idx = PickDispatcherForFetch(0);
    const uint64_t gen = generation_->load(std::memory_order_acquire);

    if (!discovery_ && !snap->jwks_uri.empty()) {
        // Static override path: mark ready and schedule the initial fetch.
        logging::Get()->info(
            "Issuer start (static jwks_uri) issuer={}", name_);
        ready_.store(true, std::memory_order_release);
        ScheduleInitialFetch(disp_idx);
    } else if (discovery_ && oidc_discovery_) {
        logging::Get()->info(
            "Issuer start (discovery) issuer={}", name_);
        KickOffOidcDiscovery(disp_idx, gen);
    } else {
        logging::Get()->warn(
            "Issuer start skipped: discovery=false and jwks_uri empty "
            "issuer={}", name_);
    }
}

void Issuer::Stop() {
    // Bump the generation so in-flight completions drop as stale.
    generation_->fetch_add(1, std::memory_order_release);
    ready_.store(false, std::memory_order_release);
    if (oidc_discovery_) oidc_discovery_->Cancel();
    if (jwks_fetcher_) jwks_fetcher_->CancelInflight();
}

bool Issuer::ValidateReload(const IssuerConfig& new_config,
                              std::string& err_out) const {
    // Topology-restart-only fields — same checks as ApplyReload's prelude
    // so AuthManager::Reload can catch these before mutating any issuer.
    if (new_config.name != name_) {
        err_out = "issuer name changed — restart required";
        return false;
    }
    if (new_config.issuer_url != issuer_url_) {
        err_out = "issuer_url changed — restart required";
        return false;
    }
    if (new_config.mode != mode_) {
        err_out = "mode changed — restart required";
        return false;
    }
    if (new_config.upstream != upstream_) {
        err_out = "upstream changed — restart required";
        return false;
    }
    if (new_config.discovery != discovery_) {
        err_out = "discovery toggle changed — restart required";
        return false;
    }
    // Static jwks_uri is part of issuer topology for discovery=false
    // issuers: a reload that swaps the URL silently points future key
    // refreshes at a different JWKS source — which can either start
    // rejecting current tokens (keys no longer present in the new set)
    // or trust an unintended JWKS (a different IdP entirely). Reject so
    // AuthManager::Reload preserves live state; the operator can restart
    // with the new URL intentionally. For discovery=true issuers the
    // operator-supplied jwks_uri is ignored at runtime (discovery
    // overwrites it on each OIDC-config fetch), so don't gate on it.
    if (!discovery_) {
        std::shared_ptr<const IssuerSnapshot> snap;
        {
            std::lock_guard<std::mutex> lk(snapshot_mtx_);
            snap = snapshot_;
        }
        if (snap && new_config.jwks_uri != snap->jwks_uri) {
            err_out = "jwks_uri changed on static (discovery=false) issuer "
                      "— restart required";
            return false;
        }
    }
    return ValidateReloadableFields(new_config, mode_, err_out);
}

bool Issuer::ApplyReload(const IssuerConfig& new_config, std::string& err_out) {
    // Validate before mutating. ValidateReload runs the full topology +
    // range + algorithm-allowlist checks — keep ApplyReload as the single
    // mutation path so out-of-band callers (tests) hit the same gate.
    if (!ValidateReload(new_config, err_out)) {
        return false;
    }

    auto new_snap = BuildMutableSnapshotFromConfig(new_config);
    // Preserve the discovery-derived jwks_uri / introspection_endpoint
    // so a reload doesn't blow away IdP-provided values. The operator's
    // static override (when discovery=false) already flows through
    // BuildMutableSnapshotFromConfig.
    {
        std::lock_guard<std::mutex> lk(snapshot_mtx_);
        if (snapshot_ && discovery_) {
            new_snap->jwks_uri = snapshot_->jwks_uri;
            new_snap->introspection_endpoint = snapshot_->introspection_endpoint;
        }
        snapshot_ = new_snap;
    }
    if (jwks_cache_) {
        jwks_cache_->SetTtlSec(new_config.jwks_cache_sec);
    }
    const uint64_t new_gen =
        generation_->fetch_add(1, std::memory_order_release) + 1;
    // If discovery is still in its retry cycle (pre-first-success), the
    // existing oidc_discovery_->Start callback captured the OLD generation.
    // Bumping generation_ without re-arming discovery wedges the issuer:
    // every future on_ready_cb is rejected as stale, so the retry cycle
    // never reaches InstallJwksUriLocked / ready_. Re-kick with the new
    // generation. For already-ready issuers we leave the running cycle
    // alone — re-kicking would clear ready_ momentarily and drop in-flight
    // JWKS fetches for no benefit.
    if (discovery_ && oidc_discovery_ &&
        !ready_.load(std::memory_order_acquire)) {
        // Apply the reloaded retry interval to the live OidcDiscovery
        // BEFORE re-kicking — Start() captures retry_sec_ by value into
        // the new cycle, so without this the fresh cycle would still
        // sleep on the old interval and `discovery_retry_sec` would not
        // actually hot-reload in the state where it matters (retrying
        // pre-first-success).
        oidc_discovery_->SetRetrySec(new_config.discovery_retry_sec);
        logging::Get()->info(
            "Issuer reload: re-kicking OIDC discovery issuer={} new_gen={}",
            name_, new_gen);
        KickOffOidcDiscovery(PickDispatcherForFetch(0), new_gen);
    }
    logging::Get()->info(
        "Issuer reloaded issuer={} leeway_sec={} audiences={} algorithms={}",
        name_, new_config.leeway_sec, new_config.audiences.size(),
        new_config.algorithms.size());
    return true;
}

std::shared_ptr<const IssuerSnapshot> Issuer::LoadSnapshot() const {
    std::lock_guard<std::mutex> lk(snapshot_mtx_);
    return snapshot_;
}

std::shared_ptr<const std::string> Issuer::LookupKeyByKid(
        const std::string& kid, size_t dispatcher_index) {
    if (!jwks_cache_) return nullptr;
    auto pem = jwks_cache_->LookupKeyByKid(kid);
    if (pem) {
        // Hit: honor jwks_cache_sec TTL by scheduling a background refresh
        // when the cached copy is stale. Serve the stale key for THIS
        // request (stale-on-error is the documented policy for healthy
        // relays). Without this, a key rotation that keeps the same `kid`
        // (or a revocation) would remain trusted indefinitely — the
        // miss-only refresh path never fires for same-kid hits.
        if (ready_.load(std::memory_order_acquire) &&
            jwks_cache_->IsTtlExpired()) {
            // Observability: bump `jwks_stale_served` for this TTL-
            // expired serve. Exposed via BuildView → /stats. Documented
            // in jwks_cache.h as the counter operators watch to detect
            // degraded IdP / refresh-failure scenarios; without this
            // bump, the advertised signal is always zero.
            jwks_cache_->IncrementStaleServed();
            ScheduleInitialFetch(PickDispatcherForFetch(dispatcher_index));
        }
        return pem;
    }

    // Miss: schedule a coalesced refresh on the caller's dispatcher. The
    // caller sees UNDETERMINED for THIS request; once the refresh lands,
    // subsequent requests with the same kid succeed.
    if (!ready_.load(std::memory_order_acquire)) {
        logging::Get()->debug(
            "Issuer kid-miss (not-ready) issuer={} kid={}",
            name_, logging::SanitizeLogValue(kid));
        return nullptr;
    }
    ScheduleInitialFetch(PickDispatcherForFetch(dispatcher_index));
    return nullptr;
}

IssuerSnapshotView Issuer::BuildView() const {
    IssuerSnapshotView view;
    view.issuer_id = name_;
    view.mode = mode_;
    view.ready = ready_.load(std::memory_order_acquire);
    if (jwks_cache_) {
        auto stats = jwks_cache_->SnapshotStats();
        view.jwks_refresh_ok = static_cast<uint64_t>(stats.refresh_ok);
        view.jwks_refresh_fail = static_cast<uint64_t>(stats.refresh_fail);
        view.jwks_stale_served = static_cast<uint64_t>(stats.stale_served);
        view.jwks_key_count = stats.key_count;
        view.last_jwks_refresh = stats.last_refresh;
    }
    return view;
}

size_t Issuer::PickDispatcherForFetch(size_t caller_dispatcher_index) const noexcept {
    if (dispatchers_.empty()) return 0;
    if (caller_dispatcher_index < dispatchers_.size()) {
        return caller_dispatcher_index;
    }
    return 0;
}

void Issuer::KickOffOidcDiscovery(size_t dispatcher_index, uint64_t generation) {
    if (!oidc_discovery_) return;
    // Capture a weak_ptr so delayed retry closures that fire after
    // ~Issuer (EnQueueDelayed tasks the Dispatcher cannot drain) safely
    // observe the Issuer is gone rather than dereferencing freed memory.
    // shared_from_this() is valid because Issuer is always constructed
    // via AuthManager which holds shared_ptr<Issuer>.
    std::weak_ptr<Issuer> weak_self = weak_from_this();
    oidc_discovery_->Start(
        dispatcher_index, generation,
        [weak_self](uint64_t cb_gen, const std::string& jwks_uri,
                     const std::string& introspection_endpoint) {
            auto self = weak_self.lock();
            if (!self) return;  // Issuer was destroyed while retry was queued.
            // Generation gate: reload / Stop() bumped generation_, so a
            // late-arriving discovery response from a superseded cycle
            // must drop. The restart path in ApplyReload calls this
            // function again with the NEW generation, so the fresh cycle
            // passes the gate.
            if (cb_gen != self->generation_->load(std::memory_order_acquire)) {
                logging::Get()->info(
                    "OIDC discovery drop stale gen issuer={} cb_gen={} "
                    "current={}",
                    self->name_, cb_gen,
                    self->generation_->load(std::memory_order_acquire));
                return;
            }
            {
                std::lock_guard<std::mutex> lk(self->snapshot_mtx_);
                self->InstallJwksUriLocked(jwks_uri, introspection_endpoint);
            }
            self->ready_.store(true, std::memory_order_release);
            self->ScheduleInitialFetch(/*dispatcher_index=*/0);
        });
}

void Issuer::InstallJwksUriLocked(const std::string& uri,
                                   const std::string& introspection_endpoint) {
    if (!snapshot_) return;
    // snapshot_ is shared_ptr<const IssuerSnapshot>; build a mutable copy
    // then publish it as const again via implicit conversion on assign.
    auto updated = std::make_shared<IssuerSnapshot>(*snapshot_);
    updated->jwks_uri = uri;
    updated->introspection_endpoint = introspection_endpoint;
    snapshot_ = std::shared_ptr<const IssuerSnapshot>(std::move(updated));
}

void Issuer::ScheduleInitialFetch(size_t dispatcher_index) {
    if (!jwks_fetcher_ || !jwks_cache_) return;
    // Coalesce: if a refresh is already in flight, skip. Otherwise claim
    // the slot and dispatch.
    if (!jwks_cache_->AcquireRefreshSlot()) {
        logging::Get()->debug(
            "Issuer refresh already in flight issuer={}", name_);
        return;
    }
    auto snap = LoadSnapshot();
    if (!snap || snap->jwks_uri.empty()) {
        jwks_cache_->ReleaseRefreshSlot();
        logging::Get()->warn(
            "Issuer cannot fetch JWKS (empty jwks_uri) issuer={}", name_);
        return;
    }
    const uint64_t gen = generation_->load(std::memory_order_acquire);
    jwks_fetcher_->StartFetch(
        snap->jwks_uri, dispatcher_index,
        snap->jwks_refresh_timeout_sec, gen, /*after_cb=*/{});
}

}  // namespace AUTH_NAMESPACE
