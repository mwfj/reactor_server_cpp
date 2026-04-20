#pragma once

#include "common.h"
#include "auth/auth_config.h"
#include "auth/auth_context.h"
#include "auth/auth_policy_matcher.h"
#include "auth/auth_result.h"
#include "auth/issuer.h"
#include "config/server_config.h"
// <atomic>, <memory>, <mutex>, <unordered_map>, <vector> via common.h

class UpstreamManager;
class Dispatcher;
struct HttpRequest;
class HttpResponse;

namespace AUTH_NAMESPACE {

class UpstreamHttpClient;

// ---------------------------------------------------------------------------
// Top-level owner of issuers, the applied-policy list, and the forward-
// overlay snapshot. Installed as a middleware via `AuthMiddleware` and
// consulted at outbound-hop time via `ForwardConfig()`.
//
// Thread-safety envelope:
// - `InvokeMiddleware`, `ForwardConfig`, `SnapshotAll` — ANY dispatcher.
// - `RegisterPolicy`, `Start`, `Stop`, `Reload`,
//   `CommitPolicyAndEnforcement` — main / signal thread only;
//   internally serialised by `reload_mtx_`.
//
// Ownership is the canonical UPPER_SNAKE_CASE ownership tree from §3.4:
//   HttpServer → unique_ptr<AuthManager>
//   AuthManager → unordered_map<string, shared_ptr<Issuer>>
//   AuthManager → shared_ptr<const AppliedPolicyList> (atomic swap)
//   AuthManager → shared_ptr<const AuthForwardConfig> (atomic swap)
// ---------------------------------------------------------------------------
class AuthManager {
 public:
    struct SnapshotView {
        std::map<std::string, IssuerSnapshotView> issuers;
        uint64_t total_allowed = 0;
        uint64_t total_denied = 0;
        uint64_t total_undetermined = 0;
        size_t policy_count = 0;
        uint64_t generation = 0;
    };

    AuthManager(const AuthConfig& config,
                UpstreamManager* upstream_manager,
                std::vector<std::shared_ptr<Dispatcher>> dispatchers);
    ~AuthManager();

    AuthManager(const AuthManager&) = delete;
    AuthManager& operator=(const AuthManager&) = delete;

    // Kicks off OIDC discovery / static JWKS fetches for every issuer.
    // Non-blocking; issuers that are not-yet-ready surface as UNDETERMINED
    // until ready.
    void Start();

    // Aborts in-flight fetches and marks the manager stopping. Idempotent.
    void Stop();

    // Register a policy against one or more path prefixes. Idempotent on
    // duplicate (prefix, policy_name) pairs. MUST be called before Start
    // returns OR via `CommitPolicyAndEnforcement` during reload —
    // post-Start ad-hoc calls log a warn + no-op to prevent races.
    void RegisterPolicy(std::vector<std::string> prefixes, AuthPolicy policy);

    // Middleware entry point. Matches a policy against `req.path`,
    // extracts the bearer token from Authorization, verifies it, and
    // populates `req.auth` on ALLOW. Returns true when the request
    // should continue (ALLOW or no policy match), false when a 401 /
    // 403 / 503 has been written to `resp`.
    bool InvokeMiddleware(const HttpRequest& req, HttpResponse& resp);

    // Reload-safe forward-overlay snapshot. Caller must keep the
    // shared_ptr alive for the duration of one outbound hop and drop it
    // at the end.
    std::shared_ptr<const AuthForwardConfig> ForwardConfig() const;

    // Applies reloadable fields: issuer snapshots, the forward config,
    // and a generation bump. Returns false on validation failure with
    // an error message in `err_out`. Never throws.
    bool Reload(const AuthConfig& new_config, std::string& err_out);

    // Final reload cutover — rebuild the AppliedPolicyList from live
    // upstreams + merged top-level policies AND flip `master_enabled_`
    // under the SAME lock, in that order (policy swap first, then the
    // release-store on `master_enabled_`). Called by HttpServer::Reload
    // AFTER AuthManager::Reload() has applied issuer + forward snapshots
    // AND the upstream topology check has completed, so `new_upstreams`
    // reflects the prefixes the router will actually serve this run.
    //
    // Single publication edge: readers observing `master_enabled_=true`
    // transitively see the new policy list, new forward snapshot, and
    // new issuer snapshots. Without this atomic cutover, a `false → true`
    // reload that also edited policies would expose a window where
    // requests run with enforcement ON against the OLD policy list.
    // See design doc §11.2 step 4 + §18.5 for the rationale.
    void CommitPolicyAndEnforcement(
        const std::vector<UpstreamConfig>& new_upstreams,
        const std::vector<AuthPolicy>& new_top_level_policies,
        bool new_master_enabled);

    // Snapshot of runtime counters + per-issuer views.
    SnapshotView SnapshotAll() const;

    // True after Start has been called AND every discovery-enabled
    // issuer has at least started (discovery may still be in flight).
    bool IsStarted() const noexcept {
        return started_.load(std::memory_order_acquire);
    }

    // Live view of the master enforcement switch — mirrors auth.enabled
    // through Reload. Used by observability surfaces (snapshot endpoint,
    // log lines) that need the running state rather than the staged
    // config, because auth.enabled is live-reloadable.
    bool IsEnforcing() const noexcept {
        return master_enabled_.load(std::memory_order_acquire);
    }

    // Access to the internal issuer by name — used by WebSocket upgrade
    // handlers that drive InvokeMiddleware manually. Returns nullptr when
    // the name is unknown.
    Issuer* GetIssuer(const std::string& issuer_name);

 private:
    // Extract the bearer token from an Authorization header. Returns an
    // empty string on missing / malformed header. Public-facing errors
    // are surfaced via VerifyResult::InvalidRequest at the call site.
    static std::string ExtractBearerToken(const HttpRequest& req,
                                           std::string& log_label_out);

    // Build an AppliedPolicyList from live+top-level sources. Used by
    // both RegisterPolicy-driven startup (reused here) and by
    // CommitPolicyAndEnforcement.
    static std::shared_ptr<const AppliedPolicyList>
    BuildAppliedPolicyList(
        const std::vector<UpstreamConfig>& upstreams,
        const std::vector<AuthPolicy>& top_level_policies);

    std::unordered_map<std::string, std::shared_ptr<Issuer>> issuers_;
    std::shared_ptr<UpstreamHttpClient> upstream_http_client_;

    std::shared_ptr<const AppliedPolicyList> policies_;
    std::shared_ptr<const AuthForwardConfig> forward_;
    mutable std::mutex snapshot_mtx_;

    UpstreamManager* upstream_manager_;                    // non-owning
    std::vector<std::shared_ptr<Dispatcher>> dispatchers_;
    std::string hmac_key_;                                 // process-local

    std::atomic<uint64_t> generation_{1};
    std::atomic<bool> started_{false};
    std::atomic<bool> stopping_{false};
    // Master enforcement switch mirrored from AuthConfig::enabled. Live-
    // updatable by Reload so `auth.enabled: true → false` (and vice versa)
    // takes effect without restart. When false, InvokeMiddleware returns
    // true immediately (pass-through). The middleware is installed whenever
    // AuthManager exists (enabled or not) so a later reload can flip it on.
    std::atomic<bool> master_enabled_{false};

    std::atomic<uint64_t> total_allowed_{0};
    std::atomic<uint64_t> total_denied_{0};
    std::atomic<uint64_t> total_undetermined_{0};

    std::mutex reload_mtx_;
};

}  // namespace AUTH_NAMESPACE
