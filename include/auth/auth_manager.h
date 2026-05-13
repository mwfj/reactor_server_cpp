#pragma once

#include "common.h"
#include "auth/auth_config.h"
#include "auth/auth_context.h"
#include "auth/auth_policy_matcher.h"
#include "auth/auth_result.h"
#include "auth/issuer.h"
#include "auth/token_hasher.h"
#include "config/server_config.h"
#include "http/http_router.h"
#include <unordered_set>
// <atomic>, <memory>, <mutex>, <unordered_map>, <vector> via common.h

class UpstreamManager;
class Dispatcher;
struct HttpRequest;
class HttpResponse;

namespace OBSERVABILITY_NAMESPACE {
class ObservabilityManager;
}  // namespace OBSERVABILITY_NAMESPACE

namespace AUTH_NAMESPACE {

class UpstreamHttpClient;
class IntrospectionClient;

// Cache-state label emitted on the X-Auth-Cache response header. JWT mode
// has no per-request cache and uses None (header omitted). Introspection
// mode walks Hit / Miss / Stale / Negative / Uncached based on the
// dispatch path.
enum class AuthCache {
    None,
    Hit,
    Miss,
    Stale,
    Negative,
    Uncached,
};

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
    // Per-(issuer, policy) accumulator surfaced under /stats auth.per_policy
    // and auth.issuers[].per_policy. `issuer` is empty for verdicts produced
    // before issuer selection (e.g. missing_authorization, token_too_large).
    struct PerPolicyCountersView {
        std::string issuer;
        std::string policy;
        uint64_t allowed = 0;
        uint64_t denied = 0;
        uint64_t undetermined = 0;
    };

    struct SnapshotView {
        std::map<std::string, IssuerSnapshotView> issuers;
        uint64_t total_allowed = 0;
        uint64_t total_denied = 0;
        uint64_t total_undetermined = 0;
        size_t policy_count = 0;
        uint64_t generation = 0;
        // Aggregate introspection-mode counters across all issuers.
        // All zero in JWT-only deployments.
        uint64_t introspection_ok = 0;
        uint64_t introspection_fail = 0;
        uint64_t introspection_cache_hit = 0;
        uint64_t introspection_cache_miss = 0;
        uint64_t introspection_cache_negative_hit = 0;
        uint64_t introspection_stale_served = 0;
        bool enabled = false;
        bool debug_response_headers = false;
        // Sorted by (issuer, policy) — std::map iteration in SnapshotAll
        // produces stable JSON ordering for /stats.
        std::vector<PerPolicyCountersView> per_policy;
    };

    // Construct an AuthManager.
    //
    // `obs_manager` is optional and defaults to nullptr — auth-only
    // deployments without observability wired pass nullptr. When set,
    // `InvokeAsyncMiddleware` builds an `IssueTraceContext` for every
    // introspection POST so the IdP receives `traceparent` / `tracestate`
    // / `uber-trace-id` headers continuing the inbound trace, and
    // (when `traces.auth_idp_span` is enabled) allocates an
    // `auth.idp_check` INTERNAL span over the deferred dispatch.
    AuthManager(const AuthConfig& config,
                UpstreamManager* upstream_manager,
                std::vector<std::shared_ptr<Dispatcher>> dispatchers,
                OBSERVABILITY_NAMESPACE::ObservabilityManager* obs_manager
                    = nullptr);
    ~AuthManager();

    AuthManager(const AuthManager&) = delete;
    AuthManager& operator=(const AuthManager&) = delete;

    // Kicks off OIDC discovery / static JWKS fetches for every issuer.
    // Non-blocking; issuers that are not-yet-ready surface as UNDETERMINED
    // until ready.
    void Start();

    // Publish the stopping_ atomic so future Reload calls bail at entry
    // and background discovery / JWKS retry kicks observe the shutdown.
    // Does NOT cancel per-issuer in-flight work; that happens in Stop().
    // Safe to call from HttpServer::Stop BEFORE the protocol drain so
    // background fetches don't burn drain budget on non-client work.
    // Idempotent. Cheap (one atomic store).
    void RequestStop();

    // Aborts in-flight fetches and marks the manager stopping. Acquires
    // the manager's reload_mtx_ to serialize with concurrent Reload —
    // a Reload past this point will observe stopping_=true at entry and
    // bail without re-kicking discovery. Idempotent.
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
    bool InvokeMiddleware(HttpRequest& req, HttpResponse& resp);

    // Async middleware entry point. Drives the introspection-mode dispatch
    // path. Sync fast-paths (cache hit / negative-hit / stale-serve / no
    // policy / JWT-mode pass-through / DENY for missing/oversized bearer)
    // call SetSyncResult+MarkCompletedSync inline. The deferred path fires
    // a POST through IntrospectionClient and resolves via state->Complete.
    void InvokeAsyncMiddleware(HttpRequest& req, HttpResponse& resp,
                                std::shared_ptr<HttpRouter::AsyncPendingState> state);

    // Read-only accessor for tests + the async dispatch path.
    const TokenHasher& hasher() const { return hasher_; }

    // Reload-safe forward-overlay snapshot. Caller must keep the
    // shared_ptr alive for the duration of one outbound hop and drop it
    // at the end.
    std::shared_ptr<const AuthForwardConfig> ForwardConfig() const;

    // Validate-only path. Runs the issuer-topology check (count + name
    // set) and per-issuer ValidateReload. Pure read — does NOT mutate
    // any live state, does NOT publish snapshots. Returns false on
    // rejection with `err_out` populated. Lets the HttpServer reload
    // path fail-fast on auth-bad configs BEFORE applying any other
    // subsystem reload (rate-limit, circuit-breaker, etc.) AND before
    // any future DNS-bearing reload phase, so an auth-only bad config
    // rejects deterministically without depending on DNS health.
    // Never throws.
    bool ValidateReload(const AuthConfig& new_config,
                         std::string& err_out) const;

    // Applies reloadable fields: issuer snapshots, the forward config,
    // and a generation bump. Returns false on validation failure with
    // an error message in `err_out`. Never throws.
    //
    // Reload is side-effect-free with respect to outbound auth fetches:
    // a post-reload OIDC re-kick that would otherwise dispatch through
    // UpstreamHttpClient is queued on each Issuer and not actually
    // fired until `FlushPostReloadKicks()` runs. HttpServer::Reload
    // calls FlushPostReloadKicks AFTER DNS commit so any kicked fetch
    // observes the freshly-published partition->resolved_endpoint_.
    bool Reload(const AuthConfig& new_config, std::string& err_out);

    // Drain the post-reload OIDC re-kick queued by the most recent
    // successful Reload(). No-op when no reload has run, when shutdown
    // is in progress, or for issuers whose discovery is already ready
    // / not configured. Idempotent.
    void FlushPostReloadKicks();

    // Final reload cutover — under the SAME `snapshot_mtx_` lock:
    //   1. swap `forward_` to `new_forward`
    //   2. swap `policies_` to a freshly-built AppliedPolicyList
    //   3. release-store `master_enabled_` to `new_master_enabled`
    // Called by HttpServer::Reload AFTER AuthManager::Reload() has
    // applied issuer snapshots AND the upstream topology check has
    // completed, so `new_upstreams` reflects the prefixes the router
    // will actually serve this run.
    //
    // Single publication edge: readers observing `master_enabled_=true`
    // transitively see the new policy list, new forward snapshot, and
    // new issuer snapshots. forward_ is published HERE (not earlier in
    // Reload) because ProxyTransaction reads ForwardConfig() per-hop
    // whenever IsEnforcing() is true; if forward_ swapped before the
    // policy rebuild on a TRUE→TRUE reload, requests during the gap
    // would apply the new overlay (header rename / strip) against the
    // OLD policy list — silent header-shape divergence visible to
    // upstreams. See design doc §11.2 step 4 + §18.5.
    void CommitPolicyAndEnforcement(
        const std::vector<UpstreamConfig>& new_upstreams,
        const std::vector<AuthPolicy>& new_top_level_policies,
        const AuthForwardConfig& new_forward,
        bool new_master_enabled,
        bool new_debug_response_headers);

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

    // Single-call observability helper for every auth verdict. Bumps the
    // process-wide aggregate (total_allowed_ / total_denied_ /
    // total_undetermined_), bumps the (issuer, policy) bucket, and stamps
    // X-Auth-Decision / X-Auth-Issuer / X-Auth-Cache when the live
    // debug_response_headers_ flag is on. Empty issuer omits the issuer
    // header (no issuer was matched yet). Public so the introspection
    // resume finalizers (built in an anonymous namespace) can call it via
    // a captured manager pointer.
    // captured_incarnation is the policy-name incarnation observed at
    // dispatch time (see PolicyIncarnation). Sync paths pass std::nullopt
    // (no gate — they have no dispatch-finalize time gap). Async
    // introspection finalizers capture the value at dispatch and pass it
    // here so a verdict from a removed-then-readded policy incarnation
    // does NOT contaminate the new bucket. On mismatch the per-policy
    // bump is dropped; the aggregate counter and debug headers still
    // fire because the request was a real client-visible verdict.
    void RecordVerdict(HttpResponse& resp,
                        VerifyOutcome outcome,
                        const std::string& issuer,
                        const std::string& policy,
                        AuthCache cache,
                        std::optional<uint64_t> captured_incarnation = std::nullopt,
                        std::string_view deny_reason = std::string_view{});

    // Emit reactor.auth.cache_lookups{outcome, issuer}. outcome MUST be one
    // of "hit", "miss", "stale_serve", "refresh_fail". No-op when the
    // observability manager isn't wired. Public so the introspection
    // resume finalizers (anonymous-namespace helpers) can call it via a
    // captured manager pointer.
    void EmitCacheLookup(const char* outcome,
                          const std::string& issuer) const noexcept;

    // Returns the current incarnation for `policy_name`. Always >= 1 for
    // a policy that has ever been part of a reconcile (or that has been
    // observed at all — see PolicyIncarnation impl, which lazy-creates
    // entries at value 1 so async dispatchers and sync reconcilers never
    // disagree about "incarnation 0 means never seen"). Bumped each time
    // a policy.name appears AFTER being absent in the previous reconcile
    // — i.e. every removed-then-readded cycle. Sync paths don't need to
    // call this; async paths capture the value at dispatch and pass it
    // back through RecordVerdict at finalize. Acquires per_policy_mtx_
    // briefly.
    uint64_t PolicyIncarnation(const std::string& policy_name) const;

    // Snapshot of the LIVE issuer name set — the keys of `issuers_` at
    // call time. Used by the reload-validation path to scope per-issuer
    // `ValidateHotReloadable` checks and by the top-level-policy merge
    // to distinguish live issuer refs from staged-only ones.
    //
    // Source of truth is the running AuthManager, NOT `ServerConfig`:
    // `main.cc::ReloadConfig` overwrites `current_config` with staged
    // auth topology even when a SIGHUP issuer-topology edit was warned
    // and deferred. Reading `current_config.auth.issuers` on the NEXT
    // SIGHUP would then treat staged-only issuers as live and hard-
    // reject unrelated reload-safe edits. Sourcing from `issuers_`
    // keeps the reload scope in lock-step with what's actually running.
    //
    // Thread-safety: `issuers_` topology is mutated only by Start/Stop/
    // Reload on the main/signal thread (topology deltas are rejected by
    // `Reload` — §11.2 step 2 — so keys are stable post-Start). Callers
    // on that same thread see a consistent view; dispatcher threads
    // must not call this. Safe and lock-free in the reload-driver path.
    std::unordered_set<std::string> LiveIssuerNames() const;

 private:
    // Extract the bearer token from an Authorization header. Returns an
    // empty string on missing / malformed header. Public-facing errors
    // are surfaced via VerifyResult::InvalidRequest at the call site.
    static std::string ExtractBearerToken(const HttpRequest& req,
                                           std::string& log_label_out);

    // Build an AppliedPolicyList from live+top-level sources. Used by
    // both RegisterPolicy-driven startup (reused here) and by
    // CommitPolicyAndEnforcement. Each AppliedPolicy's `incarnation`
    // field is populated from `incarnations` (lookup by policy.name);
    // missing names default to 1 so a fresh-start dispatch can capture
    // a non-zero value that distinguishes from `incarnation = 0` left
    // over from default-constructed entries.
    static std::shared_ptr<const AppliedPolicyList>
    BuildAppliedPolicyList(
        const std::vector<UpstreamConfig>& upstreams,
        const std::vector<AuthPolicy>& top_level_policies,
        const std::unordered_map<std::string, uint64_t>& incarnations = {});

    // Introspection-mode dispatch: cache lookup with sync fast-paths
    // (Fresh+active / Fresh+!active / Stale+active) and a deferred POST on
    // miss. Always resolves `state` via SetSyncResult+MarkCompletedSync or
    // Complete(payload). `fwd_snap` MUST be the same forward_ snapshot the
    // caller paired with the policies_ snapshot used to select `policy` —
    // a separate ForwardConfig() read here would race a concurrent
    // CommitForwardAndPolicies() reload and inject headers/raw_token using
    // a forward overlay that doesn't match the policy's reload generation.
    // policy_incarnation comes from the matched AppliedPolicy in the
    // snapshot the caller used to select `policy` — atomic with the
    // policy match. Threaded into IntrospectionDoneCtx so the resume
    // finalizer's RecordVerdict gate can detect a removed-then-readded
    // race.
    void InvokeAsyncIntrospection(
        const std::shared_ptr<Issuer>& issuer,
        const IssuerSnapshot& snap,
        const AuthPolicy& policy,
        const std::string& token,
        const HttpRequest& req,
        HttpResponse& resp,
        std::shared_ptr<HttpRouter::AsyncPendingState> state,
        std::shared_ptr<const AuthForwardConfig> fwd_snap,
        uint64_t policy_incarnation);

    // Same as InvokeAsyncIntrospection but skips the cache entirely. Used
    // when TokenHasher::Hash returns nullopt (rare HMAC failure) — caching
    // a colliding key would cross-leak claim bundles between tokens.
    void InvokeIntrospectionUncached(
        const std::shared_ptr<Issuer>& issuer,
        const IssuerSnapshot& snap,
        const AuthPolicy& policy,
        const std::string& token,
        const HttpRequest& req,
        HttpResponse& resp,
        std::shared_ptr<HttpRouter::AsyncPendingState> state,
        std::shared_ptr<const AuthForwardConfig> fwd_snap,
        uint64_t policy_incarnation);

    // Allocate the `auth.idp_check` INTERNAL span (or emit the
    // `auth.pending_start` event in events-fallback mode) once a live
    // introspection POST is committed. Called from the cache-miss
    // branch of `InvokeAsyncIntrospection` and from
    // `InvokeIntrospectionUncached` — NOT from `InvokeAsyncMiddleware`,
    // because the cache-hit short-circuits don't roundtrip the IdP
    // and "auth.idp_check" must describe the roundtrip, not the
    // cache lookup. Also re-points `state.issue_ctx` (built earlier
    // with inbound_server_span as parent) at the new span so the
    // outbound POST's traceparent carries the auth.idp_check span_id.
    void SetupAuthIdpCheckObservability(
        HttpRouter::AsyncPendingState& state,
        bool inbound_is_recording,
        const std::string& issuer_name);

    // Stamp a validated AuthContext onto req for the sync fast-paths
    // (cache hit / stale-serve). Mirrors the JWT-mode mutation block.
    static void StampAuthContext(const HttpRequest& req,
                                  AuthContext ctx,
                                  const std::string& issuer,
                                  const std::string& policy,
                                  const std::string& raw_jwt_header,
                                  const std::string& token);

    // Drop buckets whose policy.name is no longer present in `new_policies`.
    // Buckets keyed on a still-present policy.name are preserved across
    // reload — operators see the same counter through a same-name reload.
    // Removed-then-readded names reset to zero. Caller holds per_policy_mtx_.
    void ReconcilePerPolicyKeysLocked(const AppliedPolicyList& new_policies);

    // Bump the (issuer, policy) bucket. Lazy-creates on first observation.
    // Skips silently when both keys are empty. Issuer may be "" for verdicts
    // produced before issuer selection (token missing, oversized, etc.).
    // The atomic increment runs inside per_policy_mtx_ so a concurrent
    // ReconcilePerPolicyKeysLocked cannot erase the bucket between lookup
    // and use.
    void BumpPerPolicy(const std::string& issuer,
                        const std::string& policy,
                        VerifyOutcome outcome,
                        std::optional<uint64_t> captured_incarnation = std::nullopt);

    // Stamp X-Auth-Decision / X-Auth-Issuer / X-Auth-Cache on `resp`. No-op
    // when the live `debug_response_headers_` flag is false. Empty issuer
    // omits the issuer header (no issuer was matched yet); cache_label
    // empty / nullptr omits the cache header (JWT mode has no per-request
    // cache).
    void StampDebugHeader(HttpResponse& resp,
                          const char* decision,
                          const std::string& issuer,
                          const char* cache_label) const;

    std::unordered_map<std::string, std::shared_ptr<Issuer>> issuers_;
    std::shared_ptr<UpstreamHttpClient> upstream_http_client_;

    std::shared_ptr<const AppliedPolicyList> policies_;
    std::shared_ptr<const AuthForwardConfig> forward_;
    mutable std::mutex snapshot_mtx_;

    UpstreamManager* upstream_manager_;                    // non-owning
    std::vector<std::shared_ptr<Dispatcher>> dispatchers_;
    // Non-owning observability manager. Nullable. When set, the async
    // dispatch path builds an `IssueTraceContext` for every introspection
    // POST and (gated on `traces.auth_idp_span`) allocates an
    // `auth.idp_check` INTERNAL span over the deferred resolution.
    //
    // INVARIANT: AuthManager is declared in HttpServer BEFORE
    // ObservabilityManager, so reverse-destruction destroys the
    // observability manager FIRST. AuthManager's destructor MUST NOT
    // dereference this pointer; only runtime callers (where HttpServer
    // is still alive) are safe.
    OBSERVABILITY_NAMESPACE::ObservabilityManager* obs_manager_ = nullptr;
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
    // Live debug-response-headers switch — published in the same
    // snapshot_mtx_ critical section as policies_ / forward_ /
    // master_enabled_, BEFORE master_enabled_'s release-store. Hot path
    // reads with memory_order_acquire; cost when off is one acquire load
    // and one branch.
    std::atomic<bool> debug_response_headers_{false};

    std::atomic<uint64_t> total_allowed_{0};
    std::atomic<uint64_t> total_denied_{0};
    std::atomic<uint64_t> total_undetermined_{0};

    // Introspection-mode counters. Populated on the introspection dispatch
    // paths; left at zero in JWT-only deployments. Surfaced under
    // `auth.introspection.*` by SnapshotAll() / the /stats handler.
    std::atomic<uint64_t> introspection_ok_{0};
    std::atomic<uint64_t> introspection_fail_{0};
    std::atomic<uint64_t> introspection_cache_hit_{0};
    std::atomic<uint64_t> introspection_cache_miss_{0};
    std::atomic<uint64_t> introspection_cache_negative_hit_{0};
    std::atomic<uint64_t> introspection_stale_served_{0};
    std::atomic<uint64_t> introspection_cache_entries_{0};

    // Constructed from `hmac_key_` at Start(). Used by the introspection
    // dispatch path to derive cache keys. ready() must be true post-Start.
    TokenHasher hasher_{std::string(32, '\0')};

    // Constructed at Start() once `upstream_http_client_` is wired. Owns
    // the introspection POST plumbing for every issuer.
    std::unique_ptr<IntrospectionClient> introspection_client_;

    // Per-(issuer, policy) accumulators. Independent of snapshot_mtx_ —
    // these are runtime counters, not config snapshot. unique_ptr because
    // PerPolicyCounters holds non-movable atomics; std::map keeps lookup
    // ordered for stable /stats JSON output. Lookups happen once per
    // request after the verdict is known, never on the per-byte hot path.
    struct PerPolicyCounters {
        std::atomic<uint64_t> allowed{0};
        std::atomic<uint64_t> denied{0};
        std::atomic<uint64_t> undetermined{0};
    };
    using PerPolicyKey = std::pair<std::string, std::string>;
    mutable std::mutex per_policy_mtx_;
    std::map<PerPolicyKey, std::unique_ptr<PerPolicyCounters>> per_policy_;

    // Per-policy-name incarnation. Bumped each time a policy.name appears
    // in the new applied list AFTER being absent in the previous reconcile
    // — i.e. every removed-then-readded cycle. Async dispatch sites
    // capture the value at request time and pass it back through
    // RecordVerdict at finalize time so a stale-incarnation verdict is
    // dropped instead of contaminating the new bucket. Both maps live
    // under per_policy_mtx_; reads are coalesced with the per-bucket
    // operations so the gate is mutex-cheap.
    // Mutable so the const PolicyIncarnation() can lazy-create entries
    // at value 1 — the first read for a never-seen name pins the live
    // value to 1, matching what BuildAppliedPolicyList embeds for
    // missing-from-incarnations names. Both maps are ALWAYS accessed
    // under per_policy_mtx_.
    mutable std::unordered_map<std::string, uint64_t> policy_incarnation_;
    std::unordered_set<std::string> policy_last_reconciled_;

    std::mutex reload_mtx_;
};

}  // namespace AUTH_NAMESPACE
