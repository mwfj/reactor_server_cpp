#include "auth/auth_manager.h"

#include "auth/auth_claims.h"
#include "auth/auth_error_responses.h"
#include "auth/introspection_cache.h"
#include "auth/introspection_client.h"
#include "auth/issuer.h"
#include "auth/jwt_verifier.h"
#include "auth/token_hasher.h"
#include "auth/upstream_http_client.h"
#include "http/http_request.h"
#include "http/http_response.h"
#include "http/http_status.h"
#include "http/trailer_policy.h"  // TrimOptionalWhitespace (RFC 7230 §3.2.3)
#include "log/log_utils.h"
#include "log/logger.h"

namespace AUTH_NAMESPACE {

namespace {

static constexpr const char* kOnUndeterminedAllow = "allow";

// Outbound 8 KiB cap on bearer-token bytes. Larger tokens are unconditionally
// 401'd before any verification work — they are almost always either
// malformed or attacker-shaped. Enforced symmetrically by the sync
// (InvokeMiddleware) and async (InvokeAsyncMiddleware) entry points.
constexpr size_t kMaxBearerTokenBytes = 8192;

// Re-run policy + issuer claim checks against an already-populated
// AuthContext. Used by:
//   - cache hit / stale-hit paths in InvokeAsyncIntrospection (no body
//     available; required_claim presence checks BOTH ctx.claims (scalars)
//     AND ctx.non_scalar_claims (arrays/objects), giving cache-hit parity
//     with JWT-mode payload.contains(c) regardless of claim shape).
//   - IntrospectionClient post-parse path (body available — the live
//     POST result still goes through this same helper for symmetry,
//     after PopulateFromPayload has copied required_claim names into
//     either ctx.claims or ctx.non_scalar_claims via the augmented
//     claim_keys list).
//
// Audience: policy.required_audience overrides; otherwise issuer
// snap.audiences fallback (any-match). Empty on both sides → accept.
//
// Required claims: presence-only check against ctx.claims OR
// ctx.non_scalar_claims (matches JWT-mode semantics — JwtVerifier checks
// payload.contains(c)).
//
// Required scopes: HasRequiredScopes(ctx.scopes, policy.required_scopes).
//
// Returns Allow on pass; Deny401 on audience/required-claim fail; Deny403
// on scope fail. Never throws — pure data access against ctx fields.
VerifyResult RunPolicyAndIssuerClaimChecks(
        const AuthPolicy& policy,
        const IssuerSnapshot& snap,
        const AuthContext& ctx) {
    if (!policy.required_audience.empty()) {
        if (!MatchesAudienceFromCtx(ctx, policy.required_audience)) {
            return VerifyResult::InvalidToken("audience mismatch",
                                                "audience_mismatch");
        }
    } else if (!snap.audiences.empty()) {
        bool any_ok = false;
        for (const auto& a : snap.audiences) {
            if (MatchesAudienceFromCtx(ctx, a)) { any_ok = true; break; }
        }
        if (!any_ok) {
            return VerifyResult::InvalidToken("audience mismatch",
                                                "audience_mismatch");
        }
    }
    for (const auto& c : snap.required_claims) {
        const bool present = ctx.claims.find(c) != ctx.claims.end() ||
                             ctx.non_scalar_claims.find(c) !=
                                 ctx.non_scalar_claims.end();
        if (!present) {
            return VerifyResult::InvalidToken("missing required claim",
                                                "missing_required_claim");
        }
    }
    if (!HasRequiredScopes(ctx.scopes, policy.required_scopes)) {
        return VerifyResult::InsufficientScope("insufficient scope",
                                                "insufficient_scope");
    }
    return VerifyResult::Allow();
}

// Build inline policies from live+new upstream lists: each inline
// `proxy.auth` block with `enabled=true` implicitly registers a policy
// whose applies_to is {proxy.route_prefix}.
void CollectInlineAuthPolicies(const std::vector<UpstreamConfig>& upstreams,
                                AppliedPolicyList& out) {
    for (const auto& u : upstreams) {
        if (!u.proxy.auth.enabled) continue;
        if (u.proxy.route_prefix.empty()) continue;
        // The policy's `applies_to` ignored for inline use; prefix taken
        // from route_prefix directly. Name is conventional — operators
        // don't see it outside of debug logs.
        AuthPolicy p = u.proxy.auth;
        if (p.name.empty()) p.name = "inline:" + u.name;
        // Clear applies_to to avoid confusing snapshot API consumers.
        p.applies_to.clear();
        out.push_back({u.proxy.route_prefix, p});
    }
}

void CollectTopLevelPolicies(const std::vector<AuthPolicy>& top_level,
                              AppliedPolicyList& out) {
    for (const auto& p : top_level) {
        if (!p.enabled) continue;
        for (const auto& prefix : p.applies_to) {
            out.push_back({prefix, p});
        }
    }
}

const char* DecisionLabel(VerifyOutcome outcome) {
    switch (outcome) {
      case VerifyOutcome::ALLOW: return "allow";
      case VerifyOutcome::DENY_401:
      case VerifyOutcome::DENY_403: return "deny";
      case VerifyOutcome::UNDETERMINED: return "undetermined";
    }
    return "";
}

const char* CacheLabel(AuthCache cache) {
    switch (cache) {
      case AuthCache::None: return "";
      case AuthCache::Hit: return "hit";
      case AuthCache::Miss: return "miss";
      case AuthCache::Stale: return "stale";
      case AuthCache::Negative: return "negative";
      case AuthCache::Uncached: return "uncached";
    }
    return "";
}

}  // namespace

AuthManager::AuthManager(const AuthConfig& config,
                          UpstreamManager* upstream_manager,
                          std::vector<std::shared_ptr<Dispatcher>> dispatchers)
    : upstream_manager_(upstream_manager),
      dispatchers_(std::move(dispatchers)) {
    // Master switch — mirrored from AuthConfig::enabled and live-reloadable.
    master_enabled_.store(config.enabled, std::memory_order_release);
    debug_response_headers_.store(config.debug_response_headers,
                                   std::memory_order_release);
    // Resolve the HMAC key: operator-supplied env var OR fresh random.
    if (!config.hmac_cache_key_env.empty()) {
        hmac_key_ = LoadHmacKeyFromEnv(config.hmac_cache_key_env);
    }
    if (hmac_key_.empty()) {
        hmac_key_ = GenerateHmacKey();
    }

    // Shared HTTP client reused across issuers (§19.3).
    upstream_http_client_ = std::make_shared<UpstreamHttpClient>(
        upstream_manager_, dispatchers_);

    // Build issuers. Topology-stable: the set is fixed here; reloads can
    // only touch reloadable fields on existing issuers.
    issuers_.reserve(config.issuers.size());
    for (const auto& [name, issuer_cfg] : config.issuers) {
        // IssuerConfig.name is the authoritative identifier. Guard
        // against config-keyed maps where the key and the embedded name
        // disagree.
        IssuerConfig normalized = issuer_cfg;
        if (normalized.name.empty()) normalized.name = name;
        auto issuer = std::make_shared<Issuer>(
            normalized, upstream_manager_, dispatchers_,
            upstream_http_client_, hmac_key_, &stopping_);
        issuers_.emplace(normalized.name, std::move(issuer));
    }

    // Initial snapshots: forward from config, policies built empty
    // (RegisterPolicy adds entries; Start is the sealing point).
    {
        AuthForwardConfig fwd_copy = config.forward;
        fwd_copy.PopulateDerived();
        forward_ = std::make_shared<const AuthForwardConfig>(std::move(fwd_copy));
    }
    policies_ = std::make_shared<AppliedPolicyList>();

    logging::Get()->info(
        "AuthManager constructed issuers={} policies={} (applied later) "
        "gen={}",
        issuers_.size(), config.policies.size(),
        generation_.load(std::memory_order_relaxed));
}

AuthManager::~AuthManager() {
    Stop();
}

void AuthManager::Start() {
    // Construct the token hasher from the resolved HMAC key. Fail-closed
    // when the key is unusable: leaving master_enabled_=true with a
    // non-ready hasher would silently bypass the cache (every request
    // becomes a live POST), which is a stealth performance regression.
    hasher_ = TokenHasher(hmac_key_);
    if (!hasher_.ready()) {
        throw std::runtime_error(
            "AuthManager::Start: token hasher initialization failed — "
            "hmac_cache_key_env unset or invalid");
    }

    introspection_client_ =
        std::make_unique<IntrospectionClient>(upstream_http_client_);

    for (auto& [name, issuer] : issuers_) {
        issuer->Start();
    }
    started_.store(true, std::memory_order_release);
    logging::Get()->info("AuthManager started issuers={}", issuers_.size());
}

void AuthManager::RequestStop() {
    stopping_.store(true, std::memory_order_release);
}

void AuthManager::FlushPostReloadKicks() {
    // Stopping check first — if shutdown was published between Reload
    // and here, skip the kicks. Issuer::FlushPostReloadKick repeats the
    // check defensively; this short-circuit avoids the per-issuer loop.
    if (stopping_.load(std::memory_order_acquire)) return;
    for (auto& [name, issuer] : issuers_) {
        if (issuer) issuer->FlushPostReloadKick();
    }
}

void AuthManager::Stop() {
    // Acquire reload_mtx_ first: serialises with any in-flight Reload that
    // is already inside its critical section past the stopping_ check
    // (i.e. the Reload thread reached Reload's lock_guard before we set
    // stopping_ above). Without this, Stop's per-issuer issuer->Stop()
    // could race with that Reload's issuer->ApplyReload(), losing the
    // cancel when ApplyReload re-arms discovery.
    std::lock_guard<std::mutex> reload_lock(reload_mtx_);
    stopping_.store(true, std::memory_order_release);
    for (auto& [name, issuer] : issuers_) {
        if (issuer) issuer->Stop();
    }
}

void AuthManager::RegisterPolicy(std::vector<std::string> prefixes,
                                   AuthPolicy policy) {
    if (started_.load(std::memory_order_acquire)) {
        logging::Get()->warn(
            "AuthManager::RegisterPolicy called post-Start (ignored) "
            "policy={}",
            policy.name.empty() ? std::string("<unnamed>") : policy.name);
        return;
    }
    if (!policy.enabled) {
        logging::Get()->debug(
            "AuthManager::RegisterPolicy policy disabled; skipped name={}",
            policy.name);
        return;
    }
    // Append under snapshot_mtx_ — a race with InvokeMiddleware still
    // publishes a coherent shared_ptr after the swap.
    std::lock_guard<std::mutex> lk(snapshot_mtx_);
    auto updated = std::make_shared<AppliedPolicyList>(*policies_);
    for (auto& prefix : prefixes) {
        updated->push_back({std::move(prefix), policy});
    }
    policies_ = std::shared_ptr<const AppliedPolicyList>(std::move(updated));
    logging::Get()->debug(
        "AuthManager::RegisterPolicy policy={} entries={} total={}",
        policy.name, prefixes.size(), policies_->size());
}

std::shared_ptr<const AuthForwardConfig> AuthManager::ForwardConfig() const {
    std::lock_guard<std::mutex> lk(snapshot_mtx_);
    return forward_;
}

bool AuthManager::ValidateReload(const AuthConfig& new_config,
                                   std::string& err_out) const {
    // Topology check — same as Reload's Pass 1, but pure (no plan-vector
    // build, no iteration of issuers_ besides counting + name lookup).
    // const-qualified to make the no-mutation invariant a type-system
    // guarantee.
    if (new_config.issuers.size() != issuers_.size()) {
        err_out = "auth issuer topology change (add/remove) requires restart";
        return false;
    }
    for (const auto& [name, ic] : new_config.issuers) {
        auto it = issuers_.find(name);
        if (it == issuers_.end()) {
            err_out = "auth issuer topology change: unknown '" + name + "'";
            return false;
        }
        IssuerConfig normalized = ic;
        if (normalized.name.empty()) normalized.name = name;
        std::string validate_err;
        if (!it->second->ValidateReload(normalized, validate_err)) {
            err_out = "issuer '" + normalized.name + "': " + validate_err;
            return false;
        }
    }
    return true;
}

bool AuthManager::Reload(const AuthConfig& new_config, std::string& err_out) {
    std::lock_guard<std::mutex> reload_lock(reload_mtx_);

    // Bail if shutdown has been requested. RequestStop() / Stop() publish
    // stopping_ with release ordering; we acquire it under reload_mtx_ so
    // that a concurrent Stop after RequestStop sees this Reload exit
    // cleanly without ApplyReload re-arming background discovery.
    if (stopping_.load(std::memory_order_acquire)) {
        err_out = "auth manager is stopping";
        return false;
    }

    // Pass 1 — topology check. Any add/remove/rename rejects the whole
    //          reload; the manager preserves live state.
    if (new_config.issuers.size() != issuers_.size()) {
        err_out = "auth issuer topology change (add/remove) requires restart";
        return false;
    }
    std::vector<std::pair<std::shared_ptr<Issuer>, IssuerConfig>> plan;
    plan.reserve(new_config.issuers.size());
    for (const auto& [name, ic] : new_config.issuers) {
        auto it = issuers_.find(name);
        if (it == issuers_.end()) {
            err_out = "auth issuer topology change: unknown '" + name + "'";
            return false;
        }
        IssuerConfig normalized = ic;
        if (normalized.name.empty()) normalized.name = name;
        plan.emplace_back(it->second, normalized);
    }

    // Pass 2 — VALIDATE every issuer before mutating any. Prior behavior
    //          applied each issuer sequentially, so a late failure left
    //          earlier issuers already committed. With ValidateReload we
    //          get atomicity across the set: if ANY issuer would reject,
    //          no issuer changes live state.
    for (auto& [issuer_ptr, new_cfg] : plan) {
        std::string validate_err;
        if (!issuer_ptr->ValidateReload(new_cfg, validate_err)) {
            err_out = "issuer '" + new_cfg.name + "': " + validate_err;
            return false;
        }
    }

    // Pass 3 — APPLY. ApplyReload re-runs its own defence-in-depth
    //          validation; we expect every call to succeed now, but if
    //          one does fail (race with config mutation, or a field
    //          missed by ValidateReload), log loudly — live state may be
    //          partially updated at that point.
    for (auto& [issuer_ptr, new_cfg] : plan) {
        std::string apply_err;
        if (!issuer_ptr->ApplyReload(new_cfg, apply_err)) {
            logging::Get()->error(
                "AuthManager::Reload apply failed AFTER validate passed — "
                "live state may be partial issuer={} err={}",
                new_cfg.name, apply_err);
            err_out = "issuer '" + new_cfg.name
                    + "' apply failed after validate: " + apply_err;
            return false;
        }
    }

    // forward_ and master_enabled_ are DELIBERATELY NOT touched here.
    // The final cutover (forward_ + policies_ + master_enabled_) happens
    // in CommitPolicyAndEnforcement under the same `snapshot_mtx_` lock,
    // called by HttpServer::Reload after the upstream topology check.
    //
    // Why forward_ moved out of Reload (was here in earlier rounds):
    // ProxyTransaction::Start reads ForwardConfig() per-hop whenever
    // IsEnforcing() is true. On a TRUE→TRUE reload that combines a
    // forward overlay edit with a policy edit, publishing forward_
    // here would let in-flight requests apply the new overlay (header
    // rename / claim re-injection / preserve_authorization=false strip)
    // against the OLD policy list — silent header-shape divergence
    // visible to upstreams. Single-snapshot cutover requires forward_
    // to publish at the same publication edge as policies_.
    generation_.fetch_add(1, std::memory_order_release);

    logging::Get()->info(
        "AuthManager reloaded (issuer+forward) enabled_pending={} issuers={} gen={}",
        new_config.enabled, issuers_.size(),
        generation_.load(std::memory_order_acquire));
    return true;
}

void AuthManager::CommitPolicyAndEnforcement(
        const std::vector<UpstreamConfig>& new_upstreams,
        const std::vector<AuthPolicy>& new_top_level_policies,
        const AuthForwardConfig& new_forward,
        bool new_master_enabled,
        bool new_debug_response_headers) {
    auto rebuilt = BuildAppliedPolicyList(new_upstreams,
                                            new_top_level_policies);
    AuthForwardConfig fwd_copy = new_forward;
    fwd_copy.PopulateDerived();
    auto fwd_snap = std::make_shared<const AuthForwardConfig>(std::move(fwd_copy));
    // Detect a forward.claim_keys change so we can drop stale positive
    // introspection cache entries AFTER the swap. Cached
    // ctx.claims/non_scalar_claims were populated using the OLD claim_keys
    // list — any new key added by the operator would otherwise be missing
    // from the cached ctx until the positive TTL expired, dropping
    // outbound headers (claims_to_headers) for cache-hit requests.
    bool claim_keys_changed = false;
    // Single atomic cutover under snapshot_mtx_:
    //   1. forward_ swap
    //   2. policies_ swap
    //   3. debug_response_headers_ release-store
    //   4. master_enabled_ release-store (final publication edge)
    // A reader observing master_enabled_=true sees fresh forward_ /
    // policies_ / debug_response_headers_ via the lock-mutex acquire
    // ordering. Forward is grouped here (not in Reload) so a TRUE→TRUE
    // reload combining a forward overlay edit with a policy edit can't
    // expose the window where ProxyTransaction reads new forward_ while
    // the matcher is still on the old policy list.
    {
        std::lock_guard<std::mutex> lk(snapshot_mtx_);
        if (forward_) {
            claim_keys_changed = forward_->claim_keys != fwd_snap->claim_keys;
        } else {
            claim_keys_changed = !fwd_snap->claim_keys.empty();
        }
        forward_ = std::move(fwd_snap);
        policies_ = rebuilt;
        debug_response_headers_.store(new_debug_response_headers,
                                       std::memory_order_release);
        master_enabled_.store(new_master_enabled,
                               std::memory_order_release);
    }
    // Reconcile per-policy buckets: drop counters keyed on policy.name
    // values that no longer appear in the rebuilt list. Same-name buckets
    // are preserved so operators see stable counters through a same-name
    // reload; removed-then-readded names reset to zero on next emit.
    {
        std::lock_guard<std::mutex> lk(per_policy_mtx_);
        if (rebuilt) {
            ReconcilePerPolicyKeysLocked(*rebuilt);
        }
    }
    // Drop positive introspection cache entries on every issuer when
    // forward.claim_keys changed — done AFTER the snapshot swap so any
    // concurrent cache-miss POST observes the new claim_keys via the
    // augmented `claim_keys` list InvokeAsyncIntrospection threads through.
    //
    // Two-pass over issuers_ to fence in-flight completions:
    //   Pass A — bump generation_ ONLY for ready introspection-mode
    //            issuers, BEFORE clearing any cache. In-flight
    //            introspection completions captured the OLD claim_keys
    //            at dispatch time and check `gen !=
    //            issuer->generation()` BEFORE writing into the cache;
    //            the bump forces them onto the `reload_in_flight` drop-
    //            guard so they can never insert a stale entry after our
    //            Clear() below.
    //   Pass B — Clear() each issuer's introspection cache (the per-
    //            issuer getter returns null for JWT-mode, so JWT-mode
    //            issuers naturally skip).
    //
    // Why the ready+introspection gate on Pass A:
    // The issuer's `generation_` is shared between the introspection
    // completion gate (what we want to fence here) AND OidcDiscovery's
    // on_ready_cb gate. A pre-ready issuer has a discovery callback
    // in flight that captured the old generation; bumping unconditionally
    // would orphan that callback (KickOffOidcDiscovery's gen-check would
    // reject it forever, leaving the issuer not-ready until restart).
    // Pre-ready issuers also can't have any cache entries — IsReady()
    // gates request acceptance — so there are no in-flight introspection
    // completions to fence anyway. JWT-mode issuers have no
    // introspection cache and thus nothing to fence.
    //
    // issuers_ is topology-stable post-construction (Reload preserves the
    // existing map; topology changes are restart-required), and
    // IntrospectionCache::Clear takes per-shard locks internally.
    if (claim_keys_changed) {
        size_t fenced = 0;
        for (auto& [name, issuer_ptr] : issuers_) {
            if (!issuer_ptr) continue;
            if (issuer_ptr->mode() != kModeIntrospection) continue;
            if (!issuer_ptr->IsReady()) continue;
            (void)issuer_ptr->BumpGenerationForClaimKeyReload();
            ++fenced;
        }
        for (auto& [name, issuer_ptr] : issuers_) {
            if (!issuer_ptr) continue;
            if (auto* cache = issuer_ptr->introspection_cache()) {
                cache->Clear();
            }
        }
        logging::Get()->info(
            "AuthManager commit: introspection caches cleared "
            "(forward.claim_keys changed) issuers={} generations_fenced={}",
            issuers_.size(), fenced);
    }
    logging::Get()->info(
        "AuthManager commit: policies={} enforcing={}",
        rebuilt ? rebuilt->size() : 0, new_master_enabled);
}

AuthManager::SnapshotView AuthManager::SnapshotAll() const {
    SnapshotView out;
    out.total_allowed = total_allowed_.load(std::memory_order_relaxed);
    out.total_denied = total_denied_.load(std::memory_order_relaxed);
    out.total_undetermined = total_undetermined_.load(std::memory_order_relaxed);
    out.generation = generation_.load(std::memory_order_acquire);
    out.enabled = master_enabled_.load(std::memory_order_acquire);
    out.debug_response_headers =
        debug_response_headers_.load(std::memory_order_acquire);
    out.introspection_ok =
        introspection_ok_.load(std::memory_order_relaxed);
    out.introspection_fail =
        introspection_fail_.load(std::memory_order_relaxed);
    out.introspection_cache_hit =
        introspection_cache_hit_.load(std::memory_order_relaxed);
    out.introspection_cache_miss =
        introspection_cache_miss_.load(std::memory_order_relaxed);
    out.introspection_cache_negative_hit =
        introspection_cache_negative_hit_.load(std::memory_order_relaxed);
    out.introspection_stale_served =
        introspection_stale_served_.load(std::memory_order_relaxed);
    {
        std::lock_guard<std::mutex> lk(snapshot_mtx_);
        out.policy_count = policies_ ? policies_->size() : 0;
    }
    {
        std::lock_guard<std::mutex> lk(per_policy_mtx_);
        out.per_policy.reserve(per_policy_.size());
        for (const auto& [k, v] : per_policy_) {
            PerPolicyCountersView pp;
            pp.issuer = k.first;
            pp.policy = k.second;
            pp.allowed = v->allowed.load(std::memory_order_relaxed);
            pp.denied = v->denied.load(std::memory_order_relaxed);
            pp.undetermined = v->undetermined.load(std::memory_order_relaxed);
            out.per_policy.push_back(std::move(pp));
        }
    }
    for (const auto& [name, issuer] : issuers_) {
        if (!issuer) continue;
        out.issuers[name] = issuer->BuildView();
    }
    return out;
}

Issuer* AuthManager::GetIssuer(const std::string& issuer_name) {
    auto it = issuers_.find(issuer_name);
    if (it == issuers_.end()) return nullptr;
    return it->second.get();
}

std::unordered_set<std::string> AuthManager::LiveIssuerNames() const {
    // Topology-stable post-Start → lock-free copy. See header for the
    // full thread-safety contract.
    std::unordered_set<std::string> out;
    out.reserve(issuers_.size());
    for (const auto& kv : issuers_) {
        out.insert(kv.first);
    }
    return out;
}

bool AuthManager::InvokeMiddleware(const HttpRequest& req,
                                     HttpResponse& resp) {
    // Master enforcement switch — `auth.enabled: false` passes through even
    // when the middleware is installed (installed unconditionally so
    // `auth.enabled: false → true` via SIGHUP takes effect without restart).
    if (!master_enabled_.load(std::memory_order_acquire)) {
        return true;
    }
    // Ordering invariant: all RegisterPolicy() calls precede Start(), which
    // installs this middleware — the snapshot is always complete here.
    //
    // Fast path: take both snapshot pointers under a single lock. Reload
    // swaps them under snapshot_mtx_ — we see a consistent pair for the
    // full request duration.
    std::shared_ptr<const AppliedPolicyList> policies_snap;
    std::shared_ptr<const AuthForwardConfig> fwd_snap;
    {
        std::lock_guard<std::mutex> lk(snapshot_mtx_);
        policies_snap = policies_;
        fwd_snap = forward_;
    }
    if (!policies_snap || policies_snap->empty()) {
        // No policies: no auth required. Continue.
        return true;
    }

    const AppliedPolicy* ap =
        FindPolicyForPath(*policies_snap, req.path);
    if (ap == nullptr) {
        return true;
    }
    const AuthPolicy& policy = ap->policy;
    if (!policy.enabled) return true;

    const std::string realm = policy.realm.empty()
        ? std::string("api") : policy.realm;

    // Extract bearer token.
    std::string log_label;
    std::string token = ExtractBearerToken(req, log_label);
    if (token.empty()) {
        logging::Get()->info(
            "auth_deny reason={} route={} policy={}",
            log_label.empty() ? std::string("missing_authorization") : log_label,
            logging::SanitizePath(req.path), policy.name);
        resp = MakeUnauthorized(realm, AuthErrorCode::InvalidRequest,
                                 "authorization required");
        RecordVerdict(resp, VerifyOutcome::DENY_401, std::string{},
                       policy.name, AuthCache::None);
        return false;
    }
    // 8 KiB DoS guard mirrors InvokeAsyncMiddleware. JWT-only requests and
    // the sync PeekIssuer step (below) MUST also reject oversized tokens
    // before any verification work — otherwise the cap is bypassable on
    // pure JWT deployments.
    if (token.size() > kMaxBearerTokenBytes) {
        logging::Get()->info(
            "auth_deny reason=token_too_large route={} policy={}",
            logging::SanitizePath(req.path), policy.name);
        resp = MakeUnauthorized(realm, AuthErrorCode::InvalidRequest,
                                 "token too large");
        RecordVerdict(resp, VerifyOutcome::DENY_401, std::string{},
                       policy.name, AuthCache::None);
        return false;
    }

    // Pick the issuer: prefer `iss` peek, else the first policy issuer.
    Issuer* chosen = nullptr;
    auto peeked = JwtVerifier::PeekIssuer(token);
    if (peeked) {
        for (const auto& issuer_name : policy.issuers) {
            auto it = issuers_.find(issuer_name);
            if (it == issuers_.end() || !it->second) continue;
            // Issuer config keys the allowlist by the *name* operators
            // use in config; the `iss` claim the token carries is
            // issuer_url. Compare against the configured url.
            if (it->second->issuer_url() == *peeked) {
                chosen = it->second.get();
                break;
            }
        }
        if (!chosen) {
            // `iss` present but not in the policy allowlist — DENY 401.
            logging::Get()->info(
                "auth_deny reason=issuer_not_accepted route={} policy={}",
                logging::SanitizePath(req.path), policy.name);
            resp = MakeUnauthorized(realm, AuthErrorCode::InvalidToken,
                                     "issuer not accepted");
            RecordVerdict(resp, VerifyOutcome::DENY_401, std::string{},
                           policy.name, AuthCache::None);
            return false;
        }
    } else if (!policy.issuers.empty()) {
        // No `iss` peek (opaque token, malformed JWT, etc.). For mixed-mode
        // policies, prefer the first introspection-mode issuer so the
        // sync chain passes through to the async chain (which validates
        // opaque tokens against the IdP). Falling back to issuers.front()
        // when front() is JWT-mode would cause JwtVerifier to reject the
        // opaque token as malformed before the async chain ever runs.
        for (const auto& issuer_name : policy.issuers) {
            auto it = issuers_.find(issuer_name);
            if (it == issuers_.end() || !it->second) continue;
            if (it->second->mode() == kModeIntrospection) {
                chosen = it->second.get();
                break;
            }
        }
        if (!chosen) {
            // No introspection issuer in this policy — pure JWT-mode; fall
            // back to front() and let jwt-cpp's `with_issuer` enforce.
            auto it = issuers_.find(policy.issuers.front());
            if (it != issuers_.end()) chosen = it->second.get();
        }
    }
    if (!chosen) {
        // No issuer available (rare — policy was validated at load).
        logging::Get()->warn(
            "auth_undetermined reason=no_issuer_for_policy route={} policy={}",
            logging::SanitizePath(req.path), policy.name);
        if (policy.on_undetermined == "allow") {
            AuthContext ctx;
            ctx.undetermined = true;
            ctx.policy_name = policy.name;
            req.auth.emplace(std::move(ctx));
            RecordVerdict(resp, VerifyOutcome::UNDETERMINED, std::string{},
                           policy.name, AuthCache::None);
            return true;
        }
        resp = MakeServiceUnavailable(realm, 5,
                                        "authentication unavailable");
        RecordVerdict(resp, VerifyOutcome::UNDETERMINED, std::string{},
                       policy.name, AuthCache::None);
        return false;
    }

    // Introspection-mode policies are owned by the async adapter
    // (InvokeAsyncMiddleware). Pass through so the request reaches the
    // async chain; bearer extraction and issuer selection are re-run there.
    if (chosen->mode() == kModeIntrospection) {
        return true;
    }

    // Operator-configured forward.claims_to_headers keys flow into
    // Verify so PopulateFromPayload can copy them into ctx.claims for
    // outbound injection. Policy-level required_claims are enforced
    // inside Verify and do NOT need to appear here. claim_keys is
    // pre-built into the AuthForwardConfig snapshot; an empty vector
    // (no fwd_snap) is safe to pass.
    static const std::vector<std::string> kEmptyClaimKeys;
    const std::vector<std::string>& claim_keys =
        fwd_snap ? fwd_snap->claim_keys : kEmptyClaimKeys;

    // Run the verifier. Never throws. Pass the inbound request's
    // dispatcher_index through so a kid-miss JWKS refresh stays on the
    // caller's partition instead of always hitting partition 0. Fall
    // back to 0 when unset (rare paths / tests that don't populate it).
    AuthContext ctx;
    const size_t verifier_dispatcher =
        req.dispatcher_index >= 0
            ? static_cast<size_t>(req.dispatcher_index)
            : 0;
    VerifyResult vr = JwtVerifier::Verify(
        token, *chosen, policy, claim_keys, verifier_dispatcher, ctx);

    switch (vr.outcome) {
        case VerifyOutcome::ALLOW: {
            // Populate claims_to_headers-requested keys BEFORE committing.
            // JwtVerifier::Verify intentionally does not see the forward
            // config; it runs the policy-level checks. Operator-selected
            // claims flow from forward.claims_to_headers via the overlay
            // at the outbound hop (HeaderRewriter Phase E).
            ctx.policy_name = policy.name;
            // Stash the raw token only when the operator explicitly asked
            // for it via forward.raw_jwt_header.
            if (fwd_snap && !fwd_snap->raw_jwt_header.empty()) {
                ctx.raw_token = token;
            }
            req.auth.emplace(std::move(ctx));
            RecordVerdict(resp, VerifyOutcome::ALLOW, chosen->name(),
                           policy.name, AuthCache::None);
            if (auto lg = logging::Get();
                    lg->should_log(spdlog::level::debug)) {
                lg->debug("auth_allow route={} issuer={} sub={} policy={}",
                          logging::SanitizePath(req.path),
                          logging::SanitizeLogValue(chosen->name()),
                          logging::SanitizeLogValue(req.auth->subject),
                          logging::SanitizeLogValue(policy.name));
            }
            return true;
        }
        case VerifyOutcome::DENY_401: {
            logging::Get()->info(
                "auth_deny route={} issuer={} reason={} policy={}",
                logging::SanitizePath(req.path),
                logging::SanitizeLogValue(chosen->name()),
                vr.log_reason,
                logging::SanitizeLogValue(policy.name));
            resp = MakeUnauthorized(realm, vr.error_code,
                                     vr.error_description);
            RecordVerdict(resp, VerifyOutcome::DENY_401, chosen->name(),
                           policy.name, AuthCache::None);
            return false;
        }
        case VerifyOutcome::DENY_403: {
            logging::Get()->info(
                "auth_deny route={} issuer={} reason={} policy={}",
                logging::SanitizePath(req.path),
                logging::SanitizeLogValue(chosen->name()),
                vr.log_reason,
                logging::SanitizeLogValue(policy.name));
            resp = MakeForbidden(realm, vr.error_description,
                                  policy.required_scopes);
            RecordVerdict(resp, VerifyOutcome::DENY_403, chosen->name(),
                           policy.name, AuthCache::None);
            return false;
        }
        case VerifyOutcome::UNDETERMINED: {
            logging::Get()->warn(
                "auth_undetermined route={} issuer={} reason={} policy={}",
                logging::SanitizePath(req.path),
                logging::SanitizeLogValue(chosen->name()),
                vr.log_reason,
                logging::SanitizeLogValue(policy.name));
            if (policy.on_undetermined == "allow") {
                AuthContext advisory;
                advisory.undetermined = true;
                advisory.policy_name = policy.name;
                advisory.issuer = chosen->name();
                req.auth.emplace(std::move(advisory));
                RecordVerdict(resp, VerifyOutcome::UNDETERMINED,
                               chosen->name(), policy.name, AuthCache::None);
                return true;
            }
            resp = MakeServiceUnavailable(realm, vr.retry_after_sec,
                                            "authentication unavailable");
            RecordVerdict(resp, VerifyOutcome::UNDETERMINED, chosen->name(),
                           policy.name, AuthCache::None);
            return false;
        }
    }
    // Unreachable — every outcome is handled above.
    return false;
}

// ---------------------------------------------------------------------------
// Static helpers
// ---------------------------------------------------------------------------

std::string AuthManager::ExtractBearerToken(const HttpRequest& req,
                                              std::string& log_label_out) {
    auto h = req.GetHeader("authorization");
    if (h.empty()) {
        log_label_out = "missing_authorization";
        return {};
    }
    // Case-insensitive "Bearer " prefix (RFC 6750 §2.1).
    static const char kPrefix[] = "bearer ";
    const size_t plen = sizeof(kPrefix) - 1;
    if (h.size() <= plen) {
        log_label_out = "bad_scheme";
        return {};
    }
    for (size_t i = 0; i < plen; ++i) {
        char c = h[i];
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        if (c != kPrefix[i]) {
            log_label_out = "bad_scheme";
            return {};
        }
    }
    // Trim OWS per RFC 7230 §3.2.3 via the shared helper used by every
    // other HTTP header parser in this codebase.
    std::string token = TrimOptionalWhitespace(h.substr(plen));
    if (token.empty()) {
        log_label_out = "empty_token";
        return {};
    }
    return token;
}

std::shared_ptr<const AppliedPolicyList> AuthManager::BuildAppliedPolicyList(
        const std::vector<UpstreamConfig>& upstreams,
        const std::vector<AuthPolicy>& top_level_policies) {
    auto out = std::make_shared<AppliedPolicyList>();
    CollectInlineAuthPolicies(upstreams, *out);
    CollectTopLevelPolicies(top_level_policies, *out);
    // Post-build integrity check: duplicate exact-prefix collisions between
    // inline proxy.auth blocks and top-level policies can lead to
    // non-deterministic policy selection (FindPolicyForPath returns the
    // first longest-match, not necessarily the intended one). Log a warning;
    // the duplicate is NOT fatal at runtime — the list is still usable.
    std::string dup_err;
    if (!ValidatePolicyList(*out, dup_err)) {
        logging::Get()->warn(
            "AuthManager policy list has duplicate prefix entry: {}", dup_err);
    }
    return std::shared_ptr<const AppliedPolicyList>(std::move(out));
}

// ---------------------------------------------------------------------------
// Async middleware path (introspection mode)
// ---------------------------------------------------------------------------

void AuthManager::StampAuthContext(const HttpRequest& req,
                                     AuthContext ctx,
                                     const std::string& issuer,
                                     const std::string& policy,
                                     const std::string& raw_jwt_header,
                                     const std::string& token) {
    ctx.policy_name = policy;
    if (ctx.issuer.empty()) ctx.issuer = issuer;
    if (!raw_jwt_header.empty()) {
        ctx.raw_token = token;
    }
    req.auth.emplace(std::move(ctx));
}

void AuthManager::StampDebugHeader(HttpResponse& resp,
                                     const char* decision,
                                     const std::string& issuer,
                                     const char* cache_label) const {
    if (!debug_response_headers_.load(std::memory_order_acquire)) {
        return;
    }
    if (decision && *decision) {
        resp.Header("X-Auth-Decision", decision);
    }
    if (!issuer.empty()) {
        resp.Header("X-Auth-Issuer", issuer);
    }
    if (cache_label && *cache_label) {
        resp.Header("X-Auth-Cache", cache_label);
    }
}

void AuthManager::BumpPerPolicy(const std::string& issuer,
                                  const std::string& policy,
                                  VerifyOutcome outcome) {
    if (issuer.empty() && policy.empty()) {
        return;
    }
    std::lock_guard<std::mutex> lk(per_policy_mtx_);
    auto key = std::make_pair(issuer, policy);
    auto it = per_policy_.find(key);
    if (it == per_policy_.end()) {
        auto inserted = per_policy_.emplace(
            std::move(key), std::make_unique<PerPolicyCounters>());
        it = inserted.first;
    }
    PerPolicyCounters& counters = *it->second;
    switch (outcome) {
      case VerifyOutcome::ALLOW:
        counters.allowed.fetch_add(1, std::memory_order_relaxed);
        break;
      case VerifyOutcome::DENY_401:
      case VerifyOutcome::DENY_403:
        counters.denied.fetch_add(1, std::memory_order_relaxed);
        break;
      case VerifyOutcome::UNDETERMINED:
        counters.undetermined.fetch_add(1, std::memory_order_relaxed);
        break;
    }
}

void AuthManager::RecordVerdict(HttpResponse& resp,
                                  VerifyOutcome outcome,
                                  const std::string& issuer,
                                  const std::string& policy,
                                  AuthCache cache) {
    switch (outcome) {
      case VerifyOutcome::ALLOW:
        total_allowed_.fetch_add(1, std::memory_order_relaxed);
        break;
      case VerifyOutcome::DENY_401:
      case VerifyOutcome::DENY_403:
        total_denied_.fetch_add(1, std::memory_order_relaxed);
        break;
      case VerifyOutcome::UNDETERMINED:
        total_undetermined_.fetch_add(1, std::memory_order_relaxed);
        break;
    }
    BumpPerPolicy(issuer, policy, outcome);
    StampDebugHeader(resp, DecisionLabel(outcome), issuer, CacheLabel(cache));
}

void AuthManager::ReconcilePerPolicyKeysLocked(
        const AppliedPolicyList& new_policies) {
    std::unordered_set<std::string> kept;
    for (const auto& ap : new_policies) {
        kept.insert(ap.policy.name);
    }
    for (auto it = per_policy_.begin(); it != per_policy_.end(); ) {
        if (kept.count(it->first.second) == 0) {
            it = per_policy_.erase(it);
        } else {
            ++it;
        }
    }
}

void AuthManager::InvokeAsyncMiddleware(
        const HttpRequest& req, HttpResponse& resp,
        std::shared_ptr<HttpRouter::AsyncPendingState> state) {
    auto sync_pass = [&state]() {
        state->SetSyncResult(AsyncMiddlewareResult::PASS);
        state->MarkCompletedSync();
    };

    if (!master_enabled_.load(std::memory_order_acquire)) {
        sync_pass();
        return;
    }

    // Capture both snapshots under one lock so a CommitForwardAndPolicies
    // reload between policy selection and forward injection cannot mix a
    // pre-reload policy with a post-reload forward overlay (which would
    // inject headers/raw_token using config the operator hadn't yet
    // associated with this policy).
    std::shared_ptr<const AppliedPolicyList> policies_snap;
    std::shared_ptr<const AuthForwardConfig> fwd_snap;
    {
        std::lock_guard<std::mutex> lk(snapshot_mtx_);
        policies_snap = policies_;
        fwd_snap = forward_;
    }
    if (!policies_snap || policies_snap->empty()) {
        sync_pass();
        return;
    }

    const AppliedPolicy* ap = FindPolicyForPath(*policies_snap, req.path);
    if (ap == nullptr || !ap->policy.enabled) {
        sync_pass();
        return;
    }
    const AuthPolicy& policy = ap->policy;
    const std::string realm = policy.realm.empty()
        ? std::string("api") : policy.realm;

    // Bearer extraction. The sync chain runs first, so a JWT-mode policy
    // would have either ALLOW'd (req.auth set) or DENY'd before we see it
    // — reaching here on a JWT-mode request means the sync path passed it
    // through (introspection-mode pass-through, or master_enabled toggled
    // mid-request). Either way, run the full extraction so the async path
    // is self-contained.
    std::string log_label;
    std::string token = ExtractBearerToken(req, log_label);
    if (token.empty()) {
        logging::Get()->info(
            "auth_deny reason={} route={} policy={}",
            log_label.empty() ? std::string("missing_authorization") : log_label,
            logging::SanitizePath(req.path),
            logging::SanitizeLogValue(policy.name));
        resp = MakeUnauthorized(realm, AuthErrorCode::InvalidRequest,
                                 "authorization required");
        RecordVerdict(resp, VerifyOutcome::DENY_401, std::string{},
                       policy.name, AuthCache::None);
        state->SetSyncResult(AsyncMiddlewareResult::DENY);
        state->MarkCompletedSync();
        return;
    }
    if (token.size() > kMaxBearerTokenBytes) {
        logging::Get()->info(
            "auth_deny reason=token_too_large route={} policy={}",
            logging::SanitizePath(req.path),
            logging::SanitizeLogValue(policy.name));
        resp = MakeUnauthorized(realm, AuthErrorCode::InvalidRequest,
                                 "token too large");
        RecordVerdict(resp, VerifyOutcome::DENY_401, std::string{},
                       policy.name, AuthCache::None);
        state->SetSyncResult(AsyncMiddlewareResult::DENY);
        state->MarkCompletedSync();
        return;
    }

    // Fast path: if no issuer in this policy uses introspection mode, skip
    // the async chain entirely and let the sync chain handle it.
    bool any_introspection = false;
    for (const auto& issuer_name : policy.issuers) {
        auto it = issuers_.find(issuer_name);
        if (it != issuers_.end() && it->second
                && it->second->mode() == kModeIntrospection) {
            any_introspection = true;
            break;
        }
    }
    if (!any_introspection) {
        sync_pass();
        return;
    }

    // Issuer selection mirrors the sync path: prefer `iss` peek, else fall
    // back to the first policy issuer. Pass through (no DENY) when no
    // issuer can be selected — the sync path will have produced a 503 /
    // pass-through already on a JWT-mode request, and an introspection-
    // mode request without a peekable issuer is rare (opaque tokens carry
    // no `iss`); for those we use the first policy issuer.
    Issuer* chosen = nullptr;
    auto peeked = JwtVerifier::PeekIssuer(token);
    if (peeked) {
        for (const auto& issuer_name : policy.issuers) {
            auto it = issuers_.find(issuer_name);
            if (it == issuers_.end() || !it->second) continue;
            if (it->second->issuer_url() == *peeked) {
                chosen = it->second.get();
                break;
            }
        }
        if (!chosen) {
            logging::Get()->info(
                "auth_deny reason=issuer_not_accepted route={} policy={}",
                logging::SanitizePath(req.path),
                logging::SanitizeLogValue(policy.name));
            resp = MakeUnauthorized(realm, AuthErrorCode::InvalidToken,
                                     "issuer not accepted");
            RecordVerdict(resp, VerifyOutcome::DENY_401, std::string{},
                           policy.name, AuthCache::None);
            state->SetSyncResult(AsyncMiddlewareResult::DENY);
            state->MarkCompletedSync();
            return;
        }
    } else if (!policy.issuers.empty()) {
        // Opaque token (no peekable `iss`) — must be an introspection
        // candidate. Walk policy.issuers in order, prefer the FIRST
        // introspection issuer that IS READY at dispatch time; if all
        // ready introspection issuers exhaust, fall through to the
        // not-ready branch below.
        //
        // Why ready-first vs literal first: in a multi-introspection
        // policy where issuer A is unhealthy (discovery still retrying)
        // but issuer B is up, the literal-first selection routes every
        // request to A and produces UNDETERMINED — even though B could
        // have served the token. Walking by IsReady at dispatch lets
        // operators add a redundant introspection issuer for failover
        // without losing the policy's first-issuer-preference for the
        // healthy steady state.
        //
        // KNOWN LIMITATION (documented in docs/oauth2.md): runtime
        // fan-out across the LIVE POST (issuer A says active=false for
        // a B-owned opaque token, or A's POST times out) is not
        // implemented. The first ready issuer's verdict is final for
        // that request; subsequent requests for the same token re-
        // evaluate after the negative cache TTL elapses
        // (`introspection.negative_cache_sec`, default 10s) and may
        // pick a different issuer if A then becomes not-ready. The
        // multi-introspection warning at config validation captures
        // the operator-visible cost.
        for (const auto& issuer_name : policy.issuers) {
            auto it = issuers_.find(issuer_name);
            if (it == issuers_.end() || !it->second) continue;
            if (it->second->mode() != kModeIntrospection) continue;
            if (!it->second->IsReady()) continue;
            chosen = it->second.get();
            break;
        }
        // Fallback: if no introspection issuer is ready, take the first
        // introspection issuer (ready or not) so the not-ready branch
        // below runs with a meaningful issuer for the
        // policy.on_undetermined / Retry-After computation.
        if (!chosen) {
            for (const auto& issuer_name : policy.issuers) {
                auto it = issuers_.find(issuer_name);
                if (it == issuers_.end() || !it->second) continue;
                if (it->second->mode() == kModeIntrospection) {
                    chosen = it->second.get();
                    break;
                }
            }
        }
        // Still nothing — no introspection issuer in the policy. Fall
        // back to the first entry. The mode-gate below converts this
        // to a sync_pass (JWT path owns the verdict on mixed-mode
        // policies with no introspection issuer eligible).
        if (!chosen) {
            auto it = issuers_.find(policy.issuers.front());
            if (it != issuers_.end()) chosen = it->second.get();
        }
    }
    if (!chosen) {
        // Shouldn't happen under a validated policy, but stay self-contained.
        sync_pass();
        return;
    }

    // JWT-mode policies were handled by the sync chain — pass through.
    if (chosen->mode() != kModeIntrospection) {
        sync_pass();
        return;
    }

    auto snap_issuer = chosen->LoadSnapshot();
    if (!chosen->IsReady() || !snap_issuer) {
        const int retry_after = snap_issuer
            ? snap_issuer->discovery_retry_sec : 30;
        logging::Get()->warn(
            "auth_undetermined route={} issuer={} reason=issuer_not_ready policy={}",
            logging::SanitizePath(req.path),
            logging::SanitizeLogValue(chosen->name()),
            logging::SanitizeLogValue(policy.name));
        if (policy.on_undetermined == kOnUndeterminedAllow) {
            AuthContext advisory;
            advisory.undetermined = true;
            advisory.policy_name = policy.name;
            advisory.issuer = chosen->name();
            req.auth.emplace(std::move(advisory));
            RecordVerdict(resp, VerifyOutcome::UNDETERMINED,
                           chosen->name(), policy.name, AuthCache::None);
            sync_pass();
            return;
        }
        resp = MakeServiceUnavailable(realm, retry_after,
                                        "authentication unavailable");
        RecordVerdict(resp, VerifyOutcome::UNDETERMINED, chosen->name(),
                       policy.name, AuthCache::None);
        state->SetSyncResult(AsyncMiddlewareResult::DENY);
        state->MarkCompletedSync();
        return;
    }

    // Locate the live shared_ptr so the deferred path can capture a
    // weak_ptr that survives reload-driven topology bumps cleanly.
    auto it = issuers_.find(chosen->name());
    if (it == issuers_.end() || !it->second) {
        // Topology changed between selection and dispatch — extremely rare.
        sync_pass();
        return;
    }
    InvokeAsyncIntrospection(it->second, *snap_issuer, policy, token,
                              req, resp, std::move(state),
                              std::move(fwd_snap));
}

namespace {

// TTL clamp: min(cache_sec, max(0, exp - now_seconds)). When `exp` is 0
// (introspection response had no `exp` field) the cache_sec value wins
// unmodified. Returns 0 (no insert) when both bounds collapse to zero.
std::chrono::seconds ClampPositiveTtl(int cache_sec,
                                       int64_t exp_seconds_since_epoch,
                                       std::chrono::system_clock::time_point now) {
    int ttl = cache_sec;
    if (exp_seconds_since_epoch > 0) {
        const int64_t now_secs =
            std::chrono::duration_cast<std::chrono::seconds>(
                now.time_since_epoch()).count();
        const int64_t remaining = exp_seconds_since_epoch - now_secs;
        if (remaining <= 0) return std::chrono::seconds{0};
        if (remaining < ttl) ttl = static_cast<int>(remaining);
    }
    if (ttl < 0) ttl = 0;
    return std::chrono::seconds{ttl};
}

// Inputs needed by the introspection completion callback. Built by both
// InvokeAsyncIntrospection (cached) and InvokeIntrospectionUncached
// (uncached). Behavioural differences between the two paths live in
// `enable_cache_ops`, `cache_key`, `cache` (and the optional
// `intro_stale_served` counter pointer).
//
// `manager` is non-owning — AuthManager outlives every in-flight
// transaction (Stop flips weak_issuer's underlying object first, so the
// closure short-circuits via the weak_issuer.lock() drop-guard before
// any manager-> call runs post-destruction). Used by the resume
// finalizers to drive RecordVerdict for total + per-policy + debug
// header emission.
struct IntrospectionDoneCtx {
    // Identity / suspend state
    std::shared_ptr<HttpRouter::AsyncPendingState> state;
    std::weak_ptr<Issuer> weak_issuer;
    uint64_t gen = 0;
    std::string token;

    // Per-request snapshot (immutable for the lifetime of the call)
    std::string sanitized_req_path;
    std::string realm;
    std::string issuer_name;
    std::string policy_name;
    std::string on_undetermined;
    std::vector<std::string> required_scopes;
    std::string raw_jwt_header;
    int retry_after_sec = 0;
    AuthPolicy policy;
    std::vector<std::string> snap_audiences;
    std::vector<std::string> snap_required_claims;

    // Introspection-specific counters. AuthManager-aggregate counters
    // (total_allowed / total_denied / total_undetermined) are bumped
    // inside RecordVerdict via the captured manager pointer.
    std::atomic<uint64_t>* intro_ok = nullptr;
    std::atomic<uint64_t>* intro_fail = nullptr;
    std::atomic<uint64_t>* intro_stale_served = nullptr;  // null on uncached path

    // Cache control
    bool enable_cache_ops = false;
    std::string cache_key;          // non-empty only when enable_cache_ops=true
    AuthCache cache = AuthCache::Miss;  // Miss (cached) or Uncached (uncached)

    AuthManager* manager = nullptr;
};

// Build the dispatcher-thread completion callback shared by the cached
// and uncached introspection paths. Behavior differences are encoded in
// IntrospectionDoneCtx (enable_cache_ops gates the cache-insert + stale-
// serve block; cache_log_label rides into the auth_allow debug log).
IntrospectionClient::DoneCallback MakeIntrospectionDoneCallback(
        IntrospectionDoneCtx c) {
    return [c = std::move(c)](IntrospectionClient::Result result) mutable {
        AsyncMiddlewarePayload payload;

        // Build an UNDETERMINED payload (used by drop guards AND by the
        // genuine UNDETERMINED outcome branch). intro_fail is incremented
        // at the cache-insert site for outcomes from a real IdP roundtrip;
        // drop-guard UNDETERMINED paths bypass the cache site by design and
        // intentionally do NOT count as introspection_fail — those are
        // issuer-state failures, not IdP failures.
        auto build_undetermined = [&](std::string log_reason) {
            if (c.on_undetermined == kOnUndeterminedAllow) {
                payload.result = AsyncMiddlewareResult::PASS;
                payload.finalizer =
                    [issuer_name = c.issuer_name,
                     policy_name = c.policy_name,
                     sanitized_req_path = c.sanitized_req_path,
                     log_reason,
                     manager = c.manager,
                     cache = c.cache]
                    (const HttpRequest& r, HttpResponse& rs) {
                    logging::Get()->warn(
                        "auth_undetermined route={} issuer={} reason={} policy={}",
                        sanitized_req_path,
                        logging::SanitizeLogValue(issuer_name),
                        log_reason,
                        logging::SanitizeLogValue(policy_name));
                    AuthContext advisory;
                    advisory.undetermined = true;
                    advisory.policy_name = policy_name;
                    advisory.issuer = issuer_name;
                    r.auth.emplace(std::move(advisory));
                    if (manager) {
                        manager->RecordVerdict(
                            rs, VerifyOutcome::UNDETERMINED,
                            issuer_name, policy_name, cache);
                    }
                };
            } else {
                payload.result = AsyncMiddlewareResult::DENY;
                payload.finalizer =
                    [realm = c.realm,
                     retry_after_sec = c.retry_after_sec,
                     issuer_name = c.issuer_name,
                     policy_name = c.policy_name,
                     sanitized_req_path = c.sanitized_req_path,
                     log_reason,
                     manager = c.manager,
                     cache = c.cache]
                    (const HttpRequest&, HttpResponse& rs) {
                    logging::Get()->warn(
                        "auth_undetermined route={} issuer={} reason={} policy={}",
                        sanitized_req_path,
                        logging::SanitizeLogValue(issuer_name),
                        log_reason,
                        logging::SanitizeLogValue(policy_name));
                    rs = MakeServiceUnavailable(
                        realm, retry_after_sec,
                        "authentication unavailable");
                    if (manager) {
                        manager->RecordVerdict(
                            rs, VerifyOutcome::UNDETERMINED,
                            issuer_name, policy_name, cache);
                    }
                };
            }
        };

        // Drop guards must STILL Complete — otherwise the suspended
        // request is orphaned and active_requests_ leaks until the
        // heartbeat safety-cap fires.
        auto issuer_strong = c.weak_issuer.lock();
        if (!issuer_strong) {
            build_undetermined("issuer_unavailable");
            c.state->Complete(std::move(payload));
            return;
        }
        if (c.gen != issuer_strong->generation()) {
            build_undetermined("reload_in_flight");
            c.state->Complete(std::move(payload));
            return;
        }
        if (issuer_strong->stopping()) {
            build_undetermined("issuer_stopping");
            c.state->Complete(std::move(payload));
            return;
        }

        // Cache-insert decision is gated on the explicit idp_active
        // flag set by ParseResponseSafe. Negative entries land ONLY
        // for explicit `active: false` responses — policy-scoped
        // denials (audience/scope/required_claims fail on
        // active: true) keep the positive entry so a different
        // policy may legitimately ALLOW the same token. Skipped
        // entirely on the uncached path.
        if (c.enable_cache_ops) {
            if (auto* cache = issuer_strong->introspection_cache()) {
                if (result.idp_active) {
                    auto snap_now = issuer_strong->LoadSnapshot();
                    if (snap_now) {
                        auto ttl = ClampPositiveTtl(
                            snap_now->introspection.cache_sec,
                            result.exp_from_resp,
                            std::chrono::system_clock::now());
                        if (ttl > std::chrono::seconds{0}) {
                            cache->Insert(c.cache_key, result.ctx,
                                          /*active=*/true, ttl);
                        }
                    }
                } else if (result.vr.outcome == VerifyOutcome::DENY_401 &&
                           result.vr.log_reason == "introspection_inactive") {
                    auto snap_now = issuer_strong->LoadSnapshot();
                    if (snap_now) {
                        cache->Insert(
                            c.cache_key, AuthContext{}, /*active=*/false,
                            std::chrono::seconds{
                                snap_now->introspection.negative_cache_sec});
                    }
                } else if (result.vr.outcome == VerifyOutcome::UNDETERMINED) {
                    // Live POST failed (timeout, circuit_open, 5xx, etc.) —
                    // last-resort stale-serve from a positive entry within
                    // grace, before producing the policy's UNDETERMINED
                    // response. NEVER stale-serves negative entries
                    // (LookupStale enforces that invariant). Re-run policy
                    // checks against the stale ctx so cross-policy reuse
                    // stays correct.
                    auto stale = cache->LookupStale(
                        c.cache_key, std::chrono::steady_clock::now());
                    if (stale.state == IntrospectionCache::LookupState::Stale
                            && stale.active) {
                        IssuerSnapshot snap_for_check;
                        snap_for_check.audiences = c.snap_audiences;
                        snap_for_check.required_claims = c.snap_required_claims;
                        VerifyResult vr_stale = RunPolicyAndIssuerClaimChecks(
                            c.policy, snap_for_check, stale.ctx);
                        if (vr_stale.outcome == VerifyOutcome::ALLOW) {
                            result.vr = VerifyResult::Allow();
                            result.ctx = std::move(stale.ctx);
                            if (c.intro_stale_served) {
                                c.intro_stale_served->fetch_add(
                                    1, std::memory_order_relaxed);
                            }
                        }
                    }
                }
            }
        }

        // Layer issuer-level audience fallback + required_claims on top
        // of IntrospectionClient's policy-only check. Cache write above
        // already used the un-overridden ctx so cross-policy reuse stays
        // intact — the override only affects THIS request's response.
        // Skips stale-promoted ctx (already policy-checked above).
        if (result.idp_active &&
            result.vr.outcome == VerifyOutcome::ALLOW) {
            IssuerSnapshot snap_for_check;
            snap_for_check.audiences = c.snap_audiences;
            snap_for_check.required_claims = c.snap_required_claims;
            VerifyResult vr_full = RunPolicyAndIssuerClaimChecks(
                c.policy, snap_for_check, result.ctx);
            if (vr_full.outcome != VerifyOutcome::ALLOW) {
                result.vr = std::move(vr_full);
            }
        }

        // IdP-outcome counters fire HERE — AFTER the issuer-level
        // re-check so the final result.vr.outcome is what gets counted.
        // Critically, this fires REGARDLESS of whether the resume_cb is
        // later armed; async-route warmup paths (which 503 the client
        // and never run the finalizer) still increment intro_ok /
        // intro_fail correctly. AuthManager-aggregate counters
        // (total_allowed / total_denied / total_undetermined) fire from
        // RecordVerdict inside the finalizer so they track CLIENT-VISIBLE
        // verdicts, not IdP-side raw outcomes.
        if (result.vr.outcome == VerifyOutcome::ALLOW) {
            c.intro_ok->fetch_add(1, std::memory_order_relaxed);
        } else {
            c.intro_fail->fetch_add(1, std::memory_order_relaxed);
        }

        switch (result.vr.outcome) {
          case VerifyOutcome::ALLOW: {
              payload.result = AsyncMiddlewareResult::PASS;
              AuthContext ctx = result.ctx;
              payload.finalizer =
                  [ctx = std::move(ctx),
                   issuer_name = c.issuer_name,
                   policy_name = c.policy_name,
                   sanitized_req_path = c.sanitized_req_path,
                   raw_jwt_header = c.raw_jwt_header,
                   token = c.token,
                   manager = c.manager,
                   cache = c.cache]
                  (const HttpRequest& r, HttpResponse& rs) {
                  AuthContext local_ctx = ctx;
                  local_ctx.policy_name = policy_name;
                  if (local_ctx.issuer.empty())
                      local_ctx.issuer = issuer_name;
                  if (!raw_jwt_header.empty()) {
                      local_ctx.raw_token = token;
                  }
                  r.auth.emplace(std::move(local_ctx));
                  if (manager) {
                      manager->RecordVerdict(rs, VerifyOutcome::ALLOW,
                                              issuer_name, policy_name, cache);
                  }
                  if (auto lg = logging::Get();
                          lg->should_log(spdlog::level::debug)) {
                      lg->debug(
                          "auth_allow route={} issuer={} sub={} policy={} cache={}",
                          sanitized_req_path,
                          logging::SanitizeLogValue(issuer_name),
                          logging::SanitizeLogValue(
                              r.auth ? r.auth->subject : std::string{}),
                          logging::SanitizeLogValue(policy_name),
                          CacheLabel(cache));
                  }
              };
              break;
          }
          case VerifyOutcome::DENY_401: {
              payload.result = AsyncMiddlewareResult::DENY;
              payload.finalizer =
                  [realm = c.realm,
                   ec = result.vr.error_code,
                   desc = result.vr.error_description,
                   log_reason = result.vr.log_reason,
                   issuer_name = c.issuer_name,
                   sanitized_req_path = c.sanitized_req_path,
                   policy_name = c.policy_name,
                   manager = c.manager,
                   cache = c.cache]
                  (const HttpRequest&, HttpResponse& rs) {
                  rs = MakeUnauthorized(realm, ec, desc);
                  if (manager) {
                      manager->RecordVerdict(rs, VerifyOutcome::DENY_401,
                                              issuer_name, policy_name, cache);
                  }
                  logging::Get()->info(
                      "auth_deny route={} issuer={} reason={} policy={}",
                      sanitized_req_path,
                      logging::SanitizeLogValue(issuer_name),
                      log_reason,
                      logging::SanitizeLogValue(policy_name));
              };
              break;
          }
          case VerifyOutcome::DENY_403: {
              payload.result = AsyncMiddlewareResult::DENY;
              payload.finalizer =
                  [realm = c.realm,
                   desc = result.vr.error_description,
                   scopes = c.required_scopes,
                   sanitized_req_path = c.sanitized_req_path,
                   issuer_name = c.issuer_name,
                   policy_name = c.policy_name,
                   log_reason = result.vr.log_reason,
                   manager = c.manager,
                   cache = c.cache]
                  (const HttpRequest&, HttpResponse& rs) {
                  rs = MakeForbidden(realm, desc, scopes);
                  if (manager) {
                      manager->RecordVerdict(rs, VerifyOutcome::DENY_403,
                                              issuer_name, policy_name, cache);
                  }
                  logging::Get()->info(
                      "auth_deny route={} issuer={} reason={} policy={}",
                      sanitized_req_path,
                      logging::SanitizeLogValue(issuer_name),
                      log_reason,
                      logging::SanitizeLogValue(policy_name));
              };
              break;
          }
          case VerifyOutcome::UNDETERMINED:
              build_undetermined(result.vr.log_reason);
              break;
        }
        c.state->Complete(std::move(payload));
    };
}

}  // namespace

void AuthManager::InvokeAsyncIntrospection(
        const std::shared_ptr<Issuer>& issuer,
        const IssuerSnapshot& snap,
        const AuthPolicy& policy,
        const std::string& token,
        const HttpRequest& req,
        HttpResponse& resp,
        std::shared_ptr<HttpRouter::AsyncPendingState> state,
        std::shared_ptr<const AuthForwardConfig> fwd_snap) {
    auto key_opt = hasher_.Hash(token);
    if (!key_opt) {
        // HMAC failure — extremely rare. Skip the cache; live POST.
        InvokeIntrospectionUncached(issuer, snap, policy, token,
                                     req, resp, std::move(state),
                                     std::move(fwd_snap));
        return;
    }
    const std::string key = *key_opt;

    auto* cache = issuer->introspection_cache();
    if (!cache) {
        // Issuer reports introspection mode but cache wasn't constructed.
        // Defence-in-depth: skip the cache layer rather than crash.
        InvokeIntrospectionUncached(issuer, snap, policy, token,
                                     req, resp, std::move(state),
                                     std::move(fwd_snap));
        return;
    }

    const std::string realm = policy.realm.empty()
        ? std::string("api") : policy.realm;
    const std::string issuer_name = issuer->name();
    const std::string raw_jwt_header =
        fwd_snap ? fwd_snap->raw_jwt_header : std::string{};

    auto now = std::chrono::steady_clock::now();
    auto hit = cache->Lookup(key, now);

    if (hit.state == IntrospectionCache::LookupState::Fresh && hit.active) {
        introspection_cache_hit_.fetch_add(1, std::memory_order_relaxed);
        // Re-run the per-request policy + issuer claim checks against the
        // cached ctx. The cache stores the IdP verdict (active=true) only;
        // the gateway's policy verdict is per-(token, route) and MUST be
        // recomputed on every hit so a positive entry cached under a
        // permissive policy can't grant access on a stricter policy.
        VerifyResult vr = RunPolicyAndIssuerClaimChecks(policy, snap, hit.ctx);
        if (vr.outcome == VerifyOutcome::DENY_401) {
            logging::Get()->info(
                "auth_deny route={} issuer={} reason={} policy={} cache=hit",
                logging::SanitizePath(req.path),
                logging::SanitizeLogValue(issuer_name),
                vr.log_reason,
                logging::SanitizeLogValue(policy.name));
            resp = MakeUnauthorized(realm, vr.error_code, vr.error_description);
            RecordVerdict(resp, VerifyOutcome::DENY_401, issuer_name,
                           policy.name, AuthCache::Hit);
            state->SetSyncResult(AsyncMiddlewareResult::DENY);
            state->MarkCompletedSync();
            return;
        }
        if (vr.outcome == VerifyOutcome::DENY_403) {
            logging::Get()->info(
                "auth_deny route={} issuer={} reason={} policy={} cache=hit",
                logging::SanitizePath(req.path),
                logging::SanitizeLogValue(issuer_name),
                vr.log_reason,
                logging::SanitizeLogValue(policy.name));
            resp = MakeForbidden(realm, vr.error_description,
                                  policy.required_scopes);
            RecordVerdict(resp, VerifyOutcome::DENY_403, issuer_name,
                           policy.name, AuthCache::Hit);
            state->SetSyncResult(AsyncMiddlewareResult::DENY);
            state->MarkCompletedSync();
            return;
        }
        StampAuthContext(req, std::move(hit.ctx), issuer_name, policy.name,
                          raw_jwt_header, token);
        RecordVerdict(resp, VerifyOutcome::ALLOW, issuer_name, policy.name,
                       AuthCache::Hit);
        if (auto lg = logging::Get();
                lg->should_log(spdlog::level::debug)) {
            lg->debug("auth_allow route={} issuer={} policy={} cache=hit",
                      logging::SanitizePath(req.path),
                      logging::SanitizeLogValue(issuer_name),
                      logging::SanitizeLogValue(policy.name));
        }
        state->SetSyncResult(AsyncMiddlewareResult::PASS);
        state->MarkCompletedSync();
        return;
    }
    if (hit.state == IntrospectionCache::LookupState::Fresh && !hit.active) {
        introspection_cache_negative_hit_.fetch_add(
            1, std::memory_order_relaxed);
        logging::Get()->info(
            "auth_deny route={} issuer={} reason=introspection_inactive policy={} cache=negative",
            logging::SanitizePath(req.path),
            logging::SanitizeLogValue(issuer_name),
            logging::SanitizeLogValue(policy.name));
        resp = MakeUnauthorized(realm, AuthErrorCode::InvalidToken,
                                 "token is not active");
        RecordVerdict(resp, VerifyOutcome::DENY_401, issuer_name,
                       policy.name, AuthCache::Negative);
        state->SetSyncResult(AsyncMiddlewareResult::DENY);
        state->MarkCompletedSync();
        return;
    }

    // Stale-serve is NOT short-circuited pre-POST: an unconditional pre-POST
    // serve would widen revocation latency by up to stale_grace_sec even
    // when the IdP is healthy. Instead, every cache miss fires the live
    // POST; the upstream's circuit breaker short-circuits to UNDETERMINED
    // when the IdP is sick (returns `error=circuit_open` without an HTTP
    // round-trip), and the resume closure's UNDETERMINED branch falls back
    // to LookupStale below. Net behavior matches the design intent ("skip
    // the POST when known-degraded; serve fresh otherwise") without giving
    // the auth subsystem direct visibility into CircuitBreakerManager.
    introspection_cache_miss_.fetch_add(1, std::memory_order_relaxed);

    // Snapshot every field the deferred completion may read INTO BY-VALUE
    // LOCALS. After this function returns, `req`, `snap`, `issuer` (the
    // shared_ptr argument) all go out of scope; the closure must NOT
    // reference them.
    const std::string sanitized_req_path = logging::SanitizePath(req.path);
    const int retry_after_sec = snap.introspection.timeout_sec;
    const std::string realm_local = realm;
    const std::string policy_name = policy.name;
    const auto on_undet = policy.on_undetermined;
    const auto required_scopes = policy.required_scopes;
    const uint64_t gen = issuer->generation();
    AuthPolicy policy_copy = policy;
    // Copy the pre-built claim_keys snapshot, then UNION-IN every issuer
    // required_claim name so PopulateFromPayload copies them into ctx.claims
    // — making cache-hit RunPolicyAndIssuerClaimChecks able to verify
    // presence without re-parsing the body. Linear de-dup: required_claims
    // is typically <5 entries.
    std::vector<std::string> claim_keys;
    if (fwd_snap) {
        claim_keys = fwd_snap->claim_keys;
    }
    for (const auto& rc : snap.required_claims) {
        bool present = false;
        for (const auto& k : claim_keys) {
            if (k == rc) { present = true; break; }
        }
        if (!present) claim_keys.push_back(rc);
    }
    // Capture issuer-level audiences + required_claims into the closure so
    // the post-parse re-check can enforce them (introspection_client.cc only
    // checks policy.required_audience and policy.required_scopes; issuer
    // fallback + required_claims are policy concerns layered here).
    const std::vector<std::string> snap_audiences = snap.audiences;
    const std::vector<std::string> snap_required_claims = snap.required_claims;
    if (req.dispatcher_index < 0) {
        logging::Get()->error(
            "InvokeAsyncIntrospection: req.dispatcher_index unset "
            "(request bypassed transport-layer wiring)");
        AsyncMiddlewarePayload payload;
        payload.result = AsyncMiddlewareResult::DENY;
        payload.finalizer = [retry_after_sec, realm](
                const HttpRequest&, HttpResponse& rs) {
            rs = MakeServiceUnavailable(realm, retry_after_sec,
                                         "authentication unavailable");
        };
        total_undetermined_.fetch_add(1, std::memory_order_relaxed);
        state->Complete(std::move(payload));
        return;
    }
    const size_t dispatcher_idx = static_cast<size_t>(req.dispatcher_index);

    std::weak_ptr<Issuer> weak_issuer = issuer;

    // Cancel hook: flip the atomic; UpstreamHttpClient observes it on its
    // next dispatcher tick and short-circuits queued waiters.
    auto cancel_token = std::make_shared<std::atomic<bool>>(false);
    state->SetCancelCb([cancel_token]() {
        cancel_token->store(true, std::memory_order_release);
    });

    // Pointers to atomic counters survive AuthManager destruction only when
    // AuthManager outlives every in-flight transaction. AuthManager::Stop
    // drives Issuer::Stop which flips cancel_token, so the closure's
    // weak_issuer.lock() returns null before any counter increment runs
    // post-destruction. The pointers are safe under that ordering.
    auto* intro_ok_ptr = &introspection_ok_;
    auto* intro_fail_ptr = &introspection_fail_;
    auto* intro_stale_ptr = &introspection_stale_served_;

    // Bind each Verify() argument to a named local so the call site
    // matches the header's parameter list one-line-per-parameter.
    const std::string& endpoint      = snap.introspection_endpoint;
    const std::string& client_id     = snap.introspection.client_id;
    const std::string  client_secret = issuer->client_secret();
    const std::string& auth_style    = snap.introspection.auth_style;

    // Build the introspection completion callback via the shared factory
    // (cached path: enable_cache_ops=true, cache_log_label="miss",
    // intro_stale_served counter wired in for stale-serve).
    IntrospectionDoneCtx done_ctx;
    done_ctx.state                = state;
    done_ctx.weak_issuer          = weak_issuer;
    done_ctx.gen                  = gen;
    done_ctx.token                = token;
    done_ctx.sanitized_req_path   = sanitized_req_path;
    done_ctx.realm                = realm_local;
    done_ctx.issuer_name          = issuer_name;
    done_ctx.policy_name          = policy_name;
    done_ctx.on_undetermined      = on_undet;
    done_ctx.required_scopes      = required_scopes;
    done_ctx.raw_jwt_header       = raw_jwt_header;
    done_ctx.retry_after_sec      = retry_after_sec;
    done_ctx.policy               = policy_copy;
    done_ctx.snap_audiences       = snap_audiences;
    done_ctx.snap_required_claims = snap_required_claims;
    done_ctx.intro_ok             = intro_ok_ptr;
    done_ctx.intro_fail           = intro_fail_ptr;
    done_ctx.intro_stale_served   = intro_stale_ptr;
    done_ctx.enable_cache_ops     = true;
    done_ctx.cache_key            = key;
    done_ctx.cache                = AuthCache::Miss;
    done_ctx.manager              = this;
    IntrospectionClient::DoneCallback on_verify_done =
        MakeIntrospectionDoneCallback(std::move(done_ctx));

    introspection_client_->Verify(
        weak_issuer,
        endpoint,
        client_id,
        client_secret,
        auth_style,
        token,
        dispatcher_idx,
        policy_copy,
        claim_keys,
        gen,
        std::move(on_verify_done),
        cancel_token);
}

void AuthManager::InvokeIntrospectionUncached(
        const std::shared_ptr<Issuer>& issuer,
        const IssuerSnapshot& snap,
        const AuthPolicy& policy,
        const std::string& token,
        const HttpRequest& req,
        HttpResponse& resp,
        std::shared_ptr<HttpRouter::AsyncPendingState> state,
        std::shared_ptr<const AuthForwardConfig> fwd_snap) {
    (void)resp;
    introspection_cache_miss_.fetch_add(1, std::memory_order_relaxed);

    const std::string sanitized_req_path = logging::SanitizePath(req.path);
    const int retry_after_sec = snap.introspection.timeout_sec;
    const std::string realm_local = policy.realm.empty()
        ? std::string("api") : policy.realm;
    const std::string issuer_name = issuer->name();
    const std::string policy_name = policy.name;
    const auto on_undet = policy.on_undetermined;
    const auto required_scopes = policy.required_scopes;
    const uint64_t gen = issuer->generation();
    AuthPolicy policy_copy = policy;
    const std::string raw_jwt_header =
        fwd_snap ? fwd_snap->raw_jwt_header : std::string{};
    std::vector<std::string> claim_keys;
    if (fwd_snap) {
        claim_keys = fwd_snap->claim_keys;
    }
    // Augment with required_claim names so PopulateFromPayload copies them
    // into ctx.claims (mirrors the InvokeAsyncIntrospection path — required
    // for parity even though this entry has no cache lookup, since the cb
    // runs the same RunPolicyAndIssuerClaimChecks layered re-check below).
    for (const auto& rc : snap.required_claims) {
        bool present = false;
        for (const auto& k : claim_keys) {
            if (k == rc) { present = true; break; }
        }
        if (!present) claim_keys.push_back(rc);
    }
    const std::vector<std::string> snap_audiences = snap.audiences;
    const std::vector<std::string> snap_required_claims = snap.required_claims;
    if (req.dispatcher_index < 0) {
        logging::Get()->error(
            "InvokeIntrospectionUncached: req.dispatcher_index unset "
            "(request bypassed transport-layer wiring)");
        AsyncMiddlewarePayload payload;
        payload.result = AsyncMiddlewareResult::DENY;
        payload.finalizer = [retry_after_sec, realm_local](
                const HttpRequest&, HttpResponse& rs) {
            rs = MakeServiceUnavailable(realm_local, retry_after_sec,
                                         "authentication unavailable");
        };
        total_undetermined_.fetch_add(1, std::memory_order_relaxed);
        state->Complete(std::move(payload));
        return;
    }
    const size_t dispatcher_idx = static_cast<size_t>(req.dispatcher_index);

    std::weak_ptr<Issuer> weak_issuer = issuer;

    auto cancel_token = std::make_shared<std::atomic<bool>>(false);
    state->SetCancelCb([cancel_token]() {
        cancel_token->store(true, std::memory_order_release);
    });

    auto* intro_ok_ptr = &introspection_ok_;
    auto* intro_fail_ptr = &introspection_fail_;

    // Bind each Verify() argument to a named local so the call site
    // matches the header's parameter list one-line-per-parameter.
    const std::string& endpoint      = snap.introspection_endpoint;
    const std::string& client_id     = snap.introspection.client_id;
    const std::string  client_secret = issuer->client_secret();
    const std::string& auth_style    = snap.introspection.auth_style;

    // Build the introspection completion callback via the shared factory
    // (uncached path: enable_cache_ops=false, cache_log_label="uncached",
    // intro_stale_served pointer left null — no cache → no stale-serve).
    IntrospectionDoneCtx done_ctx;
    done_ctx.state                = state;
    done_ctx.weak_issuer          = weak_issuer;
    done_ctx.gen                  = gen;
    done_ctx.token                = token;
    done_ctx.sanitized_req_path   = sanitized_req_path;
    done_ctx.realm                = realm_local;
    done_ctx.issuer_name          = issuer_name;
    done_ctx.policy_name          = policy_name;
    done_ctx.on_undetermined      = on_undet;
    done_ctx.required_scopes      = required_scopes;
    done_ctx.raw_jwt_header       = raw_jwt_header;
    done_ctx.retry_after_sec      = retry_after_sec;
    done_ctx.policy               = policy_copy;
    done_ctx.snap_audiences       = snap_audiences;
    done_ctx.snap_required_claims = snap_required_claims;
    done_ctx.intro_ok             = intro_ok_ptr;
    done_ctx.intro_fail           = intro_fail_ptr;
    done_ctx.intro_stale_served   = nullptr;
    done_ctx.enable_cache_ops     = false;
    done_ctx.cache                = AuthCache::Uncached;
    done_ctx.manager              = this;
    IntrospectionClient::DoneCallback on_verify_done =
        MakeIntrospectionDoneCallback(std::move(done_ctx));

    introspection_client_->Verify(
        weak_issuer,
        endpoint,
        client_id,
        client_secret,
        auth_style,
        token,
        dispatcher_idx,
        policy_copy,
        claim_keys,
        gen,
        std::move(on_verify_done),
        cancel_token);
}

}  // namespace AUTH_NAMESPACE
