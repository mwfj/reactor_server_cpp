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

// Re-run policy + issuer claim checks against an already-populated
// AuthContext. Used by:
//   - cache hit / stale-hit paths in InvokeAsyncIntrospection (no body
//     available; required_claim presence falls back to ctx.claims —
//     string-typed required claims work, array/object-typed are skipped
//     because PopulateFromPayload only flattens scalars into ctx.claims).
//   - IntrospectionClient post-parse path (body available — the live
//     POST result still goes through this same helper for symmetry,
//     after PopulateFromPayload has copied required_claim names into
//     ctx.claims via the augmented claim_keys list).
//
// Audience: policy.required_audience overrides; otherwise issuer
// snap.audiences fallback (any-match). Empty on both sides → accept.
//
// Required claims: presence-only check against ctx.claims keys (matches
// JWT-mode semantics — JwtVerifier checks payload.contains(c)). Cache
// hits can only verify presence for scalar-typed claims; document the
// limitation in docs/oauth2.md.
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
        if (ctx.claims.find(c) == ctx.claims.end()) {
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

}  // namespace

AuthManager::AuthManager(const AuthConfig& config,
                          UpstreamManager* upstream_manager,
                          std::vector<std::shared_ptr<Dispatcher>> dispatchers)
    : upstream_manager_(upstream_manager),
      dispatchers_(std::move(dispatchers)) {
    // Master switch — mirrored from AuthConfig::enabled and live-reloadable.
    master_enabled_.store(config.enabled, std::memory_order_release);
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
            upstream_http_client_, hmac_key_);
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

void AuthManager::Stop() {
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

bool AuthManager::Reload(const AuthConfig& new_config, std::string& err_out) {
    std::lock_guard<std::mutex> reload_lock(reload_mtx_);

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
        bool new_master_enabled) {
    auto rebuilt = BuildAppliedPolicyList(new_upstreams,
                                            new_top_level_policies);
    AuthForwardConfig fwd_copy = new_forward;
    fwd_copy.PopulateDerived();
    auto fwd_snap = std::make_shared<const AuthForwardConfig>(std::move(fwd_copy));
    // Single atomic cutover under snapshot_mtx_:
    //   1. forward_ swap
    //   2. policies_ swap
    //   3. master_enabled_ release-store (final publication edge)
    // A reader observing master_enabled_=true sees fresh forward_ and
    // policies_ pointers via the lock-mutex acquire ordering. Forward is
    // grouped here (not in Reload) so a TRUE→TRUE reload combining a
    // forward overlay edit with a policy edit can't expose the window
    // where ProxyTransaction reads new forward_ while the matcher is
    // still on the old policy list.
    {
        std::lock_guard<std::mutex> lk(snapshot_mtx_);
        forward_ = std::move(fwd_snap);
        policies_ = rebuilt;
        master_enabled_.store(new_master_enabled,
                               std::memory_order_release);
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
        total_denied_.fetch_add(1, std::memory_order_relaxed);
        logging::Get()->info(
            "auth_deny reason={} route={} policy={}",
            log_label.empty() ? std::string("missing_authorization") : log_label,
            logging::SanitizePath(req.path), policy.name);
        resp = MakeUnauthorized(realm, AuthErrorCode::InvalidRequest,
                                 "authorization required");
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
            total_denied_.fetch_add(1, std::memory_order_relaxed);
            logging::Get()->info(
                "auth_deny reason=issuer_not_accepted route={} policy={}",
                logging::SanitizePath(req.path), policy.name);
            resp = MakeUnauthorized(realm, AuthErrorCode::InvalidToken,
                                     "issuer not accepted");
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
        total_undetermined_.fetch_add(1, std::memory_order_relaxed);
        if (policy.on_undetermined == "allow") {
            AuthContext ctx;
            ctx.undetermined = true;
            ctx.policy_name = policy.name;
            req.auth.emplace(std::move(ctx));
            return true;
        }
        resp = MakeServiceUnavailable(realm, 5,
                                        "authentication unavailable");
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
            total_allowed_.fetch_add(1, std::memory_order_relaxed);
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
            total_denied_.fetch_add(1, std::memory_order_relaxed);
            logging::Get()->info(
                "auth_deny route={} issuer={} reason={} policy={}",
                logging::SanitizePath(req.path),
                logging::SanitizeLogValue(chosen->name()),
                vr.log_reason,
                logging::SanitizeLogValue(policy.name));
            resp = MakeUnauthorized(realm, vr.error_code,
                                     vr.error_description);
            return false;
        }
        case VerifyOutcome::DENY_403: {
            total_denied_.fetch_add(1, std::memory_order_relaxed);
            logging::Get()->info(
                "auth_deny route={} issuer={} reason={} policy={}",
                logging::SanitizePath(req.path),
                logging::SanitizeLogValue(chosen->name()),
                vr.log_reason,
                logging::SanitizeLogValue(policy.name));
            resp = MakeForbidden(realm, vr.error_description,
                                  policy.required_scopes);
            return false;
        }
        case VerifyOutcome::UNDETERMINED: {
            total_undetermined_.fetch_add(1, std::memory_order_relaxed);
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
                return true;
            }
            resp = MakeServiceUnavailable(realm, vr.retry_after_sec,
                                            "authentication unavailable");
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

namespace {

// Outbound 8 KiB cap on bearer-token bytes. Larger tokens are unconditionally
// 401'd before any cache lookup or upstream POST — they are almost always
// either malformed or attacker-shaped.
constexpr size_t kMaxBearerTokenBytes = 8192;

}  // namespace

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

    std::shared_ptr<const AppliedPolicyList> policies_snap;
    {
        std::lock_guard<std::mutex> lk(snapshot_mtx_);
        policies_snap = policies_;
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
        total_denied_.fetch_add(1, std::memory_order_relaxed);
        logging::Get()->info(
            "auth_deny reason={} route={} policy={}",
            log_label.empty() ? std::string("missing_authorization") : log_label,
            logging::SanitizePath(req.path),
            logging::SanitizeLogValue(policy.name));
        resp = MakeUnauthorized(realm, AuthErrorCode::InvalidRequest,
                                 "authorization required");
        state->SetSyncResult(AsyncMiddlewareResult::DENY);
        state->MarkCompletedSync();
        return;
    }
    if (token.size() > kMaxBearerTokenBytes) {
        total_denied_.fetch_add(1, std::memory_order_relaxed);
        logging::Get()->info(
            "auth_deny reason=token_too_large route={} policy={}",
            logging::SanitizePath(req.path),
            logging::SanitizeLogValue(policy.name));
        resp = MakeUnauthorized(realm, AuthErrorCode::InvalidRequest,
                                 "token too large");
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
            total_denied_.fetch_add(1, std::memory_order_relaxed);
            logging::Get()->info(
                "auth_deny reason=issuer_not_accepted route={} policy={}",
                logging::SanitizePath(req.path),
                logging::SanitizeLogValue(policy.name));
            resp = MakeUnauthorized(realm, AuthErrorCode::InvalidToken,
                                     "issuer not accepted");
            state->SetSyncResult(AsyncMiddlewareResult::DENY);
            state->MarkCompletedSync();
            return;
        }
    } else if (!policy.issuers.empty()) {
        // Opaque token (no peekable `iss`) — must be an introspection
        // candidate. Prefer the FIRST introspection-mode issuer in
        // policy.issuers order; falling back to policy.issuers.front()
        // would route opaque tokens to a JWT-mode issuer in mixed-mode
        // policies (which then deny because the JWT path can't decode
        // them). The sync chain already returned PASS for this request
        // because the JWT path treats undecodable tokens as not-its-job;
        // the async chain MUST pick an introspection issuer so the IdP
        // gets the chance to validate.
        for (const auto& issuer_name : policy.issuers) {
            auto it = issuers_.find(issuer_name);
            if (it == issuers_.end() || !it->second) continue;
            if (it->second->mode() == kModeIntrospection) {
                chosen = it->second.get();
                break;
            }
        }
        // No introspection issuer in the policy — fall back to the first
        // entry. The mode-gate below converts this to a sync_pass (JWT
        // path owns the verdict on mixed-mode policies with no
        // introspection issuer eligible).
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
        total_undetermined_.fetch_add(1, std::memory_order_relaxed);
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
            sync_pass();
            return;
        }
        resp = MakeServiceUnavailable(realm, retry_after,
                                        "authentication unavailable");
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
                              req, resp, std::move(state));
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

}  // namespace

void AuthManager::InvokeAsyncIntrospection(
        const std::shared_ptr<Issuer>& issuer,
        const IssuerSnapshot& snap,
        const AuthPolicy& policy,
        const std::string& token,
        const HttpRequest& req,
        HttpResponse& resp,
        std::shared_ptr<HttpRouter::AsyncPendingState> state) {
    auto key_opt = hasher_.Hash(token);
    if (!key_opt) {
        // HMAC failure — extremely rare. Skip the cache; live POST.
        InvokeIntrospectionUncached(issuer, snap, policy, token,
                                     req, resp, std::move(state));
        return;
    }
    const std::string key = *key_opt;

    auto* cache = issuer->introspection_cache();
    if (!cache) {
        // Issuer reports introspection mode but cache wasn't constructed.
        // Defence-in-depth: skip the cache layer rather than crash.
        InvokeIntrospectionUncached(issuer, snap, policy, token,
                                     req, resp, std::move(state));
        return;
    }

    const std::string realm = policy.realm.empty()
        ? std::string("api") : policy.realm;
    const std::string issuer_name = issuer->name();
    auto fwd_snap = ForwardConfig();
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
            total_denied_.fetch_add(1, std::memory_order_relaxed);
            logging::Get()->info(
                "auth_deny route={} issuer={} reason={} policy={} cache=hit",
                logging::SanitizePath(req.path),
                logging::SanitizeLogValue(issuer_name),
                vr.log_reason,
                logging::SanitizeLogValue(policy.name));
            resp = MakeUnauthorized(realm, vr.error_code, vr.error_description);
            state->SetSyncResult(AsyncMiddlewareResult::DENY);
            state->MarkCompletedSync();
            return;
        }
        if (vr.outcome == VerifyOutcome::DENY_403) {
            total_denied_.fetch_add(1, std::memory_order_relaxed);
            logging::Get()->info(
                "auth_deny route={} issuer={} reason={} policy={} cache=hit",
                logging::SanitizePath(req.path),
                logging::SanitizeLogValue(issuer_name),
                vr.log_reason,
                logging::SanitizeLogValue(policy.name));
            resp = MakeForbidden(realm, vr.error_description,
                                  policy.required_scopes);
            state->SetSyncResult(AsyncMiddlewareResult::DENY);
            state->MarkCompletedSync();
            return;
        }
        StampAuthContext(req, std::move(hit.ctx), issuer_name, policy.name,
                          raw_jwt_header, token);
        total_allowed_.fetch_add(1, std::memory_order_relaxed);
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
        total_denied_.fetch_add(1, std::memory_order_relaxed);
        logging::Get()->info(
            "auth_deny route={} issuer={} reason=introspection_inactive policy={} cache=negative",
            logging::SanitizePath(req.path),
            logging::SanitizeLogValue(issuer_name),
            logging::SanitizeLogValue(policy.name));
        resp = MakeUnauthorized(realm, AuthErrorCode::InvalidToken,
                                 "token is not active");
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
    auto* total_undet_ptr = &total_undetermined_;
    auto* total_allow_ptr = &total_allowed_;
    auto* total_deny_ptr = &total_denied_;
    auto* intro_ok_ptr = &introspection_ok_;
    auto* intro_fail_ptr = &introspection_fail_;
    auto* intro_stale_ptr = &introspection_stale_served_;

    introspection_client_->Verify(
        weak_issuer, snap.introspection_endpoint,
        snap.introspection.client_id, issuer->client_secret(),
        snap.introspection.auth_style, token, dispatcher_idx,
        policy_copy, claim_keys, gen,
        [state, weak_issuer, gen, key, realm_local, issuer_name,
         sanitized_req_path, policy_name, on_undet, required_scopes,
         raw_jwt_header, retry_after_sec, token,
         total_undet_ptr, total_allow_ptr, total_deny_ptr,
         intro_ok_ptr, intro_fail_ptr, intro_stale_ptr,
         policy_copy, snap_audiences, snap_required_claims]
        (IntrospectionClient::Result result) {
            AsyncMiddlewarePayload payload;

            // Build an UNDETERMINED payload (used by drop guards AND by
            // the genuine UNDETERMINED outcome branch). Mirrors the JWT
            // UNDETERMINED observability: increment total_undetermined_,
            // emit auth_undetermined warn log, on `allow` stamp advisory
            // ctx with policy_name + issuer.
            auto build_undetermined = [&](std::string log_reason) {
                if (on_undet == kOnUndeterminedAllow) {
                    payload.result = AsyncMiddlewareResult::PASS;
                    payload.finalizer =
                        [issuer_name, policy_name, sanitized_req_path,
                         log_reason, total_undet_ptr]
                        (const HttpRequest& r, HttpResponse&) {
                        // intro_fail_ptr is incremented at the cache-
                        // insert site for outcomes from a real IdP
                        // roundtrip; drop-guard UNDETERMINED paths
                        // (issuer_unavailable / reload_in_flight /
                        // issuer_stopping) bypass the cache site by
                        // design and intentionally do NOT count as
                        // introspection_fail — those are issuer-state
                        // failures, not IdP failures.
                        total_undet_ptr->fetch_add(
                            1, std::memory_order_relaxed);
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
                    };
                } else {
                    payload.result = AsyncMiddlewareResult::DENY;
                    payload.finalizer =
                        [realm_local, retry_after_sec, issuer_name,
                         policy_name, sanitized_req_path, log_reason,
                         total_undet_ptr]
                        (const HttpRequest&, HttpResponse& rs) {
                        total_undet_ptr->fetch_add(
                            1, std::memory_order_relaxed);
                        logging::Get()->warn(
                            "auth_undetermined route={} issuer={} reason={} policy={}",
                            sanitized_req_path,
                            logging::SanitizeLogValue(issuer_name),
                            log_reason,
                            logging::SanitizeLogValue(policy_name));
                        rs = MakeServiceUnavailable(
                            realm_local, retry_after_sec,
                            "authentication unavailable");
                    };
                }
            };

            // Drop guards must STILL Complete — otherwise the suspended
            // request is orphaned and active_requests_ leaks until the
            // heartbeat safety-cap fires.
            auto issuer_strong = weak_issuer.lock();
            if (!issuer_strong) {
                build_undetermined("issuer_unavailable");
                state->Complete(std::move(payload));
                return;
            }
            if (gen != issuer_strong->generation()) {
                build_undetermined("reload_in_flight");
                state->Complete(std::move(payload));
                return;
            }
            if (issuer_strong->stopping()) {
                build_undetermined("issuer_stopping");
                state->Complete(std::move(payload));
                return;
            }

            // Cache-insert decision is gated on the explicit idp_active
            // flag set by ParseResponseSafe. Negative entries land ONLY
            // for explicit `active: false` responses — policy-scoped
            // denials (audience/scope/required_claims fail on
            // active: true) keep the positive entry so a different
            // policy may legitimately ALLOW the same token.
            if (auto* cache = issuer_strong->introspection_cache()) {
                if (result.idp_active) {
                    auto snap_now = issuer_strong->LoadSnapshot();
                    if (snap_now) {
                        auto ttl = ClampPositiveTtl(
                            snap_now->introspection.cache_sec,
                            result.exp_from_resp,
                            std::chrono::system_clock::now());
                        if (ttl > std::chrono::seconds{0}) {
                            cache->Insert(key, result.ctx,
                                          /*active=*/true, ttl);
                        }
                    }
                } else if (result.vr.outcome == VerifyOutcome::DENY_401 &&
                           result.vr.log_reason == "introspection_inactive") {
                    auto snap_now = issuer_strong->LoadSnapshot();
                    if (snap_now) {
                        cache->Insert(
                            key, AuthContext{}, /*active=*/false,
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
                        key, std::chrono::steady_clock::now());
                    if (stale.state == IntrospectionCache::LookupState::Stale
                            && stale.active) {
                        IssuerSnapshot snap_for_check;
                        snap_for_check.audiences = snap_audiences;
                        snap_for_check.required_claims = snap_required_claims;
                        VerifyResult vr_stale = RunPolicyAndIssuerClaimChecks(
                            policy_copy, snap_for_check, stale.ctx);
                        if (vr_stale.outcome == VerifyOutcome::ALLOW) {
                            result.vr = VerifyResult::Allow();
                            result.ctx = std::move(stale.ctx);
                            intro_stale_ptr->fetch_add(
                                1, std::memory_order_relaxed);
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
                snap_for_check.audiences = snap_audiences;
                snap_for_check.required_claims = snap_required_claims;
                VerifyResult vr_full = RunPolicyAndIssuerClaimChecks(
                    policy_copy, snap_for_check, result.ctx);
                if (vr_full.outcome != VerifyOutcome::ALLOW) {
                    result.vr = std::move(vr_full);
                }
            }

            // IdP-outcome counters fire HERE — AFTER the issuer-level
            // re-check so the final result.vr.outcome is what gets
            // counted. Critically, this fires REGARDLESS of whether the
            // resume_cb is later armed; async-route warmup paths (which
            // 503 the client and never run the finalizer) still increment
            // intro_ok / intro_fail correctly. total_allowed_ /
            // total_denied_ stay in the finalizer because those track
            // CLIENT-VISIBLE verdicts (warmup is 503, not allow/deny).
            //
            // Semantics: intro_ok = final ALLOW; intro_fail = everything
            // else (active:false → DENY_401, policy-scoped DENY_401/403,
            // UNDETERMINED, malformed, 4xx/5xx, timeouts, circuit-open).
            // Drop guards (issuer_unavailable / reload_in_flight /
            // issuer_stopping) skip this site by their early return and
            // intentionally do NOT count as intro_fail — those are
            // issuer-state failures, not IdP failures.
            if (result.vr.outcome == VerifyOutcome::ALLOW) {
                intro_ok_ptr->fetch_add(1, std::memory_order_relaxed);
            } else {
                intro_fail_ptr->fetch_add(1, std::memory_order_relaxed);
            }

            switch (result.vr.outcome) {
              case VerifyOutcome::ALLOW: {
                  payload.result = AsyncMiddlewareResult::PASS;
                  AuthContext ctx = result.ctx;
                  payload.finalizer =
                      [ctx = std::move(ctx), issuer_name, policy_name,
                       sanitized_req_path, raw_jwt_header, token,
                       total_allow_ptr]
                      (const HttpRequest& r, HttpResponse&) {
                      // intro_ok_ptr already incremented at the post-
                      // re-check site above so warmup paths still count.
                      AuthContext local_ctx = ctx;
                      local_ctx.policy_name = policy_name;
                      if (local_ctx.issuer.empty())
                          local_ctx.issuer = issuer_name;
                      if (!raw_jwt_header.empty()) {
                          local_ctx.raw_token = token;
                      }
                      r.auth.emplace(std::move(local_ctx));
                      total_allow_ptr->fetch_add(
                          1, std::memory_order_relaxed);
                      if (auto lg = logging::Get();
                              lg->should_log(spdlog::level::debug)) {
                          lg->debug(
                              "auth_allow route={} issuer={} sub={} policy={} cache=miss",
                              sanitized_req_path,
                              logging::SanitizeLogValue(issuer_name),
                              logging::SanitizeLogValue(
                                  r.auth ? r.auth->subject : std::string{}),
                              logging::SanitizeLogValue(policy_name));
                      }
                  };
                  break;
              }
              case VerifyOutcome::DENY_401: {
                  payload.result = AsyncMiddlewareResult::DENY;
                  payload.finalizer =
                      [realm_local, ec = result.vr.error_code,
                       desc = result.vr.error_description,
                       log_reason = result.vr.log_reason, issuer_name,
                       sanitized_req_path, policy_name,
                       total_deny_ptr]
                      (const HttpRequest&, HttpResponse& rs) {
                      // intro_ok_ptr / intro_fail_ptr already incremented
                      // at the cache-insert site above based on idp_active.
                      rs = MakeUnauthorized(realm_local, ec, desc);
                      total_deny_ptr->fetch_add(
                          1, std::memory_order_relaxed);
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
                      [realm_local, desc = result.vr.error_description,
                       scopes = required_scopes, sanitized_req_path,
                       issuer_name, policy_name,
                       log_reason = result.vr.log_reason,
                       total_deny_ptr]
                      (const HttpRequest&, HttpResponse& rs) {
                      // intro_ok_ptr already incremented at the cache-
                      // insert site above (DENY_403 implies idp_active).
                      rs = MakeForbidden(realm_local, desc, scopes);
                      total_deny_ptr->fetch_add(
                          1, std::memory_order_relaxed);
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
            state->Complete(std::move(payload));
        },
        cancel_token);
}

void AuthManager::InvokeIntrospectionUncached(
        const std::shared_ptr<Issuer>& issuer,
        const IssuerSnapshot& snap,
        const AuthPolicy& policy,
        const std::string& token,
        const HttpRequest& req,
        HttpResponse& resp,
        std::shared_ptr<HttpRouter::AsyncPendingState> state) {
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
    auto fwd_snap = ForwardConfig();
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

    auto* total_undet_ptr = &total_undetermined_;
    auto* total_allow_ptr = &total_allowed_;
    auto* total_deny_ptr = &total_denied_;
    auto* intro_ok_ptr = &introspection_ok_;
    auto* intro_fail_ptr = &introspection_fail_;

    introspection_client_->Verify(
        weak_issuer, snap.introspection_endpoint,
        snap.introspection.client_id, issuer->client_secret(),
        snap.introspection.auth_style, token, dispatcher_idx,
        policy_copy, claim_keys, gen,
        [state, weak_issuer, gen, realm_local, issuer_name,
         sanitized_req_path, policy_name, on_undet, required_scopes,
         raw_jwt_header, retry_after_sec, token,
         total_undet_ptr, total_allow_ptr, total_deny_ptr,
         intro_ok_ptr, intro_fail_ptr,
         policy_copy, snap_audiences, snap_required_claims]
        (IntrospectionClient::Result result) {
            AsyncMiddlewarePayload payload;
            auto build_undetermined = [&](std::string log_reason) {
                if (on_undet == kOnUndeterminedAllow) {
                    payload.result = AsyncMiddlewareResult::PASS;
                    payload.finalizer =
                        [issuer_name, policy_name, sanitized_req_path,
                         log_reason, total_undet_ptr]
                        (const HttpRequest& r, HttpResponse&) {
                        // intro_fail_ptr is incremented at the cache-
                        // insert site for outcomes from a real IdP
                        // roundtrip; drop-guard UNDETERMINED paths
                        // (issuer_unavailable / reload_in_flight /
                        // issuer_stopping) bypass the cache site by
                        // design and intentionally do NOT count as
                        // introspection_fail — those are issuer-state
                        // failures, not IdP failures.
                        total_undet_ptr->fetch_add(
                            1, std::memory_order_relaxed);
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
                    };
                } else {
                    payload.result = AsyncMiddlewareResult::DENY;
                    payload.finalizer =
                        [realm_local, retry_after_sec, issuer_name,
                         policy_name, sanitized_req_path, log_reason,
                         total_undet_ptr]
                        (const HttpRequest&, HttpResponse& rs) {
                        total_undet_ptr->fetch_add(
                            1, std::memory_order_relaxed);
                        logging::Get()->warn(
                            "auth_undetermined route={} issuer={} reason={} policy={}",
                            sanitized_req_path,
                            logging::SanitizeLogValue(issuer_name),
                            log_reason,
                            logging::SanitizeLogValue(policy_name));
                        rs = MakeServiceUnavailable(
                            realm_local, retry_after_sec,
                            "authentication unavailable");
                    };
                }
            };

            auto issuer_strong = weak_issuer.lock();
            if (!issuer_strong) {
                build_undetermined("issuer_unavailable");
                state->Complete(std::move(payload));
                return;
            }
            if (gen != issuer_strong->generation()) {
                build_undetermined("reload_in_flight");
                state->Complete(std::move(payload));
                return;
            }
            if (issuer_strong->stopping()) {
                build_undetermined("issuer_stopping");
                state->Complete(std::move(payload));
                return;
            }

            // No cache insert in the uncached path — that's the whole
            // point of falling here when TokenHasher::Hash failed.

            // Layer issuer-level audience fallback + required_claims on top
            // of IntrospectionClient's policy-only check.
            if (result.idp_active &&
                result.vr.outcome == VerifyOutcome::ALLOW) {
                IssuerSnapshot snap_for_check;
                snap_for_check.audiences = snap_audiences;
                snap_for_check.required_claims = snap_required_claims;
                VerifyResult vr_full = RunPolicyAndIssuerClaimChecks(
                    policy_copy, snap_for_check, result.ctx);
                if (vr_full.outcome != VerifyOutcome::ALLOW) {
                    result.vr = std::move(vr_full);
                }
            }

            // IdP-outcome counters fire AFTER the layered re-check so the
            // final outcome is what gets counted. Same warmup-friendly
            // semantics as InvokeAsyncIntrospection above.
            if (result.vr.outcome == VerifyOutcome::ALLOW) {
                intro_ok_ptr->fetch_add(1, std::memory_order_relaxed);
            } else {
                intro_fail_ptr->fetch_add(1, std::memory_order_relaxed);
            }

            switch (result.vr.outcome) {
              case VerifyOutcome::ALLOW: {
                  payload.result = AsyncMiddlewareResult::PASS;
                  AuthContext ctx = result.ctx;
                  payload.finalizer =
                      [ctx = std::move(ctx), issuer_name, policy_name,
                       sanitized_req_path, raw_jwt_header, token,
                       total_allow_ptr]
                      (const HttpRequest& r, HttpResponse&) {
                      // intro_ok_ptr already counted at the cache-site
                      // block above for parity with the cached path.
                      AuthContext local_ctx = ctx;
                      local_ctx.policy_name = policy_name;
                      if (local_ctx.issuer.empty())
                          local_ctx.issuer = issuer_name;
                      if (!raw_jwt_header.empty()) {
                          local_ctx.raw_token = token;
                      }
                      r.auth.emplace(std::move(local_ctx));
                      total_allow_ptr->fetch_add(
                          1, std::memory_order_relaxed);
                      if (auto lg = logging::Get();
                              lg->should_log(spdlog::level::debug)) {
                          lg->debug(
                              "auth_allow route={} issuer={} sub={} policy={} cache=uncached",
                              sanitized_req_path,
                              logging::SanitizeLogValue(issuer_name),
                              logging::SanitizeLogValue(
                                  r.auth ? r.auth->subject : std::string{}),
                              logging::SanitizeLogValue(policy_name));
                      }
                  };
                  break;
              }
              case VerifyOutcome::DENY_401: {
                  payload.result = AsyncMiddlewareResult::DENY;
                  payload.finalizer =
                      [realm_local, ec = result.vr.error_code,
                       desc = result.vr.error_description,
                       log_reason = result.vr.log_reason, issuer_name,
                       sanitized_req_path, policy_name,
                       total_deny_ptr]
                      (const HttpRequest&, HttpResponse& rs) {
                      rs = MakeUnauthorized(realm_local, ec, desc);
                      total_deny_ptr->fetch_add(
                          1, std::memory_order_relaxed);
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
                      [realm_local, desc = result.vr.error_description,
                       scopes = required_scopes, sanitized_req_path,
                       issuer_name, policy_name,
                       log_reason = result.vr.log_reason,
                       total_deny_ptr]
                      (const HttpRequest&, HttpResponse& rs) {
                      rs = MakeForbidden(realm_local, desc, scopes);
                      total_deny_ptr->fetch_add(
                          1, std::memory_order_relaxed);
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
            state->Complete(std::move(payload));
        },
        cancel_token);
}

}  // namespace AUTH_NAMESPACE
