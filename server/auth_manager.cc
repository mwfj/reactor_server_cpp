#include "auth/auth_manager.h"

#include "auth/auth_error_responses.h"
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
    forward_ = std::make_shared<const AuthForwardConfig>(config.forward);
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

    // Forward config — atomic swap.
    {
        std::lock_guard<std::mutex> lk(snapshot_mtx_);
        forward_ = std::make_shared<const AuthForwardConfig>(new_config.forward);
    }

    // master_enabled_ is DELIBERATELY NOT touched here. The final cutover
    // happens in CommitPolicyAndEnforcement, called by HttpServer::Reload
    // after the upstream topology check. Flipping master_enabled_ here
    // would reopen a `false → true` reload window: between this return
    // and the separate policy rebuild, requests could run with
    // enforcement ON against the OLD policy list.
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
        bool new_master_enabled) {
    auto rebuilt = BuildAppliedPolicyList(new_upstreams,
                                            new_top_level_policies);
    // Single atomic cutover under snapshot_mtx_: policy swap FIRST, then
    // the master_enabled_ release-store. The release-store is the final
    // publication edge — a reader observing master_enabled_=true sees the
    // fresh policies_ pointer too. Ordering matters: flipping the enable
    // flag before the policy swap would expose the window this method
    // exists to close.
    {
        std::lock_guard<std::mutex> lk(snapshot_mtx_);
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
        // No `iss` peek — fall back to the first allowed issuer; jwt-cpp's
        // `with_issuer` will still enforce the claim match.
        auto it = issuers_.find(policy.issuers.front());
        if (it != issuers_.end()) chosen = it->second.get();
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

    // Operator-configured forward.claims_to_headers keys flow into
    // Verify so PopulateFromPayload can copy them into ctx.claims for
    // outbound injection. Policy-level required_claims are enforced
    // inside Verify and do NOT need to appear here.
    std::vector<std::string> claim_keys;
    if (fwd_snap) {
        claim_keys.reserve(fwd_snap->claims_to_headers.size());
        for (const auto& kv : fwd_snap->claims_to_headers) {
            claim_keys.push_back(kv.first);
        }
    }

    // Run the verifier. Never throws.
    AuthContext ctx;
    VerifyResult vr =
        JwtVerifier::Verify(token, *chosen, policy, claim_keys, ctx);

    switch (vr.outcome) {
        case VerifyOutcome::ALLOW: {
            // Populate claims_to_headers-requested keys BEFORE committing.
            // JwtVerifier::Verify intentionally does not see the forward
            // config; it runs the policy-level checks. Operator-selected
            // claims flow from forward.claims_to_headers via the overlay
            // at the outbound hop (HeaderRewriter Phase E).
            ctx.policy_name = policy.name;
            // Stash the raw token only when the operator explicitly asked
            // for it via forward.raw_jwt_header (spec §9 item 9).
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

}  // namespace AUTH_NAMESPACE
