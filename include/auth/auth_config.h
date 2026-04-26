#pragma once

#include "common.h"
// <string>, <vector>, <map>, <unordered_map> via common.h

namespace AUTH_NAMESPACE {

// Mode discriminator string values for IssuerConfig::mode. Bare-string
// comparisons to "jwt" / "introspection" appear in many sites (issuer.cc,
// auth_manager.cc, config_loader.cc); centralise here so a typo at one site
// fails to compile rather than silently misbehaving.
inline constexpr const char* kModeJwt = "jwt";
inline constexpr const char* kModeIntrospection = "introspection";

// ---------------------------------------------------------------------------
// Introspection-mode config (RFC 7662 token introspection).
// ---------------------------------------------------------------------------
struct IntrospectionConfig {
    std::string endpoint;                          // Full URL; required when mode=introspection
    std::string client_id;                         // OAuth client id for the introspection request
    std::string client_secret_env;                 // Env-var name holding the client secret (inline secret is rejected)
    std::string auth_style = "basic";              // "basic" (Authorization header) or "body" (urlencoded body)
    int timeout_sec = 3;                           // Per-request timeout for introspection POST
    int cache_sec = 60;                            // Positive-result cache TTL (capped by token exp)
    int negative_cache_sec = 10;                   // Negative-result cache TTL
    int stale_grace_sec = 30;                      // Serve stale positive when IdP unreachable
    int max_entries = 100000;                      // Per-issuer cache cap (LRU eviction on insert)
    int shards = 16;                               // Sharded LRU shard count

    bool operator==(const IntrospectionConfig& o) const {
        return endpoint == o.endpoint &&
               client_id == o.client_id &&
               client_secret_env == o.client_secret_env &&
               auth_style == o.auth_style &&
               timeout_sec == o.timeout_sec &&
               cache_sec == o.cache_sec &&
               negative_cache_sec == o.negative_cache_sec &&
               stale_grace_sec == o.stale_grace_sec &&
               max_entries == o.max_entries &&
               shards == o.shards;
    }
    bool operator!=(const IntrospectionConfig& o) const { return !(*this == o); }
};

// ---------------------------------------------------------------------------
// Per-issuer config. One entry per trusted IdP.
// ---------------------------------------------------------------------------
struct IssuerConfig {
    std::string name;                              // Config key (e.g. "google", "openai", "ours")
    std::string issuer_url;                        // MUST be https://
    bool discovery = true;                         // Use OIDC .well-known/openid-configuration
    std::string jwks_uri;                          // Optional static override; only used when discovery=false
    std::string upstream;                          // Name of the UpstreamHostPool used for outbound IdP calls
    std::string mode = "jwt";                      // "jwt" or "introspection"
    std::vector<std::string> audiences;            // Accepted `aud` values
    std::vector<std::string> algorithms = {        // Per-issuer allowlist (asymmetric only in v1)
        "RS256"};
    int leeway_sec = 30;                           // Clock-skew tolerance for exp/nbf/iat
    int jwks_cache_sec = 300;                      // JWKS TTL
    int jwks_refresh_timeout_sec = 5;              // Per-refresh upstream timeout
    int discovery_retry_sec = 30;                  // Retry interval if startup discovery fails
    std::vector<std::string> required_claims;      // Claims that MUST be present (beyond iss/exp/aud)
    IntrospectionConfig introspection;             // Only meaningful when mode=introspection

    bool operator==(const IssuerConfig& o) const {
        return name == o.name && issuer_url == o.issuer_url &&
               discovery == o.discovery && jwks_uri == o.jwks_uri &&
               upstream == o.upstream && mode == o.mode &&
               audiences == o.audiences && algorithms == o.algorithms &&
               leeway_sec == o.leeway_sec &&
               jwks_cache_sec == o.jwks_cache_sec &&
               jwks_refresh_timeout_sec == o.jwks_refresh_timeout_sec &&
               discovery_retry_sec == o.discovery_retry_sec &&
               required_claims == o.required_claims &&
               introspection == o.introspection;
    }
    bool operator!=(const IssuerConfig& o) const { return !(*this == o); }
};

// ---------------------------------------------------------------------------
// Per-policy config. Attached either:
//   (a) inline on a proxy via ProxyConfig::auth (applies_to derived from route_prefix)
//   (b) top-level via AuthConfig::policies (applies_to declared explicitly)
// ---------------------------------------------------------------------------
struct AuthPolicy {
    std::string name;                              // Optional for inline policies; required for top-level
    bool enabled = false;                          // Opt-in per policy; default off (prevents empty policy from gating)
    std::vector<std::string> applies_to;           // Path prefixes (used only for top-level policies)
    std::vector<std::string> issuers;              // Accepted issuer names (must match AuthConfig::issuers keys)
    std::vector<std::string> required_scopes;      // All must be present in token scope/scp
    std::string required_audience;                 // Overrides issuer-level `audiences` when set
    std::string on_undetermined = "deny";          // "deny" (default) or "allow"
    std::string realm = "api";                     // For WWW-Authenticate: Bearer realm="..."

    bool operator==(const AuthPolicy& o) const {
        return name == o.name && enabled == o.enabled &&
               applies_to == o.applies_to && issuers == o.issuers &&
               required_scopes == o.required_scopes &&
               required_audience == o.required_audience &&
               on_undetermined == o.on_undetermined &&
               realm == o.realm;
    }
    bool operator!=(const AuthPolicy& o) const { return !(*this == o); }
};

// ---------------------------------------------------------------------------
// Forward-overlay config. How validated identity is injected into the
// outbound (upstream) request header set by HeaderRewriter. Reload-mutable;
// held inside AuthManager as std::shared_ptr<const AuthForwardConfig> and
// snapshotted per-request at the start of the outbound hop.
// ---------------------------------------------------------------------------
struct AuthForwardConfig {
    std::string subject_header = "X-Auth-Subject";
    std::string issuer_header  = "X-Auth-Issuer";
    std::string scopes_header  = "X-Auth-Scopes";
    std::string raw_jwt_header;                            // Empty (default) = disabled
    std::map<std::string, std::string> claims_to_headers;  // claim -> outbound header name
    bool strip_inbound_identity_headers = true;            // Drop inbound X-Auth-* to prevent spoofing
    bool preserve_authorization = true;                    // Forward original Authorization header

    // Derived from claims_to_headers; populated by PopulateDerived() before
    // the snapshot is wrapped in shared_ptr<const>. Avoids a per-request
    // rebuild on the hot verify path. Excluded from equality (derived).
    std::vector<std::string> claim_keys;

    void PopulateDerived() {
        claim_keys.clear();
        claim_keys.reserve(claims_to_headers.size());
        for (const auto& kv : claims_to_headers) {
            claim_keys.push_back(kv.first);
        }
    }

    bool operator==(const AuthForwardConfig& o) const {
        return subject_header == o.subject_header &&
               issuer_header == o.issuer_header &&
               scopes_header == o.scopes_header &&
               raw_jwt_header == o.raw_jwt_header &&
               claims_to_headers == o.claims_to_headers &&
               strip_inbound_identity_headers == o.strip_inbound_identity_headers &&
               preserve_authorization == o.preserve_authorization;
    }
    bool operator!=(const AuthForwardConfig& o) const { return !(*this == o); }
};

// ---------------------------------------------------------------------------
// Top-level auth config block.
// ---------------------------------------------------------------------------
struct AuthConfig {
    bool enabled = false;                                  // Master switch
    std::unordered_map<std::string, IssuerConfig> issuers; // Keyed by IssuerConfig::name (redundant but stable)
    std::vector<AuthPolicy> policies;                      // Top-level policies with applies_to
    AuthForwardConfig forward;                             // Outbound header overlay config
    std::string hmac_cache_key_env;                        // Env-var name for process-local HMAC key; empty = generated

    bool operator==(const AuthConfig& o) const {
        return enabled == o.enabled && issuers == o.issuers &&
               policies == o.policies && forward == o.forward &&
               hmac_cache_key_env == o.hmac_cache_key_env;
    }
    bool operator!=(const AuthConfig& o) const { return !(*this == o); }
};

}  // namespace AUTH_NAMESPACE
