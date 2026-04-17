#include "auth/auth_claims.h"

#include <sstream>

namespace auth {

namespace {

std::vector<std::string> SplitWhitespace(const std::string& s) {
    // operator>>(istream&, string&) skips leading whitespace and reads a
    // non-empty run of non-whitespace characters — it cannot produce an
    // empty `tok` on success, so no inner empty-check is needed here.
    std::vector<std::string> out;
    std::istringstream iss(s);
    std::string tok;
    while (iss >> tok) out.push_back(std::move(tok));
    return out;
}

}  // namespace

std::vector<std::string> ExtractScopes(const nlohmann::json& payload) {
    // Try `scope` first (OAuth 2.0 convention — space-separated string).
    if (payload.contains("scope") && payload["scope"].is_string()) {
        return SplitWhitespace(payload["scope"].get<std::string>());
    }
    // Then `scp`. Two common forms in the wild:
    //   - RFC 8693 / Keycloak / Ory: array of strings
    //   - Azure AD / Entra delegated flows: space-delimited string
    // Accept both; fall back to empty list for any other shape (e.g. object).
    if (payload.contains("scp")) {
        const auto& v = payload["scp"];
        if (v.is_array()) {
            std::vector<std::string> out;
            out.reserve(v.size());
            for (const auto& s : v) {
                if (s.is_string()) out.push_back(s.get<std::string>());
            }
            return out;
        }
        if (v.is_string()) {
            return SplitWhitespace(v.get<std::string>());
        }
    }
    // Azure AD and friends. Accept both array-of-strings AND a single
    // whitespace-delimited string — matches the dual-form handling of
    // `scp` above. Some identity providers (and custom introspection
    // endpoints) serialize scopes as a single string even though the
    // field name is plural; rejecting that form would make
    // required_scopes wrongly reject otherwise-valid tokens.
    if (payload.contains("scopes")) {
        const auto& v = payload["scopes"];
        if (v.is_array()) {
            std::vector<std::string> out;
            out.reserve(v.size());
            for (const auto& s : v) {
                if (s.is_string()) out.push_back(s.get<std::string>());
            }
            return out;
        }
        if (v.is_string()) {
            return SplitWhitespace(v.get<std::string>());
        }
    }
    return {};
}

bool PopulateFromPayload(const nlohmann::json& payload,
                         const std::vector<std::string>& claims_keys,
                         AuthContext& ctx) {
    // Defensive reset of the fields THIS function manages. Without this,
    // a non-fresh AuthContext (e.g. a verifier that reuses a stack object
    // across requests, or a retry path that re-invokes Populate) would
    // INHERIT the previous call's iss / sub / scopes / claims when the
    // current payload doesn't supply them — a token could end up with
    // the prior caller's principal, scopes, or forwarded-claim values.
    // Principal-confusion bug. The cheap fix is "this function owns these
    // fields; clear up front, populate from payload."
    //
    // Fields NOT cleared here (policy_name, raw_token, undetermined) are
    // caller-managed; they're set by the middleware around the verifier
    // call, not derived from the JWT payload. Clearing them would force
    // the caller to re-set on every payload populate, which is the wrong
    // contract.
    //
    // Cleared even when we return false below (non-object payload) — a
    // caller who accidentally uses ctx after a false return gets clean
    // empty fields, not stale ones from a previous successful call. This
    // is the safer side of the fail-closed coin.
    ctx.issuer.clear();
    ctx.subject.clear();
    ctx.scopes.clear();
    ctx.claims.clear();

    if (!payload.is_object()) return false;

    // `iss` and `sub` are both OPTIONAL per RFC 7519 §4.1.1 / §4.1.2; the
    // RFC 7662 introspection response also doesn't guarantee them (only
    // `active` is required). Common cases where one or both are absent:
    //
    //   - Client-credentials / service-account access tokens: no human
    //     `sub`. The OAuth client itself is identified by `client_id`,
    //     which the verifier can pass through via `claims_to_headers`.
    //   - Introspection responses from minimal IdPs: may return
    //     `{"active": true, "scope": "read:data"}` and nothing else.
    //   - Symmetric-key flows (deferred — HS256 is out of scope for v1):
    //     issuer is implicit in the shared key.
    //
    // The verifier (Phase 2 `JwtVerifier`) is the layer that enforces
    // `iss` matches a configured issuer, via jwt-cpp's `with_issuer(...)`
    // — by the time we get here that constraint has already been
    // applied. Our job here is claim EXTRACTION, not policy enforcement,
    // so we populate what's present and leave what isn't empty. False is
    // returned ONLY for a structurally-invalid payload (not an object).
    //
    // Downstream readers (the future HeaderRewriter overlay) must treat
    // both `ctx.issuer` and `ctx.subject` as possibly-empty and skip
    // emitting their respective headers when empty rather than emitting
    // empty values that would mislead upstream services.
    if (payload.contains("iss") && payload["iss"].is_string()) {
        ctx.issuer = payload["iss"].get<std::string>();
    }
    if (payload.contains("sub") && payload["sub"].is_string()) {
        ctx.subject = payload["sub"].get<std::string>();
    }
    ctx.scopes = ExtractScopes(payload);

    // Copy only operator-requested claims into ctx.claims, to keep the
    // context object small and to limit the data that flows into logs.
    //
    // Only scalar claims are flattened into the string-valued map. Array /
    // object claims are SILENTLY SKIPPED — a common operator ask like
    // "forward the `groups` array to X-Auth-Groups" will produce no header
    // with the current Phase 1-2 model. That is intentional for this layer:
    // array-to-header flattening (typically comma-separated, or multi-valued
    // headers) is a HeaderRewriter / middleware concern because the
    // serialization choice depends on what the upstream expects. Phase 3
    // wiring should add that flattening at the overlay layer, not here.
    //
    // Numeric claims: check unsigned FIRST, then signed. This ordering
    // preserves uint64 values > INT64_MAX — e.g. OAuth numeric IDs for user
    // or tenant claims that operators may map via claims_to_headers.
    // Without the unsigned branch, `is_number_integer()` + `get<int64_t>()`
    // would silently wrap values like 18446744073709551615 to -1, which
    // would then flow into X-Auth-* headers and downstream services would
    // see the wrong principal data. nlohmann's `is_number_integer()`
    // returns true for both signed and unsigned; `is_number_unsigned()`
    // narrows to the specific unsigned shape.
    for (const auto& key : claims_keys) {
        if (!payload.contains(key)) continue;
        const auto& v = payload[key];
        if (v.is_string()) {
            ctx.claims[key] = v.get<std::string>();
        } else if (v.is_number_unsigned()) {
            ctx.claims[key] = std::to_string(v.get<uint64_t>());
        } else if (v.is_number_integer()) {
            ctx.claims[key] = std::to_string(v.get<int64_t>());
        } else if (v.is_number_float()) {
            ctx.claims[key] = std::to_string(v.get<double>());
        } else if (v.is_boolean()) {
            ctx.claims[key] = v.get<bool>() ? "true" : "false";
        }
        // Arrays/objects: skip (see comment above — flattening is a Phase 3
        // HeaderRewriter concern, not a claim-extraction concern).
    }
    return true;
}

bool HasRequiredScopes(const std::vector<std::string>& have,
                       const std::vector<std::string>& required) {
    if (required.empty()) return true;
    for (const auto& r : required) {
        bool found = false;
        for (const auto& h : have) {
            if (h == r) { found = true; break; }
        }
        if (!found) return false;
    }
    return true;
}

bool MatchesAudience(const nlohmann::json& payload,
                     const std::string& required) {
    if (required.empty()) return true;
    if (!payload.contains("aud")) return false;
    const auto& aud = payload["aud"];
    if (aud.is_string()) {
        return aud.get<std::string>() == required;
    }
    if (aud.is_array()) {
        for (const auto& v : aud) {
            if (v.is_string() && v.get<std::string>() == required) return true;
        }
    }
    return false;
}

}  // namespace auth
