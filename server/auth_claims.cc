#include "auth/auth_claims.h"

#include <sstream>

namespace auth {

namespace {

std::vector<std::string> SplitWhitespace(const std::string& s) {
    std::vector<std::string> out;
    std::istringstream iss(s);
    std::string tok;
    while (iss >> tok) {
        if (!tok.empty()) out.push_back(std::move(tok));
    }
    return out;
}

}  // namespace

std::vector<std::string> ExtractScopes(const nlohmann::json& payload) {
    // Try `scope` first (OAuth 2.0 convention — space-separated string).
    if (payload.contains("scope") && payload["scope"].is_string()) {
        return SplitWhitespace(payload["scope"].get<std::string>());
    }
    // Then `scp` (RFC 8693 / common IdP convention — array of strings).
    if (payload.contains("scp") && payload["scp"].is_array()) {
        std::vector<std::string> out;
        out.reserve(payload["scp"].size());
        for (const auto& v : payload["scp"]) {
            if (v.is_string()) out.push_back(v.get<std::string>());
        }
        return out;
    }
    // Azure AD and friends.
    if (payload.contains("scopes") && payload["scopes"].is_array()) {
        std::vector<std::string> out;
        out.reserve(payload["scopes"].size());
        for (const auto& v : payload["scopes"]) {
            if (v.is_string()) out.push_back(v.get<std::string>());
        }
        return out;
    }
    return {};
}

bool PopulateFromPayload(const nlohmann::json& payload,
                         const std::vector<std::string>& claims_keys,
                         AuthContext& ctx) {
    if (!payload.is_object()) return false;

    // `iss` and `sub` are mandatory (RFC 7519 §4.1.1 / §4.1.2) — a token
    // without them is not considered valid for our purposes.
    if (!payload.contains("iss") || !payload["iss"].is_string()) return false;
    if (!payload.contains("sub") || !payload["sub"].is_string()) return false;

    ctx.issuer = payload["iss"].get<std::string>();
    ctx.subject = payload["sub"].get<std::string>();
    ctx.scopes = ExtractScopes(payload);

    // Copy only operator-requested claims into ctx.claims, to keep the
    // context object small and to limit the data that flows into logs.
    for (const auto& key : claims_keys) {
        if (!payload.contains(key)) continue;
        const auto& v = payload[key];
        if (v.is_string()) {
            ctx.claims[key] = v.get<std::string>();
        } else if (v.is_number_integer()) {
            ctx.claims[key] = std::to_string(v.get<int64_t>());
        } else if (v.is_number_float()) {
            ctx.claims[key] = std::to_string(v.get<double>());
        } else if (v.is_boolean()) {
            ctx.claims[key] = v.get<bool>() ? "true" : "false";
        }
        // Arrays/objects: skip (operator should pick a more specific key).
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
