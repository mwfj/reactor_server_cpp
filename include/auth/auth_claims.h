#pragma once

#include "common.h"
#include "auth/auth_context.h"
#include <nlohmann/json.hpp>
// <string>, <vector> via common.h

namespace auth {

// Helpers that translate a decoded-JWT payload OR an introspection-response
// JSON into the AuthContext we attach to HttpRequest.
//
// Kept separate from JwtVerifier / IntrospectionClient so the same
// claim-extraction logic is used by both paths and tested once.

// Build a scope list from the payload. OAuth 2.0 tokens conventionally use
// either `scope` (space-separated string) or `scp` (JSON array of strings).
// Some IdPs (e.g. Azure AD) also emit `scopes`. This helper accepts all three.
std::vector<std::string> ExtractScopes(const nlohmann::json& payload);

// Populate AuthContext from a decoded JWT payload plus operator-configured
// `claims_to_headers` keys (we only copy claims that the operator asks for
// into AuthContext::claims, to keep the context small).
//
// Also sets:
//   ctx.issuer  = payload["iss"] (if string)
//   ctx.subject = payload["sub"] (if string)
//   ctx.scopes  = ExtractScopes(payload)
//
// Returns true when `sub` and `iss` are both present and string; false
// otherwise (caller returns 401 invalid_token).
bool PopulateFromPayload(const nlohmann::json& payload,
                         const std::vector<std::string>& claims_keys,
                         AuthContext& ctx);

// Check whether all required scopes are present in the token's scope list.
// Returns true iff every entry in `required` appears in `have`. Empty
// `required` is always accepted.
bool HasRequiredScopes(const std::vector<std::string>& have,
                       const std::vector<std::string>& required);

// Check whether the token's `aud` claim matches a required audience string.
// `aud` may be a string or array in JWT. Returns true iff `required` matches
// one of the audiences. Empty `required` is always accepted (no audience
// requirement).
bool MatchesAudience(const nlohmann::json& payload,
                     const std::string& required);

}  // namespace auth
