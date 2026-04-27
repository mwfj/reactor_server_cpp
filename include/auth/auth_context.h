#pragma once

#include "common.h"
#include <optional>
#include <set>
// <string>, <vector>, <map>, <optional> via common.h

namespace AUTH_NAMESPACE {

// AuthContext is the output of the auth middleware on successful validation.
// Attached to HttpRequest via a mutable field (see include/http/http_request.h).
// Read by downstream middleware, route handlers, and by HeaderRewriter when
// constructing the outbound (upstream) request header set.
struct AuthContext {
    std::string issuer;                                   // Validated `iss` claim
    std::string subject;                                  // Validated `sub` claim
    std::vector<std::string> scopes;                      // From `scope` (space-sep) or `scp` (array)
    std::vector<std::string> audiences;                   // Validated `aud` (string-or-array, see RFC 7519 §4.1.3)
    std::map<std::string, std::string> claims;            // Operator-selected SCALAR claims (claims_to_headers source)
    // Names of operator-requested claims that were present in the JWT/
    // introspection payload but had a non-scalar (array/object) JSON shape.
    // Tracked separately from `claims` so required-claim presence checks
    // can match JWT-mode `payload.contains(c)` semantics WITHOUT abusing
    // a magic string value inside `claims` (which would conflict with
    // tokens that legitimately carry the literal sentinel as a claim
    // value). HeaderRewriter never reads this set — array→header
    // flattening is a future feature; non-scalar claim names emit no
    // outbound header today.
    std::set<std::string> non_scalar_claims;
    std::string policy_name;                              // Matched policy's name (observability)

    // SENSITIVE — raw bearer token. NEVER log this field. Never include it
    // in error messages, debug dumps, or diagnostic responses. Per
    // LOGGING_STANDARDS.md, logs must reference `subject` (post-validation)
    // only; the raw token must never appear. The middleware should populate
    // this field ONLY when `AuthForwardConfig::raw_jwt_header` is non-empty
    // (operator explicitly opted in to re-forwarding under a separate
    // header name) — otherwise leave it empty to minimize the blast radius
    // if a future request-dump helper accidentally serializes AuthContext.
    std::string raw_token;
    bool undetermined = false;                            // True when on_undetermined="allow" path forwarded
};

}  // namespace AUTH_NAMESPACE
