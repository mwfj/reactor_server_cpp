#pragma once

#include "common.h"
#include <optional>
// <string>, <vector>, <map>, <optional> via common.h

namespace auth {

// AuthContext is the output of the auth middleware on successful validation.
// Attached to HttpRequest via a mutable field (see include/http/http_request.h).
// Read by downstream middleware, route handlers, and by HeaderRewriter when
// constructing the outbound (upstream) request header set.
struct AuthContext {
    std::string issuer;                                   // Validated `iss` claim
    std::string subject;                                  // Validated `sub` claim
    std::vector<std::string> scopes;                      // From `scope` (space-sep) or `scp` (array)
    std::map<std::string, std::string> claims;            // Operator-selected claims (claims_to_headers source)
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

    void Clear() {
        issuer.clear();
        subject.clear();
        scopes.clear();
        claims.clear();
        policy_name.clear();
        raw_token.clear();
        undetermined = false;
    }
};

}  // namespace auth
