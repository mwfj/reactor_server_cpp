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
    std::string raw_token;                                // Raw bearer token (for raw_jwt_header injection, if enabled)
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
