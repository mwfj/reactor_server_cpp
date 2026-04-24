#pragma once

#include "common.h"
#include "http/http_response.h"
#include "auth/auth_result.h"
// <string> via common.h

namespace AUTH_NAMESPACE {

// ---------------------------------------------------------------------------
// Builders for the 401 / 403 / 503 responses emitted by AuthManager's
// middleware. Kept separate from the manager so the format is testable
// in isolation, and so other components (e.g. WebSocket upgrade handlers
// that run the middleware chain manually) can share the same output.
//
// All responses follow RFC 6750 §3 wording:
//   WWW-Authenticate: Bearer realm="api", error="invalid_token",
//     error_description="token expired"
// ---------------------------------------------------------------------------

// Build the RFC 6750 WWW-Authenticate header value. `realm` defaults to
// "api" when empty. `error_code` is the RFC 6750 error token
// ("invalid_request", "invalid_token", "insufficient_scope",
// "undetermined"). `error_description` is an operator-visible string
// (already sanitized — never contains the raw token).
// `scope` is the space-joined list of required scopes (only meaningful for
// insufficient_scope). Empty parameters are omitted from the output.
std::string BuildWwwAuthenticate(const std::string& realm,
                                  const std::string& error_code,
                                  const std::string& error_description,
                                  const std::string& scope);

// Produce a 401 response with WWW-Authenticate set. Uses HttpStatus::UNAUTHORIZED.
HttpResponse MakeUnauthorized(const std::string& realm,
                               AuthErrorCode error_code,
                               const std::string& error_description);

// Produce a 403 response with WWW-Authenticate set and scope= populated.
HttpResponse MakeForbidden(const std::string& realm,
                            const std::string& error_description,
                            const std::vector<std::string>& required_scopes);

// Produce a 503 response for UNDETERMINED outcomes. Sets Retry-After with
// a safe positive integer derived from `retry_after_sec` (clamped 1..300).
HttpResponse MakeServiceUnavailable(const std::string& realm,
                                     int retry_after_sec,
                                     const std::string& error_description);

}  // namespace AUTH_NAMESPACE
