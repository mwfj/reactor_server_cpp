#pragma once

#include "common.h"
#include "auth/auth_config.h"
#include "auth/auth_context.h"
#include "auth/auth_result.h"
// <string>, <optional> via common.h

namespace AUTH_NAMESPACE {

class Issuer;

// ---------------------------------------------------------------------------
// Stateless JWT verifier. Wraps jwt-cpp with exception containment at
// every attacker-reachable call site (design §9 item 16). All public
// entry points return VerifyResult and never throw.
//
// OpenSSL concurrency: OpenSSL 1.1+ (we link 3.x) is thread-safe out of
// the box. jwt-cpp's internal EVP_DigestVerify / EVP_DigestInit_ex
// calls are per-thread with no shared state. Safe from any dispatcher.
//
// Algorithm hygiene:
// - Per-issuer allowlist is taken from IssuerSnapshot::algorithms.
// - `alg: none` is NEVER configured into the allowlist (ConfigLoader
//   rejects `"none"` at load time; Verify never calls
//   `allow_algorithm(jwt::algorithm::none{})`). This is a property of
//   THIS code, not of the library (§9 item 11).
// - Unknown algorithms fail the allowlist check before any signature
//   bytes are examined.
// ---------------------------------------------------------------------------
class JwtVerifier {
 public:
    // Verify a bearer token. On ALLOW, populates `out_ctx` with issuer,
    // subject, scopes, and operator-selected claims. Never throws.
    static VerifyResult Verify(const std::string& token,
                                Issuer& issuer,
                                const AuthPolicy& policy,
                                AuthContext& out_ctx);

    // Decode the JWT and return the `iss` claim without verifying the
    // signature. Used by AuthManager to route a token to the right
    // issuer when a policy accepts multiple issuers. Returns std::nullopt
    // on any decode failure.
    static std::optional<std::string> PeekIssuer(const std::string& token);
};

}  // namespace AUTH_NAMESPACE
