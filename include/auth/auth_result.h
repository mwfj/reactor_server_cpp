#pragma once

#include "common.h"
// <string>, <cstdint> via common.h

namespace AUTH_NAMESPACE {

// ---------------------------------------------------------------------------
// Result vocabulary for the auth pipeline (middleware + verifier). Kept in
// a dedicated header so `auth_context.h` stays a pure data struct and so
// downstream modules that only need the outcome enum can avoid pulling in
// the full AuthContext definition. See design spec §6.1 / §8.
// ---------------------------------------------------------------------------

// Outcome of a verify pass over a bearer token + policy.
enum class VerifyOutcome {
    ALLOW,         // Token valid; AuthContext populated.
    DENY_401,      // invalid_request OR invalid_token — RFC 6750 §3 error codes.
    DENY_403,      // insufficient_scope — RFC 6750 §3.
    UNDETERMINED,  // IdP unreachable / JWKS kid-miss / verifier build error.
};

// Finer-grained error classification used to build the WWW-Authenticate
// response header and log label. `None` is reserved for ALLOW outcomes.
enum class AuthErrorCode : uint8_t {
    None = 0,
    InvalidRequest,      // Missing / malformed / oversized Authorization value.
    InvalidToken,        // Signature / issuer / audience / expiry failure.
    InsufficientScope,   // Required scopes absent from token.
    Undetermined,        // Outcome unknown — use on_undetermined policy.
};

// Value type returned from JwtVerifier::Verify and consumed by AuthManager
// to shape the client-facing response. Never throws; constructed via the
// static helpers below so the intent-to-result mapping is obvious.
struct VerifyResult {
    VerifyOutcome outcome = VerifyOutcome::UNDETERMINED;
    AuthErrorCode error_code = AuthErrorCode::Undetermined;
    // Safe-to-surface error description — appears in RFC 6750
    // `error_description` on the WWW-Authenticate header. MUST NOT contain
    // raw token bytes or header contents; design §8 / §9 item 9.
    std::string error_description;
    // Internal log label — a short, log-friendly string like
    // "signature_invalid". Never logged alongside the raw token. Empty for
    // ALLOW outcomes.
    std::string log_reason;
    // Retry-After hint (seconds) populated when outcome == UNDETERMINED and
    // the caller wants to surface a recommended backoff. 0 means
    // "use policy default".
    int retry_after_sec = 0;
    // Issuer hint for observability only — populated when we know which
    // issuer a token claimed (read from `iss` before signature verification),
    // so log lines can correlate without exposing the token. Empty when
    // the issuer could not be peeked.
    std::string iss_hint;

    static VerifyResult Allow() {
        VerifyResult r;
        r.outcome = VerifyOutcome::ALLOW;
        r.error_code = AuthErrorCode::None;
        return r;
    }

    // RFC 6750 `invalid_request` (401). Use for missing / malformed input
    // that does not require evaluating the signature (no header, wrong
    // scheme, oversized token).
    static VerifyResult InvalidRequest(std::string error_desc,
                                        std::string log_label) {
        VerifyResult r;
        r.outcome = VerifyOutcome::DENY_401;
        r.error_code = AuthErrorCode::InvalidRequest;
        r.error_description = std::move(error_desc);
        r.log_reason = std::move(log_label);
        return r;
    }

    // RFC 6750 `invalid_token` (401). Use for signature / claim failures.
    static VerifyResult InvalidToken(std::string error_desc,
                                      std::string log_label) {
        VerifyResult r;
        r.outcome = VerifyOutcome::DENY_401;
        r.error_code = AuthErrorCode::InvalidToken;
        r.error_description = std::move(error_desc);
        r.log_reason = std::move(log_label);
        return r;
    }

    // RFC 6750 `insufficient_scope` (403). Caller should surface the
    // required scope list in the WWW-Authenticate header.
    static VerifyResult InsufficientScope(std::string error_desc,
                                           std::string log_label) {
        VerifyResult r;
        r.outcome = VerifyOutcome::DENY_403;
        r.error_code = AuthErrorCode::InsufficientScope;
        r.error_description = std::move(error_desc);
        r.log_reason = std::move(log_label);
        return r;
    }

    // Undetermined outcome — IdP unreachable, JWKS kid miss with no cached
    // key, verifier construction failed, etc. Caller uses the policy's
    // `on_undetermined` setting to decide whether to deny (503) or allow
    // the request through with `X-Auth-Undetermined: true`.
    static VerifyResult Undetermined(std::string log_label,
                                      int retry_after_sec = 0) {
        VerifyResult r;
        r.outcome = VerifyOutcome::UNDETERMINED;
        r.error_code = AuthErrorCode::Undetermined;
        r.log_reason = std::move(log_label);
        r.retry_after_sec = retry_after_sec;
        return r;
    }

    bool is_allow() const noexcept { return outcome == VerifyOutcome::ALLOW; }
    bool is_deny() const noexcept {
        return outcome == VerifyOutcome::DENY_401
            || outcome == VerifyOutcome::DENY_403;
    }
    bool is_undetermined() const noexcept {
        return outcome == VerifyOutcome::UNDETERMINED;
    }
};

// String form of AuthErrorCode — used as the RFC 6750 `error` token in
// WWW-Authenticate. Kept here so both the verifier and the error-response
// builder emit the same spelling. Returns an empty string for None.
inline const char* AuthErrorCodeAsString(AuthErrorCode code) noexcept {
    switch (code) {
        case AuthErrorCode::InvalidRequest:    return "invalid_request";
        case AuthErrorCode::InvalidToken:      return "invalid_token";
        case AuthErrorCode::InsufficientScope: return "insufficient_scope";
        case AuthErrorCode::Undetermined:      return "undetermined";
        case AuthErrorCode::None:
        default:                                return "";
    }
}

}  // namespace AUTH_NAMESPACE
