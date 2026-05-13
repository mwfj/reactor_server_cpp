#pragma once

// auth_metrics.h — small inline helpers for the auth subsystem's
// observability emit sites.
//
// Purpose: strip the unbounded tail off log-style reason strings
// (e.g. `"jwt_verify_failed: invalid signature, key not found"`) before
// they reach `reactor.auth.requests{reason=...}`, and canonicalise the
// stripped result against a closed vocabulary. The logging path keeps
// the full diagnostic; the metric path stays bounded by the vocabulary
// below so cardinality is operator-safe.
//
// Closed vocabulary (any deny path that doesn't fit collapses to "other"):
//   missing_token, expired_token, malformed_token, signature_invalid,
//   jwt_verify_failed, aud_mismatch, iss_mismatch,
//   introspection_inactive, introspection_error,
//   policy_denied, cache_miss_no_issuer, other
//
// ALLOW callers pass "ok" explicitly at the emit site; this header has
// nothing to do with the ALLOW reason label.

#include "common.h"  // <string>, <string_view> via common.h transitives

namespace AUTH_NAMESPACE {

// "jwt_verify_failed: invalid signature" -> "jwt_verify_failed"
// "introspection_error:502"              -> "introspection_error"
// "expired_token"                        -> "expired_token"
//
// Whitespace immediately preceding the colon is trimmed so
// "x :tail" returns "x".
inline std::string StripReasonTail(std::string_view reason) {
    auto colon = reason.find(':');
    if (colon == std::string_view::npos) return std::string(reason);
    auto head = reason.substr(0, colon);
    while (!head.empty() && (head.back() == ' ' || head.back() == '\t')) {
        head.remove_suffix(1);
    }
    return std::string(head);
}

// Map a stripped reason to a static literal in the closed vocabulary.
// Returns "other" for anything outside the vocabulary so cardinality
// stays bounded regardless of operator config or upstream weirdness.
//
// The first vocabulary block accepts EXACT vocab tokens (so callers
// that already pass canonical labels round-trip identity). The second
// block translates internal verifier / introspection log_reasons into
// the canonical vocab — those internal reasons have legacy spellings
// (e.g. "issuer_mismatch", "audience_mismatch") that don't match the
// canonical short tags (`iss_mismatch`, `aud_mismatch`) by character.
inline const char* CanonicalReasonLabel(std::string_view stripped) {
    // Identity passes for callers that pass canonical labels directly.
    if (stripped == "missing_token")          return "missing_token";
    if (stripped == "expired_token")          return "expired_token";
    if (stripped == "malformed_token")        return "malformed_token";
    if (stripped == "signature_invalid")      return "signature_invalid";
    if (stripped == "jwt_verify_failed")      return "jwt_verify_failed";
    if (stripped == "aud_mismatch")           return "aud_mismatch";
    if (stripped == "iss_mismatch")           return "iss_mismatch";
    if (stripped == "introspection_inactive") return "introspection_inactive";
    if (stripped == "introspection_error")    return "introspection_error";
    if (stripped == "policy_denied")          return "policy_denied";
    if (stripped == "cache_miss_no_issuer")   return "cache_miss_no_issuer";

    // Legacy verifier / introspection log_reason translations.
    if (stripped == "issuer_mismatch")           return "iss_mismatch";
    if (stripped == "audience_mismatch")         return "aud_mismatch";
    if (stripped == "token_expired_or_nbf")      return "expired_token";
    if (stripped == "decode_failed")             return "malformed_token";
    if (stripped == "payload_extract_failed")    return "malformed_token";
    if (stripped == "missing_alg")               return "malformed_token";
    if (stripped == "alg_none")                  return "malformed_token";
    if (stripped == "alg_not_allowed")           return "malformed_token";
    if (stripped == "missing_kid_multi_key")     return "malformed_token";
    if (stripped == "verify_failed")             return "jwt_verify_failed";
    if (stripped == "verify_threw")              return "jwt_verify_failed";
    if (stripped == "verifier_unknown_algorithm")return "jwt_verify_failed";
    if (stripped == "verifier_build_failed")     return "jwt_verify_failed";
    if (stripped == "missing_required_claim")    return "policy_denied";
    if (stripped == "insufficient_scope")        return "policy_denied";

    return "other";
}

// Return a non-empty issuer label for metric emission. Empty issuers
// (no `iss` claim, pre-issuer-resolution error paths) reduce to the
// `"<unknown>"` sentinel. Returning by `const string&` so non-empty
// inputs cost zero allocation on the hot path.
inline const std::string& IssuerLabelOrUnknown(const std::string& issuer) {
    static const std::string kUnknown{"<unknown>"};
    return issuer.empty() ? kUnknown : issuer;
}

}  // namespace AUTH_NAMESPACE
