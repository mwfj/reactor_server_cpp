#include "auth/jwt_verifier.h"

#include "auth/issuer.h"
#include "auth/auth_claims.h"
#include "log/logger.h"
#include "log/log_utils.h"

#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/nlohmann-json/traits.h>

#include <nlohmann/json.hpp>

// ---------------------------------------------------------------------------
// JwtVerifier — thin wrapper around jwt-cpp. Every call at the library
// boundary is wrapped in try/catch; outcomes are translated into
// VerifyResult by the Reject / Allow factories in auth_result.h.
//
// Hot-path cost: decode (~microseconds base64 + JSON), JWKS lookup (map
// hit), RSA/ECDSA verify (~30µs on modern hardware). No I/O — the JWKS
// cache serves keys from memory, and misses trigger an async refresh
// that surfaces as UNDETERMINED to the CURRENT request.
// ---------------------------------------------------------------------------

namespace AUTH_NAMESPACE {

namespace {

constexpr size_t MAX_TOKEN_BYTES = 8192;  // §9 item 5.

struct DecodedHead {
    std::string alg;
    std::string kid;
};

// Decode the JWT header + payload without verifying the signature. Returns
// an empty optional on ANY decode failure (malformed, oversized, bad
// base64, bad JSON). Exception-contained per §9 item 16.
std::optional<jwt::decoded_jwt<jwt::traits::nlohmann_json>>
DecodeSafe(const std::string& token, const std::string& issuer_name) {
    if (token.empty() || token.size() > MAX_TOKEN_BYTES) {
        logging::Get()->info(
            "auth_deny reason=token_size_out_of_range issuer={} size={}",
            issuer_name, token.size());
        return std::nullopt;
    }
    try {
        return jwt::decode<jwt::traits::nlohmann_json>(token);
    } catch (const std::exception& ex) {
        logging::Get()->info(
            "auth_deny reason=decode_failed issuer={} err={}",
            issuer_name, ex.what());
        return std::nullopt;
    } catch (...) {
        logging::Get()->info(
            "auth_deny reason=decode_failed_unknown issuer={}", issuer_name);
        return std::nullopt;
    }
}

// Read (alg, kid) from a decoded JWT header. Both are wrapped in
// try/catch because jwt-cpp throws on missing / mis-typed claims.
DecodedHead ReadHead(
        const jwt::decoded_jwt<jwt::traits::nlohmann_json>& decoded,
        const std::string& issuer_name) {
    DecodedHead h;
    try {
        if (decoded.has_header_claim("alg")) {
            h.alg = decoded.get_header_claim("alg").as_string();
        }
    } catch (const std::exception& ex) {
        logging::Get()->info(
            "auth_deny reason=alg_read_failed issuer={} err={}",
            issuer_name, ex.what());
    } catch (...) { /* swallow */ }
    try {
        if (decoded.has_header_claim("kid")) {
            h.kid = decoded.get_header_claim("kid").as_string();
        }
    } catch (const std::exception& ex) {
        logging::Get()->debug(
            "auth kid_read_failed issuer={} err={}",
            issuer_name, ex.what());
    } catch (...) { /* swallow */ }
    return h;
}

// Extract the payload JSON, safely. jwt-cpp's get_payload_json throws on
// internal JSON issues that shouldn't happen for a successfully-decoded
// token — but we still catch belt-and-suspenders.
bool ExtractPayload(
        const jwt::decoded_jwt<jwt::traits::nlohmann_json>& decoded,
        nlohmann::json& out,
        const std::string& issuer_name) {
    try {
        out = decoded.get_payload_json();
        return true;
    } catch (const std::exception& ex) {
        logging::Get()->warn(
            "auth payload_extract_failed issuer={} err={}",
            issuer_name, ex.what());
    } catch (...) {
        logging::Get()->warn(
            "auth payload_extract_failed_unknown issuer={}", issuer_name);
    }
    return false;
}

// Construct and invoke the verifier with a single allowed (algorithm,
// PEM) pair. Wrapped in try/catch at each boundary. We NEVER add
// `jwt::algorithm::none{}` to the verifier — per §9 item 11, that's a
// property of THIS code, not of the library.
//
// Returns a VerifyResult describing the outcome.
VerifyResult VerifyWithAlg(
        const jwt::decoded_jwt<jwt::traits::nlohmann_json>& decoded,
        const std::string& alg,
        const std::string& pem,
        const std::string& issuer_url,
        int leeway_sec,
        const std::string& issuer_name) {
    try {
        auto v = jwt::verify<jwt::traits::nlohmann_json>()
                     .with_issuer(issuer_url)
                     .leeway(leeway_sec > 0 ? leeway_sec : 0);

        if (alg == "RS256") {
            v.allow_algorithm(jwt::algorithm::rs256(pem, "", "", ""));
        } else if (alg == "RS384") {
            v.allow_algorithm(jwt::algorithm::rs384(pem, "", "", ""));
        } else if (alg == "RS512") {
            v.allow_algorithm(jwt::algorithm::rs512(pem, "", "", ""));
        } else if (alg == "ES256") {
            v.allow_algorithm(jwt::algorithm::es256(pem, "", "", ""));
        } else if (alg == "ES384") {
            v.allow_algorithm(jwt::algorithm::es384(pem, "", "", ""));
        } else {
            // Caller filtered already; defense-in-depth. Not invalid_token
            // here — this is a verifier-build issue.
            return VerifyResult::Undetermined("verifier_unknown_algorithm");
        }

        std::error_code ec;
        try {
            v.verify(decoded, ec);
        } catch (const std::exception& ex) {
            logging::Get()->warn(
                "auth_deny reason=verify_threw issuer={} err={}",
                issuer_name, ex.what());
            return VerifyResult::InvalidToken(
                "verification error", "verify_threw");
        } catch (...) {
            logging::Get()->warn(
                "auth_deny reason=verify_threw_unknown issuer={}",
                issuer_name);
            return VerifyResult::InvalidToken(
                "verification error", "verify_threw");
        }
        if (ec) {
            // jwt-cpp populates the error_code with a specific reason on
            // failure (signature, expiry, nbf, issuer mismatch, etc.).
            const auto& msg = ec.message();
            std::string log_label = "verify_failed";
            if (msg.find("expired") != std::string::npos ||
                msg.find("not yet valid") != std::string::npos) {
                log_label = "token_expired_or_nbf";
            } else if (msg.find("signature") != std::string::npos) {
                log_label = "signature_invalid";
            } else if (msg.find("issuer") != std::string::npos) {
                log_label = "issuer_mismatch";
            }
            logging::Get()->info(
                "auth_deny reason={} issuer={} detail={}",
                log_label, issuer_name, msg);
            return VerifyResult::InvalidToken(msg, log_label);
        }
        return VerifyResult::Allow();
    } catch (const std::exception& ex) {
        // allow_algorithm() can throw if the PEM is malformed — that's
        // a JWKS corruption we already accepted, so treat as UNDETERMINED
        // and let a refresh try again on the next request.
        logging::Get()->warn(
            "auth verifier_build_failed issuer={} alg={} err={}",
            issuer_name, alg, ex.what());
        return VerifyResult::Undetermined("verifier_build_failed");
    } catch (...) {
        logging::Get()->warn(
            "auth verifier_build_failed_unknown issuer={} alg={}",
            issuer_name, alg);
        return VerifyResult::Undetermined("verifier_build_failed");
    }
}

// Check that `iss` in the payload matches the configured issuer URL.
// jwt-cpp's `with_issuer` already enforces this, but we keep the check
// explicit here for defense-in-depth and for the "peek the iss claim
// for logging" path.
bool CheckIssuerMatch(const nlohmann::json& payload,
                       const std::string& expected_iss) {
    auto it = payload.find("iss");
    if (it == payload.end() || !it->is_string()) return false;
    return it->get<std::string>() == expected_iss;
}

}  // namespace

std::optional<std::string> JwtVerifier::PeekIssuer(const std::string& token) {
    if (token.empty() || token.size() > MAX_TOKEN_BYTES) return std::nullopt;
    try {
        auto decoded = jwt::decode<jwt::traits::nlohmann_json>(token);
        nlohmann::json payload;
        try {
            payload = decoded.get_payload_json();
        } catch (...) {
            return std::nullopt;
        }
        auto it = payload.find("iss");
        if (it != payload.end() && it->is_string()) {
            return it->get<std::string>();
        }
        return std::nullopt;
    } catch (const std::exception&) {
        return std::nullopt;
    } catch (...) {
        return std::nullopt;
    }
}

VerifyResult JwtVerifier::Verify(const std::string& token,
                                  Issuer& issuer,
                                  const AuthPolicy& policy,
                                  const std::vector<std::string>& claim_keys,
                                  AuthContext& out_ctx) {
    const std::string& issuer_name = issuer.name();

    // Decode header + payload. Malformed / oversized / non-JSON: 401
    // invalid_request.
    auto decoded_opt = DecodeSafe(token, issuer_name);
    if (!decoded_opt) {
        return VerifyResult::InvalidRequest("malformed token", "decode_failed");
    }
    const auto& decoded = *decoded_opt;

    auto head = ReadHead(decoded, issuer_name);
    auto snap = issuer.LoadSnapshot();
    if (!snap) {
        logging::Get()->warn(
            "auth_undetermined reason=issuer_not_ready phase=load_snapshot "
            "issuer={}",
            issuer_name);
        return VerifyResult::Undetermined("issuer_not_ready");
    }

    // Algorithm allowlist check — BEFORE any signature work (§9 item 11).
    // "none" is never in the list (ConfigLoader rejects it); still,
    // defense-in-depth: refuse unconditionally.
    if (head.alg.empty()) {
        logging::Get()->info(
            "auth_deny reason=missing_alg issuer={}", issuer_name);
        return VerifyResult::InvalidToken("missing alg header", "missing_alg");
    }
    if (head.alg == "none") {
        logging::Get()->warn(
            "auth_deny reason=alg_none issuer={} (blocked unconditionally)",
            issuer_name);
        return VerifyResult::InvalidToken("alg:none is not allowed",
                                           "alg_none");
    }
    bool alg_allowed = false;
    for (const auto& a : snap->algorithms) {
        if (a == head.alg) { alg_allowed = true; break; }
    }
    if (!alg_allowed) {
        logging::Get()->info(
            "auth_deny reason=alg_not_allowed alg={} issuer={}",
            logging::SanitizeLogValue(head.alg), issuer_name);
        return VerifyResult::InvalidToken("algorithm not allowed",
                                           "alg_not_allowed");
    }

    // Look up the PEM for the kid. A miss schedules an async refresh and
    // returns nullptr — the current request fails with UNDETERMINED.
    int dispatcher_hint = 0;  // Any dispatcher will do for a cache miss.
    auto pem_sp = issuer.LookupKeyByKid(head.kid, dispatcher_hint);
    if (!pem_sp) {
        if (!issuer.IsReady()) {
            logging::Get()->warn(
                "auth_undetermined reason=issuer_not_ready phase=kid_lookup "
                "issuer={} kid={}",
                issuer_name, logging::SanitizeLogValue(head.kid));
            return VerifyResult::Undetermined("issuer_not_ready");
        }
        logging::Get()->info(
            "auth_undetermined reason=unknown_kid issuer={} kid={} "
            "(JWKS refresh scheduled)",
            issuer_name, logging::SanitizeLogValue(head.kid));
        return VerifyResult::Undetermined("unknown_kid");
    }

    // Run the verification. jwt-cpp's `with_issuer` enforces iss==issuer_url
    // as part of the claim checks inside verify(..., ec).
    VerifyResult vr = VerifyWithAlg(decoded, head.alg, *pem_sp,
                                     issuer.issuer_url(), snap->leeway_sec,
                                     issuer_name);
    if (!vr.is_allow()) {
        vr.iss_hint = issuer_name;
        return vr;
    }

    // Extract payload for claim / audience / scope checks.
    nlohmann::json payload;
    if (!ExtractPayload(decoded, payload, issuer_name)) {
        return VerifyResult::InvalidToken("payload extract failed",
                                           "payload_extract_failed");
    }

    // Defense-in-depth issuer check.
    if (!CheckIssuerMatch(payload, issuer.issuer_url())) {
        logging::Get()->info(
            "auth_deny reason=issuer_mismatch_payload issuer={}", issuer_name);
        return VerifyResult::InvalidToken("issuer claim mismatch",
                                           "issuer_mismatch");
    }

    // Audience check. Policy override wins; otherwise any of the issuer's
    // audiences must match.
    const std::string& required_aud = !policy.required_audience.empty()
        ? policy.required_audience
        : std::string();  // policy override takes precedence
    if (!required_aud.empty()) {
        if (!MatchesAudience(payload, required_aud)) {
            logging::Get()->info(
                "auth_deny reason=audience_mismatch issuer={} source=policy",
                issuer_name);
            return VerifyResult::InvalidToken("audience mismatch",
                                               "audience_mismatch");
        }
    } else if (!snap->audiences.empty()) {
        bool any_ok = false;
        for (const auto& aud : snap->audiences) {
            if (MatchesAudience(payload, aud)) { any_ok = true; break; }
        }
        if (!any_ok) {
            logging::Get()->info(
                "auth_deny reason=audience_mismatch issuer={} source=issuer",
                issuer_name);
            return VerifyResult::InvalidToken("audience mismatch",
                                               "audience_mismatch");
        }
    }

    // Required-claim presence check — each entry must exist in the payload.
    for (const auto& c : snap->required_claims) {
        if (!payload.contains(c)) {
            logging::Get()->info(
                "auth_deny reason=missing_required_claim issuer={} claim={}",
                issuer_name, c);
            return VerifyResult::InvalidToken("missing required claim",
                                               "missing_required_claim");
        }
    }

    // Populate AuthContext from the verified payload. `claim_keys` is the
    // union of operator-configured forward.claims_to_headers keys built
    // by AuthManager from its ForwardConfig snapshot; PopulateFromPayload
    // copies exactly those keys into ctx.claims for outbound injection.
    //
    // AuthContext::issuer carries the VERIFIED `iss` claim (the token's
    // actual issuer URL), NOT the configured local alias. jwt-cpp's
    // with_issuer(ic.issuer_url) pre-verification has already bound the
    // payload's `iss` to the configured URL, so PopulateFromPayload's
    // `ctx.issuer = payload["iss"]` write is the validated value that
    // downstream consumers (HeaderRewriter's issuer_header, handlers
    // reading req.auth.issuer) must see. Overwriting with the local
    // alias name (e.g. "google" vs "https://accounts.google.com") would
    // publish the wrong identity to upstreams and break anyone verifying
    // issuer URLs server-side.
    PopulateFromPayload(payload, claim_keys, out_ctx);

    // Scope check against policy.required_scopes.
    if (!HasRequiredScopes(out_ctx.scopes, policy.required_scopes)) {
        std::string joined;
        for (const auto& s : policy.required_scopes) {
            if (!joined.empty()) joined += ' ';
            joined += s;
        }
        logging::Get()->info(
            "auth_deny reason=insufficient_scope issuer={} required=[{}]",
            issuer_name, joined);
        return VerifyResult::InsufficientScope(
            "missing required scope",
            "insufficient_scope:" + joined);
    }

    return VerifyResult::Allow();
}

}  // namespace AUTH_NAMESPACE
