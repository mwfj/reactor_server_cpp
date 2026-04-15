#pragma once

#include "common.h"
#include <nlohmann/json.hpp>
// <string>, <vector>, <cstdint> via common.h

namespace auth {

// Decoded JWT components. Fields are populated to the extent they were
// present in the token; callers should assume nothing is guaranteed beyond
// what Decode() actually parsed.
//
// JwtDecoded does NOT verify signatures — it parses structure only. The
// raw header/payload bytes (without base64url decoding) are preserved in
// `header_raw_b64` and `payload_raw_b64` so that the signature verifier can
// operate on the signing input (`header_raw_b64 + "." + payload_raw_b64`).
struct JwtDecoded {
    std::string header_raw_b64;        // "eyJ..."
    std::string payload_raw_b64;       // "eyJ..."
    std::string signature_raw_b64;     // "abc..."  (may be empty for alg=none — which we reject)
    std::string signing_input;         // header_raw_b64 + "." + payload_raw_b64

    // Parsed header fields (must be present for a well-formed signed JWT).
    std::string alg;                   // e.g. "RS256"
    std::string kid;                   // Key ID from JWKS (may be empty for single-key JWKS)
    std::string typ;                   // Usually "JWT"

    // Decoded payload as JSON (for claim lookups). Ownership kept here.
    nlohmann::json payload;
};

// JWT size limit (design §9 item 5). A bearer token exceeding this is
// rejected at decode time.
constexpr size_t MAX_JWT_BYTES = 8192;

// Decode a compact-serialized JWT (three `.`-separated base64url segments).
// Returns true on success. On failure, returns false and stores a short
// diagnostic in err_out.
//
// This function:
//   - Validates overall size (<= MAX_JWT_BYTES)
//   - Splits into header/payload/signature base64url segments
//   - base64url-decodes header and payload
//   - parses both as JSON
//   - extracts alg / kid / typ from header
//
// It does NOT:
//   - Verify the signature (that's JwtVerifier)
//   - Validate claims (exp, aud, iss — handler-layer concerns)
//   - Reject alg=none (that's the verifier's alg-allowlist, with per-issuer
//     policy — but Decode does reject the obviously-invalid 2-segment shape
//     which `alg: none` uses).
bool Decode(const std::string& token, JwtDecoded& out, std::string& err_out);

// Base64url decode (RFC 7515 §2). Input may omit padding. Returns empty on
// invalid input.
std::string Base64UrlDecode(const std::string& input);

// Base64url encode (RFC 7515 §2). No padding in output.
std::string Base64UrlEncode(const std::string& input);

}  // namespace auth
