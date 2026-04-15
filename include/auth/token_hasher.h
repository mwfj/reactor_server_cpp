#pragma once

#include "common.h"
#include <optional>
// <string>, <cstdint> via common.h

namespace auth {

// Keyed HMAC-SHA256 hasher used to derive cache keys for the introspection
// cache. Takes raw bearer tokens and returns a 128-bit (16-byte) truncated
// HMAC, hex-encoded for convenient map keying.
//
// Security rationale: the introspection cache stores validated claim bundles
// keyed by an opaque function of the bearer token. Using a raw SHA-256 would
// let an attacker with process-memory access enumerate tokens by hashing
// candidates. HMAC with a per-process random key prevents enumeration even
// on memory capture — the attacker would need the key too.
//
// The key is process-local, generated at AuthManager::Start() time from the
// env var named by `auth.hmac_cache_key_env` (if set) or from
// RAND_bytes() otherwise. On restart, a new key is generated and the cache
// is empty — that is the correct behavior; cache-key secrecy does not need
// to persist across restarts, and the cache rebuilds quickly.
class TokenHasher {
public:
    // Initialize with a 32-byte key. Smaller keys are accepted (zero-padded
    // internally by HMAC) but a warn is logged; larger keys are hashed down
    // to 32 bytes (standard HMAC behavior). Throws std::invalid_argument
    // when key is empty.
    explicit TokenHasher(const std::string& key);

    // Compute the cache-key hex string for a token. On success returns
    // 32 hex chars (128-bit truncation of HMAC-SHA256). Returns std::nullopt
    // on HMAC failure — callers MUST treat nullopt as "uncacheable" and
    // fall through to live introspection. Never fall back to a fixed
    // sentinel value: two distinct tokens that both hit an HMAC failure
    // would collide on the same cache key, which is a confidentiality bug
    // (a leaked-claims cache hit for one token served to another).
    //
    // Thread-safe: uses OpenSSL's one-shot HMAC() API, which allocates its
    // own EVP context per call and is reentrant.
    std::optional<std::string> Hash(const std::string& token) const;

    // Return true when the hasher is initialized with a non-empty key.
    bool ready() const { return !key_.empty(); }

private:
    std::string key_;  // Raw 32-byte (or larger) HMAC key material
};

// Generate a fresh 32-byte random key via OpenSSL's RAND_bytes.
// Returns a binary string of length 32. Throws if RAND_bytes fails.
std::string GenerateHmacKey();

// Load key material from an environment variable by name. The env value is
// interpreted using auto-detect:
//   1. If the value is valid base64url (no padding) AND decodes to exactly
//      32 bytes, the decoded bytes are used. This is the safer shell-transport
//      form recommended by the design spec (§5.1) because raw 32-byte keys
//      often contain non-printable bytes that mangle through `.env` files.
//   2. Otherwise, the value is used as raw bytes.
//
// Returns an empty string when the env var is unset or empty.
std::string LoadHmacKeyFromEnv(const std::string& env_var_name);

}  // namespace auth
