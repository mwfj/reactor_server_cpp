#pragma once

#include "common.h"
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

    // Compute the cache-key hex string for a token. Returns 32 hex chars
    // (128-bit truncation of HMAC-SHA256). Thread-safe — OpenSSL's HMAC
    // via EVP is reentrant given an independent per-call context.
    std::string Hash(const std::string& token) const;

    // Return true when the hasher is initialized with a non-empty key.
    bool ready() const { return !key_.empty(); }

private:
    std::string key_;  // Raw 32-byte (or larger) HMAC key material
};

// Generate a fresh 32-byte random key via OpenSSL's RAND_bytes.
// Returns a binary string of length 32. Throws if RAND_bytes fails.
std::string GenerateHmacKey();

// Load key material from an environment variable by name. The env value is
// interpreted as raw bytes (NOT base64). Returns an empty string when the
// env var is unset or empty.
std::string LoadHmacKeyFromEnv(const std::string& env_var_name);

}  // namespace auth
