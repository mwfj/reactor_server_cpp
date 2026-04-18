#include "auth/token_hasher.h"

#include "log/logger.h"
#include "jwt-cpp/base.h"
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <cstring>
#include <cstdlib>

namespace AUTH_NAMESPACE {

namespace {

constexpr size_t TRUNCATED_BYTES = 16;   // 128-bit truncation of HMAC-SHA256
constexpr size_t SHORT_KEY_BYTES = 32;

std::string HexEncode(const unsigned char* bytes, size_t len) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out[2 * i]     = kHex[bytes[i] >> 4];
        out[2 * i + 1] = kHex[bytes[i] & 0x0F];
    }
    return out;
}

}  // namespace

TokenHasher::TokenHasher(const std::string& key) : key_(key) {
    if (key_.empty()) {
        throw std::invalid_argument("TokenHasher: key must not be empty");
    }
    if (key_.size() < SHORT_KEY_BYTES) {
        logging::Get()->warn("TokenHasher: HMAC key is shorter than {} bytes "
                             "({}); zero-padded by HMAC. Prefer 32-byte keys.",
                             SHORT_KEY_BYTES, key_.size());
    }
}

std::optional<std::string> TokenHasher::Hash(const std::string& token) const {
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int out_len = 0;
    auto* md = EVP_sha256();

    const unsigned char* key_bytes =
        reinterpret_cast<const unsigned char*>(key_.data());
    const unsigned char* msg_bytes =
        reinterpret_cast<const unsigned char*>(token.data());

    if (!HMAC(md, key_bytes, static_cast<int>(key_.size()),
              msg_bytes, token.size(), out, &out_len)) {
        logging::Get()->error("TokenHasher::Hash: HMAC failed");
        return std::nullopt;
    }
    if (out_len < TRUNCATED_BYTES) {
        logging::Get()->error("TokenHasher::Hash: HMAC produced only {} bytes, "
                              "expected >= {}", out_len, TRUNCATED_BYTES);
        return std::nullopt;
    }
    return HexEncode(out, TRUNCATED_BYTES);
}

std::string GenerateHmacKey() {
    unsigned char buf[SHORT_KEY_BYTES];
    if (RAND_bytes(buf, static_cast<int>(sizeof(buf))) != 1) {
        throw std::runtime_error(
            "GenerateHmacKey: RAND_bytes failed — refusing to proceed with a "
            "predictable cache key");
    }
    return std::string(reinterpret_cast<char*>(buf), sizeof(buf));
}

std::string LoadHmacKeyFromEnv(const std::string& env_var_name) {
    if (env_var_name.empty()) return {};
    const char* val = std::getenv(env_var_name.c_str());
    if (!val) return {};
    std::string raw(val);
    if (raw.empty()) return {};

    // Auto-detect base64url: operators typically store base64url-encoded keys
    // because raw 32-byte binaries mangle through `.env` transport.
    //
    // Accept THREE equivalent base64url forms for a 32-byte key:
    //   1. RFC 7515 §2 standard: 43 chars, NO padding  (e.g. "QUFB...QUE")
    //   2. jwt-cpp native:       46 chars, "%3d" padding (percent-encoded '=')
    //   3. Legacy base64:        44 chars, "=" padding
    // All three decode to the same 32 bytes.
    //
    // The trick: jwt-cpp's `decode<base64url>` expects form (2) — the
    // alphabet's fill() returns "%3d", not "=". Form (1) throws because
    // `(size + 0) % 4 != 0`. Form (3) throws because "=" is not in the
    // base64url alphabet. We normalize by stripping BOTH padding forms,
    // then re-padding with the form jwt-cpp wants. This matches how
    // jwt-cpp itself handles JWT segments (see jwt.h:682, 1055, 2985 —
    // `decode<base64url>(pad<base64url>(token))`).
    //
    // Result is accepted ONLY when it yields EXACTLY 32 bytes, per §5.1
    // contract. Any other decoded length means the env value wasn't a
    // base64url 32-byte key and we fall back to raw.
    //
    // Exception containment (design spec §9 item 16): jwt::base::decode
    // throws std::runtime_error on invalid input (illegal chars, bad length).
    // Catch at this boundary and fall through to the raw-bytes interpretation
    // — a malformed env value must not propagate as an exception into
    // AuthManager::Start(), which would abort startup.
    // TRAILING-only padding strip (review round: avoid silent truncation
    // of raw env keys that happen to contain padding sequences in the
    // middle). jwt::base::trim<alphabet> uses find() to locate the fill
    // string — which strips at the FIRST occurrence, not just the tail.
    // So a raw key like "AAAA...%3dRAW" (perfectly valid as a binary
    // HMAC secret) would get truncated at the middle "%3d" and then
    // potentially decode to 32 bytes, silently changing the operator's
    // configured HMAC key. We strip only real trailing padding below,
    // then skip jwt-cpp's trim entirely and feed the candidate directly
    // into pad() + decode() — pad() adds correct trailing padding if
    // needed, and decode() rejects obviously-invalid input by throwing,
    // which our catch handles via the raw-bytes fallback.
    std::string candidate = raw;
    // Strip trailing '=' (standard base64 padding).
    while (!candidate.empty() && candidate.back() == '=') candidate.pop_back();
    // Strip trailing '%3d' (jwt-cpp's URL-safe escaped padding). MUST
    // happen after the '=' strip in case an operator's pad sequence
    // mixes forms (unlikely but harmless).
    while (candidate.size() >= 3 &&
           candidate.compare(candidate.size() - 3, 3, "%3d") == 0) {
        candidate.resize(candidate.size() - 3);
    }

    // Step 2: try base64url decoding (the common case — `openssl rand
    // -base64 32 | tr '+/' '-_' | tr -d '='` style keys).
    try {
        std::string decoded = jwt::base::decode<jwt::alphabet::base64url>(
            jwt::base::pad<jwt::alphabet::base64url>(candidate));
        if (decoded.size() == 32) {
            // Silent-swap corner case: an operator's raw 43-char key
            // composed entirely of base64url alphabet chars [A-Za-z0-9_-]
            // will be interpreted as encoded rather than raw. HMAC security
            // is preserved either way (both forms give 32 bytes of key
            // material), but the derived key differs between
            // interpretations. Log at debug — the base64url path is the
            // COMMON case (operators running `openssl rand -base64 32` and
            // stripping '=' or using the url-safe variant), so info-level
            // would spam every startup. Operators who suspect a raw/decoded
            // mismatch can enable debug logging to disambiguate.
            logging::Get()->debug(
                "LoadHmacKeyFromEnv: env var '{}' interpreted as "
                "base64url-encoded 32-byte key (decoded). If you intended "
                "a raw 43-char key, either base64url-encode it explicitly "
                "or pick a length other than 43/44 chars.",
                env_var_name);
            return decoded;
        }
    } catch (const std::exception& e) {
        logging::Get()->debug("LoadHmacKeyFromEnv: base64url decode failed "
                              "for env var '{}' ({}); trying standard base64",
                              env_var_name, e.what());
    }

    // Step 3: standard base64 fallback (for operators who ran
    // `openssl rand -base64 32`, which emits the '+' / '/' alphabet — NOT
    // base64url). base64url's alphabet excludes '+' and '/', so the first
    // attempt above throws on those characters and we fall through here.
    // The decoded bytes are identical as long as the key is 32 bytes.
    // Same rationale for skipping jwt-cpp's trim — we feed the candidate
    // directly into pad()+decode().
    try {
        std::string decoded_b64 = jwt::base::decode<jwt::alphabet::base64>(
            jwt::base::pad<jwt::alphabet::base64>(candidate));
        if (decoded_b64.size() == 32) {
            logging::Get()->debug(
                "LoadHmacKeyFromEnv: env var '{}' interpreted as "
                "standard-base64-encoded 32-byte key (decoded).",
                env_var_name);
            return decoded_b64;
        }
    } catch (const std::exception& e) {
        logging::Get()->debug("LoadHmacKeyFromEnv: standard base64 decode "
                              "also failed for env var '{}' ({}); falling "
                              "back to raw bytes interpretation",
                              env_var_name, e.what());
    }
    return raw;
}

}  // namespace AUTH_NAMESPACE
