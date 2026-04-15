#include "auth/token_hasher.h"

#include "log/logger.h"
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <cstring>
#include <cstdlib>

namespace auth {

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

std::string TokenHasher::Hash(const std::string& token) const {
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
        return {};
    }
    if (out_len < TRUNCATED_BYTES) {
        logging::Get()->error("TokenHasher::Hash: HMAC produced only {} bytes, "
                              "expected >= {}", out_len, TRUNCATED_BYTES);
        return {};
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
    return std::string(val);
}

}  // namespace auth
