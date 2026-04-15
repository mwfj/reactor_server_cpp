#include "auth/jwt_decode.h"

namespace auth {

namespace {

// Base64url alphabet (RFC 4648 §5): A-Z, a-z, 0-9, '-', '_'.
// std lookup table for decode: -1 means invalid.
int8_t DecodeChar(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

const char kEncodeTable[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

}  // namespace

std::string Base64UrlDecode(const std::string& input) {
    std::string out;
    if (input.empty()) return out;

    // 4 input chars -> 3 output bytes. Pad length to a multiple of 4 logically,
    // but we don't need literal '=' chars — we just track how many bytes the
    // final group produces.
    size_t n = input.size();
    size_t remainder = n % 4;
    if (remainder == 1) return {};  // Invalid length

    out.reserve((n * 3) / 4 + 2);

    uint32_t buf = 0;
    int bits = 0;
    for (size_t i = 0; i < n; ++i) {
        int v = DecodeChar(static_cast<unsigned char>(input[i]));
        if (v < 0) return {};  // Invalid char
        buf = (buf << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((buf >> bits) & 0xFF));
        }
    }
    // Any remaining `bits` < 8 are the padding (discarded).
    return out;
}

std::string Base64UrlEncode(const std::string& input) {
    std::string out;
    if (input.empty()) return out;
    out.reserve(((input.size() + 2) / 3) * 4);

    size_t i = 0;
    while (i + 3 <= input.size()) {
        uint32_t v = (static_cast<uint8_t>(input[i]) << 16) |
                     (static_cast<uint8_t>(input[i + 1]) << 8) |
                      static_cast<uint8_t>(input[i + 2]);
        out.push_back(kEncodeTable[(v >> 18) & 0x3F]);
        out.push_back(kEncodeTable[(v >> 12) & 0x3F]);
        out.push_back(kEncodeTable[(v >> 6) & 0x3F]);
        out.push_back(kEncodeTable[v & 0x3F]);
        i += 3;
    }
    size_t rem = input.size() - i;
    if (rem == 1) {
        uint32_t v = static_cast<uint8_t>(input[i]);
        out.push_back(kEncodeTable[(v >> 2) & 0x3F]);
        out.push_back(kEncodeTable[(v << 4) & 0x3F]);
    } else if (rem == 2) {
        uint32_t v = (static_cast<uint8_t>(input[i]) << 8) |
                      static_cast<uint8_t>(input[i + 1]);
        out.push_back(kEncodeTable[(v >> 10) & 0x3F]);
        out.push_back(kEncodeTable[(v >> 4) & 0x3F]);
        out.push_back(kEncodeTable[(v << 2) & 0x3F]);
    }
    return out;
}

bool Decode(const std::string& token, JwtDecoded& out, std::string& err_out) {
    out = {};
    if (token.empty()) {
        err_out = "empty token";
        return false;
    }
    if (token.size() > MAX_JWT_BYTES) {
        err_out = "token exceeds MAX_JWT_BYTES";
        return false;
    }

    // Split on '.' — must produce exactly 3 segments for a signed JWT.
    size_t dot1 = token.find('.');
    if (dot1 == std::string::npos) {
        err_out = "token has no '.' separator (not a JWT)";
        return false;
    }
    size_t dot2 = token.find('.', dot1 + 1);
    if (dot2 == std::string::npos) {
        err_out = "token has fewer than 3 segments (may be alg=none — rejected)";
        return false;
    }
    // Reject a 4th segment.
    if (token.find('.', dot2 + 1) != std::string::npos) {
        err_out = "token has more than 3 '.' separators";
        return false;
    }

    out.header_raw_b64 = token.substr(0, dot1);
    out.payload_raw_b64 = token.substr(dot1 + 1, dot2 - dot1 - 1);
    out.signature_raw_b64 = token.substr(dot2 + 1);
    out.signing_input = token.substr(0, dot2);

    if (out.header_raw_b64.empty() || out.payload_raw_b64.empty() ||
        out.signature_raw_b64.empty()) {
        err_out = "token has empty segment(s)";
        return false;
    }

    std::string header_json = Base64UrlDecode(out.header_raw_b64);
    if (header_json.empty()) {
        err_out = "header base64url decode failed";
        return false;
    }
    std::string payload_json = Base64UrlDecode(out.payload_raw_b64);
    if (payload_json.empty()) {
        err_out = "payload base64url decode failed";
        return false;
    }

    nlohmann::json header_parsed;
    try {
        header_parsed = nlohmann::json::parse(header_json);
    } catch (const std::exception& e) {
        err_out = "header JSON parse failed";
        return false;
    }
    try {
        out.payload = nlohmann::json::parse(payload_json);
    } catch (const std::exception& e) {
        err_out = "payload JSON parse failed";
        return false;
    }

    // Header field extraction (all optional from this layer's perspective).
    if (header_parsed.is_object()) {
        if (header_parsed.contains("alg") && header_parsed["alg"].is_string()) {
            out.alg = header_parsed["alg"].get<std::string>();
        }
        if (header_parsed.contains("kid") && header_parsed["kid"].is_string()) {
            out.kid = header_parsed["kid"].get<std::string>();
        }
        if (header_parsed.contains("typ") && header_parsed["typ"].is_string()) {
            out.typ = header_parsed["typ"].get<std::string>();
        }
    } else {
        err_out = "header is not a JSON object";
        return false;
    }

    if (out.alg.empty()) {
        err_out = "header `alg` is missing or not a string";
        return false;
    }

    return true;
}

}  // namespace auth
