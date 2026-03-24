#pragma once

#include <string>
#include <cstdint>

// RFC 3629 UTF-8 validation with full codepoint range checks:
// - Rejects overlong encodings (e.g., 0xC0 0x80 for U+0000)
// - Rejects surrogates U+D800-U+DFFF
// - Rejects codepoints > U+10FFFF
inline bool IsValidUtf8(const std::string& data) {
    size_t i = 0;
    while (i < data.size()) {
        uint8_t c = static_cast<uint8_t>(data[i]);
        uint32_t codepoint;
        size_t len;

        if (c <= 0x7F) {
            i++; continue;
        } else if ((c & 0xE0) == 0xC0) {
            len = 2;
            if (c < 0xC2) return false;  // overlong
            codepoint = c & 0x1F;
        } else if ((c & 0xF0) == 0xE0) {
            len = 3;
            codepoint = c & 0x0F;
        } else if ((c & 0xF8) == 0xF0) {
            len = 4;
            codepoint = c & 0x07;
        } else {
            return false;  // invalid lead byte
        }

        if (i + len > data.size()) return false;

        for (size_t j = 1; j < len; j++) {
            uint8_t cb = static_cast<uint8_t>(data[i + j]);
            if ((cb & 0xC0) != 0x80) return false;
            codepoint = (codepoint << 6) | (cb & 0x3F);
        }

        // Reject surrogates (U+D800-U+DFFF) and codepoints > U+10FFFF
        if (codepoint >= 0xD800 && codepoint <= 0xDFFF) return false;
        if (codepoint > 0x10FFFF) return false;

        // Reject overlong encodings
        if (len == 3 && codepoint < 0x0800) return false;
        if (len == 4 && codepoint < 0x10000) return false;

        i += len;
    }
    return true;
}
