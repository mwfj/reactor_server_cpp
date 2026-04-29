#pragma once

#include "common.h"

namespace base64_util {

// Base64-encodes the input bytes using OpenSSL with no embedded newline
// (BIO_FLAGS_BASE64_NO_NL). Returns "" on any allocation / encode failure.
// Callers must distinguish empty input from encode failure if that matters.
std::string EncodeNoNewline(const void* data, size_t size);

inline std::string EncodeNoNewline(const std::string& in) {
    return EncodeNoNewline(in.data(), in.size());
}

}  // namespace base64_util
