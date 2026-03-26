#pragma once

#include "http2/http2_constants.h"
#include <string>
#include <cstddef>
#include <cstring>

class ProtocolDetector {
public:
    enum class Protocol {
        UNKNOWN,     // Not enough data to determine
        HTTP1,       // HTTP/1.0 or HTTP/1.1
        HTTP2        // HTTP/2
    };

    // Detect protocol from ALPN result (TLS connections).
    // Returns HTTP2 if alpn == "h2", HTTP1 if "http/1.1" or empty.
    static Protocol DetectFromAlpn(const std::string& alpn_protocol);

    // Detect protocol from first bytes of cleartext connection.
    // Returns UNKNOWN if fewer than CLIENT_PREFACE_LEN bytes available.
    // Returns HTTP2 if first 24 bytes match the HTTP/2 client preface.
    // Returns HTTP1 otherwise.
    static Protocol DetectFromData(const char* data, size_t len);

    // Minimum bytes needed for cleartext detection
    static constexpr size_t MinDetectionBytes() {
        return HTTP2_CONSTANTS::CLIENT_PREFACE_LEN;
    }
};
