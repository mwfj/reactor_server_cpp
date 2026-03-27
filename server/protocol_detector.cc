#include "http2/protocol_detector.h"

ProtocolDetector::Protocol ProtocolDetector::DetectFromAlpn(const std::string& alpn_protocol) {
    if (alpn_protocol == HTTP2_CONSTANTS::ALPN_H2) {
        return Protocol::HTTP2;
    }
    // "http/1.1", empty, or anything else → HTTP/1.x
    return Protocol::HTTP1;
}

ProtocolDetector::Protocol ProtocolDetector::DetectFromData(const char* data, size_t len) {
    if (len >= HTTP2_CONSTANTS::CLIENT_PREFACE_LEN) {
        if (std::memcmp(data, HTTP2_CONSTANTS::CLIENT_PREFACE,
                        HTTP2_CONSTANTS::CLIENT_PREFACE_LEN) == 0) {
            return Protocol::HTTP2;
        }
        return Protocol::HTTP1;
    }

    // Fewer than 24 bytes: check if the available bytes are a prefix of
    // the HTTP/2 client preface. If they diverge, it's definitely HTTP/1.
    // Only return UNKNOWN if every byte so far matches (could still be h2).
    if (len > 0 && std::memcmp(data, HTTP2_CONSTANTS::CLIENT_PREFACE, len) != 0) {
        return Protocol::HTTP1;
    }
    return Protocol::UNKNOWN;
}
