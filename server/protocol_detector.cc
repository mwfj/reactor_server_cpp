#include "http2/protocol_detector.h"

ProtocolDetector::Protocol ProtocolDetector::DetectFromAlpn(const std::string& alpn_protocol) {
    if (alpn_protocol == HTTP2_CONSTANTS::ALPN_H2) {
        return Protocol::HTTP2;
    }
    // "http/1.1", empty, or anything else → HTTP/1.x
    return Protocol::HTTP1;
}

ProtocolDetector::Protocol ProtocolDetector::DetectFromData(const char* data, size_t len) {
    if (len < HTTP2_CONSTANTS::CLIENT_PREFACE_LEN) {
        return Protocol::UNKNOWN;
    }
    if (std::memcmp(data, HTTP2_CONSTANTS::CLIENT_PREFACE,
                    HTTP2_CONSTANTS::CLIENT_PREFACE_LEN) == 0) {
        return Protocol::HTTP2;
    }
    return Protocol::HTTP1;
}
