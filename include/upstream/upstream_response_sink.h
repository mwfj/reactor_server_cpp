#pragma once

#include "upstream/upstream_response_head.h"

namespace UPSTREAM_CALLBACKS_NAMESPACE {

class UpstreamResponseSink {
public:
    virtual ~UpstreamResponseSink() = default;

    virtual bool OnHeaders(const UpstreamResponseHead& head) = 0;
    virtual bool OnBodyChunk(const char* data, size_t len) = 0;
    // Trailing HEADERS block. Codecs MAY elide an empty trailers block
    // (RFC 9113 §8.1 allows it on H2; the H2 codec does so today) — sinks
    // that need a "block arrived" signal regardless of payload should
    // observe stream completion through OnComplete instead. Default impl
    // is a no-op so sinks uninterested in trailers don't need to override.
    virtual void OnTrailers(
        const std::vector<std::pair<std::string, std::string>>&) {}
    virtual void OnComplete() = 0;
    virtual void OnError(int error_code, const std::string& message) = 0;
};

}  // namespace UPSTREAM_CALLBACKS_NAMESPACE
