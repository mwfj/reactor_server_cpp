#pragma once

#include "upstream/upstream_response_head.h"

namespace UPSTREAM_CALLBACKS_NAMESPACE {

class UpstreamResponseSink {
public:
    virtual ~UpstreamResponseSink() = default;

    virtual bool OnHeaders(const UpstreamResponseHead& head) = 0;
    virtual bool OnBodyChunk(const char* data, size_t len) = 0;
    virtual void OnTrailers(
        const std::vector<std::pair<std::string, std::string>>&) {}
    virtual void OnComplete() = 0;
    virtual void OnError(int error_code, const std::string& message) = 0;
};

}  // namespace UPSTREAM_CALLBACKS_NAMESPACE
