#pragma once

#include "common.h"

namespace UPSTREAM_CALLBACKS_NAMESPACE {

struct UpstreamResponseHead {
    enum class Framing {
        // Body length is known up-front. `expected_length >= 0`.
        CONTENT_LENGTH,
        // Upstream used Transfer-Encoding: chunked. Body callbacks receive
        // decoded chunk bytes only (chunk framing already stripped).
        CHUNKED,
        // Body ends only when the upstream TCP connection closes cleanly.
        EOF_TERMINATED,
        // Response has no body (e.g. HEAD, 1xx, 204, 304).
        NO_BODY,
    };

    int status_code = 0;
    std::string status_reason;
    int http_major = 1;
    int http_minor = 1;
    std::vector<std::pair<std::string, std::string>> headers;
    bool keep_alive = true;
    // Framing-derived body expectation for the final response.
    Framing framing = Framing::NO_BODY;
    // Expected body length when `framing == CONTENT_LENGTH`.
    // Sentinel -1 means "unknown / not applicable".
    int64_t expected_length = -1;
};

}  // namespace UPSTREAM_CALLBACKS_NAMESPACE
