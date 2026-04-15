#pragma once

#include "common.h"

namespace UPSTREAM_CALLBACKS_NAMESPACE {

struct UpstreamResponseHead {
    enum class Framing {
        CONTENT_LENGTH,
        CHUNKED,
        EOF_TERMINATED,
        NO_BODY,
    };

    int status_code = 0;
    std::string status_reason;
    int http_major = 1;
    int http_minor = 1;
    std::vector<std::pair<std::string, std::string>> headers;
    bool keep_alive = true;
    Framing framing = Framing::NO_BODY;
    int64_t expected_length = -1;
};

}  // namespace UPSTREAM_CALLBACKS_NAMESPACE
