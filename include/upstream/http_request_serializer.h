#pragma once

#include "common.h"
// <string>, <map> provided by common.h

class HttpRequestSerializer {
public:
    // Serialize an outgoing HTTP/1.1 request to wire format.
    // Headers must already be rewritten (hop-by-hop stripped, forwarded headers added).
    // Returns the complete wire-format string ready for SendRaw().
    //
    // `path` is the URL path component (e.g., "/users/123").
    // `query` is the query string WITHOUT the leading '?' (e.g., "active=true&page=2").
    // If `query` is non-empty, it is appended as "?query" in the request-line.
    // This preserves the HttpRequest::path / HttpRequest::query split from the
    // inbound parser -- the serializer reassembles them for the upstream wire format.
    static std::string Serialize(
        const std::string& method,
        const std::string& path,
        const std::string& query,
        const std::map<std::string, std::string>& headers,
        const std::string& body);

private:
    // Buffer size estimate for initial reserve to reduce reallocations
    static constexpr size_t INITIAL_BUFFER_RESERVE = 512;
};
