#pragma once

#include <string>
#include <map>
#include <algorithm>

struct HttpRequest {
    std::string method;           // "GET", "POST", "PUT", "DELETE", etc.
    std::string url;              // Full URL as received ("/path?query=value")
    std::string path;             // URL path component ("/path")
    std::string query;            // Query string ("query=value")
    int http_major = 1;
    int http_minor = 1;
    std::map<std::string, std::string> headers;  // Header names stored lowercase
    std::string body;
    bool keep_alive = true;
    bool upgrade = false;         // Connection: Upgrade (for WebSocket)
    size_t content_length = 0;
    bool headers_complete = false; // True when headers are parsed (body may still be pending)
    bool complete = false;        // True when full request has been parsed

    // Case-insensitive header lookup
    std::string GetHeader(const std::string& name) const {
        std::string lower = name;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        auto it = headers.find(lower);
        return (it != headers.end()) ? it->second : "";
    }

    bool HasHeader(const std::string& name) const {
        std::string lower = name;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        return headers.find(lower) != headers.end();
    }

    // Reset for reuse (keep-alive pipelining)
    void Reset() {
        method.clear();
        url.clear();
        path.clear();
        query.clear();
        http_major = 1;
        http_minor = 1;
        headers.clear();
        body.clear();
        keep_alive = true;
        upgrade = false;
        content_length = 0;
        headers_complete = false;
        complete = false;
    }
};
