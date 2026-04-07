#pragma once

#include "common.h"
// <unordered_map> provided by common.h

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

    // Route parameters populated by HttpRouter during dispatch.
    // Mutable because routing is an output of dispatch, not parser input.
    mutable std::unordered_map<std::string, std::string> params;

    // Index of the dispatcher (event loop) handling this request's connection.
    // Set by the connection handler; used for upstream pool partition affinity.
    // Mutable because it's set at dispatch time, not parser time.
    mutable int dispatcher_index = -1;

    // Peer connection metadata -- set by the connection handler at dispatch time.
    // Mutable because they are populated during dispatch, not during parsing.
    mutable std::string client_ip;    // Peer remote address (from ConnectionHandler::ip_addr())
    mutable bool client_tls = false;  // True if downstream connection has TLS
    mutable int client_fd = -1;       // Client socket fd (for log correlation)

    // Case-insensitive header lookup
    std::string GetHeader(const std::string& name) const {
        std::string lower = name;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c){ return std::tolower(c); });
        auto it = headers.find(lower);
        return (it != headers.end()) ? it->second : "";
    }

    bool HasHeader(const std::string& name) const {
        std::string lower = name;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c){ return std::tolower(c); });
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
        params.clear();
        dispatcher_index = -1;
        client_ip.clear();
        client_tls = false;
        client_fd = -1;
    }
};
