#pragma once

#include "common.h"
// <string>, <vector>, <utility>, <algorithm> provided by common.h

struct UpstreamResponse {
    int status_code = 0;
    std::string status_reason;
    int http_major = 1;
    int http_minor = 1;
    // Headers stored as ordered vector of pairs -- NOT std::map.
    // This preserves repeated headers (Set-Cookie, WWW-Authenticate, etc.)
    // which are legally repeatable per RFC 6265 section 4.1 and RFC 7235 section 4.1.
    // Using std::map would silently collapse repeated Set-Cookie headers
    // from the upstream, which is a functional regression for a gateway.
    // Matches HttpResponse's storage model (vector<pair>).
    std::vector<std::pair<std::string, std::string>> headers;  // lowercase keys
    std::string body;
    bool keep_alive = true;
    bool headers_complete = false;
    bool complete = false;

    // Reset for reuse (connection reuse across requests).
    void Reset() {
        status_code = 0;
        status_reason.clear();
        http_major = 1;
        http_minor = 1;
        headers.clear();
        body.clear();
        keep_alive = true;
        headers_complete = false;
        complete = false;
    }

    // Case-insensitive header lookup -- returns the FIRST matching header value.
    // For repeated headers (Set-Cookie), use GetAllHeaders(name) instead.
    std::string GetHeader(const std::string& name) const {
        std::string lower = name;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c){ return std::tolower(c); });
        for (const auto& pair : headers) {
            if (pair.first == lower) {
                return pair.second;
            }
        }
        return "";
    }

    bool HasHeader(const std::string& name) const {
        std::string lower = name;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c){ return std::tolower(c); });
        for (const auto& pair : headers) {
            if (pair.first == lower) {
                return true;
            }
        }
        return false;
    }

    // Return ALL values for a given header name (for repeated headers).
    std::vector<std::string> GetAllHeaders(const std::string& name) const {
        std::string lower = name;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c){ return std::tolower(c); });
        std::vector<std::string> values;
        for (const auto& pair : headers) {
            if (pair.first == lower) {
                values.push_back(pair.second);
            }
        }
        return values;
    }
};
