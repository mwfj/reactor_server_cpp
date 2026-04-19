#pragma once

#include "common.h"
// <string> via common.h

namespace AUTH_NAMESPACE {

// Parse an https:// or http:// URL into (host, path_with_query).
// host   — e.g. "auth.example.com" or "auth.example.com:8443"
// path   — e.g. "/jwks" or "/" when no path present
//
// Inputs that already start with '/' are treated as bare paths:
// host will be empty and path_with_query will be the input as-is.
struct ParsedHttpsUri {
    std::string host;
    std::string path_with_query;
};

ParsedHttpsUri ParseHttpsUri(const std::string& url);

}  // namespace AUTH_NAMESPACE
