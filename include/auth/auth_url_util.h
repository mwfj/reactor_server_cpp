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

// Case-insensitive "starts with https://" check per RFC 3986 §3.1
// (URI schemes are case-insensitive; "HTTPS://idp.example" / "HttpS://…"
// are all valid). Used to reject plaintext IdP traffic without
// incorrectly rejecting valid mixed-case scheme prefixes.
bool HasHttpsScheme(const std::string& url) noexcept;

}  // namespace AUTH_NAMESPACE
