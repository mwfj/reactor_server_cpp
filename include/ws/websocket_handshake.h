#pragma once

#include "http/http_request.h"
#include "http/http_response.h"
#include <string>

class WebSocketHandshake {
public:
    // Validate an HTTP request as a valid WebSocket upgrade (RFC 6455 section 4.2.1).
    // Returns true if valid. Sets error_message on failure.
    static bool Validate(const HttpRequest& request, std::string& error_message);

    // Generate 101 Switching Protocols response for a valid upgrade.
    static HttpResponse Accept(const HttpRequest& request);

    // Generate error response rejecting the upgrade.
    static HttpResponse Reject(int status_code, const std::string& reason);

private:
    // SHA-1(key + magic) -> base64
    static std::string ComputeAcceptKey(const std::string& client_key);
};
