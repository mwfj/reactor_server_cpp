#pragma once

#include "common.h"

class HttpResponse {
public:
    HttpResponse();

    // Builder methods (return *this for chaining)
    HttpResponse& Status(int code);
    HttpResponse& Status(int code, const std::string& reason);
    HttpResponse& Version(int major, int minor);
    HttpResponse& Header(const std::string& key, const std::string& value);
    HttpResponse& Body(const std::string& content);
    HttpResponse& Body(const std::string& content, const std::string& content_type);

    // Convenience builders
    HttpResponse& Json(const std::string& json_body);
    HttpResponse& Text(const std::string& text_body);
    HttpResponse& Html(const std::string& html_body);

    // Serialize to HTTP wire format
    std::string Serialize() const;

    // Factory methods
    static HttpResponse Ok();
    static HttpResponse BadRequest(const std::string& message = "Bad Request");
    static HttpResponse NotFound();
    static HttpResponse Unauthorized(const std::string& message = "Unauthorized");
    static HttpResponse Forbidden();
    static HttpResponse MethodNotAllowed();
    static HttpResponse InternalError(const std::string& message = "Internal Server Error");
    static HttpResponse BadGateway();
    static HttpResponse ServiceUnavailable();
    static HttpResponse GatewayTimeout();
    static HttpResponse PayloadTooLarge();
    static HttpResponse HeaderTooLarge();
    static HttpResponse RequestTimeout();
    static HttpResponse HttpVersionNotSupported();

    // Accessors
    int GetStatusCode() const { return status_code_; }
    const std::string& GetStatusReason() const { return status_reason_; }
    const std::string& GetBody() const { return body_; }
    const std::vector<std::pair<std::string, std::string>>& GetHeaders() const { return headers_; }

    // Mark this response as deferred — the framework will NOT auto-send it
    // after the request handler returns. The handler is expected to call
    // HttpConnectionHandler::SendResponse() later (from an async completion
    // callback) to deliver the real response. Used by async handlers such
    // as upstream proxy: the sync dispatch path sets Defer() and captures
    // the HttpConnectionHandler shared_ptr, then CheckoutAsync() drives the
    // eventual SendResponse when the upstream reply is ready.
    HttpResponse& Defer() { deferred_ = true; return *this; }
    bool IsDeferred() const { return deferred_; }

private:
    int status_code_;
    std::string status_reason_;
    int http_major_ = 1;
    int http_minor_ = 1;
    std::vector<std::pair<std::string, std::string>> headers_;
    std::string body_;
    bool deferred_ = false;

    static std::string DefaultReason(int code);
};
