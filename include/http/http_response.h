#pragma once

#include "common.h"
#include <optional>

class HttpResponse {
public:
    HttpResponse();

    // Builder methods (return *this for chaining)
    HttpResponse& Status(int code);
    HttpResponse& Status(int code, const std::string& reason);
    HttpResponse& Version(int major, int minor);
    HttpResponse& Header(const std::string& key, const std::string& value);
    // Append-only header insertion: always adds a new header entry, never
    // replaces existing ones. Used by the proxy path to faithfully forward
    // repeated upstream headers (Cache-Control, Link, Via, etc.) that
    // Header()'s set-semantics would collapse.
    HttpResponse& AppendHeader(const std::string& key, const std::string& value);
    HttpResponse& Body(const std::string& content);
    HttpResponse& Body(std::string&& content);
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

    // Preserve caller-set Content-Length instead of auto-computing from
    // body_.size(). Used by the proxy path for HEAD responses where the
    // upstream's Content-Length (e.g., 1234) must be forwarded even though
    // the response body is empty.
    HttpResponse& PreserveContentLength() { preserve_content_length_ = true; return *this; }
    bool IsContentLengthPreserved() const { return preserve_content_length_; }

    // Compute the Content-Length value that should appear on the wire
    // for a response with the given final status code. Mirrors the rules
    // applied inline in Serialize() so the HTTP/2 response submission
    // path (which assembles headers directly, bypassing Serialize) stays
    // in lockstep with HTTP/1 semantics for 304 metadata preservation,
    // 205 zeroing, and PreserveContentLength passthrough.
    //
    // Returns std::nullopt when no Content-Length header should be
    // emitted (1xx/101/204, or 304/preserve cases where the caller set
    // none). Otherwise returns the exact header value as a string.
    //
    // The status_code argument is explicit (rather than using
    // status_code_) to match HTTP/2's flow, where the effective status
    // is captured before headers are assembled.
    std::optional<std::string> ComputeWireContentLength(int status_code) const;

private:
    int status_code_;
    std::string status_reason_;
    int http_major_ = 1;
    int http_minor_ = 1;
    std::vector<std::pair<std::string, std::string>> headers_;
    std::string body_;
    bool deferred_ = false;
    bool preserve_content_length_ = false;

    static std::string DefaultReason(int code);
};
