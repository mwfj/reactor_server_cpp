#include "http/http_response.h"
#include <sstream>

HttpResponse::HttpResponse() : status_code_(200), status_reason_("OK") {}

HttpResponse& HttpResponse::Status(int code) {
    status_code_ = code;
    status_reason_ = DefaultReason(code);
    return *this;
}

HttpResponse& HttpResponse::Status(int code, const std::string& reason) {
    status_code_ = code;
    status_reason_ = reason;
    return *this;
}

HttpResponse& HttpResponse::Header(const std::string& key, const std::string& value) {
    headers_[key] = value;
    return *this;
}

HttpResponse& HttpResponse::Body(const std::string& content) {
    body_ = content;
    return *this;
}

HttpResponse& HttpResponse::Body(const std::string& content, const std::string& content_type) {
    body_ = content;
    headers_["Content-Type"] = content_type;
    return *this;
}

HttpResponse& HttpResponse::Json(const std::string& json_body) {
    return Body(json_body, "application/json");
}

HttpResponse& HttpResponse::Text(const std::string& text_body) {
    return Body(text_body, "text/plain");
}

HttpResponse& HttpResponse::Html(const std::string& html_body) {
    return Body(html_body, "text/html");
}

std::string HttpResponse::Serialize() const {
    std::ostringstream oss;

    // Status line
    oss << "HTTP/1.1 " << status_code_ << " " << status_reason_ << "\r\n";

    // Headers
    auto hdrs = headers_;
    // Add Content-Length if not already set.
    // Excluded: 1xx informational, 101 Switching Protocols, 204 No Content, 304 Not Modified
    if (hdrs.find("Content-Length") == hdrs.end() &&
        status_code_ >= 200 && status_code_ != 204 && status_code_ != 304 &&
        status_code_ != 101) {
        hdrs["Content-Length"] = std::to_string(body_.size());
    }
    for (const auto& kv : hdrs) {
        oss << kv.first << ": " << kv.second << "\r\n";
    }

    // Blank line
    oss << "\r\n";

    // Body
    if (!body_.empty()) {
        oss << body_;
    }

    return oss.str();
}

// Factory methods
HttpResponse HttpResponse::Ok() { return HttpResponse(); }

HttpResponse HttpResponse::BadRequest(const std::string& message) {
    return HttpResponse().Status(400).Text(message);
}

HttpResponse HttpResponse::NotFound() {
    return HttpResponse().Status(404).Text("Not Found");
}

HttpResponse HttpResponse::Unauthorized(const std::string& message) {
    return HttpResponse().Status(401).Text(message);
}

HttpResponse HttpResponse::Forbidden() {
    return HttpResponse().Status(403).Text("Forbidden");
}

HttpResponse HttpResponse::MethodNotAllowed() {
    return HttpResponse().Status(405).Text("Method Not Allowed");
}

HttpResponse HttpResponse::InternalError(const std::string& message) {
    return HttpResponse().Status(500).Text(message);
}

HttpResponse HttpResponse::ServiceUnavailable() {
    return HttpResponse().Status(503).Text("Service Unavailable");
}

HttpResponse HttpResponse::PayloadTooLarge() {
    return HttpResponse().Status(413).Text("Payload Too Large");
}

HttpResponse HttpResponse::HeaderTooLarge() {
    return HttpResponse().Status(431).Text("Request Header Fields Too Large");
}

std::string HttpResponse::DefaultReason(int code) {
    switch (code) {
        case 200: return "OK";
        case 201: return "Created";
        case 204: return "No Content";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 304: return "Not Modified";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 408: return "Request Timeout";
        case 413: return "Payload Too Large";
        case 431: return "Request Header Fields Too Large";
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        default:  return "Unknown";
    }
}
