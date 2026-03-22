#include "http/http_response.h"
#include <sstream>
#include <algorithm>

HttpResponse::HttpResponse() : status_code_(200), status_reason_("OK") {}

HttpResponse& HttpResponse::Status(int code) {
    status_code_ = code;
    status_reason_ = DefaultReason(code);
    return *this;
}

HttpResponse& HttpResponse::Status(int code, const std::string& reason) {
    status_code_ = code;
    // Sanitize reason to prevent response splitting
    status_reason_ = reason;
    status_reason_.erase(std::remove(status_reason_.begin(), status_reason_.end(), '\r'), status_reason_.end());
    status_reason_.erase(std::remove(status_reason_.begin(), status_reason_.end(), '\n'), status_reason_.end());
    return *this;
}

HttpResponse& HttpResponse::Header(const std::string& key, const std::string& value) {
    // Sanitize: strip \r and \n to prevent HTTP response splitting
    std::string safe_key = key;
    std::string safe_value = value;
    safe_key.erase(std::remove(safe_key.begin(), safe_key.end(), '\r'), safe_key.end());
    safe_key.erase(std::remove(safe_key.begin(), safe_key.end(), '\n'), safe_key.end());
    safe_value.erase(std::remove(safe_value.begin(), safe_value.end(), '\r'), safe_value.end());
    safe_value.erase(std::remove(safe_value.begin(), safe_value.end(), '\n'), safe_value.end());
    headers_.emplace_back(std::move(safe_key), std::move(safe_value));
    return *this;
}

HttpResponse& HttpResponse::Body(const std::string& content) {
    body_ = content;
    return *this;
}

HttpResponse& HttpResponse::Body(const std::string& content, const std::string& content_type) {
    body_ = content;
    Header("Content-Type", content_type);
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
    // Add Content-Length if not already set (case-insensitive check).
    // Excluded per RFC 7230/7231: 1xx, 101 (Switching Protocols), 204 (No Content),
    // 205 (Reset Content), 304 (Not Modified)
    bool has_content_length = false;
    bool has_transfer_encoding = false;
    for (const auto& kv : hdrs) {
        std::string key = kv.first;
        std::transform(key.begin(), key.end(), key.begin(), ::tolower);
        if (key == "content-length") has_content_length = true;
        if (key == "transfer-encoding") has_transfer_encoding = true;
    }
    // Don't add Content-Length when Transfer-Encoding is set (RFC 7230 §3.3.2)
    if (!has_content_length && !has_transfer_encoding &&
        status_code_ >= 200 && status_code_ != 204 &&
        status_code_ != 304 && status_code_ != 101) {
        // 205 Reset Content: must have Content-Length: 0 for keep-alive framing
        // All other eligible statuses: Content-Length = body size
        if (status_code_ == 205) {
            hdrs.emplace_back("Content-Length", "0");
        } else {
            hdrs.emplace_back("Content-Length", std::to_string(body_.size()));
        }
    }
    for (const auto& kv : hdrs) {
        oss << kv.first << ": " << kv.second << "\r\n";
    }

    // Blank line
    oss << "\r\n";

    // Body — suppress for status codes that must not have a body (101, 204, 205, 304)
    bool suppress_body = (status_code_ == 101 || status_code_ == 204 ||
                          status_code_ == 205 || status_code_ == 304 ||
                          status_code_ < 200);
    if (!body_.empty() && !suppress_body) {
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

HttpResponse HttpResponse::RequestTimeout() {
    return HttpResponse().Status(408).Text("Request Timeout");
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
        case 426: return "Upgrade Required";
        case 431: return "Request Header Fields Too Large";
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        default:  return "Unknown";
    }
}
