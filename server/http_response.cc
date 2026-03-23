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

HttpResponse& HttpResponse::Version(int major, int minor) {
    http_major_ = major;
    http_minor_ = minor;
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

    // Status line — echo the request's HTTP version (default 1.1)
    oss << "HTTP/" << http_major_ << "." << http_minor_ << " "
        << status_code_ << " " << status_reason_ << "\r\n";

    // Headers
    auto hdrs = headers_;

    // Determine if this status code must not have a body (RFC 7230/7231).
    // For these statuses, any caller-set Content-Length is invalid and must
    // be stripped/normalized to prevent keep-alive framing desync.
    bool bodyless_status = (status_code_ < 200 || status_code_ == 101 ||
                            status_code_ == 204 || status_code_ == 304);

    // Strip Transfer-Encoding headers — this server does not implement chunked
    // encoding, so emitting Transfer-Encoding: chunked with an un-chunked body
    // produces malformed HTTP. Use Content-Length framing exclusively.
    // Also strip Content-Length for bodyless statuses (1xx, 101, 204, 304)
    // to prevent framing desync on keep-alive connections.
    hdrs.erase(std::remove_if(hdrs.begin(), hdrs.end(),
        [bodyless_status](const std::pair<std::string, std::string>& kv) {
            std::string key = kv.first;
            std::transform(key.begin(), key.end(), key.begin(), ::tolower);
            if (key == "transfer-encoding") return true;
            if (key == "content-length" && bodyless_status) return true;
            return false;
        }), hdrs.end());

    // Add Content-Length if not already set.
    // Excluded: 1xx, 101, 204, 304 (bodyless — just stripped above).
    // 205 Reset Content: force Content-Length: 0 for keep-alive framing
    // regardless of what the caller set.
    if (status_code_ == 205) {
        // Strip any caller-set Content-Length first, then force 0
        hdrs.erase(std::remove_if(hdrs.begin(), hdrs.end(),
            [](const std::pair<std::string, std::string>& kv) {
                std::string key = kv.first;
                std::transform(key.begin(), key.end(), key.begin(), ::tolower);
                return key == "content-length";
            }), hdrs.end());
        hdrs.emplace_back("Content-Length", "0");
    } else if (!bodyless_status) {
        // Always strip caller-set Content-Length and auto-compute from body_.size().
        // This prevents framing inconsistencies where the caller sets a Content-Length
        // that doesn't match the body (e.g. Header("Content-Length","0").Text("hello")
        // would produce CL: 0 with a 5-byte body, desyncing keep-alive clients).
        hdrs.erase(std::remove_if(hdrs.begin(), hdrs.end(),
            [](const std::pair<std::string, std::string>& kv) {
                std::string key = kv.first;
                std::transform(key.begin(), key.end(), key.begin(), ::tolower);
                return key == "content-length";
            }), hdrs.end());
        hdrs.emplace_back("Content-Length", std::to_string(body_.size()));
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

HttpResponse HttpResponse::HttpVersionNotSupported() {
    return HttpResponse().Status(505).Text("HTTP Version Not Supported");
}

std::string HttpResponse::DefaultReason(int code) {
    switch (code) {
        // 1xx Informational
        case 100: return "Continue";
        case 101: return "Switching Protocols";
        // 2xx Success
        case 200: return "OK";
        case 201: return "Created";
        case 202: return "Accepted";
        case 203: return "Non-Authoritative Information";
        case 204: return "No Content";
        case 205: return "Reset Content";
        case 206: return "Partial Content";
        // 3xx Redirection
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 303: return "See Other";
        case 304: return "Not Modified";
        case 307: return "Temporary Redirect";
        case 308: return "Permanent Redirect";
        // 4xx Client Error
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 406: return "Not Acceptable";
        case 408: return "Request Timeout";
        case 409: return "Conflict";
        case 410: return "Gone";
        case 411: return "Length Required";
        case 412: return "Precondition Failed";
        case 413: return "Payload Too Large";
        case 414: return "URI Too Long";
        case 415: return "Unsupported Media Type";
        case 416: return "Range Not Satisfiable";
        case 417: return "Expectation Failed";
        case 422: return "Unprocessable Entity";
        case 426: return "Upgrade Required";
        case 428: return "Precondition Required";
        case 429: return "Too Many Requests";
        case 431: return "Request Header Fields Too Large";
        case 451: return "Unavailable For Legal Reasons";
        // 5xx Server Error
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        case 504: return "Gateway Timeout";
        case 505: return "HTTP Version Not Supported";
        default:  return "Unknown";
    }
}
