#include "http/http_response.h"
#include "http/http_status.h"
#include <sstream>
#include <algorithm>

HttpResponse::HttpResponse() : status_code_(HttpStatus::OK), status_reason_("OK") {}

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

    // Set-semantics: replace existing header with the same name (case-insensitive)
    // to prevent conflicting duplicates (e.g., duplicate Content-Type from
    // middleware + 404 fallback, or multiple Connection headers).
    // Exception: headers that are legally repeated and cannot be folded into a
    // single comma-separated value (RFC 6265 §4.1, RFC 7235 §4.1).
    std::string lower_key = safe_key;
    std::transform(lower_key.begin(), lower_key.end(), lower_key.begin(), [](unsigned char c){ return std::tolower(c); });
    bool repeatable = (lower_key == "set-cookie" || lower_key == "www-authenticate");
    if (!repeatable) {
        for (auto& hdr : headers_) {
            std::string existing_lower = hdr.first;
            std::transform(existing_lower.begin(), existing_lower.end(), existing_lower.begin(), [](unsigned char c){ return std::tolower(c); });
            if (existing_lower == lower_key) {
                hdr.first = std::move(safe_key);
                hdr.second = std::move(safe_value);
                return *this;
            }
        }
    }

    headers_.emplace_back(std::move(safe_key), std::move(safe_value));
    return *this;
}

bool HttpResponse::RemoveHeader(const std::string& key) {
    // Stateless case-insensitive comparator — avoids the O(N) string
    // allocations that a lowercase-copy-per-comparison approach would incur.
    // Takes `char` (the string iterator value_type) and casts to unsigned
    // char inside std::tolower to avoid UB on platforms where char is
    // signed and the input exceeds 0x7F.
    auto eq_ci = [](char a, char b) {
        return std::tolower(static_cast<unsigned char>(a)) ==
               std::tolower(static_cast<unsigned char>(b));
    };
    auto before = headers_.size();
    headers_.erase(
        std::remove_if(headers_.begin(), headers_.end(),
            [&key, &eq_ci](const std::pair<std::string, std::string>& hdr) {
                // 4-iterator std::equal form performs the size check
                // internally; safer than the 3-iterator form if a future
                // refactor accidentally drops the explicit size guard.
                return std::equal(hdr.first.begin(), hdr.first.end(),
                                  key.begin(), key.end(), eq_ci);
            }),
        headers_.end());
    return headers_.size() < before;
}

HttpResponse& HttpResponse::AppendHeader(const std::string& key, const std::string& value) {
    // Same sanitization as Header() — prevent response splitting
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

HttpResponse& HttpResponse::Body(std::string&& content) {
    body_ = std::move(content);
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

std::optional<std::string>
HttpResponse::ComputeWireContentLength(int status_code) const {
    // Mirrors the CL rules applied inline in Serialize() so the HTTP/2
    // response submission path — which assembles nghttp2 nva entries
    // directly — gets identical semantics. Any change here MUST stay
    // in lockstep with Serialize()'s Content-Length handling.

    // 1xx, 101, 204: Content-Length MUST be stripped (RFC 7230 §3.3.2).
    if (status_code < HttpStatus::OK ||
        status_code == HttpStatus::SWITCHING_PROTOCOLS ||
        status_code == HttpStatus::NO_CONTENT) {
        return std::nullopt;
    }
    // 205 Reset Content: force CL=0 regardless of caller.
    if (status_code == HttpStatus::RESET_CONTENT) return std::string("0");

    // Find the first caller-set Content-Length (case-insensitive).
    // Used for 304 passthrough and PreserveContentLength paths.
    auto first_caller_cl = [this]() -> std::optional<std::string> {
        for (const auto& kv : headers_) {
            std::string key = kv.first;
            std::transform(key.begin(), key.end(), key.begin(),
                [](unsigned char c) { return std::tolower(c); });
            if (key == "content-length") return kv.second;
        }
        return std::nullopt;
    };

    // 304 Not Modified: RFC 7232 §4.1 allows CL as metadata for the
    // selected representation. Preserve caller's first value; if none
    // set, don't inject one (injecting CL: 0 would lie about the
    // representation size).
    if (status_code == HttpStatus::NOT_MODIFIED) return first_caller_cl();

    // Non-bodyless statuses (200, HEAD replies, proxy passthrough, ...).
    // If the handler or proxy has asked for preservation, keep the
    // caller-set value (first one wins — collapses duplicates).
    // Otherwise auto-compute from body_.size() to prevent framing
    // inconsistencies where a stale caller-set CL disagrees with body.
    if (preserve_content_length_) return first_caller_cl();
    return std::to_string(body_.size());
}

std::string HttpResponse::Serialize() const {
    std::ostringstream oss;

    // Status line — echo the request's HTTP version (default 1.1)
    oss << "HTTP/" << http_major_ << "." << http_minor_ << " "
        << status_code_ << " " << status_reason_ << "\r\n";

    // Headers
    auto hdrs = headers_;

    // Determine if this status code must not have a body (RFC 7230 §3.3.3).
    // For all of these, the body is suppressed regardless of headers.
    bool bodyless_status = (status_code_ < HttpStatus::OK ||
                            status_code_ == HttpStatus::SWITCHING_PROTOCOLS ||
                            status_code_ == HttpStatus::NO_CONTENT ||
                            status_code_ == HttpStatus::NOT_MODIFIED);

    // Statuses for which Content-Length must be stripped: 1xx/101/204
    // per RFC 7230 §3.3.2. 304 is NOT in this set — RFC 7232 §4.1 allows
    // a 304 to carry Content-Length as metadata for the selected
    // representation, and RFC 7230 §3.3.3 says 304 is always terminated
    // by the blank line (so CL doesn't affect framing). Stripping CL from
    // 304 would lose information when proxying an upstream 304 reply.
    bool strip_content_length_header =
        (status_code_ < HttpStatus::OK ||
         status_code_ == HttpStatus::SWITCHING_PROTOCOLS ||
         status_code_ == HttpStatus::NO_CONTENT);

    // Strip Transfer-Encoding headers — this server does not implement chunked
    // encoding, so emitting Transfer-Encoding: chunked with an un-chunked body
    // produces malformed HTTP. Use Content-Length framing exclusively.
    hdrs.erase(std::remove_if(hdrs.begin(), hdrs.end(),
        [strip_content_length_header](const std::pair<std::string, std::string>& kv) {
            std::string key = kv.first;
            std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c){ return std::tolower(c); });
            if (key == "transfer-encoding") return true;
            if (key == "content-length" && strip_content_length_header) return true;
            return false;
        }), hdrs.end());

    // Add Content-Length if not already set.
    // - 1xx/101/204: stripped above, none added (CL prohibited).
    // - 205 Reset Content: force CL: 0 regardless of caller (for framing).
    // - 304 Not Modified: preserve caller's CL (representation metadata).
    //   Canonicalize duplicates to a single value to avoid malformed
    //   responses when proxying an upstream 304 that sent duplicate CLs.
    //   No auto-compute from body_.size() — 304 never emits a body.
    // - Other non-bodyless: preserve (proxy HEAD) or auto-compute.
    if (status_code_ == HttpStatus::RESET_CONTENT) {
        // Strip any caller-set Content-Length first, then force 0
        hdrs.erase(std::remove_if(hdrs.begin(), hdrs.end(),
            [](const std::pair<std::string, std::string>& kv) {
                std::string key = kv.first;
                std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c){ return std::tolower(c); });
                return key == "content-length";
            }), hdrs.end());
        hdrs.emplace_back("Content-Length", "0");
    } else if (status_code_ == HttpStatus::NOT_MODIFIED) {
        // 304: canonicalize duplicate Content-Length headers (keep the
        // first value, drop the rest). If the caller didn't set any CL,
        // don't inject one — the body is always suppressed, and injecting
        // CL: 0 would lie about the representation size.
        std::string first_cl;
        bool found_cl = false;
        for (const auto& kv : hdrs) {
            std::string key = kv.first;
            std::transform(key.begin(), key.end(), key.begin(),
                [](unsigned char c){ return std::tolower(c); });
            if (key == "content-length") {
                if (!found_cl) {
                    first_cl = kv.second;
                    found_cl = true;
                }
            }
        }
        if (found_cl) {
            hdrs.erase(std::remove_if(hdrs.begin(), hdrs.end(),
                [](const std::pair<std::string, std::string>& kv) {
                    std::string key = kv.first;
                    std::transform(key.begin(), key.end(), key.begin(),
                        [](unsigned char c){ return std::tolower(c); });
                    return key == "content-length";
                }), hdrs.end());
            hdrs.emplace_back("Content-Length", first_cl);
        }
    } else if (!bodyless_status) {
        if (preserve_content_length_) {
            // Proxy HEAD path: keep the upstream's Content-Length value.
            // If the upstream didn't send Content-Length (resource size
            // unknown), don't inject one — forwarding CL: 0 would be
            // incorrect. If the upstream sent duplicate/conflicting CL
            // headers, collapse to a single value (the first one) to
            // avoid malformed responses that confuse clients.
            std::string first_cl;
            bool found_cl = false;
            for (const auto& kv : hdrs) {
                std::string key = kv.first;
                std::transform(key.begin(), key.end(), key.begin(),
                    [](unsigned char c){ return std::tolower(c); });
                if (key == "content-length") {
                    if (!found_cl) {
                        first_cl = kv.second;
                        found_cl = true;
                    }
                }
            }
            if (found_cl) {
                // Remove all CL headers, re-add the canonical single value
                hdrs.erase(std::remove_if(hdrs.begin(), hdrs.end(),
                    [](const std::pair<std::string, std::string>& kv) {
                        std::string key = kv.first;
                        std::transform(key.begin(), key.end(), key.begin(),
                            [](unsigned char c){ return std::tolower(c); });
                        return key == "content-length";
                    }), hdrs.end());
                hdrs.emplace_back("Content-Length", first_cl);
            }
        } else {
            // Auto-compute Content-Length from body_.size(). This prevents
            // framing inconsistencies where the caller sets a Content-Length
            // that doesn't match the body.
            hdrs.erase(std::remove_if(hdrs.begin(), hdrs.end(),
                [](const std::pair<std::string, std::string>& kv) {
                    std::string key = kv.first;
                    std::transform(key.begin(), key.end(), key.begin(),
                        [](unsigned char c){ return std::tolower(c); });
                    return key == "content-length";
                }), hdrs.end());
            hdrs.emplace_back("Content-Length", std::to_string(body_.size()));
        }
    }
    for (const auto& kv : hdrs) {
        oss << kv.first << ": " << kv.second << "\r\n";
    }

    // Blank line
    oss << "\r\n";

    // Body — suppress for status codes that must not have a body (101, 204, 205, 304)
    bool suppress_body = (status_code_ == HttpStatus::SWITCHING_PROTOCOLS ||
                          status_code_ == HttpStatus::NO_CONTENT ||
                          status_code_ == HttpStatus::RESET_CONTENT ||
                          status_code_ == HttpStatus::NOT_MODIFIED ||
                          status_code_ < HttpStatus::OK);
    if (!body_.empty() && !suppress_body) {
        oss << body_;
    }

    return oss.str();
}

// Factory methods
HttpResponse HttpResponse::Ok() { return HttpResponse(); }

HttpResponse HttpResponse::BadRequest(const std::string& message) {
    return HttpResponse().Status(HttpStatus::BAD_REQUEST).Text(message);
}

HttpResponse HttpResponse::NotFound() {
    return HttpResponse().Status(HttpStatus::NOT_FOUND).Text("Not Found");
}

HttpResponse HttpResponse::Unauthorized(const std::string& message) {
    return HttpResponse().Status(HttpStatus::UNAUTHORIZED).Text(message);
}

HttpResponse HttpResponse::Forbidden() {
    return HttpResponse().Status(HttpStatus::FORBIDDEN).Text("Forbidden");
}

HttpResponse HttpResponse::MethodNotAllowed() {
    return HttpResponse().Status(HttpStatus::METHOD_NOT_ALLOWED).Text("Method Not Allowed");
}

HttpResponse HttpResponse::InternalError(const std::string& message) {
    return HttpResponse().Status(HttpStatus::INTERNAL_SERVER_ERROR).Text(message);
}

HttpResponse HttpResponse::BadGateway() {
    return HttpResponse().Status(HttpStatus::BAD_GATEWAY).Text("Bad Gateway");
}

HttpResponse HttpResponse::ServiceUnavailable() {
    return HttpResponse().Status(HttpStatus::SERVICE_UNAVAILABLE).Text("Service Unavailable");
}

HttpResponse HttpResponse::GatewayTimeout() {
    return HttpResponse().Status(HttpStatus::GATEWAY_TIMEOUT).Text("Gateway Timeout");
}

HttpResponse HttpResponse::PayloadTooLarge() {
    return HttpResponse().Status(HttpStatus::PAYLOAD_TOO_LARGE).Text("Payload Too Large");
}

HttpResponse HttpResponse::HeaderTooLarge() {
    return HttpResponse().Status(HttpStatus::REQUEST_HEADER_FIELDS_TOO_LARGE).Text("Request Header Fields Too Large");
}

HttpResponse HttpResponse::RequestTimeout() {
    return HttpResponse().Status(HttpStatus::REQUEST_TIMEOUT).Text("Request Timeout");
}

HttpResponse HttpResponse::HttpVersionNotSupported() {
    return HttpResponse().Status(HttpStatus::HTTP_VERSION_NOT_SUPPORTED).Text("HTTP Version Not Supported");
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
