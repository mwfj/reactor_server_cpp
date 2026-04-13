#include "http2/http2_stream.h"
#include "log/logger.h"
#include <algorithm>

// Returns the default port for a given HTTP(S) scheme. Empty string if
// scheme is unknown (caller falls back to strict exact-match).
static std::string DefaultPortForScheme(const std::string& scheme) {
    if (scheme == "http") return "80";
    if (scheme == "https") return "443";
    return "";
}

// Case-insensitive hostname comparison for :authority vs host.
// Splits host[:port], lowercases the host portion, compares.
// Port (if present) is compared exactly after scheme-aware default-port
// normalization: an absent port is treated as equivalent to the scheme's
// default port (80 for http, 443 for https). Unknown scheme → strict
// exact-port comparison (preserves prior behavior for malformed inputs).
static bool AuthorityMatch(const std::string& scheme,
                           const std::string& a,
                           const std::string& b) {
    auto split_host_port = [](const std::string& s) -> std::pair<std::string, std::string> {
        if (!s.empty() && s[0] == '[') {
            // IPv6: [::1]:port
            auto bracket = s.find(']');
            if (bracket != std::string::npos && bracket + 1 < s.size() && s[bracket + 1] == ':') {
                return {s.substr(0, bracket + 1), s.substr(bracket + 2)};
            }
            return {s, ""};
        }
        auto colon = s.rfind(':');
        if (colon != std::string::npos) {
            return {s.substr(0, colon), s.substr(colon + 1)};
        }
        return {s, ""};
    };

    auto [host_a, port_a] = split_host_port(a);
    auto [host_b, port_b] = split_host_port(b);

    const std::string default_port = DefaultPortForScheme(scheme);
    if (!default_port.empty()) {
        if (port_a.empty()) port_a = default_port;
        if (port_b.empty()) port_b = default_port;
    }

    if (port_a != port_b) return false;

    if (host_a.size() != host_b.size()) return false;
    for (size_t i = 0; i < host_a.size(); ++i) {
        if (::tolower(static_cast<unsigned char>(host_a[i])) !=
            ::tolower(static_cast<unsigned char>(host_b[i]))) {
            return false;
        }
    }
    return true;
}

Http2Stream::Http2Stream(int32_t stream_id)
    : stream_id_(stream_id)
    , created_at_(std::chrono::steady_clock::now()) {
    // HTTP/2 requests are always version 2.0
    request_.http_major = 2;
    request_.http_minor = 0;
    request_.keep_alive = true;  // HTTP/2 connections are persistent
}

Http2Stream::~Http2Stream() = default;

int Http2Stream::AddHeader(const std::string& name, const std::string& value) {
    // Handle pseudo-headers (RFC 9113 Section 8.3)
    if (!name.empty() && name[0] == ':') {
        // RFC 9113 Section 8.3: pseudo-headers MUST appear before all
        // regular header fields. A pseudo-header after a regular header
        // is malformed.
        if (seen_regular_header_) {
            logging::Get()->debug("H2 stream {} late pseudo-header: {}", stream_id_, name);
            return -1;  // Late pseudo-header
        }

        if (name == ":method") {
            if (has_method_) {
                logging::Get()->debug("H2 stream {} duplicate pseudo-header: {}", stream_id_, name);
                return -1;  // Duplicate
            }
            has_method_ = true;
            request_.method = value;
        } else if (name == ":path") {
            if (has_path_) {
                logging::Get()->debug("H2 stream {} duplicate pseudo-header: {}", stream_id_, name);
                return -1;  // Duplicate
            }
            has_path_ = true;
            request_.url = value;
            // Split path and query
            auto qpos = value.find('?');
            if (qpos != std::string::npos) {
                request_.path = value.substr(0, qpos);
                request_.query = value.substr(qpos + 1);
            } else {
                request_.path = value;
                request_.query.clear();
            }
        } else if (name == ":authority") {
            if (has_authority_) {
                logging::Get()->debug("H2 stream {} duplicate pseudo-header: {}", stream_id_, name);
                return -1;  // Duplicate
            }
            has_authority_ = true;
            authority_ = value;
            request_.headers["host"] = value;
        } else if (name == ":scheme") {
            if (has_scheme_) {
                logging::Get()->debug("H2 stream {} duplicate pseudo-header: {}", stream_id_, name);
                return -1;  // Duplicate
            }
            has_scheme_ = true;
            scheme_ = value;
        } else {
            // Unknown pseudo-header — malformed per RFC 9113 Section 8.3
            logging::Get()->debug("H2 stream {} unknown pseudo-header: {}", stream_id_, name);
            return -1;
        }
        return 0;
    }

    // First regular header — mark transition
    seen_regular_header_ = true;

    // Regular headers — store lowercase (matching HTTP/1.x convention)
    std::string lower_name = name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), [](unsigned char c){ return std::tolower(c); });

    // Cookie headers in HTTP/2 may arrive as separate header fields
    // (RFC 9113 Section 8.2.3) — concatenate with "; "
    if (lower_name == "cookie") {
        auto it = request_.headers.find("cookie");
        if (it != request_.headers.end()) {
            it->second += "; " + value;
        } else {
            request_.headers["cookie"] = value;
        }
        return 0;
    }

    // Host header handling:
    // - If :authority was set and matches (case-insensitive hostname), skip
    // - If :authority was set and conflicts, reject
    // - Duplicate host headers (without :authority) rejected below as singleton
    if (lower_name == "host" && has_authority_) {
        if (!AuthorityMatch(scheme_, authority_, value)) {
            logging::Get()->debug("H2 stream {} conflicting :authority and host", stream_id_);
            return -1;  // Malformed: conflicting :authority and host
        }
        return 0;  // Matches :authority — already set, skip
    }

    // Handle duplicate headers consistently with the HTTP/1.x parser:
    // - Reject duplicates of singleton headers (security/routing-critical)
    // - Comma-fold list-valued headers per RFC 9110 Section 5.3
    // - Cookie uses "; " per RFC 6265 Section 5.4
    // - content-length handled separately below (allows identical duplicates)
    auto it = request_.headers.find(lower_name);
    if (it != request_.headers.end()) {
        // Reject singleton headers that must not be duplicated
        if (lower_name == "host" || lower_name == "authorization" ||
            lower_name == "content-type" ||
            lower_name == "content-range" || lower_name == "content-disposition") {
            logging::Get()->debug("H2 stream {} duplicate singleton header: {}",
                                  stream_id_, name);
            return -1;
        }
        // content-length: don't reject here — reconciliation below allows
        // identical values (common in proxied/translated requests)
        if (lower_name != "content-length") {
            // List-valued headers: comma-fold
            it->second += ", " + value;
            return 0;
        }
    } else {
        request_.headers[lower_name] = value;
    }

    // Track content-length for body size expectations.
    // RFC 9110 Section 8.6: content-length must be a valid non-negative integer.
    // Multiple content-length fields with differing values are malformed.
    if (lower_name == "content-length") {
        // Reject leading/trailing whitespace, signs, or non-digit chars
        if (value.empty()) return -1;
        for (char c : value) {
            if (c < '0' || c > '9') return -1;
        }
        try {
            size_t new_cl = std::stoull(value);
            if (has_content_length_ && request_.content_length != new_cl) {
                logging::Get()->debug("H2 stream {} invalid content-length", stream_id_);
                return -1;  // Conflicting content-length values
            }
            request_.content_length = new_cl;
            has_content_length_ = true;
        } catch (...) {
            logging::Get()->debug("H2 stream {} invalid content-length", stream_id_);
            return -1;  // Overflow or other parse error
        }
    }

    return 0;
}

void Http2Stream::AppendBody(const char* data, size_t len) {
    request_.body.append(data, len);
    accumulated_body_size_ += len;
}

void Http2Stream::MarkHeadersComplete() {
    headers_complete_ = true;
    request_.headers_complete = true;
}

void Http2Stream::MarkEndStream() {
    end_stream_received_ = true;
    request_.complete = true;
    if (state_ == State::OPEN) {
        state_ = State::HALF_CLOSED_REMOTE;
    }
}

bool Http2Stream::IsRequestComplete() const {
    // Request is complete when headers are done AND end-stream was received.
    // For requests with no body (GET, HEAD, DELETE), END_STREAM comes with HEADERS.
    // For requests with body (POST, PUT), END_STREAM comes with last DATA frame.
    return headers_complete_ && end_stream_received_;
}

void Http2Stream::SetState(State new_state) {
    state_ = new_state;
}
