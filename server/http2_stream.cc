#include "http2/http2_stream.h"
#include <algorithm>

Http2Stream::Http2Stream(int32_t stream_id)
    : stream_id_(stream_id) {
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
            return -1;  // Late pseudo-header
        }

        if (name == ":method") {
            if (has_method_) return -1;  // Duplicate
            has_method_ = true;
            request_.method = value;
        } else if (name == ":path") {
            if (has_path_) return -1;  // Duplicate
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
            if (has_authority_) return -1;  // Duplicate
            has_authority_ = true;
            authority_ = value;
            request_.headers["host"] = value;
        } else if (name == ":scheme") {
            if (has_scheme_) return -1;  // Duplicate
            has_scheme_ = true;
            scheme_ = value;
        } else {
            // Unknown pseudo-header — malformed per RFC 9113 Section 8.3
            return -1;
        }
        return 0;
    }

    // First regular header — mark transition
    seen_regular_header_ = true;

    // Regular headers — store lowercase (matching HTTP/1.x convention)
    std::string lower_name = name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);

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

    // RFC 9113 Section 8.3.1: if :authority and host are both present,
    // they MUST be identical. Reject if they conflict.
    if (lower_name == "host" && has_authority_ && value != authority_) {
        return -1;  // Malformed: conflicting :authority and host
    }

    request_.headers[lower_name] = value;

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
                return -1;  // Conflicting content-length values
            }
            request_.content_length = new_cl;
            has_content_length_ = true;
        } catch (...) {
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
