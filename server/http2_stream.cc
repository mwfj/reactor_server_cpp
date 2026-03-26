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

void Http2Stream::AddHeader(const std::string& name, const std::string& value) {
    // Handle pseudo-headers (RFC 9113 Section 8.3.1)
    if (!name.empty() && name[0] == ':') {
        if (name == ":method") {
            request_.method = value;
        } else if (name == ":path") {
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
            // Map :authority to Host header (RFC 9113 Section 8.3.1)
            request_.headers["host"] = value;
        }
        // :scheme is informational — not stored in HttpRequest
        return;
    }

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
        return;
    }

    request_.headers[lower_name] = value;

    // Track content-length for body size expectations
    if (lower_name == "content-length") {
        try {
            request_.content_length = std::stoull(value);
        } catch (...) {
            // Invalid content-length — will be caught during validation
            request_.content_length = 0;
        }
    }
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
