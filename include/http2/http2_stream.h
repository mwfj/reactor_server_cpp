#pragma once

#include "http/http_request.h"
#include "http/http_response.h"
// <string>, <cstdint>, <memory> provided by common.h (via http_request.h)

// Response body data source for nghttp2. Defined here so Http2Stream can
// own it via unique_ptr, ensuring cleanup when the stream is removed.
struct ResponseDataSource {
    std::string body;
    size_t offset = 0;
};

class Http2Stream {
public:
    // Stream states (RFC 9113 Section 5.1)
    enum class State {
        IDLE,
        OPEN,
        HALF_CLOSED_REMOTE,   // Client sent END_STREAM
        HALF_CLOSED_LOCAL,    // Server sent END_STREAM
        CLOSED
    };

    explicit Http2Stream(int32_t stream_id);
    ~Http2Stream();

    // Non-copyable, movable
    Http2Stream(const Http2Stream&) = delete;
    Http2Stream& operator=(const Http2Stream&) = delete;
    Http2Stream(Http2Stream&&) = default;
    Http2Stream& operator=(Http2Stream&&) = default;

    // Header accumulation (called from nghttp2 on_header_callback).
    // Handles pseudo-headers (:method, :path, :scheme, :authority).
    // Returns 0 on success, -1 if the header value is invalid (e.g., bad content-length).
    int AddHeader(const std::string& name, const std::string& value);

    // Body accumulation (called from nghttp2 on_data_chunk_recv_callback)
    void AppendBody(const char* data, size_t len);

    // Mark headers complete (END_HEADERS received)
    void MarkHeadersComplete();

    // Mark stream as END_STREAM received from client
    void MarkEndStream();

    // Check if request is ready for dispatch
    bool IsRequestComplete() const;

    // State transitions
    void SetState(State new_state);
    State GetState() const { return state_; }
    bool IsClosed() const { return state_ == State::CLOSED; }

    // Accessors
    int32_t StreamId() const { return stream_id_; }
    HttpRequest& GetRequest() { return request_; }
    const HttpRequest& GetRequest() const { return request_; }

    // Track response state
    bool IsResponseHeadersSent() const { return response_headers_sent_; }
    void MarkResponseHeadersSent() { response_headers_sent_ = true; }
    bool IsResponseComplete() const { return response_complete_; }
    void MarkResponseComplete() { response_complete_ = true; }

    // Body size tracking for limit enforcement
    size_t AccumulatedBodySize() const { return accumulated_body_size_; }

    // Header size tracking (name + value + 32 per RFC 7541 Section 4.1).
    // Tracks per header block (reset between request headers and trailers).
    size_t AccumulatedHeaderSize() const { return accumulated_header_size_; }
    void AddHeaderBytes(size_t name_len, size_t value_len) {
        accumulated_header_size_ += name_len + value_len + 32;
    }
    void ResetHeaderSize() { accumulated_header_size_ = 0; }

    // Mark stream as rejected (RST_STREAM sent) — prevents dispatch
    void MarkRejected() { rejected_ = true; }
    bool IsRejected() const { return rejected_; }

    // Track whether the incomplete-stream counter was already decremented
    // for this stream (by DispatchStreamRequest). Prevents double-decrement
    // in OnStreamCloseCallback. Also anchors the async-deferred safety
    // cap timer — the moment a stream transitions from "being parsed"
    // to "awaiting async response", so that slow uploads do not eat
    // into the handler's own response budget.
    void MarkCounterDecremented() {
        counter_decremented_ = true;
        dispatched_at_ = std::chrono::steady_clock::now();
    }
    bool IsCounterDecremented() const { return counter_decremented_; }

    // Pseudo-header presence tracking (required for validation)
    bool HasPath() const { return has_path_; }
    bool HasScheme() const { return has_scheme_; }
    const std::string& Scheme() const { return scheme_; }

    // Content-length tracking
    bool HasContentLength() const { return has_content_length_; }

    // :authority tracking (for conflict detection with host header)
    bool HasAuthority() const { return has_authority_; }
    const std::string& Authority() const { return authority_; }

    // When this stream was created (for oldest-incomplete-stream timeout)
    std::chrono::steady_clock::time_point CreatedAt() const { return created_at_; }

    // When this stream was dispatched (counter decremented) — used as the
    // baseline for the async-deferred safety cap so that slow upload time
    // does not count against the handler's response budget. Returns
    // steady_clock::time_point::max() if the stream was never dispatched.
    std::chrono::steady_clock::time_point DispatchedAt() const { return dispatched_at_; }

    // Owns the ResponseDataSource for this stream's response body.
    // nghttp2 holds a raw pointer to it via nghttp2_data_source.ptr;
    // we keep ownership here so it is freed when the stream is destroyed.
    void SetDataSource(std::unique_ptr<ResponseDataSource> src) {
        data_source_ = std::move(src);
    }

private:
    int32_t stream_id_;
    State state_ = State::IDLE;
    HttpRequest request_;
    bool headers_complete_ = false;
    bool end_stream_received_ = false;
    bool response_headers_sent_ = false;
    bool response_complete_ = false;
    size_t accumulated_body_size_ = 0;
    size_t accumulated_header_size_ = 0;
    bool rejected_ = false;
    bool counter_decremented_ = false;
    bool has_content_length_ = false;
    bool seen_regular_header_ = false;  // true after first non-pseudo header
    bool has_method_ = false;
    bool has_path_ = false;
    bool has_scheme_ = false;
    std::string scheme_;
    bool has_authority_ = false;
    std::string authority_;
    std::unique_ptr<ResponseDataSource> data_source_;
    std::chrono::steady_clock::time_point created_at_;
    // Sentinel = max() when the stream has not been dispatched yet.
    // Anchors the async-deferred safety cap so body-upload time is not
    // counted against the handler's response budget.
    std::chrono::steady_clock::time_point dispatched_at_ =
        std::chrono::steady_clock::time_point::max();
};
