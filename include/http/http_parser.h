#pragma once

#include "http/http_request.h"
#include "http/body_stream.h"
#include "http/http_callbacks.h"
#include <string>
#include <cstddef>
#include <functional>
#include <memory>

class HttpParser {
public:
    enum class ParseError { NONE, BODY_TOO_LARGE, HEADER_TOO_LARGE, PARSE_ERROR };

    HttpParser();
    ~HttpParser();

    // Non-copyable
    HttpParser(const HttpParser&) = delete;
    HttpParser& operator=(const HttpParser&) = delete;

    // Feed raw bytes. Returns number of bytes consumed.
    // After this call, check GetRequest().complete.
    size_t Parse(const char* data, size_t len);

    // Access the parsed request
    const HttpRequest& GetRequest() const { return request_; }
    HttpRequest& GetRequest() { return request_; }

    // Reset parser state for next request (keep-alive)
    void Reset();

    // Set size limits (enforced during parsing callbacks)
    void SetMaxBodySize(size_t max) { max_body_size_ = max; }
    void SetMaxHeaderSize(size_t max) { max_header_size_ = max; }

    // Error state
    bool HasError() const { return has_error_; }
    std::string GetError() const { return error_message_; }
    ParseError GetErrorType() const { return error_type_; }

    // Streaming support: install a BodyStream so on_body pushes to it
    // instead of buffering into request_.body. Set by the connection handler
    // at HEADERS-complete when the matched route uses Streaming mode.
    // Cleared on Reset() between keep-alive requests.
    void set_streaming_body_stream(std::shared_ptr<http::BodyStream> s) {
        streaming_body_stream_ = std::move(s);
    }

    // Callback fired from on_headers_complete. Allows the connection handler
    // to perform per-request actions (route resolution, streaming setup)
    // while the parser is still mid-parse — synchronous, before on_body runs.
    // Re-exported from HTTP_CALLBACKS_NAMESPACE; canonical alias lives there
    // per CODE_CONVENTIONS.md §Callbacks & Callback Registries.
    using HeadersCompleteCallback =
        HTTP_CALLBACKS_NAMESPACE::HttpParserHeadersCompleteCallback;
    void SetHeadersCompleteCallback(HeadersCompleteCallback cb) {
        headers_complete_callback_ = std::move(cb);
    }

    // Callback fired from on_message_complete when streaming_body_stream_ is
    // set. Lets the connection handler clear streaming_upload_in_flight_ on
    // the happy-path EOS signal. Only fires when streaming is active.
    using StreamingBodyCompleteCallback =
        HTTP_CALLBACKS_NAMESPACE::HttpParserStreamingBodyCompleteCallback;
    void SetStreamingBodyCompleteCallback(StreamingBodyCompleteCallback cb) {
        streaming_body_complete_callback_ = std::move(cb);
    }

    // Public fields accessed by llhttp callbacks (defined in .cc file)
    HttpRequest request_;
    size_t max_body_size_ = 0;    // 0 = unlimited
    size_t max_header_size_ = 0;  // 0 = unlimited
    size_t header_bytes_ = 0;     // accumulated header bytes
    bool has_error_ = false;
    std::string error_message_;
    ParseError error_type_ = ParseError::NONE;
    std::string current_header_field_;
    std::string current_header_value_;
    bool parsing_header_value_ = false;
    bool in_header_field_ = false;  // true while accumulating same header field across fragments

    // Streaming body stream — non-null when the matched route uses Streaming
    // mode. on_body pushes chunks here instead of into request_.body.
    // Cleared on Reset() between keep-alive requests.
    std::shared_ptr<http::BodyStream> streaming_body_stream_;

    // Callbacks set by the connection handler to hook parse milestones.
    // Accessed by the static llhttp C callbacks (on_headers_complete,
    // on_message_complete) which only hold HttpParser*, so they must be
    // public like the other fields in this section.
    HeadersCompleteCallback headers_complete_callback_;
    StreamingBodyCompleteCallback streaming_body_complete_callback_;

private:
    // llhttp internals (pimpl -- llhttp.h only included in .cc)
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
