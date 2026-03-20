#pragma once

#include "http/http_request.h"
#include <string>
#include <cstddef>
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

private:
    // llhttp internals (pimpl -- llhttp.h only included in .cc)
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
