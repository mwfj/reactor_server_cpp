#pragma once

#include "http/http_request.h"
#include <string>
#include <cstddef>

class HttpParser {
public:
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

    // Error state
    bool HasError() const { return has_error_; }
    std::string GetError() const { return error_message_; }

    // Public fields accessed by llhttp callbacks (defined in .cc file)
    HttpRequest request_;
    bool has_error_ = false;
    std::string error_message_;
    std::string current_header_field_;
    std::string current_header_value_;
    bool parsing_header_value_ = false;

private:
    // llhttp internals (pimpl -- llhttp.h only included in .cc)
    struct Impl;
    Impl* impl_;
};
