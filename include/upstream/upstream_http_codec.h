#pragma once

#include "upstream/upstream_response.h"
#include "upstream/upstream_response_head.h"
#include "upstream/upstream_response_sink.h"
// <string>, <memory>, <cstddef> provided by common.h (via upstream_response.h)

class UpstreamHttpCodec {
public:
    enum class ParseError { NONE, PARSE_ERROR };

    // Hard cap on upstream response body size to prevent memory exhaustion
    // from misconfigured upstreams. 64 MB.
    static constexpr size_t MAX_RESPONSE_BODY_SIZE = 67108864;

    UpstreamHttpCodec();
    ~UpstreamHttpCodec();

    // Non-copyable (owns pimpl)
    UpstreamHttpCodec(const UpstreamHttpCodec&) = delete;
    UpstreamHttpCodec& operator=(const UpstreamHttpCodec&) = delete;

    // Set the request method that produced this response. Must be called
    // before Parse() so llhttp knows HEAD responses have no body.
    void SetRequestMethod(const std::string& method);

    void SetSink(UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseSink* sink);
    void PauseParsing();
    void ResumeParsing();
    UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead::Framing FramingHint() const {
        return framing_hint_;
    }
    int64_t ExpectedLength() const { return expected_length_; }
    bool IsPaused() const { return paused_; }

    // Feed raw bytes from upstream. Returns bytes consumed.
    // After this call, check GetResponse().complete.
    size_t Parse(const char* data, size_t len);

    // Signal EOF from the transport. For connection-close framing (no
    // Content-Length / Transfer-Encoding), llhttp needs this to finalize
    // the response. Returns true if the response was completed by EOF.
    bool Finish();

    // Access the parsed response
    const UpstreamResponse& GetResponse() const { return response_; }
    UpstreamResponse& GetResponse() { return response_; }

    // Reset parser state for the next response (connection reuse).
    void Reset();

    // Error state
    bool HasError() const { return has_error_; }
    std::string GetError() const { return error_message_; }
    ParseError GetErrorType() const { return error_type_; }

    // Public fields for llhttp callbacks (same pattern as HttpParser).
    // These are accessed by the static C callback functions defined in the .cc file.
    UpstreamResponse response_;
    bool has_error_ = false;
    std::string error_message_;
    ParseError error_type_ = ParseError::NONE;
    std::string current_header_field_;
    std::string current_header_value_;
    bool parsing_header_value_ = false;
    bool in_header_field_ = false;  // true while accumulating same header field across fragments
    UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseSink* sink_ = nullptr;
    UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead::Framing framing_hint_ =
        UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead::Framing::NO_BODY;
    int64_t expected_length_ = -1;
    bool paused_ = false;

private:
    // llhttp internals (pimpl -- llhttp.h only included in .cc)
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
