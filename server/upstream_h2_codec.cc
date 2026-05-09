#include "upstream/upstream_h2_codec.h"
#include "log/logger.h"

UpstreamH2Codec::UpstreamH2Codec() = default;
UpstreamH2Codec::~UpstreamH2Codec() = default;

void UpstreamH2Codec::Reset() {
    response_ = UpstreamResponse{};
    // Do not clear request_method_: callers are expected to call
    // SetRequestMethod() after Reset() when the method changes, matching
    // the H1 codec's Reset() contract.
    paused_ = false;
    has_error_ = false;
    error_message_.clear();
}

void UpstreamH2Codec::SetRequestMethod(const std::string& method) {
    request_method_ = method;
}

void UpstreamH2Codec::SetSink(
    UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseSink* sink)
{
    sink_ = sink;
}

size_t UpstreamH2Codec::Parse(const char* /*data*/, size_t len) {
    // Bytes for an H2 stream arrive via the parent UpstreamH2Connection's
    // nghttp2_session — direct Parse() on the per-stream codec is not a
    // legal call path. Treat as a programming error: log and reject so
    // a misrouted caller fails visibly instead of silently dropping data.
    has_error_ = true;
    error_message_ = "UpstreamH2Codec::Parse called directly; bytes must "
                      "route through UpstreamH2Connection";
    logging::Get()->error(
        "BUG: UpstreamH2Codec::Parse called directly len={}", len);
    return 0;
}

bool UpstreamH2Codec::Finish() {
    return false;
}

void UpstreamH2Codec::PauseParsing() {
    paused_ = true;
}

void UpstreamH2Codec::ResumeParsing() {
    paused_ = false;
}
