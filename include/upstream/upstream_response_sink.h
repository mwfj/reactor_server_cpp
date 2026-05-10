#pragma once

#include "upstream/upstream_response_head.h"

namespace UPSTREAM_CALLBACKS_NAMESPACE {

class UpstreamResponseSink {
public:
    virtual ~UpstreamResponseSink() = default;

    virtual bool OnHeaders(const UpstreamResponseHead& head) = 0;
    virtual bool OnBodyChunk(const char* data, size_t len) = 0;
    // Trailing HEADERS block. Codecs MAY elide an empty trailers block
    // (RFC 9113 §8.1 allows it on H2; the H2 codec does so today) — sinks
    // that need a "block arrived" signal regardless of payload should
    // observe stream completion through OnComplete instead. Default impl
    // is a no-op so sinks uninterested in trailers don't need to override.
    virtual void OnTrailers(
        const std::vector<std::pair<std::string, std::string>>&) {}
    virtual void OnComplete() = 0;
    virtual void OnError(int error_code, const std::string& message) = 0;

    // Fired when the upstream stream's request side is fully sent
    // (END_STREAM flag observed on either DATA or HEADERS — bodyless
    // requests trigger END_STREAM on HEADERS). Sinks use this to swap
    // a per-stream send-stall deadline for a response-completion
    // deadline.
    //
    // H2 path only. The H1 path infers send completion from socket
    // buffer drain and does not call this. Default no-op so non-H2
    // sinks can ignore.
    //
    // Invocation timing: may fire SYNCHRONOUSLY from within
    // UpstreamH2Connection::SubmitRequest for bodyless requests where
    // nghttp2 inline-flushes the HEADERS+END_STREAM frame. Sinks MUST
    // be safe to receive this callback before SubmitRequest returns
    // control to the caller.
    virtual void OnRequestSubmitted() {}

    // Fired when an intermediate request-side DATA frame is flushed
    // to the wire (END_STREAM not yet set). Sinks use this to refresh
    // the per-stream send-stall deadline so a slow-but-progressing
    // upload — body larger than the stall budget but the peer is still
    // consuming — is not falsely classified as a stall. Mirrors the
    // H1 transport-level SetWriteProgressCb refresh.
    //
    // H2 path only. Default no-op.
    virtual void OnRequestBodyProgress() {}
};

}  // namespace UPSTREAM_CALLBACKS_NAMESPACE
