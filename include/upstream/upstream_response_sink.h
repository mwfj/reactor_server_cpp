#pragma once

#include "upstream/upstream_response_head.h"

namespace UPSTREAM_CALLBACKS_NAMESPACE {

// New virtuals must have default no-op bodies to preserve embedder
// ABI; pure-virtual additions break every existing sink subclass.
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
    //
    // Contract details for sink implementers:
    //   * Fires once per intermediate DATA frame the codec actually
    //     emits to the wire. If nghttp2 coalesces two writes into one
    //     DATA frame, only one callback fires; if the body is large
    //     enough to span multiple DATA frames at MAX_FRAME_SIZE, one
    //     callback fires per frame.
    //   * NOT a 1:1 byte-progress signal — do not use it for byte
    //     accounting (use OnBodyChunk's len for that on the response
    //     side; the request side has no analogous accounting hook).
    //   * Ordering relative to OnHeaders/OnRequestSubmitted is the
    //     wire order: progress events on stream N can fire before or
    //     after response-side callbacks for stream N depending on
    //     peer scheduling.
    //   * Production sinks (ProxyTransaction) gate refresh logic on
    //     their own state machine — progress events outside the
    //     SENDING_REQUEST phase are silently dropped at the sink. The
    //     C-shim DOES dispatch unconditionally, so other sinks must
    //     gate similarly OR be safe under arrival of progress events
    //     at any time relative to other callbacks.
    virtual void OnRequestBodyProgress() {}
};

}  // namespace UPSTREAM_CALLBACKS_NAMESPACE
