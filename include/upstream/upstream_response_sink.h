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

    // Fired on END_STREAM (HEADERS for bodyless, DATA otherwise). H2
    // only. May fire synchronously from within SubmitRequest for
    // bodyless requests — sinks must be reentrant relative to submit.
    virtual void OnRequestSubmitted() {}

    // Fired when the request HEADERS frame is on the wire (serialized
    // into the transport send buffer). H2 fires from OnFrameSendCallback
    // when frame->headers.cat == NGHTTP2_HCAT_REQUEST. H1 fires
    // synchronously after transport->SendRaw(headers) returns. Per-stream
    // fire-once. Default no-op.
    virtual void OnRequestHeadersSubmitted() {}

    // Fired per transport-drain accounting tick for the request-side
    // body. `bytes_drained` is the byte count just acknowledged by the
    // transport. Drives per-request progress accounting (e.g.
    // body_bytes_written_to_upstream_).
    virtual void OnRequestBodyProgress(size_t /*bytes_drained*/) {}

    // Fired when bytes are consumed from the producer-side body source
    // (used by the streaming body pipeline to refresh window credit
    // accounting). `bytes` is the count just consumed.
    virtual void OnRequestBodySourceConsumed(size_t /*bytes*/) {}

    // Returns a self-contained callable the H2 connection invokes from a
    // deferred dispatcher task to deliver a terminal OnError. The returned
    // function MUST capture a STRONG owner so it is safe to invoke after
    // every other ref to the sink has been released. Default returns an
    // empty std::function — caller falls through to synchronous in-place
    // dispatch.
    virtual std::function<void(int, const std::string&)>
    MakeDeferredErrorCallback() {
        return {};
    }
};

}  // namespace UPSTREAM_CALLBACKS_NAMESPACE
