#pragma once

#include "common.h"
#include "upstream/upstream_response_sink.h"
#include "upstream/upstream_callbacks.h"
#include "http/body_stream.h"
// <cstdint>, <string>, <memory>, <functional> provided by common.h.

// Heap-held source that nghttp2 reads from when streaming a request body.
// Owned by the UpstreamH2Stream that submitted the request — the data
// provider read_callback dereferences `this` until offset == body.size(),
// then signals END_STREAM via NGHTTP2_DATA_FLAG_EOF.
struct UpstreamH2BodySource {
    std::string body;
    size_t offset = 0;
};

// Per-stream state for an outbound H2 request. One UpstreamH2Stream is
// created per ProxyTransaction that dispatches over an H2 connection;
// the stream is keyed by the nghttp2 stream_id assigned at submit time.
// Public fields — written from nghttp2 frame callbacks (mirrors the
// public-fields layout of UpstreamHttpCodec for the same reason).
struct UpstreamH2Stream {
    int32_t stream_id = -1;
    // Snapshot of the response head delivered to OnHeaders. Built from
    // the per-frame :status / header rows so the sink contract receives
    // a well-formed UpstreamResponseHead even though the parser-driven
    // H1 path uses a different intermediate.
    UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead response_head;
    UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseSink* sink = nullptr;
    bool ended = false;
    // Set true after the first END_HEADERS HEADERS frame fires
    // OnHeaders. Subsequent HEADERS frames (e.g. trailers) take a
    // different code path, so guard against re-dispatching the head.
    bool head_dispatched = false;
    // Set when the first HEADERS frame carried an informational status
    // (1xx). The next HEADERS frame is then expected to be the final
    // response (or another 1xx); response_head accumulators are cleared
    // at the boundary so the final headers overlay cleanly.
    bool saw_1xx_interim = false;
    // Trailing HEADERS frame contents accumulated when HCAT_HEADERS
    // arrives after head_dispatched. Dispatched via sink->OnTrailers
    // when the trailing block ends.
    std::vector<std::pair<std::string, std::string>> trailers;
    // Holds the request-body buffer used by the nghttp2 data provider
    // read_callback. Empty for bodyless requests.
    std::unique_ptr<UpstreamH2BodySource> body_source;

    // Set for streaming requests. When non-null, nghttp2 reads from body_stream
    // via UpstreamH2Connection::StreamingDataSourceReadCallback rather than from
    // body_source. Mutually exclusive with body_source.
    std::shared_ptr<http::BodyStream> body_stream;

    // Fire-once flag for OnRequestHeadersSubmitted dispatch from
    // OnFrameSendCallback's NGHTTP2_HEADERS/NGHTTP2_HCAT_REQUEST branch.
    bool headers_submitted_callback_fired_ = false;

    // Deferred terminal-classification fields for streaming-side aborts.
    // StreamingDataSourceReadCallback's ABORTED branch stores classification
    // here and returns TEMPORAL_CALLBACK_FAILURE; OnStreamClose then consumes
    // these fields and dispatches the terminal sink->OnError on a clean stack.
    bool streaming_abort_pending = false;
    int streaming_abort_code = 0;
    std::string streaming_abort_message;

    // Per-stream txn keepalive + deferred terminal-error callback.
    // Constructed at SubmitStreamingRequest time (while the OnCheckoutReady
    // strong-self capture is on the stack). Serves double duty: (a) keeps the
    // ProxyTransaction alive for the entire H2 stream lifetime so the raw
    // `sink` pointer cannot dangle; (b) deferred terminal-error callback
    // consumed by OnStreamClose's streaming-abort branch.
    // Empty std::function = no keepalive (legacy/test sinks).
    std::function<void(int, const std::string&)> streaming_abort_callback;

    // Set at submit time so frame callbacks can detect HEAD-on-NO_BODY
    // (RFC 9110 §9.3.2) without reaching back into the codec or proxy
    // transaction. Populated between make_shared and the streams_ insert
    // in UpstreamH2Connection::SubmitRequest — race-free because frame
    // callbacks for the new stream cannot fire until peer bytes arrive
    // via HandleBytes.
    std::string request_method;

    // Cumulative response body bytes delivered to the sink (or rejected
    // synchronously by Step 1.5 NO_BODY/CL validation). Validated against
    // response_head.expected_length on each chunk and at clean close to
    // catch peers that lie about Content-Length.
    int64_t body_bytes_received = 0;

    // Set by OnStreamClose; read by DetachSink to gate walker enqueue.
    bool peer_already_closed_ = false;
    // Marker for the deferred-erase walker.
    bool pending_erase_ = false;

    UpstreamH2Stream() = default;
    UpstreamH2Stream(const UpstreamH2Stream&) = delete;
    UpstreamH2Stream& operator=(const UpstreamH2Stream&) = delete;
};
