#pragma once

#include "common.h"
#include "upstream/upstream_response.h"
#include "upstream/upstream_response_sink.h"
#include "upstream/upstream_callbacks.h"
// <cstdint>, <string>, <memory> provided by common.h (via upstream_response.h)

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
    UpstreamResponse response;
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

    UpstreamH2Stream() = default;
    UpstreamH2Stream(const UpstreamH2Stream&) = delete;
    UpstreamH2Stream& operator=(const UpstreamH2Stream&) = delete;
};
