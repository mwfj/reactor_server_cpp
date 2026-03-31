#pragma once

#include "common.h"
// <functional>, <memory>, <string>, <cstdint> provided by common.h

// Forward declarations
class Http2ConnectionHandler;
class Http2Stream;
struct HttpRequest;
class HttpResponse;

namespace HTTP2_CALLBACKS_NAMESPACE {

    // Called when a complete HTTP/2 request is ready for dispatch.
    // The handler should populate the response.
    using Http2RequestCallback = std::function<void(
        std::shared_ptr<Http2ConnectionHandler> self,
        int32_t stream_id,
        const HttpRequest& request,
        HttpResponse& response
    )>;

    // Called when a stream is closed (RST_STREAM, END_STREAM, or error).
    using Http2StreamCloseCallback = std::function<void(
        std::shared_ptr<Http2ConnectionHandler> self,
        int32_t stream_id,
        uint32_t error_code
    )>;

    // Called when a new HTTP/2 stream is opened (HEADERS received).
    using Http2StreamOpenCallback = std::function<void(
        std::shared_ptr<Http2ConnectionHandler> self,
        int32_t stream_id
    )>;

    // Fires at DispatchStreamRequest entry — before content-length rejection
    // but after a complete request parse. Used to count all dispatched requests
    // including those rejected by the session (consistent with HTTP/1).
    using Http2RequestCountCallback = std::function<void()>;

    struct Http2SessionCallbacks {
        Http2RequestCallback      request_callback       = nullptr;
        Http2StreamCloseCallback  stream_close_callback  = nullptr;
        Http2StreamOpenCallback   stream_open_callback   = nullptr;
        Http2RequestCountCallback request_count_callback = nullptr;
    };

} // namespace HTTP2_CALLBACKS_NAMESPACE
