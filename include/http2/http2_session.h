#pragma once

#include "http2/http2_stream.h"
#include "http2/http2_callbacks.h"
#include "http2/http2_constants.h"
#include "connection_handler.h"
// <memory>, <map>, <vector>, <cstdint>, <chrono> provided by common.h

class Http2Session {
public:
    // Server-side session settings
    struct Settings {
        uint32_t max_concurrent_streams = HTTP2_CONSTANTS::DEFAULT_MAX_CONCURRENT_STREAMS;
        uint32_t initial_window_size    = HTTP2_CONSTANTS::DEFAULT_INITIAL_WINDOW_SIZE;
        uint32_t max_frame_size         = HTTP2_CONSTANTS::DEFAULT_MAX_FRAME_SIZE;
        uint32_t max_header_list_size   = HTTP2_CONSTANTS::DEFAULT_MAX_HEADER_LIST_SIZE;
    };

    explicit Http2Session(std::shared_ptr<ConnectionHandler> conn,
                          const Settings& settings);
    ~Http2Session();

    // Non-copyable, non-movable (owns nghttp2_session*)
    Http2Session(const Http2Session&) = delete;
    Http2Session& operator=(const Http2Session&) = delete;
    Http2Session(Http2Session&&) = delete;
    Http2Session& operator=(Http2Session&&) = delete;

    // --- Core I/O integration ---

    // Feed received bytes to nghttp2. Returns number of bytes consumed,
    // or -1 on fatal error. After this call, check WantWrite() and
    // call SendPendingFrames() if true.
    ssize_t ReceiveData(const char* data, size_t len);

    // Pull pending output bytes from nghttp2 and send via
    // ConnectionHandler::SendRaw(). Returns true if any bytes were sent.
    // MUST be called after every operation that may produce output.
    bool SendPendingFrames();

    // Check if nghttp2 has pending output bytes.
    bool WantWrite() const;

    // --- Server connection preface ---

    // Send the server connection preface (SETTINGS frame).
    // Must be called once after construction before processing client data.
    void SendServerPreface();

    // --- Response submission ---

    // Submit HTTP response for a stream. Returns 0 on success.
    int SubmitResponse(int32_t stream_id, const HttpResponse& response);

    // --- Connection management ---

    // Send GOAWAY frame with the given error code.
    void SendGoaway(uint32_t error_code = 0);

    // Send RST_STREAM for a specific stream.
    void ResetStream(int32_t stream_id, uint32_t error_code);

    // Check if the session is still alive
    bool IsAlive() const;

    // --- Stream management ---

    Http2Stream* FindStream(int32_t stream_id);
    Http2Stream* CreateStream(int32_t stream_id);
    void MarkStreamForRemoval(int32_t stream_id);
    size_t ActiveStreamCount() const;

    // --- Callbacks (set by Http2ConnectionHandler) ---

    void SetRequestCallback(HTTP2_CALLBACKS_NAMESPACE::Http2RequestCallback cb);
    void SetStreamCloseCallback(HTTP2_CALLBACKS_NAMESPACE::Http2StreamCloseCallback cb);

    // --- Flood protection ---

    // Called on each received frame. Returns false if flood detected.
    bool CheckFloodProtection(uint8_t frame_type, uint8_t flags, int32_t stream_id);

    // Access the underlying connection handler
    std::shared_ptr<ConnectionHandler> GetConnection() const { return conn_; }

    // Get the last stream ID we have processed (for GOAWAY)
    int32_t LastStreamId() const { return last_stream_id_; }
    bool IsGoawaySent() const { return goaway_sent_; }

    // Incomplete stream tracking for request-timeout enforcement.
    // incomplete_stream_count_: streams whose request hasn't been dispatched yet.
    // incomplete_generation_: bumped each time a new incomplete stream is created.
    //   Used to detect "new stream arrived" even when same-batch close+open
    //   leaves the count unchanged.
    size_t IncompleteStreamCount() const { return incomplete_stream_count_; }
    uint64_t IncompleteGeneration() const { return incomplete_generation_; }
    void OnStreamBecameIncomplete() {
        ++incomplete_stream_count_;
        ++incomplete_generation_;
    }
    void OnStreamNoLongerIncomplete() {
        if (incomplete_stream_count_ > 0) --incomplete_stream_count_;
    }

    // Body size limit (set from config, checked during data ingestion)
    void SetMaxBodySize(size_t max) { max_body_size_ = max; }
    size_t MaxBodySize() const { return max_body_size_; }

    // Header list size limit — advertised via SETTINGS and enforced in OnHeaderCallback
    void SetMaxHeaderListSize(size_t max) {
        max_header_list_size_ = max;
        settings_.max_header_list_size = static_cast<uint32_t>(max);
    }
    size_t MaxHeaderListSize() const { return settings_.max_header_list_size; }

    // Owner reference — set by Http2ConnectionHandler after construction.
    // Used to pass a valid shared_ptr to request/stream-close callbacks.
    void SetOwner(std::weak_ptr<Http2ConnectionHandler> owner) {
        owner_ = std::move(owner);
    }
    std::shared_ptr<Http2ConnectionHandler> Owner() const { return owner_.lock(); }

    // Access callbacks (used by static nghttp2 callback functions)
    HTTP2_CALLBACKS_NAMESPACE::Http2SessionCallbacks& Callbacks() { return callbacks_; }

    // Validate and dispatch a complete request on a stream.
    // Called from OnFrameRecvCallback (static) for both HEADERS and DATA END_STREAM.
    void DispatchStreamRequest(Http2Stream* stream, int32_t stream_id);

private:
    // Pimpl for nghttp2
    struct Impl;
    std::unique_ptr<Impl> impl_;

    std::shared_ptr<ConnectionHandler> conn_;
    std::map<int32_t, std::unique_ptr<Http2Stream>> streams_;
    Settings settings_;

    HTTP2_CALLBACKS_NAMESPACE::Http2SessionCallbacks callbacks_;

    std::weak_ptr<Http2ConnectionHandler> owner_;

    int32_t last_stream_id_ = 0;
    bool goaway_sent_ = false;
    size_t max_body_size_ = 0;
    size_t incomplete_stream_count_ = 0;
    uint64_t incomplete_generation_ = 0;
    size_t max_header_list_size_ = 0;

    // Flood protection counters (sliding window)
    int settings_count_ = 0;
    int ping_count_ = 0;
    int rst_stream_count_ = 0;
    std::chrono::steady_clock::time_point flood_window_start_;

    // Deferred stream deletion list (never delete during nghttp2 callback)
    std::vector<int32_t> streams_to_remove_;
    void FlushDeferredRemovals();
};
