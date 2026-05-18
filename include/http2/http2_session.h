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
        bool     enable_push            = false;  // see Http2Config::enable_push
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

    // True while ReceiveData() is on the call stack (i.e. we are inside
    // nghttp2_session_mem_recv2). Used by primitives that may be invoked
    // from an inline sync handler running inside on_frame_recv to avoid
    // reentrant nghttp2_session_mem_send2 calls — the caller of
    // ReceiveData() always flushes on the way out, so these primitives
    // can safely skip the inline flush.
    bool InReceiveData() const { return in_receive_data_; }

    // Pull pending output bytes from nghttp2 and send via
    // ConnectionHandler::SendRaw(). Returns true if any bytes were sent.
    // MUST be called after every operation that may produce output.
    bool SendPendingFrames();

    // Streaming-request consumer batching. Accumulates bytes against a
    // per-stream counter; when the threshold is reached, emits WINDOW_UPDATE
    // for both stream and connection windows via the canonical send path
    // (deferred flush when InReceiveData(), else inline SendPendingFrames).
    // Returns true if a window update was emitted; false if the stream
    // is gone or the threshold is not yet reached. Dispatcher-thread-only.
    bool ConsumeStreamingRequestBytes(int32_t stream_id, size_t consumed,
                                       size_t threshold);

    // Force-flush sub-threshold WINDOW_UPDATE residue at terminal paths
    // (inbound END_STREAM on DATA, stream cleanup before erase, every
    // abort path). Idempotent: no-op when pending == 0 or stream is gone.
    // Dispatcher-thread-only.
    void ForceFlushStreamConsume(int32_t stream_id);

    // Abort/RST cleanup: flush drained-but-not-yet-credited bytes AND refund
    // the connection-level credit for residue queued in body_stream that
    // the consumer will never read. Single FindStream + single
    // SendPendingFrames pass — preferred over ForceFlushStreamConsume at
    // abort sites because it covers both the drained-credit-flush and the
    // discarded-residue-refund concerns. Dispatcher-thread-only.
    void FinalizeAbortedStreamFlowControl(int32_t stream_id);

    // Per-stream WINDOW_UPDATE backpressure. Suspend marks the stream so
    // ConsumeStreamingRequestBytes accumulates drained bytes without
    // emitting WINDOW_UPDATE — the peer's per-stream window drains and
    // upload back-pressure flows upstream. Resume clears the latch and
    // force-flushes accumulated credit so the peer can resume sending.
    // Dispatcher-thread-only.
    void SuspendWindowUpdateForStream(int32_t stream_id);
    void ResumeWindowUpdateForStream(int32_t stream_id);

    // Streaming watermark accessors (set from Http2Config at initialization).
    size_t StreamingHighWaterBytes() const { return streaming_high_water_; }
    size_t StreamingLowWaterBytes() const { return streaming_low_water_; }
    size_t StreamingWindowUpdateBytes() const { return streaming_window_update_; }
    void SetStreamingConfig(size_t high, size_t low, size_t window_update) {
        streaming_high_water_ = high;
        streaming_low_water_ = low;
        streaming_window_update_ = window_update;
    }

    // Check if nghttp2 has pending output bytes.
    bool WantWrite() const;

    // --- Server connection preface ---

    // Send the server connection preface (SETTINGS frame).
    // Must be called once after construction before processing client data.
    void SendServerPreface();

    // --- Response submission ---

    // Result codes for SubmitTrailers.
    enum class SubmitTrailersResult {
        OK,                  // Trailers queued successfully
        NoTrailersSubmitted, // Post-sanitize set was empty; caller must emit EOF alone
        NoSuchStream,        // Stream not found in nghttp2 (handler or session gone)
        InvalidTrailer,      // nghttp2 rejected a trailer field name/value
        SubmitFailed         // nghttp2 returned a fatal error
    };

    // Submit response trailers on a stream. Sanitizes via
    // SanitizeHttp2TrailerFieldsForOutboundEmit before forwarding to nghttp2.
    // On NoTrailersSubmitted the caller MUST emit NGHTTP2_DATA_FLAG_EOF alone
    // (never EOF|NO_END_STREAM when no trailer HEADERS frame was queued).
    // MUST be called from inside the data-source read callback (inside
    // nghttp2_session_mem_send2); the caller owns the flush on the way out.
    // Dispatcher-thread-only.
    SubmitTrailersResult SubmitTrailers(
        int32_t stream_id,
        const std::vector<std::pair<std::string, std::string>>& trailers);

    // Submit HTTP response for a stream. Returns 0 on success.
    int SubmitResponse(int32_t stream_id, const HttpResponse& response);

    int SubmitStreamingResponse(
        int32_t stream_id,
        const HttpResponse& response,
        std::shared_ptr<ResponseDataSource> data_source);

    // Submit a non-final 1xx informational response on a stream WITHOUT
    // END_STREAM (RFC 9113 + RFC 8297). Status must be in [102, 200) and
    // not 101 (HTTP/2 forbids 101). Forbidden / pseudo / hop-by-hop
    // headers are stripped to match the SubmitResponse policy.
    // Returns 0 on success, -1 on validation or nghttp2 failure.
    // Caller is responsible for flushing output via SendPendingFrames().
    // Dispatcher-thread-only.
    int SubmitInterimHeaders(
        int32_t stream_id,
        int status_code,
        const std::vector<std::pair<std::string, std::string>>& headers);

    // ---- HTTP/2 server push (RFC 9113 §8.4) ----

    // True iff (a) local config enables push AND (b) the peer has not
    // advertised SETTINGS_ENABLE_PUSH=0. Reads nghttp2's snapshot of the
    // peer's most-recently-ACKed remote settings. Dispatcher-thread-only.
    bool PushEnabled() const;

    // Create a server-initiated stream entry for a freshly-promised push.
    // Skips the incomplete-stream lifecycle entirely — pushed streams are
    // never request-parsed and so must not contribute to the parse-timeout
    // safety cap (`parse_timeout_sec` branch of ResetExpiredStreams) nor
    // to OldestIncompleteStreamStart(). Returns the new (or existing on
    // duplicate id) stream pointer; callers should EraseStream(id) on
    // any subsequent submit failure.
    Http2Stream* CreateServerInitiatedStream(int32_t stream_id);

    // Remove a stream entry — used as the rollback path when a push
    // submit fails after the synthetic stream has been registered.
    void EraseStream(int32_t stream_id);

    // Atomically submit PUSH_PROMISE on `parent_stream_id` and the
    // associated response on the newly promised stream. Returns the
    // promised stream_id (>0) on success or -1 on any validation /
    // nghttp2 failure. On failure, any synthetic stream registered as
    // a side effect is rolled back via EraseStream.
    //
    // Validation enforced here (RFC 9113 §8.4 + §8.2):
    //   - method must be GET or HEAD (no body on the push request)
    //   - scheme must be http or https
    //   - authority must be non-empty
    //   - path must start with '/'
    //   - PushEnabled() must be true (local config + peer hasn't refused)
    //   - GOAWAY must not have been sent
    //   - parent stream must exist and be open
    int32_t SubmitPushPromise(int32_t parent_stream_id,
                              const std::string& method,
                              const std::string& scheme,
                              const std::string& authority,
                              const std::string& path,
                              const HttpResponse& response);

    // --- Connection management ---

    // Send GOAWAY frame with the given error code.
    void SendGoaway(uint32_t error_code = 0);

    // Send RST_STREAM for a specific stream.
    void ResetStream(int32_t stream_id, uint32_t error_code);
    int ResumeStreamData(int32_t stream_id);

    // Check if the session is still alive
    bool IsAlive() const;

    // Output backpressure: stop pulling frames when output buffer exceeds
    // the watermark. Resume when buffer drains (triggered by handler).
    // All state is dispatcher-thread only — no atomics needed.
    bool HasDeferredOutput() const { return output_deferred_; }
    void ClearDeferredOutput() { output_deferred_ = false; }
    void ResumeOutput();
    size_t OutputHighWatermark() const {
        static constexpr size_t MIN_WATERMARK = 131072;  // 128 KB
        return std::max(MIN_WATERMARK, static_cast<size_t>(settings_.max_frame_size));
    }

    // --- Stream management ---

    Http2Stream* FindStream(int32_t stream_id);
    Http2Stream* CreateStream(int32_t stream_id);
    void MarkStreamForRemoval(int32_t stream_id);
    size_t ActiveStreamCount() const;
    // Streams whose close callback has NOT yet fired. Used for counter
    // compensation when the transport closes abruptly — avoids double-
    // subtracting streams already decremented by the close callback.
    size_t UnclosedStreamCount() const;

    // --- Callbacks (set by Http2ConnectionHandler) ---

    void SetRequestCallback(HTTP2_CALLBACKS_NAMESPACE::Http2RequestCallback cb);
    void SetStreamCloseCallback(HTTP2_CALLBACKS_NAMESPACE::Http2StreamCloseCallback cb);
    // SetStreamOpenCallback: callback fires during nghttp2 frame processing
    // (inside ReceiveData). Callers MUST NOT submit nghttp2 frames from
    // within this callback — doing so is reentrant into nghttp2 and unsafe.
    void SetStreamOpenCallback(HTTP2_CALLBACKS_NAMESPACE::Http2StreamOpenCallback cb);
    void SetRequestCountCallback(HTTP2_CALLBACKS_NAMESPACE::Http2RequestCountCallback cb);
    void SetResolveRouteOptionsCallback(
        HTTP2_CALLBACKS_NAMESPACE::ResolveRouteOptionsCallback cb);

    // --- Flood protection ---

    // Called on each received frame. Returns false if flood detected.
    bool CheckFloodProtection(uint8_t frame_type, uint8_t flags, int32_t stream_id);

    // Access the underlying connection handler
    std::shared_ptr<ConnectionHandler> GetConnection() const { return conn_; }

    // Get the last stream ID we have processed (for GOAWAY)
    int32_t LastStreamId() const { return last_stream_id_.load(std::memory_order_acquire); }
    bool IsGoawaySent() const { return goaway_sent_; }

    // Incomplete stream tracking for request-timeout enforcement.
    // The deadline is based on the OLDEST incomplete stream's creation time,
    // so a fresh stream cannot extend the timeout for older stalled streams.
    size_t IncompleteStreamCount() const { return incomplete_stream_count_; }
    void OnStreamBecameIncomplete() { ++incomplete_stream_count_; }
    void OnStreamNoLongerIncomplete() {
        if (incomplete_stream_count_ > 0) --incomplete_stream_count_;
    }

    // Returns the creation time of the oldest incomplete (not-yet-dispatched)
    // stream. Used to set an absolute deadline that cannot be extended by new
    // streams. Returns time_point::max() if no incomplete streams exist.
    std::chrono::steady_clock::time_point OldestIncompleteStreamStart() const;

    // RST_STREAM streams that have exceeded either of two caps:
    //   - parse_timeout_sec: incomplete (non-counter-decremented)
    //     streams whose request parsing is still in progress. 0 = skip.
    //   - async_cap_sec: async (counter-decremented) streams where the
    //     handler never submitted a response — last-resort safety net
    //     for stuck handlers. 0 = skip. When > 0 this MUST be set by
    //     the caller to a value at least as large as the longest
    //     configured handler timeout (e.g., proxy.response_timeout_ms)
    //     so it doesn't override operator config.
    // Returns the number of streams reset. Caller should call
    // SendPendingFrames() and UpdateDeadline() after this.
    //
    // If async_cap_reset_ids is non-null, the IDs of streams RST'd by
    // the async_cap_sec branch (and only that branch) are appended so
    // the caller can fire per-stream abort hooks that release the
    // stored handler-side bookkeeping (e.g., active_requests decrement).
    size_t ResetExpiredStreams(int parse_timeout_sec, int async_cap_sec = 0,
                               std::vector<int32_t>* async_cap_reset_ids = nullptr);

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
    std::weak_ptr<Http2ConnectionHandler> WeakOwner() const { return owner_; }

    // Access callbacks (used by static nghttp2 callback functions)
    HTTP2_CALLBACKS_NAMESPACE::Http2SessionCallbacks& Callbacks() { return callbacks_; }

    // Validate and dispatch a complete request on a stream.
    // Called from OnFrameRecvCallback (static) for both HEADERS and DATA END_STREAM.
    void DispatchStreamRequest(Http2Stream* stream, int32_t stream_id);

    // Streaming-route dispatch path. Same as DispatchStreamRequest but skips
    // the AccumulatedBodySize == content_length post-buffered check; streaming
    // bytes live in body_stream, not in the buffered body. CL enforcement is
    // split: OVERRUN on each DATA chunk, UNDERRUN at DATA/trailer END_STREAM.
    // request_count_callback fires exactly once (same pattern as
    // DispatchStreamRequest). Called from OnFrameRecvCallback HCAT_REQUEST branch
    // at HEADERS-complete for streaming routes.
    void DispatchStreamRequestStreaming(Http2Stream* stream, int32_t stream_id);

private:
    // Shared body of ForceFlushStreamConsume and FinalizeAbortedStreamFlowControl.
    // `flush_send=false` lets the caller batch a single trailing
    // SendPendingFrames when multiple flow-control updates feed the same wire.
    void FlushStreamConsumeOnStream(Http2Stream* stream, int32_t stream_id,
                                     bool flush_send);

    // Helper: submit a GOAWAY frame and only latch goaway_sent_ on
    // successful submit. Used by SendGoaway + every flood-protection
    // branch in OnFrameRecvCallback. Centralizing avoids the "set flag,
    // discard rv" anti-pattern that made drain wait for the full
    // shutdown_drain_timeout_sec when a submit failed. Must be called
    // from the dispatcher thread.
    //
    // last_stream_id_override — used by flood branches that need the
    // nghttp2 live last-proc-stream-id (last_stream_id_ is a cached
    // snapshot that may be stale mid-recv); pass -1 to fall back to
    // the atomic last_stream_id_.
    //
    // flush — pass false when called from inside an nghttp2_session_mem_recv2
    // callback (flood branches) because flushing from within a recv
    // callback is unsafe. The caller must flush after recv returns.
    void SubmitGoawayChecked(uint32_t error_code,
                              int32_t last_stream_id_override,
                              bool flush);

    // Pimpl for nghttp2
    struct Impl;
    std::unique_ptr<Impl> impl_;

    std::shared_ptr<ConnectionHandler> conn_;
    std::map<int32_t, std::unique_ptr<Http2Stream>> streams_;
    Settings settings_;

    HTTP2_CALLBACKS_NAMESPACE::Http2SessionCallbacks callbacks_;

    std::weak_ptr<Http2ConnectionHandler> owner_;

    std::atomic<int32_t> last_stream_id_{0};
    bool goaway_sent_ = false;
    bool output_deferred_ = false;  // dispatcher-thread only
    // True while ReceiveData() is on the stack. Used to detect and
    // suppress reentrant SendPendingFrames() calls when an inline sync
    // handler invokes send_interim / push_resource from within an
    // on_frame_recv callback. See Http2Session::InReceiveData().
    bool in_receive_data_ = false;
    size_t max_body_size_ = 0;
    size_t incomplete_stream_count_ = 0;
    size_t max_header_list_size_ = 0;

    // Streaming watermark config (set from Http2Config::streaming at init).
    size_t streaming_high_water_ = 262144;    // 256 KB
    size_t streaming_low_water_  = 65536;     // 64 KB
    size_t streaming_window_update_ = 32768;  // 32 KB

    // Flood protection counters (sliding window)
    int settings_count_ = 0;
    int ping_count_ = 0;
    int rst_stream_count_ = 0;
    std::chrono::steady_clock::time_point flood_window_start_;

    // Deferred stream deletion list (never delete during nghttp2 callback)
    std::vector<int32_t> streams_to_remove_;
    void FlushDeferredRemovals();
};
