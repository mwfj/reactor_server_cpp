#pragma once

#include "http/http_callbacks.h"
#include "http2/http2_session.h"
#include "http2/http2_callbacks.h"
#include "connection_handler.h"
// <memory> provided by common.h (via connection_handler.h)

class Http2ConnectionHandler : public std::enable_shared_from_this<Http2ConnectionHandler> {
public:
    explicit Http2ConnectionHandler(
        std::shared_ptr<ConnectionHandler> conn,
        const Http2Session::Settings& settings);
    ~Http2ConnectionHandler();

    // Type aliases for callbacks (set by HttpServer)
    using RequestCallback     = HTTP2_CALLBACKS_NAMESPACE::Http2RequestCallback;
    using StreamCloseCallback = HTTP2_CALLBACKS_NAMESPACE::Http2StreamCloseCallback;
    using StreamOpenCallback  = HTTP2_CALLBACKS_NAMESPACE::Http2StreamOpenCallback;

    void SetRequestCallback(RequestCallback callback);
    void SetStreamCloseCallback(StreamCloseCallback callback);
    void SetStreamOpenCallback(StreamOpenCallback callback);
    void SetRequestCountCallback(HTTP2_CALLBACKS_NAMESPACE::Http2RequestCountCallback callback);

    // Set request limits (applied per-stream)
    void SetMaxBodySize(size_t max);
    void SetMaxHeaderSize(size_t max);
    void SetRequestTimeout(int seconds);
    // Absolute safety cap for async (counter-decremented) streams that
    // never submit a response. Computed by HttpServer from upstream
    // configs so it honors the largest configured proxy.response_timeout_ms.
    // 0 = disabled (no cap). See HttpServer::max_async_deferred_sec_.
    void SetMaxAsyncDeferredSec(int sec);

    // Called when raw data arrives from the reactor (entry point)
    void OnRawData(std::shared_ptr<ConnectionHandler> conn, std::string& data);

    // Initialize the HTTP/2 session and send server preface.
    // Optionally accepts initial data (preface bytes already buffered).
    void Initialize(const std::string& initial_data = "");

    // Request graceful shutdown. Thread-safe: sets atomic flag and enqueues
    // dispatcher-thread task that sends GOAWAY and initiates drain.
    void RequestShutdown();

    // Called when transport output buffer drains to zero.
    // Schedules async resume if session has deferred output.
    void OnSendComplete();

    // Called after each partial write with the remaining buffer size.
    // Resumes deferred nghttp2 output when buffer drops below watermark.
    void OnWriteProgress(size_t remaining_bytes);

    // Callback invoked (once) when the connection finishes draining all
    // active streams during graceful shutdown. Called on dispatcher thread.
    using DrainCompleteCallback = std::function<void()>;
    void SetDrainCompleteCallback(DrainCompleteCallback cb);

    // Access the underlying connection
    std::shared_ptr<ConnectionHandler> GetConnection() const { return conn_; }

    // Access the session (for stream count, alive check, etc.)
    Http2Session* GetSession() { return session_.get(); }

    // Submit a response to a specific stream. Used by async route handlers
    // to deliver a deferred response from the dispatcher thread after an
    // async operation completes. Safe to call with a stream_id that has
    // already closed (e.g. due to client RST_STREAM or connection drop) —
    // Http2Session handles the missing-stream case internally.
    // Submits a response and flushes pending frames. Returns 0 on
    // submit success, -1 if Http2Session::SubmitResponse rejected the
    // call (stream not found / closed / 1xx misuse). The flush still
    // runs on -1 so any prior queued frames drain. Callers that record
    // observability on success must check the return value AND call
    // WasStreamClosedSuccessfully(stream_id) after the flush, because
    // submit-then-RST in the same recv batch will return 0 here but
    // discard the response frames during the post-receive flush.
    int SubmitStreamResponse(int32_t stream_id, const HttpResponse& response);

    // Per-stream post-wire-write notification slot. H2 multiplexes
    // streams, so the slot is keyed on stream_id. Used by
    // ShutdownContext's H2 CASE B path: arms `notify_sent` BEFORE
    // SubmitStreamResponse, observes the flip after nghttp2 commits
    // the response frames.
    void SetPostWriteNotifyOnce(int32_t stream_id,
                                  std::shared_ptr<std::atomic<bool>> notify_sent);

    // Internal: after an explicit SendPendingFrames() flush, re-check whether
    // graceful shutdown can now complete or whether the normal deadline
    // tracking should be refreshed.
    void RecheckShutdownDrainAfterFlush();

    // See HttpConnectionHandler::CreateStreamingResponseSender for the
    // contract on `finalize_request`'s signature (status_code, bytes_sent,
    // error_type).
    HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender CreateStreamingResponseSender(
        int32_t stream_id,
        std::function<bool()> claim_response,
        std::function<void()> release_response_claim,
        std::function<void(int status_code,
                            uint64_t bytes_sent,
                            std::string error_type)> finalize_request);

    // Submit a non-final 1xx informational response (e.g. 103 Early Hints)
    // on a specific stream and flush nghttp2 output.
    //
    // Thread-safe: off-dispatcher callers are internally hopped to the
    // dispatcher so nghttp2 state is always touched on the correct
    // thread. On-dispatcher return value: true on success, false on
    // validation failure (missing stream, final already submitted,
    // invalid status). Off-dispatcher return value: always true (the
    // call was queued); the actual submit decision runs on the
    // dispatcher when the hop fires.
    bool SendInterimResponse(
        int32_t stream_id,
        int status_code,
        const std::vector<std::pair<std::string, std::string>>& headers);

    // HTTP/2 server push primitive — atomically issues PUSH_PROMISE on
    // `parent_stream_id` and the associated response on the freshly
    // promised stream, then flushes nghttp2 output.
    //
    // Thread-safe: off-dispatcher callers are rejected safely with no
    // side effects. Return value semantics (consistent with the
    // ResourcePusher public contract: >0 = promised id, -1 = failure):
    //   - On dispatcher: the promised stream_id (>0) on success, -1
    //     on validation / state failure (shutdown requested, push
    //     disabled, GOAWAY sent, parent closed or final response
    //     already submitted, invalid method/scheme/path/authority,
    //     nghttp2 failure — see Http2Session::SubmitPushPromise for
    //     the full validation list).
    //   - Off dispatcher: returns -1 and does NOT queue a push. A
    //     failure sentinel must not have a hidden side effect because
    //     callers may use -1 to trigger a Link-header fallback.
    //     Handlers that need push semantics MUST call from the
    //     dispatcher thread.
    //
    // Application code should use the bound ResourcePusher closure
    // (async routes) or HTTP2_PUSH_NAMESPACE::PushResource (sync
    // routes — see include/http/push_helper.h) rather than calling
    // this directly.
    int32_t PushResource(
        int32_t parent_stream_id,
        const std::string& method,
        const std::string& scheme,
        const std::string& authority,
        const std::string& path,
        const HttpResponse& response);

    // Check if session is still active
    bool IsAlive() const { return session_ && session_->IsAlive(); }

    // True during Initialize() — suppresses premature shutdown rejection
    bool IsInitializing() const { return initializing_; }

    // Thread-safe per-connection stream tracking for counter compensation
    // when the transport closes abruptly.
    int64_t LocalStreamCount() const {
        return local_stream_count_.load(std::memory_order_relaxed);
    }
    void IncrementLocalStreamCount() {
        local_stream_count_.fetch_add(1, std::memory_order_relaxed);
    }
    void DecrementLocalStreamCount() {
        local_stream_count_.fetch_sub(1, std::memory_order_relaxed);
    }

    // Check if shutdown was requested (atomic, safe from any thread)
    bool IsShutdownRequested() const {
        return shutdown_requested_.load(std::memory_order_acquire);
    }

    // Per-stream async-abort hooks. Installed by the server's async
    // request dispatcher after the complete() closure is built for a
    // deferred stream. Fired by the deadline-driven safety-cap path
    // when ResetExpiredStreams RSTs a stuck stream, so the stored
    // completion closure's one-shot completed/cancelled atomics flip
    // and active_requests is decremented exactly once. Also cleared
    // on normal stream close.
    //
    // Dispatcher-thread-only — no synchronization.
    void SetStreamAbortHook(int32_t stream_id,
                            std::function<void()> hook) {
        stream_abort_hooks_[stream_id] = std::move(hook);
    }
    void EraseStreamAbortHook(int32_t stream_id) {
        stream_abort_hooks_.erase(stream_id);
    }
    void FireAndEraseStreamAbortHook(int32_t stream_id) {
        auto it = stream_abort_hooks_.find(stream_id);
        if (it == stream_abort_hooks_.end()) {
            // Even when the abort hook is absent, fire the post-write
            // notifier so a shutdown-route pump on this stream sees
            // "framework gave up" — same semantics as H1's
            // TripAsyncAbortHook.
            FireStreamPostWriteNotify(stream_id);
            return;
        }
        auto hook = std::move(it->second);
        stream_abort_hooks_.erase(it);
        if (hook) hook();
        FireStreamPostWriteNotify(stream_id);
    }
    // Fire ALL remaining stream-abort hooks. Called from
    // HttpServer::RemoveConnection when a connection is being torn
    // down abruptly: ~Http2Session's nghttp2_session_del will fire
    // on_stream_close for each stream, but OnStreamCloseCallback
    // locks weak Owner() — which is already null when the handler
    // is destroying — so the stream-close callback is NOT invoked
    // on the teardown path. Without this, a client-side disconnect
    // while async routes are deferred would leak active_requests_
    // permanently for any wedged handler.
    void FireAllStreamAbortHooks() {
        auto hooks = std::move(stream_abort_hooks_);
        stream_abort_hooks_.clear();
        for (auto& [id, hook] : hooks) {
            if (hook) hook();
        }
        // Fire every remaining per-stream post-write notifier — the
        // observability/shutdown-route pumps observe "framework gave
        // up on this submission" and can proceed to Stop().
        for (auto& [id, slot] : stream_post_write_notify_) {
            (void)id;
            if (slot) slot->store(true, std::memory_order_release);
        }
        stream_post_write_notify_.clear();
        // Drain any deferred post-receive finalisers. Streaming senders
        // that fired SendHeaders/End from inside ReceiveData and
        // queued their finalize through EnqueuePostReceiveTask would
        // otherwise leak observability + active_requests bookkeeping
        // when the connection is torn down before OnRawData's tail
        // flush could run. The deferred closure's
        // WasStreamClosedSuccessfully check correctly returns false for
        // streams whose on_stream_close did not record (teardown skips
        // OnStreamCloseCallback's user-callback path), so the
        // finalisers record client_disconnect.
        DrainPostReceiveTasks();
    }

private:
    // Fire-and-erase a single stream's post-write notifier. Idempotent.
    void FireStreamPostWriteNotify(int32_t stream_id) {
        auto it = stream_post_write_notify_.find(stream_id);
        if (it == stream_post_write_notify_.end()) return;
        if (it->second) {
            it->second->store(true, std::memory_order_release);
        }
        stream_post_write_notify_.erase(it);
    }
public:

private:
    StreamCloseCallback WrapStreamCloseCallback(StreamCloseCallback callback);

    // Dispatcher-thread-only weak refs to active per-stream streaming senders.
    // Used to forward transport write-progress events so H2 backpressure can
    // account for bytes already drained out of nghttp2's per-stream ring and
    // now buffered on the shared connection output buffer.
    std::unordered_map<
        int32_t,
        std::weak_ptr<HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::Impl>>
        active_stream_sender_impls_;

    void NotifyActiveStreamSendersWriteProgress(size_t remaining_bytes);
    void NotifyActiveStreamSendersWriteComplete();

    std::shared_ptr<ConnectionHandler> conn_;
    std::unique_ptr<Http2Session> session_;
    Http2Session::Settings settings_;

    size_t max_body_size_ = 0;
    size_t max_header_size_ = 0;
    int request_timeout_sec_ = 0;
    int max_async_deferred_sec_ = 0;  // 0 = disabled (no safety cap)

    bool initialized_ = false;
    bool initializing_ = false;  // true during Initialize(), suppresses premature drain
    bool deadline_armed_ = false;
    std::atomic<bool> shutdown_requested_{false};
    DrainCompleteCallback drain_complete_cb_;
    bool drain_notified_ = false;
    bool resume_scheduled_ = false;  // dispatcher-thread only
    std::chrono::steady_clock::time_point last_deadline_;  // avoids redundant SetDeadline calls

    // Per-connection stream counter. Incremented by stream-open callback,
    // decremented by stream-close callback. Thread-safe (atomic). Used for
    // counter compensation on abrupt close — avoids reading non-atomic
    // session containers from the wrong thread.
    std::atomic<int64_t> local_stream_count_{0};

    // Internal: set connection deadline based on oldest incomplete stream.
    void UpdateDeadline();

    // Internal: fire drain-complete callback once. Calls CloseAfterWrite first.
    void NotifyDrainComplete();

    // Stored callbacks for deferred initialization
    RequestCallback pending_request_cb_;
    StreamCloseCallback pending_stream_close_cb_;
    StreamOpenCallback pending_stream_open_cb_;
    HTTP2_CALLBACKS_NAMESPACE::Http2RequestCountCallback pending_request_count_cb_;

    // Per-stream safety-cap abort hooks. See SetStreamAbortHook.
    std::unordered_map<int32_t, std::function<void()>> stream_abort_hooks_;

    // Per-stream post-wire-write notifier slots. Flipped after the
    // response frames commit to nghttp2's output buffer; cleared post-
    // signal. Consumed by the shutdown-route pump.
    std::unordered_map<int32_t, std::shared_ptr<std::atomic<bool>>>
        stream_post_write_notify_;

    // Per-stream nghttp2 close error code, recorded in
    // WrapStreamCloseCallback before the user callback runs. Lets a
    // deferred response finalize (the streaming sender or the async
    // complete path) discriminate "stream cleanly closed" (NO_ERROR)
    // from "stream reset by peer" (CANCEL / REFUSED_STREAM / ...) so
    // observability records the actual outcome instead of overwriting
    // a clean status onto a discarded response. Dispatcher-thread-only.
    std::unordered_map<int32_t, uint32_t> stream_close_error_codes_;

    // Tasks deferred from inside Http2Session::ReceiveData
    // (e.g. streaming-sender finalisers) until AFTER OnRawData's
    // post-receive SendPendingFrames flushes. By that point any
    // late RST_STREAM the peer included in the same recv batch has
    // closed the stream, so the deferred task can read the actual
    // outcome via WasStreamClosedSuccessfully. Dispatcher-thread-only.
    std::vector<std::function<void()>> pending_post_receive_tasks_;

public:
    // Outcome predicate for deferred finalisers. Returns true when the
    // stream is still alive in nghttp2 (response in flight) OR closed
    // with NGHTTP2_NO_ERROR (clean END_STREAM both directions). Returns
    // false only when the stream closed with a non-zero error code
    // (peer RST or local protocol abort) — which means the response
    // never reached the wire as a clean END_STREAM. Erases the close-
    // code entry on consume so the map stays bounded. Dispatcher-
    // thread-only.
    bool WasStreamClosedSuccessfully(int32_t stream_id);

    // Enqueue a closure to run AFTER OnRawData's tail SendPendingFrames
    // (and after any in-flight on_stream_close callbacks that flush
    // would drive). Used by streaming senders that finalise observability
    // from inside a receive callback — the success/error decision must
    // wait until the rest of the recv batch has been processed.
    void EnqueuePostReceiveTask(std::function<void()> task);

private:
    // Drain pending_post_receive_tasks_. Called from OnRawData after
    // the post-receive flush; callers outside that path must not invoke.
    void DrainPostReceiveTasks();
};
