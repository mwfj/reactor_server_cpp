#pragma once

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
    void SubmitStreamResponse(int32_t stream_id, const HttpResponse& response);

    // Submit a non-final 1xx informational response (e.g. 103 Early Hints)
    // on a specific stream and flush nghttp2 output. The contract is
    // dispatcher-thread-only — off-thread calls are refused with a warn
    // log so a mis-routed call never corrupts nghttp2 state. Returns
    // true on successful submission, false on validation / state failure
    // (missing stream, final already submitted, off-thread, invalid status).
    bool SendInterimResponse(
        int32_t stream_id,
        int status_code,
        const std::vector<std::pair<std::string, std::string>>& headers);

    // HTTP/2 server push primitive — atomically issues PUSH_PROMISE on
    // `parent_stream_id` and the associated response on the freshly
    // promised stream, then flushes nghttp2 output. Returns the promised
    // stream_id (>0) on success, -1 otherwise (off-thread, shutdown
    // requested, push disabled, validation failure, nghttp2 failure —
    // see Http2Session::SubmitPushPromise for the full validation list).
    //
    // Dispatcher-thread-only contract — off-thread callers must hop via
    // RunOnDispatcher() first. Application code should use the bound
    // ResourcePusher closure (async routes) or http::PushResource (sync
    // routes) rather than calling this directly.
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
        if (it == stream_abort_hooks_.end()) return;
        auto hook = std::move(it->second);
        stream_abort_hooks_.erase(it);
        if (hook) hook();
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
    }

private:
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
};
