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

    void SetRequestCallback(RequestCallback callback);
    void SetStreamCloseCallback(StreamCloseCallback callback);

    // Set request limits (applied per-stream)
    void SetMaxBodySize(size_t max);
    void SetMaxHeaderSize(size_t max);
    void SetRequestTimeout(int seconds) { request_timeout_sec_ = seconds; }

    // Called when raw data arrives from the reactor (entry point)
    void OnRawData(std::shared_ptr<ConnectionHandler> conn, std::string& data);

    // Initialize the HTTP/2 session and send server preface.
    // Optionally accepts initial data (preface bytes already buffered).
    void Initialize(const std::string& initial_data = "");

    // Request graceful shutdown. Thread-safe: sets atomic flag and enqueues
    // dispatcher-thread task that sends GOAWAY and initiates drain.
    void RequestShutdown();

    // Callback invoked (once) when the connection finishes draining all
    // active streams during graceful shutdown. Called on dispatcher thread.
    using DrainCompleteCallback = std::function<void()>;
    void SetDrainCompleteCallback(DrainCompleteCallback cb);

    // Access the underlying connection
    std::shared_ptr<ConnectionHandler> GetConnection() const { return conn_; }

    // Access the session (for stream count, alive check, etc.)
    Http2Session* GetSession() { return session_.get(); }

    // Check if session is still active
    bool IsAlive() const { return session_ && session_->IsAlive(); }

private:
    std::shared_ptr<ConnectionHandler> conn_;
    std::unique_ptr<Http2Session> session_;
    Http2Session::Settings settings_;

    size_t max_body_size_ = 0;
    size_t max_header_size_ = 0;
    int request_timeout_sec_ = 0;

    bool initialized_ = false;
    bool deadline_armed_ = false;
    std::atomic<bool> shutdown_requested_{false};
    DrainCompleteCallback drain_complete_cb_;
    bool drain_notified_ = false;
    std::chrono::steady_clock::time_point last_deadline_;  // avoids redundant SetDeadline calls

    // Internal: called after ReceiveData; a no-op since dispatch is
    // synchronous inside nghttp2 callbacks.
    void DispatchPendingRequests();

    // Internal: set connection deadline based on oldest incomplete stream.
    void UpdateDeadline();

    // Internal: fire drain-complete callback once. Calls CloseAfterWrite first.
    void NotifyDrainComplete();

    // Stored callbacks for deferred initialization
    RequestCallback pending_request_cb_;
    StreamCloseCallback pending_stream_close_cb_;
};
