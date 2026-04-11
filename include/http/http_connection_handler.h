#pragma once

#include "http/http_callbacks.h"
#include "http/http_parser.h"
#include "http/http_request.h"
#include "http/http_response.h"
#include "ws/websocket_connection.h"
#include "ws/websocket_handshake.h"
#include "connection_handler.h"

// <memory>, <functional>, <chrono> provided by common.h (via connection_handler.h)

class HttpConnectionHandler : public std::enable_shared_from_this<HttpConnectionHandler> {
public:
    explicit HttpConnectionHandler(std::shared_ptr<ConnectionHandler> conn);

    // Public type aliases for backward compatibility with SetupHandlers() callers
    using RequestCallback    = HTTP_CALLBACKS_NAMESPACE::HttpConnRequestCallback;
    using RouteCheckCallback = HTTP_CALLBACKS_NAMESPACE::HttpConnRouteCheckCallback;
    using MiddlewareCallback = HTTP_CALLBACKS_NAMESPACE::HttpConnMiddlewareCallback;
    using UpgradeCallback    = HTTP_CALLBACKS_NAMESPACE::HttpConnUpgradeCallback;

    void SetRequestCallback(RequestCallback callback);
    void SetRouteCheckCallback(RouteCheckCallback callback);
    void SetMiddlewareCallback(MiddlewareCallback callback);
    void SetUpgradeCallback(UpgradeCallback callback);
    void SetRequestCountCallback(HTTP_CALLBACKS_NAMESPACE::HttpConnRequestCountCallback callback);
    void SetShutdownCheckCallback(HTTP_CALLBACKS_NAMESPACE::HttpConnShutdownCheckCallback callback);

    // Send an HTTP response
    void SendResponse(const HttpResponse& response);

    // Check if upgraded to WebSocket
    bool IsUpgraded() const { return upgraded_; }

    // Access WebSocket connection (nullptr if not upgraded)
    WebSocketConnection* GetWebSocket() { return ws_conn_.get(); }

    // Access underlying connection
    std::shared_ptr<ConnectionHandler> GetConnection() const { return conn_; }

    // Set request size limits (from ServerConfig)
    void SetMaxBodySize(size_t max);
    void SetMaxHeaderSize(size_t max);
    void SetMaxWsMessageSize(size_t max) { max_ws_message_size_ = max; }

    // Update all size limits on an existing connection during live reload.
    // Must be called on the connection's dispatcher thread (via RunOnDispatcher).
    // Handles both HTTP-mode and WS-mode connections:
    //   HTTP: updates parser limits + transport input cap
    //   WS:   updates parser + message limits + transport input cap (ws-specific)
    void UpdateSizeLimits(size_t body, size_t header, size_t ws,
                          size_t http_input_cap);

    // Set request timeout (Slowloris protection).
    // Deadline is armed on first OnRawData call (after TLS handshake completes for TLS connections).
    void SetRequestTimeout(int seconds);

    // Set the absolute safety cap (in seconds) for a deferred async
    // response window. When set > 0, the heartbeat callback aborts the
    // deferred state after this elapsed time — releasing the connection
    // even if an async handler forgets to call complete() or a proxy
    // talking to a hung upstream never completes. 0 disables the cap
    // entirely (no absolute bound; honors operator "disabled" configs).
    // HttpServer computes this from upstream configs at MarkServerReady
    // (see HttpServer::max_async_deferred_sec_).
    void SetMaxAsyncDeferredSec(int sec);

    // Called when raw data arrives (set as NetServer's on_message callback)
    void OnRawData(std::shared_ptr<ConnectionHandler> conn, std::string& data);

    // Begin an async-response cycle. Called by the framework when an async
    // route handler is about to run. Saves the request context needed to
    // normalize the final response (HEAD body stripping, Connection: close,
    // HTTP/1.0 keep-alive signaling) and blocks the parser from accepting
    // new requests until CompleteAsyncResponse runs — preserving HTTP/1
    // response ordering on keep-alive connections.
    void BeginAsyncResponse(const HttpRequest& req);

    // Complete an async-response cycle. Called from the async completion
    // callback (on the dispatcher thread). Applies post-dispatch
    // normalization using the context saved by BeginAsyncResponse, writes
    // the response, and either closes the connection or resumes parsing
    // any pipelined bytes that arrived during the deferred window.
    void CompleteAsyncResponse(HttpResponse response);

    // Cancel a deferred async-response cycle that was started by
    // BeginAsyncResponse but whose handler threw before handing off the
    // completion callback. Resets deferred state + shutdown exemption so
    // the outer exception handler can send a 500 and close normally.
    void CancelAsyncResponse();

    // Install a one-shot "abort the async cycle" hook. Used by the
    // deferred-heartbeat safety-cap path to short-circuit the stored
    // AsyncCompletionCallback closure (flipping its completed/cancelled
    // atomics) and release its active_requests bookkeeping exactly
    // once, even if the real handler never calls complete(). The hook
    // is installed by the server-level request dispatcher after the
    // complete closure is built; the handler owns it for the lifetime
    // of the deferred window. Cleared by Complete/CancelAsyncResponse.
    void SetAsyncAbortHook(std::function<void()> hook) {
        async_abort_hook_ = std::move(hook);
    }

    // Append bytes that arrived while an async response was pending.
    // Called by OnRawData. Separated from OnRawData so that the framework's
    // own "resume after deferred" path can feed buffered bytes back in
    // without recursion surprises.
    void StashDeferredBytes(const std::string& data);

    // True if an async response is currently pending delivery.
    bool IsAsyncResponsePending() const { return deferred_response_pending_; }

    // Graceful-shutdown exemption.
    //
    // Set automatically by BeginAsyncResponse/CompleteAsyncResponse for the
    // async route API. Also exposed publicly so advanced users implementing
    // custom async patterns outside the AsyncHandler API can still mark
    // their connections exempt from HttpServer::Stop()'s close sweep.
    //
    // The flag lives on the underlying ConnectionHandler so NetServer's
    // close sweep can check it live (a pre-sweep snapshot cannot close
    // the race with a request that's just now entering an async handler).
    void SetShutdownExempt(bool exempt) {
        if (conn_) conn_->SetShutdownExempt(exempt);
    }
    bool IsShutdownExempt() const {
        return conn_ && conn_->IsShutdownExempt();
    }

private:
    size_t max_body_size_ = 0;    // 0 = unlimited
    size_t max_header_size_ = 0;  // 0 = unlimited
    size_t max_ws_message_size_ = 0; // 0 = unlimited
    int request_timeout_sec_ = 0; // 0 = disabled
    int max_async_deferred_sec_ = 0;  // 0 = disabled (no safety cap)

    // Slowloris protection: tracks when the current incomplete request started
    bool request_in_progress_ = false;
    std::chrono::steady_clock::time_point request_start_;

    // HTTP version of the current request (for echoing in responses).
    // Defaults to 1.1; updated when a complete request is parsed.
    int current_http_minor_ = 1;

    // Tracks whether we've sent 100 Continue for the current request.
    // Reset when the parser is reset for the next pipelined request.
    bool sent_100_continue_ = false;

    // Close the underlying connection (send response then close)
    void CloseConnection();

    // Internal phases of OnRawData -- split for readability
    void HandleUpgradedData(const std::string& data);
    void HandleParseError();
    // Returns true to continue pipelining loop, false to stop processing
    bool HandleCompleteRequest(const char*& buf, size_t& remaining, size_t consumed);
    void HandleIncompleteRequest();

    // Shared response normalization used by both the sync request loop and
    // the async deferred completion path. Scans Connection headers for a
    // "close" token (RFC 7230 §6.1 comma-separated list), injects an
    // HTTP/1.0 Connection: keep-alive if the client asked for persistence
    // on HTTP/1.0, and enforces Connection: close when the client did not
    // request keep-alive. Returns the final "should close after send"
    // decision so the caller can CloseConnection() after writing.
    bool NormalizeOutgoingResponse(HttpResponse& response,
                                   bool client_keep_alive,
                                   int client_http_minor);

    // Strip the body from a serialized wire response for HEAD requests
    // (RFC 7231 §4.3.2). Truncates `wire` at the blank line that
    // terminates the header block, preserving the Content-Length header.
    static void StripResponseBodyForHead(std::string& wire);

    std::shared_ptr<ConnectionHandler> conn_;
    HttpParser parser_;
    HTTP_CALLBACKS_NAMESPACE::HttpConnCallbacks callbacks_;
    bool upgraded_ = false;
    std::unique_ptr<WebSocketConnection> ws_conn_;

    // Deferred-response state — dispatcher-thread only, no atomics needed.
    // Populated by BeginAsyncResponse and consumed by CompleteAsyncResponse.
    // While deferred_response_pending_ is true, OnRawData buffers new bytes
    // into deferred_pending_buf_ instead of parsing them, preventing
    // out-of-order responses on pipelined HTTP/1 keep-alive connections.
    // deferred_http_minor_ is intentionally NOT stored: current_http_minor_
    // is updated by the parser at header-completion time and persists
    // across the deferred window (no new requests are parsed until the
    // completion runs), so it serves as the canonical version field.
    bool deferred_response_pending_ = false;
    bool deferred_was_head_ = false;
    bool deferred_keep_alive_ = true;
    std::string deferred_pending_buf_;

    // Start time of the current deferred-response window. Currently
    // only used for diagnostic / logging purposes; the heartbeat
    // deadline is unbounded so handlers' own timeouts govern the
    // overall request lifetime.
    std::chrono::steady_clock::time_point deferred_start_{};

    // Safety-cap abort hook. See SetAsyncAbortHook.
    std::function<void()> async_abort_hook_;
};
