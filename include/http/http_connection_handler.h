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
    void SetResolveRouteOptionsCallback(
        HTTP_CALLBACKS_NAMESPACE::HttpConnResolveRouteOptionsCallback callback);
    // Install the async middleware callback for WS upgrades. Optional;
    // when not installed the WS upgrade path skips the async phase and
    // runs the sync path only.
    void SetAsyncMiddlewareCallback(
        HTTP_CALLBACKS_NAMESPACE::HttpConnAsyncMiddlewareCallback callback);
    void SetUpgradeCallback(UpgradeCallback callback);
    void SetRequestCountCallback(HTTP_CALLBACKS_NAMESPACE::HttpConnRequestCountCallback callback);
    void SetShutdownCheckCallback(HTTP_CALLBACKS_NAMESPACE::HttpConnShutdownCheckCallback callback);

    // Send an HTTP response
    void SendResponse(const HttpResponse& response);

    // ============================================================
    // Observability finalize hooks
    // ============================================================
    // Per-request post-wire-write notification slot. The shutdown-route
    // pump arms this when no observability snapshot exists so it knows
    // when the response has been buffered.
    //
    // The framework signals it by calling `notify_sent->store(true,
    // std::memory_order_release);` immediately AFTER the post-wire-
    // write step (the same instant a WithFinalize hook would fire).
    // Cleared after signal so subsequent pipelined requests see a
    // fresh state.
    //
    // On transport teardown before write completion, the framework
    // still flips the flag — the helper observes "framework gave up
    // on this submission" which is the correct shutdown signal.
    void SetPostWriteNotifyOnce(std::shared_ptr<std::atomic<bool>> notify_sent);
    // ============================================================

    // Create a streaming final-response sender for the current deferred async
    // request. Used by the proxy relay path to stream bytes without going
    // through CompleteAsyncResponse(HttpResponse).
    //
    // `finalize_request` fires exactly once on End() OR Abort() with the
    // observed final state of the stream:
    //   status_code     — the status passed to SendHeaders, or 0 if Abort
    //                     fired before SendHeaders.
    //   bytes_sent      — cumulative bytes accepted by SendData (the
    //                     wire body size, modulo HEAD-strip).
    //   error_type      — empty for End(); a stable label
    //                     ("upstream_truncated", "client_disconnect", etc.)
    //                     mapped from AbortReason on Abort. The OTel
    //                     observability finalize uses this verbatim as
    //                     the `error.type` attribute on the SERVER span.
    HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender CreateStreamingResponseSender(
        std::function<bool()> claim_response,
        std::function<void(int status_code,
                            uint64_t bytes_sent,
                            std::string error_type)> finalize_request);

    // Send a non-final 1xx response (103 Early Hints, 102 Processing, etc.).
    // Thread-safe: off-dispatcher callers are internally hopped to the
    // dispatcher so write order is preserved with the final response.
    //
    // Return value semantics:
    //   - On dispatcher: true if the interim was written to the output
    //     buffer; false if rejected synchronously (HTTP/1.0 request,
    //     final response already serialized, invalid status code, or
    //     oversized header block).
    //   - Off dispatcher: always returns true (the call was queued).
    //     The final drop/emit decision happens when the hopped lambda
    //     runs — if complete() was called before this invocation, the
    //     queued interim is dropped to preserve response ordering.
    //
    // Multiple interims on the same request are legal per RFC 8297.
    // Forbidden headers (Connection, Keep-Alive, Transfer-Encoding,
    // Content-Length, TE, Upgrade, Proxy-*) are silently stripped.
    // CR/LF in header key or value is stripped to prevent response
    // splitting. Status code must be in [102,199]. 101 is reserved for
    // WebSocket upgrade. 100 is framework-managed (internal 100-continue).
    bool SendInterimResponse(
        int status_code,
        const std::vector<std::pair<std::string, std::string>>& headers);

    // Check if upgraded to WebSocket
    bool IsUpgraded() const { return upgraded_; }

    // True iff HttpServer's upgrade_callback has already decremented the
    // legacy /stats counter `active_http1_connections_` for this connection.
    // Set inside the callback after fetch_sub; checked by RemoveConnection
    // alongside !IsUpgraded() so the counter is decremented EXACTLY ONCE
    // across the success path AND both throw paths. Without this flag the
    // sync-path catch (which preserves upgraded_=true because 101 is already
    // on the wire) would leak +1, and the async-resume catch (which resets
    // upgraded_=false because 101 hasn't been flushed) would double-decrement.
    bool LegacyH1StatsDecremented() const { return legacy_h1_decremented_; }
    void MarkLegacyH1StatsDecremented() { legacy_h1_decremented_ = true; }

    // Access WebSocket connection (nullptr if not upgraded)
    WebSocketConnection* GetWebSocket() { return ws_conn_.get(); }

    // Access underlying connection
    std::shared_ptr<ConnectionHandler> GetConnection() const { return conn_; }

    // Called from HttpServer's transport send-complete / write-progress
    // routing so the active streaming sender can detect low-water drains.
    void OnSendComplete();
    void OnWriteProgress(size_t remaining_bytes);

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

    // Variant that fires `before_replay` AFTER the wire bytes have been
    // queued via SendRaw and AFTER the deferred state has been cleared,
    // but BEFORE the deferred-pipeline replay loop resumes parsing.
    // Lets a caller land observability or pipeline-ordered work
    // between the request-A response and any synchronous request-B
    // middleware/registration triggered by replay.
    void CompleteAsyncResponseBeforeReplay(
        HttpResponse response,
        std::function<void()> before_replay);

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

    // Fire the async-abort hook if one is installed, then clear it.
    // Idempotent via the hook's internal one-shot exchange. Called
    // from HttpServer::RemoveConnection when the downstream client
    // drops the socket while a request is still deferred — without
    // this, the heartbeat timer dies with the connection and a stuck
    // handler would leak active_requests_ permanently.
    //
    // Also fires the post_write_notify_ flag so any shutdown-route
    // pump waiting on this slot observes "framework gave up on this
    // submission" — the correct shutdown signal.
    // The helper does not need to distinguish wrote-OK vs gave-up:
    // either way the queued submit work has run and Stop() can
    // proceed.
    void TripAsyncAbortHook() {
        auto hook = std::move(async_abort_hook_);
        if (hook) hook();
        if (post_write_notify_) {
            post_write_notify_->store(true, std::memory_order_release);
            post_write_notify_.reset();
        }
    }

    // Append bytes that arrived while an async response was pending.
    // Called by OnRawData. Separated from OnRawData so that the framework's
    // own "resume after deferred" path can feed buffered bytes back in
    // without recursion surprises.
    void StashDeferredBytes(const std::string& data);

    // Clear the streaming-upload-in-flight flag. Called from the async-resume
    // aborted-body guard (H.3) when the guard fires on the dispatcher thread.
    // Mirrors the flag clear at the other four terminal sites enumerated at
    // the field declaration above. H2's no-op counterpart on
    // Http2ConnectionHandler keeps the generic MakeAsyncResumeCallback
    // template clean.
    void ClearStreamingUploadInFlight() { streaming_upload_in_flight_ = false; }

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
    //
    // Atomic as defense in depth. All writers run on the dispatcher
    // (parser header-complete). The primary cross-thread reader,
    // SendInterimResponse, now hops to the dispatcher before reading
    // this, so release/acquire ordering is not strictly required via
    // this field alone — but keeping the atomic is zero-cost on modern
    // platforms (aligned 32-bit load compiles to a plain mov) and
    // forecloses future regressions if a new caller reads from a worker
    // thread without hopping.
    std::atomic<int> current_http_minor_{1};

    // Tracks whether we've sent 100 Continue for the current request.
    // Reset when the parser is reset for the next pipelined request.
    bool sent_100_continue_ = false;

    // Set true by the headers_complete_callback streaming dispatch path
    // immediately before DispatchStreamingRoute; cleared at FIVE terminal
    // sites so the OnRawData stash gate correctly bypasses buffering for
    // mid-request body chunks on a streaming upload:
    //   (a) on_message_complete via SetStreamingBodyCompleteCallback (happy path)
    //   (b) HandleParseError at function entry
    //   (c) CloseConnection at function entry
    //   (d) parser_.Reset() site (symmetric with sent_100_continue_)
    //   (e) async-resume aborted-body guard (H.3)
    bool streaming_upload_in_flight_ = false;

    // Close the underlying connection (send response then close)
    void CloseConnection();

    // Internal phases of OnRawData -- split for readability
    void HandleUpgradedData(const std::string& data);
    void HandleParseError();
    // Returns true to continue pipelining loop, false to stop processing
    bool HandleCompleteRequest(const char*& buf, size_t& remaining, size_t consumed);
    void HandleIncompleteRequest();

    // Continue the WS upgrade handshake after any middleware has
    // resolved with PASS. Owns RFC 6455 handshake validation, 101 send,
    // and WS state-machine init. Returns true if the upgrade completed
    // or a rejection was sent (caller closes either way).
    //
    // `mw_response` carries headers stamped by the sync middleware. The
    // sync path uses SendResponse directly; the async resume path uses
    // CompleteAsyncResponse so deferred-response state unwinds correctly.
    // Trailing bytes after the request are flushed by the caller.
    bool ContinueWsUpgradeAfterAuth(HttpRequest& req,
                                    HttpResponse mw_response,
                                    bool from_async_resume,
                                    const char* trailing_buf,
                                    size_t trailing_len);

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
    // Dispatcher-thread-only flag (no atomic needed). See
    // LegacyH1StatsDecremented() docstring above for the contract.
    bool legacy_h1_decremented_ = false;
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
    // True once a deferred async request has committed its final streaming
    // headers. The request must still block pipelined parsing until End/Abort,
    // but the generic async safety cap no longer applies after commitment.
    bool deferred_response_committed_ = false;
    bool deferred_was_head_ = false;
    bool deferred_keep_alive_ = true;
    std::string deferred_pending_buf_;
    // Snapshot of `req.obs_snapshot` captured at BeginAsyncResponse time.
    // The parser request slot is Reset() after the handler returns (the
    // sync send path at HandleCompleteRequest's tail clears it before
    // returning false), so the cap-fire safety-cap path running later
    // can no longer read obs_snapshot from parser_.GetRequest(). The
    // captured shared_ptr keeps the snapshot alive for the deferred
    // window — cleared by Complete/CancelAsyncResponse along with the
    // other deferred fields.
    std::shared_ptr<OBSERVABILITY_NAMESPACE::ObservabilitySnapshot>
        deferred_obs_snapshot_;
    // Mirror of req.method == "HEAD" for the deferred snapshot's
    // wire-body-size accounting in the cap-fire path. Already
    // captured as deferred_was_head_ above; the cap-fire path passes
    // a synthetic req copy so the FinalizeIfSnapshot static helper
    // can compute wire size correctly without needing the
    // (now-reset) parser request.

    // Tracks whether the final (>=200) response has been written for the
    // CURRENT request. Set by SendResponse (status >= 200) and
    // CompleteAsyncResponse, cleared by BeginAsyncResponse. Sync handlers
    // don't reset this on each new keep-alive request — but they also don't
    // have access to InterimResponseSender, so a stale `true` from a
    // previous sync request is harmless. Async cycles always reset on entry.
    //
    // Atomic with acquire/release ordering: the sync request handler runs
    // on the dispatcher thread, but documented off-thread interim callers
    // (after hopping via RunOnDispatcher to call complete()) may still
    // observe this from any thread. Defensive against future off-thread
    // callers via the published happens-before edge.
    // <atomic> is provided by common.h (via connection_handler.h).
    std::atomic<bool> final_response_sent_{false};

    // Start time of the current deferred-response window. Currently
    // only used for diagnostic / logging purposes; the heartbeat
    // deadline is unbounded so handlers' own timeouts govern the
    // overall request lifetime.
    std::chrono::steady_clock::time_point deferred_start_{};

    // Safety-cap abort hook. See SetAsyncAbortHook.
    std::function<void()> async_abort_hook_;

    // Per-request orthogonal post-wire-write notifier slot. Set by
    // SetPostWriteNotifyOnce; flipped after the wire-bytes are buffered;
    // cleared post-signal so the next pipelined request starts clean.
    std::shared_ptr<std::atomic<bool>> post_write_notify_;

    // Active streaming sender for the current deferred async request.
    // Weak to avoid creating a handler↔sender ownership cycle.
    std::weak_ptr<HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::Impl>
        active_stream_sender_impl_;
};
