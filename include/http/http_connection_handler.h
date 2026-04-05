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

    // Set request timeout (Slowloris protection).
    // Deadline is armed on first OnRawData call (after TLS handshake completes for TLS connections).
    void SetRequestTimeout(int seconds);

    // Called when raw data arrives (set as NetServer's on_message callback)
    void OnRawData(std::shared_ptr<ConnectionHandler> conn, std::string& data);

    // Graceful-shutdown exemption.
    //
    // Application handlers that dispatch async work (e.g. upstream proxy via
    // UpstreamManager::CheckoutAsync) have a window where the request has
    // been parsed but no client response bytes have been buffered yet. Without
    // opting in, NetServer::Stop()'s generic CloseAfterWrite sweep will
    // force-close the client transport during that window, dropping the
    // in-flight request even though the PR's upstream drain phase would
    // otherwise give it time to complete.
    //
    // Handlers should call SetShutdownExempt(true) before starting async
    // work and SetShutdownExempt(false) after the final response has been
    // handed to SendResponse(). HttpServer::Stop() walks the connection map
    // and exempts any connection whose flag is set.
    void SetShutdownExempt(bool exempt) {
        shutdown_exempt_.store(exempt, std::memory_order_release);
    }
    bool IsShutdownExempt() const {
        return shutdown_exempt_.load(std::memory_order_acquire);
    }

private:
    size_t max_body_size_ = 0;    // 0 = unlimited
    size_t max_header_size_ = 0;  // 0 = unlimited
    size_t max_ws_message_size_ = 0; // 0 = unlimited
    int request_timeout_sec_ = 0; // 0 = disabled

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

    std::shared_ptr<ConnectionHandler> conn_;
    HttpParser parser_;
    HTTP_CALLBACKS_NAMESPACE::HttpConnCallbacks callbacks_;
    bool upgraded_ = false;
    std::unique_ptr<WebSocketConnection> ws_conn_;

    // Set by handlers doing async work (e.g. upstream proxy) to opt out of
    // the shutdown close sweep. Atomic because it's written on the dispatcher
    // thread (in handlers) and read on the stopper thread (in HttpServer::Stop).
    std::atomic<bool> shutdown_exempt_{false};
};
