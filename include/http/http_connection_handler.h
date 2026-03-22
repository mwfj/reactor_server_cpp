#pragma once

#include "http/http_parser.h"
#include "http/http_request.h"
#include "http/http_response.h"
#include "ws/websocket_connection.h"
#include "ws/websocket_handshake.h"
#include "connection_handler.h"

#include <memory>
#include <functional>
#include <chrono>

class HttpConnectionHandler : public std::enable_shared_from_this<HttpConnectionHandler> {
public:
    explicit HttpConnectionHandler(std::shared_ptr<ConnectionHandler> conn);

    // Handler for complete HTTP requests
    using RequestHandler = std::function<void(
        std::shared_ptr<HttpConnectionHandler> self,
        const HttpRequest& request,
        HttpResponse& response
    )>;
    void SetRequestHandler(RequestHandler handler);

    // Check if a WebSocket route exists for the given path.
    // Returns true if upgrade should proceed, false to reject.
    using RouteChecker = std::function<bool(const std::string& path)>;
    void SetRouteChecker(RouteChecker checker);

    // Run middleware chain before WebSocket upgrade.
    // Returns true if all middleware passed, false if any short-circuited (response is set).
    using MiddlewareRunner = std::function<bool(const HttpRequest& request, HttpResponse& response)>;
    void SetMiddlewareRunner(MiddlewareRunner runner);

    // Handler called ONCE after WebSocket upgrade is complete and ws_conn_ exists.
    // Wires application-level OnMessage/OnClose callbacks on the WebSocketConnection.
    using UpgradeHandler = std::function<void(
        std::shared_ptr<HttpConnectionHandler> self,
        const HttpRequest& request
    )>;
    void SetUpgradeHandler(UpgradeHandler handler);

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
    std::shared_ptr<ConnectionHandler> conn_;
    HttpParser parser_;
    RequestHandler request_handler_;
    RouteChecker route_checker_;
    MiddlewareRunner middleware_runner_;
    UpgradeHandler upgrade_handler_;
    bool upgraded_ = false;
    std::unique_ptr<WebSocketConnection> ws_conn_;
};
