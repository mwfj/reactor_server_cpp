#pragma once

#include "http/http_parser.h"
#include "http/http_request.h"
#include "http/http_response.h"
#include "ws/websocket_connection.h"
#include "ws/websocket_handshake.h"
#include "connection_handler.h"

#include <memory>
#include <functional>

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

    // Handler for WebSocket upgrade requests.
    // Returns true if upgrade should proceed (route exists), false to reject.
    using UpgradeHandler = std::function<bool(
        std::shared_ptr<HttpConnectionHandler> self,
        const HttpRequest& request,
        std::shared_ptr<ConnectionHandler> conn
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
    void SetMaxBodySize(size_t max) { max_body_size_ = max; }
    void SetMaxHeaderSize(size_t max) { max_header_size_ = max; }

    // Called when raw data arrives (set as NetServer's on_message callback)
    void OnRawData(std::shared_ptr<ConnectionHandler> conn, std::string& data);

private:
    size_t max_body_size_ = 0;    // 0 = unlimited
    size_t max_header_size_ = 0;  // 0 = unlimited
    std::shared_ptr<ConnectionHandler> conn_;
    HttpParser parser_;
    RequestHandler request_handler_;
    UpgradeHandler upgrade_handler_;
    bool upgraded_ = false;
    std::unique_ptr<WebSocketConnection> ws_conn_;
};
