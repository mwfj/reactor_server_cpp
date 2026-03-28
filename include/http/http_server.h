#pragma once

#include "net_server.h"
#include "http/http_router.h"
#include "http/http_connection_handler.h"
#include "http2/http2_connection_handler.h"
#include "http2/protocol_detector.h"
#include "config/server_config.h"
#include "tls/tls_context.h"

#include <map>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <string>

class HttpServer {
public:
    // Construct with explicit host/port
    HttpServer(const std::string& ip, int port);

    // Construct with config
    explicit HttpServer(const ServerConfig& config);

    ~HttpServer();

    // Route registration (delegates to router)
    void Get(const std::string& path, HttpRouter::Handler handler);
    void Post(const std::string& path, HttpRouter::Handler handler);
    void Put(const std::string& path, HttpRouter::Handler handler);
    void Delete(const std::string& path, HttpRouter::Handler handler);
    void Route(const std::string& method, const std::string& path, HttpRouter::Handler handler);
    void WebSocket(const std::string& path, HttpRouter::WsUpgradeHandler handler);
    void Use(HttpRouter::Middleware middleware);

    // Server lifecycle.
    // NOTE: Start/Stop is one-shot — after Stop(), the internal dispatchers
    // and thread pool are permanently stopped and cannot be restarted.
    // To restart, destroy and reconstruct the HttpServer.
    void Start();  // Blocks in event loop
    void Stop();

    // Called after init completes but before the blocking event loop.
    // Used by daemon mode to signal readiness to the parent process.
    void SetReadyCallback(std::function<void()> cb);

private:
    NetServer net_server_;
    HttpRouter router_;
    std::map<int, std::shared_ptr<HttpConnectionHandler>> http_connections_;
    std::mutex conn_mtx_;

    void HandleNewConnection(std::shared_ptr<ConnectionHandler> conn);
    void HandleCloseConnection(std::shared_ptr<ConnectionHandler> conn);
    void HandleErrorConnection(std::shared_ptr<ConnectionHandler> conn);
    void HandleMessage(std::shared_ptr<ConnectionHandler> conn, std::string& message);

    // Helper: set up request + upgrade handlers on an HttpConnectionHandler
    void SetupHandlers(std::shared_ptr<HttpConnectionHandler> http_conn);
    // Helper: wire NetServer callbacks to this HttpServer
    void WireNetServerCallbacks();
    // Compute the pre-read input buffer cap from configured limits.
    size_t ComputeInputCap() const;
    // Safe WS transport-close notification: null-check, exception-safe, log errors.
    // Must be called OUTSIDE conn_mtx_ to prevent deadlock.
    void SafeNotifyWsClose(const std::shared_ptr<HttpConnectionHandler>& http_conn);

    std::shared_ptr<TlsContext> tls_ctx_;  // Shared with NetServer for safe lifetime

    // Request limits — defaults match ServerConfig defaults.
    // The ip/port constructor uses these; the config constructor overwrites them.
    size_t max_body_size_ = 1048576;       // 1 MB
    size_t max_header_size_ = 8192;        // 8 KB
    size_t max_ws_message_size_ = 16777216; // 16 MB
    int request_timeout_sec_ = 30;         // Slowloris protection

    // HTTP/2 support
    bool http2_enabled_ = true;
    Http2Session::Settings h2_settings_;
    std::map<int, std::shared_ptr<Http2ConnectionHandler>> h2_connections_;

    // Connections whose protocol has not yet been determined due to insufficient
    // data. Keyed by fd, stores connection identity + buffered bytes to guard
    // against fd-reuse races. Protected by conn_mtx_.
    struct PendingDetection {
        std::shared_ptr<ConnectionHandler> conn;
        std::string data;
    };
    std::map<int, PendingDetection> pending_detection_;

    // Graceful HTTP/2 shutdown drain
    int shutdown_drain_timeout_sec_ = 30;
    struct DrainingH2Conn {
        std::shared_ptr<Http2ConnectionHandler> handler;
        std::shared_ptr<ConnectionHandler> conn;
    };
    std::vector<DrainingH2Conn> h2_draining_;
    std::mutex drain_mtx_;
    std::condition_variable drain_cv_;
    void OnH2DrainComplete(ConnectionHandler* conn_ptr);
    void WaitForH2Drain();

    // Helper: set up request handler on an Http2ConnectionHandler
    void SetupH2Handlers(std::shared_ptr<Http2ConnectionHandler> h2_conn);

    // Detect protocol and create the appropriate handler (HTTP/1.x or HTTP/2).
    // Returns true if handler was created and data was routed.
    bool DetectAndRouteProtocol(std::shared_ptr<ConnectionHandler> conn,
                                std::string& message);
};
