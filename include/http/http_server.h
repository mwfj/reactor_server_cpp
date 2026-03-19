#pragma once

#include "net_server.h"
#include "http/http_router.h"
#include "http/http_connection_handler.h"
#include "config/server_config.h"
#include "tls/tls_context.h"

#include <map>
#include <memory>
#include <mutex>
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

    // Server lifecycle
    void Start();  // Blocks in event loop
    void Stop();

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

    std::unique_ptr<TlsContext> tls_ctx_;
};
