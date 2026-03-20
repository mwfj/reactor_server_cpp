#include "http/http_server.h"
#include "ws/websocket_frame.h"
#include "log/logger.h"
#include <algorithm>

void HttpServer::WireNetServerCallbacks() {
    net_server_.SetNewConnectionCb(
        [this](std::shared_ptr<ConnectionHandler> conn) { HandleNewConnection(conn); });
    net_server_.SetCloseConnectionCb(
        [this](std::shared_ptr<ConnectionHandler> conn) { HandleCloseConnection(conn); });
    net_server_.SetErrorCb(
        [this](std::shared_ptr<ConnectionHandler> conn) { HandleErrorConnection(conn); });
    net_server_.SetOnMessageCb(
        [this](std::shared_ptr<ConnectionHandler> conn, std::string& msg) { HandleMessage(conn, msg); });
}

HttpServer::HttpServer(const std::string& ip, int port)
    : net_server_(ip, static_cast<size_t>(port))
{
    WireNetServerCallbacks();
}

HttpServer::HttpServer(const ServerConfig& config)
    : net_server_(config.bind_host, static_cast<size_t>(config.bind_port),
                  std::max(config.idle_timeout_sec / 6, 10),  // scan interval: fraction of timeout
                  std::chrono::seconds(config.idle_timeout_sec),
                  config.worker_threads)
{
    WireNetServerCallbacks();

    max_body_size_ = config.max_body_size;
    max_header_size_ = config.max_header_size;
    max_ws_message_size_ = config.max_ws_message_size;
    net_server_.SetMaxConnections(config.max_connections);

    if (config.tls.enabled) {
        tls_ctx_ = std::make_unique<TlsContext>(config.tls.cert_file, config.tls.key_file);
        if (config.tls.min_version == "1.3") {
            tls_ctx_->SetMinProtocolVersion(TLS1_3_VERSION);
        }
        net_server_.SetTlsContext(tls_ctx_.get());
    }
}

HttpServer::~HttpServer() {
    Stop();
}

// Route registration delegates
void HttpServer::Get(const std::string& path, HttpRouter::Handler handler)    { router_.Get(path, std::move(handler)); }
void HttpServer::Post(const std::string& path, HttpRouter::Handler handler)   { router_.Post(path, std::move(handler)); }
void HttpServer::Put(const std::string& path, HttpRouter::Handler handler)    { router_.Put(path, std::move(handler)); }
void HttpServer::Delete(const std::string& path, HttpRouter::Handler handler) { router_.Delete(path, std::move(handler)); }
void HttpServer::Route(const std::string& method, const std::string& path, HttpRouter::Handler handler) { router_.Route(method, path, std::move(handler)); }
void HttpServer::WebSocket(const std::string& path, HttpRouter::WsUpgradeHandler handler) { router_.WebSocket(path, std::move(handler)); }
void HttpServer::Use(HttpRouter::Middleware middleware) { router_.Use(std::move(middleware)); }

void HttpServer::Start() {
    logging::Get()->info("HttpServer starting");
    net_server_.Start();
}

void HttpServer::Stop() {
    logging::Get()->info("HttpServer stopping");
    // Note: WebSocket graceful close (1001 Going Away) is not sent during Stop()
    // because NetServer::Stop() clears connections before the reactor can flush
    // queued close frames. Clients will see TCP RST on server shutdown.
    // For graceful shutdown, applications should close WebSocket connections
    // explicitly before calling Stop().
    net_server_.Stop();
    {
        std::lock_guard<std::mutex> lck(conn_mtx_);
        http_connections_.clear();
    }
}

void HttpServer::SetupHandlers(std::shared_ptr<HttpConnectionHandler> http_conn) {
    // Apply request size limits
    http_conn->SetMaxBodySize(max_body_size_);
    http_conn->SetMaxHeaderSize(max_header_size_);
    http_conn->SetMaxWsMessageSize(max_ws_message_size_);

    // Set request handler: dispatch through router
    http_conn->SetRequestHandler(
        [this](std::shared_ptr<HttpConnectionHandler> self,
               const HttpRequest& request,
               HttpResponse& response) {
            if (!router_.Dispatch(request, response)) {
                response = HttpResponse::NotFound();
            }
        }
    );

    // Middleware runner for WebSocket upgrades (auth, CORS, rate limiting)
    http_conn->SetMiddlewareRunner(
        [this](const HttpRequest& request, HttpResponse& response) -> bool {
            return router_.RunMiddleware(request, response);
        }
    );

    // Route checker: determines if a WebSocket route exists (called before 101)
    http_conn->SetRouteChecker(
        [this](const std::string& path) -> bool {
            return router_.HasWebSocketRoute(path);
        }
    );

    // Upgrade handler: wires WS callbacks (called exactly once, after ws_conn_ created)
    http_conn->SetUpgradeHandler(
        [this](std::shared_ptr<HttpConnectionHandler> self,
               const HttpRequest& request) {
            auto ws_handler = router_.GetWebSocketHandler(request.path);
            if (ws_handler && self->GetWebSocket()) {
                ws_handler(*self->GetWebSocket());
            }
        }
    );
}

void HttpServer::HandleNewConnection(std::shared_ptr<ConnectionHandler> conn) {
    std::lock_guard<std::mutex> lck(conn_mtx_);
    auto it = http_connections_.find(conn->fd());
    if (it != http_connections_.end() && it->second->GetConnection() == conn) {
        // Already created by HandleMessage lazy-init -- don't overwrite
        return;
    }
    auto http_conn = std::make_shared<HttpConnectionHandler>(conn);
    SetupHandlers(http_conn);
    http_connections_[conn->fd()] = http_conn;
    logging::Get()->debug("New HTTP connection fd={} from {}:{}",
                          conn->fd(), conn->ip_addr(), conn->port());
}

void HttpServer::HandleCloseConnection(std::shared_ptr<ConnectionHandler> conn) {
    logging::Get()->debug("HTTP connection closed fd={}", conn->fd());
    std::lock_guard<std::mutex> lck(conn_mtx_);
    // Guard against fd reuse race: only remove if the stored HttpConnectionHandler
    // wraps the same ConnectionHandler that is being closed. Otherwise, a new
    // connection may have already claimed this fd.
    auto it = http_connections_.find(conn->fd());
    if (it != http_connections_.end() && it->second->GetConnection() == conn) {
        http_connections_.erase(it);
    }
}

void HttpServer::HandleErrorConnection(std::shared_ptr<ConnectionHandler> conn) {
    logging::Get()->error("HTTP connection error fd={}", conn->fd());
    std::lock_guard<std::mutex> lck(conn_mtx_);
    auto it = http_connections_.find(conn->fd());
    if (it != http_connections_.end() && it->second->GetConnection() == conn) {
        http_connections_.erase(it);
    }
}

void HttpServer::HandleMessage(std::shared_ptr<ConnectionHandler> conn, std::string& message) {
    std::shared_ptr<HttpConnectionHandler> http_conn;
    {
        std::lock_guard<std::mutex> lck(conn_mtx_);
        auto it = http_connections_.find(conn->fd());
        if (it == http_connections_.end()) {
            // Race condition: data arrived before HandleNewConnection created
            // the HttpConnectionHandler. Create it now (lazy initialization).
            http_conn = std::make_shared<HttpConnectionHandler>(conn);
            SetupHandlers(http_conn);
            http_connections_[conn->fd()] = http_conn;
        } else {
            http_conn = it->second;
        }
    }

    // Guard against fd-reuse: verify the handler still wraps the same connection
    if (http_conn->GetConnection() != conn) return;

    http_conn->OnRawData(conn, message);
}
