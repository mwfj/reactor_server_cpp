#include "http/http_server.h"
#include "config/config_loader.h"
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
    : net_server_(ip, static_cast<size_t>(port),
                  10,                          // scan interval: 30s default timeout / 3
                  std::chrono::seconds(300))   // default idle timeout
{
    WireNetServerCallbacks();
}

// Validate config before construction — throws on invalid values
static const ServerConfig& ValidateConfig(const ServerConfig& config) {
    ConfigLoader::Validate(config);
    return config;
}

HttpServer::HttpServer(const ServerConfig& config)
    : net_server_(ValidateConfig(config).bind_host, static_cast<size_t>(config.bind_port),
                  // Timer scan interval: must be frequent enough to enforce BOTH timeouts.
                  // Use the smaller of (idle/6) and (request/3), with 1s floor.
                  // If either timeout is 0 (disabled), use the other for the calculation.
                  [&]() -> int {
                      int idle_interval = config.idle_timeout_sec > 0
                          ? std::max(config.idle_timeout_sec / 6, 1) : 0;
                      int req_interval = config.request_timeout_sec > 0
                          ? std::max(config.request_timeout_sec / 3, 1) : 0;
                      if (idle_interval == 0 && req_interval == 0) return 60;  // both disabled
                      if (idle_interval == 0) return req_interval;
                      if (req_interval == 0) return idle_interval;
                      return std::min(idle_interval, req_interval);
                  }(),
                  // Pass idle_timeout_sec directly — 0 means disabled.
                  // ConnectionHandler::IsTimeOut handles duration==0 by skipping idle check.
                  std::chrono::seconds(config.idle_timeout_sec),
                  config.worker_threads)
{
    WireNetServerCallbacks();

    // Initialize logging from config
    {
        spdlog::level::level_enum log_level = spdlog::level::info;
        if (config.log.level == "trace") log_level = spdlog::level::trace;
        else if (config.log.level == "debug") log_level = spdlog::level::debug;
        else if (config.log.level == "info") log_level = spdlog::level::info;
        else if (config.log.level == "warn") log_level = spdlog::level::warn;
        else if (config.log.level == "error") log_level = spdlog::level::err;
        else if (config.log.level == "critical") log_level = spdlog::level::critical;

        logging::Init("reactor", log_level, config.log.file,
                       config.log.max_file_size, config.log.max_files);
    }

    max_body_size_ = config.max_body_size;
    max_header_size_ = config.max_header_size;
    max_ws_message_size_ = config.max_ws_message_size;
    request_timeout_sec_ = config.request_timeout_sec;
    net_server_.SetMaxConnections(config.max_connections);

    if (config.tls.enabled) {
        tls_ctx_ = std::make_unique<TlsContext>(config.tls.cert_file, config.tls.key_file);
        if (config.tls.min_version == "1.2") {
            // Default — already set in TlsContext constructor
        } else if (config.tls.min_version == "1.3") {
            tls_ctx_->SetMinProtocolVersion(TLS1_3_VERSION);
        } else {
            throw std::runtime_error(
                "Unsupported tls.min_version: '" + config.tls.min_version +
                "' (must be '1.2' or '1.3')");
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
    http_conn->SetRequestTimeout(request_timeout_sec_);

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
    std::shared_ptr<HttpConnectionHandler> old_handler;
    {
        std::lock_guard<std::mutex> lck(conn_mtx_);
        auto it = http_connections_.find(conn->fd());
        if (it != http_connections_.end()) {
            if (it->second->GetConnection() == conn) {
                // Already created by HandleMessage lazy-init — don't overwrite.
                // Fall through to per-connection setup below (SetMaxInputSize,
                // SetDeadline) which the lazy-init path doesn't do.
            } else {
                // FD reused — save old handler for WS notification outside the lock
                old_handler = it->second;
                auto http_conn = std::make_shared<HttpConnectionHandler>(conn);
                SetupHandlers(http_conn);
                http_connections_[conn->fd()] = http_conn;
            }
        } else {
            auto http_conn = std::make_shared<HttpConnectionHandler>(conn);
            SetupHandlers(http_conn);
            http_connections_[conn->fd()] = http_conn;
        }
    }
    // Notify old WS handler outside the lock to prevent deadlock
    if (old_handler) {
        auto* ws = old_handler->GetWebSocket();
        if (ws) {
            ws->NotifyTransportClose();
        }
    }
    // Cap the input buffer to prevent allocating far beyond configured limits
    // before the parser has a chance to reject (413/431). The cap is the sum of
    // max_header_size + max_body_size (the most a valid request can contain).
    // If both are 0 (unlimited), no cap is set (backward compat).
    if (max_header_size_ > 0 || max_body_size_ > 0) {
        conn->SetMaxInputSize(max_header_size_ + max_body_size_);
    }

    // Arm a connection-level deadline covering the TLS handshake + first HTTP request.
    // Without this, a client can slow-drip the TLS handshake indefinitely, bypassing
    // the request timeout (which only activates after parsed HTTP bytes in OnRawData).
    // When OnRawData fires after handshake completion, it overwrites this with the
    // per-request deadline. No DeadlineTimeoutCb is needed — can't send HTTP 408
    // during a TLS handshake, so the timer just closes the connection.
    if (request_timeout_sec_ > 0) {
        conn->SetDeadline(std::chrono::steady_clock::now() +
                          std::chrono::seconds(request_timeout_sec_));
    }

    logging::Get()->debug("New HTTP connection fd={} from {}:{}",
                          conn->fd(), conn->ip_addr(), conn->port());
}

void HttpServer::HandleCloseConnection(std::shared_ptr<ConnectionHandler> conn) {
    logging::Get()->debug("HTTP connection closed fd={}", conn->fd());
    std::shared_ptr<HttpConnectionHandler> http_conn;
    {
        std::lock_guard<std::mutex> lck(conn_mtx_);
        auto it = http_connections_.find(conn->fd());
        if (it != http_connections_.end() && it->second->GetConnection() == conn) {
            http_conn = it->second;
            http_connections_.erase(it);
        }
    }
    // Notify WS close handler OUTSIDE the lock to prevent deadlock
    if (http_conn) {
        auto* ws = http_conn->GetWebSocket();
        if (ws) {
            ws->NotifyTransportClose();  // Checks is_open_ internally
        }
    }
}

void HttpServer::HandleErrorConnection(std::shared_ptr<ConnectionHandler> conn) {
    logging::Get()->error("HTTP connection error fd={}", conn->fd());
    std::shared_ptr<HttpConnectionHandler> http_conn;
    {
        std::lock_guard<std::mutex> lck(conn_mtx_);
        auto it = http_connections_.find(conn->fd());
        if (it != http_connections_.end() && it->second->GetConnection() == conn) {
            http_conn = it->second;
            http_connections_.erase(it);
        }
    }
    if (http_conn) {
        auto* ws = http_conn->GetWebSocket();
        if (ws) {
            ws->NotifyTransportClose();  // Checks is_open_ internally
        }
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
            // Per-connection setup that HandleNewConnection normally does.
            if (max_header_size_ > 0 || max_body_size_ > 0) {
                conn->SetMaxInputSize(max_header_size_ + max_body_size_);
            }
        } else {
            http_conn = it->second;
        }
    }

    // Guard against fd-reuse: if the handler wraps a stale connection,
    // notify the old WS handler and replace with a fresh one.
    if (http_conn->GetConnection() != conn) {
        // Notify old WebSocket close handler before discarding
        auto* old_ws = http_conn->GetWebSocket();
        if (old_ws) {
            old_ws->NotifyTransportClose();
        }
        http_conn = std::make_shared<HttpConnectionHandler>(conn);
        SetupHandlers(http_conn);
        std::lock_guard<std::mutex> lck(conn_mtx_);
        http_connections_[conn->fd()] = http_conn;
        // Per-connection setup
        if (max_header_size_ > 0 || max_body_size_ > 0) {
            conn->SetMaxInputSize(max_header_size_ + max_body_size_);
        }
    }

    http_conn->OnRawData(conn, message);
}
