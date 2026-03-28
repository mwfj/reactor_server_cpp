#include "http/http_server.h"
#include "config/config_loader.h"
#include "ws/websocket_frame.h"
#include "http2/http2_constants.h"
#include "log/logger.h"
#include <algorithm>
#include <set>

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

// Validate host is a numeric IPv4 address — inet_addr() silently returns
// INADDR_NONE for hostnames like "localhost" or IPv6 literals, causing
// a confusing bind failure much later.
static const std::string& ValidateHost(const std::string& host) {
    if (host.empty()) {
        throw std::invalid_argument("bind host must not be empty");
    }
    if (inet_addr(host.c_str()) == INADDR_NONE && host != "255.255.255.255") {
        throw std::invalid_argument(
            "Invalid bind host: '" + host +
            "' (must be a numeric IPv4 address, e.g. '0.0.0.0' or '127.0.0.1')");
    }
    return host;
}

// Validate port before member construction — must run in the initializer
// list, before net_server_ tries to bind/listen on the (possibly invalid) port.
static size_t ValidatePort(int port) {
    if (port < 1 || port > 65535) {
        throw std::invalid_argument(
            "Invalid port: " + std::to_string(port) + " (must be 1-65535)");
    }
    return static_cast<size_t>(port);
}

HttpServer::HttpServer(const std::string& ip, int port)
    : net_server_(ValidateHost(ip), ValidatePort(port),
                  10,                          // scan interval: 30s default timeout / 3
                  std::chrono::seconds(300),   // default idle timeout
                  ServerConfig{}.worker_threads)
{
    WireNetServerCallbacks();
    // Apply the same defaults as the config constructor — must match ServerConfig defaults.
    net_server_.SetMaxConnections(ServerConfig{}.max_connections);
    net_server_.SetMaxInputSize(ComputeInputCap());
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
                      // Both user timeouts disabled, but protocol-level deadlines
                      // (WS close handshake 5s, HTTP close-drain 30s) still need
                      // the timer scan to enforce them. Use 5s to match the
                      // shortest protocol deadline.
                      if (idle_interval == 0 && req_interval == 0) return 5;
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
    logging::Init("reactor", logging::ParseLevel(config.log.level),
                  config.log.file, config.log.max_file_size, config.log.max_files);

    max_body_size_ = config.max_body_size;
    max_header_size_ = config.max_header_size;
    max_ws_message_size_ = config.max_ws_message_size;
    request_timeout_sec_ = config.request_timeout_sec;
    shutdown_drain_timeout_sec_ = config.shutdown_drain_timeout_sec;
    net_server_.SetMaxConnections(config.max_connections);

    // Set input buffer cap on NetServer — applied BEFORE epoll registration
    // to eliminate the race where data arrives before the cap is set.
    net_server_.SetMaxInputSize(ComputeInputCap());

    // Initialize HTTP/2 enabled flag BEFORE the TLS section so that ALPN
    // protocol selection below uses the config value, not the member default.
    http2_enabled_ = config.http2.enabled;

    if (config.tls.enabled) {
        tls_ctx_ = std::make_shared<TlsContext>(config.tls.cert_file, config.tls.key_file);
        if (config.tls.min_version == "1.2") {
            // Default — already set in TlsContext constructor
        } else if (config.tls.min_version == "1.3") {
            tls_ctx_->SetMinProtocolVersion(TLS1_3_VERSION);
        } else {
            throw std::runtime_error(
                "Unsupported tls.min_version: '" + config.tls.min_version +
                "' (must be '1.2' or '1.3')");
        }

        // Register ALPN protocols for HTTP/2 negotiation
        if (http2_enabled_) {
            tls_ctx_->SetAlpnProtocols({"h2", "http/1.1"});
        } else {
            tls_ctx_->SetAlpnProtocols({"http/1.1"});
        }

        net_server_.SetTlsContext(tls_ctx_);
    }

    // Initialize HTTP/2 session settings from config
    h2_settings_.max_concurrent_streams = config.http2.max_concurrent_streams;
    h2_settings_.initial_window_size    = config.http2.initial_window_size;
    h2_settings_.max_frame_size         = config.http2.max_frame_size;
    h2_settings_.max_header_list_size   = config.http2.max_header_list_size;
}

size_t HttpServer::ComputeInputCap() const {
    // Cap per-cycle input buffer allocation. When the cap is hit, the read
    // loop stops (data stays in kernel buffer) and schedules another read
    // after the parser processes what it has. No data is discarded.
    // No multiplier needed — the parser processes data incrementally across
    // cycles. Wire overhead (chunked framing etc.) is handled naturally.
    size_t http_cap = 0;
    if (max_header_size_ > 0 && max_body_size_ > 0) {
        size_t sum = max_header_size_ + max_body_size_;
        if (sum >= max_header_size_) http_cap = sum;  // overflow guard
    } else if (max_header_size_ > 0) {
        http_cap = max_header_size_;
    } else if (max_body_size_ > 0) {
        http_cap = max_body_size_;
    }

    // Also bound by WS message size. A client can coalesce an HTTP upgrade
    // request with a large first WS frame in one read. Without this, the
    // pre-upgrade cap (based on HTTP limits) allows more data than
    // max_ws_message_size_ to be buffered before the cap switches post-upgrade.
    // The HTTP parser processes incrementally, so a smaller cap is fine —
    // it just means more read cycles for large HTTP bodies.
    if (max_ws_message_size_ > 0) {
        if (http_cap == 0) return max_ws_message_size_;
        return std::min(http_cap, max_ws_message_size_);
    }
    return http_cap;
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

void HttpServer::SetReadyCallback(std::function<void()> cb) {
    net_server_.SetReadyCallback(std::move(cb));
}

void HttpServer::Stop() {
    logging::Get()->info("HttpServer stopping");

    // Collect WS connections while holding the lock, then send close frames
    // AFTER releasing. Sending under the lock would deadlock: a failed inline
    // write in DoSendRaw → CallCloseCb → HandleCloseConnection → conn_mtx_.
    std::vector<std::pair<std::shared_ptr<HttpConnectionHandler>,
                          std::shared_ptr<ConnectionHandler>>> ws_conns;
    {
        std::lock_guard<std::mutex> lck(conn_mtx_);
        for (auto& pair : http_connections_) {
            auto* ws = pair.second->GetWebSocket();
            if (ws && ws->IsOpen()) {
                ws_conns.emplace_back(pair.second, pair.second->GetConnection());
            }
        }
    }
    // Send 1001 Going Away close frames outside the lock.
    for (auto& [http_conn, conn] : ws_conns) {
        auto* ws = http_conn->GetWebSocket();
        if (ws && ws->IsOpen()) {
            try {
                ws->SendClose(1001, "Going Away");
                // During shutdown, close transport after the close frame drains.
                // SendClose() normally avoids CloseAfterWrite to wait 5s for the
                // peer's reply, but during shutdown that wait is unnecessary —
                // the 1001 code in the frame tells the client why we're closing.
                if (conn) conn->CloseAfterWrite();
            }
            catch (...) {}
        }
    }

    // Stop accepting new connections before building the H2 drain snapshot.
    // Prevents new connections from bypassing the graceful shutdown path.
    net_server_.StopAccepting();

    // Graceful HTTP/2 shutdown: request GOAWAY + drain on the dispatcher thread.
    // Collect H2 connections under conn_mtx_ first, then release before
    // acquiring drain_mtx_ to avoid nested lock ordering (conn_mtx_ → drain_mtx_).
    using H2Pair = std::pair<std::shared_ptr<Http2ConnectionHandler>,
                             std::shared_ptr<ConnectionHandler>>;
    std::vector<H2Pair> h2_snapshot;
    {
        std::lock_guard<std::mutex> lck(conn_mtx_);
        h2_snapshot.reserve(h2_connections_.size());
        for (auto& [fd, h2_conn] : h2_connections_) {
            auto conn = h2_conn->GetConnection();
            if (!conn) continue;
            h2_snapshot.emplace_back(h2_conn, std::move(conn));
        }
    }

    std::set<ConnectionHandler*> draining_conn_ptrs;
    for (auto& [h2_conn, conn] : h2_snapshot) {
        // Skip connections that closed between snapshot and now
        if (conn->IsClosing()) continue;
        ConnectionHandler* conn_ptr = conn.get();

        // Install drain-complete callback
        h2_conn->SetDrainCompleteCallback([this, conn_ptr]() {
            OnH2DrainComplete(conn_ptr);
        });

        // Strong refs — kept alive through drain
        {
            std::lock_guard<std::mutex> dlck(drain_mtx_);
            h2_draining_.push_back({h2_conn, conn});
        }
        draining_conn_ptrs.insert(conn_ptr);

        // Enqueue GOAWAY + drain check on dispatcher thread
        h2_conn->RequestShutdown();
    }

    // If drain wait is safe (not on a dispatcher thread) and H2 connections
    // exist, exempt them from the close sweep and install the drain callback.
    // On a dispatcher thread: degrade to normal close sweep (no exemption,
    // no drain wait) to avoid deadlock.
    bool has_draining = false;
    {
        std::lock_guard<std::mutex> dlck(drain_mtx_);
        has_draining = !h2_draining_.empty();
    }
    if (has_draining && !net_server_.IsOnDispatcherThread()) {
        net_server_.SetDrainingConns(std::move(draining_conn_ptrs));
        net_server_.SetPreStopDrainCallback([this]() { WaitForH2Drain(); });
    } else if (has_draining) {
        logging::Get()->warn("HttpServer::Stop() called from dispatcher thread — "
                             "HTTP/2 graceful drain skipped to avoid deadlock");
        // Don't exempt H2 connections — let normal close sweep handle them
    }

    net_server_.Stop();
    {
        std::lock_guard<std::mutex> lck(conn_mtx_);
        http_connections_.clear();
        h2_connections_.clear();
        pending_detection_.clear();
    }
    // Clear one-shot drain state (Stop may be called from destructor too)
    {
        std::lock_guard<std::mutex> dlck(drain_mtx_);
        h2_draining_.clear();
    }
}

void HttpServer::OnH2DrainComplete(ConnectionHandler* conn_ptr) {
    // Called from dispatcher thread when an H2 connection finishes draining.
    std::lock_guard<std::mutex> lck(drain_mtx_);
    h2_draining_.erase(
        std::remove_if(h2_draining_.begin(), h2_draining_.end(),
            [conn_ptr](const DrainingH2Conn& d) {
                return d.conn.get() == conn_ptr;
            }),
        h2_draining_.end());
    if (h2_draining_.empty()) {
        drain_cv_.notify_one();
    }
}

void HttpServer::WaitForH2Drain() {
    std::unique_lock<std::mutex> lck(drain_mtx_);
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::seconds(shutdown_drain_timeout_sec_);
    drain_cv_.wait_until(lck, deadline, [this]() {
        return h2_draining_.empty();
    });

    if (!h2_draining_.empty()) {
        // Timeout: force-close remaining. Move to local to avoid holding
        // drain_mtx_ during ForceClose (prevents lock coupling with late callbacks).
        auto remaining = std::move(h2_draining_);
        h2_draining_.clear();
        lck.unlock();
        for (auto& d : remaining) {
            if (d.conn) d.conn->ForceClose();
        }
    }
}

void HttpServer::SetupHandlers(std::shared_ptr<HttpConnectionHandler> http_conn) {
    // Apply request size limits
    http_conn->SetMaxBodySize(max_body_size_);
    http_conn->SetMaxHeaderSize(max_header_size_);
    http_conn->SetMaxWsMessageSize(max_ws_message_size_);
    http_conn->SetRequestTimeout(request_timeout_sec_);

    // Set request handler: dispatch through router
    http_conn->SetRequestCallback(
        [this](std::shared_ptr<HttpConnectionHandler> self,
               const HttpRequest& request,
               HttpResponse& response) {
            if (!router_.Dispatch(request, response)) {
                // Set 404 on the existing response to preserve any headers
                // that middleware already added (CORS, request-id, etc.)
                response.Status(404).Text("Not Found");
            }
        }
    );

    // Middleware runner for WebSocket upgrades (auth, CORS, rate limiting)
    http_conn->SetMiddlewareCallback(
        [this](const HttpRequest& request, HttpResponse& response) -> bool {
            return router_.RunMiddleware(request, response);
        }
    );

    // Route checker: determines if a WebSocket route exists (called before 101)
    http_conn->SetRouteCheckCallback(
        [this](const std::string& path) -> bool {
            return router_.HasWebSocketRoute(path);
        }
    );

    // Upgrade handler: wires WS callbacks (called exactly once, after ws_conn_ created)
    http_conn->SetUpgradeCallback(
        [this](std::shared_ptr<HttpConnectionHandler> self,
               const HttpRequest& request) {
            auto ws_handler = router_.GetWebSocketHandler(request.path);
            if (ws_handler && self->GetWebSocket()) {
                ws_handler(*self->GetWebSocket());
            }
        }
    );
}

void HttpServer::SafeNotifyWsClose(const std::shared_ptr<HttpConnectionHandler>& http_conn) {
    if (!http_conn) return;
    auto* ws = http_conn->GetWebSocket();
    if (ws) {
        try { ws->NotifyTransportClose(); }
        catch (const std::exception& e) {
            logging::Get()->error("Exception in WS close handler: {}", e.what());
        }
    }
}

void HttpServer::HandleNewConnection(std::shared_ptr<ConnectionHandler> conn) {
    // Guard: if the connection already closed (fast disconnect between
    // RegisterCallbacks enabling epoll and new_conn_callback running here),
    // skip entirely. Inserting a handler for a closed connection would leave
    // stale state in http_connections_ (potentially under fd -1 after ReleaseFd).
    if (conn->IsClosing()) return;

    if (http2_enabled_) {
        // Guard against accept/data race: if HandleMessage already ran and
        // created a handler for THIS connection, skip everything below.
        {
            std::lock_guard<std::mutex> lck(conn_mtx_);
            auto h2_it = h2_connections_.find(conn->fd());
            if (h2_it != h2_connections_.end()) {
                if (h2_it->second->GetConnection() == conn) {
                    return;  // Already initialized by HandleMessage
                }
                // Stale handler from fd reuse — evict
                h2_connections_.erase(h2_it);
            }
            auto h1_it = http_connections_.find(conn->fd());
            if (h1_it != http_connections_.end()) {
                if (h1_it->second->GetConnection() == conn) {
                    return;  // Already initialized by HandleMessage
                }
                // Stale handler from fd reuse — evict
                h1_it->second = nullptr;  // prevent WS notify on stale handler
                http_connections_.erase(h1_it);
            }
            // Also clean up stale pending detection
            auto pd_it = pending_detection_.find(conn->fd());
            if (pd_it != pending_detection_.end() && pd_it->second.conn != conn) {
                pending_detection_.erase(pd_it);
            }
        }

        // Note: TLS ALPN h2 detection cannot happen here — HandleNewConnection
        // runs before TLS handshake completes (tls_state_ == HANDSHAKE, not READY).
        // GetAlpnProtocol() returns empty until handshake finishes.
        // ALPN detection happens in HandleMessage → DetectAndRouteProtocol after
        // the first OnMessage fires (which is post-handshake).
    } else {
        // HTTP/2 disabled — always create HTTP/1.x handler immediately.
        std::shared_ptr<HttpConnectionHandler> old_handler;
        bool already_initialized = false;
        {
            std::lock_guard<std::mutex> lck(conn_mtx_);
            auto it = http_connections_.find(conn->fd());
            if (it != http_connections_.end()) {
                if (it->second->GetConnection() == conn) {
                    already_initialized = true;
                } else {
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
        SafeNotifyWsClose(old_handler);
        if (already_initialized) return;
    }

    // Arm a connection-level deadline covering the TLS handshake + first request
    // / protocol detection. Prevents slow-drip attacks during the detection window.
    if (request_timeout_sec_ > 0) {
        conn->SetDeadline(std::chrono::steady_clock::now() +
                          std::chrono::seconds(request_timeout_sec_));
    }

    logging::Get()->debug("New HTTP connection fd={} from {}:{}",
                          conn->fd(), conn->ip_addr(), conn->port());
}

void HttpServer::HandleCloseConnection(std::shared_ptr<ConnectionHandler> conn) {
    logging::Get()->debug("HTTP connection closed fd={}", conn->fd());

    // Single lock: check both H2 and HTTP/1.x maps
    std::shared_ptr<HttpConnectionHandler> http_conn;
    bool was_h2 = false;
    {
        std::lock_guard<std::mutex> lck(conn_mtx_);
        auto pd_it = pending_detection_.find(conn->fd());
        if (pd_it != pending_detection_.end() && pd_it->second.conn == conn) {
            pending_detection_.erase(pd_it);
        }
        auto h2_it = h2_connections_.find(conn->fd());
        if (h2_it != h2_connections_.end() && h2_it->second->GetConnection() == conn) {
            h2_connections_.erase(h2_it);
            was_h2 = true;
        }
        if (!was_h2) {
            auto it = http_connections_.find(conn->fd());
            if (it != http_connections_.end() && it->second->GetConnection() == conn) {
                http_conn = it->second;
                http_connections_.erase(it);
            }
        }
    }
    // Outside lock: notify drain set and WS close handler
    if (was_h2) {
        OnH2DrainComplete(conn.get());
        return;
    }
    SafeNotifyWsClose(http_conn);
}

void HttpServer::HandleErrorConnection(std::shared_ptr<ConnectionHandler> conn) {
    logging::Get()->error("HTTP connection error fd={}", conn->fd());

    // Single lock: check both H2 and HTTP/1.x maps
    std::shared_ptr<HttpConnectionHandler> http_conn;
    bool was_h2 = false;
    {
        std::lock_guard<std::mutex> lck(conn_mtx_);
        auto pd_it = pending_detection_.find(conn->fd());
        if (pd_it != pending_detection_.end() && pd_it->second.conn == conn) {
            pending_detection_.erase(pd_it);
        }
        auto h2_it = h2_connections_.find(conn->fd());
        if (h2_it != h2_connections_.end() && h2_it->second->GetConnection() == conn) {
            h2_connections_.erase(h2_it);
            was_h2 = true;
        }
        if (!was_h2) {
            auto it = http_connections_.find(conn->fd());
            if (it != http_connections_.end() && it->second->GetConnection() == conn) {
                http_conn = it->second;
                http_connections_.erase(it);
            }
        }
    }
    if (was_h2) {
        OnH2DrainComplete(conn.get());
        return;
    }
    SafeNotifyWsClose(http_conn);
}

void HttpServer::HandleMessage(std::shared_ptr<ConnectionHandler> conn, std::string& message) {
    // Single lock: look up both H2 and HTTP/1.x maps.
    // Copy shared_ptrs under the lock, then call OnRawData outside it:
    // OnRawData can trigger callbacks that acquire conn_mtx_ — deadlock.
    std::shared_ptr<Http2ConnectionHandler> h2_conn;
    std::shared_ptr<HttpConnectionHandler> http_conn;
    {
        std::lock_guard<std::mutex> lck(conn_mtx_);

        // Check HTTP/2 connections
        auto h2_it = h2_connections_.find(conn->fd());
        if (h2_it != h2_connections_.end()) {
            if (h2_it->second->GetConnection() == conn) {
                h2_conn = h2_it->second;
            } else {
                // fd reused — remove stale entry (will fall through to detection)
                h2_connections_.erase(h2_it);
            }
        }

        // Check HTTP/1.x connections (only if not H2)
        if (!h2_conn) {
            auto it = http_connections_.find(conn->fd());
            if (it != http_connections_.end()) {
                http_conn = it->second;
            }
        }
    }

    if (h2_conn) {
        h2_conn->OnRawData(conn, message);
        return;
    }

    if (http_conn) {
        // Guard against fd-reuse: if the handler wraps a stale connection,
        // notify the old WS handler and replace with a fresh one.
        if (http_conn->GetConnection() != conn) {
            SafeNotifyWsClose(http_conn);
            http_conn = nullptr;
            {
                std::lock_guard<std::mutex> lck(conn_mtx_);
                http_connections_.erase(conn->fd());
            }
            // Fall through to DetectAndRouteProtocol below
        } else {
            http_conn->OnRawData(conn, message);
            return;
        }
    }

    // No handler exists yet (or stale fd-reuse removed above) — detect protocol and create one.
    // Prepend any buffered partial-preface bytes accumulated from a prior call.
    // Verify connection identity to guard against fd-reuse races.
    {
        std::lock_guard<std::mutex> lck(conn_mtx_);
        auto pd_it = pending_detection_.find(conn->fd());
        if (pd_it != pending_detection_.end()) {
            if (pd_it->second.conn == conn) {
                pd_it->second.data += message;
                message = std::move(pd_it->second.data);
            }
            // If conn doesn't match, discard stale entry (fd reused)
            pending_detection_.erase(pd_it);
        }
    }
    DetectAndRouteProtocol(conn, message);
}

bool HttpServer::DetectAndRouteProtocol(
    std::shared_ptr<ConnectionHandler> conn, std::string& message) {

    ProtocolDetector::Protocol proto = ProtocolDetector::Protocol::HTTP1;

    if (http2_enabled_) {
        if (conn->HasTls()) {
            // TLS: HTTP/2 MUST be negotiated via ALPN (RFC 9113 Section 3.2).
            // No preface sniffing — empty ALPN means HTTP/1.x.
            std::string alpn = conn->GetAlpnProtocol();
            if (!alpn.empty()) {
                proto = ProtocolDetector::DetectFromAlpn(alpn);
            }
            // else: no ALPN negotiated → stays HTTP1
        } else {
            // Cleartext: check for HTTP/2 client preface (h2c prior knowledge)
            proto = ProtocolDetector::DetectFromData(message.data(), message.size());
            if (proto == ProtocolDetector::Protocol::UNKNOWN) {
                // Not enough data to classify — buffer and wait for more bytes.
                // This handles h2c clients that send the 24-byte preface split
                // across multiple TCP segments. Store connection identity to
                // guard against fd-reuse races.
                std::lock_guard<std::mutex> lck(conn_mtx_);
                auto& pd = pending_detection_[conn->fd()];
                if (pd.conn == conn) {
                    pd.data += message;
                } else {
                    pd = {conn, message};
                }
                return true;
            }
        }
    }

    if (proto == ProtocolDetector::Protocol::HTTP2) {
        // Create HTTP/2 handler
        auto h2_conn = std::make_shared<Http2ConnectionHandler>(conn, h2_settings_);
        SetupH2Handlers(h2_conn);
        // Initialize BEFORE publishing to h2_connections_, so Stop() can't
        // call RequestShutdown() while session_ is still being created.
        h2_conn->Initialize(message);
        {
            std::lock_guard<std::mutex> lck(conn_mtx_);
            h2_connections_[conn->fd()] = h2_conn;
        }
        return true;
    }

    // HTTP/1.x — create handler (existing path)
    auto http_conn = std::make_shared<HttpConnectionHandler>(conn);
    SetupHandlers(http_conn);
    {
        std::lock_guard<std::mutex> lck(conn_mtx_);
        http_connections_[conn->fd()] = http_conn;
    }
    http_conn->OnRawData(conn, message);
    return true;
}

void HttpServer::SetupH2Handlers(std::shared_ptr<Http2ConnectionHandler> h2_conn) {
    h2_conn->SetMaxBodySize(max_body_size_);
    // Note: NOT calling SetMaxHeaderSize here. HTTP/2 header limits come from
    // h2_settings_.max_header_list_size (Http2Config, default 64KB), which is
    // already baked into the session settings and advertised via SETTINGS frame.
    // Calling SetMaxHeaderSize would overwrite it with the HTTP/1.x limit (8KB).
    h2_conn->SetRequestTimeout(request_timeout_sec_);

    // Set request callback: dispatch through HttpRouter (same as HTTP/1.x)
    h2_conn->SetRequestCallback(
        [this](std::shared_ptr<Http2ConnectionHandler> /*self*/,
               int32_t /*stream_id*/,
               const HttpRequest& request,
               HttpResponse& response) {
            if (!router_.Dispatch(request, response)) {
                response.Status(404).Text("Not Found");
            }
        }
    );
}
