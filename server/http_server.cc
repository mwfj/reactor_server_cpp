#include "http/http_server.h"
#include "config/config_loader.h"
#include "ws/websocket_frame.h"
#include "http2/http2_constants.h"
#include "log/logger.h"
#include <algorithm>
#include <set>

// RAII guard: decrements an atomic counter on scope exit. Used in request
// dispatch callbacks to ensure active_requests_ is decremented even on throw.
struct RequestGuard {
    std::atomic<int64_t>& counter;
    ~RequestGuard() { counter.fetch_sub(1, std::memory_order_relaxed); }
    RequestGuard(const RequestGuard&) = delete;
    RequestGuard& operator=(const RequestGuard&) = delete;
};

int HttpServer::ComputeTimerInterval(int idle_timeout_sec, int request_timeout_sec) {
    int idle_iv = idle_timeout_sec > 0
        ? std::max(idle_timeout_sec / 6, 1) : 0;
    int req_iv = request_timeout_sec > 0
        ? std::max(request_timeout_sec / 3, 1) : 0;
    // Both user timeouts disabled, but protocol-level deadlines (WS close
    // handshake 5s, HTTP close-drain 30s) still need the timer scan.
    if (idle_iv == 0 && req_iv == 0) return 5;
    if (idle_iv == 0) return req_iv;
    if (req_iv == 0) return idle_iv;
    return std::min(idle_iv, req_iv);
}

void HttpServer::MarkServerReady() {
    start_time_ = std::chrono::steady_clock::now();
    server_ready_.store(true, std::memory_order_release);
}

void HttpServer::CompensateH2Streams(
    const std::shared_ptr<Http2ConnectionHandler>& h2) {
    if (!h2) return;
    int64_t unclosed = h2->LocalStreamCount();
    if (unclosed > 0) {
        active_h2_streams_.fetch_sub(unclosed, std::memory_order_relaxed);
    }
}

void HttpServer::RemoveConnection(std::shared_ptr<ConnectionHandler> conn) {
    std::shared_ptr<HttpConnectionHandler> http_conn;
    std::shared_ptr<Http2ConnectionHandler> h2_handler;
    bool was_h2 = false;
    bool was_tracked = false;
    {
        std::lock_guard<std::mutex> lck(conn_mtx_);
        auto pd_it = pending_detection_.find(conn->fd());
        if (pd_it != pending_detection_.end() && pd_it->second.conn == conn) {
            pending_detection_.erase(pd_it);
            was_tracked = true;
        }
        auto h2_it = h2_connections_.find(conn->fd());
        if (h2_it != h2_connections_.end() && h2_it->second->GetConnection() == conn) {
            h2_handler = h2_it->second;
            h2_connections_.erase(h2_it);
            was_h2 = true;
            was_tracked = true;
        }
        if (!was_h2) {
            auto it = http_connections_.find(conn->fd());
            if (it != http_connections_.end() && it->second->GetConnection() == conn) {
                http_conn = it->second;
                http_connections_.erase(it);
                was_tracked = true;
            }
        }
    }
    if (was_tracked) {
        active_connections_.fetch_sub(1, std::memory_order_relaxed);
    }
    if (was_h2) {
        active_http2_connections_.fetch_sub(1, std::memory_order_relaxed);
        CompensateH2Streams(h2_handler);
        OnH2DrainComplete(conn.get());
        return;
    }
    if (http_conn) {
        active_http1_connections_.fetch_sub(1, std::memory_order_relaxed);
    }
    SafeNotifyWsClose(http_conn);
}

void HttpServer::WireNetServerCallbacks() {
    net_server_.SetNewConnectionCb(
        [this](std::shared_ptr<ConnectionHandler> conn) { HandleNewConnection(conn); });
    net_server_.SetCloseConnectionCb(
        [this](std::shared_ptr<ConnectionHandler> conn) { HandleCloseConnection(conn); });
    net_server_.SetErrorCb(
        [this](std::shared_ptr<ConnectionHandler> conn) { HandleErrorConnection(conn); });
    net_server_.SetOnMessageCb(
        [this](std::shared_ptr<ConnectionHandler> conn, std::string& msg) { HandleMessage(conn, msg); });

    // Resume deferred H2 output when transport buffer drains to zero.
    // HttpServer only does fd→handler lookup; scheduling is owned by
    // Http2ConnectionHandler::OnSendComplete().
    net_server_.SetSendCompletionCb(
        [this](std::shared_ptr<ConnectionHandler> conn) {
            std::shared_ptr<Http2ConnectionHandler> h2_conn;
            {
                std::lock_guard<std::mutex> lck(conn_mtx_);
                auto it = h2_connections_.find(conn->fd());
                if (it != h2_connections_.end() &&
                    it->second->GetConnection() == conn) {
                    h2_conn = it->second;
                }
            }
            if (h2_conn) {
                h2_conn->OnSendComplete();
            }
        });

    // Resume deferred H2 output at the low watermark (partial writes).
    net_server_.SetWriteProgressCb(
        [this](std::shared_ptr<ConnectionHandler> conn, size_t remaining) {
            std::shared_ptr<Http2ConnectionHandler> h2_conn;
            {
                std::lock_guard<std::mutex> lck(conn_mtx_);
                auto it = h2_connections_.find(conn->fd());
                if (it != h2_connections_.end() &&
                    it->second->GetConnection() == conn) {
                    h2_conn = it->second;
                }
            }
            if (h2_conn) {
                h2_conn->OnWriteProgress(remaining);
            }
        });
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
    resolved_worker_threads_ = net_server_.GetWorkerCount();
    net_server_.SetReadyCallback([this]() { MarkServerReady(); });
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
                  ComputeTimerInterval(config.idle_timeout_sec,
                                       config.request_timeout_sec),
                  // Pass idle_timeout_sec directly — 0 means disabled.
                  // ConnectionHandler::IsTimeOut handles duration==0 by skipping idle check.
                  std::chrono::seconds(config.idle_timeout_sec),
                  config.worker_threads)
{
    WireNetServerCallbacks();
    resolved_worker_threads_ = net_server_.GetWorkerCount();
    net_server_.SetReadyCallback([this]() { MarkServerReady(); });

    // Initialize logging from config
    logging::Init("reactor", logging::ParseLevel(config.log.level),
                  config.log.file, config.log.max_file_size, config.log.max_files);

    max_body_size_.store(config.max_body_size, std::memory_order_relaxed);
    max_header_size_.store(config.max_header_size, std::memory_order_relaxed);
    max_ws_message_size_.store(config.max_ws_message_size, std::memory_order_relaxed);
    request_timeout_sec_.store(config.request_timeout_sec, std::memory_order_relaxed);
    shutdown_drain_timeout_sec_.store(config.shutdown_drain_timeout_sec, std::memory_order_relaxed);
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
    // Snapshot all three size-limit atomics locally before computing to
    // prevent mixed-generation buffer caps during concurrent Reload().
    size_t body_sz = max_body_size_.load(std::memory_order_relaxed);
    size_t hdr_sz = max_header_size_.load(std::memory_order_relaxed);
    size_t ws_sz = max_ws_message_size_.load(std::memory_order_relaxed);

    // Cap per-cycle input buffer allocation. When the cap is hit, the read
    // loop stops (data stays in kernel buffer) and schedules another read
    // after the parser processes what it has. No data is discarded.
    size_t http_cap = 0;
    if (hdr_sz > 0 && body_sz > 0) {
        size_t sum = hdr_sz + body_sz;
        if (sum >= hdr_sz) http_cap = sum;  // overflow guard
    } else if (hdr_sz > 0) {
        http_cap = hdr_sz;
    } else if (body_sz > 0) {
        http_cap = body_sz;
    }

    // Also bound by WS message size.
    if (ws_sz > 0) {
        if (http_cap == 0) return ws_sz;
        return std::min(http_cap, ws_sz);
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
    net_server_.SetReadyCallback([this, user_cb = std::move(cb)]() {
        MarkServerReady();
        if (user_cb) user_cb();
    });
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

        // Strong refs — kept alive through drain.
        // Install callback + push atomically under drain_mtx_ to prevent
        // the race where HandleCloseConnection runs OnH2DrainComplete
        // between callback install and push (finding nothing to remove).
        {
            std::lock_guard<std::mutex> dlck(drain_mtx_);
            h2_draining_.push_back({h2_conn, conn});
        }
        draining_conn_ptrs.insert(conn_ptr);

        // Enqueue GOAWAY + drain check on dispatcher thread
        h2_conn->RequestShutdown();

        // Re-check: if the connection closed during setup, remove the stale
        // entry now. HandleCloseConnection may have already tried and missed.
        if (conn->IsClosing()) {
            OnH2DrainComplete(conn_ptr);
        }
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
                    std::chrono::seconds(
                        shutdown_drain_timeout_sec_.load(std::memory_order_relaxed));
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
    // Apply request size limits (snapshot from atomics — cached per-connection)
    http_conn->SetMaxBodySize(max_body_size_.load(std::memory_order_relaxed));
    http_conn->SetMaxHeaderSize(max_header_size_.load(std::memory_order_relaxed));
    http_conn->SetMaxWsMessageSize(max_ws_message_size_.load(std::memory_order_relaxed));
    http_conn->SetRequestTimeout(request_timeout_sec_.load(std::memory_order_relaxed));

    // Count every completed HTTP parse — dispatched, rejected (400/413/etc), or
    // upgraded. Fires from HandleCompleteRequest before dispatch or rejection.
    http_conn->SetRequestCountCallback([this]() {
        total_requests_.fetch_add(1, std::memory_order_relaxed);
    });

    // Set request handler: dispatch through router.
    http_conn->SetRequestCallback(
        [this](std::shared_ptr<HttpConnectionHandler> self,
               const HttpRequest& request,
               HttpResponse& response) {
            active_requests_.fetch_add(1, std::memory_order_relaxed);
            RequestGuard guard{active_requests_};

            if (!router_.Dispatch(request, response)) {
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
            // total_requests_ already counted by request_count_callback
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

    // NOTE: total_accepted_ and active_connections_ are NOT incremented here.
    // They are incremented at map-insertion points (pending_detection_ in this
    // method, http_connections_ in the http2_disabled path, or h2_connections_/
    // http_connections_ in DetectAndRouteProtocol). This ties counters to map
    // membership, which is always symmetric with the was_tracked decrement in
    // HandleCloseConnection/HandleErrorConnection. This eliminates the accept/
    // data race where HandleMessage and HandleCloseConnection run before this
    // method — the counter is incremented by whoever inserts into the map first.

    if (http2_enabled_) {
        // Guard against accept/data race: if HandleMessage already ran and
        // created a handler for THIS connection, skip everything below.
        std::shared_ptr<HttpConnectionHandler> stale_h1;
        std::shared_ptr<Http2ConnectionHandler> stale_h2;
        bool evicted_pd = false;
        bool new_conn_tracked = false;
        {
            std::lock_guard<std::mutex> lck(conn_mtx_);
            auto h2_it = h2_connections_.find(conn->fd());
            if (h2_it != h2_connections_.end()) {
                if (h2_it->second->GetConnection() == conn) {
                    return;  // Already initialized by HandleMessage
                }
                // Stale handler from fd reuse — save for stream compensation,
                // then evict. The old connection's close callback can no longer
                // find this entry, so we must decrement here.
                stale_h2 = h2_it->second;
                h2_connections_.erase(h2_it);
            }
            auto h1_it = http_connections_.find(conn->fd());
            if (h1_it != http_connections_.end()) {
                if (h1_it->second->GetConnection() == conn) {
                    return;  // Already initialized by HandleMessage
                }
                // Stale handler from fd reuse — save for WS close, then evict
                stale_h1 = std::move(h1_it->second);
                http_connections_.erase(h1_it);
            }
            // Track in pending_detection_ for counter symmetry: if the
            // connection closes before HandleMessage runs (no map entry yet),
            // HandleCloseConnection needs to find it here to decrement.
            // Track in pending_detection_ and count the connection.
            // Counter is tied to map membership — symmetric with was_tracked
            // decrement in HandleCloseConnection/HandleErrorConnection.
            auto pd_it = pending_detection_.find(conn->fd());
            if (pd_it != pending_detection_.end()) {
                if (pd_it->second.conn != conn) {
                    // Stale entry — replace with current conn tracking.
                    // Compensating decrement for old entry handled below.
                    pd_it->second = {conn, ""};
                    evicted_pd = true;
                    new_conn_tracked = true;
                }
                // else: same conn already tracked (partial preface + race
                // with HandleMessage) — already counted, keep data
            } else {
                pending_detection_[conn->fd()] = {conn, ""};
                new_conn_tracked = true;
            }
        }
        // Increment counters for the newly tracked connection
        if (new_conn_tracked) {
            total_accepted_.fetch_add(1, std::memory_order_relaxed);
            active_connections_.fetch_add(1, std::memory_order_relaxed);
        }
        // Compensating decrements for evicted stale entries — their close
        // callbacks can no longer find the map entries we just removed.
        if (stale_h2) {
            active_connections_.fetch_sub(1, std::memory_order_relaxed);
            active_http2_connections_.fetch_sub(1, std::memory_order_relaxed);
            CompensateH2Streams(stale_h2);
        }
        if (stale_h1) {
            active_connections_.fetch_sub(1, std::memory_order_relaxed);
            active_http1_connections_.fetch_sub(1, std::memory_order_relaxed);
        }
        if (evicted_pd && !stale_h2 && !stale_h1) {
            active_connections_.fetch_sub(1, std::memory_order_relaxed);
        }
        // Notify stale WS handler outside the lock.
        SafeNotifyWsClose(stale_h1);
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
                    // Counter tied to map insertion
                    total_accepted_.fetch_add(1, std::memory_order_relaxed);
                    active_connections_.fetch_add(1, std::memory_order_relaxed);
                    active_http1_connections_.fetch_add(1, std::memory_order_relaxed);
                }
            } else {
                auto http_conn = std::make_shared<HttpConnectionHandler>(conn);
                SetupHandlers(http_conn);
                http_connections_[conn->fd()] = http_conn;
                // Counter tied to map insertion
                total_accepted_.fetch_add(1, std::memory_order_relaxed);
                active_connections_.fetch_add(1, std::memory_order_relaxed);
                active_http1_connections_.fetch_add(1, std::memory_order_relaxed);
            }
        }
        // Compensating decrement for evicted stale handler (fd reuse)
        if (old_handler) {
            active_connections_.fetch_sub(1, std::memory_order_relaxed);
            active_http1_connections_.fetch_sub(1, std::memory_order_relaxed);
        }
        SafeNotifyWsClose(old_handler);
        if (already_initialized) return;
    }

    // Arm a connection-level deadline for the TLS handshake + protocol detection
    // window. Load from atomic at use time — not cached per-connection.
    int req_timeout = request_timeout_sec_.load(std::memory_order_relaxed);
    if (req_timeout > 0) {
        conn->SetDeadline(std::chrono::steady_clock::now() +
                          std::chrono::seconds(req_timeout));
    }

    logging::Get()->debug("New HTTP connection fd={} from {}:{}",
                          conn->fd(), conn->ip_addr(), conn->port());
}

void HttpServer::HandleCloseConnection(std::shared_ptr<ConnectionHandler> conn) {
    logging::Get()->debug("HTTP connection closed fd={}", conn->fd());
    RemoveConnection(conn);
}

void HttpServer::HandleErrorConnection(std::shared_ptr<ConnectionHandler> conn) {
    logging::Get()->error("HTTP connection error fd={}", conn->fd());
    RemoveConnection(conn);
}

void HttpServer::HandleMessage(std::shared_ptr<ConnectionHandler> conn, std::string& message) {
    // Single lock: look up both H2 and HTTP/1.x maps.
    // Copy shared_ptrs under the lock, then call OnRawData outside it:
    // OnRawData can trigger callbacks that acquire conn_mtx_ — deadlock.
    std::shared_ptr<Http2ConnectionHandler> h2_conn;
    std::shared_ptr<Http2ConnectionHandler> evicted_stale_h2;
    std::shared_ptr<HttpConnectionHandler> http_conn;
    {
        std::lock_guard<std::mutex> lck(conn_mtx_);

        // Check HTTP/2 connections
        auto h2_it = h2_connections_.find(conn->fd());
        if (h2_it != h2_connections_.end()) {
            if (h2_it->second->GetConnection() == conn) {
                h2_conn = h2_it->second;
            } else {
                // fd reused — save for stream compensation, then evict
                evicted_stale_h2 = h2_it->second;
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
    // Compensating decrement for evicted stale H2 entry
    if (evicted_stale_h2) {
        active_connections_.fetch_sub(1, std::memory_order_relaxed);
        active_http2_connections_.fetch_sub(1, std::memory_order_relaxed);
        CompensateH2Streams(evicted_stale_h2);
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
            bool evicted_stale_h1 = false;
            {
                std::lock_guard<std::mutex> lck(conn_mtx_);
                auto it = http_connections_.find(conn->fd());
                if (it != http_connections_.end() &&
                    it->second->GetConnection() != conn) {
                    http_connections_.erase(it);
                    evicted_stale_h1 = true;
                }
            }
            if (evicted_stale_h1) {
                active_connections_.fetch_sub(1, std::memory_order_relaxed);
                active_http1_connections_.fetch_sub(1, std::memory_order_relaxed);
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
    // Check if pending_detection_ has a tracking entry for this connection.
    // If found with matching identity, counters were already incremented
    // by HandleNewConnection. If not found, this is the accept/data race
    // path (HandleMessage ran before HandleNewConnection) — DetectAndRoute
    // must handle the counter increment.
    bool already_counted = false;
    {
        bool evicted_stale_pd = false;
        std::lock_guard<std::mutex> lck(conn_mtx_);
        auto pd_it = pending_detection_.find(conn->fd());
        if (pd_it != pending_detection_.end()) {
            if (pd_it->second.conn == conn) {
                pd_it->second.data += message;
                message = std::move(pd_it->second.data);
                already_counted = true;
            } else {
                // Stale entry (fd reused) — compensating decrement
                evicted_stale_pd = true;
            }
            pending_detection_.erase(pd_it);
        }
        if (evicted_stale_pd) {
            active_connections_.fetch_sub(1, std::memory_order_relaxed);
        }
    }
    DetectAndRouteProtocol(conn, message, already_counted);
}

bool HttpServer::DetectAndRouteProtocol(
    std::shared_ptr<ConnectionHandler> conn, std::string& message,
    bool already_counted) {

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
                // across multiple TCP segments.
                std::lock_guard<std::mutex> lck(conn_mtx_);
                auto& pd = pending_detection_[conn->fd()];
                if (pd.conn == conn) {
                    // Same conn — append additional preface bytes
                    pd.data += message;
                } else {
                    // First insertion for this connection. If not already_counted
                    // (accept/data race: HandleMessage before HandleNewConnection),
                    // increment now so the counter is set before the entry exists
                    // in the map. HandleNewConnection will see the same-conn entry
                    // and skip its own increment.
                    pd = {conn, message};
                    if (!already_counted) {
                        total_accepted_.fetch_add(1, std::memory_order_relaxed);
                        active_connections_.fetch_add(1, std::memory_order_relaxed);
                    }
                }
                return true;
            }
        }
    }

    if (proto == ProtocolDetector::Protocol::HTTP2) {
        // Skip if connection is fully closing (not just peer half-close)
        if (conn->IsClosing()) return true;
        if (!already_counted) {
            total_accepted_.fetch_add(1, std::memory_order_relaxed);
            active_connections_.fetch_add(1, std::memory_order_relaxed);
        }
        active_http2_connections_.fetch_add(1, std::memory_order_relaxed);
        // Snapshot h2_settings_ and publish handler under a single lock to
        // prevent race with Reload() and to avoid double mutex acquisition.
        Http2Session::Settings settings_snapshot;
        std::shared_ptr<Http2ConnectionHandler> h2_conn;
        {
            std::lock_guard<std::mutex> lck(conn_mtx_);
            settings_snapshot = h2_settings_;
            h2_conn = std::make_shared<Http2ConnectionHandler>(conn, settings_snapshot);
            SetupH2Handlers(h2_conn);
            // Publish BEFORE Initialize so HandleCloseConnection can find and
            // remove the handler if Initialize's SendRaw triggers a synchronous
            // close. RequestShutdown safely handles uninitialized sessions.
            h2_connections_[conn->fd()] = h2_conn;
        }
        h2_conn->Initialize(message);
        return true;
    }

    // HTTP/1.x — create handler (existing path)
    if (!already_counted) {
        total_accepted_.fetch_add(1, std::memory_order_relaxed);
        active_connections_.fetch_add(1, std::memory_order_relaxed);
    }
    active_http1_connections_.fetch_add(1, std::memory_order_relaxed);
    auto http_conn = std::make_shared<HttpConnectionHandler>(conn);
    SetupHandlers(http_conn);
    {
        std::lock_guard<std::mutex> lck(conn_mtx_);
        // Identity check: don't overwrite a handler for a different connection
        // on the same fd (fd-reuse race with HandleNewConnection).
        auto existing = http_connections_.find(conn->fd());
        if (existing != http_connections_.end() &&
            existing->second->GetConnection() != conn) {
            // Stale entry — safe to overwrite
        }
        http_connections_[conn->fd()] = http_conn;
    }
    http_conn->OnRawData(conn, message);
    return true;
}

void HttpServer::SetupH2Handlers(std::shared_ptr<Http2ConnectionHandler> h2_conn) {
    h2_conn->SetMaxBodySize(max_body_size_.load(std::memory_order_relaxed));
    // Note: NOT calling SetMaxHeaderSize here. HTTP/2 header limits come from
    // h2_settings_.max_header_list_size (Http2Config, default 64KB), which is
    // already baked into the session settings and advertised via SETTINGS frame.
    h2_conn->SetRequestTimeout(request_timeout_sec_.load(std::memory_order_relaxed));

    // Set request callback: dispatch through HttpRouter (same as HTTP/1.x).
    // total_requests_ is counted in stream_open_callback (below), which fires
    // for every stream including those rejected before dispatch — consistent
    // with HTTP/1's request_count_callback that counts all parsed requests.
    h2_conn->SetRequestCallback(
        [this](std::shared_ptr<Http2ConnectionHandler> /*self*/,
               int32_t /*stream_id*/,
               const HttpRequest& request,
               HttpResponse& response) {
            active_requests_.fetch_add(1, std::memory_order_relaxed);
            RequestGuard guard{active_requests_};

            if (!router_.Dispatch(request, response)) {
                response.Status(404).Text("Not Found");
            }
        }
    );

    // Stream open/close counter callbacks.
    // Also maintain per-connection local_stream_count_ for thread-safe
    // compensation on abrupt close (avoids reading session containers
    // from the wrong thread).
    h2_conn->SetStreamOpenCallback(
        [this](std::shared_ptr<Http2ConnectionHandler> self, int32_t /*stream_id*/) {
            active_h2_streams_.fetch_add(1, std::memory_order_relaxed);
            total_requests_.fetch_add(1, std::memory_order_relaxed);
            self->IncrementLocalStreamCount();
        }
    );
    h2_conn->SetStreamCloseCallback(
        [this](std::shared_ptr<Http2ConnectionHandler> self,
               int32_t /*stream_id*/, uint32_t /*error_code*/) {
            active_h2_streams_.fetch_sub(1, std::memory_order_relaxed);
            self->DecrementLocalStreamCount();
        }
    );
}

bool HttpServer::Reload(const ServerConfig& new_config) {
    // Gate on server readiness — socket_dispatchers_ is built during Start()
    // and must not be walked until construction is complete.
    if (!server_ready_.load(std::memory_order_acquire)) {
        logging::Get()->warn("Reload() called before server is ready, ignored");
        return false;
    }

    // Validate reload-safe fields only — restart-only fields (bind_host,
    // bind_port, tls.*, worker_threads, http2.enabled) are ignored by Reload()
    // so they must not block validation. Build a copy with restart-only fields
    // set to the known-valid construction values that pass Validate().
    {
        ServerConfig validation_copy = new_config;
        validation_copy.bind_host = "127.0.0.1";  // always valid
        validation_copy.bind_port = 8080;          // always valid
        validation_copy.worker_threads = 1;        // always valid
        validation_copy.tls.enabled = false;       // skip TLS path checks
        // Validate H2 sub-settings only when the running server has H2 enabled.
        // When H2 is disabled, Reload() still copies them to h2_settings_ but
        // they're never used, so placeholder/out-of-range values are harmless.
        validation_copy.http2.enabled = http2_enabled_;
        try {
            ConfigLoader::Validate(validation_copy);
        } catch (const std::invalid_argument& e) {
            logging::Get()->error("Reload() rejected invalid config: {}", e.what());
            return false;
        }
    }

    // Update reload-safe limit fields (atomic stores)
    max_body_size_.store(new_config.max_body_size, std::memory_order_relaxed);
    max_header_size_.store(new_config.max_header_size, std::memory_order_relaxed);
    max_ws_message_size_.store(new_config.max_ws_message_size, std::memory_order_relaxed);
    request_timeout_sec_.store(new_config.request_timeout_sec, std::memory_order_relaxed);
    shutdown_drain_timeout_sec_.store(new_config.shutdown_drain_timeout_sec,
                                     std::memory_order_relaxed);

    // Update max_connections and input buffer cap
    net_server_.SetMaxConnections(new_config.max_connections);
    net_server_.SetMaxInputSize(ComputeInputCap());

    // Update idle timeout via EnQueue to dispatcher threads
    net_server_.SetConnectionTimeout(
        std::chrono::seconds(new_config.idle_timeout_sec));

    // Recompute timer scan interval. Only shorten, never lengthen — existing
    // connections keep their old per-connection deadlines and must be scanned
    // at least as frequently as before.
    {
        int new_scan = ComputeTimerInterval(new_config.idle_timeout_sec,
                                            new_config.request_timeout_sec);
        int cur_scan = net_server_.GetTimerInterval();
        net_server_.SetTimerInterval(
            cur_scan > 0 ? std::min(new_scan, cur_scan) : new_scan);
    }

    // Update HTTP/2 settings for NEW connections only (under conn_mtx_).
    // Existing sessions keep their negotiated SETTINGS values — submitting
    // a new SETTINGS frame to live sessions mid-stream is not supported.
    {
        std::lock_guard<std::mutex> lck(conn_mtx_);
        h2_settings_.max_concurrent_streams = new_config.http2.max_concurrent_streams;
        h2_settings_.initial_window_size    = new_config.http2.initial_window_size;
        h2_settings_.max_frame_size         = new_config.http2.max_frame_size;
        h2_settings_.max_header_list_size   = new_config.http2.max_header_list_size;
    }
    return true;
}

HttpServer::ServerStats HttpServer::GetStats() const {
    ServerStats stats;
    // Return 0 uptime before the ready callback sets start_time_ — avoids
    // bogus values from default-constructed time_point{}.
    if (server_ready_.load(std::memory_order_acquire)) {
        auto now = std::chrono::steady_clock::now();
        stats.uptime_seconds = std::chrono::duration_cast<std::chrono::seconds>(
            now - start_time_).count();
    }
    stats.active_connections      = active_connections_.load(std::memory_order_relaxed);
    stats.active_http1_connections = active_http1_connections_.load(std::memory_order_relaxed);
    stats.active_http2_connections = active_http2_connections_.load(std::memory_order_relaxed);
    // Clamp to 0 — compensation/close-callback races can briefly drive negative
    stats.active_h2_streams       = std::max<int64_t>(0,
        active_h2_streams_.load(std::memory_order_relaxed));
    stats.total_accepted          = total_accepted_.load(std::memory_order_relaxed);
    stats.total_requests          = total_requests_.load(std::memory_order_relaxed);
    stats.active_requests         = active_requests_.load(std::memory_order_relaxed);
    stats.max_connections     = net_server_.GetMaxConnections();
    stats.idle_timeout_sec    = static_cast<int>(net_server_.GetConnectionTimeout().count());
    stats.request_timeout_sec = request_timeout_sec_.load(std::memory_order_relaxed);
    stats.worker_threads      = resolved_worker_threads_;
    return stats;
}
