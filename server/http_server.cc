#include "http/http_server.h"
#include "config/config_loader.h"
#include "ws/websocket_frame.h"
#include "http2/http2_constants.h"
#include "upstream/upstream_manager.h"
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
    int interval;
    if (idle_iv == 0 && req_iv == 0) interval = 5;
    else if (idle_iv == 0) interval = req_iv;
    else if (req_iv == 0) interval = idle_iv;
    else interval = std::min(idle_iv, req_iv);
    // Cap at 5s — the shortest protocol deadline (WS close-handshake 5s).
    // Protocol-level deadlines (WS close 5s, HTTP drain 30s) need the timer
    // scan regardless of idle/request timeout tuning. Without this cap,
    // large timeouts push the scan cadence past protocol deadlines.
    // Log rotation checks also run on this cadence; 5s is reasonable
    // (they use try_lock, near-zero cost when not due).
    static constexpr int PROTOCOL_DEADLINE_CAP = 5;
    return std::min(interval, PROTOCOL_DEADLINE_CAP);
}

bool HttpServer::HasPendingH1Output() {
    std::lock_guard<std::mutex> lck(conn_mtx_);
    for (const auto& [fd, http_conn] : http_connections_) {
        auto conn = http_conn->GetConnection();
        // Use atomic flags as a race-free proxy for "output buffer not empty":
        // close_after_write is set by the close sweep, and cleared (via
        // ForceClose → IsClosing) when the buffer drains to zero. Reading
        // OutputBufferSize() directly would be UB (non-atomic std::string
        // read while dispatcher threads write).
        if (conn && conn->IsCloseDeferred() && !conn->IsClosing()) {
            return true;
        }
    }
    return false;
}

void HttpServer::MarkServerReady() {
    // Assign dispatcher indices for upstream pool partition affinity
    const auto& dispatchers = net_server_.GetSocketDispatchers();
    for (size_t i = 0; i < dispatchers.size(); ++i) {
        dispatchers[i]->SetDispatcherIndex(static_cast<int>(i));
    }

    // Create upstream pool manager if upstreams are configured
    if (!upstream_configs_.empty()) {
        try {
            upstream_manager_ = std::make_unique<UpstreamManager>(
                upstream_configs_, dispatchers);
        } catch (const std::exception& e) {
            logging::Get()->error("Failed to create UpstreamManager: {}",
                                  e.what());
            // Non-fatal — server starts without upstream pools
        }

        // Ensure the timer cadence is fast enough for upstream connect timeouts.
        // SetDeadline stores a ms-precision deadline, but TimerHandler only fires
        // at the timer scan interval. If connect_timeout_ms < current interval,
        // timeouts would fire late. Reduce the interval if needed.
        int min_upstream_sec = std::numeric_limits<int>::max();
        for (const auto& u : upstream_configs_) {
            // ceil division: ensures the timer fires within 1 interval of the
            // deadline, minimizing overshoot. Floor would let deadlines fire
            // up to (interval - 1)s late in the worst case.
            int connect_sec = std::max(
                (u.pool.connect_timeout_ms + 999) / 1000, 1);
            min_upstream_sec = std::min(min_upstream_sec, connect_sec);
            // Also consider idle timeout for eviction cadence
            if (u.pool.idle_timeout_sec > 0) {
                min_upstream_sec = std::min(min_upstream_sec,
                                            u.pool.idle_timeout_sec);
            }
        }
        if (min_upstream_sec < std::numeric_limits<int>::max()) {
            int current_interval = net_server_.GetTimerInterval();
            if (min_upstream_sec < current_interval) {
                net_server_.SetTimerInterval(min_upstream_sec);
                logging::Get()->debug("Timer interval reduced to {}s for "
                                      "upstream timeouts", min_upstream_sec);
            }
        }
    }

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
        // Only decrement if not upgraded — the upgrade callback already
        // decremented active_http1_connections_ at upgrade time.
        if (!http_conn->IsUpgraded()) {
            active_http1_connections_.fetch_sub(1, std::memory_order_relaxed);
        }
    }
    SafeNotifyWsClose(http_conn);
    OnWsDrainComplete(conn.get());
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

    // Wire timer callback for upstream pool idle eviction.
    // Fires periodically on each dispatcher thread (via TimerHandler
    // and epoll_wait timeout) — calls EvictExpired on the partition
    // for that dispatcher's index.
    // Guard with server_ready_ to avoid racing with MarkServerReady()
    // which writes upstream_manager_ from the main thread. The acquire
    // load synchronizes with the release store in MarkServerReady().
    net_server_.SetTimerCb(
        [this](std::shared_ptr<Dispatcher> disp) {
            if (server_ready_.load(std::memory_order_acquire) &&
                upstream_manager_ && disp->dispatcher_index() >= 0) {
                upstream_manager_->EvictExpired(
                    static_cast<size_t>(disp->dispatcher_index()));
            }
        });
}

// Validate host is a strict dotted-quad IPv4 address. Uses inet_pton (not
// inet_addr) to reject legacy shorthand forms like "1" or octal "0127.0.0.1".
static const std::string& ValidateHost(const std::string& host) {
    if (host.empty()) {
        throw std::invalid_argument("bind host must not be empty");
    }
    struct in_addr addr{};
    if (inet_pton(AF_INET, host.c_str(), &addr) != 1) {
        throw std::invalid_argument(
            "Invalid bind host: '" + host +
            "' (must be a dotted-quad IPv4 address, e.g. '0.0.0.0' or '127.0.0.1')");
    }
    return host;
}

// Validate port before member construction — must run in the initializer
// list, before net_server_ tries to bind/listen on the (possibly invalid) port.
static size_t ValidatePort(int port) {
    if (port < 0 || port > 65535) {
        throw std::invalid_argument(
            "Invalid port: " + std::to_string(port) + " (must be 0-65535)");
    }
    return static_cast<size_t>(port);
}

HttpServer::HttpServer(const std::string& ip, int port)
    : net_server_(ValidateHost(ip), ValidatePort(port),
                  ComputeTimerInterval(ServerConfig{}.idle_timeout_sec,
                                       ServerConfig{}.request_timeout_sec),
                  std::chrono::seconds(ServerConfig{}.idle_timeout_sec),
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

    // Store upstream configurations for pool creation in Start()
    upstream_configs_ = config.upstreams;
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

int HttpServer::GetBoundPort() const {
    return net_server_.GetBoundPort();
}

void HttpServer::Stop() {
    logging::Get()->info("HttpServer stopping");

    // Prevent Reload() from mutating dead state after Stop().
    server_ready_.store(false, std::memory_order_release);
    // Mark shutdown started — used by GetStats() to keep reporting uptime
    // during the drain phase (server_ready_ is already false at this point).
    // The release barrier publishes the already-written start_time_.
    shutting_down_started_.store(true, std::memory_order_release);

    // Stop accepting FIRST — prevents new connections from being accepted
    // between the WS snapshot and the H2 drain snapshot. Without this, a WS
    // accepted in the gap would miss the 1001 "Going Away" close frame.
    net_server_.StopAccepting();

    // Upstream pool shutdown — before WS/H2 drain so upstream responses
    // can still flow while dispatchers are running.
    if (upstream_manager_) {
        upstream_manager_->InitiateShutdown();

        auto drain_timeout = std::chrono::seconds(
            shutdown_drain_timeout_sec_.load(std::memory_order_relaxed));

        if (!net_server_.IsOnDispatcherThread()) {
            upstream_manager_->WaitForDrain(drain_timeout);
        } else {
            // Stop-from-handler: poll + pump tasks (same pattern as H2 drain).
            // Limitation: upstream I/O pinned to this dispatcher cannot make
            // progress because we can't return to the event loop while the
            // handler is still on the call stack. Same-dispatcher upstream
            // requests will be force-closed on timeout. This is inherent to
            // stop-from-handler and matches the existing H2 degraded drain.
            logging::Get()->warn("Upstream drain: stop-from-handler, "
                                 "using task pump");
            static constexpr int PUMP_INTERVAL_MS = 200;
            auto deadline = std::chrono::steady_clock::now() + drain_timeout;
            while (std::chrono::steady_clock::now() < deadline) {
                net_server_.ProcessSelfDispatcherTasks();
                if (upstream_manager_->AllDrained()) break;
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(PUMP_INTERVAL_MS));
            }
            upstream_manager_->ForceCloseRemaining();
        }
    }

    // Collect WS connections while holding the lock, then send close frames
    // AFTER releasing. Sending under the lock would deadlock: a failed inline
    // write in DoSendRaw → CallCloseCb → HandleCloseConnection → conn_mtx_.
    std::vector<std::pair<std::shared_ptr<HttpConnectionHandler>,
                          std::shared_ptr<ConnectionHandler>>> ws_conns;
    std::set<ConnectionHandler*> ws_draining;
    {
        std::lock_guard<std::mutex> lck(conn_mtx_);
        for (auto& pair : http_connections_) {
            auto* ws = pair.second->GetWebSocket();
            if (!ws) continue;
            auto conn = pair.second->GetConnection();
            if (ws->IsOpen()) {
                // Active WS — will send close frame below
                ws_conns.emplace_back(pair.second, conn);
                if (conn) ws_draining.insert(conn.get());
            } else if (ws->IsClosing()) {
                // Already in close handshake (sent close, waiting for reply).
                // Must exempt from the generic close sweep so the peer has
                // time to reply before the transport is torn down.
                if (conn) ws_draining.insert(conn.get());
            }
        }
        // Install ws_draining_ INSIDE conn_mtx_ so IsClosing() entries are
        // published atomically with the snapshot. Without this, a peer that
        // finishes the close handshake between lock release and ws_draining_
        // installation would be missed by OnWsDrainComplete (sees empty set),
        // causing shutdown to wait the full 6s timeout on a stale entry.
        if (!ws_draining.empty()) {
            std::lock_guard<std::mutex> dlck(drain_mtx_);
            ws_draining_ = ws_draining;
        }
    }
    // Send 1001 Going Away close frames outside the lock.
    for (auto& [http_conn, conn] : ws_conns) {
        auto* ws = http_conn->GetWebSocket();
        if (ws && ws->IsOpen()) {
            try {
                ws->SendClose(1001, "Going Away");
            }
            catch (...) {}
        }
    }

    // Rescan: catch keep-alive connections that upgraded to WS between the
    // initial snapshot and now. These late upgrades missed the 1001 close
    // frame above. The window is small but real under concurrent traffic.
    {
        std::vector<std::pair<std::shared_ptr<HttpConnectionHandler>,
                              std::shared_ptr<ConnectionHandler>>> late_ws;
        {
            std::lock_guard<std::mutex> lck(conn_mtx_);
            for (auto& pair : http_connections_) {
                auto* ws = pair.second->GetWebSocket();
                if (!ws) continue;
                // Catch both IsOpen (will send close) and IsClosing (already
                // in close handshake — needs drain tracking like the initial
                // snapshot's IsClosing path).
                if (!ws->IsOpen() && !ws->IsClosing()) continue;
                auto conn = pair.second->GetConnection();
                if (!conn || ws_draining.count(conn.get())) continue;
                late_ws.emplace_back(pair.second, conn);
            }
        }
        // Pre-populate drain tracking before sending close frames (same
        // pattern as the initial snapshot — prevents fast-close races).
        {
            std::lock_guard<std::mutex> dlck(drain_mtx_);
            for (auto& [http_conn, conn] : late_ws) {
                if (conn) {
                    ws_draining.insert(conn.get());
                    ws_draining_.insert(conn.get());
                }
            }
        }
        for (auto& [http_conn, conn] : late_ws) {
            auto* ws = http_conn->GetWebSocket();
            if (ws && ws->IsOpen()) {
                try {
                    ws->SendClose(1001, "Going Away");
                } catch (...) {}
            }
        }
    }

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

        // Install drain-complete callback on the dispatcher thread to avoid
        // racing with NotifyDrainComplete (which reads drain_complete_cb_
        // on the dispatcher thread). std::function is not safe for concurrent
        // read/write, so both must happen on the same thread.
        {
            auto h2 = h2_conn;  // copy shared_ptr for the lambda
            conn->RunOnDispatcher([h2, this, conn_ptr]() {
                h2->SetDrainCompleteCallback([this, conn_ptr]() {
                    OnH2DrainComplete(conn_ptr);
                });
            });
        }

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

    // Merge WS draining set into H2 draining set — both are exempt from
    // the generic close sweep in NetServer::Stop().
    draining_conn_ptrs.insert(ws_draining.begin(), ws_draining.end());

    // Note: pending_detection_ connections are NOT exempted from the close
    // sweep. If one becomes H2 late, DetectAndRouteProtocol's late drain
    // path sends GOAWAY via RequestShutdown — the GOAWAY bytes drain through
    // CloseAfterWrite's write path before ForceClose. Exempting all pending
    // connections would leave unclassified/HTTP/1 sockets open with no drain
    // tracking, bypassing shutdown teardown entirely.

    if (!draining_conn_ptrs.empty()) {
        net_server_.SetDrainingConns(std::move(draining_conn_ptrs));
    }

    // H1 drain timeout: gives in-flight HTTP/1 responses time to flush
    // under backpressure before StopEventLoop kills the event loops.
    static constexpr int H1_DRAIN_TIMEOUT_SEC = 2;
    static constexpr int PUMP_INTERVAL_MS = 200;

    if (!net_server_.IsOnDispatcherThread()) {
        bool has_ws = !ws_draining.empty();
        net_server_.SetPreStopDrainCallback([this, has_ws]() {
            WaitForH2Drain();
            if (has_ws) {
                net_server_.SetTimerInterval(1);
                std::unique_lock<std::mutex> lck(drain_mtx_);
                drain_cv_.wait_until(lck,
                    std::chrono::steady_clock::now() +
                        std::chrono::seconds(6),
                    [this]() { return ws_draining_.empty(); });
                // Force-close WS connections that didn't complete handshake.
                // Without this, they stay exempt from the close sweep and
                // only close on shared_ptr destruction, skipping OnClose callbacks.
                if (!ws_draining_.empty()) {
                    logging::Get()->warn("WS drain timeout, force-closing {} "
                                         "remaining connections",
                                         ws_draining_.size());
                    auto remaining = std::move(ws_draining_);
                    ws_draining_.clear();
                    lck.unlock();
                    for (auto* conn_ptr : remaining) {
                        // Look up the connection in http_connections_ to get
                        // the shared_ptr needed for SafeNotifyWsClose + ForceClose.
                        std::shared_ptr<HttpConnectionHandler> http_conn;
                        std::shared_ptr<ConnectionHandler> conn;
                        {
                            std::lock_guard<std::mutex> clck(conn_mtx_);
                            for (auto& [fd, hc] : http_connections_) {
                                auto c = hc->GetConnection();
                                if (c && c.get() == conn_ptr) {
                                    http_conn = hc;
                                    conn = c;
                                    break;
                                }
                            }
                        }
                        SafeNotifyWsClose(http_conn);
                        if (conn) conn->ForceClose();
                    }
                }
            }
            // Wait for HTTP/1 output buffers to drain (max 2s).
            // Without this, large/slow responses are truncated when
            // StopEventLoop kills the event loops.
            {
                auto h1_deadline = std::chrono::steady_clock::now() +
                                   std::chrono::seconds(H1_DRAIN_TIMEOUT_SEC);
                while (std::chrono::steady_clock::now() < h1_deadline) {
                    if (!HasPendingH1Output()) break;
                    std::this_thread::sleep_for(
                        std::chrono::milliseconds(PUMP_INTERVAL_MS));
                }
            }
            // Re-check for late H2 sessions added by DetectAndRouteProtocol
            // during the WS/H1 drain phases above. Without this, a slow
            // h2c connection classified after WaitForH2Drain returned would
            // never get its streams drained.
            {
                std::unique_lock<std::mutex> lck(drain_mtx_);
                if (!h2_draining_.empty()) {
                    lck.unlock();
                    WaitForH2Drain();
                }
            }
        });
    } else {
        // On a dispatcher thread: poll with task pump between waits.
        logging::Get()->warn("HttpServer::Stop() called from dispatcher thread — "
                             "using abbreviated drain");
        bool has_ws = !ws_draining.empty();
        net_server_.SetTimerInterval(1);
        net_server_.SetPreStopDrainCallback([this, has_ws]() {
            // H2 drain: poll with task pump instead of blocking wait.
            {
                auto deadline = std::chrono::steady_clock::now() +
                                std::chrono::seconds(
                                    shutdown_drain_timeout_sec_.load(
                                        std::memory_order_relaxed));
                while (std::chrono::steady_clock::now() < deadline) {
                    net_server_.ProcessSelfDispatcherTasks();
                    std::unique_lock<std::mutex> lck(drain_mtx_);
                    if (h2_draining_.empty()) break;
                    drain_cv_.wait_for(lck,
                        std::chrono::milliseconds(PUMP_INTERVAL_MS));
                }
            }
            // Force-close H2 connections that didn't complete drain.
            {
                std::unique_lock<std::mutex> lck(drain_mtx_);
                if (!h2_draining_.empty()) {
                    logging::Get()->warn(
                        "Dispatcher-thread H2 drain timeout, "
                        "force-closing {} remaining connections",
                        h2_draining_.size());
                    auto remaining = std::move(h2_draining_);
                    h2_draining_.clear();
                    lck.unlock();
                    for (auto& d : remaining) {
                        if (d.conn) d.conn->ForceClose();
                    }
                }
            }
            // WS drain: poll for close completion.
            if (has_ws) {
                auto ws_deadline = std::chrono::steady_clock::now() +
                                   std::chrono::seconds(6);
                while (std::chrono::steady_clock::now() < ws_deadline) {
                    net_server_.ProcessSelfDispatcherTasks();
                    std::unique_lock<std::mutex> lck(drain_mtx_);
                    if (ws_draining_.empty()) break;
                    drain_cv_.wait_for(lck,
                        std::chrono::milliseconds(PUMP_INTERVAL_MS));
                }
                // Force-close remaining WS connections (same as off-thread path).
                std::unique_lock<std::mutex> lck(drain_mtx_);
                if (!ws_draining_.empty()) {
                    logging::Get()->warn(
                        "Dispatcher-thread WS drain timeout, "
                        "force-closing {} remaining connections",
                        ws_draining_.size());
                    auto remaining = std::move(ws_draining_);
                    ws_draining_.clear();
                    lck.unlock();
                    for (auto* conn_ptr : remaining) {
                        std::shared_ptr<HttpConnectionHandler> http_conn;
                        std::shared_ptr<ConnectionHandler> conn;
                        {
                            std::lock_guard<std::mutex> clck(conn_mtx_);
                            for (auto& [fd, hc] : http_connections_) {
                                auto c = hc->GetConnection();
                                if (c && c.get() == conn_ptr) {
                                    http_conn = hc;
                                    conn = c;
                                    break;
                                }
                            }
                        }
                        SafeNotifyWsClose(http_conn);
                        if (conn) conn->ForceClose();
                    }
                }
            }
            // HTTP/1 drain with task pump.
            {
                auto h1_deadline = std::chrono::steady_clock::now() +
                                   std::chrono::seconds(H1_DRAIN_TIMEOUT_SEC);
                while (std::chrono::steady_clock::now() < h1_deadline) {
                    net_server_.ProcessSelfDispatcherTasks();
                    if (!HasPendingH1Output()) break;
                    std::this_thread::sleep_for(
                        std::chrono::milliseconds(PUMP_INTERVAL_MS));
                }
            }
            // Re-check for late H2 sessions (same as off-thread path).
            // Must release drain_mtx_ before ProcessSelfDispatcherTasks:
            // H2 drain callbacks call OnH2DrainComplete which takes drain_mtx_.
            {
                auto deadline = std::chrono::steady_clock::now() +
                                std::chrono::seconds(
                                    shutdown_drain_timeout_sec_.load(
                                        std::memory_order_relaxed));
                bool has_late = false;
                { std::lock_guard<std::mutex> lck(drain_mtx_); has_late = !h2_draining_.empty(); }
                while (has_late && std::chrono::steady_clock::now() < deadline) {
                    net_server_.ProcessSelfDispatcherTasks();
                    std::unique_lock<std::mutex> lck(drain_mtx_);
                    if (h2_draining_.empty()) break;
                    drain_cv_.wait_for(lck, std::chrono::milliseconds(PUMP_INTERVAL_MS));
                    has_late = !h2_draining_.empty();
                }
                // Force-close remaining late H2 sessions.
                std::unique_lock<std::mutex> lck(drain_mtx_);
                if (!h2_draining_.empty()) {
                    logging::Get()->warn(
                        "Late H2 drain timeout, force-closing {} remaining",
                        h2_draining_.size());
                    auto remaining = std::move(h2_draining_);
                    h2_draining_.clear();
                    lck.unlock();
                    for (auto& d : remaining) {
                        if (d.conn) d.conn->ForceClose();
                    }
                }
            }
        });
    }

    net_server_.Stop();

    // Destroy upstream pools AFTER dispatchers are stopped and joined.
    // This ensures no UpstreamLease can call ReturnConnection() after
    // the PoolPartition is freed. Dispatcher threads are dead at this
    // point — all handler code has completed and all leases released.
    upstream_manager_.reset();

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
        ws_draining_.clear();
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

void HttpServer::OnWsDrainComplete(ConnectionHandler* conn_ptr) {
    std::lock_guard<std::mutex> lck(drain_mtx_);
    if (ws_draining_.erase(conn_ptr) > 0 && ws_draining_.empty()) {
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
        logging::Get()->warn("H2 drain timeout, force-closing remaining connections");
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
            // During shutdown, signal the client to close the connection.
            // Without this, a keep-alive response looks persistent but
            // the server closes the socket anyway (protocol violation).
            // The handler's resp_close check recognizes this header and
            // calls CloseConnection() after sending the response.
            if (!server_ready_.load(std::memory_order_acquire)) {
                response.Header("Connection", "close");
            }
        }
    );

    // Middleware runner for WebSocket upgrades (auth, CORS, rate limiting)
    http_conn->SetMiddlewareCallback(
        [this](const HttpRequest& request, HttpResponse& response) -> bool {
            return router_.RunMiddleware(request, response);
        }
    );

    // Route checker: determines if a WebSocket route exists and populates
    // request.params so middleware can read route parameters (e.g., /ws/:room).
    // Called BEFORE middleware in the upgrade flow.
    // Note: no shutdown gate here — returning false would produce a 404 for a
    // valid WS route. The shutdown_check_callback (after handshake validation,
    // before 101) handles shutdown rejection with a proper 503.
    http_conn->SetRouteCheckCallback(
        [this](const HttpRequest& request) -> bool {
            auto handler = router_.GetWebSocketHandler(request);
            return handler != nullptr;
        }
    );

    // Shutdown check: late gate for WS upgrades that slipped past the early
    // route_check (which runs before middleware/handshake/101).
    http_conn->SetShutdownCheckCallback([this]() -> bool {
        return !server_ready_.load(std::memory_order_acquire);
    });

    // Upgrade handler: wires WS callbacks (called exactly once, after ws_conn_ created)
    http_conn->SetUpgradeCallback(
        [this](std::shared_ptr<HttpConnectionHandler> self,
               const HttpRequest& request) {
            // Connection is no longer HTTP/1 — it's now WebSocket.
            // Decrement here so /stats doesn't count WS as HTTP/1.
            // RemoveConnection checks IsUpgraded() to skip the double-decrement.
            active_http1_connections_.fetch_sub(1, std::memory_order_relaxed);
            // total_requests_ already counted by request_count_callback
            auto ws_handler = router_.GetWebSocketHandler(request);
            if (ws_handler && self->GetWebSocket()) {
                self->GetWebSocket()->SetParams(request.params);
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
    if (conn->IsClosing()) {
        logging::Get()->debug("New connection already closing fd={}, skipping", conn->fd());
        return;
    }

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
            // Recheck under lock — peer may have disconnected between the
            // pre-lock check and lock acquisition.
            if (conn->IsClosing()) return;
            auto h2_it = h2_connections_.find(conn->fd());
            if (h2_it != h2_connections_.end()) {
                if (h2_it->second->GetConnection() == conn) {
                    return;  // Already initialized by HandleMessage
                }
                // Stale handler from fd reuse — save for stream compensation,
                // then evict.
                logging::Get()->debug("Evicted stale H2 handler fd={}", conn->fd());
                stale_h2 = h2_it->second;
                h2_connections_.erase(h2_it);
            }
            auto h1_it = http_connections_.find(conn->fd());
            if (h1_it != http_connections_.end()) {
                if (h1_it->second->GetConnection() == conn) {
                    return;  // Already initialized by HandleMessage
                }
                // Stale handler from fd reuse — save for WS close, then evict
                logging::Get()->debug("Evicted stale handler fd={}", conn->fd());
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
            // Increment inside the lock — RemoveConnection holds the same lock
            // when decrementing, so the counter is always >= 0.
            if (new_conn_tracked) {
                total_accepted_.fetch_add(1, std::memory_order_relaxed);
                active_connections_.fetch_add(1, std::memory_order_relaxed);
            }
        }
        // Compensating decrements for evicted stale entries — their close
        // callbacks can no longer find the map entries we just removed.
        if (stale_h2) {
            active_connections_.fetch_sub(1, std::memory_order_relaxed);
            active_http2_connections_.fetch_sub(1, std::memory_order_relaxed);
            CompensateH2Streams(stale_h2);
            // Notify drain set so WaitForH2Drain doesn't block on this dead entry
            OnH2DrainComplete(stale_h2->GetConnection().get());
        }
        if (stale_h1) {
            active_connections_.fetch_sub(1, std::memory_order_relaxed);
            // Only decrement HTTP/1 counter if NOT upgraded — the upgrade
            // callback already decremented at upgrade time.
            if (!stale_h1->IsUpgraded()) {
                active_http1_connections_.fetch_sub(1, std::memory_order_relaxed);
            }
        }
        if (evicted_pd && !stale_h2 && !stale_h1) {
            active_connections_.fetch_sub(1, std::memory_order_relaxed);
        }
        // Notify stale WS handler outside the lock.
        SafeNotifyWsClose(stale_h1);
        if (stale_h1) {
            auto c = stale_h1->GetConnection();
            if (c) OnWsDrainComplete(c.get());
        }
    } else {
        // HTTP/2 disabled — always create HTTP/1.x handler immediately.
        std::shared_ptr<HttpConnectionHandler> old_handler;
        bool already_initialized = false;
        {
            std::lock_guard<std::mutex> lck(conn_mtx_);
            // Guard: if connection already closed (accept/close race),
            // skip insert to avoid leaking a stale handler + counters.
            if (conn->IsClosing()) return;
            auto it = http_connections_.find(conn->fd());
            if (it != http_connections_.end()) {
                if (it->second->GetConnection() == conn) {
                    already_initialized = true;
                } else {
                    old_handler = it->second;
                    auto http_conn = std::make_shared<HttpConnectionHandler>(conn);
                    SetupHandlers(http_conn);
                    http_connections_[conn->fd()] = http_conn;
                    total_accepted_.fetch_add(1, std::memory_order_relaxed);
                    active_connections_.fetch_add(1, std::memory_order_relaxed);
                    active_http1_connections_.fetch_add(1, std::memory_order_relaxed);
                }
            } else {
                auto http_conn = std::make_shared<HttpConnectionHandler>(conn);
                SetupHandlers(http_conn);
                http_connections_[conn->fd()] = http_conn;
                total_accepted_.fetch_add(1, std::memory_order_relaxed);
                active_connections_.fetch_add(1, std::memory_order_relaxed);
                active_http1_connections_.fetch_add(1, std::memory_order_relaxed);
            }
        }
        // Compensating decrement for evicted stale handler (fd reuse)
        if (old_handler) {
            active_connections_.fetch_sub(1, std::memory_order_relaxed);
            if (!old_handler->IsUpgraded()) {
                active_http1_connections_.fetch_sub(1, std::memory_order_relaxed);
            }
        }
        SafeNotifyWsClose(old_handler);
        if (old_handler) {
            auto c = old_handler->GetConnection();
            if (c) OnWsDrainComplete(c.get());
        }
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
        OnH2DrainComplete(evicted_stale_h2->GetConnection().get());
    }

    if (h2_conn) {
        h2_conn->OnRawData(conn, message);
        return;
    }

    if (http_conn) {
        // Guard against fd-reuse: if the handler wraps a stale connection,
        // notify the old WS handler and replace with a fresh one.
        if (http_conn->GetConnection() != conn) {
            bool was_upgraded = http_conn->IsUpgraded();
            SafeNotifyWsClose(http_conn);
            {
                auto c = http_conn->GetConnection();
                if (c) OnWsDrainComplete(c.get());
            }
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
                if (!was_upgraded) {
                    active_http1_connections_.fetch_sub(1, std::memory_order_relaxed);
                }
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
    // Consume buffered data from pending_detection_ but DON'T determine
    // already_counted here — HandleNewConnection can race between our lock
    // release and DetectAndRouteProtocol's lock acquisition, re-inserting
    // the entry. DetectAndRouteProtocol's recheck under its own lock is
    // the authoritative source for already_counted.
    bool already_counted = false;
    {
        bool evicted_stale_pd = false;
        std::lock_guard<std::mutex> lck(conn_mtx_);
        auto pd_it = pending_detection_.find(conn->fd());
        if (pd_it != pending_detection_.end()) {
            if (pd_it->second.conn == conn) {
                // Consume buffered data, erase, and mark counted.
                // DetectAndRouteProtocol rechecks under its own lock —
                // if HandleNewConnection re-inserts between here and there,
                // the recheck correctly handles the new entry.
                pd_it->second.data += message;
                message = std::move(pd_it->second.data);
                already_counted = true;
            } else {
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
                std::lock_guard<std::mutex> lck(conn_mtx_);
                // Don't re-insert a closing connection — HandleMessage erased
                // the pending_detection_ entry before calling us, so
                // RemoveConnection can't find it. Re-inserting would leak
                // the entry + counter permanently.
                if (conn->IsClosing()) {
                    if (already_counted) {
                        active_connections_.fetch_sub(1, std::memory_order_relaxed);
                    }
                    return true;
                }
                auto& pd = pending_detection_[conn->fd()];
                if (pd.conn == conn) {
                    pd.data += message;
                } else {
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
        // If already closing, don't increment new counters. But if this
        // connection was already counted (pending_detection_ entry consumed by
        // HandleMessage), we must undo that count since we won't publish a
        // map entry for RemoveConnection to find.
        if (conn->IsClosing()) {
            logging::Get()->debug("H2 detection skipped, conn already closing fd={}", conn->fd());
            if (already_counted) {
                active_connections_.fetch_sub(1, std::memory_order_relaxed);
            }
            return true;
        }
        logging::Get()->debug("Protocol detected: HTTP/2 fd={}", conn->fd());
        Http2Session::Settings settings_snapshot;
        std::shared_ptr<Http2ConnectionHandler> h2_conn;
        {
            std::lock_guard<std::mutex> lck(conn_mtx_);
            if (conn->IsClosing()) {
                if (already_counted) {
                    active_connections_.fetch_sub(1, std::memory_order_relaxed);
                }
                return true;
            }
            // Re-check: HandleNewConnection may have re-inserted a tracking
            // entry between HandleMessage's consumption and this lock. Always
            // check (not just when !already_counted) because the race can
            // produce a duplicate entry even when we already consumed one.
            {
                auto pd_it = pending_detection_.find(conn->fd());
                if (pd_it != pending_detection_.end() && pd_it->second.conn == conn) {
                    if (!already_counted) {
                        already_counted = true;
                    }
                    // Consume any buffered data from the re-inserted entry
                    if (!pd_it->second.data.empty()) {
                        message = pd_it->second.data + message;
                    }
                    pending_detection_.erase(pd_it);
                    // DON'T increment again — HandleNewConnection already did
                }
            }
            auto h2_existing = h2_connections_.find(conn->fd());
            if (h2_existing != h2_connections_.end() &&
                h2_existing->second->GetConnection() == conn) {
                // HandleNewConnection already set up via a parallel path — skip
                return true;
            }
            if (!already_counted) {
                total_accepted_.fetch_add(1, std::memory_order_relaxed);
                active_connections_.fetch_add(1, std::memory_order_relaxed);
            }
            active_http2_connections_.fetch_add(1, std::memory_order_relaxed);
            settings_snapshot = h2_settings_;
            h2_conn = std::make_shared<Http2ConnectionHandler>(conn, settings_snapshot);
            SetupH2Handlers(h2_conn);
            h2_connections_[conn->fd()] = h2_conn;
        }
        h2_conn->Initialize(message);
        // Late H2 detection during shutdown: full drain bookkeeping so
        // WaitForH2Drain() tracks this session and NetServer::Stop() exempts
        // it from the generic close sweep. RequestShutdown sends GOAWAY AFTER
        // Initialize processes buffered data — requests already in the packet
        // are honored (drained), not refused.
        if (!server_ready_.load(std::memory_order_acquire)) {
            h2_conn->RequestShutdown();
            ConnectionHandler* conn_ptr = conn.get();
            h2_conn->SetDrainCompleteCallback([this, conn_ptr]() {
                OnH2DrainComplete(conn_ptr);
            });
            {
                std::lock_guard<std::mutex> dlck(drain_mtx_);
                h2_draining_.push_back({h2_conn, conn});
            }
            net_server_.AddDrainingConn(conn_ptr);
            h2_conn->RequestShutdown();
            // Re-check: connection may have closed during setup
            if (conn->IsClosing()) {
                OnH2DrainComplete(conn_ptr);
            }
        }
        return true;
    }

    // HTTP/1.x — create handler (existing path)
    if (conn->IsClosing()) {
        logging::Get()->debug("H1 detection skipped, conn already closing fd={}", conn->fd());
        if (already_counted) {
            active_connections_.fetch_sub(1, std::memory_order_relaxed);
        }
        return true;
    }
    logging::Get()->debug("Protocol detected: HTTP/1.x fd={}", conn->fd());
    auto http_conn = std::make_shared<HttpConnectionHandler>(conn);
    SetupHandlers(http_conn);
    std::shared_ptr<HttpConnectionHandler> stale_existing;
    {
        std::lock_guard<std::mutex> lck(conn_mtx_);
        if (conn->IsClosing()) {
            if (already_counted) {
                active_connections_.fetch_sub(1, std::memory_order_relaxed);
            }
            return true;
        }
        // Always recheck — HandleNewConnection can race and re-insert
        {
            auto pd_it = pending_detection_.find(conn->fd());
            if (pd_it != pending_detection_.end() && pd_it->second.conn == conn) {
                if (!already_counted) already_counted = true;
                pending_detection_.erase(pd_it);
            }
        }
        auto h1_existing = http_connections_.find(conn->fd());
        if (h1_existing != http_connections_.end() &&
            h1_existing->second->GetConnection() == conn) {
            // Already published by HandleNewConnection — save to forward
            // bytes after lock release.
            http_conn = h1_existing->second;
        } else {
            // Normal path: create new handler
            if (!already_counted) {
                total_accepted_.fetch_add(1, std::memory_order_relaxed);
                active_connections_.fetch_add(1, std::memory_order_relaxed);
            }
            active_http1_connections_.fetch_add(1, std::memory_order_relaxed);
            // Fd-reuse: stale handler for a different connection
            if (h1_existing != http_connections_.end() &&
                h1_existing->second->GetConnection() != conn) {
                stale_existing = h1_existing->second;
                active_connections_.fetch_sub(1, std::memory_order_relaxed);
                if (!stale_existing->IsUpgraded()) {
                    active_http1_connections_.fetch_sub(1, std::memory_order_relaxed);
                }
            }
            http_connections_[conn->fd()] = http_conn;
        }
    }
    SafeNotifyWsClose(stale_existing);
    if (stale_existing) {
        auto c = stale_existing->GetConnection();
        if (c) OnWsDrainComplete(c.get());
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
    // Count every dispatched H2 request — including those rejected by
    // content-length checks in DispatchStreamRequest. Matches HTTP/1's
    // request_count_callback which fires at HandleCompleteRequest entry.
    h2_conn->SetRequestCountCallback([this]() {
        total_requests_.fetch_add(1, std::memory_order_relaxed);
    });

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
        // Validate H2 sub-settings only when the running server uses H2.
        // When H2 is disabled at startup, Reload() copies sub-settings to
        // h2_settings_ but they're never used (no H2 sessions are created),
        // so invalid placeholder values are harmless and should not block reload.
        validation_copy.http2.enabled = http2_enabled_;
        try {
            ConfigLoader::Validate(validation_copy);
        } catch (const std::invalid_argument& e) {
            logging::Get()->error("Reload() rejected invalid config: {}", e.what());
            return false;
        }
    }

    // Three-phase update to prevent mid-reload connections from seeing
    // inconsistent cap vs limits:
    //   1. Set cap to min(old_cap, new_cap) — safe for both shrink and grow
    //   2. Update per-connection limit atomics
    //   3. Set final cap from new limits
    // A connection accepted during any phase gets a cap that's ≤ what its
    // limits enforce, preventing over-buffering.
    {
        // Compute what the new cap will be from the incoming config
        size_t body = new_config.max_body_size;
        size_t hdr = new_config.max_header_size;
        size_t ws = new_config.max_ws_message_size;
        size_t http_cap = 0;
        if (hdr > 0 && body > 0) {
            size_t sum = hdr + body;
            if (sum >= hdr) http_cap = sum;
        } else if (hdr > 0) {
            http_cap = hdr;
        } else if (body > 0) {
            http_cap = body;
        }
        size_t final_cap = (ws > 0) ? (http_cap == 0 ? ws : std::min(http_cap, ws))
                                    : http_cap;
        // Three-phase update ensures the cap is never larger than what the
        // limits enforce at any point during the transition:
        //   Phase 1: set cap to min(old, new) — tightest constraint
        //   Phase 2: update limit atomics (SetupHandlers reads these)
        //   Phase 3: set final cap (may be larger if limits grew)
        // 0 means unlimited — never use it as the transitional cap.
        size_t old_cap = ComputeInputCap();  // from current atomics
        size_t transition_cap;
        if (old_cap == 0 && final_cap == 0) transition_cap = 0;
        else if (old_cap == 0) transition_cap = final_cap;
        else if (final_cap == 0) transition_cap = old_cap;
        else transition_cap = std::min(old_cap, final_cap);
        net_server_.SetMaxInputSize(transition_cap);
        max_body_size_.store(new_config.max_body_size, std::memory_order_relaxed);
        max_header_size_.store(new_config.max_header_size, std::memory_order_relaxed);
        max_ws_message_size_.store(new_config.max_ws_message_size, std::memory_order_relaxed);
        net_server_.SetMaxInputSize(final_cap);
    }

    // Update the remaining reload-safe fields
    request_timeout_sec_.store(new_config.request_timeout_sec, std::memory_order_relaxed);
    shutdown_drain_timeout_sec_.store(new_config.shutdown_drain_timeout_sec,
                                     std::memory_order_relaxed);
    net_server_.SetMaxConnections(new_config.max_connections);

    // Update idle timeout via EnQueue to dispatcher threads
    net_server_.SetConnectionTimeout(
        std::chrono::seconds(new_config.idle_timeout_sec));

    // Recompute timer scan interval from the new timeout values. Always
    // apply — the old "only shorten" logic permanently ratcheted the
    // interval down, pinning the server to 1s scans for its entire
    // lifetime after a single low-timeout reload. Existing connections
    // with old deadlines may see detection delayed by at most one extra
    // scan cycle when the interval grows, which is acceptable (timeout
    // changes are documented as applying to new connections).
    {
        int new_interval = ComputeTimerInterval(new_config.idle_timeout_sec,
                                                 new_config.request_timeout_sec);
        // Preserve upstream timeout cadence — upstream configs are restart-only,
        // but the timer interval must not widen past the shortest upstream timeout.
        for (const auto& u : upstream_configs_) {
            int connect_sec = std::max(
                (u.pool.connect_timeout_ms + 999) / 1000, 1);
            new_interval = std::min(new_interval, connect_sec);
            if (u.pool.idle_timeout_sec > 0) {
                new_interval = std::min(new_interval, u.pool.idle_timeout_sec);
            }
        }
        net_server_.SetTimerInterval(new_interval);
    }

    // Update HTTP/2 settings for NEW connections only (under conn_mtx_).
    // Existing sessions keep their negotiated SETTINGS values — submitting
    // a new SETTINGS frame to live sessions mid-stream is not supported.
    // Only apply when H2 is currently enabled AND the new config keeps it
    // enabled. If the new config sets http2.enabled=false, that's a
    // restart-required change — all H2 tuning should be deferred to restart
    // so new connections don't observe staged-for-restart settings.
    if (http2_enabled_ && new_config.http2.enabled) {
        std::lock_guard<std::mutex> lck(conn_mtx_);
        h2_settings_.max_concurrent_streams = new_config.http2.max_concurrent_streams;
        h2_settings_.initial_window_size    = new_config.http2.initial_window_size;
        h2_settings_.max_frame_size         = new_config.http2.max_frame_size;
        h2_settings_.max_header_list_size   = new_config.http2.max_header_list_size;
    }

    // Upstream pool changes require a restart — pools are built once in Start()
    // and cannot be rebuilt at runtime without a full drain cycle.
    if (new_config.upstreams != upstream_configs_) {
        logging::Get()->warn("Reload: upstream configuration changes require a "
                             "restart to take effect (ignored)");
    }

    return true;
}

HttpServer::ServerStats HttpServer::GetStats() const {
    ServerStats stats;
    // Use server_ready_ as the publication barrier for start_time_ (which
    // is non-atomic, written by MarkServerReady on the server thread).
    // Also check shutting_down_started_: Stop() clears server_ready_ before
    // the drain phase, but start_time_ is still valid — without this,
    // /stats during graceful shutdown reports uptime 0.
    if (server_ready_.load(std::memory_order_acquire) ||
        shutting_down_started_.load(std::memory_order_acquire)) {
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
