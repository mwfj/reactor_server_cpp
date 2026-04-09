#include "http/http_server.h"
#include "config/config_loader.h"
#include "ws/websocket_frame.h"
#include "http2/http2_constants.h"
#include "upstream/upstream_manager.h"
#include "upstream/proxy_handler.h"
#include "log/logger.h"
#include <algorithm>
#include <set>

// RAII guard: decrements an atomic counter on scope exit. Used in request
// dispatch callbacks to ensure active_requests_ is decremented even on throw.
// Takes the shared_ptr by reference so the guard doesn't extend the atomic's
// lifetime on its own — only the async completion callback needs that.
struct RequestGuard {
    std::shared_ptr<std::atomic<int64_t>>& counter;
    bool armed = true;
    ~RequestGuard() { if (armed) counter->fetch_sub(1, std::memory_order_relaxed); }
    // Disarm so the decrement does NOT fire on scope exit. Used by async
    // routes: the request is logically still in-flight after the handler
    // returns, and active_requests_ must stay elevated until the
    // completion callback fires. The callback path handles the decrement.
    void release() { armed = false; }
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
        if (!conn || conn->IsClosing()) continue;
        // Use atomic flags as a race-free proxy for "output buffer not empty":
        // close_after_write is set by the close sweep, and cleared (via
        // ForceClose → IsClosing) when the buffer drains to zero. Reading
        // OutputBufferSize() directly would be UB (non-atomic std::string
        // read while dispatcher threads write).
        if (conn->IsCloseDeferred()) return true;
        // Deferred async responses (HTTP/1 async routes waiting on upstream
        // or other external work) are exempt from the close sweep. Their
        // completion callbacks still need to run and write their response,
        // so HttpServer::Stop()'s H1 drain loop must stay alive for them
        // too — otherwise the drain exits early, the event loops stop,
        // and the deferred response is silently dropped.
        if (conn->IsShutdownExempt()) return true;
    }
    return false;
}

void HttpServer::MarkServerReady() {
    // Assign dispatcher indices for upstream pool partition affinity
    const auto& dispatchers = net_server_.GetSocketDispatchers();
    for (size_t i = 0; i < dispatchers.size(); ++i) {
        dispatchers[i]->SetDispatcherIndex(static_cast<int>(i));
    }

    // Create upstream pool manager if upstreams are configured.
    // This is fatal: if upstreams are explicitly configured, the server
    // cannot serve proxy traffic without them. On failure, stop the server
    // (dispatchers are already running) and rethrow so the caller sees the
    // error instead of silently starting without upstream pools.
    if (!upstream_configs_.empty()) {
        try {
            upstream_manager_ = std::make_unique<UpstreamManager>(
                upstream_configs_, dispatchers);
        } catch (...) {
            logging::Get()->error("Upstream pool init failed, stopping server");
            net_server_.Stop();
            throw;
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
            // Also consider proxy response timeout — if configured,
            // the timer scan must fire often enough to detect stalled
            // upstream responses within one interval of the deadline.
            if (u.proxy.response_timeout_ms > 0) {
                int response_sec = std::max(
                    (u.proxy.response_timeout_ms + 999) / 1000, 1);
                min_upstream_sec = std::min(min_upstream_sec, response_sec);
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

    // Process deferred Proxy() calls (registered before Start)
    for (const auto& [pattern, name] : pending_proxy_routes_) {
        Proxy(pattern, name);
    }
    pending_proxy_routes_.clear();

    // Auto-register proxy routes from upstream configs
    RegisterProxyRoutes();

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

void HttpServer::GetAsync(const std::string& path, HttpRouter::AsyncHandler handler)    { router_.RouteAsync("GET",    path, std::move(handler)); }
void HttpServer::PostAsync(const std::string& path, HttpRouter::AsyncHandler handler)   { router_.RouteAsync("POST",   path, std::move(handler)); }
void HttpServer::PutAsync(const std::string& path, HttpRouter::AsyncHandler handler)    { router_.RouteAsync("PUT",    path, std::move(handler)); }
void HttpServer::DeleteAsync(const std::string& path, HttpRouter::AsyncHandler handler) { router_.RouteAsync("DELETE", path, std::move(handler)); }
void HttpServer::RouteAsync(const std::string& method, const std::string& path, HttpRouter::AsyncHandler handler) { router_.RouteAsync(method, path, std::move(handler)); }

void HttpServer::Proxy(const std::string& route_pattern,
                       const std::string& upstream_service_name) {
    // Reject empty route patterns — calling .back() on an empty string is UB,
    // and an empty pattern is never a valid route.
    if (route_pattern.empty()) {
        logging::Get()->error("Proxy: route_pattern must not be empty "
                              "(upstream '{}')", upstream_service_name);
        return;
    }

    // Validate that the upstream service exists in config (can check eagerly)
    const UpstreamConfig* found = nullptr;
    for (const auto& u : upstream_configs_) {
        if (u.name == upstream_service_name) {
            found = &u;
            break;
        }
    }
    if (!found) {
        logging::Get()->error("Proxy: upstream service '{}' not configured",
                              upstream_service_name);
        return;
    }

    // Validate proxy config eagerly — fail fast for code-registered routes
    // that bypass config_loader validation (which only runs for JSON-loaded
    // configs with non-empty route_prefix).
    if (found->proxy.response_timeout_ms < 1000) {
        logging::Get()->error("Proxy: upstream '{}' has invalid "
                              "response_timeout_ms={} (must be >= 1000, "
                              "timer scan resolution is 1s)",
                              upstream_service_name,
                              found->proxy.response_timeout_ms);
        return;
    }
    if (found->proxy.retry.max_retries < 0 ||
        found->proxy.retry.max_retries > 10) {
        logging::Get()->error("Proxy: upstream '{}' has invalid "
                              "max_retries={} (must be 0-10)",
                              upstream_service_name,
                              found->proxy.retry.max_retries);
        return;
    }
    // Validate methods — reject unknowns and duplicates (same as config_loader).
    // Without this, duplicates crash RouteAsync and unknowns bypass validation.
    {
        static const std::unordered_set<std::string> valid_methods = {
            "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"
        };
        std::unordered_set<std::string> seen;
        for (const auto& m : found->proxy.methods) {
            if (valid_methods.find(m) == valid_methods.end()) {
                logging::Get()->error("Proxy: upstream '{}' has invalid "
                                      "method '{}'", upstream_service_name, m);
                return;
            }
            if (!seen.insert(m).second) {
                logging::Get()->error("Proxy: upstream '{}' has duplicate "
                                      "method '{}'", upstream_service_name, m);
                return;
            }
        }
    }

    if (!upstream_manager_) {
        // Pre-Start or MarkServerReady hasn't run yet: defer registration.
        // Routes are registered before the server accepts connections,
        // so there's no race with live route lookups.
        pending_proxy_routes_.emplace_back(route_pattern, upstream_service_name);
        logging::Get()->debug("Proxy: deferred registration {} -> {} "
                              "(upstream manager not yet initialized)",
                              route_pattern, upstream_service_name);
        return;
    }

    // Reject registration once the server is live (accepting connections).
    // RouteTrie is not thread-safe for concurrent insert + lookup. Routes
    // must be registered before accept starts (MarkServerReady time is safe
    // because server_ready_ is set AFTER route registration completes).
    if (server_ready_.load(std::memory_order_acquire)) {
        logging::Get()->error("Proxy: cannot register routes after server "
                              "is live (route_pattern='{}', upstream='{}'). "
                              "Call Proxy() before Start().",
                              route_pattern, upstream_service_name);
        return;
    }

    // Detect whether the pattern already contains a catch-all segment.
    // RouteTrie only treats '*' as special at segment start (immediately
    // after '/'), so mid-segment '*' like /file*name is literal.
    bool has_catch_all = false;
    {
        for (size_t i = 0; i < route_pattern.size(); ++i) {
            if (route_pattern[i] == '*' &&
                (i == 0 || route_pattern[i - 1] == '/')) {
                has_catch_all = true;
                break;
            }
        }
    }

    // If no catch-all, build the full route_prefix that includes the
    // auto-generated "*proxy_path" so ProxyHandler knows the param name.
    std::string config_prefix = route_pattern;
    if (!has_catch_all) {
        std::string catch_all_pattern = route_pattern;
        if (catch_all_pattern.back() != '/') {
            catch_all_pattern += '/';
        }
        catch_all_pattern += "*proxy_path";
        config_prefix = catch_all_pattern;
    }

    // Duplicate guard: key on {upstream, static_prefix} — the prefix up to
    // the catch-all segment. This catches both exact duplicates AND
    // equivalent patterns with different catch-all param names (e.g.,
    // "/api" + auto-generated "/api/*proxy_path" vs explicit "/api/*rest").
    // Strip the catch-all param name: "/api/*proxy_path" → "/api/*",
    // "/api/*rest" → "/api/*". Patterns without catch-all use as-is.
    std::string dedup_prefix = config_prefix;
    {
        auto star_pos = dedup_prefix.rfind('*');
        if (star_pos != std::string::npos) {
            dedup_prefix = dedup_prefix.substr(0, star_pos + 1);  // keep the '*'
        }
    }
    std::string handler_key = upstream_service_name + "\t" + dedup_prefix;

    ProxyConfig handler_config = found->proxy;
    handler_config.route_prefix = config_prefix;
    auto handler = std::make_unique<ProxyHandler>(
        upstream_service_name,
        handler_config,
        found->tls.enabled,
        found->host,
        found->port,
        found->tls.sni_hostname,
        upstream_manager_.get());

    ProxyHandler* handler_ptr = handler.get();

    // Determine methods to register. When GET is present, always include
    // HEAD so HEAD requests are forwarded as HEAD to the upstream instead
    // of falling through to the async GET fallback (which rewrites the
    // method to GET and forces the upstream to generate a full body).
    static const std::vector<std::string> DEFAULT_PROXY_METHODS =
        {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"};
    std::vector<std::string> effective_methods;
    if (found->proxy.methods.empty()) {
        effective_methods = DEFAULT_PROXY_METHODS;
    } else {
        effective_methods = found->proxy.methods;
        bool has_get = false, has_head = false;
        for (const auto& m : effective_methods) {
            if (m == "GET") has_get = true;
            if (m == "HEAD") has_head = true;
        }
        if (has_get && !has_head) {
            effective_methods.push_back("HEAD");
        }
    }
    const auto& methods = effective_methods;

    // Method-level conflict check BEFORE storing the handler. Storing first
    // would destroy any existing handler under the same key via operator=,
    // leaving its routes' raw handler_ptr dangling.
    auto& registered = proxy_route_methods_[dedup_prefix];
    for (const auto& m : methods) {
        if (registered.count(m)) {
            logging::Get()->error("Proxy: method {} on path '{}' already "
                                  "registered (upstream '{}')",
                                  m, dedup_prefix, upstream_service_name);
            return;
        }
    }

    // Conflict check passed — now store in stable ownership BEFORE
    // registering routes. If RouteAsync throws, the handler survives so
    // any partially-inserted route lambdas don't hold dangling pointers.
    proxy_handlers_[handler_key] = std::move(handler);
    for (const auto& m : methods) {
        registered.insert(m);
    }

    auto register_route = [&](const std::string& pattern) {
        for (const auto& method : methods) {
            router_.RouteAsync(method, pattern,
                [handler_ptr](const HttpRequest& request,
                              HTTP_CALLBACKS_NAMESPACE::AsyncCompletionCallback complete) {
                    handler_ptr->Handle(request, std::move(complete));
                });
        }
        logging::Get()->info("Proxy route registered: {} -> {} ({}:{})",
                             pattern, upstream_service_name,
                             found->host, found->port);
    };

    // Register exact prefix + catch-all variant (same as RegisterProxyRoutes).
    // Both auto-generated and explicit catch-all routes need a companion
    // exact-prefix registration so bare paths (e.g., /api/v1 without
    // trailing slash) don't 404.
    if (!has_catch_all) {
        register_route(route_pattern);       // exact prefix
        register_route(config_prefix);       // auto-generated catch-all
    } else {
        // Explicit catch-all: extract the prefix before the catch-all
        // segment and register it as the exact-match companion.
        auto star_pos = route_pattern.rfind('*');
        if (star_pos != std::string::npos) {
            std::string exact_prefix = route_pattern.substr(0, star_pos);
            // Remove trailing slash left by the catch-all separator
            while (exact_prefix.size() > 1 && exact_prefix.back() == '/') {
                exact_prefix.pop_back();
            }
            if (!exact_prefix.empty()) {
                register_route(exact_prefix);
            }
        }
        register_route(route_pattern);       // user-provided catch-all
    }
}

void HttpServer::RegisterProxyRoutes() {
    if (!upstream_manager_) {
        return;
    }

    for (const auto& upstream : upstream_configs_) {
        if (upstream.proxy.route_prefix.empty()) {
            continue;  // No proxy config for this upstream
        }

        // Check if the route_prefix already has a catch-all segment.
        // Same segment-start rule as RouteTrie (only after '/').
        std::string route_pattern = upstream.proxy.route_prefix;
        bool has_catch_all = false;
        for (size_t i = 0; i < route_pattern.size(); ++i) {
            if (route_pattern[i] == '*' &&
                (i == 0 || route_pattern[i - 1] == '/')) {
                has_catch_all = true;
                break;
            }
        }

        // Build effective route_prefix that includes the catch-all segment
        // so ProxyHandler can extract the catch-all param name.
        std::string config_prefix = route_pattern;
        if (!has_catch_all) {
            if (config_prefix.back() != '/') {
                config_prefix += '/';
            }
            config_prefix += "*proxy_path";
        }

        // Same canonicalized duplicate guard as Proxy() — see comment there.
        std::string dedup_prefix = config_prefix;
        {
            auto sp = dedup_prefix.rfind('*');
            if (sp != std::string::npos) {
                dedup_prefix = dedup_prefix.substr(0, sp + 1);
            }
        }
        std::string handler_key = upstream.name + "\t" + dedup_prefix;

        // Create ProxyHandler with the full catch-all-aware route_prefix.
        ProxyConfig handler_config = upstream.proxy;
        handler_config.route_prefix = config_prefix;
        auto handler = std::make_unique<ProxyHandler>(
            upstream.name,
            handler_config,
            upstream.tls.enabled,
            upstream.host,
            upstream.port,
            upstream.tls.sni_hostname,
            upstream_manager_.get());
        ProxyHandler* handler_ptr = handler.get();

        // Same HEAD auto-registration as Proxy()
        static const std::vector<std::string> DEFAULT_PROXY_METHODS =
            {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"};
        std::vector<std::string> effective_methods;
        if (upstream.proxy.methods.empty()) {
            effective_methods = DEFAULT_PROXY_METHODS;
        } else {
            effective_methods = upstream.proxy.methods;
            bool has_get = false, has_head = false;
            for (const auto& m : effective_methods) {
                if (m == "GET") has_get = true;
                if (m == "HEAD") has_head = true;
            }
            if (has_get && !has_head) {
                effective_methods.push_back("HEAD");
            }
        }
        const auto& methods = effective_methods;

        // Method-level conflict check BEFORE storing (same as Proxy())
        auto& registered = proxy_route_methods_[dedup_prefix];
        bool conflict = false;
        for (const auto& m : methods) {
            if (registered.count(m)) {
                logging::Get()->warn("RegisterProxyRoutes: method {} on '{}' "
                                     "already registered, skipping upstream '{}'",
                                     m, dedup_prefix, upstream.name);
                conflict = true;
                break;
            }
        }
        if (conflict) continue;

        // Conflict check passed — store handler, then register routes
        proxy_handlers_[handler_key] = std::move(handler);
        for (const auto& m : methods) {
            registered.insert(m);
        }

        auto register_route = [&](const std::string& pattern) {
            for (const auto& method : methods) {
                router_.RouteAsync(method, pattern,
                    [handler_ptr](const HttpRequest& request,
                                  HTTP_CALLBACKS_NAMESPACE::AsyncCompletionCallback complete) {
                        handler_ptr->Handle(request, std::move(complete));
                    });
            }
            logging::Get()->info("Proxy route registered: {} -> {} ({}:{})",
                                 pattern, upstream.name,
                                 upstream.host, upstream.port);
        };

        if (!has_catch_all) {
            // Register the exact prefix to handle requests that match it
            // without a trailing path (e.g., /api/users).
            register_route(upstream.proxy.route_prefix);
        } else {
            // Explicit catch-all: register exact-prefix companion so bare
            // paths (e.g., /api/v1) don't 404 (same as Proxy()).
            auto sp = upstream.proxy.route_prefix.rfind('*');
            if (sp != std::string::npos) {
                std::string exact_prefix =
                    upstream.proxy.route_prefix.substr(0, sp);
                while (exact_prefix.size() > 1 && exact_prefix.back() == '/') {
                    exact_prefix.pop_back();
                }
                if (!exact_prefix.empty()) {
                    register_route(exact_prefix);
                }
            }
        }
        // Register the catch-all variant (auto-generated or user-provided)
        register_route(config_prefix);
    }
}

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

    // NOTE: upstream_manager_->InitiateShutdown() is NOT called here.
    // It is deferred to pre_stop_drain_cb (after H2/WS/H1 protocol drain)
    // so that proxy handlers dispatched during the drain window can still
    // call CheckoutAsync() successfully. Calling InitiateShutdown too early
    // would reject checkouts from already-accepted requests that only reach
    // their upstream call late in the drain phase.
    //
    // HTTP/1 proxy handlers with no buffered client response at the time of
    // the close sweep are protected by opting in via
    // HttpConnectionHandler::SetShutdownExempt(true). The scan below (after
    // the WS/H2 draining set is assembled) adds those connections to
    // draining_conn_ptrs, exempting them from the CloseAfterWrite sweep until
    // the handler sets the flag back to false (typically right before the
    // final SendResponse).

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

    // HTTP/1 async handlers (proxy / deferred responses) mark their transport
    // exempt via ConnectionHandler::SetShutdownExempt, which NetServer's
    // sweep live-checks per iteration. A pre-sweep snapshot here would be
    // UNSAFE: a request that enters its async handler after the snapshot
    // but before the sweep would be dropped by CloseAfterWrite on an empty
    // output buffer. The live check closes that race.

    // Note: pending_detection_ connections are NOT exempted from the close
    // sweep here. If one becomes H2 late, DetectAndRouteProtocol's late
    // drain path clears the pre-armed CloseAfterWrite and sets shutdown-
    // exempt to block the stale lambda, then hands the connection to the
    // H2 drain mechanism. Exempting all pending connections upfront would
    // leave unclassified/HTTP/1 sockets open with no drain tracking.

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
            // Upstream shutdown — deferred until AFTER H2/WS/H1 protocol
            // drains so proxy handlers dispatched during the drain window
            // can still call CheckoutAsync() successfully. Initiating here
            // sets the reject-new-checkouts flag, then WaitForDrain waits
            // for in-flight leases to complete.
            if (upstream_manager_) {
                upstream_manager_->InitiateShutdown();
                upstream_manager_->WaitForDrain(
                    std::chrono::seconds(shutdown_drain_timeout_sec_.load(
                        std::memory_order_relaxed)));
            }
            // Post-upstream H1 flush window: an async (exempt) HTTP/1 handler
            // whose completion fires during the upstream drain (or that takes
            // longer than the first H1 drain loop) only starts writing its
            // client response after the earlier H1 drain has finished. Use
            // the operator-configured shutdown_drain_timeout_sec_ instead of
            // the hard-coded H1_DRAIN_TIMEOUT_SEC: any async H1 route that
            // doesn't go through UpstreamManager (or simply takes longer than
            // 2s before it starts writing) would otherwise be cut off when
            // StopEventLoop runs.
            {
                auto h1_deadline = std::chrono::steady_clock::now() +
                    std::chrono::seconds(shutdown_drain_timeout_sec_.load(
                        std::memory_order_relaxed));
                while (std::chrono::steady_clock::now() < h1_deadline) {
                    if (!HasPendingH1Output()) break;
                    std::this_thread::sleep_for(
                        std::chrono::milliseconds(PUMP_INTERVAL_MS));
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
            // Upstream drain — initiate AFTER protocol drains so late
            // proxy handlers can still check out. Then poll with task pump
            // until leases are returned, and force-close stragglers.
            // Followed by a second H1 flush window so async proxy
            // responses that arrive DURING the upstream drain still have
            // time to write their client bytes before the event loop stops.
            if (upstream_manager_) {
                upstream_manager_->InitiateShutdown();
                static constexpr int UP_PUMP_MS = 200;
                auto up_deadline = std::chrono::steady_clock::now() +
                    std::chrono::seconds(shutdown_drain_timeout_sec_.load(
                        std::memory_order_relaxed));
                while (std::chrono::steady_clock::now() < up_deadline) {
                    net_server_.ProcessSelfDispatcherTasks();
                    if (upstream_manager_->AllDrained()) break;
                    std::this_thread::sleep_for(
                        std::chrono::milliseconds(UP_PUMP_MS));
                }
                upstream_manager_->ForceCloseRemaining();
            }
            // Post-upstream H1 flush window: use the configured drain budget
            // so async H1 routes that take longer than 2s aren't cut off.
            {
                auto h1_deadline = std::chrono::steady_clock::now() +
                    std::chrono::seconds(shutdown_drain_timeout_sec_.load(
                        std::memory_order_relaxed));
                while (std::chrono::steady_clock::now() < h1_deadline) {
                    net_server_.ProcessSelfDispatcherTasks();
                    if (!HasPendingH1Output()) break;
                    std::this_thread::sleep_for(
                        std::chrono::milliseconds(PUMP_INTERVAL_MS));
                }
            }
        });
    }

    // Upstream shutdown is handled inside pre_stop_drain_cb (below),
    // which runs AFTER H2 stream drain, WS close handshake, and H1 flush.
    // This ensures in-flight proxy requests from all protocol paths complete
    // before upstream checkouts are rejected.

    net_server_.Stop();

    // Do NOT reset upstream_manager_ here. In the stop-from-handler case,
    // the calling handler is still on the stack and may hold an UpstreamLease
    // that destructs when the handler unwinds. upstream_manager_ must outlive
    // all handler stack frames. It is destroyed naturally by ~HttpServer()
    // after Stop() returns and all stack frames have unwound.

    {
        std::lock_guard<std::mutex> lck(conn_mtx_);
        http_connections_.clear();
        h2_connections_.clear();
        pending_detection_.clear();
    }
    // Clear proxy handlers after upstream shutdown. ProxyHandlers hold raw
    // UpstreamManager* pointers, but upstream_manager_ is still alive here
    // (destroyed in ~HttpServer). Clearing here prevents any stale route
    // callback from reaching a proxy handler after Stop().
    proxy_handlers_.clear();
    proxy_route_methods_.clear();

    // Clear one-shot drain state (Stop may be called from destructor too)
    {
        std::lock_guard<std::mutex> dlck(drain_mtx_);
        h2_draining_.clear();
        ws_draining_.clear();
    }
    // Clear shutdown flag so GetStats() stops reporting uptime.
    // Without this, uptime keeps increasing after Stop() completes.
    shutting_down_started_.store(false, std::memory_order_release);
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
            active_requests_->fetch_add(1, std::memory_order_relaxed);
            RequestGuard guard{active_requests_};

            // Async routes take precedence over sync routes for the same
            // path. The framework dispatches async handlers as follows:
            //   1. Run middleware (auth, CORS, rate limiting). If it
            //      rejects, fall through to the sync send path with the
            //      rejection response — NEVER invoke the async handler.
            //   2. Otherwise, call BeginAsyncResponse to save request
            //      context + block the parser + mark shutdown-exempt, mark
            //      the response deferred (so HandleCompleteRequest skips
            //      auto-send), and invoke the user handler with a
            //      protocol-agnostic completion callback.
            //   3. The user invokes complete(final_response); the captured
            //      weak_ptr re-locks the handler and CompleteAsyncResponse
            //      performs normalization, sends the bytes, and either
            //      closes or resumes parsing pipelined data.
            bool async_head_fallback = false;
            auto async_handler = router_.GetAsyncHandler(
                request, &async_head_fallback);
            if (async_handler) {
                bool mw_ok = router_.RunMiddleware(request, response);
                if (!mw_ok) {
                    HttpRouter::FillDefaultRejectionResponse(response);
                    if (!server_ready_.load(std::memory_order_acquire)) {
                        response.Header("Connection", "close");
                    }
                    return;  // Sync send path below runs auto-send
                }

                // BeginAsyncResponse must see the ORIGINAL request so
                // deferred_was_head_ captures the real client method —
                // CompleteAsyncResponse uses it to strip the body at send
                // time (RFC 7231 §4.3.2), mirroring the sync HEAD path.
                response.Defer();
                self->BeginAsyncResponse(request);

                // Capture middleware-stamped headers (CORS, trace IDs,
                // cookies) so the completion callback can merge them into
                // the user's final response. Rejected requests already keep
                // these headers (the sync send path serializes `response`),
                // but successful async completions build a new HttpResponse
                // from scratch and would lose them without this capture.
                auto mw_headers = response.GetHeaders();

                std::weak_ptr<HttpConnectionHandler> weak_self = self;
                auto active_counter = active_requests_;
                // Two guards for the complete-then-throw edge case:
                //   completed: one-shot entry — prevents duplicate callback
                //              invocations (handler calls complete twice).
                //   cancelled: set by the catch block — prevents the INNER
                //              RunOnDispatcher lambda from running after the
                //              outer catch already sent a 500. Without this,
                //              a handler that calls complete() synchronously
                //              and then throws would double-finish: the
                //              enqueued lambda runs CompleteAsyncResponse +
                //              decrements, and the guard also decrements.
                auto completed = std::make_shared<std::atomic<bool>>(false);
                auto cancelled = std::make_shared<std::atomic<bool>>(false);
                HttpRouter::AsyncCompletionCallback complete =
                    [weak_self, active_counter,
                     mw_headers, completed, cancelled](HttpResponse final_resp) {
                        auto is_repeatable_header = [](const std::string& name) {
                            std::string lower = name;
                            std::transform(
                                lower.begin(), lower.end(), lower.begin(),
                                [](unsigned char c) { return std::tolower(c); });
                            return lower == "set-cookie" ||
                                   lower == "www-authenticate";
                        };
                        if (completed->exchange(true)) return;
                        // Merge middleware + handler headers: middleware
                        // first (base), handler second (overrides for
                        // non-repeatable, appends for repeatable).
                        HttpResponse merged;
                        merged.Status(final_resp.GetStatusCode(),
                                      final_resp.GetStatusReason());
                        merged.Body(final_resp.GetBody());
                        // Preserve proxy HEAD Content-Length flag across merge
                        if (final_resp.IsContentLengthPreserved()) {
                            merged.PreserveContentLength();
                        }
                        std::set<std::string> final_non_repeatable;
                        for (const auto& fh : final_resp.GetHeaders()) {
                            if (!is_repeatable_header(fh.first)) {
                                std::string lower = fh.first;
                                std::transform(
                                    lower.begin(), lower.end(), lower.begin(),
                                    [](unsigned char c) { return std::tolower(c); });
                                final_non_repeatable.insert(std::move(lower));
                            }
                        }
                        for (const auto& mh : mw_headers) {
                            std::string lower = mh.first;
                            std::transform(
                                lower.begin(), lower.end(), lower.begin(),
                                [](unsigned char c) { return std::tolower(c); });
                            if (!is_repeatable_header(mh.first) &&
                                final_non_repeatable.count(lower)) {
                                continue;
                            }
                            merged.AppendHeader(mh.first, mh.second);
                        }
                        for (const auto& fh : final_resp.GetHeaders()) {
                            merged.AppendHeader(fh.first, fh.second);
                        }
                        auto s = weak_self.lock();
                        if (!s) {
                            active_counter->fetch_sub(1, std::memory_order_relaxed);
                            return;
                        }
                        auto conn = s->GetConnection();
                        if (!conn) {
                            active_counter->fetch_sub(1, std::memory_order_relaxed);
                            return;
                        }
                        auto shared_resp = std::make_shared<HttpResponse>(
                            std::move(merged));
                        conn->RunOnDispatcher(
                            [s, shared_resp, active_counter, cancelled]() {
                            if (cancelled->load(std::memory_order_acquire)) return;
                            s->CompleteAsyncResponse(std::move(*shared_resp));
                            active_counter->fetch_sub(1, std::memory_order_relaxed);
                        });
                    };

                // Don't release the guard until the handler returns
                // successfully. If the handler throws, the guard fires
                // during stack unwinding and decrements active_requests_.
                // The inner catch clears deferred state before rethrowing
                // so the outer catch in HandleCompleteRequest can send a
                // 500 and close normally (CloseAfterWrite won't be blocked
                // by shutdown_exempt_, and OnRawData won't buffer into
                // the deferred stash).
                try {
                    if (async_head_fallback) {
                        HttpRequest get_req = request;
                        get_req.method = "GET";
                        async_handler(get_req, std::move(complete));
                    } else {
                        async_handler(request, std::move(complete));
                    }
                } catch (...) {
                    // Mark both flags: completed stops a stored callback
                    // from re-entering; cancelled stops any already-queued
                    // RunOnDispatcher lambda from running (handles the
                    // complete-then-throw case). CancelAsyncResponse clears
                    // deferred state so the outer catch's 500 + close works.
                    completed->store(true, std::memory_order_relaxed);
                    cancelled->store(true, std::memory_order_release);
                    self->CancelAsyncResponse();
                    throw;  // outer catch sends 500 + closes
                }
                // Handler returned without throwing — it owns the
                // completion callback and is responsible for invoking it.
                // Disarm the guard so the callback handles the decrement.
                guard.release();
                return;
            }

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
        // Late H2 detection during shutdown: clear any pre-armed close flag
        // BEFORE Initialize — Initialize sends the server preface and may
        // dispatch/send the buffered request, whose DoSendRaw/CallWriteCb
        // would honor the stale close_after_write_ and ForceClose on the
        // first empty-buffer moment, truncating the request this drain path
        // is trying to preserve.
        if (!server_ready_.load(std::memory_order_acquire)) {
            conn->ClearCloseAfterWrite();
            conn->SetShutdownExempt(true);
        }
        h2_conn->Initialize(message);
        // Late H2 detection during shutdown: full drain bookkeeping so
        // WaitForH2Drain() tracks this session and NetServer::Stop() exempts
        // it from the generic close sweep. RequestShutdown sends GOAWAY AFTER
        // Initialize processes buffered data — requests already in the packet
        // are honored (drained), not refused.
        if (!server_ready_.load(std::memory_order_acquire)) {
            ConnectionHandler* conn_ptr = conn.get();
            std::weak_ptr<ConnectionHandler> conn_weak = conn;
            h2_conn->SetDrainCompleteCallback([this, conn_ptr, conn_weak]() {
                // Clear exemption before NotifyDrainComplete's CloseAfterWrite
                // fires — it was only needed to block the stale pre-armed lambda.
                if (auto c = conn_weak.lock()) {
                    c->SetShutdownExempt(false);
                }
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
        [this](std::shared_ptr<Http2ConnectionHandler> self,
               int32_t stream_id,
               const HttpRequest& request,
               HttpResponse& response) {
            active_requests_->fetch_add(1, std::memory_order_relaxed);
            RequestGuard guard{active_requests_};

            // Async route dispatch — mirrors the HTTP/1 path. Middleware
            // runs first (auth, CORS, rate limiting) and can reject before
            // we invoke the async handler. On success we mark the response
            // deferred (Http2Session::OnRequest returns early on IsDeferred)
            // and hand the user a completion callback that captures
            // stream_id + a weak_ptr to the H2 connection handler. H2's
            // graceful-shutdown drain already waits on open streams, so
            // the async operation is naturally protected during shutdown
            // without needing shutdown_exempt_ bookkeeping.
            bool async_head_fallback = false;
            auto async_handler = router_.GetAsyncHandler(
                request, &async_head_fallback);
            if (async_handler) {
                if (!router_.RunMiddleware(request, response)) {
                    HttpRouter::FillDefaultRejectionResponse(response);
                    return;
                }
                response.Defer();

                auto mw_headers = response.GetHeaders();
                std::weak_ptr<Http2ConnectionHandler> weak_self = self;
                auto active_counter = active_requests_;
                // Guard against double-submit: if the handler stores the
                // callback and then throws, the outer catch in OnRequest
                // synthesizes a 500 on the same stream. Without this flag,
                // the stored callback fires later → double submit + double
                // decrement of active_requests_. The catch path below
                // marks `completed` so the callback becomes a no-op.
                auto completed = std::make_shared<std::atomic<bool>>(false);
                auto cancelled = std::make_shared<std::atomic<bool>>(false);
                HttpRouter::AsyncCompletionCallback complete =
                    [weak_self, stream_id, active_counter,
                     mw_headers, completed, cancelled](HttpResponse final_resp) {
                        auto is_repeatable_header = [](const std::string& name) {
                            std::string lower = name;
                            std::transform(
                                lower.begin(), lower.end(), lower.begin(),
                                [](unsigned char c) { return std::tolower(c); });
                            return lower == "set-cookie" ||
                                   lower == "www-authenticate";
                        };
                        if (completed->exchange(true)) return;
                        // Same merge as H1: middleware first, handler second.
                        // Use AppendHeader to preserve repeated upstream
                        // headers (Cache-Control, Link, Via, etc.).
                        HttpResponse merged;
                        merged.Status(final_resp.GetStatusCode(),
                                      final_resp.GetStatusReason());
                        merged.Body(final_resp.GetBody());
                        if (final_resp.IsContentLengthPreserved()) {
                            merged.PreserveContentLength();
                        }
                        std::set<std::string> final_non_repeatable;
                        for (const auto& fh : final_resp.GetHeaders()) {
                            if (!is_repeatable_header(fh.first)) {
                                std::string lower = fh.first;
                                std::transform(
                                    lower.begin(), lower.end(), lower.begin(),
                                    [](unsigned char c) { return std::tolower(c); });
                                final_non_repeatable.insert(std::move(lower));
                            }
                        }
                        for (const auto& mh : mw_headers) {
                            std::string lower = mh.first;
                            std::transform(
                                lower.begin(), lower.end(), lower.begin(),
                                [](unsigned char c) { return std::tolower(c); });
                            if (!is_repeatable_header(mh.first) &&
                                final_non_repeatable.count(lower)) {
                                continue;
                            }
                            merged.AppendHeader(mh.first, mh.second);
                        }
                        for (const auto& fh : final_resp.GetHeaders()) {
                            merged.AppendHeader(fh.first, fh.second);
                        }
                        auto s = weak_self.lock();
                        if (!s) {
                            active_counter->fetch_sub(1, std::memory_order_relaxed);
                            return;
                        }
                        auto conn = s->GetConnection();
                        if (!conn) {
                            active_counter->fetch_sub(1, std::memory_order_relaxed);
                            return;
                        }
                        auto shared_resp = std::make_shared<HttpResponse>(
                            std::move(merged));
                        conn->RunOnDispatcher(
                            [s, stream_id, shared_resp, active_counter, cancelled]() {
                            if (cancelled->load(std::memory_order_acquire)) return;
                            s->SubmitStreamResponse(stream_id, *shared_resp);
                            active_counter->fetch_sub(1, std::memory_order_relaxed);
                        });
                    };

                try {
                    if (async_head_fallback) {
                        HttpRequest get_req = request;
                        get_req.method = "GET";
                        async_handler(get_req, std::move(complete));
                    } else {
                        async_handler(request, std::move(complete));
                    }
                } catch (...) {
                    completed->store(true, std::memory_order_relaxed);
                    cancelled->store(true, std::memory_order_release);
                    throw;
                }
                guard.release();
                return;
            }

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

HttpServer::ConnectionSnapshot HttpServer::SnapshotConnections() {
    ConnectionSnapshot snap;
    std::lock_guard<std::mutex> lck(conn_mtx_);
    snap.h1.reserve(http_connections_.size());
    for (auto& [fd, hconn] : http_connections_) {
        snap.h1.push_back(hconn);
    }
    snap.h2.reserve(h2_connections_.size());
    for (auto& [fd, h2conn] : h2_connections_) {
        snap.h2.push_back(h2conn);
    }
    snap.pending.reserve(pending_detection_.size());
    for (auto& [fd, pd] : pending_detection_) {
        snap.pending.push_back(pd.conn);
    }
    return snap;
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
        // Validate H2 sub-settings only when the running server currently
        // has H2 enabled AND the new config keeps it enabled. Two cases
        // skip validation:
        //   1. H2 disabled at startup (http2_enabled_=false): sub-settings
        //      are never used, so placeholders are harmless.
        //   2. H2 currently enabled but new config stages a disable
        //      (new_config.http2.enabled=false): http2.enabled is restart-
        //      only, so the disable won't take effect until restart. The
        //      operator may be staging the disable alongside placeholder
        //      H2 tuning; rejecting the reload would block live-safe
        //      field changes (timeouts, limits, log level).
        validation_copy.http2.enabled =
            http2_enabled_ && new_config.http2.enabled;
        // Upstream configs are restart-only — clear them so staged edits
        // in the config file don't block live-safe field reloads.
        validation_copy.upstreams.clear();
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

        // Push updated limits to existing connections. Per-connection limits
        // are dispatcher-thread-only fields (plain size_t, not atomic), so
        // enqueue updates through each connection's dispatcher.
        {
            auto snap = SnapshotConnections();
            size_t body = new_config.max_body_size;
            size_t header = new_config.max_header_size;
            size_t ws_msg = new_config.max_ws_message_size;

            for (auto& hconn : snap.h1) {
                auto conn = hconn->GetConnection();
                if (!conn) continue;
                conn->RunOnDispatcher([hconn, body, header, ws_msg, final_cap]() {
                    hconn->UpdateSizeLimits(body, header, ws_msg, final_cap);
                });
            }
            for (auto& h2conn : snap.h2) {
                auto conn = h2conn->GetConnection();
                if (!conn) continue;
                conn->RunOnDispatcher([h2conn, conn, body, final_cap]() {
                    h2conn->SetMaxBodySize(body);
                    conn->SetMaxInputSize(final_cap);
                });
            }
            // Pending-detection connections have no protocol handler yet —
            // only the transport-level input cap needs updating.
            for (auto& conn : snap.pending) {
                if (!conn) continue;
                conn->RunOnDispatcher([conn, final_cap]() {
                    conn->SetMaxInputSize(final_cap);
                });
            }
        }
    }

    // Update the remaining reload-safe fields
    request_timeout_sec_.store(new_config.request_timeout_sec, std::memory_order_relaxed);
    shutdown_drain_timeout_sec_.store(new_config.shutdown_drain_timeout_sec,
                                     std::memory_order_relaxed);
    net_server_.SetMaxConnections(new_config.max_connections);

    // Push updated request timeout to existing connections. Like size limits,
    // request_timeout_sec_ is a plain int on each handler, snapshotted at
    // accept time. Without this, long-lived keep-alive/H2 sessions use the
    // old Slowloris deadline after a reload.
    {
        int timeout = new_config.request_timeout_sec;
        auto snap = SnapshotConnections();

        for (auto& hconn : snap.h1) {
            auto conn = hconn->GetConnection();
            if (!conn) continue;
            conn->RunOnDispatcher([hconn, timeout]() {
                hconn->SetRequestTimeout(timeout);
            });
        }
        for (auto& h2conn : snap.h2) {
            auto conn = h2conn->GetConnection();
            if (!conn) continue;
            conn->RunOnDispatcher([h2conn, timeout]() {
                h2conn->SetRequestTimeout(timeout);
            });
        }
        // Pending-detection connections have no protocol handler yet, but
        // they may have partial data buffered (Slowloris on the preface).
        // Set/clear a transport-level deadline to match the new timeout.
        for (auto& conn : snap.pending) {
            if (!conn) continue;
            conn->RunOnDispatcher([conn, timeout]() {
                if (timeout > 0) {
                    conn->SetDeadline(std::chrono::steady_clock::now() +
                                      std::chrono::seconds(timeout));
                } else {
                    conn->ClearDeadline();
                }
            });
        }
    }

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
            // Also preserve proxy response timeout cadence
            if (u.proxy.response_timeout_ms > 0) {
                int response_sec = std::max(
                    (u.proxy.response_timeout_ms + 999) / 1000, 1);
                new_interval = std::min(new_interval, response_sec);
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
    stats.active_requests         = active_requests_->load(std::memory_order_relaxed);
    stats.max_connections     = net_server_.GetMaxConnections();
    stats.idle_timeout_sec    = static_cast<int>(net_server_.GetConnectionTimeout().count());
    stats.request_timeout_sec = request_timeout_sec_.load(std::memory_order_relaxed);
    stats.worker_threads      = resolved_worker_threads_;
    return stats;
}
