#include "http/http_server.h"
#include "http/http_status.h"
#include "config/config_loader.h"
#include "ws/websocket_frame.h"
#include "http2/http2_constants.h"
#include "upstream/upstream_manager.h"
#include "upstream/proxy_handler.h"
#include "log/logger.h"
#include "log/log_utils.h"
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

// Thread-local scope flag that lets MarkServerReady's internal
// registration pass (pending_proxy_routes_ + RegisterProxyRoutes) call
// back through the public entry points without tripping the startup
// gate. Only MarkServerReady sets this — and only on its own dispatcher
// thread — so user-threaded Post()/Proxy() calls on other threads still
// see the gate closed.
static thread_local bool tls_internal_registration_pass = false;

struct InternalRegistrationScope {
    InternalRegistrationScope() { tls_internal_registration_pass = true; }
    ~InternalRegistrationScope() { tls_internal_registration_pass = false; }
    InternalRegistrationScope(const InternalRegistrationScope&) = delete;
    InternalRegistrationScope& operator=(const InternalRegistrationScope&) = delete;
};

// Collects (method, patterns) pairs during proxy route pre-checking.
// Used by both Proxy() and RegisterProxyRoutes() to filter per-(method,
// pattern) collisions atomically before any RouteAsync call mutates the
// router.
struct MethodRegistration {
    std::string method;
    std::vector<std::string> patterns;
};

// Ceiling division: convert a timeout in milliseconds to whole seconds,
// rounding up. Used for sizing a cap / upper bound (e.g., the async
// deferred safety cap) where we want strict "at least as large as the
// input ms." The naive `(ms + 999) / 1000` on plain int overflows for
// ms values near INT_MAX — ConfigLoader::Validate does not currently
// cap these fields, so an operator typo like response_timeout_ms=
// 2147483647 would drive the result negative. Promoting to int64_t
// and saturating to INT_MAX keeps the rounding safe and monotonic.
//
// Returns at least 1 and at most INT_MAX.
static int CeilMsToSec(int ms) {
    if (ms <= 0) return 1;
    int64_t sec64 = (static_cast<int64_t>(ms) + 999) / 1000;
    if (sec64 > std::numeric_limits<int>::max()) {
        return std::numeric_limits<int>::max();
    }
    if (sec64 < 1) return 1;
    return static_cast<int>(sec64);
}

// Convert a timeout in milliseconds to a DISPATCHER TIMER CADENCE in
// whole seconds. Distinct from CeilMsToSec because cadence sizing has
// different requirements than cap sizing:
//
//   - Sub-2s timeouts (1000, 2000) ms are CLAMPED to 1s cadence
//     instead of being rounded up to 2s. Otherwise a 1100ms deadline
//     is scanned only every 2s and can fire up to ~0.9s late —
//     under-delivering the documented "1s resolution" for ms-based
//     upstream timeouts. This also protects other sub-2s deadlines on
//     the same dispatcher (e.g. session / request-timeout deadlines
//     that would inherit a coarse cadence from an upstream round-up).
//
//   - For >= 2s timeouts, ceiling still gives the correct cadence:
//     cadence equal to the timeout budget in seconds. Scanning at a
//     finer granularity would burn CPU for no correctness win; the
//     overshoot is already bounded by `cadence - (ms/1000)` which is
//     in [0, 1) by construction.
//
//   - Zero/negative inputs normalize to 1s (the finest representable
//     cadence), matching historic call-site behavior.
//
// Saturates at INT_MAX and returns at least 1. int64_t intermediate
// to avoid the same overflow concern as CeilMsToSec.
static int CadenceSecFromMs(int ms) {
    if (ms <= 0) return 1;
    if (ms < 2000) return 1;
    int64_t sec64 = (static_cast<int64_t>(ms) + 999) / 1000;
    if (sec64 > std::numeric_limits<int>::max()) {
        return std::numeric_limits<int>::max();
    }
    return static_cast<int>(sec64);
}

// Normalize a route pattern for dedup comparison by stripping all param
// and catch-all names. E.g., "/api/:id/users/*rest" → "/api/:/users/*".
// This way, semantically identical routes with different param names
// (like /api/:id/*rest vs /api/:user/*tail) produce the same dedup key.
// Regex constraints like :id([0-9]+) are PRESERVED — the route trie treats
// /users/:id([0-9]+) and /users/:name([a-z]+) as distinct routes, so the
// dedup key must distinguish them too.
static std::string NormalizeRouteForDedup(const std::string& pattern) {
    std::string result;
    result.reserve(pattern.size());
    size_t i = 0;
    while (i < pattern.size()) {
        bool at_seg_start = (i == 0) || (result.back() == '/');
        if (at_seg_start && pattern[i] == ':') {
            result += ':';
            ++i;
            // Skip param name (until '/', '(' for regex constraint, or end)
            while (i < pattern.size() && pattern[i] != '/' && pattern[i] != '(') {
                ++i;
            }
            // Preserve regex constraint if present: "([0-9]+)".
            // Balance nested parentheses, mirroring route_trie::ExtractConstraint.
            if (i < pattern.size() && pattern[i] == '(') {
                int depth = 0;
                while (i < pattern.size()) {
                    char c = pattern[i];
                    // Handle backslash escapes like \( \) so they don't affect depth
                    if (c == '\\' && i + 1 < pattern.size()) {
                        result += c;
                        result += pattern[i + 1];
                        i += 2;
                        continue;
                    }
                    if (c == '(') ++depth;
                    else if (c == ')') --depth;
                    result += c;
                    ++i;
                    if (depth == 0) break;
                }
            }
        } else if (at_seg_start && pattern[i] == '*') {
            result += '*';
            // Skip catch-all name (rest of string — catch-all must be last)
            break;
        } else {
            result += pattern[i];
            ++i;
        }
    }
    return result;
}

// Generate a catch-all param name that doesn't collide with existing
// param names in the route pattern. Starts with "proxy_path", falls
// back to "_proxy_tail", then appends numeric suffixes.
static std::string GenerateCatchAllName(const std::string& pattern) {
    auto has_param = [&](const std::string& name) {
        return pattern.find(":" + name) != std::string::npos;
    };
    if (!has_param("proxy_path")) return "proxy_path";
    if (!has_param("_proxy_tail")) return "_proxy_tail";
    for (int i = 0; i < 100; ++i) {
        std::string candidate = "_pp" + std::to_string(i);
        if (!has_param(candidate)) return candidate;
    }
    return "_proxy_fallback";  // extremely unlikely
}

// Headers that can legitimately appear multiple times in a response. When
// merging middleware + handler/upstream headers in the async completion
// path, these names are preserved from BOTH sources (so middleware-added
// caching/policy headers aren't silently dropped when the upstream also
// emits the same name). All other headers are treated as single-value and
// the handler/upstream wins (middleware copy is dropped to avoid invalid
// duplicates like two Content-Type or two Location headers).
//
// Includes Set-Cookie / authenticate headers that literally cannot be
// combined into one line (RFC 6265, RFC 7235) plus common list-based
// response headers that often carry gateway/middleware-added values
// alongside upstream values (Cache-Control, Link, Via, Vary, Warning,
// Allow, Content-Language).
static bool IsRepeatableResponseHeader(const std::string& name) {
    std::string lower(name);
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return lower == "set-cookie" ||
           lower == "www-authenticate" ||
           lower == "proxy-authenticate" ||
           lower == "cache-control" ||
           lower == "link" ||
           lower == "via" ||
           lower == "warning" ||
           lower == "vary" ||
           lower == "allow" ||
           lower == "content-language";
}

// Ensure the pattern has a NAMED catch-all so ProxyHandler can extract the
// strip_prefix tail from request.params. Handles three cases:
//   1. No catch-all          → append "/*<generated>"
//   2. Unnamed catch-all "*" → rewrite to "*<generated>" in place
//   3. Already named "*name" → return unchanged
// Without (2), patterns like /api/:version/* would leave catch_all_param_
// empty in ProxyHandler, and strip_prefix would fall back to static_prefix_
// stripping (only the leading static segment), misrouting every request.
static std::string EnsureNamedCatchAll(const std::string& pattern) {
    // Non-origin-form patterns (e.g. "*" for OPTIONS *) are treated as
    // EXACT static routes by RouteTrie::ParsePattern when they don't
    // start with '/'. Never rewrite them — "*" as a catch-all is only
    // meaningful at a segment boundary of an origin-form path.
    if (pattern.empty() || pattern.front() != '/') {
        return pattern;
    }

    bool has_catch_all = false;
    bool is_named = false;
    size_t catch_all_pos = std::string::npos;
    for (size_t i = 0; i < pattern.size(); ++i) {
        if (pattern[i] == '*' && (i == 0 || pattern[i - 1] == '/')) {
            has_catch_all = true;
            catch_all_pos = i;
            // Named if there's a character after '*' (catch-all must be last,
            // so anything after '*' is the name).
            is_named = (i + 1 < pattern.size());
            break;
        }
    }

    if (has_catch_all && is_named) {
        return pattern;
    }

    std::string generated = GenerateCatchAllName(pattern);

    if (!has_catch_all) {
        std::string result = pattern;
        if (result.empty() || result.back() != '/') result += '/';
        result += "*" + generated;
        return result;
    }

    // Unnamed catch-all: insert the generated name right after '*'.
    return pattern.substr(0, catch_all_pos + 1) + generated;
}

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
    // Bypass RejectIfServerLive for the internal registration pass below.
    // MarkServerReady runs on the dispatcher thread and is the ONLY
    // legitimate mutator of router_/pending_proxy_routes_ between Start()
    // and server_ready_ = true. The thread-local scope is narrow so a
    // user-threaded Post()/Proxy() call on another thread still sees the
    // gate closed (as intended).
    InternalRegistrationScope scope;

    // Assign dispatcher indices for upstream pool partition affinity
    const auto& dispatchers = net_server_.GetSocketDispatchers();
    for (size_t i = 0; i < dispatchers.size(); ++i) {
        dispatchers[i]->SetDispatcherIndex(static_cast<int>(i));
    }

    // Rate limit: always create manager + register middleware, even when
    // disabled or no zones. Reload() can enable/add zones later, and
    // middleware cannot be registered after MarkServerReady() returns.
    rate_limit_manager_ = std::make_unique<RateLimitManager>(rate_limit_config_);
    {
        RateLimitManager* rl = rate_limit_manager_.get();
        router_.PrependMiddleware([rl](
            const HttpRequest& request, HttpResponse& response) -> bool {
            if (!rl->enabled()) return true;

            if (!rl->Check(request, response)) {
                if (rl->dry_run()) {
                    logging::Get()->info(
                        "Rate limit dry-run: would deny {} {} from {}",
                        request.method,
                        logging::SanitizePath(request.path),
                        request.client_ip);
                    return true;
                }
                int code = rl->status_code();
                response.Status(code);
                std::string reason = response.GetStatusReason();
                response.Header("Content-Type", "text/plain")
                        .Text(std::to_string(code) + " " + reason);
                return false;
            }
            return true;
        });
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
            // CadenceSecFromMs: clamps sub-2s timeouts to 1s cadence
            // (instead of rounding up to 2s), preserving the documented
            // 1s resolution for ms-based upstream timeouts.
            int connect_sec = CadenceSecFromMs(u.pool.connect_timeout_ms);
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
                int response_sec = CadenceSecFromMs(u.proxy.response_timeout_ms);
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

    // Process deferred Proxy() calls + auto-register proxy routes from
    // upstream configs. Any validation failure in either path throws
    // std::invalid_argument — we catch it, stop the already-running
    // dispatchers, and rethrow so the caller of HttpServer::Start()
    // sees the failure instead of the server starting in a partially
    // configured state where the expected proxy routes are missing.
    // Mirrors the upstream_manager_ init-failure pattern above.
    try {
        for (const auto& [pattern, name] : pending_proxy_routes_) {
            Proxy(pattern, name);
        }
        pending_proxy_routes_.clear();
        RegisterProxyRoutes();
    } catch (...) {
        logging::Get()->error(
            "Proxy route registration failed, stopping server");
        net_server_.Stop();
        throw;
    }

    // Compute the async-deferred safety cap from all upstream configs
    // referenced by successfully-registered proxy routes (both the
    // auto-registration path via RegisterProxyRoutes and the
    // programmatic HttpServer::Proxy() API). See RecomputeAsyncDeferredCap
    // for the sizing logic and opt-out sentinel.
    RecomputeAsyncDeferredCap();

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
        // Fire any pending per-stream abort hooks before releasing the
        // handler. When the h2 handler destructs, ~Http2Session calls
        // nghttp2_session_del which dispatches on_stream_close for each
        // stream — but OnStreamCloseCallback locks the weak Owner(),
        // which is null during destruction, so the server-level
        // SetStreamCloseCallback NEVER runs on the teardown path. Without
        // this explicit fire, a client-side disconnect with deferred
        // async streams would leak active_requests_ for any wedged
        // handler (matches the HTTP/1 TripAsyncAbortHook fix below).
        if (h2_handler) {
            h2_handler->FireAllStreamAbortHooks();
        }
        OnH2DrainComplete(conn.get());
        return;
    }
    if (http_conn) {
        // Only decrement if not upgraded — the upgrade callback already
        // decremented active_http1_connections_ at upgrade time.
        if (!http_conn->IsUpgraded()) {
            active_http1_connections_.fetch_sub(1, std::memory_order_relaxed);
        }
        // If the downstream client dropped while an async request was
        // still deferred, the heartbeat timer dies with the connection
        // and the stored complete() closure is the only thing that
        // would have decremented active_requests_. A wedged handler
        // (stuck proxy upstream, bugged custom async route) would
        // therefore leak the counter permanently. Fire the abort hook
        // before releasing the handler — it is one-shot (internal
        // exchange on `completed`) so firing when the handler is
        // already racing complete() is safe.
        http_conn->TripAsyncAbortHook();
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
            if (!server_ready_.load(std::memory_order_acquire)) return;

            if (upstream_manager_ && disp->dispatcher_index() >= 0) {
                upstream_manager_->EvictExpired(
                    static_cast<size_t>(disp->dispatcher_index()));
            }

            // Rate limit entry eviction (partitioned by dispatcher index)
            if (rate_limit_manager_ && disp->dispatcher_index() >= 0) {
                rate_limit_manager_->EvictExpired(
                    static_cast<size_t>(disp->dispatcher_index()),
                    static_cast<size_t>(resolved_worker_threads_));
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

    // Store rate limit config for MarkServerReady()
    rate_limit_config_ = config.rate_limit;
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

// Route / middleware mutation is gated by RejectIfServerLive() so a
// call from SetReadyCallback or a worker thread after Start() can't
// race the dispatch path on the non-thread-safe RouteTrie / middleware
// chain. The gate trips as soon as Start() is called (startup_begun_)
// — NOT just once server_ready_ flips true — because MarkServerReady
// mutates router_ on the dispatcher thread during the window between
// those two events. Proxy() has the same guard — see the block near
// its top. MarkServerReady bypasses the check via
// tls_internal_registration_pass so its internal reprocessing of
// pending_proxy_routes_ and RegisterProxyRoutes still works.
bool HttpServer::RejectIfServerLive(const char* op,
                                     const std::string& path) const {
    if (tls_internal_registration_pass) return false;
    if (startup_begun_.load(std::memory_order_acquire) ||
        server_ready_.load(std::memory_order_acquire)) {
        logging::Get()->error(
            "{}: cannot register route/middleware after Start() has been "
            "called (path='{}'). RouteTrie is not safe for concurrent "
            "insert+lookup — register before Start().",
            op, path);
        return true;
    }
    return false;
}

// Route registration delegates
void HttpServer::Get(const std::string& path, HttpRouter::Handler handler)    { if (RejectIfServerLive("Get", path)) return; router_.Get(path, std::move(handler)); }
void HttpServer::Post(const std::string& path, HttpRouter::Handler handler)   { if (RejectIfServerLive("Post", path)) return; router_.Post(path, std::move(handler)); }
void HttpServer::Put(const std::string& path, HttpRouter::Handler handler)    { if (RejectIfServerLive("Put", path)) return; router_.Put(path, std::move(handler)); }
void HttpServer::Delete(const std::string& path, HttpRouter::Handler handler) { if (RejectIfServerLive("Delete", path)) return; router_.Delete(path, std::move(handler)); }
void HttpServer::Route(const std::string& method, const std::string& path, HttpRouter::Handler handler) { if (RejectIfServerLive("Route", path)) return; router_.Route(method, path, std::move(handler)); }
void HttpServer::WebSocket(const std::string& path, HttpRouter::WsUpgradeHandler handler) { if (RejectIfServerLive("WebSocket", path)) return; router_.WebSocket(path, std::move(handler)); }
void HttpServer::Use(HttpRouter::Middleware middleware) { if (RejectIfServerLive("Use", "<middleware>")) return; router_.Use(std::move(middleware)); }

void HttpServer::GetAsync(const std::string& path, HttpRouter::AsyncHandler handler)    { if (RejectIfServerLive("GetAsync", path)) return; router_.RouteAsync("GET",    path, std::move(handler)); }
void HttpServer::PostAsync(const std::string& path, HttpRouter::AsyncHandler handler)   { if (RejectIfServerLive("PostAsync", path)) return; router_.RouteAsync("POST",   path, std::move(handler)); }
void HttpServer::PutAsync(const std::string& path, HttpRouter::AsyncHandler handler)    { if (RejectIfServerLive("PutAsync", path)) return; router_.RouteAsync("PUT",    path, std::move(handler)); }
void HttpServer::DeleteAsync(const std::string& path, HttpRouter::AsyncHandler handler) { if (RejectIfServerLive("DeleteAsync", path)) return; router_.RouteAsync("DELETE", path, std::move(handler)); }
void HttpServer::RouteAsync(const std::string& method, const std::string& path, HttpRouter::AsyncHandler handler) { if (RejectIfServerLive("RouteAsync", path)) return; router_.RouteAsync(method, path, std::move(handler)); }

void HttpServer::Proxy(const std::string& route_pattern,
                       const std::string& upstream_service_name) {
    // Gate external callers. MarkServerReady bypasses this via
    // tls_internal_registration_pass when replaying the pending list.
    // The check covers BOTH the deferred (!upstream_manager_) branch
    // — pending_proxy_routes_ is a plain vector and would race an
    // in-progress MarkServerReady — and the live-registration branch.
    if (!tls_internal_registration_pass &&
        (startup_begun_.load(std::memory_order_acquire) ||
         server_ready_.load(std::memory_order_acquire))) {
        logging::Get()->error(
            "Proxy: cannot register routes after Start() has been called "
            "(route_pattern='{}', upstream='{}'). Call Proxy() before "
            "Start().",
            route_pattern, upstream_service_name);
        return;
    }
    // Reject empty route patterns — calling .back() on an empty string is UB,
    // and an empty pattern is never a valid route.
    //
    // Validation throws std::invalid_argument (rather than logging and
    // returning) so embedders calling this API directly can see the
    // failure instead of finding a missing route at traffic time. The
    // HttpServer(ServerConfig) constructor already runs
    // ConfigLoader::Validate() on upstream_configs_, so the per-upstream
    // checks below are defense-in-depth for that path. They still need
    // to throw on the runtime Proxy() API path, where the route_pattern
    // argument is freshly supplied by the caller and has not gone
    // through any prior validation.
    if (route_pattern.empty()) {
        throw std::invalid_argument(
            "Proxy: route_pattern must not be empty (upstream '" +
            upstream_service_name + "')");
    }
    // Validate the route pattern early — same rules as config_loader
    // applies to JSON-loaded routes. Without this, invalid patterns
    // (duplicate params, catch-all not last, etc.) only fail inside
    // RouteAsync after handler/method bookkeeping has been partially
    // applied.
    try {
        auto segments = ROUTE_TRIE::ParsePattern(route_pattern);
        ROUTE_TRIE::ValidatePattern(route_pattern, segments);
    } catch (const std::invalid_argument& e) {
        throw std::invalid_argument(
            "Proxy: invalid route_pattern '" + route_pattern + "': " + e.what());
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
        throw std::invalid_argument(
            "Proxy: upstream service '" + upstream_service_name +
            "' not configured");
    }

    // Validate proxy config eagerly — fail fast for code-registered routes
    // that bypass config_loader validation. Normally ConfigLoader::Validate
    // already rejects these at HttpServer construction time, but we repeat
    // the check here so the Proxy() API cannot silently register a route
    // against a mis-validated upstream (defense-in-depth) — and so an
    // embedder gets an immediate exception if they somehow populate
    // upstream_configs_ outside the normal constructor path.
    if (found->proxy.response_timeout_ms != 0 &&
        found->proxy.response_timeout_ms < 1000) {
        throw std::invalid_argument(
            "Proxy: upstream '" + upstream_service_name +
            "' has invalid response_timeout_ms=" +
            std::to_string(found->proxy.response_timeout_ms) +
            " (must be 0 or >= 1000)");
    }
    if (found->proxy.retry.max_retries < 0 ||
        found->proxy.retry.max_retries > 10) {
        throw std::invalid_argument(
            "Proxy: upstream '" + upstream_service_name +
            "' has invalid max_retries=" +
            std::to_string(found->proxy.retry.max_retries) +
            " (must be 0-10)");
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
                throw std::invalid_argument(
                    "Proxy: upstream '" + upstream_service_name +
                    "' has invalid method '" + m + "'");
            }
            if (!seen.insert(m).second) {
                throw std::invalid_argument(
                    "Proxy: upstream '" + upstream_service_name +
                    "' has duplicate method '" + m + "'");
            }
        }
    }

    if (!upstream_manager_) {
        // Pre-Start: defer registration. pending_proxy_routes_ mutation
        // is safe here because the startup gate above ensures we are
        // either before Start() (single-threaded user code) or inside
        // MarkServerReady's internal pass (dispatcher thread, exclusive
        // owner of pending_proxy_routes_).
        pending_proxy_routes_.emplace_back(route_pattern, upstream_service_name);
        logging::Get()->debug("Proxy: deferred registration {} -> {} "
                              "(upstream manager not yet initialized)",
                              route_pattern, upstream_service_name);
        return;
    }

    // Detect whether the pattern already contains a catch-all segment.
    // RouteTrie only treats '*' as special at segment start (immediately
    // after '/'), so mid-segment '*' like /file*name is literal. Also
    // skip non-origin-form patterns entirely (e.g. "*" for OPTIONS *):
    // those are exact static routes, not catch-all patterns.
    bool has_catch_all = false;
    if (!route_pattern.empty() && route_pattern.front() == '/') {
        for (size_t i = 0; i < route_pattern.size(); ++i) {
            if (route_pattern[i] == '*' &&
                (i == 0 || route_pattern[i - 1] == '/')) {
                has_catch_all = true;
                break;
            }
        }
    }

    // Build the effective config_prefix with a NAMED catch-all. Handles:
    //  - no catch-all            → appends "/*<generated>"
    //  - unnamed catch-all "/*"  → rewrites to "/*<generated>" so
    //                              ProxyHandler's strip_prefix can find it
    //  - already-named "*name"   → unchanged
    //  - non-origin-form "*"     → unchanged (exact static route)
    std::string config_prefix = EnsureNamedCatchAll(route_pattern);

    // Normalize the route for dedup: strip all param and catch-all names
    // so semantically identical routes with different names produce the
    // same key. E.g., /api/:id/*rest and /api/:user/*tail both → /api/:/*.
    std::string dedup_prefix = NormalizeRouteForDedup(config_prefix);
    std::string handler_key = upstream_service_name + "\t" + dedup_prefix;

    ProxyConfig handler_config = found->proxy;
    handler_config.route_prefix = config_prefix;
    auto handler = std::make_shared<ProxyHandler>(
        upstream_service_name,
        handler_config,
        found->tls.enabled,
        found->host,
        found->port,
        found->tls.sni_hostname,
        upstream_manager_.get());

    // Determine methods to register. HEAD is included so the proxy sends
    // HEAD upstream (not GET via fallback, which downloads the full body).
    // Explicit sync Head() handlers are not shadowed because GetAsyncHandler
    // checks sync HEAD routes before async HEAD matches.
    static const std::vector<std::string> DEFAULT_PROXY_METHODS =
        {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"};
    const bool methods_from_defaults = found->proxy.methods.empty();
    const auto& methods = methods_from_defaults
        ? DEFAULT_PROXY_METHODS : found->proxy.methods;

    // Method-level conflict check BEFORE storing the handler.
    // Partial overlaps are tolerated: skip conflicting methods (with a
    // warn log) and register the rest. Callers expect non-conflicting
    // methods to remain reachable instead of losing the entire route.
    auto& registered = proxy_route_methods_[dedup_prefix];
    std::vector<std::string> accepted_methods;
    accepted_methods.reserve(methods.size());
    for (const auto& m : methods) {
        if (registered.count(m)) {
            logging::Get()->warn("Proxy: method {} on path '{}' already "
                                 "registered by proxy, skipping "
                                 "(upstream '{}')",
                                 m, dedup_prefix, upstream_service_name);
            continue;
        }
        accepted_methods.push_back(m);
    }
    if (accepted_methods.empty()) {
        logging::Get()->error("Proxy: no methods available for path '{}' "
                              "(all conflicted, upstream '{}')",
                              dedup_prefix, upstream_service_name);
        return;
    }

    // Build the list of patterns to register. Both auto-generated and
    // explicit catch-all routes need a companion exact-prefix registration
    // so bare paths (e.g., /api/v1 without trailing slash) don't 404. The
    // catch-all variant is always config_prefix (the NAMED form) so
    // ProxyHandler's catch_all_param_ matches the trie's registered name.
    //
    // Track the "derived companion" separately: only in the has_catch_all
    // case, the exact-prefix companion is derived from the user's
    // catch-all pattern (the user wrote /api/*rest and we implicitly
    // also register /api). This pattern gets an extra sync-conflict
    // check below, so a pre-existing sync handler on the bare prefix
    // isn't silently hijacked by the async companion.
    std::vector<std::string> patterns_to_register;
    std::string derived_companion;  // non-empty only for has_catch_all with a derived companion
    if (!has_catch_all) {
        patterns_to_register.push_back(route_pattern);    // exact prefix (user-specified)
        // Skip the catch-all variant when EnsureNamedCatchAll produced
        // the same string as route_pattern (e.g., non-origin-form "*"
        // for OPTIONS *, which is an exact static route — not a
        // rewritable catch-all). Pushing both would attempt a duplicate
        // RouteAsync insert after partial mutation, since the pre-check
        // only consults routes already in the router.
        if (config_prefix != route_pattern) {
            patterns_to_register.push_back(config_prefix);  // auto catch-all
        }
    } else {
        // Explicit catch-all (possibly rewritten from unnamed to named).
        // Extract the prefix before the catch-all segment.
        auto star_pos = config_prefix.rfind('*');
        if (star_pos != std::string::npos) {
            std::string exact_prefix = config_prefix.substr(0, star_pos);
            while (exact_prefix.size() > 1 && exact_prefix.back() == '/') {
                exact_prefix.pop_back();
            }
            if (!exact_prefix.empty()) {
                derived_companion = exact_prefix;
                patterns_to_register.push_back(exact_prefix);
            }
        }
        patterns_to_register.push_back(config_prefix);    // named catch-all
    }

    // PRE-CHECK PER METHOD: build a per-method list of patterns where
    // registration is allowed, considering BOTH async and sync conflicts.
    //
    // Async conflict on any pattern → drop the method ENTIRELY (from all
    // patterns). Two async routes on semantically equivalent patterns
    // cannot coexist in the same trie.
    //
    // Sync conflict on the DERIVED companion pattern → drop just that
    // (method, pattern) pair, not the whole method. The companion is
    // implicit (user wrote /api/*rest; /api is derived). If the user
    // already has a sync handler serving the bare prefix, the companion
    // would silently hijack it via async-over-sync precedence — so we
    // skip the companion registration for that method and let the sync
    // handler keep serving bare-prefix requests. Non-companion patterns
    // aren't touched by the sync check (they're the user's explicit
    // Proxy target and they accepted the implications).
    //
    // Atomic in the sense that the set of (method, pattern) pairs that
    // will actually register is fully conflict-free BEFORE any
    // RouteAsync call mutates the router.
    std::vector<MethodRegistration> to_register;
    to_register.reserve(accepted_methods.size());
    // PRE-CHECK PER (METHOD, PATTERN): filter individual collisions
    // rather than dropping the whole method on the first conflict.
    // Without this, a proxy on /api/*rest whose bare-prefix companion
    // /api collides with an existing async GET /api would drop GET
    // entirely — even though the catch-all /api/*rest would still
    // coexist in the trie and serve /api/foo.
    for (const auto& method : accepted_methods) {
        MethodRegistration mr;
        mr.method = method;
        mr.patterns.reserve(patterns_to_register.size());
        for (const auto& pattern : patterns_to_register) {
            // Async conflict: the pre-check subsumes the trie's
            // own throw condition for this specific pattern, so
            // skipping just this pattern is safe.
            if (router_.HasAsyncRouteConflict(method, pattern)) {
                logging::Get()->warn(
                    "Proxy: async route '{} {}' already registered on the "
                    "router, skipping pattern for upstream '{}'",
                    method, pattern, upstream_service_name);
                continue;
            }
            // Bare-prefix companions are always registered regardless
            // of sync conflict. The runtime yield in
            // HttpRouter::GetAsyncHandler consults proxy_companion_patterns_
            // and defers to a matching sync route per-request, which
            // correctly handles both disjoint regexes (companion serves
            // its own subset) and overlapping regexes (sync wins on the
            // overlap).
            mr.patterns.push_back(pattern);
        }
        if (!mr.patterns.empty()) {
            to_register.push_back(std::move(mr));
        }
    }
    if (to_register.empty()) {
        logging::Get()->error(
            "Proxy: no (method, pattern) pairs available after live-"
            "router conflict check for upstream '{}' pattern '{}'",
            upstream_service_name, route_pattern);
        return;
    }

    // Rebuild accepted_methods from to_register (stable order) so the
    // HEAD-flag computation and bookkeeping below see the final set.
    accepted_methods.clear();
    accepted_methods.reserve(to_register.size());
    for (const auto& mr : to_register) {
        accepted_methods.push_back(mr.method);
    }

    // Now that the final method set is known, compute HEAD-related flags.
    // block_head_fallback: user explicitly included GET but omitted HEAD,
    // so HEAD→GET fallback on this pattern would leak the method filter.
    // head_from_defaults: HEAD was added by default_methods (not the
    // user's explicit list) — mark the pattern so an explicit sync
    // Head() handler on the same path wins, per the HEAD precedence fix.
    bool proxy_has_get = std::find(accepted_methods.begin(),
                                    accepted_methods.end(), "GET")
                         != accepted_methods.end();
    bool proxy_has_head = std::find(accepted_methods.begin(),
                                     accepted_methods.end(), "HEAD")
                          != accepted_methods.end();
    bool block_head_fallback = proxy_has_get && !proxy_has_head;
    bool head_from_defaults = methods_from_defaults && proxy_has_head;

    // Collect the union of patterns actually registered, so pattern-level
    // per-pattern flags (DisableHeadFallback / MarkProxyDefaultHead) can
    // be applied consistently regardless of which individual (method,
    // pattern) pairs survived the sync-conflict filter above.
    std::unordered_set<std::string> registered_patterns;
    for (const auto& mr : to_register) {
        for (const auto& p : mr.patterns) {
            registered_patterns.insert(p);
        }
    }

    // Build a per-pattern "has GET" set so HEAD pairing is computed
    // per-pattern, not per-registration. The per-(method,pattern)
    // async conflict filter can drop GET on the companion pattern
    // (because an earlier async GET on the same pattern exists) while
    // keeping GET on the catch-all, so the global `proxy_has_get` flag
    // is TRUE overall but NOT for the skipped pattern. Marking every
    // surviving HEAD pattern as paired=proxy_has_get would
    // incorrectly keep the proxy HEAD on the companion even though
    // the real GET owner is the user's earlier async route.
    std::unordered_set<std::string> patterns_with_get;
    for (const auto& mr : to_register) {
        if (mr.method == "GET") {
            for (const auto& pattern : mr.patterns) {
                patterns_with_get.insert(pattern);
            }
        }
    }

    // Perform the actual registration per-method per-pattern. Any
    // exception here is unexpected (e.g., std::bad_alloc) and is
    // propagated; the common "duplicate/conflicting pattern" case was
    // caught by the per-method pre-check above. The companion marker
    // is set PER (method, pattern) here so unrelated async routes
    // registered later on the same pattern with a different method
    // don't inherit the yield-to-sync behavior.
    for (const auto& mr : to_register) {
        for (const auto& pattern : mr.patterns) {
            // Capture handler by shared_ptr so the lambda shares
            // ownership — later overwrites of proxy_handlers_[handler_key]
            // don't destroy this handler while this route is still live.
            router_.RouteAsync(mr.method, pattern,
                [handler](const HttpRequest& request,
                          HTTP_CALLBACKS_NAMESPACE::AsyncCompletionCallback complete) {
                    handler->Handle(request, std::move(complete));
                });
            // Mark the derived bare-prefix companion only for the
            // methods this proxy actually registers on it. A method
            // not in the proxy's method list should NOT yield — a
            // later first-class async route on the same pattern with
            // a different method is unrelated to this companion.
            if (!derived_companion.empty() && pattern == derived_companion) {
                router_.MarkProxyCompanion(mr.method, pattern);
            }
        }
    }
    for (const auto& pattern : registered_patterns) {
        if (block_head_fallback) {
            router_.DisableHeadFallback(pattern);
        }
        if (head_from_defaults) {
            // paired_with_get is PER-PATTERN: true iff the SAME proxy
            // registration also installed GET on THIS pattern. The
            // per-method conflict filter may have kept GET on some
            // patterns (catch-all) while dropping it on others
            // (companion conflicting with a pre-existing user route),
            // so using a global flag would incorrectly mark the
            // companion's HEAD as paired. The HEAD precedence logic
            // then routes HEAD through the real GET owner instead of
            // sticking on this proxy.
            bool pattern_paired_with_get =
                patterns_with_get.count(pattern) > 0;
            router_.MarkProxyDefaultHead(pattern, pattern_paired_with_get);
        }
        logging::Get()->info("Proxy route registered: {} -> {} ({}:{})",
                             pattern, upstream_service_name,
                             found->host, found->port);
    }

    // All routes registered successfully — commit bookkeeping. The
    // handler shared_ptr is captured by the lambdas above (keeping it
    // alive even if proxy_handlers_ is later overwritten), so this is
    // just for future Proxy() lookups and conflict detection.
    proxy_handlers_[handler_key] = handler;
    for (const auto& m : accepted_methods) {
        registered.insert(m);
    }
    // Track the upstream name so the async-deferred safety cap
    // computed in MarkServerReady folds it in (otherwise manual
    // proxies with response_timeout_ms=0 would still inherit the
    // 3600s default — see RecomputeAsyncDeferredCap).
    proxy_referenced_upstreams_.insert(upstream_service_name);
}

void HttpServer::RecomputeAsyncDeferredCap() {
    // Compute the async-deferred safety cap from all upstream configs
    // referenced by successfully-registered proxy routes.
    //
    // The cap is a last-resort abort timer for deferred async
    // responses that never call complete() (e.g., a proxy talking to
    // a genuinely wedged upstream with response_timeout_ms configured,
    // or a custom RouteAsync handler with a bug). To avoid overriding
    // operator-configured timeouts, the cap is sized to be strictly
    // larger than the longest configured proxy.response_timeout_ms.
    //
    // Upstreams with proxy.response_timeout_ms == 0 (operator opted out
    // of a per-request deadline for that upstream) are SKIPPED in the
    // max — not used to globally disable the cap. The async safety cap
    // exists precisely to catch stuck handlers that slip past per-request
    // timeouts, so letting a single upstream's opt-out remove it for
    // every unrelated proxy route and custom async handler on this
    // server would be a footgun — a wedged handler would then hang
    // forever with no last-resort abort. Zero-timeout upstreams are
    // still bounded by the resulting global cap (at least the default
    // floor), but that is a very loose safety net, not a per-request
    // deadline.
    //
    // Default floor: 3600s (1 hour). Generous enough for most custom
    // async handlers and most realistic proxy response timeouts; the
    // computation below raises it when a proxy config demands more.
    //
    // Iterates proxy_referenced_upstreams_ rather than upstream_configs_
    // directly, so programmatic HttpServer::Proxy() calls are included
    // even when the upstream's JSON proxy.route_prefix is empty.
    static constexpr int DEFAULT_MIN_CAP_SEC = 3600;
    static constexpr int BUFFER_SEC = 60;
    int computed_sec = DEFAULT_MIN_CAP_SEC;
    for (const auto& name : proxy_referenced_upstreams_) {
        const UpstreamConfig* found = nullptr;
        for (const auto& u : upstream_configs_) {
            if (u.name == name) {
                found = &u;
                break;
            }
        }
        if (!found) continue;  // Should not happen — defensive
        if (found->proxy.response_timeout_ms == 0) {
            // This upstream is opted out of per-request deadlines.
            // We neither raise NOR disable the global cap here —
            // ProxyHandler::Handle sets a PER-REQUEST override
            // (HttpRequest::async_cap_sec_override = 0) so that THIS
            // proxy's requests run unbounded while unrelated routes on
            // the same server still get the global safety net. See
            // HttpRequest::async_cap_sec_override and the per-request
            // override read in HttpConnectionHandler's deferred
            // heartbeat / Http2Session::ResetExpiredStreams.
            continue;
        }
        // 64-bit ceil division + saturating add to keep the cap
        // monotonic in the input and safe against operator typos
        // near INT_MAX (ConfigLoader::Validate does not currently
        // cap this field).
        int base_sec = CeilMsToSec(found->proxy.response_timeout_ms);
        int sec;
        if (base_sec > std::numeric_limits<int>::max() - BUFFER_SEC) {
            sec = std::numeric_limits<int>::max();
        } else {
            sec = base_sec + BUFFER_SEC;
        }
        computed_sec = std::max(computed_sec, sec);
    }
    int new_cap = computed_sec;
    max_async_deferred_sec_.store(new_cap, std::memory_order_relaxed);
    logging::Get()->debug("HttpServer async deferred safety cap: {}s "
                          "(referenced upstreams={})",
                          new_cap, proxy_referenced_upstreams_.size());
}

void HttpServer::RegisterProxyRoutes() {
    if (!upstream_manager_) {
        return;
    }

    for (const auto& upstream : upstream_configs_) {
        if (upstream.proxy.route_prefix.empty()) {
            continue;  // No proxy config for this upstream
        }

        // Validate proxy config — same checks as ConfigLoader::Validate.
        // For JSON-loaded configs this is a no-op second pass (Validate
        // already rejected anything invalid at HttpServer construction).
        // For programmatic configs the HttpServer(ServerConfig) constructor
        // also runs ConfigLoader::Validate via ValidateConfig(), so this
        // block is defense-in-depth. If a mismatch ever develops between
        // the validator and the registration code, THROW rather than
        // silently log-and-skip — starting the server without the
        // expected proxy routes is a much harder failure to diagnose
        // than an exception at Start() time. MarkServerReady wraps this
        // call in a try/catch that stops the server and rethrows so the
        // caller of HttpServer::Start() sees the failure.
        try {
            auto segments = ROUTE_TRIE::ParsePattern(upstream.proxy.route_prefix);
            ROUTE_TRIE::ValidatePattern(upstream.proxy.route_prefix, segments);
        } catch (const std::invalid_argument& e) {
            throw std::invalid_argument(
                "RegisterProxyRoutes: upstream '" + upstream.name +
                "' has invalid route_prefix '" + upstream.proxy.route_prefix +
                "': " + e.what());
        }
        if (upstream.proxy.response_timeout_ms != 0 &&
            upstream.proxy.response_timeout_ms < 1000) {
            throw std::invalid_argument(
                "RegisterProxyRoutes: upstream '" + upstream.name +
                "' has invalid response_timeout_ms=" +
                std::to_string(upstream.proxy.response_timeout_ms) +
                " (must be 0 or >= 1000)");
        }
        if (upstream.proxy.retry.max_retries < 0 ||
            upstream.proxy.retry.max_retries > 10) {
            throw std::invalid_argument(
                "RegisterProxyRoutes: upstream '" + upstream.name +
                "' has invalid max_retries=" +
                std::to_string(upstream.proxy.retry.max_retries) +
                " (must be 0-10)");
        }
        {
            static const std::unordered_set<std::string> valid_methods = {
                "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD",
                "OPTIONS", "TRACE"
            };
            std::unordered_set<std::string> seen;
            for (const auto& m : upstream.proxy.methods) {
                if (valid_methods.find(m) == valid_methods.end()) {
                    throw std::invalid_argument(
                        "RegisterProxyRoutes: upstream '" + upstream.name +
                        "' has invalid method '" + m + "'");
                }
                if (!seen.insert(m).second) {
                    throw std::invalid_argument(
                        "RegisterProxyRoutes: upstream '" + upstream.name +
                        "' has duplicate method '" + m + "'");
                }
            }
        }

        // Check if the route_prefix already has a catch-all segment.
        // Same segment-start rule as RouteTrie (only after '/'). Skip
        // non-origin-form patterns entirely — "*" for OPTIONS * is an
        // exact static route, not a catch-all.
        std::string route_pattern = upstream.proxy.route_prefix;
        bool has_catch_all = false;
        if (!route_pattern.empty() && route_pattern.front() == '/') {
            for (size_t i = 0; i < route_pattern.size(); ++i) {
                if (route_pattern[i] == '*' &&
                    (i == 0 || route_pattern[i - 1] == '/')) {
                    has_catch_all = true;
                    break;
                }
            }
        }

        // Build effective route_prefix with a NAMED catch-all. Handles
        // no-catch-all, unnamed catch-all, and already-named cases.
        // See EnsureNamedCatchAll for details on why unnamed catch-alls
        // must be rewritten for strip_prefix to work correctly.
        std::string config_prefix = EnsureNamedCatchAll(route_pattern);

        // Same normalized dedup as Proxy()
        std::string dedup_prefix = NormalizeRouteForDedup(config_prefix);
        std::string handler_key = upstream.name + "\t" + dedup_prefix;

        // Create ProxyHandler with the full catch-all-aware route_prefix.
        // shared_ptr so route lambdas can capture shared ownership and
        // survive a later overwrite of proxy_handlers_[handler_key].
        ProxyConfig handler_config = upstream.proxy;
        handler_config.route_prefix = config_prefix;
        auto handler = std::make_shared<ProxyHandler>(
            upstream.name,
            handler_config,
            upstream.tls.enabled,
            upstream.host,
            upstream.port,
            upstream.tls.sni_hostname,
            upstream_manager_.get());

        // Same HEAD policy as Proxy() — HEAD included for correct upstream semantics
        static const std::vector<std::string> DEFAULT_PROXY_METHODS =
            {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"};
        const bool methods_from_defaults = upstream.proxy.methods.empty();
        const auto& methods = methods_from_defaults
            ? DEFAULT_PROXY_METHODS : upstream.proxy.methods;

        // Method-level conflict check BEFORE storing (same as Proxy()).
        // Partial overlaps are tolerated: skip conflicting methods and
        // register the rest.
        auto& registered = proxy_route_methods_[dedup_prefix];
        std::vector<std::string> accepted_methods;
        accepted_methods.reserve(methods.size());
        for (const auto& m : methods) {
            if (registered.count(m)) {
                logging::Get()->warn("RegisterProxyRoutes: method {} on '{}' "
                                     "already registered by proxy, skipping "
                                     "(upstream '{}')",
                                     m, dedup_prefix, upstream.name);
                continue;
            }
            accepted_methods.push_back(m);
        }
        if (accepted_methods.empty()) {
            logging::Get()->error("RegisterProxyRoutes: no methods available "
                                  "for path '{}' (all conflicted, upstream '{}')",
                                  dedup_prefix, upstream.name);
            continue;
        }

        // Build the list of patterns to register. Same layout as Proxy().
        // Track `derived_companion` separately (see HttpServer::Proxy for
        // the rationale — the derived bare-prefix companion gets an
        // extra sync-conflict check so it doesn't silently hijack a
        // pre-existing sync handler).
        std::vector<std::string> patterns_to_register;
        std::string derived_companion;
        if (!has_catch_all) {
            // Register the exact prefix to handle requests without a
            // trailing path (e.g., /api/users). Not a "derived"
            // companion — the user wrote this pattern directly.
            patterns_to_register.push_back(upstream.proxy.route_prefix);
        } else {
            // Explicit catch-all (possibly rewritten from unnamed to named):
            // register exact-prefix companion so bare paths (e.g., /api/v1)
            // don't 404. Extract from config_prefix to account for the
            // unnamed→named rewrite done by EnsureNamedCatchAll.
            auto sp = config_prefix.rfind('*');
            if (sp != std::string::npos) {
                std::string exact_prefix = config_prefix.substr(0, sp);
                while (exact_prefix.size() > 1 && exact_prefix.back() == '/') {
                    exact_prefix.pop_back();
                }
                if (!exact_prefix.empty()) {
                    derived_companion = exact_prefix;
                    patterns_to_register.push_back(exact_prefix);
                }
            }
        }
        // Register the catch-all variant (auto-generated or user-provided,
        // always with named catch-all after EnsureNamedCatchAll).
        // Skip when it duplicates the exact-prefix we already pushed
        // (non-origin-form like "*" where EnsureNamedCatchAll returns
        // the input unchanged) — otherwise RouteAsync would throw a
        // duplicate-route exception on the second insert.
        if (patterns_to_register.empty() ||
            patterns_to_register.back() != config_prefix) {
            patterns_to_register.push_back(config_prefix);
        }

        // PRE-CHECK PER (METHOD, PATTERN): build a per-method list of
        // patterns, filtering out individual collisions rather than
        // dropping the entire method on the first conflict. Previously
        // an async conflict on ANY pattern (e.g. an existing async GET
        // /api overlapping with the bare-prefix companion of a proxy
        // on /api/*rest) dropped GET for the whole proxy — even though
        // the catch-all /api/*rest would still coexist in the trie.
        // The sync-companion branch below already does this per-pattern;
        // async is now symmetric. See HttpServer::Proxy for the
        // same fix applied to the programmatic path.
        std::vector<MethodRegistration> to_register;
        to_register.reserve(accepted_methods.size());
        for (const auto& method : accepted_methods) {
            MethodRegistration mr;
            mr.method = method;
            mr.patterns.reserve(patterns_to_register.size());
            for (const auto& pattern : patterns_to_register) {
                // Async conflict: the pre-check subsumes the trie's
                // own throw condition for this specific pattern, so
                // skipping just this pattern is safe (the remaining
                // patterns in this method cannot trigger a mid-loop
                // RouteAsync throw).
                if (router_.HasAsyncRouteConflict(method, pattern)) {
                    logging::Get()->warn(
                        "RegisterProxyRoutes: async route '{} {}' already "
                        "registered on the router, skipping pattern for "
                        "upstream '{}'",
                        method, pattern, upstream.name);
                    continue;
                }
                // Bare-prefix companions are always registered
                // regardless of sync conflict — runtime yield in
                // HttpRouter::GetAsyncHandler defers to a matching
                // sync route per-request. See HttpServer::Proxy for
                // the full rationale.
                mr.patterns.push_back(pattern);
            }
            if (!mr.patterns.empty()) {
                to_register.push_back(std::move(mr));
            }
        }
        if (to_register.empty()) {
            logging::Get()->error(
                "RegisterProxyRoutes: no (method, pattern) pairs "
                "available after live-router conflict check for "
                "upstream '{}'",
                upstream.name);
            continue;
        }

        // Rebuild accepted_methods (stable order) from to_register.
        accepted_methods.clear();
        accepted_methods.reserve(to_register.size());
        for (const auto& mr : to_register) {
            accepted_methods.push_back(mr.method);
        }

        // Now that the final method set is known, compute HEAD flags.
        // See HttpServer::Proxy for the detailed rationale.
        bool proxy_has_get = std::find(accepted_methods.begin(),
                                        accepted_methods.end(), "GET")
                             != accepted_methods.end();
        bool proxy_has_head = std::find(accepted_methods.begin(),
                                         accepted_methods.end(), "HEAD")
                              != accepted_methods.end();
        bool block_head_fallback = proxy_has_get && !proxy_has_head;
        bool head_from_defaults = methods_from_defaults && proxy_has_head;

        // Collect the union of patterns actually registered so per-pattern
        // flags apply consistently regardless of which (method, pattern)
        // pairs survived the sync-conflict filter.
        std::unordered_set<std::string> registered_patterns;
        for (const auto& mr : to_register) {
            for (const auto& p : mr.patterns) {
                registered_patterns.insert(p);
            }
        }

        // Build per-pattern "has GET" set. See HttpServer::Proxy for
        // the full rationale — the per-method conflict filter can
        // drop GET on some patterns while keeping it on others, so a
        // global proxy_has_get flag misattributes pairing.
        std::unordered_set<std::string> patterns_with_get;
        for (const auto& mr : to_register) {
            if (mr.method == "GET") {
                for (const auto& pattern : mr.patterns) {
                    patterns_with_get.insert(pattern);
                }
            }
        }

        // Perform the actual registration per-method per-pattern. The
        // companion marker is set PER (method, pattern) here so an
        // unrelated async route registered later on the same pattern
        // with a different method doesn't inherit the yield-to-sync
        // behavior. See HttpServer::Proxy for the same rationale.
        for (const auto& mr : to_register) {
            for (const auto& pattern : mr.patterns) {
                // Capture handler by shared_ptr so the lambda shares
                // ownership and survives any later overwrite.
                router_.RouteAsync(mr.method, pattern,
                    [handler](const HttpRequest& request,
                              HTTP_CALLBACKS_NAMESPACE::AsyncCompletionCallback complete) {
                        handler->Handle(request, std::move(complete));
                    });
                if (!derived_companion.empty() && pattern == derived_companion) {
                    router_.MarkProxyCompanion(mr.method, pattern);
                }
            }
        }
        for (const auto& pattern : registered_patterns) {
            if (block_head_fallback) {
                router_.DisableHeadFallback(pattern);
            }
            if (head_from_defaults) {
                // paired_with_get is PER-PATTERN — true iff the SAME
                // proxy registration also installed GET on THIS exact
                // pattern. See HttpServer::Proxy for the rationale;
                // same bug exists here if we used a registration-wide
                // proxy_has_get flag.
                bool pattern_paired_with_get =
                    patterns_with_get.count(pattern) > 0;
                router_.MarkProxyDefaultHead(pattern, pattern_paired_with_get);
            }
            logging::Get()->info("Proxy route registered: {} -> {} ({}:{})",
                                 pattern, upstream.name,
                                 upstream.host, upstream.port);
        }

        // All routes registered successfully — commit bookkeeping.
        proxy_handlers_[handler_key] = handler;
        for (const auto& m : accepted_methods) {
            registered.insert(m);
        }
        // Track the upstream so the async-deferred safety cap
        // considers its response_timeout_ms — same rationale as
        // the programmatic Proxy() path.
        proxy_referenced_upstreams_.insert(upstream.name);
    }
}

void HttpServer::Start() {
    logging::Get()->info("HttpServer starting");
    // Close the registration window AS SOON AS Start() is called, not
    // when server_ready_ flips true later. RouteTrie is not thread-safe
    // for concurrent insert + lookup, and MarkServerReady runs on the
    // dispatcher thread while user code may still be on the caller
    // thread. Without this flag, a late Post() on the caller thread
    // could race with MarkServerReady's RegisterProxyRoutes inserts.
    startup_begun_.store(true, std::memory_order_release);
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
    http_conn->SetMaxAsyncDeferredSec(
        max_async_deferred_sec_.load(std::memory_order_relaxed));

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
                // Allocate a cancel slot for handler-installed cleanup
                // (e.g., ProxyHandler registers tx->Cancel() here).
                // Fired by the async abort hook below. Populated BEFORE
                // invoking async_handler so the handler can install its
                // cancel callback inline.
                auto cancel_slot =
                    std::make_shared<std::function<void()>>();
                request.async_cancel_slot = cancel_slot;
                HttpRouter::AsyncCompletionCallback complete =
                    [weak_self, active_counter,
                     mw_headers, completed, cancelled](HttpResponse final_resp) {
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
                            if (!IsRepeatableResponseHeader(fh.first)) {
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
                            if (!IsRepeatableResponseHeader(mh.first) &&
                                final_non_repeatable.count(lower)) {
                                continue;
                            }
                            merged.AppendHeader(mh.first, mh.second);
                        }
                        // Dedupe non-repeatable headers WITHIN the final
                        // response too. Without this, a buggy upstream
                        // or handler that emits duplicate Content-Type
                        // / Location / etc. would have both copies
                        // forwarded verbatim, producing a malformed
                        // downstream response. Repeatable headers
                        // (Set-Cookie, Cache-Control, Link, Via, ...)
                        // are still appended in full.
                        std::set<std::string> seen_final_non_repeatable;
                        for (const auto& fh : final_resp.GetHeaders()) {
                            if (!IsRepeatableResponseHeader(fh.first)) {
                                std::string lower = fh.first;
                                std::transform(
                                    lower.begin(), lower.end(), lower.begin(),
                                    [](unsigned char c) { return std::tolower(c); });
                                if (!seen_final_non_repeatable.insert(lower).second) {
                                    continue;  // already emitted first copy
                                }
                            }
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
                // Install a safety-cap abort hook so the deferred
                // heartbeat (which may fire 504 on a stuck handler) can
                // short-circuit the stored complete closure and release
                // the active_requests bookkeeping exactly once. Uses the
                // same one-shot `completed` atomic as the complete
                // closure so abort + complete races decrement at most
                // once. Also fires the handler-installed cancel_slot
                // (e.g. ProxyHandler's tx->Cancel()) so upstream work
                // can release pool capacity instead of running to
                // completion against a disconnected client.
                self->SetAsyncAbortHook(
                    [completed, cancelled, active_counter, cancel_slot]() {
                        if (!completed->exchange(true,
                                                 std::memory_order_acq_rel)) {
                            cancelled->store(true, std::memory_order_release);
                            active_counter->fetch_sub(
                                1, std::memory_order_relaxed);
                            // Fire handler cancel (if any) — one-shot.
                            // Move out first so a throwing cancel hook
                            // cannot be re-entered and the captures are
                            // released even on failure.
                            if (cancel_slot && *cancel_slot) {
                                auto local = std::move(*cancel_slot);
                                *cancel_slot = nullptr;
                                try { local(); }
                                catch (const std::exception& e) {
                                    logging::Get()->error(
                                        "Async cancel hook threw: {}",
                                        e.what());
                                }
                            }
                        }
                    });
                // Disarm the guard so the callback (or the abort hook)
                // handles the decrement.
                guard.release();
                return;
            }

            if (!router_.Dispatch(request, response)) {
                response.Status(HttpStatus::NOT_FOUND).Text("Not Found");
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
    h2_conn->SetMaxAsyncDeferredSec(
        max_async_deferred_sec_.load(std::memory_order_relaxed));

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
                // Handler-installed cancel slot — mirrors HTTP/1.
                // Populated before async_handler runs; fired by the
                // per-stream abort hook on client-side abort (stream
                // RST, close callback, or the async safety cap).
                auto cancel_slot =
                    std::make_shared<std::function<void()>>();
                request.async_cancel_slot = cancel_slot;
                HttpRouter::AsyncCompletionCallback complete =
                    [weak_self, stream_id, active_counter,
                     mw_headers, completed, cancelled](HttpResponse final_resp) {
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
                            if (!IsRepeatableResponseHeader(fh.first)) {
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
                            if (!IsRepeatableResponseHeader(mh.first) &&
                                final_non_repeatable.count(lower)) {
                                continue;
                            }
                            merged.AppendHeader(mh.first, mh.second);
                        }
                        // Dedupe non-repeatable headers WITHIN the final
                        // response too. Without this, a buggy upstream
                        // or handler that emits duplicate Content-Type
                        // / Location / etc. would have both copies
                        // forwarded verbatim, producing a malformed
                        // downstream response. Repeatable headers
                        // (Set-Cookie, Cache-Control, Link, Via, ...)
                        // are still appended in full.
                        std::set<std::string> seen_final_non_repeatable;
                        for (const auto& fh : final_resp.GetHeaders()) {
                            if (!IsRepeatableResponseHeader(fh.first)) {
                                std::string lower = fh.first;
                                std::transform(
                                    lower.begin(), lower.end(), lower.begin(),
                                    [](unsigned char c) { return std::tolower(c); });
                                if (!seen_final_non_repeatable.insert(lower).second) {
                                    continue;  // already emitted first copy
                                }
                            }
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
                // Handler returned without throwing — install a
                // per-stream abort hook for the safety-cap path.
                // When ResetExpiredStreams RSTs a stuck stream, the
                // hook flips the stored complete closure's one-shot
                // completed/cancelled atomics and decrements
                // active_requests exactly once, avoiding the
                // bookkeeping leak that would otherwise occur when
                // the real handler never calls complete(). It also
                // fires the handler-installed cancel_slot (e.g.
                // ProxyHandler's tx->Cancel()) so upstream work is
                // released back to the pool on client-side abort.
                self->SetStreamAbortHook(
                    stream_id,
                    [completed, cancelled, active_counter, cancel_slot]() {
                        if (!completed->exchange(true,
                                                 std::memory_order_acq_rel)) {
                            cancelled->store(true, std::memory_order_release);
                            active_counter->fetch_sub(
                                1, std::memory_order_relaxed);
                            if (cancel_slot && *cancel_slot) {
                                auto local = std::move(*cancel_slot);
                                *cancel_slot = nullptr;
                                try { local(); }
                                catch (const std::exception& e) {
                                    logging::Get()->error(
                                        "Async cancel hook threw: {}",
                                        e.what());
                                }
                            }
                        }
                    });
                guard.release();
                return;
            }

            if (!router_.Dispatch(request, response)) {
                response.Status(HttpStatus::NOT_FOUND).Text("Not Found");
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
               int32_t stream_id, uint32_t /*error_code*/) {
            active_h2_streams_.fetch_sub(1, std::memory_order_relaxed);
            self->DecrementLocalStreamCount();
            // FIRE the abort hook — do NOT merely erase it. A client-side
            // RST_STREAM, peer disconnect, or connection-level GOAWAY
            // can close a pending async stream BEFORE the handler ever
            // calls complete(). If we only erased, a stuck handler
            // would never decrement active_requests_ and /stats would
            // stay permanently elevated. Firing is idempotent: the
            // hook's one-shot `completed` exchange(true) returns true
            // on the normal-complete path (closure already fired the
            // decrement), so the hook is a no-op on clean close and
            // releases bookkeeping on early close.
            self->FireAndEraseStreamAbortHook(stream_id);
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
        // Rate limit config IS live-reloadable and MUST be validated.
        // Unlike upstreams (restart-only), rate_limit changes are applied
        // immediately via rate_limit_manager_->Reload(), so bad values
        // (rate<=0, invalid key_type, duplicate zone names) must be caught.
        validation_copy.rate_limit = new_config.rate_limit;
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
        // CadenceSecFromMs clamps sub-2s timeouts to 1s so reload-time
        // recomputation matches the startup-time cadence.
        for (const auto& u : upstream_configs_) {
            int connect_sec = CadenceSecFromMs(u.pool.connect_timeout_ms);
            new_interval = std::min(new_interval, connect_sec);
            if (u.pool.idle_timeout_sec > 0) {
                new_interval = std::min(new_interval, u.pool.idle_timeout_sec);
            }
            // Also preserve proxy response timeout cadence
            if (u.proxy.response_timeout_ms > 0) {
                int response_sec = CadenceSecFromMs(u.proxy.response_timeout_ms);
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

    // Rate limit reload — always safe because manager is always created
    if (rate_limit_manager_) {
        rate_limit_manager_->Reload(new_config.rate_limit);
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
