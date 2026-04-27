#pragma once

#include "net_server.h"
#include "http/http_router.h"
#include "http/http_connection_handler.h"
#include "http2/http2_connection_handler.h"
#include "http2/protocol_detector.h"
#include "config/server_config.h"
#include "net/dns_resolver.h"
#include "tls/tls_context.h"
#include "rate_limit/rate_limiter.h"

#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>

// Forward declarations for upstream pool and proxy
class UpstreamManager;
class ProxyHandler;

namespace CIRCUIT_BREAKER_NAMESPACE {
class CircuitBreakerManager;
}

namespace AUTH_NAMESPACE {
class AuthManager;
}

class HttpServer {
public:
    // Snapshot of server runtime statistics. All values are approximate
    // (relaxed atomic reads) — slightly stale snapshots are acceptable.
    struct ServerStats {
        int64_t uptime_seconds = 0;
        int64_t active_connections = 0;
        int64_t active_http1_connections = 0;
        int64_t active_http2_connections = 0;
        int64_t active_h2_streams = 0;
        int64_t total_accepted = 0;
        int64_t total_requests = 0;
        int64_t active_requests = 0;
        // Reload-safe config fields (live values from atomics)
        int max_connections = 0;
        int idle_timeout_sec = 0;
        int request_timeout_sec = 0;
        int worker_threads = 0;  // resolved from auto mode
    };

    // Construct with explicit host/port. Delegates to the config ctor,
    // so the input goes through the same Normalize + Validate pipeline —
    // hostnames and bare IPv6 literals are accepted symmetrically.
    HttpServer(const std::string& ip, int port);

    // Construct with config. Takes `config` by value so the body can
    // run Normalize + Validate on the copy without mutating the caller's
    // struct. Source-compatible with `const ServerConfig&` callers (the
    // copy happens at call site). Throws std::invalid_argument on
    // malformed host input or semantic validation failures.
    explicit HttpServer(ServerConfig config);

    ~HttpServer();

    // Route registration (delegates to router) — synchronous handlers.
    // The framework serializes the response and closes out the request when
    // the handler returns. Use the *Async variants for handlers that need
    // to dispatch async work (e.g. upstream proxy) and send the response later.
    void Get(const std::string& path, HttpRouter::Handler handler);
    void Post(const std::string& path, HttpRouter::Handler handler);
    void Put(const std::string& path, HttpRouter::Handler handler);
    void Delete(const std::string& path, HttpRouter::Handler handler);
    void Route(const std::string& method, const std::string& path, HttpRouter::Handler handler);
    void WebSocket(const std::string& path, HttpRouter::WsUpgradeHandler handler);
    void Use(HttpRouter::Middleware middleware);

    // Route registration — asynchronous handlers.
    //
    // The handler receives the request plus a protocol-agnostic completion
    // callback. Invoke `complete(final_response)` once when the async work
    // finishes; the framework handles response delivery for both HTTP/1
    // and HTTP/2 transparently. Typical pattern for an upstream proxy:
    //
    //   server.GetAsync("/proxy", [this](const HttpRequest& req, auto complete) {
    //       upstream_->CheckoutAsync("svc", req.dispatcher_index,
    //           [complete](UpstreamLease lease) {
    //               // ... perform the upstream request ...
    //               HttpResponse final;
    //               final.Status(200).Text("...");
    //               complete(std::move(final));
    //           },
    //           [complete](int /*err*/) {
    //               HttpResponse e;
    //               e.Status(502).Text("Bad Gateway");
    //               complete(std::move(e));
    //           });
    //   });
    //
    // Framework guarantees while the async response is pending:
    //   - Middleware (auth, CORS, rate limiting) has already run before the
    //     handler is invoked; rejection responses never reach the handler.
    //   - The connection is exempt from the graceful-shutdown close sweep
    //     (HTTP/1) or tracked in the H2 stream drain (HTTP/2).
    //   - HTTP/1 pipelined bytes arriving after the deferred request are
    //     buffered and parsed only after complete() fires, preserving
    //     response ordering.
    //   - complete() applies HEAD body-stripping and Connection close /
    //     keep-alive normalization automatically, using the original
    //     request's metadata.
    //
    // Async routes take precedence over sync routes for the same
    // method+path. The completion callback MUST be invoked on the
    // dispatcher thread that owns the request connection; upstream pool
    // callbacks naturally run on the right dispatcher.
    void GetAsync(const std::string& path, HttpRouter::AsyncHandler handler);
    void PostAsync(const std::string& path, HttpRouter::AsyncHandler handler);
    void PutAsync(const std::string& path, HttpRouter::AsyncHandler handler);
    void DeleteAsync(const std::string& path, HttpRouter::AsyncHandler handler);
    void RouteAsync(const std::string& method, const std::string& path,
                    HttpRouter::AsyncHandler handler);

    // Proxy route registration: forward all requests matching route_pattern
    // to the named upstream service. The upstream must be configured in the
    // server config's upstreams array. The proxy config comes from the
    // upstream's proxy section in the config.
    void Proxy(const std::string& route_pattern,
               const std::string& upstream_service_name);

    // Server lifecycle.
    // NOTE: Start/Stop is one-shot — after Stop(), the internal dispatchers
    // and thread pool are permanently stopped and cannot be restarted.
    // To restart, destroy and reconstruct the HttpServer.
    void Start();  // Blocks in event loop
    void Stop();

    // Apply reload-safe config fields at runtime. Called from the main
    // (signal) thread on SIGHUP. Thread-safe: uses atomic stores for limit
    // fields and EnQueue for dispatcher-thread-affine updates.
    // Restart-required fields (bind_host, bind_port, tls.*, worker_threads,
    // http2.enabled) are silently ignored — the caller logs them.
    // Returns false if the config was rejected (validation failure, not ready).
    //
    // Takes `new_config` by value so Reload can self-normalize its copy
    // without mutating the caller's struct. In-process callers that
    // construct a ServerConfig and call Reload() directly get the same
    // Normalize + Validate pipeline as the SIGHUP-driven path in main.cc.
    // Structural malformation (bad brackets, malformed trailing-dot sni)
    // in a restart-only host field is warn-downgraded so live-safe edits
    // in the same reload aren't blocked.
    bool Reload(ServerConfig new_config);

    // Return a snapshot of server runtime statistics.
    ServerStats GetStats() const;

    // Return a thread-safe snapshot of the live server config.
    //
    // `live_config_` is written by the constructor at startup and also
    // updated by `Reload()` for live-reloadable fields:
    //   - dns.resolve_timeout_ms, dns.overall_timeout_ms, dns.stale_on_error
    //     (updated each successful Reload that passes the DNS gates)
    //   - upstreams (mirrored from upstream_configs_ at end of Reload)
    //
    // Fields NOT written by Reload (restart-only):
    //   - dns.lookup_family, dns.resolver_max_inflight (worker pool sized
    //     at construction, not resized on reload)
    //   - bind_host, bind_port, worker_threads, tls.*, http2.enabled
    //
    // Acquires `reload_mtx_` so reads are coherent with in-flight Reloads.
    ServerConfig GetLiveConfigSnapshot() const;

    // Return a copy of the resolved bind endpoint, or std::nullopt if
    // Start() has not completed successfully (ctor-only or gate-aborted).
    // Populated in Start()'s two-phase commit AFTER both shutdown gates
    // pass. /stats.bind is rendered from this; tests use it to observe
    // post-DNS resolved endpoint + the ephemeral-port refresh. Safe to
    // read post-Start because writes happen before server_ready_
    // publishes on startup.
    std::optional<NET_DNS_NAMESPACE::ResolvedEndpoint> GetBindResolved() const;

    // DNS stats snapshot: resolver counters + stale-serve counter.
    // All counter reads are relaxed atomics — slightly stale is fine.
    struct HttpServerDnsStats {
        NET_DNS_NAMESPACE::ResolverSnapshot resolver;
        uint64_t total_reload_stale_served = 0;
    };
    HttpServerDnsStats GetDnsStatsSnapshot() const;

    // Per-upstream resolved endpoint snapshot for /stats rendering.
    // age_seconds is monotonic (steady_clock), not wall-clock epoch.
    struct UpstreamResolvedEntry {
        std::string service_name;
        std::string host_raw;
        std::string resolved_authority;
        int64_t age_seconds = 0;
        std::optional<bool>        last_reresolve_succeeded;
        std::optional<std::string> last_reresolve_error;
    };
    std::vector<UpstreamResolvedEntry> GetUpstreamResolvedSnapshot() const;

    // Called after init completes but before the blocking event loop.
    // Used by daemon mode to signal readiness to the parent process.
    void SetReadyCallback(std::function<void()> cb);

    // True after Start() finishes building dispatchers and ready callback fires.
    bool IsReady() const { return server_ready_.load(std::memory_order_acquire); }

    // Returns the actual port the server is listening on.
    int GetBoundPort() const;

    // Access the upstream pool manager for proxy handlers.
    // Returns nullptr if no upstreams configured, not started, or stopped.
    // Reachable while ready OR during the graceful shutdown drain window.
    // Stop() clears server_ready_ immediately but defers
    // UpstreamManager::InitiateShutdown() until after H2/WS/H1 protocol
    // drain completes. During that window, already-accepted proxy handlers
    // must still be able to reach the pool to do their upstream calls, so
    // we keep GetUpstreamManager() live while shutting_down_started_ is set.
    // shutting_down_started_ is cleared at the end of Stop(), before
    // ~HttpServer() destroys upstream_manager_, so the returned pointer
    // remains valid as long as the getter is non-null.
    UpstreamManager* GetUpstreamManager() const {
        if (!server_ready_.load(std::memory_order_acquire) &&
            !shutting_down_started_.load(std::memory_order_acquire)) {
            return nullptr;
        }
        return upstream_manager_.get();
    }

    // Forwarder to `AuthManager::LiveIssuerNames` — see that docstring
    // for the "live runtime vs staged config" rationale and the
    // reload-driver-thread contract. Returns empty when auth is not
    // configured. Out-of-line because AuthManager is forward-declared.
    std::unordered_set<std::string> LiveAuthIssuerNames() const;

public:
    // Thread-local pointer to the active ResourcePusher for the sync request
    // currently executing on this thread. Installed by the H1 / H2 sync
    // dispatch sites around router_.Dispatch with a scope guard so it is
    // never dangling outside a dispatch. Read by the free helper
    // HTTP2_PUSH_NAMESPACE::PushResource() so synchronous handlers can issue HTTP/2 pushes
    // without changing the sync handler signature. Always nullptr outside
    // a dispatch (the helper returns -1 with a debug log in that case).
    //
    // Public-not-private because HTTP2_PUSH_NAMESPACE::PushResource (declared in
    // include/http/push_helper.h) needs direct access; kept inside the
    // class so it is namespaced under HttpServer:: rather than polluting
    // the global / http namespace with a free thread-local.
    static thread_local HTTP_CALLBACKS_NAMESPACE::ResourcePusher* current_sync_pusher_;

private:
    // `live_config_` is initialized first because every other member's
    // ctor reads it from the initializer list. A full member-order
    // rearrangement (moving `net_server_` last) is deferred to a focused
    // state-consolidation pass so this step does not also carry
    // destruction-order risk. Current layout preserves the manual
    // destruction order enforced by `~HttpServer() → Stop()`.
    // `live_config_` holds the Normalize+Validate result from ctor time.
    ServerConfig live_config_;

    // Serialises (a) Reload-vs-Reload; (b) `GetLiveConfigSnapshot() const`
    // vs in-flight Reload; (c) Stop's post-drain teardown barrier vs
    // in-flight Reload. `mutable` because it serialises access — the
    // mutex is not part of object state. NOT acquired on Stop's
    // pre-drain accept-close path — that stays lock-free.
    mutable std::mutex reload_mtx_;

    // Per-server DNS resolver. Ctor is cheap (allocates `PoolState` only;
    // lazy worker spawn on first non-literal ResolveAsync). Owned via
    // unique_ptr so the destruction order is deterministic.
    std::unique_ptr<NET_DNS_NAMESPACE::DnsResolver> dns_resolver_;

    // Lock-free signal channel from Stop() to in-progress Start()/Reload()
    // Stop() stores true with release ordering as
    // the FIRST executable line; Start/Reload load with acquire at each
    // phase boundary. Separate from `reload_mtx_` so a Stop signal can
    // reach a Start blocked in DNS without waiting on the mutex.
    std::atomic<bool> stopping_{false};

    // Populated by Start()'s two-phase commit:
    // post-Phase-A DNS batch + post-Phase-B StartListening + ephemeral
    // port refresh. Absent when Start() has not run successfully (ctor-
    // only state, or aborted via Phase-A / Phase-B stopping_ gate). 
    // Writer is Start() on the main startup thread; readers run after server_ready_=true,
    // so no additional synchronization is required — `server_ready_`
    // doubles as the publication barrier for these members.
    std::optional<NET_DNS_NAMESPACE::ResolvedEndpoint> bind_resolved_;

    // Same two-phase commit as bind_resolved_. Map keyed by
    // upstream.name. Consumed by `MarkServerReady` when constructing
    // `UpstreamManager` via the 3-arg ctor. Empty when Start() aborted
    // or no upstreams are configured.
    NET_DNS_NAMESPACE::ResolvedMap upstream_resolved_;

    // Last reresolve outcome per upstream service name.
    // Written under reload_mtx_ by Reload(); read (with reload_mtx_) by
    // GetUpstreamResolvedSnapshot(). Only populated after the first DNS-aware
    // Reload() call; entries remain absent until that point.
    struct ReresolveStatus {
        bool succeeded = true;
        std::string error_message;
    };
    std::unordered_map<std::string, ReresolveStatus> upstream_reresolve_status_;

    NetServer net_server_;
    HttpRouter router_;
    std::map<int, std::shared_ptr<HttpConnectionHandler>> http_connections_;
    std::mutex conn_mtx_;

    void HandleNewConnection(std::shared_ptr<ConnectionHandler> conn);
    void HandleCloseConnection(std::shared_ptr<ConnectionHandler> conn);
    void HandleErrorConnection(std::shared_ptr<ConnectionHandler> conn);
    void HandleMessage(std::shared_ptr<ConnectionHandler> conn, std::string& message);

    // Reject any route / middleware mutation once the server has been
    // marked ready. RouteTrie (and the middleware chain) are not safe
    // for concurrent insert + lookup, so calls from SetReadyCallback
    // or any worker thread after Start() must be refused. Returns
    // true if the operation should be rejected (server is live).
    bool RejectIfServerLive(const char* op, const std::string& path) const;

    // Snapshot of all active connection handlers, taken under conn_mtx_.
    // Used by Reload() to push updated config to existing connections.
    struct ConnectionSnapshot {
        std::vector<std::shared_ptr<HttpConnectionHandler>> h1;
        std::vector<std::shared_ptr<Http2ConnectionHandler>> h2;
        std::vector<std::shared_ptr<ConnectionHandler>> pending;
    };
    ConnectionSnapshot SnapshotConnections();

    // Helper: set up request + upgrade handlers on an HttpConnectionHandler
    void SetupHandlers(std::shared_ptr<HttpConnectionHandler> http_conn);
    // Helper: wire NetServer callbacks to this HttpServer
    void WireNetServerCallbacks();
    // Compute the pre-read input buffer cap from configured limits.
    size_t ComputeInputCap() const;
    // Safe WS transport-close notification: null-check, exception-safe, log errors.
    // Must be called OUTSIDE conn_mtx_ to prevent deadlock.
    void SafeNotifyWsClose(const std::shared_ptr<HttpConnectionHandler>& http_conn);

    // Compute timer scan interval from timeout values.
    static int ComputeTimerInterval(int idle_timeout_sec, int request_timeout_sec);

    // Returns true if any HTTP/1 connection has pending output data.
    // Used during shutdown to wait for in-flight responses to drain.
    bool HasPendingH1Output();

    // Set start_time_ and server_ready_ flag. Called by the ready callback.
    void MarkServerReady();

    // Subtract remaining stream count from active_h2_streams_.
    void CompensateH2Streams(const std::shared_ptr<Http2ConnectionHandler>& h2);

    // Shared implementation for HandleCloseConnection/HandleErrorConnection.
    // Removes the connection from all maps, decrements counters, and notifies
    // drain/WS handlers. Must be called with conn_mtx_ NOT held.
    void RemoveConnection(std::shared_ptr<ConnectionHandler> conn);

    std::shared_ptr<TlsContext> tls_ctx_;  // Shared with NetServer for safe lifetime

    // Request limits — defaults match ServerConfig defaults.
    // The ip/port constructor uses these; the config constructor overwrites them.
    // Atomic: Reload() writes from main thread, SetupHandlers()/SetupH2Handlers()
    // reads from dispatcher threads.
    std::atomic<size_t> max_body_size_{1048576};       // 1 MB
    std::atomic<size_t> max_header_size_{8192};        // 8 KB
    std::atomic<size_t> max_ws_message_size_{16777216}; // 16 MB
    std::atomic<int> request_timeout_sec_{30};         // Slowloris protection

    // Safety cap for deferred async requests that never call complete().
    // Computed from config at MarkServerReady: max of (DEFAULT_MIN,
    // max upstream.proxy.response_timeout_ms/1000 + buffer). Set to 0
    // (disabled) when ANY upstream has response_timeout_ms == 0
    // (explicitly disabled) — in that mode operators accept the hang
    // risk for stuck handlers in exchange for unbounded async lifetime.
    // Propagated to HttpConnectionHandler / Http2ConnectionHandler so
    // the per-connection heartbeat / stream-reset paths can enforce it
    // without overriding operator-configured timeouts.
    std::atomic<int> max_async_deferred_sec_{3600};    // 1 hour default

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
    std::atomic<int> shutdown_drain_timeout_sec_{30};

    // Runtime counters for /stats endpoint. All use memory_order_relaxed.
    std::atomic<int64_t> active_connections_{0};
    std::atomic<int64_t> active_http1_connections_{0};
    std::atomic<int64_t> active_http2_connections_{0};
    std::atomic<int64_t> active_h2_streams_{0};
    std::atomic<int64_t> total_accepted_{0};
    std::atomic<int64_t> total_requests_{0};
    // Incremented by MergeResolvedForReload each time a stale (error) endpoint
    // is served because stale_on_error is true and no fresh result arrived.
    std::atomic<uint64_t> total_reload_stale_served_{0};
    // Heap-allocated so async completion callbacks that capture a shared_ptr
    // copy keep the atomic alive past ~HttpServer. A late callback firing
    // after shutdown would otherwise dereference a freed stack member.
    std::shared_ptr<std::atomic<int64_t>> active_requests_ =
        std::make_shared<std::atomic<int64_t>>(0);

    // Server start time for uptime calculation. Set by the ready callback
    // when the server actually starts accepting connections, not at construction.
    std::chrono::steady_clock::time_point start_time_;

    // Resolved worker count (set at construction, never changes).
    // Needed because auto mode (worker_threads=0) resolves inside ThreadPool.
    int resolved_worker_threads_ = 0;

    // Set at the entry of Start() — before any dispatcher spins up
    // and before MarkServerReady mutates router_/proxy state. Closes
    // the gap between "user called Start()" and "server_ready_ = true":
    // during that window MarkServerReady runs unsynchronized inserts
    // into RouteTrie from the dispatcher thread, so any concurrent
    // Post()/Proxy()/RegisterProxyRoutes-style call from another
    // thread would race those inserts. RejectIfServerLive and Proxy()
    // check this flag in addition to server_ready_, and MarkServerReady
    // bypasses the check via an internal thread-local scope guard.
    std::atomic<bool> startup_begun_{false};

    // Set by the ready callback after Start() finishes building dispatchers.
    // Reload() checks this to avoid walking socket_dispatchers_ during startup.
    std::atomic<bool> server_ready_{false};
    // Set by Stop() after server_ready_=false. Used by GetStats() to keep
    // reporting valid uptime during the drain phase. Acts as a release
    // barrier for the non-atomic start_time_ field.
    std::atomic<bool> shutting_down_started_{false};
    struct DrainingH2Conn {
        std::shared_ptr<Http2ConnectionHandler> handler;
        std::shared_ptr<ConnectionHandler> conn;
    };
    std::vector<DrainingH2Conn> h2_draining_;
    std::set<ConnectionHandler*> ws_draining_;  // WS connections in close handshake
    std::mutex drain_mtx_;
    std::condition_variable drain_cv_;
    void OnH2DrainComplete(ConnectionHandler* conn_ptr);
    void OnWsDrainComplete(ConnectionHandler* conn_ptr);
    void WaitForH2Drain();

    // Helper: set up request handler on an Http2ConnectionHandler
    void SetupH2Handlers(std::shared_ptr<Http2ConnectionHandler> h2_conn);

    // Detect protocol and create the appropriate handler (HTTP/1.x or HTTP/2).
    // Returns true if handler was created and data was routed.
    // already_counted: true if total_accepted_/active_connections_ were already
    // incremented by HandleNewConnection (normal path); false on the accept/data
    // race path where HandleMessage runs before HandleNewConnection.
    bool DetectAndRouteProtocol(std::shared_ptr<ConnectionHandler> conn,
                                std::string& message, bool already_counted);

    // Upstream connection pool
    std::vector<UpstreamConfig> upstream_configs_;
    std::unique_ptr<UpstreamManager> upstream_manager_;

    // Circuit breaker — declared AFTER upstream_manager_ so destruction
    // order is breaker-FIRST, pool-SECOND (design §3.1). On shutdown the
    // breaker's slices may still be consulted by in-flight
    // ProxyTransactions until they drain; destroying the breaker first
    // (before the pool) is safe because UpstreamManager's outstanding
    // breaker_manager_ pointer is checked against null on every lookup.
    // Destroying the pool first would leave breaker slices holding
    // dangling references.
    std::unique_ptr<CIRCUIT_BREAKER_NAMESPACE::CircuitBreakerManager> circuit_breaker_manager_;

    // Rate limiting
    RateLimitConfig rate_limit_config_;
    std::unique_ptr<RateLimitManager> rate_limit_manager_;

    // Auth — cached config from construction (used to build the manager
    // in MarkServerReady and to supply the canonical auth source for
    // reload). AuthManager is declared AFTER circuit_breaker_manager_ so
    // destruction runs: proxy_handlers_ (hold AuthManager*) → auth_manager_
    // → circuit_breaker_manager_ → upstream_manager_.
    AUTH_NAMESPACE::AuthConfig auth_config_;
    std::unique_ptr<AUTH_NAMESPACE::AuthManager> auth_manager_;

    // Proxy handlers keyed by (upstream_service_name + normalized prefix).
    // shared_ptr (not unique_ptr) so that route lambdas capture shared
    // ownership — if a later Proxy()/RegisterProxyRoutes() call replaces
    // the entry under the same key (e.g., partial method overlap adding
    // new methods), existing route lambdas still hold the old handler
    // alive until they are themselves replaced or destroyed, avoiding
    // a use-after-free when the handler_ptr inside those lambdas would
    // otherwise dangle.
    std::unordered_map<std::string, std::shared_ptr<ProxyHandler>> proxy_handlers_;

    // Tracks which methods are registered per canonical proxy path.
    // Key: dedup_prefix (e.g., "/api/*"), Value: set of registered methods.
    // Used to detect method-level conflicts before RouteAsync throws.
    std::unordered_map<std::string, std::unordered_set<std::string>> proxy_route_methods_;

    // Pending manual Proxy() registrations — stored when Proxy() is called
    // before Start(), processed in MarkServerReady() after upstream_manager_
    // is created. Each entry is {route_pattern, upstream_service_name}.
    std::vector<std::pair<std::string, std::string>> pending_proxy_routes_;

    // Names of upstream services actually referenced by at least one
    // successfully-registered proxy route (either from
    // RegisterProxyRoutes' JSON auto-registration OR from programmatic
    // HttpServer::Proxy() calls). Used by MarkServerReady to size the
    // async-deferred safety cap: upstreams not referenced here cannot
    // affect request lifetimes and must not be folded into the cap, and
    // upstreams referenced here must be, regardless of whether their
    // JSON config has proxy.route_prefix set.
    std::unordered_set<std::string> proxy_referenced_upstreams_;

    // Recomputes max_async_deferred_sec_ from proxy_referenced_upstreams_.
    // Called from MarkServerReady after all proxy routes are registered.
    void RecomputeAsyncDeferredCap();

    // Auto-register proxy routes from upstream configs at Start() time
    void RegisterProxyRoutes();
};
