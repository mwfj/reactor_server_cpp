#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <cstdint>
#include <algorithm>
#include <limits>

#include "auth/auth_config.h"
#include "http/route_options.h"
#include "net/dns_resolver.h"
#include "observability/observability_config.h"

struct TlsConfig {
    bool enabled = false;
    std::string cert_file;
    std::string key_file;
    std::string min_version = "1.2";
};

struct LogConfig {
    std::string level = "info";
    std::string file;
    size_t max_file_size = 10485760;   // 10 MB
    int max_files = 3;
};

struct Http2Config {
    bool enabled = true;                         // Enable HTTP/2 (h2 + h2c)
    uint32_t max_concurrent_streams = 100;       // RFC 9113 default recommendation
    uint32_t initial_window_size = 65535;         // RFC 9113 default (64 KB - 1)
    uint32_t max_frame_size = 16384;             // RFC 9113 default (16 KB)
    uint32_t max_header_list_size = 65536;       // 64 KB
    // Server push (RFC 9113 §8.4). Default OFF — modern browsers
    // (Chrome, Firefox) have removed client-side support, so this is
    // primarily for tooling, internal RPC clients, or curated deployments.
    // SETTINGS_ENABLE_PUSH semantics: when false the server advertises 0
    // in its preface; when true the entry is OMITTED so nghttp2's local
    // default of 1 applies internally for our PUSH_PROMISE emission.
    bool enable_push = false;

    // Inbound H2 streaming-request body watermarks + WINDOW_UPDATE
    // replenishment threshold. Live-reloadable.
    struct StreamingConfig {
        size_t high_water_bytes = 262144;       // 256 KB
        size_t low_water_bytes  = 65536;        // 64 KB
        size_t window_update_bytes = 32768;     // 32 KB
    };
    StreamingConfig streaming;
};

// Inbound HTTP/1.1 streaming-request body watermarks. Live-reloadable.
struct Http1Config {
    struct StreamingConfig {
        size_t high_water_bytes = 262144;       // 256 KB
        size_t low_water_bytes  = 65536;        // 64 KB
    };
    StreamingConfig streaming;
};

// Per-upstream HTTP/2 client configuration. Distinct from `Http2Config`
// (which governs INBOUND HTTP/2 server settings) — this struct configures
// the OUTBOUND H2 client used by the upstream connection pool. Each upstream
// in `ServerConfig::upstreams` carries its own `Http2UpstreamConfig`.
//
// Field classification (see operator==/LiveEqual + ConfigLoader::ValidateHotReloadable):
//   Restart-only: enabled, prefer  (topology — affects ALPN list / pool layout)
//   Live:         max_concurrent_streams_pref, initial_window_size,
//                 max_frame_size, header_table_size, max_header_list_size,
//                 ping_idle_sec, ping_timeout_sec,
//                 goaway_drain_timeout_sec, saturation_open_pct,
//                 preconnect_watermark_pct
struct Http2UpstreamConfig {
    bool enabled = false;
    std::string prefer = "auto";                 // "auto" | "always" | "never"
    uint32_t max_concurrent_streams_pref = 100;  // local cap on per-connection stream count
    uint32_t initial_window_size = 1048576;      // per-stream initial window (1 MB)
    uint32_t max_frame_size = 16384;             // RFC 9113 default
    uint32_t header_table_size = 4096;           // HPACK dynamic table
    uint32_t max_header_list_size = 65536;       // peer header block cap (64 KB)
    int ping_idle_sec = 60;                      // emit PING after this idle window
    int ping_timeout_sec = 10;                   // close conn if no PONG within this
    int goaway_drain_timeout_sec = 30;           // bound on graceful drain
    int saturation_open_pct = 0;                 // 0 disables saturation routing
    // 0 disables predictive preconnect. Must be in [0, 100]. When > 0,
    // also requires saturation_open_pct > 0 (validator rejects the
    // silent-no-op shape) AND preconnect_watermark_pct < saturation_open_pct
    // (the prediction must fire BEFORE saturation actually trips).
    int preconnect_watermark_pct = 0;

    // Outbound H2 streaming-request body watermarks. Live-reloadable;
    // not part of LiveEqual. nghttp2 auto-manages WINDOW_UPDATE so no
    // window_update_bytes here (unlike inbound Http2Config::StreamingConfig).
    struct StreamingOutboundConfig {
        size_t high_water_bytes = 262144;
        size_t low_water_bytes  = 65536;
    };
    StreamingOutboundConfig streaming;

    // Full equality: every field. Used by tests + serialization round-trips.
    bool operator==(const Http2UpstreamConfig& o) const {
        return enabled == o.enabled && prefer == o.prefer &&
               max_concurrent_streams_pref == o.max_concurrent_streams_pref &&
               initial_window_size == o.initial_window_size &&
               max_frame_size == o.max_frame_size &&
               header_table_size == o.header_table_size &&
               max_header_list_size == o.max_header_list_size &&
               ping_idle_sec == o.ping_idle_sec &&
               ping_timeout_sec == o.ping_timeout_sec &&
               goaway_drain_timeout_sec == o.goaway_drain_timeout_sec &&
               saturation_open_pct == o.saturation_open_pct &&
               preconnect_watermark_pct == o.preconnect_watermark_pct &&
               streaming.high_water_bytes == o.streaming.high_water_bytes &&
               streaming.low_water_bytes  == o.streaming.low_water_bytes;
    }
    bool operator!=(const Http2UpstreamConfig& o) const { return !(*this == o); }

    // Restart-only equality: compares ONLY topology fields. Used by
    // `UpstreamConfig::operator==` once the live-H2 reload propagation path
    // lands so a SIGHUP touching only live H2 fields doesn't trip the
    // outer "restart required" warning.
    bool LiveEqual(const Http2UpstreamConfig& o) const {
        return enabled == o.enabled && prefer == o.prefer;
    }

    // Smallest cadence-relevant H2 timer in seconds, or INT_MAX when
    // disabled. The INT_MAX sentinel lets callers fold this into a
    // running std::min without a per-site `if (enabled)` guard.
    int MinCadenceSec() const {
        if (!enabled) return std::numeric_limits<int>::max();
        int m = ping_idle_sec > 0 ? ping_idle_sec
                                  : std::numeric_limits<int>::max();
        if (ping_timeout_sec > 0) m = std::min(m, ping_timeout_sec);
        if (goaway_drain_timeout_sec > 0) {
            m = std::min(m, goaway_drain_timeout_sec);
        }
        return m;
    }
};

struct UpstreamTlsConfig {
    bool enabled = false;
    std::string ca_file;
    bool verify_peer = true;
    std::string sni_hostname;
    std::string min_version = "1.2";

    bool operator==(const UpstreamTlsConfig& o) const {
        return enabled == o.enabled && ca_file == o.ca_file &&
               verify_peer == o.verify_peer && sni_hostname == o.sni_hostname &&
               min_version == o.min_version;
    }
    bool operator!=(const UpstreamTlsConfig& o) const { return !(*this == o); }
};

struct UpstreamPoolConfig {
    int max_connections = 64;
    int max_idle_connections = 16;
    int connect_timeout_ms = 5000;
    int idle_timeout_sec = 90;
    int max_lifetime_sec = 3600;
    int max_requests_per_conn = 0;

    bool operator==(const UpstreamPoolConfig& o) const {
        return max_connections == o.max_connections &&
               max_idle_connections == o.max_idle_connections &&
               connect_timeout_ms == o.connect_timeout_ms &&
               idle_timeout_sec == o.idle_timeout_sec &&
               max_lifetime_sec == o.max_lifetime_sec &&
               max_requests_per_conn == o.max_requests_per_conn;
    }
    bool operator!=(const UpstreamPoolConfig& o) const { return !(*this == o); }
};

struct ProxyHeaderRewriteConfig {
    bool set_x_forwarded_for = true;      // Append client IP to X-Forwarded-For
    bool set_x_forwarded_proto = true;     // Set X-Forwarded-Proto
    bool set_via_header = true;            // Add Via header
    bool rewrite_host = true;             // Rewrite Host to upstream address

    bool operator==(const ProxyHeaderRewriteConfig& o) const {
        return set_x_forwarded_for == o.set_x_forwarded_for &&
               set_x_forwarded_proto == o.set_x_forwarded_proto &&
               set_via_header == o.set_via_header &&
               rewrite_host == o.rewrite_host;
    }
    bool operator!=(const ProxyHeaderRewriteConfig& o) const { return !(*this == o); }
};

struct ProxyRetryConfig {
    int max_retries = 0;                    // 0 = no retries
    bool retry_on_connect_failure = true;   // Retry when pool checkout connect fails
    bool retry_on_5xx = false;              // Retry on 5xx response from upstream
    bool retry_on_timeout = false;          // Retry on response timeout
    bool retry_on_disconnect = true;        // Retry when upstream closes mid-response
    bool retry_non_idempotent = false;      // Retry POST/PATCH/DELETE (dangerous)

    bool operator==(const ProxyRetryConfig& o) const {
        return max_retries == o.max_retries &&
               retry_on_connect_failure == o.retry_on_connect_failure &&
               retry_on_5xx == o.retry_on_5xx &&
               retry_on_timeout == o.retry_on_timeout &&
               retry_on_disconnect == o.retry_on_disconnect &&
               retry_non_idempotent == o.retry_non_idempotent;
    }
    bool operator!=(const ProxyRetryConfig& o) const { return !(*this == o); }
};

struct ProxyConfig {
    // Response relay mode:
    //   auto   = choose at runtime from framing / content type / size
    //   always = keep buffered HttpResponse completion
    //   never  = prefer streaming whenever the downstream protocol allows it
    std::string buffering = "auto";
    // High-water mark, in bytes, for protocol-native downstream streaming
    // buffers. Crossing this limit pauses upstream reads until the downstream
    // side drains back to low-water.
    uint32_t relay_buffer_limit_bytes = 1048576;
    // In buffering=auto mode, fixed-length responses above this size stream
    // instead of buffering. Units: bytes. Must be <= relay_buffer_limit_bytes.
    uint32_t auto_stream_content_length_threshold_bytes = 262144;
    // Body-phase idle timeout after upstream headers have been received.
    // Units: seconds. 0 disables. Ignored for SSE (`text/event-stream`).
    uint32_t stream_idle_timeout_sec = 30;
    // Absolute body-phase streaming budget after headers have been received.
    // Units: seconds. 0 disables.
    uint32_t stream_max_duration_sec = 0;
    // HTTP/1.0 fallback when runtime relay mode selects streaming:
    //   close  = stream with EOF framing and close the connection
    //   buffer = force buffered completion instead
    std::string h10_streaming = "close";
    // Forward upstream trailers to the downstream protocol when supported.
    // HTTP/1.1 chunked streaming can emit them; HTTP/2 currently warns and
    // drops them because trailer submission is not wired yet.
    bool forward_trailers = false;

    // Response timeout: max time to wait for upstream response headers
    // after request is fully sent. 0 = disabled (no deadline). Otherwise
    // must be >= 1000 (timer scan has 1s resolution).
    int response_timeout_ms = 30000;  // 30 seconds

    // Route pattern prefix to match (e.g., "/api/users")
    // Supports the existing pattern syntax: "/api/:version/users/*path"
    std::string route_prefix;

    // Strip the route prefix before forwarding to upstream.
    // Example: route_prefix="/api/v1", strip_prefix=true
    //   client: GET /api/v1/users/123 -> upstream: GET /users/123
    // When false: upstream sees the full original path.
    bool strip_prefix = false;

    // Methods to proxy. Empty = all methods.
    std::vector<std::string> methods;

    // Header rewriting configuration
    ProxyHeaderRewriteConfig header_rewrite;

    // Retry policy configuration
    ProxyRetryConfig retry;

    // Inline auth policy for this proxy (applies_to derived from route_prefix).
    // Reload-propagated via AuthManager::Reload — EXCLUDED from operator==
    // below so that proxy.auth edits do not trip the outer "restart required"
    // warning in HttpServer::Reload(). See `DEVELOPMENT_RULES.md` under
    // *"Live-reloadable config fields in restart-required equality operators
    // — ordering matters"* for the rationale.
    AUTH_NAMESPACE::AuthPolicy auth;

    // Excludes `auth` — auth policy edits are live-reloadable via
    // `AuthManager::Reload`, which `HttpServer::Reload` invokes on every
    // reload. Topology fields (response_timeout_ms, route_prefix,
    // strip_prefix, methods, header_rewrite, retry) remain restart-only.
    //
    // Contract: a config pair that differs ONLY in auth fields must compare
    // EQUAL so the outer reload doesn't fire a spurious warn. This is the
    // same discipline used by `UpstreamConfig::operator==` for the
    // `circuit_breaker` field.
    bool operator==(const ProxyConfig& o) const {
        return buffering == o.buffering &&
               relay_buffer_limit_bytes == o.relay_buffer_limit_bytes &&
               auto_stream_content_length_threshold_bytes ==
                   o.auto_stream_content_length_threshold_bytes &&
               stream_idle_timeout_sec == o.stream_idle_timeout_sec &&
               stream_max_duration_sec == o.stream_max_duration_sec &&
               h10_streaming == o.h10_streaming &&
               forward_trailers == o.forward_trailers &&
               response_timeout_ms == o.response_timeout_ms &&
               route_prefix == o.route_prefix &&
               strip_prefix == o.strip_prefix &&
               methods == o.methods &&
               header_rewrite == o.header_rewrite &&
               retry == o.retry;
    }
    bool operator!=(const ProxyConfig& o) const { return !(*this == o); }
};

struct CircuitBreakerConfig {
    bool enabled = false;                      // Opt-in; off by default
    bool dry_run = false;                      // Compute + log, but do not reject

    // Trip conditions (ORed). Either alone is sufficient.
    int consecutive_failure_threshold = 5;     // Trip after N consecutive failures
    int failure_rate_threshold = 50;           // Trip when fail_rate >= N percent
    int minimum_volume = 20;                   // Required window volume before
                                               // failure_rate is consulted
    int window_seconds = 10;                   // Sliding-window duration

    // HALF_OPEN admission
    int permitted_half_open_calls = 5;

    // Recovery timing. open_duration = min(base * 2^consecutive_trips, max).
    int base_open_duration_ms = 5000;
    int max_open_duration_ms = 60000;

    // Safety valve (future-proof for load-balanced services; no-op v1).
    int max_ejection_percent_per_host_set = 50;

    // Retry budget (orthogonal to the breaker). Caps concurrent retries to
    // max(retry_budget_min_concurrency, in_flight * retry_budget_percent/100).
    // Wired into the request path via ProxyTransaction's retry-budget
    // gate in MaybeRetry; also read by
    // CircuitBreakerHost to construct its owned RetryBudget.
    int retry_budget_percent = 20;
    int retry_budget_min_concurrency = 3;

    bool operator==(const CircuitBreakerConfig& o) const {
        return enabled == o.enabled &&
               dry_run == o.dry_run &&
               consecutive_failure_threshold == o.consecutive_failure_threshold &&
               failure_rate_threshold == o.failure_rate_threshold &&
               minimum_volume == o.minimum_volume &&
               window_seconds == o.window_seconds &&
               permitted_half_open_calls == o.permitted_half_open_calls &&
               base_open_duration_ms == o.base_open_duration_ms &&
               max_open_duration_ms == o.max_open_duration_ms &&
               max_ejection_percent_per_host_set == o.max_ejection_percent_per_host_set &&
               retry_budget_percent == o.retry_budget_percent &&
               retry_budget_min_concurrency == o.retry_budget_min_concurrency;
    }
    bool operator!=(const CircuitBreakerConfig& o) const { return !(*this == o); }
};

struct UpstreamConfig {
    std::string name;
    std::string host;
    int port = 80;
    UpstreamTlsConfig tls;
    UpstreamPoolConfig pool;
    ProxyConfig proxy;
    CircuitBreakerConfig circuit_breaker;
    Http2UpstreamConfig http2;
    // Per-upstream request-handling mode. Defaults to Streaming for proxy
    // routes (HttpServer::RegisterProxyRoutes auto-override); operators
    // may pin to Buffered via config. Restart-only — see operator==.
    http::RouteRequestMode request_mode = http::RouteRequestMode::Streaming;

    // Excludes `circuit_breaker` — breaker fields are live-reloadable via
    // `CircuitBreakerManager::Reload`, which `HttpServer::Reload` invokes on
    // every reload. Topology fields (name, host, port, tls, pool,
    // proxy) remain restart-only; a mismatch here triggers the
    // "restart required" warning in the outer reload.
    //
    // H2 live fields (ping timers, window sizes, etc.) are propagated via
    // CommitHttp2Snapshots (wired into both MarkServerReady and Reload).
    // LiveEqual compares only the restart-only H2 fields (enabled, prefer),
    // so a SIGHUP that changes only ping_idle_sec no longer fires a
    // spurious "restart required" warning.
    //
    // `request_mode` is restart-only — buffered ↔ streaming flip requires
    // re-registering the route with new RouteOptions, which only happens
    // at startup via RegisterProxyRoutes.
    bool operator==(const UpstreamConfig& o) const {
        return name == o.name && host == o.host && port == o.port &&
               tls == o.tls && pool == o.pool && proxy == o.proxy &&
               http2.LiveEqual(o.http2) &&
               request_mode == o.request_mode;
    }
    bool operator!=(const UpstreamConfig& o) const { return !(*this == o); }
};

struct RateLimitZoneConfig {
    std::string name;                        // Zone name (for logging/stats)
    double rate = 0;                         // Requests per second
    int64_t capacity = 0;                    // Max burst size (bucket capacity)
    std::string key_type = "client_ip";      // Key extraction method
    int max_entries = 100000;                // Max tracked keys (LRU eviction beyond this)
    std::vector<std::string> applies_to;     // Route prefixes (empty = all routes)

    bool operator==(const RateLimitZoneConfig& o) const {
        return name == o.name && rate == o.rate && capacity == o.capacity &&
               key_type == o.key_type && max_entries == o.max_entries &&
               applies_to == o.applies_to;
    }
    bool operator!=(const RateLimitZoneConfig& o) const { return !(*this == o); }
};

struct RateLimitConfig {
    bool enabled = false;                    // Master switch
    bool dry_run = false;                    // Shadow mode: log but don't enforce
    int status_code = 429;                   // HTTP status for rejected requests
    bool include_headers = true;             // Include RateLimit-* response headers
    std::vector<RateLimitZoneConfig> zones;  // Rate limit zones/rules

    bool operator==(const RateLimitConfig& o) const {
        return enabled == o.enabled && dry_run == o.dry_run &&
               status_code == o.status_code && include_headers == o.include_headers &&
               zones == o.zones;
    }
    bool operator!=(const RateLimitConfig& o) const { return !(*this == o); }
};

// NOTE: When adding fields, also update ConfigLoader::LoadFromString(),
// ConfigLoader::ToJson(), ConfigLoader::ApplyEnvOverrides(), and
// ConfigLoader::Validate() to keep serialization/deserialization in sync.
struct ServerConfig {
    std::string bind_host = "127.0.0.1";
    int bind_port = 8080;
    TlsConfig tls;
    LogConfig log;
    int max_connections = 10000;
    int idle_timeout_sec = 300;
    int worker_threads = 3;
    size_t max_header_size = 8192;       // 8 KB
    size_t max_body_size = 1048576;      // 1 MB
    size_t max_ws_message_size = 16777216; // 16 MB
    int request_timeout_sec = 30;
    // Drain budget (in seconds) used by HttpServer::Stop. Reused as a
    // deadline at multiple points in the shutdown sequence — sizing
    // pod terminationGracePeriodSeconds against this knob requires
    // accounting for every reuse, not just one application.
    //
    // Wall-clock worst case across the off-thread Stop() path:
    //   1. WaitForH2Drain                    — up to T  (H2 GOAWAY drain)
    //   2. WS close handshake                — up to 6s (fixed)
    //   3. HTTP/1 output flush               — up to 2s (H1_DRAIN_TIMEOUT_SEC)
    //   4. Late-H2 re-check (WaitForH2Drain) — up to T  (slow h2c classify)
    //   5. Post-protocol drain section       — up to T  (single deadline:
    //                                                    obs-flush +
    //                                                    upstream-drain +
    //                                                    kill+obs-stop +
    //                                                    post-upstream H1)
    // Sum: 3 × T + 8s. Step 5 itself is a single shutdown_deadline =
    // now + T anchor (steps 5a-5d each consume from the same budget
    // via budget_left()), but T is also the per-call deadline for
    // steps 1 and 4.
    //
    // Pod terminationGracePeriodSeconds: size as 3 × T + 8s + margin.
    //
    // 0 = immediate (skip waits, force-close); negative rejected by Validate.
    int shutdown_drain_timeout_sec = 30;
    Http2Config http2;
    Http1Config http1;
    std::vector<UpstreamConfig> upstreams;
    RateLimitConfig rate_limit;
    AUTH_NAMESPACE::AuthConfig auth;
    NET_DNS_NAMESPACE::DnsConfig dns;
    OBSERVABILITY_NAMESPACE::ObservabilityConfig observability;
};
