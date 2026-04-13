# Configuration and Logging

JSON-based configuration loading with environment variable overrides and structured logging via spdlog.

## Configuration

### ServerConfig

Three config structs with sensible defaults:

```cpp
struct TlsConfig {
    bool enabled = false;
    std::string cert_file;
    std::string key_file;
    std::string min_version = "1.2";
};

struct LogConfig {
    std::string level = "info";     // trace, debug, info, warn, error, critical
    std::string file;               // empty = stdout only
    size_t max_file_size = 10485760; // 10 MB
    int max_files = 3;
};

struct Http2Config {
    bool enabled = true;                   // Enable HTTP/2 (h2 + h2c)
    uint32_t max_concurrent_streams = 100; // Max simultaneous streams
    uint32_t initial_window_size = 65535;  // Flow control window (64 KB - 1)
    uint32_t max_frame_size = 16384;       // Max frame payload (16 KB)
    uint32_t max_header_list_size = 65536; // Max header block size (64 KB)
};

struct ServerConfig {
    std::string bind_host = "127.0.0.1";
    int bind_port = 8080;
    TlsConfig tls;
    LogConfig log;
    Http2Config http2;
    int max_connections = 10000;
    int idle_timeout_sec = 300;      // 5 minutes
    int worker_threads = 3;
    size_t max_header_size = 8192;       // 8 KB
    size_t max_body_size = 1048576;      // 1 MB
    size_t max_ws_message_size = 16777216; // 16 MB
    int request_timeout_sec = 30;        // Slowloris protection
    int shutdown_drain_timeout_sec = 30; // Max wait for in-flight H2 streams
};
```

### Loading Configuration

```cpp
#include "config/config_loader.h"

// From JSON file
ServerConfig config = ConfigLoader::LoadFromFile("config/server.json");

// From JSON string
ServerConfig config = ConfigLoader::LoadFromString(R"({"bind_port": 9090})");

// Default values
ServerConfig config = ConfigLoader::Default();

// Apply environment variable overrides (takes precedence)
ConfigLoader::ApplyEnvOverrides(config);

// Validate (throws on invalid)
ConfigLoader::Validate(config);

// Use with HttpServer
HttpServer server(config);
```

### JSON Config File

Reference config at `config/server.example.json`:

```json
{
    "bind_host": "127.0.0.1",
    "bind_port": 8080,
    "max_connections": 10000,
    "idle_timeout_sec": 300,
    "worker_threads": 3,
    "max_header_size": 8192,
    "max_body_size": 1048576,
    "max_ws_message_size": 16777216,
    "request_timeout_sec": 30,
    "tls": {
        "enabled": false,
        "cert_file": "",
        "key_file": "",
        "min_version": "1.2"
    },
    "http2": {
        "enabled": true,
        "max_concurrent_streams": 100,
        "initial_window_size": 65535,
        "max_frame_size": 16384,
        "max_header_list_size": 65536
    },
    "log": {
        "level": "info",
        "file": "",
        "max_file_size": 10485760,
        "max_files": 3
    }
}
```

Missing fields in the JSON file retain their default values. When `log.file` is empty (default), the server logs to console only. Set to a path (e.g., `"logs/reactor.log"`) to enable file logging with date-based rotation. Set `max_files` to `1` for external logrotate compatibility (no automatic rotation).

### Environment Variable Overrides

Environment variables take precedence over JSON file values:

| Variable | Config Field | Type |
|----------|-------------|------|
| `REACTOR_BIND_HOST` | `bind_host` | string |
| `REACTOR_BIND_PORT` | `bind_port` | int |
| `REACTOR_TLS_ENABLED` | `tls.enabled` | bool (`true`/`false`) |
| `REACTOR_TLS_CERT` | `tls.cert_file` | string |
| `REACTOR_TLS_KEY` | `tls.key_file` | string |
| `REACTOR_LOG_LEVEL` | `log.level` | string |
| `REACTOR_LOG_FILE` | `log.file` | string |
| `REACTOR_MAX_CONNECTIONS` | `max_connections` | int |
| `REACTOR_IDLE_TIMEOUT` | `idle_timeout_sec` | int |
| `REACTOR_WORKER_THREADS` | `worker_threads` | int |
| `REACTOR_REQUEST_TIMEOUT` | `request_timeout_sec` | int |
| `REACTOR_SHUTDOWN_DRAIN_TIMEOUT` | `shutdown_drain_timeout_sec` | int |
| `REACTOR_HTTP2_ENABLED` | `http2.enabled` | bool (`1`/`true`/`yes`) |
| `REACTOR_HTTP2_MAX_CONCURRENT_STREAMS` | `http2.max_concurrent_streams` | int |
| `REACTOR_HTTP2_INITIAL_WINDOW_SIZE` | `http2.initial_window_size` | int |
| `REACTOR_HTTP2_MAX_FRAME_SIZE` | `http2.max_frame_size` | int |
| `REACTOR_HTTP2_MAX_HEADER_LIST_SIZE` | `http2.max_header_list_size` | int |

### Upstream Configuration

Upstream connection pools are configured via the `upstreams` array in the JSON config. Each entry defines a named backend service with its own pool and optional TLS settings.

```json
{
    "upstreams": [
        {
            "name": "api-backend",
            "host": "10.0.1.5",
            "port": 8080,
            "tls": {
                "enabled": false
            },
            "pool": {
                "max_connections": 64,
                "max_idle_connections": 16,
                "connect_timeout_ms": 5000,
                "idle_timeout_sec": 90,
                "max_lifetime_sec": 3600,
                "max_requests_per_conn": 0
            }
        },
        {
            "name": "auth-service",
            "host": "auth.internal",
            "port": 443,
            "tls": {
                "enabled": true,
                "ca_file": "/etc/ssl/ca-bundle.crt",
                "verify_peer": true,
                "sni_hostname": "auth.internal",
                "min_version": "1.2"
            },
            "pool": {
                "max_connections": 32,
                "connect_timeout_ms": 3000
            }
        }
    ]
}
```

**Pool fields** (`pool.*`):

| Field | Default | Description |
|-------|---------|-------------|
| `max_connections` | 64 | Total connections per service (split across dispatchers) |
| `max_idle_connections` | 16 | Max idle connections to keep warm |
| `connect_timeout_ms` | 5000 | TCP connect timeout in milliseconds |
| `idle_timeout_sec` | 90 | Close idle connections after this many seconds |
| `max_lifetime_sec` | 3600 | Max connection age before forced rotation (0 = unlimited) |
| `max_requests_per_conn` | 0 | Max requests per connection before rotation (0 = unlimited) |

**Upstream TLS fields** (`tls.*`):

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | false | Enable TLS for upstream connections |
| `ca_file` | "" | CA certificate bundle for peer verification |
| `verify_peer` | true | Verify upstream server certificate |
| `sni_hostname` | "" | SNI hostname for TLS handshake |
| `min_version` | "1.2" | Minimum TLS version ("1.2" or "1.3") |

**Note:** Upstream configuration changes require a server restart — pools are built once during `Start()` and cannot be rebuilt at runtime.

### Proxy Route Configuration

Each upstream entry may include an optional `proxy` section to auto-register a proxy route that forwards matching requests to the backend. When `proxy.route_prefix` is non-empty, `HttpServer::Start()` registers the route automatically — no handler code is needed.

```json
{
    "upstreams": [
        {
            "name": "api-backend",
            "host": "10.0.1.5",
            "port": 8080,
            "pool": { "max_connections": 64 },
            "proxy": {
                "route_prefix": "/api/v1",
                "strip_prefix": true,
                "response_timeout_ms": 5000,
                "methods": ["GET", "POST", "PUT", "DELETE"],
                "header_rewrite": {
                    "set_x_forwarded_for": true,
                    "set_x_forwarded_proto": true,
                    "set_via_header": true,
                    "rewrite_host": true
                },
                "retry": {
                    "max_retries": 2,
                    "retry_on_connect_failure": true,
                    "retry_on_5xx": false,
                    "retry_on_timeout": false,
                    "retry_on_disconnect": true,
                    "retry_non_idempotent": false
                }
            }
        }
    ]
}
```

**Proxy fields** (`proxy.*`):

| Field | Default | Description |
|-------|---------|-------------|
| `route_prefix` | "" | Route pattern to match (empty = disabled). Supports full pattern syntax: `/api/v1`, `/api/:version/*path`, `/users/:id([0-9]+)`. Patterns ending in `/*rest` match anything under the prefix. |
| `strip_prefix` | false | When `true`, strip the static portion of `route_prefix` before forwarding. Example: `route_prefix="/api/v1"`, `strip_prefix=true` → client `GET /api/v1/users/123` reaches upstream as `GET /users/123`. |
| `response_timeout_ms` | 30000 | Max time to wait for upstream response headers after the request is fully sent. **Must be `0` or `>= 1000`** (timer scan has 1 s resolution). `0` disables the per-request deadline and lifts the async safety cap for this request only — use with caution, long-running handlers still respect the server-wide `max_async_deferred_sec_`. |
| `methods` | `[]` | Methods to proxy. Empty array means all methods. Methods listed here are auto-registered on the route; conflicts with any user-registered async route on the same `(method, pattern)` are detected at `Start()` and raise `std::invalid_argument`. |

**Proxy header rewrite fields** (`proxy.header_rewrite.*`):

| Field | Default | Description |
|-------|---------|-------------|
| `set_x_forwarded_for` | true | Append the client IP to `X-Forwarded-For` (preserves any upstream chain) |
| `set_x_forwarded_proto` | true | Set `X-Forwarded-Proto` to `http` or `https` based on the client connection |
| `set_via_header` | true | Add the server's `Via` header per RFC 7230 §5.7.1 |
| `rewrite_host` | true | Rewrite the outgoing `Host` header to the upstream's authority (off = forward client's Host verbatim) |

Hop-by-hop headers listed in RFC 7230 §6.1 (`Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailers`, `Transfer-Encoding`, `Upgrade`) are always stripped from both the outgoing request and the returned response.

**Proxy retry fields** (`proxy.retry.*`):

| Field | Default | Description |
|-------|---------|-------------|
| `max_retries` | 0 | Max retry attempts (0 = no retries). Backoff uses full jitter (25 ms base, 250 ms cap) with a 1 ms minimum: `random(1, min(250, 25 * 2^attempt))`. The first retry is immediate for connection-level failures (`retry_on_connect_failure`, `retry_on_disconnect`) so stale keep-alive recovery is fast; response-level failures (`retry_on_5xx`, `retry_on_timeout`) always back off to give the upstream breathing room. Retries are scheduled via the dispatcher's delayed task queue — never a sleep on the event loop thread. |
| `retry_on_connect_failure` | true | Retry when the pool checkout fails to establish a TCP/TLS connection |
| `retry_on_5xx` | false | Retry when the upstream returns a 5xx response (headers only — once the body starts streaming to the client, retries stop) |
| `retry_on_timeout` | false | Retry when the response deadline fires before headers arrive |
| `retry_on_disconnect` | true | Retry when the upstream closes the connection before any response bytes are sent to the client |
| `retry_non_idempotent` | false | Allow retries on POST/PATCH/DELETE (dangerous — can duplicate side effects; default safe methods only) |

**Notes:**

- Retries never fire after any response bytes have been sent to the downstream client.
- `proxy.route_prefix` conflicts — two upstreams auto-registering the same pattern, or an upstream conflicting with a user-registered async route on the same `(method, pattern)` — are rejected at `Start()` with `std::invalid_argument`.
- The proxy engine is built on the async route framework: per-request deadlines, client abort propagation, and pool checkout cancellation are all handled by `ProxyTransaction::Cancel()`. See [docs/http.md](http.md) for the programmatic API.

### Validation

`ConfigLoader::Validate()` checks:
- Port in valid range (0-65535, 0 = OS-assigned ephemeral port)
- Worker threads > 0
- If TLS enabled, cert_file and key_file must be non-empty
- shutdown_drain_timeout_sec: 0-300 (0 = immediate close)
- If HTTP/2 enabled: max_concurrent_streams >= 1, initial_window_size 1 to 2^31-1, max_frame_size 16384 to 16777215, max_header_list_size >= 1

Throws `std::invalid_argument` on validation failure.

### Type Safety

- `size_t` fields (`max_header_size`, `max_body_size`, `max_ws_message_size`) use `is_number_unsigned()` to reject negative JSON values (prevents unsigned wrap-around)
- Integer env vars use `std::stoi()` (not `atoi()`) for proper error detection on non-numeric input

## Rate Limiting

Request rate limiting is provided as middleware via a token bucket algorithm. Zones are defined in the `rate_limit` config section and can be hot-reloaded via SIGHUP.

### Configuration Example

```json
{
  "rate_limit": {
    "enabled": true,
    "dry_run": false,
    "status_code": 429,
    "include_headers": true,
    "zones": [
      {
        "name": "per_ip",
        "rate": 100,
        "capacity": 200,
        "key_type": "client_ip",
        "max_entries": 100000,
        "applies_to": []
      },
      {
        "name": "per_api_key",
        "rate": 50,
        "capacity": 100,
        "key_type": "header:X-API-Key",
        "max_entries": 50000,
        "applies_to": ["/api/"]
      }
    ]
  }
}
```

### Field Reference

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | bool | Master switch. When false, the middleware is a no-op (one atomic load per request). |
| `dry_run` | bool | Shadow mode: log denials but allow all requests through. `Retry-After` is stripped on allowed dry-run responses to prevent client backoff. |
| `status_code` | int | HTTP status for rejected requests (400-599). Response body is `"{code} {reason}"` derived from the standard reason phrase. |
| `include_headers` | bool | Emit `RateLimit-Policy` / `RateLimit` / `Retry-After` response headers per IETF draft-ietf-httpapi-ratelimit-headers-10. |
| `zones[].name` | string | Zone name. Must be unique and non-empty. Used in logs/stats. |
| `zones[].rate` | double | Sustained rate in requests/second. Range `[0.001, 1e9]`. Values below 0.001 truncate to 0 and would starve the bucket. |
| `zones[].capacity` | int64 | Max burst (bucket capacity). Range `[1, 1e12]`. |
| `zones[].key_type` | string | Key extractor: `client_ip`, `path`, `header:<name>`, `client_ip+path`, or `client_ip+header:<name>`. Bare `header:` (no name) is rejected. |
| `zones[].max_entries` | int | Soft cap on tracked keys per zone. Must be `>= 16` (the shard count). Runtime cap is rounded down to a multiple of the shard count. Enforced synchronously on insert to protect against high-cardinality bursts. |
| `zones[].applies_to` | array | Route prefixes the zone applies to. Empty = all routes. Matching respects segment boundaries (`/api` matches `/api` and `/api/users`, NOT `/apis`). Empty strings are rejected. |

### Environment Overrides

```
REACTOR_RATE_LIMIT_ENABLED=true
REACTOR_RATE_LIMIT_DRY_RUN=false
REACTOR_RATE_LIMIT_STATUS_CODE=429
```

Zone configuration (the `zones[]` array) is JSON-only — env vars cover only the global flags.

### Response Headers (IETF draft-10)

On every response (when `include_headers` is true) and at least one zone applied:

```
RateLimit-Policy: {capacity};w={window_seconds}
RateLimit: limit={L}, remaining={R}, reset={T}
```

Where `window_seconds = ceil(capacity / rate)` — the time to refill from empty. For example, `rate=10, capacity=100` emits `RateLimit-Policy: 100;w=10` (100 requests per 10-second window). Zones that did not govern the request (applies_to miss or empty extracted key) do NOT drive headers.

On denied responses (unless `dry_run=true`):

```
Retry-After: {seconds}
```

`Retry-After` reflects the first-denying zone (iteration stops there to avoid unnecessary token consumption in later zones). Operators should list narrower/shorter-retry zones first in the config.

### Hot-Reload Semantics

Live-reloadable fields (via SIGHUP):
- Scalar flags: `enabled`, `dry_run`, `status_code`, `include_headers`
- Zone rate/capacity/max_entries/applies_to: applied via atomic policy-snapshot swap
- Add/remove zones: atomic zone-list swap
- Zones matched by name + key_type are reused (preserve bucket state)
- `key_type` change on an existing zone name → new zone (old state discarded)

In-flight requests see consistent snapshots — the old policy/zone-list stays alive until all readers release it.

### Operational Notes

- Config validation is applied during reload — bad `rate_limit` (rate≤0, unknown key_type, duplicate names, empty applies_to entry, etc.) is rejected and the running config is kept.
- Reducing `max_entries` drastically (e.g., 100k → 16) can cause a one-time latency spike on the next insert into each over-capacity shard (synchronous eviction). Rare in practice.
- The rate limit middleware is always registered at startup even when disabled, so enabling it via reload never requires a restart.

## Structured Logging

### API

```cpp
#include "log/logger.h"
#include "log/log_utils.h"  // SanitizePath helper

// Create log directory if needed
logging::EnsureLogDir("logs");

// Initialize (call once, before spawning threads)
// File path uses date-based naming: "logs/reactor.log" →
//   "logs/reactor-2026-03-30.log" (actual file)
logging::Init(
    "reactor",                     // Logger name
    spdlog::level::info,          // Minimum level
    "logs/reactor.log",           // Log file path (empty = stdout only)
    10485760,                     // Max file size per log file (10 MB)
    3                             // Max total log files to keep
);

// System markers for visual separation
logging::WriteMarker("SERVER START");

// Use throughout the application
logging::Get()->info("Server starting on {}:{}", host, port);
logging::Get()->debug("New connection fd={}", fd);
logging::Get()->warn("Connection limit reached: {}", max_connections);
logging::Get()->error("TLS handshake failed fd={}", fd);

// Periodic size-based rotation check
logging::CheckRotation();

// Log file reopen (e.g., on SIGHUP)
logging::Reopen();

// Shutdown
logging::WriteMarker("SERVER STOP");
logging::Shutdown();
```

### Date-Based File Naming

Log files use the naming pattern `{prefix}-{YYYY-MM-DD}[-{seq}].log`:

```
logs/reactor-2026-03-30.log       (first file of the day)
logs/reactor-2026-03-30-1.log     (after first size rotation)
logs/reactor-2026-03-30-2.log     (after second rotation)
```

On restart, the logger appends to the latest non-full file for today's date. The `logs/` directory is created automatically when the server starts (if `log.file` has a directory component).

### Log Levels

| Level | Use Case |
|-------|----------|
| `trace` | Detailed debugging (frame bytes, buffer contents, timer ticks) |
| `debug` | Construction, internal invocations, state transitions |
| `info` | Server lifecycle, key trajectory stages, request received |
| `warn` | Limits exceeded, timeouts, non-fatal operational errors |
| `error` | Logic failures that don't crash the system |
| `critical` | System or critical-component crash |

### Output Format

```
[2026-03-30 12:34:56.789] [reactor] [info] ================================ SERVER START ================================
[2026-03-30 12:34:56.790] [reactor] [info] reactor_server version 0.1.0 starting
[2026-03-30 12:34:56.791] [reactor] [debug] New connection fd=5
[2026-03-30 12:34:57.001] [reactor] [warn] Request timeout fd=5
[2026-03-30 12:34:57.002] [reactor] [error] TLS handshake failed fd=5
```

### Trace Correlation

All log entries include contextual identifiers for correlation:
- **Connection**: `fd=N` (file descriptor)
- **HTTP/2 streams**: `stream=N`
- **Requests**: method + sanitized path (no query params)

### Sensitive Data Protection

Use `logging::SanitizePath(path)` to strip query parameters and fragments from URLs before logging. Never log API keys, authorization headers, cookie values, message content, or full URLs with query parameters.

### Sinks

- **Console sink**: Active by default, with color output (disabled in daemon mode)
- **File sink**: Configured via `log.file` in ServerConfig
  - Uses `basic_file_sink_mt` with date-based path resolution
  - Size-based rotation via `CheckRotation()` (called periodically)
  - Default file: `logs/reactor.log` → `logs/reactor-{date}.log`

### Thread Safety

- `Init()` must be called before spawning threads (sets up spdlog registry)
- `Get()` is thread-safe after initialization
- `CheckRotation()` is thread-safe (acquires internal mutex)
- If `Init()` not called, `Get()` returns spdlog's default logger

## Third-Party Dependencies

| Library | Version | Path | Purpose |
|---------|---------|------|---------|
| nlohmann/json | 3.11.3 | `third_party/nlohmann/json.hpp` | Single-header JSON parsing |
| spdlog | 1.15.1 | `third_party/spdlog/` | Header-only structured logging |

Both are MIT-licensed, vendored in the repository.
