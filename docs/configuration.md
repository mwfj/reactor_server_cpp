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
| `REACTOR_RATE_LIMIT_ENABLED` | `rate_limit.enabled` | bool (`1`/`true`/`yes`) |
| `REACTOR_RATE_LIMIT_DRY_RUN` | `rate_limit.dry_run` | bool (`1`/`true`/`yes`) |
| `REACTOR_RATE_LIMIT_STATUS_CODE` | `rate_limit.status_code` | int (400-599) |

Per-zone rate limit config (the `zones[]` array) is JSON-only — env vars cover the global toggles only.

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
- All `int`-typed config fields go through a strict integer parser (`ParseStrictInt`) that rejects:
  - Non-integer JSON (`true`, `1.9`, `"42"`, `null`, arrays, objects)
  - Values outside `[INT_MIN, INT_MAX]` — without this, `nlohmann/json`'s `.get<int>()` silently wraps oversized unsigned values (e.g. `{"bind_port": 4294967297}` would load as port 1)
  - Applies to top-level fields (`bind_port`, `max_connections`, `idle_timeout_sec`, `worker_threads`, `request_timeout_sec`, `shutdown_drain_timeout_sec`), nested integers (`log.max_files`, `rate_limit.status_code`, `rate_limit.zones[].max_entries`), and every `auth.*` / `circuit_breaker.*` integer

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

## Authentication (OAuth 2.0 Token Validation)

> **Status — Available.** JWT verification (local signature), introspection (RFC 7662 POST to the IdP), per-route policy enforcement, multi-issuer routing, JWKS caching, OIDC discovery, the `auth.forward` outbound-header overlay, the per-issuer introspection cache (sharded LRU, HMAC-keyed) and async middleware dispatch are all wired and tested. For a practical operator walkthrough including failure modes, header injection semantics, and troubleshooting, see [`docs/oauth2.md`](oauth2.md). This section is the **field reference** — defaults, validation rules, and reload semantics for every key under `auth.*` and `proxy.auth.*`.

### Top-Level `auth` Block

```json
{
  "auth": {
    "enabled": false,
    "hmac_cache_key_env": "REACTOR_AUTH_CACHE_KEY",
    "issuers": {
      "google": {
        "issuer_url": "https://accounts.google.com",
        "discovery": true,
        "upstream": "google-idp",
        "mode": "jwt",
        "audiences": ["https://api.example.com"],
        "algorithms": ["RS256", "ES256"],
        "leeway_sec": 30,
        "jwks_cache_sec": 300,
        "jwks_refresh_timeout_sec": 5,
        "discovery_retry_sec": 30,
        "required_claims": []
      },
      "ours": {
        "issuer_url": "https://idp.internal",
        "discovery": false,
        "jwks_uri": "https://idp.internal/.well-known/jwks.json",
        "upstream": "internal-idp",
        "mode": "introspection",
        "introspection": {
          "endpoint": "https://idp.internal/oauth2/introspect",
          "client_id": "reactor-gateway",
          "client_secret_env": "REACTOR_INTROSPECTION_SECRET",
          "auth_style": "basic",
          "timeout_sec": 3,
          "cache_sec": 60,
          "negative_cache_sec": 10,
          "stale_grace_sec": 30,
          "max_entries": 100000,
          "shards": 16
        }
      }
    },
    "policies": [
      {
        "name": "admin-only",
        "enabled": false,
        "applies_to": ["/admin/"],
        "issuers": ["ours"],
        "required_scopes": ["admin"],
        "required_audience": "https://api.example.com",
        "on_undetermined": "deny",
        "realm": "admin"
      }
    ],
    "forward": {
      "subject_header": "X-Auth-Subject",
      "issuer_header": "X-Auth-Issuer",
      "scopes_header": "X-Auth-Scopes",
      "raw_jwt_header": "",
      "claims_to_headers": {
        "email": "X-Auth-Email"
      },
      "strip_inbound_identity_headers": true,
      "preserve_authorization": true
    }
  }
}
```

### Inline `proxy.auth` Block

Per-upstream auth policies live inline on the proxy entry — the prefix is derived from `proxy.route_prefix`, so inline policies do **not** carry an `applies_to`.

```json
{
  "upstreams": [{
    "name": "billing-api",
    "host": "127.0.0.1",
    "port": 9000,
    "proxy": {
      "route_prefix": "/billing/",
      "auth": {
        "enabled": false,
        "issuers": ["ours"],
        "required_scopes": ["billing.read"],
        "on_undetermined": "deny"
      }
    }
  }]
}
```

### Field Reference

All `auth.*` and `proxy.auth.*` keys, with defaults and whether they are live-reloadable via SIGHUP.

**Top-level `auth`**

| Field | Default | Reloadable | Notes |
|---|---|---|---|
| `auth.enabled` | `false` | yes | Master switch. When `false`, the middleware no-ops with a single atomic-load per request. |
| `auth.hmac_cache_key_env` | `""` | no (process-local) | Environment variable holding the HMAC-SHA256 key used to hash token-cache lookup keys. Supports base64url, standard base64 (with or without padding), or raw bytes; auto-detected. When unset and `auth.enabled=true`, a per-process random key is generated on startup. |

**Per-issuer (`auth.issuers.<name>`)**

| Field | Default | Reloadable | Notes |
|---|---|---|---|
| `issuer_url` | required | no (topology) | The IdP's issuer string; must match the `iss` claim on incoming tokens. |
| `discovery` | `false` | no (topology) | When `true`, fetch `.well-known/openid-configuration`. When `false`, `jwks_uri` must be provided. |
| `jwks_uri` | `""` | no (topology) | Required if `discovery=false`. Must be `https://`. Ignored when `discovery=true`. |
| `upstream` | required | no (topology) | Name of the `upstreams[]` entry used to reach the IdP. |
| `mode` | `"jwt"` | no (topology) | `"jwt"` (local signature verification) or `"introspection"` (RFC 7662 POST to IdP). |
| `audiences` | `[]` | yes | Accepted `aud` claim values. Empty list means any audience — not recommended. |
| `algorithms` | `["RS256"]` | yes | Allowlist: `RS256`, `RS384`, `RS512`, `ES256`, `ES384`. `HS*` and `none` are not supported. |
| `leeway_sec` | `30` | yes | Clock-skew tolerance for `exp` / `nbf`. |
| `jwks_cache_sec` | `300` | yes | JWKS TTL. |
| `jwks_refresh_timeout_sec` | `5` | yes | Upstream timeout for the JWKS GET. |
| `discovery_retry_sec` | `30` | yes | Retry interval for failed OIDC discovery. |
| `required_claims` | `[]` | yes | Additional claim names that must be present (any value). |
| `introspection.*` | — | no (topology) | Phase 3 opaque-token introspection. Parsed but not enforced; selecting `mode: "introspection"` is rejected. |

**Per-policy (`auth.policies[]` top-level) / (`proxy.auth` inline)**

| Field | Default | Reloadable | Notes |
|---|---|---|---|
| `name` | required (top-level only) | no | Must be a non-empty, non-whitespace identifier. Inline policies take their name from the parent upstream. |
| `enabled` | `false` | yes | When `false`, the policy parses but doesn't enforce. |
| `applies_to` | `[]` (top-level) | no (topology) | Literal byte-prefix path list. Required when `enabled=true` on top-level. Not accepted on inline policies (they derive their prefix from `proxy.route_prefix`). |
| `issuers` | `[]` | yes | Allowlist of issuer names; at least one must be present when enabled. Multi-issuer: the gateway peeks the `iss` claim to pick the verifier. |
| `required_scopes` | `[]` | yes | Every named scope must appear in the token's `scope` / `scp` claim. |
| `required_audience` | `""` | yes | If non-empty, adds this audience to the issuer's allowed list for this policy only. |
| `on_undetermined` | `"deny"` | yes | `"deny"` returns 503 with `Retry-After`; `"allow"` lets the request through with `X-Auth-Undetermined: true`. |
| `realm` | `"api"` | yes | Value used for the `realm=` parameter in `WWW-Authenticate`. |

**Forward overlay (`auth.forward`)** — all fields live-reloadable:

| Field | Default | Notes |
|---|---|---|
| `subject_header` | `""` | Output header for verified `sub`. Empty omits. |
| `issuer_header` | `""` | Output header for verified `iss`. |
| `scopes_header` | `""` | Output header for extracted scope list (space-joined). |
| `raw_jwt_header` | `""` | Output header for the raw compact JWT. **Opt-in; security-sensitive.** |
| `claims_to_headers` | `{}` | Map of `<claim>: <header>` — forwards string/number claims. |
| `strip_inbound_identity_headers` | `true` | Delete any client-provided copies of overlay-owned headers. Keep on. |
| `preserve_authorization` | `true` | Forward the original `Authorization` header. Set to `false` to strip. |

### Validation Rules

`ConfigLoader::Validate()` enforces:

- **TLS-mandatory upstream endpoints** — `jwks_uri` and `introspection.endpoint` MUST be `https://`. Plain HTTP is hard-rejected (token-bearing exchanges over plaintext are a credential leak).
- **Inline `client_secret` is forbidden** — only `client_secret_env` (env-var indirection) is accepted. Prevents secrets from sitting in versioned config files.
- **Issuer cross-references** — `auth.issuers.<name>.upstream` must name an existing entry in `upstreams[]` (skipped on reload-stripped copies; `ValidateProxyAuth` re-checks against the live upstream set).
- **Top-level policy `name` is required** — array-index-based log lines are unstable across config edits; every operator-visible log/metric must cite a stable identifier.
- **Reserved auth.forward names** — `subject_header` / `issuer_header` / `scopes_header` / `raw_jwt_header` and every `claims_to_headers` value are rejected if they collide with:
  - HTTP/2 pseudo-headers (`:method`, `:path`, `:scheme`, `:authority`, `:status`)
  - Hop-by-hop headers (RFC 7230 §6.1: `Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`, plus the legacy `Proxy-Connection`)
  - Framing-critical headers (`Host`, `Content-Length`, `Content-Type`, `Content-Encoding`)
  - `Authorization` (would conflict with `preserve_authorization`)
  - HeaderRewriter-owned hop-identity headers (`Via`, `X-Forwarded-For`, `X-Forwarded-Proto`) — these names are rewritten on every outbound request, so an auth.forward mapping to one would silently mangle either the identity signal or the proxy chain
- **Header-name validity** — every output header name is checked against RFC 7230 §3.2.6 `tchar` (rejects spaces, slashes, colons, etc.).
- **Inline auth requires a literal byte-prefix `route_prefix`** — patterned routes (e.g. `/api/:version/`) are rejected for inline auth because the matcher does literal byte-prefix matching, not trie pattern matching, and the JSON would otherwise describe a different protected path than the runtime applies.
- **`applies_to` on top-level policies** — required when `enabled: true`; literal byte prefixes (printable characters allowed, including `:` / `*` for legitimate literal URLs).
- **`on_undetermined`** — must be `"deny"` (default) or `"allow"`.
- **Strict integer parsing** — every `auth.*` integer (`leeway_sec`, `jwks_cache_sec`, `introspection.timeout_sec`, etc.) goes through `ParseStrictInt` (see Type Safety above).

### Additional Examples

**Google + private IdP on the same gateway.** Two issuers, two policies:

```json
"auth": {
  "enabled": true,
  "issuers": {
    "google": {
      "issuer_url": "https://accounts.google.com",
      "discovery": true, "upstream": "google-idp",
      "audiences": ["https://api.example.com"],
      "algorithms": ["RS256"]
    },
    "ours": {
      "issuer_url": "https://idp.internal",
      "discovery": false,
      "jwks_uri": "https://idp.internal/.well-known/jwks.json",
      "upstream": "internal-idp",
      "audiences": ["https://api.example.com"],
      "algorithms": ["RS256", "ES256"]
    }
  },
  "policies": [
    {
      "name": "admin-api",
      "enabled": true,
      "applies_to": ["/admin/"],
      "issuers": ["ours"],
      "required_scopes": ["admin"]
    },
    {
      "name": "public-api",
      "enabled": true,
      "applies_to": ["/v1/"],
      "issuers": ["google", "ours"]
    }
  ]
}
```

**Advisory / shadow mode.** Log denials but admit traffic:

```json
{
  "name": "shadow-api",
  "enabled": true,
  "applies_to": ["/v1/"],
  "issuers": ["google"],
  "on_undetermined": "allow"
}
```

Requests with an `UNDETERMINED` outcome (IdP unreachable, kid miss, etc.) go through with `X-Auth-Undetermined: true`. Malformed tokens still 401 — advisory mode only covers "we don't know", not "we know it's bad."

**Opt into raw JWT forwarding.** Advanced — only when the upstream genuinely needs to re-verify:

```json
"forward": {
  "subject_header": "X-Auth-Subject",
  "raw_jwt_header": "X-Auth-Raw-JWT",
  "strip_inbound_identity_headers": true,
  "preserve_authorization": false
}
```

**Introspection (Phase 3 — declared but deferred).** The schema accepts the block so future releases can enable it without a config migration, but `mode: "introspection"` is rejected at startup today:

```json
"issuers": {
  "opaque-idp": {
    "issuer_url": "https://idp.internal",
    "discovery": false,
    "upstream": "internal-idp",
    "mode": "introspection",
    "introspection": {
      "endpoint": "https://idp.internal/oauth2/introspect",
      "client_id": "reactor-gateway",
      "client_secret_env": "REACTOR_INTROSPECTION_SECRET",
      "timeout_sec": 3,
      "cache_sec": 60
    }
  }
}
```

### Hot-reload behavior

**Live-reloadable** (SIGHUP applies immediately):

- `auth.enabled`
- Per-issuer: `audiences`, `algorithms`, `leeway_sec`, `required_claims`, `jwks_cache_sec`, `jwks_refresh_timeout_sec`, `discovery_retry_sec`
- Per-policy: `enabled`, `required_scopes`, `required_audience`, `on_undetermined`, `realm`
- All `auth.forward.*` fields

**Restart-required** (SIGHUP logs a warn; live state is preserved):

- `auth.hmac_cache_key_env` (HMAC key is process-local)
- Adding / removing issuers
- Per-issuer: `issuer_url`, `discovery`, `jwks_uri`, `upstream`, `mode`
- Policy topology: `applies_to` on top-level policies; `route_prefix` on inline policies; list of configured policies

`ConfigLoader::ValidateHotReloadable()` runs hard-reject validation on the live-reloadable subset so invalid reloads never reach live state — broken values are rejected before the new config is committed. Restart-required field changes are logged and skipped (not rejected), so you can reload live fields even if a topology change is also staged in the config file; the topology just won't take effect until the next restart.

In-flight requests always see the snapshot they started with (both `policies_` and `forward_` are `shared_ptr<const T>` swapped atomically).

## Third-Party Dependencies

| Library | Version | Path | Purpose | License |
|---------|---------|------|---------|---------|
| nlohmann/json | 3.11.3 | `third_party/nlohmann/json.hpp` | Single-header JSON parsing | MIT |
| spdlog | 1.15.1 | `third_party/spdlog/` | Header-only structured logging | MIT |
| jwt-cpp | 0.7.1 | `third_party/jwt-cpp/` | Header-only JWT decoding/verification (compiled with `JWT_DISABLE_PICOJSON` so the project's existing nlohmann/json carries the JSON traits) | MIT |

All vendored in the repository.
