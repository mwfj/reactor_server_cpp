# Reactor Pattern HTTP/WebSocket Server

A C++17 network server and gateway built on the Reactor pattern. It uses non-blocking, edge-triggered I/O (`epoll` on Linux, `kqueue` on macOS) and includes HTTP/1.1, HTTP/2, WebSocket, TLS, upstream proxying, rate limiting, circuit breaking, DNS resolution, and OAuth 2.0 bearer-token validation.

## Features

- **HTTP/1.1** — request routing, middleware, keep-alive, pipelining, chunked transfer, strict parser validation
- **HTTP/2** — RFC 9113 support: stream multiplexing, HPACK, flow control, h2c detection, TLS ALPN, Early Hints, optional server push
- **WebSocket** — RFC 6455 support: handshake, binary/text frames, fragmentation, close handshake, ping/pong
- **TLS/SSL** — OpenSSL 3.x integration for downstream server TLS and upstream client TLS
- **Upstream Proxy** — per-service connection pools with TLS, streaming response relay, retry policy, trailer handling, and header rewriting
- **HTTP/2 Upstream** — per-upstream opt-in multiplexed H2 client (donated-lease pattern), ALPN-negotiated `auto / always / never` dispatch, two-deadline send-stall + response-timeout model, transport-drain-driven sink dispatch, GOAWAY/PING liveness, live-reloadable session settings
- **Rate Limiting** — per-client / per-route token-bucket middleware with LRU eviction, `RateLimit-*` headers, dry-run mode, hot reload
- **Circuit Breaking** — per-upstream state machines, retry budgets, dry-run mode, wait-queue drain, hot-reloadable breaker tuning
- **OAuth 2.0 Token Validation** — JWT validation with JWKS/OIDC discovery, multi-issuer policies, outbound identity headers, and RFC 7662 introspection mode
- **Observability (OpenTelemetry)** — W3C + Jaeger trace propagation, OTLP/JSON traces + metrics push, Prometheus pull `/metrics`, route-aware sampling, per-request span tree across inbound + auth + proxy + WS, idempotent finalize-CAS bookkeeping, four-phase graceful shutdown
- **DNS and IPv6** — bind-host and upstream hostname resolution, IPv4/IPv6 family selection, stale-on-error reload handling
- **Reactor Core** — edge-triggered epoll (Linux) / kqueue (macOS), non-blocking I/O, multi-threaded dispatcher pool
- **Thread Pool** — configurable worker threads for event loop dispatchers
- **Connection Management** — idle timeout detection, request deadlines (Slowloris protection), graceful shutdown with WS close frames and H2 GOAWAY drain
- **CLI** — production binary with config validation, signal management, PID file tracking, health/stats endpoints, daemon mode
- **Configuration** — JSON config files + environment variable overrides + CLI flag overrides, SIGHUP hot reload
- **Structured Logging** — spdlog-based logging with date-based file rotation

## Quick Start

```bash
# Build everything (test runner + production server)
make

# Start the server
./server_runner start

# Start with custom port and log level
./server_runner start -p 9090 -l debug

# Start with a config file
./server_runner start -c config/server.example.json

# Check server status
./server_runner status

# Graceful shutdown
./server_runner stop
```

## Running the Server

### Basic Usage

```bash
# Start with defaults (127.0.0.1:8080)
./server_runner start

# Override host and port
./server_runner start -H 0.0.0.0 -p 8080

# Daemon mode
./server_runner start -d -c config/production.json

# Validate config without starting
./server_runner validate -c config/server.example.json

# Show resolved config (defaults + file + env + CLI)
./server_runner config -p 9090 -l debug

# Version info
./server_runner version -V

# Show usage
./server_runner help
```

### CLI Reference

```text
server_runner <command> [options]

Commands:
  start       Start the server (foreground, or -d for daemon)
  stop        Stop a running server
  reload      Reload configuration (daemon mode; shuts down foreground)
  status      Check server status
  validate    Validate configuration
  config      Show effective configuration
  version     Show version information
  help        Show this help

Start options:
  -c, --config <file>         Config file (default: config/server.json)
  -p, --port <port>           Override bind port (0-65535, 0=ephemeral)
  -H, --host <address>        Override bind address: IPv4 literal,
                              IPv6 literal (bare or bracketed), or hostname
  -l, --log-level <level>     Override log level
                              (trace, debug, info, warn, error, critical)
  -w, --workers <N>           Override worker thread count (0 = auto)
  -P, --pid-file <file>       PID file path (default: /tmp/reactor_server.pid)
  -d, --daemonize             Run as a background daemon
  --no-health-endpoint        Disable the /health endpoint
  --no-stats-endpoint         Disable the /stats endpoint

Stop/status/reload options:
  -P, --pid-file <file>       PID file path (default: /tmp/reactor_server.pid)

Validate/config options:
  -c, --config <file>         Config file
  -p, --port <port>           Override bind port
  -H, --host <address>        Override bind address
  -l, --log-level <level>     Override log level
  -w, --workers <N>           Override worker threads
  -d, --daemonize             Check daemon-mode constraints (validate only)
  -P, --pid-file <file>       PID file to validate (validate -d only)

Global options:
  -v, --version               Same as 'version'
  -V, --version-verbose       Verbose version with build details
  -h, --help                  Same as 'help'
```

### Signal Handling

| Signal | Behavior |
|--------|----------|
| `SIGTERM` | Graceful shutdown (sends WS Close 1001, H2 GOAWAY, drains connections, exits) |
| `SIGINT` | Same as SIGTERM (Ctrl+C) |
| `SIGHUP` | Daemon: config hot-reload + log reopen. Foreground: graceful shutdown |
| `SIGPIPE` | Ignored |

### Config Override Precedence

```
defaults < config file < environment variables < CLI flags
```

Environment overrides include:

```text
REACTOR_BIND_HOST
REACTOR_BIND_PORT
REACTOR_TLS_ENABLED
REACTOR_TLS_CERT
REACTOR_TLS_KEY
REACTOR_LOG_LEVEL
REACTOR_LOG_FILE
REACTOR_MAX_CONNECTIONS
REACTOR_IDLE_TIMEOUT
REACTOR_WORKER_THREADS
REACTOR_REQUEST_TIMEOUT
REACTOR_SHUTDOWN_DRAIN_TIMEOUT
REACTOR_HTTP2_ENABLED
REACTOR_HTTP2_MAX_CONCURRENT_STREAMS
REACTOR_HTTP2_INITIAL_WINDOW_SIZE
REACTOR_HTTP2_MAX_FRAME_SIZE
REACTOR_HTTP2_MAX_HEADER_LIST_SIZE
REACTOR_RATE_LIMIT_ENABLED
REACTOR_RATE_LIMIT_DRY_RUN
REACTOR_RATE_LIMIT_STATUS_CODE
REACTOR_DNS_LOOKUP_FAMILY
REACTOR_DNS_RESOLVE_TIMEOUT_MS
REACTOR_DNS_OVERALL_TIMEOUT_MS
REACTOR_DNS_STALE_ON_ERROR
```

### Health & Stats Endpoints

Enabled by default:

```bash
curl http://127.0.0.1:8080/health
# {"status":"ok","pid":12345,"uptime_seconds":3600}

curl http://127.0.0.1:8080/stats
# {"uptime_seconds":3600,"connections":{"active":42,...},"requests":{"total":50000,...},...}
```

Disable with `--no-health-endpoint` (disables both) or `--no-stats-endpoint` (disables only `/stats`).

## Programming API

### HTTP Server

```cpp
#include "http/http_server.h"
#include "http/http_status.h"

HttpServer server("0.0.0.0", 8080);

// Middleware
server.Use([](const HttpRequest& req, HttpResponse& res) {
    res.Header("X-Request-Id", "example");
    return true;  // continue chain
});

// Routes
server.Get("/health", [](const HttpRequest& req, HttpResponse& res) {
    res.Status(HttpStatus::OK).Json(R"({"status":"ok"})");
});

server.Post("/echo", [](const HttpRequest& req, HttpResponse& res) {
    res.Status(HttpStatus::OK).Body(req.body, "text/plain");
});

server.Start();  // blocks in event loop
```

### WebSocket

```cpp
server.WebSocket("/ws", [](WebSocketConnection& ws) {
    ws.OnMessage([](WebSocketConnection& ws, const std::string& msg, bool is_binary) {
        ws.SendText("Echo: " + msg);
    });

    ws.OnClose([](WebSocketConnection& ws, uint16_t code, const std::string& reason) {
        std::cout << "Client disconnected: " << code << std::endl;
    });
});
```

### TLS

```cpp
ServerConfig config;
config.bind_host = "0.0.0.0";
config.bind_port = 443;
config.tls.enabled = true;
config.tls.cert_file = "/etc/ssl/server.pem";
config.tls.key_file = "/etc/ssl/server.key";
config.tls.min_version = "1.2";

HttpServer server(config);
server.Start();
```

### Configuration

JSON config file:

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
    "shutdown_drain_timeout_sec": 30,
    "tls": {
        "enabled": false,
        "cert_file": "",
        "key_file": "",
        "min_version": "1.2"
    },
    "log": {
        "level": "info",
        "file": "",
        "max_file_size": 10485760,
        "max_files": 3
    },
    "http2": {
        "enabled": true,
        "max_concurrent_streams": 100,
        "initial_window_size": 65535,
        "max_frame_size": 16384,
        "max_header_list_size": 65536,
        "enable_push": false
    },
    "dns": {
        "lookup_family": "v4_preferred",
        "resolve_timeout_ms": 5000,
        "overall_timeout_ms": 15000,
        "stale_on_error": true,
        "resolver_max_inflight": 32
    },
    "rate_limit": {
        "enabled": false,
        "dry_run": false,
        "status_code": 429,
        "include_headers": true,
        "zones": []
    },
    "upstreams": []
}
```

`upstreams[]` entries can define connection-pool limits, upstream TLS, proxy route settings, retry behavior, circuit breaker tuning, and inline auth policies. See `config/server.example.json` and [docs/configuration.md](docs/configuration.md) for more examples.

### Proxy, circuit breaker, and auth configuration

The production config can auto-register proxy routes from `upstreams[].proxy.route_prefix`, or application code can call `server.Proxy(pattern, upstream_name)`.

```json
{
    "upstreams": [
        {
            "name": "api",
            "host": "api.internal",
            "port": 8080,
            "pool": {
                "max_connections": 64,
                "max_idle_connections": 16,
                "connect_timeout_ms": 5000
            },
            "proxy": {
                "route_prefix": "/api",
                "strip_prefix": true,
                "methods": ["GET", "POST", "PUT", "DELETE"],
                "buffering": "auto",
                "retry": {
                    "max_retries": 1,
                    "retry_on_connect_failure": true,
                    "retry_on_disconnect": true
                }
            },
            "circuit_breaker": {
                "enabled": true,
                "consecutive_failure_threshold": 5,
                "failure_rate_threshold": 50,
                "minimum_volume": 20,
                "window_seconds": 10,
                "retry_budget_percent": 20,
                "retry_budget_min_concurrency": 3
            }
        }
    ]
}
```

OAuth validation is configured as resource-server middleware. JWT mode validates bearer tokens locally against JWKS keys; introspection mode posts opaque tokens to an RFC 7662 endpoint and caches the result.

```json
{
    "auth": {
        "enabled": true,
        "issuers": {
            "main": {
                "issuer_url": "https://issuer.example.com",
                "discovery": true,
                "upstream": "issuer",
                "mode": "jwt",
                "audiences": ["https://api.example.com"],
                "algorithms": ["RS256"]
            }
        },
        "policies": [
            {
                "name": "api-read",
                "enabled": true,
                "applies_to": ["/api"],
                "issuers": ["main"],
                "required_scopes": ["api.read"],
                "on_undetermined": "deny",
                "realm": "api"
            }
        ],
        "forward": {
            "subject_header": "X-Auth-Subject",
            "issuer_header": "X-Auth-Issuer",
            "scopes_header": "X-Auth-Scopes",
            "strip_inbound_identity_headers": true,
            "preserve_authorization": true
        }
    }
}
```

For opaque tokens, set an issuer to `"mode": "introspection"` and provide `introspection.endpoint`, `client_id`, `client_secret_env`, cache TTLs, and timeout settings. Inline proxy auth is also supported through `upstreams[].proxy.auth`.

Issuer `upstream` values refer to named entries in `upstreams[]`; define one for each identity provider the gateway must call.

## Architecture

```
Layer 6: server_runner, ConfigLoader        (CLI, config, signals, health/stats)
Layer 5: HttpServer                         (application entry point)
Layer 4: HttpRouter, AuthManager,           (routing, middleware, OAuth, rate limit)
         RateLimiter, ProxyHandler
Layer 3: HttpParser, WebSocketParser        (protocol parsing)
         HttpConnectionHandler              (HTTP/1.1 state machine)
         Http2Session, Http2Stream          (HTTP/2 session/stream management)
         Http2ConnectionHandler             (HTTP/2 state machine)
         ProtocolDetector                   (HTTP/1.x vs HTTP/2 detection)
Layer 2: TlsContext, TlsConnection,         (TLS, ALPN, hostname resolution)
         DnsResolver
Layer 1: ConnectionHandler, Channel,        (reactor core)
         Dispatcher, EventHandler
```

See [docs/architecture.md](docs/architecture.md) for the full design, data flow diagrams, and memory management model.

## Project Structure

```
reactor_server_cpp/
├── include/              # Headers
│   ├── auth/             #   OAuth/JWT/OIDC/introspection validation
│   ├── circuit_breaker/  #   Circuit breaker and retry budget
│   ├── cli/              #   CLI layer (parser, signal handler, PID file, version)
│   ├── config/           #   Configuration (server_config, config_loader)
│   ├── http/             #   HTTP layer (server, router, parser, request/response)
│   ├── http2/            #   HTTP/2 layer (session, stream, connection handler)
│   ├── log/              #   Logging (logger, log_utils)
│   ├── net/              #   DNS resolver
│   ├── rate_limit/       #   Rate limiting (manager, zone, token bucket)
│   ├── tls/              #   TLS layer (context, connection)
│   ├── upstream/         #   Upstream proxy (pool, proxy handler, retry policy)
│   ├── ws/               #   WebSocket layer (connection, parser, frame, handshake)
│   └── *.h               #   Reactor core (dispatcher, channel, connection, etc.)
├── server/               # Implementation (.cc)
│   ├── main.cc           #   Production entry point
│   └── *.cc              #   All component implementations
├── test/                 # Test suites and harnesses
├── thread_pool/          # Standalone thread pool (separate build)
├── third_party/          # llhttp, nghttp2, nlohmann/json, spdlog, jwt-cpp
├── config/               # Example config files
├── docs/                 # Documentation
└── Makefile
```

## Build

```bash
make                    # Build both test runner (./test_runner) and server (./server_runner)
make server             # Build only the production server
make test               # Build and run all tests
make clean              # Remove artifacts
make help               # Show all targets

# Run a specific test suite (single-suite categories)
./test_runner basic
./test_runner stress
./test_runner race
./test_runner timeout
./test_runner config
./test_runner http       # internal regressions + end-to-end HTTP
./test_runner http2      # internal regressions + end-to-end HTTP/2
./test_runner ws
./test_runner tls
./test_runner cli
./test_runner route
./test_runner upstream
./test_runner rate_limit
./test_runner kqueue     # macOS only; skipped on Linux

# Feature-family umbrellas — each runs every sub-suite in the family
./test_runner auth              # full auth feature family
./test_runner circuit_breaker   # full circuit-breaker feature family
./test_runner proxy             # internal proxy regressions + engine
./test_runner dns               # DnsResolver primitives + dual-stack (umbrella)
./test_runner dual_stack        # Sub-suite — dual-stack integration only
./test_runner dns_resolver      # Sub-suite — DnsResolver primitives only

# Auth sub-suites (drill into one aspect)
./test_runner auth_foundation
./test_runner jwt
./test_runner jwks
./test_runner oidc
./test_runner hrauth
./test_runner auth_mgr
./test_runner auth2
./test_runner auth_fail
./test_runner auth_reload
./test_runner auth_multi
./test_runner auth_ws
./test_runner auth_race
./test_runner router_async
./test_runner introspection_cache
./test_runner intro_client
./test_runner auth_intro
./test_runner auth_observability

./test_runner help       # Show all runner options

# Thread pool subproject (independent)
make -C thread_pool
./thread_pool/run
```

`make test_dual_stack_tsan` builds and runs the ThreadSanitizer dual-stack race subset.

**Requirements:** g++ or clang++ with C++17 support, pthreads, OpenSSL 3.x development headers/libraries, and make.

## Documentation

| Document | Description |
|----------|-------------|
| [docs/cli.md](docs/cli.md) | CLI usage, flags, signal handling, PID files, daemon mode |
| [docs/architecture.md](docs/architecture.md) | Reactor pattern, layered design, data flow, memory management |
| [docs/callback_architecture.md](docs/callback_architecture.md) | 3-layer callback chain, type definitions, weak_ptr design pattern |
| [docs/testing.md](docs/testing.md) | Test suites, running tests, port configuration, CI workflow cadence (per-PR / nightly stress / weekly valgrind) |
| [docs/http.md](docs/http.md) | HTTP/1.1 layer — routing, middleware, request/response API |
| [docs/http2.md](docs/http2.md) | HTTP/2 layer — streams, HPACK, flow control, ALPN |
| [docs/websocket.md](docs/websocket.md) | WebSocket — upgrade flow, frames, message API, RFC 6455 compliance |
| [docs/tls.md](docs/tls.md) | TLS/SSL — configuration, state machine, OpenSSL integration |
| [docs/configuration.md](docs/configuration.md) | JSON config, environment variables, DNS, upstreams, rate limiting, structured logging |
| [docs/oauth2.md](docs/oauth2.md) | OAuth 2.0 JWT and introspection validation |
| [docs/circuit_breaker.md](docs/circuit_breaker.md) | Circuit breaker configuration, retry budgets, hot reload, observability |
| [docs/http2_upstream.md](docs/http2_upstream.md) | HTTP/2 upstream client — `prefer` modes, reload semantics, failure modes, tuning |
| [docs/observability.md](docs/observability.md) | OpenTelemetry — traces, metrics, propagators, sampling, OTLP / Prometheus configuration |

## Platform Support

| Platform | Status |
|----------|--------|
| Linux (`epoll`) | Supported |
| macOS (`kqueue`) | Supported |
| Windows | Not implemented |
