# Reactor pattern based HTTP/Websocket Server

A high-performance C++ network server built on the Reactor pattern with epoll/kqueue I/O multiplexing. Supports HTTP/1.1, HTTP/2 (RFC 9113), WebSocket (RFC 6455), and TLS — all layered on top of a non-blocking, edge-triggered event loop designed for thousands of concurrent connections.

## Features

- **HTTP/1.1** — request routing, middleware, keep-alive, pipelining, chunked transfer
- **HTTP/2** — RFC 9113 compliant: stream multiplexing, HPACK, flow control, ALPN negotiation, flood protection
- **WebSocket** — RFC 6455 compliant: handshake, binary/text frames, fragmentation, close handshake, ping/pong
- **TLS/SSL** — optional OpenSSL 3.x integration with configurable minimum version and cipher suites
- **Reactor Core** — edge-triggered epoll (Linux) / kqueue (macOS), non-blocking I/O, multi-threaded dispatcher pool
- **Thread Pool** — configurable worker threads for event loop dispatchers
- **Connection Management** — idle timeout detection, request deadlines (Slowloris protection), graceful shutdown with WS close frames and H2 GOAWAY drain
- **CLI** — production binary with config validation, signal management, PID file tracking, health/stats endpoints, daemon mode
- **Configuration** — JSON config files + environment variable overrides + CLI flag overrides
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
./server_runner
```

### CLI Reference

```
server_runner <command> [options]

Commands:
  start       Start the server (foreground, or -d for daemon)
  stop        Stop a running server
  reload      Reload configuration (daemon: hot-reload, foreground: shutdown)
  status      Check server status
  validate    Validate configuration
  config      Show effective configuration
  version     Show version information
  help        Show this help

Start options:
  -c, --config <file>         Config file (default: config/server.json)
  -p, --port <port>           Override bind port (0-65535, 0=ephemeral)
  -H, --host <address>        Override bind address (numeric IPv4 only)
  -l, --log-level <level>     Override log level (trace/debug/info/warn/error/critical)
  -w, --workers <N>           Override worker thread count (0 = auto)
  -P, --pid-file <file>       PID file path (default: /tmp/reactor_server.pid)
  -d, --daemonize             Run as a background daemon
  --no-health-endpoint       Disable /health and /stats endpoints
  --no-stats-endpoint        Disable the /stats endpoint

Stop/status options:
  -P, --pid-file <file>       PID file path

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

Environment variables: `REACTOR_BIND_HOST`, `REACTOR_BIND_PORT`, `REACTOR_TLS_ENABLED`, `REACTOR_TLS_CERT`, `REACTOR_TLS_KEY`, `REACTOR_LOG_LEVEL`, `REACTOR_LOG_FILE`, `REACTOR_MAX_CONNECTIONS`, `REACTOR_IDLE_TIMEOUT`, `REACTOR_WORKER_THREADS`, `REACTOR_REQUEST_TIMEOUT`

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

HttpServer server("0.0.0.0", 8080);

// Middleware
server.Use([](const HttpRequest& req, HttpResponse& res) {
    res.Header("X-Request-Id", generate_id());
    return true;  // continue chain
});

// Routes
server.Get("/health", [](const HttpRequest& req, HttpResponse& res) {
    res.Status(200).Json(R"({"status":"ok"})");
});

server.Post("/echo", [](const HttpRequest& req, HttpResponse& res) {
    res.Status(200).Body(req.body, "text/plain");
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
    "bind_host": "0.0.0.0",
    "bind_port": 8080,
    "max_connections": 10000,
    "idle_timeout_sec": 300,
    "worker_threads": 3,
    "max_body_size": 1048576,
    "max_header_size": 8192,
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
        "max_header_list_size": 65536
    }
}
```

## Architecture

```
Layer 5: HttpServer                          (application entry point)
Layer 4: HttpRouter, WebSocketConnection    (routing, WS message API)
Layer 3: HttpParser, WebSocketParser        (protocol parsing)
         HttpConnectionHandler              (HTTP/1.1 state machine)
         Http2Session, Http2Stream          (HTTP/2 session/stream management)
         Http2ConnectionHandler             (HTTP/2 state machine)
         ProtocolDetector                   (HTTP/1.x vs HTTP/2 detection)
Layer 2: TlsContext, TlsConnection          (optional TLS, ALPN)
Layer 1: ConnectionHandler, Channel,        (reactor core)
         Dispatcher, EventHandler
```

See [docs/architecture.md](docs/architecture.md) for the full design, data flow diagrams, and memory management model.

## Project Structure

```
reactor_server_cpp/
├── include/              # Headers
│   ├── http/             #   HTTP layer (server, router, parser, request/response)
│   ├── http2/            #   HTTP/2 layer (session, stream, connection handler)
│   ├── ws/               #   WebSocket layer (connection, parser, frame, handshake)
│   ├── tls/              #   TLS layer (context, connection)
│   ├── cli/              #   CLI layer (parser, signal handler, PID file, version)
│   ├── config/           #   Configuration (server_config, config_loader)
│   ├── log/              #   Logging (logger, log_utils)
│   └── *.h               #   Reactor core (dispatcher, channel, connection, etc.)
├── server/               # Implementation (.cc)
│   ├── main.cc           #   Production entry point
│   └── *.cc              #   All component implementations
├── test/                 # Test suites (basic, stress, race, timeout, http, ws, tls, http2, cli, route, kqueue)
├── thread_pool/          # Standalone thread pool (separate build)
├── third_party/          # llhttp, nghttp2, nlohmann/json, spdlog
├── config/               # Example config files
├── docs/                 # Documentation
└── Makefile
```

## Build

```bash
make                    # Build both test runner (./test_runner) and server (./server_runner)
make server             # Build only the production server
make test               # Build and run all tests (211 tests across 13 suites)
make clean              # Remove artifacts
make help               # Show all targets

# Run specific test suites
./test_runner basic     # Basic functionality (6 tests)
./test_runner stress    # Stress tests — 100 concurrent clients (1 test)
./test_runner race      # Race condition tests (14 tests)
./test_runner timeout   # Connection timeout tests (6 tests)
./test_runner config    # Configuration tests (8 tests)
./test_runner http      # HTTP protocol tests (14 tests)
./test_runner ws        # WebSocket protocol tests (10 tests)
./test_runner tls       # TLS/SSL tests (2 tests)
./test_runner http2     # HTTP/2 protocol tests (37 tests)
./test_runner cli       # CLI entry point tests (79 tests)
./test_runner route     # Route trie/pattern matching (44 tests)
./test_runner kqueue    # macOS kqueue platform tests (7 tests, skipped on Linux)

# Thread pool subproject (independent)
cd thread_pool && make && ./run
```

**Requirements:** g++ (C++17), pthreads, OpenSSL 3.x (libssl-dev)

## Documentation

| Document | Description |
|----------|-------------|
| [docs/cli.md](docs/cli.md) | CLI usage, flags, signal handling, PID files, daemon mode |
| [docs/architecture.md](docs/architecture.md) | Reactor pattern, layered design, data flow, memory management |
| [docs/callback_architecture.md](docs/callback_architecture.md) | 3-layer callback chain, type definitions, weak_ptr design pattern |
| [docs/testing.md](docs/testing.md) | Test suites, running tests, port configuration |
| [docs/http.md](docs/http.md) | HTTP/1.1 layer — routing, middleware, request/response API |
| [docs/http2.md](docs/http2.md) | HTTP/2 layer — streams, HPACK, flow control, ALPN |
| [docs/websocket.md](docs/websocket.md) | WebSocket — upgrade flow, frames, message API, RFC 6455 compliance |
| [docs/tls.md](docs/tls.md) | TLS/SSL — configuration, state machine, OpenSSL integration |
| [docs/configuration.md](docs/configuration.md) | JSON config, environment variables, structured logging |

## Platform Support

| Platform | Status |
|----------|--------|
| Linux (epoll) | Production-ready |
| macOS (kqueue) | Production-ready |
| Windows (IOCP) | Planned |
