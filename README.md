# Reactor pattern based HTTP/Websocket Server

A high-performance C++ network server built on the Reactor pattern with epoll/kqueue I/O multiplexing. Supports HTTP/1.1, WebSocket (RFC 6455), and TLS — all layered on top of a non-blocking, edge-triggered event loop designed for thousands of concurrent connections.

## Features

- **HTTP/1.1** — request routing, middleware, keep-alive, pipelining, chunked transfer
- **WebSocket** — RFC 6455 compliant: handshake, binary/text frames, fragmentation, close handshake, ping/pong
- **TLS/SSL** — optional OpenSSL 3.x integration with configurable minimum version and cipher suites
- **Reactor Core** — edge-triggered epoll (Linux) / kqueue (macOS), non-blocking I/O, multi-threaded dispatcher pool
- **Thread Pool** — configurable worker threads for event loop dispatchers
- **Connection Management** — idle timeout detection, request deadlines (Slowloris protection), graceful shutdown with WS close frames
- **Configuration** — JSON config files + environment variable overrides
- **Structured Logging** — spdlog-based async logging with file rotation

## Quick Start

```bash
# Build
make

# Run all tests (51 tests)
make test

# Run specific suites
./run basic stress race timeout http ws tls config
```

## Usage

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

JSON config file or environment variables:

```json
{
    "bind_host": "0.0.0.0",
    "bind_port": 8080,
    "max_connections": 10000,
    "max_body_size": 1048576,
    "max_header_size": 8192,
    "request_timeout_sec": 30,
    "tls": {
        "enabled": false,
        "cert_file": "",
        "key_file": "",
        "min_version": "1.2"
    }
}
```

Environment overrides: `REACTOR_BIND_HOST`, `REACTOR_BIND_PORT`, `REACTOR_TLS_ENABLED`, etc.

### Raw TCP (Legacy)

For custom protocols without HTTP framing:

```cpp
#include "reactor_server.h"

ReactorServer server("0.0.0.0", 8888);
server.Start();  // echo server with length-prefix protocol
```

## Architecture

```
Layer 5: HttpServer / ReactorServer         (application entry points)
Layer 4: HttpRouter, WebSocketConnection    (routing, WS message API)
Layer 3: HttpParser, WebSocketParser        (protocol parsing)
         HttpConnectionHandler              (HTTP state machine)
Layer 2: TlsContext, TlsConnection          (optional TLS)
Layer 1: ConnectionHandler, Channel,        (reactor core)
         Dispatcher, EventHandler
```

See [docs/architecture.md](docs/architecture.md) for the full design, data flow diagrams, and memory management model.

## Project Structure

```
reactor_server_cpp/
├── include/              # Headers
│   ├── http/             #   HTTP layer (server, router, parser, request/response)
│   ├── ws/               #   WebSocket layer (connection, parser, frame, handshake)
│   ├── tls/              #   TLS layer (context, connection)
│   └── *.h               #   Reactor core (dispatcher, channel, connection, etc.)
├── server/               # Implementation (.cc)
├── test/                 # Test suites (basic, stress, race, timeout, http, ws, tls)
├── thread_pool/          # Standalone thread pool (separate build)
├── third_party/          # llhttp (HTTP parser), nlohmann/json, spdlog
├── util/                 # Utilities (timestamp)
├── docs/                 # Documentation
│   ├── architecture.md          #   Core design and data flow
│   ├── callback_architecture.md #   Callback layer design
│   ├── testing.md               #   Test suites and running tests
│   ├── http.md                  #   HTTP/1.1 layer
│   ├── websocket.md             #   WebSocket (RFC 6455)
│   ├── tls.md                   #   TLS/SSL support
│   └── configuration.md        #   Config and logging
└── Makefile
```

## Build

```bash
make                # Build (g++ with C++17, links pthread + OpenSSL)
make clean          # Remove artifacts
make help           # Show all targets

# Thread pool subproject (independent)
cd thread_pool && make && ./run
```

**Requirements:** g++ (C++17), pthreads, OpenSSL 3.x (libssl-dev)

## Documentation

| Document | Description |
|----------|-------------|
| [docs/architecture.md](docs/architecture.md) | Reactor pattern, layered design, data flow, memory management, cross-platform support |
| [docs/callback_architecture.md](docs/callback_architecture.md) | 3-layer callback chain, type definitions, weak_ptr design pattern |
| [docs/testing.md](docs/testing.md) | Test suites, running tests, port configuration |
| [docs/http.md](docs/http.md) | HTTP/1.1 layer — routing, middleware, request/response API |
| [docs/websocket.md](docs/websocket.md) | WebSocket — upgrade flow, frames, message API, RFC 6455 compliance |
| [docs/tls.md](docs/tls.md) | TLS/SSL — configuration, state machine, OpenSSL integration |
| [docs/configuration.md](docs/configuration.md) | JSON config, environment variables, structured logging |

## Platform Support

| Platform | Status |
|----------|--------|
| Linux (epoll) | Production-ready |
| macOS (kqueue) | Implemented |
| Windows (IOCP) | Planned |
