# TLS/SSL Support

Optional TLS/SSL using OpenSSL 3.x. TLS sits below the HTTP/WebSocket layer, transparently wrapping socket I/O. When enabled, `ConnectionHandler` uses `SSL_read()`/`SSL_write()` instead of raw `::read()`/`::write()`. Without configuration, connections use raw TCP exactly as before.

## Quick Start

```cpp
#include "http/http_server.h"
#include "config/server_config.h"

ServerConfig config;
config.bind_host = "0.0.0.0";
config.bind_port = 443;
config.tls.enabled = true;
config.tls.cert_file = "/etc/ssl/server.pem";
config.tls.key_file = "/etc/ssl/server.key";
config.tls.min_version = "1.2";

HttpServer server(config);
server.Get("/", [](const HttpRequest& req, HttpResponse& res) {
    res.Status(200).Text("Hello over TLS!");
});
server.Start();
```

## Components

| Component | Header | Role |
|-----------|--------|------|
| `TlsContext` | `include/tls/tls_context.h` | Server-wide RAII wrapper around `SSL_CTX` |
| `TlsConnection` | `include/tls/tls_connection.h` | Per-connection RAII wrapper around `SSL` |

## TlsContext

One per server. Created by `HttpServer` when `config.tls.enabled == true`.

```cpp
TlsContext(const std::string& cert_file, const std::string& key_file);
```

- Loads certificate and private key, verifies they match
- Sets TLS 1.2 minimum by default (constructor checks return value, throws on failure)
- `SetMinProtocolVersion(version)` — throws if OpenSSL rejects the floor (prevents silent fail-open)
- `SetCipherList(ciphers)` — configurable cipher suites
- Non-copyable, non-movable
- **Shared ownership**: `HttpServer` creates via `make_shared`, passes to `NetServer` — guarantees context outlives both regardless of destruction order

## TlsConnection

One per client connection. Created in `NetServer::HandleNewConnection()` when TLS context is configured.

```cpp
TlsConnection(TlsContext& ctx, int fd);
```

### Return Codes

| Constant | Value | Meaning |
|----------|-------|---------|
| `TLS_COMPLETE` | 0 | Handshake complete / would_block |
| `TLS_WANT_READ` | 1 | Needs read readiness |
| `TLS_WANT_WRITE` | 2 | Needs write readiness |
| `TLS_ERROR` | -1 | Fatal error |
| `TLS_PEER_CLOSED` | -2 | Peer sent close_notify |
| `TLS_CROSS_RW` | -3 | Read needs write / Write needs read (renegotiation) |

### Methods

- `DoHandshake()` — returns TLS_COMPLETE, TLS_WANT_READ, TLS_WANT_WRITE, or TLS_ERROR
- `Read(buf, len)` — returns >0 bytes, TLS_COMPLETE (would_block), TLS_CROSS_RW, TLS_PEER_CLOSED, or TLS_ERROR
- `Write(buf, len)` — returns >0 bytes, TLS_COMPLETE (would_block), TLS_CROSS_RW, or TLS_ERROR
- `Shutdown()` — sends close_notify
- `IsHandshakeComplete()`, `GetCipherName()`, `GetProtocolVersion()`

## TLS State Machine in ConnectionHandler

```
                     ┌──────────────┐
                     │    NONE      │  (no TLS, raw TCP)
                     │  ::read()   │
                     │  ::send()   │
                     └──────────────┘

  ┌──────────────┐         ┌──────────────┐
  │  HANDSHAKE   │────────▶│    READY     │
  │ DoHandshake()│  done   │ SSL_read()   │
  │              │         │ SSL_write()  │
  └──────────────┘         └──────────────┘
        ▲                        │
        │                        │
    SetTlsConnection()     Normal operation
    (before RegisterCallbacks)
```

### OnMessage() Behavior

| TLS State | Read Method |
|-----------|-------------|
| `NONE` | `::read(fd, buf, len)` |
| `HANDSHAKE` | `tls_->DoHandshake()` (WANT_READ → return, WANT_WRITE → EnableWriteMode) |
| `READY` | `tls_->Read(buf, len)` |

### CallWriteCb() Behavior

| TLS State | Write Method |
|-----------|-------------|
| `NONE` | `::send(fd, buf, len, SEND_FLAGS)` |
| `HANDSHAKE` | `tls_->DoHandshake()` (on complete, falls through to flush pending output) |
| `READY` | `tls_->Write(buf, len)` |

## TLS Injection Ordering

**Critical**: TLS is injected BEFORE `RegisterCallbacks()` in `NetServer::HandleNewConnection()`:

```cpp
auto conn = make_shared<ConnectionHandler>(dispatcher, std::move(socket));
if (tls_ctx_) {
    auto tls = make_unique<TlsConnection>(*tls_ctx_, conn->fd());
    conn->SetTlsConnection(std::move(tls));  // BEFORE RegisterCallbacks
}
conn->RegisterCallbacks();  // Enables epoll — safe now
```

This prevents a race where `RegisterCallbacks()` enables epoll read mode and Client Hello bytes arrive before `OnMessage()` knows about TLS.

## Configuration

### JSON Config File

```json
{
    "tls": {
        "enabled": true,
        "cert_file": "/etc/ssl/server.pem",
        "key_file": "/etc/ssl/server.key",
        "min_version": "1.2"
    }
}
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `REACTOR_TLS_ENABLED` | `true` / `false` |
| `REACTOR_TLS_CERT` | Path to certificate file |
| `REACTOR_TLS_KEY` | Path to private key file |

### Validation

`ConfigLoader::Validate()` checks:
- If TLS enabled, cert_file and key_file must be non-empty
- Certificate and key must match (verified by `SSL_CTX_check_private_key()`)

## Security Design

### Never Fail Open

All OpenSSL configuration calls check return values. If `SSL_CTX_set_min_proto_version()` fails, the server throws rather than starting with a weaker TLS minimum:

```cpp
if (!SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION)) {
    throw std::runtime_error("Failed to set minimum TLS version");
}
```

### Minimum Version

Default is TLS 1.2. Can be set to `"1.2"` or `"1.3"` via config. The `SetMinProtocolVersion()` method enforces this at the SSL_CTX level.

## Dependency

**OpenSSL 3.x** — system library (`-lssl -lcrypto`). Also provides SHA-1 and base64 for the WebSocket handshake (`Sec-WebSocket-Accept` header computation).

Install: `sudo apt install libssl-dev` (Ubuntu/Debian) or `brew install openssl` (macOS).
