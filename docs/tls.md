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
| `TlsContext` | `include/tls/tls_context.h` | Server-wide RAII wrapper around `SSL_CTX` (server mode) |
| `TlsClientContext` | `include/tls/tls_client_context.h` | Client-mode `SSL_CTX` for upstream connections |
| `TlsConnection` | `include/tls/tls_connection.h` | Per-connection RAII wrapper around `SSL` (server + client) |

## TlsContext

One per server. Created by `HttpServer` when `config.tls.enabled == true`.

```cpp
TlsContext(const std::string& cert_file, const std::string& key_file);
```

- Loads certificate and private key, verifies they match
- Sets TLS 1.2 minimum by default (constructor checks return value, throws on failure)
- `SetMinProtocolVersion(version)` — throws if OpenSSL rejects the floor (prevents silent fail-open)
- `SetCipherList(ciphers)` — configurable cipher suites
- `SetAlpnProtocols({"h2", "http/1.1"})` — registers ALPN selection callback for HTTP/2 negotiation
- Non-copyable, non-movable
- **Shared ownership**: `HttpServer` creates via `make_shared`, passes to `NetServer` — guarantees context outlives both regardless of destruction order

## TlsClientContext

Client-mode `SSL_CTX` for outbound upstream connections. Created by `UpstreamHostPool` when `upstream.tls.enabled == true`, shared across all `PoolPartition` instances for that service.

```cpp
TlsClientContext(const UpstreamTlsConfig& config);
```

- **Peer verification**: `SSL_VERIFY_PEER` enabled by default (`verify_peer = true`). Loads CA bundle from `ca_file`.
- **SNI**: Sets `sni_hostname` on each `SSL` object via `SSL_set_tlsext_host_name()` so virtual-hosted upstreams route correctly.
- **Minimum version**: Same `min_version` support as server-mode (`"1.2"` or `"1.3"`).
- **Shared ownership**: `shared_ptr<TlsClientContext>` shared across PoolPartitions — outlives any single partition.

Key difference from `TlsContext` (server mode): no certificate/key loading (client doesn't present a cert), no ALPN advertisement (upstream is HTTP/1.1 only for now).

## Upstream TLS SNI Rule

The SNI hostname sent during the upstream TLS handshake is determined by a three-tier rule based on the upstream `host` type and the `tls.sni_hostname` config field:

| `host` type | `tls.sni_hostname` set | SNI sent | Verify name |
|---|---|---|---|
| Hostname | No | `host` value (trailing dot stripped) | `host` (dotless) |
| Hostname | Yes | `sni_hostname` | `sni_hostname` |
| IP literal | No | None — no SNI extension (RFC 6066 §3) | None |
| IP literal | Yes | `sni_hostname` | `sni_hostname` |

**No SNI on IP literals** — RFC 6066 §3 prohibits sending the SNI extension when the server is identified by an IP address. The gateway honours this by omitting the extension entirely when `host` is an IPv4 or IPv6 literal and no explicit `sni_hostname` is configured.

**Validator constraint** — `verify_peer: true` combined with an IP-literal `host` and no `sni_hostname` override is rejected at config load with a clear error. This combination is rejected because there is no certificate name to verify against.

**Explicit override example** — connecting to an upstream by IP while verifying its certificate:

```json
{
  "upstreams": [
    {
      "name": "secure-backend",
      "host": "10.0.1.5",
      "port": 443,
      "tls": {
        "enabled": true,
        "verify_peer": true,
        "sni_hostname": "api.internal",
        "ca_file": "/etc/ssl/ca-bundle.crt"
      }
    }
  ]
}
```

With `sni_hostname: "api.internal"`, the TLS handshake sends `api.internal` as the SNI extension and verifies the server certificate against that name — even though the TCP connection goes to `10.0.1.5`.

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
- `GetAlpnProtocol()` — returns the ALPN-negotiated protocol (e.g., `"h2"`, `"http/1.1"`, or `""` if not negotiated)

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
