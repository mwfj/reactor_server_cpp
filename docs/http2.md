# HTTP/2 Layer

HTTP/2 (RFC 9113) support built on [nghttp2](https://nghttp2.org/), running alongside the existing HTTP/1.x layer. Both protocols share the same `HttpRouter`, middleware chain, `HttpRequest`, and `HttpResponse` types — application code is unchanged.

## Quick Start

```cpp
#include "http/http_server.h"

// HTTP/2 is enabled by default — no extra setup needed.
// The same HttpServer handles both HTTP/1.x and HTTP/2.
HttpServer server("0.0.0.0", 8080);

server.Get("/hello", [](const HttpRequest& req, HttpResponse& res) {
    res.Status(200).Json(R"({"protocol":"h2 or h1"})");
});

server.Start();
```

Test with curl:
```bash
# Cleartext h2c (prior knowledge)
curl --http2-prior-knowledge http://localhost:8080/hello

# TLS h2 (requires TLS config)
curl --http2 https://localhost:8080/hello
```

## Protocol Negotiation

HTTP/2 connections are established via two mechanisms:

### ALPN over TLS (h2)

During the TLS handshake, the server advertises `h2` and `http/1.1` via ALPN (Application-Layer Protocol Negotiation). The client selects its preferred protocol. If `h2` is selected, the connection enters HTTP/2 mode immediately after the handshake completes.

```
Client                 TLS Handshake                Server
  |-- ClientHello (ALPN: [h2, http/1.1]) -------->|
  |                  Server selects "h2"           |
  |<---- ServerHello (ALPN: h2) ------------------|
  |                  TLS complete                  |
  |-- Client Preface (magic + SETTINGS) --------->|
  |<---- Server Preface (SETTINGS) ---------------|
  |                  HTTP/2 established            |
```

### Prior Knowledge (h2c)

For cleartext connections, the client sends the 24-byte HTTP/2 connection preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`) as its first bytes. The server detects this preface and enters HTTP/2 mode.

```
Client                 TCP Connection              Server
  |-- "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" ------->|
  |   + SETTINGS frame                             |
  |   Server detects preface → HTTP/2 mode         |
  |<---- Server Preface (SETTINGS) ---------------|
  |                  HTTP/2 established            |
```

If the first bytes don't match the HTTP/2 preface, the connection falls through to HTTP/1.x handling.

**Note:** The HTTP/1.1 Upgrade mechanism (`Upgrade: h2c`) is not supported — it is deprecated in RFC 9113.

## Components

| Component | Header | Role |
|-----------|--------|------|
| `Http2Session` | `include/http2/http2_session.h` | nghttp2 session wrapper (pimpl), stream management, flood protection |
| `Http2Stream` | `include/http2/http2_stream.h` | Per-stream state: request accumulation, response lifecycle |
| `Http2ConnectionHandler` | `include/http2/http2_connection_handler.h` | Per-connection HTTP/2 state machine, bridges reactor to nghttp2 |
| `ProtocolDetector` | `include/http2/protocol_detector.h` | ALPN + preface-based protocol detection |
| `Http2Config` | `include/config/server_config.h` | HTTP/2 tunables (max_concurrent_streams, window size, etc.) |

## Architecture

```
Layer 5: HttpServer (unchanged — handles both protocols)
Layer 4: HttpRouter (unchanged — receives HttpRequest/HttpResponse)
Layer 3: HttpConnectionHandler ←OR→ Http2ConnectionHandler
         (HTTP/1.x path)            (HTTP/2 path)
                                      ↓
                                 Http2Session (nghttp2 wrapper)
                                   ├── Http2Stream[1]
                                   ├── Http2Stream[3]
                                   └── Http2Stream[n]
         ProtocolDetector (routes to the correct handler)
Layer 2: TlsContext + TlsConnection (ALPN negotiation)
Layer 1: ConnectionHandler, Channel, Dispatcher (reactor core)
```

Both protocol paths converge at `HttpRouter` — routes, middleware, and handlers work identically regardless of HTTP version.

## Data Flow

```
Client sends    → epoll_wait → ConnectionHandler::OnMessage (read until EAGAIN)
HTTP/2 request    → [TLS: SSL_read, ALPN check]
                  → HttpServer::HandleMessage
                     → ProtocolDetector routes to Http2ConnectionHandler
                  → Http2ConnectionHandler::OnRawData
                     → nghttp2_session_mem_recv2(session, data, len)
                        → on_begin_headers_callback → creates Http2Stream
                        → on_header_callback → populates HttpRequest
                        → on_data_chunk_recv_callback → appends body
                        → on_frame_recv_callback (END_STREAM) →
                           dispatches through HttpRouter
                           → handler(request, response)
                           → nghttp2_submit_response2()
                     → nghttp2_session_mem_send2(session) → response bytes
                     → ConnectionHandler::SendRaw()
```

## Stream Multiplexing

HTTP/2 multiplexes multiple requests over a single TCP connection using streams. Each stream has:
- A unique odd-numbered ID (assigned by the client)
- Independent state machine: IDLE → OPEN → HALF_CLOSED_REMOTE → CLOSED
- Its own flow control window

The server processes streams concurrently — nghttp2 handles frame interleaving automatically.

## Configuration

### Http2Config

```cpp
struct Http2Config {
    bool enabled = true;                   // Enable HTTP/2 (h2 + h2c)
    uint32_t max_concurrent_streams = 100; // Max simultaneous streams per connection
    uint32_t initial_window_size = 65535;  // Flow control window (64 KB - 1)
    uint32_t max_frame_size = 16384;       // Max frame payload (16 KB)
    uint32_t max_header_list_size = 65536; // Max header block size (64 KB)
};
```

### JSON Config

```json
{
    "http2": {
        "enabled": true,
        "max_concurrent_streams": 100,
        "initial_window_size": 65535,
        "max_frame_size": 16384,
        "max_header_list_size": 65536
    }
}
```

### Environment Variable Overrides

| Variable | Config Field |
|----------|-------------|
| `REACTOR_HTTP2_ENABLED` | `http2.enabled` |
| `REACTOR_HTTP2_MAX_CONCURRENT_STREAMS` | `http2.max_concurrent_streams` |
| `REACTOR_HTTP2_INITIAL_WINDOW_SIZE` | `http2.initial_window_size` |
| `REACTOR_HTTP2_MAX_FRAME_SIZE` | `http2.max_frame_size` |
| `REACTOR_HTTP2_MAX_HEADER_LIST_SIZE` | `http2.max_header_list_size` |

### Validation

RFC 9113 constraints enforced by `ConfigLoader::Validate()`:
- `max_concurrent_streams` >= 1
- `initial_window_size`: 1 to 2^31-1
- `max_frame_size`: 16384 to 16777215
- `max_header_list_size` >= 1

## Security

### Flood Protection

| Attack | Detection | Response |
|--------|-----------|----------|
| Rapid Reset (CVE-2023-44487) | RST_STREAM count > 100/10s | GOAWAY(ENHANCE_YOUR_CALM) |
| SETTINGS Flood | SETTINGS count > 100/10s | GOAWAY(ENHANCE_YOUR_CALM) |
| PING Flood | PING count > 50/10s | GOAWAY(ENHANCE_YOUR_CALM) |
| CONTINUATION Flood | Enforced via max_header_list_size | RST_STREAM (by nghttp2) |

### Header Validation

Per RFC 9113 Section 8.2.2:
- **Forbidden headers** rejected: `connection`, `keep-alive`, `proxy-connection`, `transfer-encoding`, `upgrade`
- **TE header**: only `te: trailers` allowed
- **Required pseudo-headers**: `:method` and `:path` must be present
- **Body size limits** enforced per-stream via RST_STREAM(CANCEL)

### TLS Requirements

For h2 over TLS:
- TLS 1.2 minimum (already enforced by existing TlsContext)
- ALPN negotiation required (no prior knowledge over TLS)
- AEAD cipher suites recommended (default OpenSSL config satisfies this)

## Graceful Shutdown

```
HttpServer::Stop()
  1. Collect HTTP/2 connections under conn_mtx_, release lock
  2. Send GOAWAY(NO_ERROR) to each h2 connection
  3. CloseAfterWrite() to drain pending responses
  4. Existing HTTP/1.x + WS shutdown (WS Close 1001)
  5. NetServer::Stop()
```

## Pseudo-Header Mapping

HTTP/2 pseudo-headers are mapped to `HttpRequest` fields:

| HTTP/2 Pseudo-Header | HttpRequest Field |
|----------------------|-------------------|
| `:method` | `request.method` |
| `:path` | `request.url`, split into `request.path` + `request.query` |
| `:authority` | `request.headers["host"]` |
| `:scheme` | Not stored (informational) |

For HTTP/2 requests, `request.http_major = 2` and `request.http_minor = 0`.

Cookie headers arriving as separate HTTP/2 header fields are concatenated with `"; "` per RFC 9113 Section 8.2.3.

## Limitations

- Server push disabled (SETTINGS_ENABLE_PUSH = 0)
- No WebSocket-over-HTTP/2 (Extended CONNECT, RFC 8441)
- No HTTP/2 priority tree optimization (nghttp2 handles basic priority)
- No manual flow control (nghttp2 automatic mode)

## Third-Party Dependency

**nghttp2** (v1.64.0) — HTTP/2 C library. Vendored at `third_party/nghttp2/`. Compiled as C99 objects, linked with C++ code. Hidden behind pimpl pattern in `Http2Session` — no nghttp2 types in public headers. MIT license.
