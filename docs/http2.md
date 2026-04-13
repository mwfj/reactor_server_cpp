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
- **TE header**: only `te: trailers` allowed (OWS-trimmed, case-insensitive)
- **Required pseudo-headers (non-CONNECT)**: `:method`, `:path`, and `:scheme` must be present
- **CONNECT pseudo-headers**: `:method` + `:authority` required; `:path` and `:scheme` must NOT be present (checked by presence, not value — an explicit empty `:path` is rejected)
- **`:authority` vs `host`**: case-insensitive hostname comparison (RFC 3986 Section 3.2.2), exact port match, IPv6 bracket-aware
- **Trailer validation**: pseudo-headers forbidden; `content-length`, `host`, `authorization`, `content-type`, `content-encoding`, `content-range`, and connection-specific headers rejected per RFC 9110 Section 6.5.1
- **1xx responses**: all `status < 200` rejected from app-facing `SubmitResponse()` with RST_STREAM(INTERNAL_ERROR); internal 100-continue uses `nghttp2_submit_headers` directly
- **Unsupported Expect**: rejected with 417 response + RST_STREAM(NO_ERROR) when client side is still open (no END_STREAM on request); clean 417 without RST when request already ended
- **Body size limits** enforced per-stream via RST_STREAM(CANCEL)

### TLS Requirements

For h2 over TLS:
- TLS 1.2 minimum (already enforced by existing TlsContext)
- ALPN negotiation required (no prior knowledge over TLS)
- AEAD cipher suites recommended (default OpenSSL config satisfies this)

## Graceful Shutdown

```
HttpServer::Stop()
  1. Existing HTTP/1.x + WS shutdown (WS Close 1001)
  2. StopAccepting() — close listen socket, barrier for in-flight accepts
  3. For each HTTP/2 connection:
     → Install DrainCompleteCallback (under drain_mtx_)
     → RequestShutdown() → enqueues dispatcher-thread task via RunOnDispatcher
     → On dispatcher: sends GOAWAY(NO_ERROR) via nghttp2
     → If deferred output (backpressure), ResumeOutput() before CloseAfterWrite
     → New streams refused (IsGoawaySent || owner shutdown), existing drain
     → NotifyDrainComplete() when ActiveStreamCount() == 0 AND
       output buffer empty AND no deferred nghttp2 frames AND !WantWrite()
     → Re-check after RequestShutdown: if connection closed during setup,
       OnH2DrainComplete removes stale entry from drain set
  4. NetServer skips draining H2 connections in its CloseAfterWrite sweep
  5. WaitForH2Drain() blocks until all drain or shutdown_drain_timeout_sec expires
  6. Timeout: ForceClose remaining connections
  7. Second drain barrier covers final H2 CloseAfterWrite tasks
```

The shutdown is fully graceful: GOAWAY carries `last_stream_id` so clients know which requests to retry, active streams drain with full flow control (WINDOW_UPDATE still processed), and the nghttp2 session is only touched on its dispatcher thread (no cross-thread mutation). A configurable `shutdown_drain_timeout_sec` (default 30s) bounds the wait.

**Drain-complete is transport-level:** `NotifyDrainComplete()` only fires from `OnSendComplete()` when the transport output buffer is empty (bytes on the wire), not just when nghttp2 has serialized the frames. If `ResumeOutput()` adds bytes but the buffer was already empty and no write event follows, `OnSendComplete` re-enters to check drain eligibility.

**Shutdown vs peer half-close:** `IsCloseDeferred()` (set on both server shutdown and peer EOF) is NOT used to reject new streams or skip H2 initialization. Only `IsGoawaySent()` and the owner's `IsShutdownRequested()` flag (with `!IsInitializing()` guard) reject new streams. This ensures requests arriving with a peer FIN in the same read batch are still serviced.

If `Stop()` is called from a dispatcher thread (e.g., a request handler calling `HttpServer::Stop()`), the H2 drain wait is skipped to avoid deadlock. A warning is logged. This matches the existing `ThreadPool::Stop()` self-stop safety pattern.

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

## Request Timeout

HTTP/2 request timeouts are enforced per-stream via `request_timeout_sec`:

- Each stream's creation time is tracked. The connection deadline is set to `oldest_incomplete_start + request_timeout_sec`.
- When the deadline fires, only the expired stream(s) are RST'd (`RST_STREAM(CANCEL)`). Healthy streams on the same connection are unaffected.
- The `DeadlineTimeoutCb` returns `true` (keep connection alive) after RST'ing expired streams.
- **Safety deadline for idle_timeout_sec=0:** After resetting all streams, if no active streams remain and `idle_timeout_sec` is disabled, a safety deadline of `request_timeout_sec` is armed to prevent the connection from staying open forever. This only fires when the connection is truly idle (no active streams) — it never tears down healthy sibling streams.
- Rejected streams (e.g. 417 half-open) are included in both deadline calculation and `ResetExpiredStreams`, ensuring they don't escape timeout enforcement or consume `max_concurrent_streams` slots indefinitely.
- Once all incomplete/rejected streams are resolved, the deadline is cleared and `idle_timeout` governs.
- New streams cannot extend the deadline for older stalled streams (the deadline always reflects the oldest incomplete stream).

### Handshake + Request Timeout

For TLS connections, the total timeout exposure is up to `2 x request_timeout_sec`: one window for the TLS handshake + protocol detection, and a separate window for the first HTTP request. This is intentional — separating handshake and request timeouts is standard (cf. nginx `ssl_handshake_timeout` vs `client_header_timeout`). The handshake deadline is set in `HandleNewConnection` and reset by the protocol handler once it takes over.

## Output Backpressure

`SendPendingFrames()` stops pulling frames from nghttp2 when the transport output buffer exceeds a high watermark (`max(128KB, max_frame_size)`). At least one frame is always pulled per call so control frames (SETTINGS ACK, GOAWAY) from the current `ReceiveData` call are delivered. Once `output_deferred_` is set, subsequent calls return immediately until `ResumeOutput()` clears the flag. This bounds per-connection output buffering and prevents slow peers from causing unbounded memory growth.

Resume happens at two points:
- **`OnSendComplete()`** (buffer drains to zero): schedules async resume via `RunOnDispatcher()`.
- **`OnWriteProgress()`** (partial write, buffer below watermark): resumes deferred output at the low watermark so multiplexed streams make progress without waiting for full drain. Uses a `write_progress_callback` fired from `ConnectionHandler::CallWriteCb()` after each successful partial write.

If the connection is closing (`IsClosing()`), `SendPendingFrames` breaks the loop early to avoid wasting CPU serializing frames for a disconnected peer.

## Early Hints (103)

HTTP/2 async routes can emit `103 Early Hints` responses before the final response via the `InterimResponseSender` passed to the handler — the same API as HTTP/1.1 (see [docs/http.md](http.md#early-hints-103) for the basic usage and contract). On HTTP/2 the interim is sent as a non-final HEADERS frame **without** `END_STREAM`, so the same stream carries both the 103 and the eventual 200.

Defined in [RFC 8297](https://datatracker.ietf.org/doc/html/rfc8297); HTTP/2 wire format in [RFC 9113 §8.1](https://datatracker.ietf.org/doc/html/rfc9113#section-8.1).

### Implementation notes specific to HTTP/2

- **`SubmitInterimHeaders`** on `Http2Session` submits a HEADERS frame with `NGHTTP2_FLAG_NONE` and no data provider, leaving the stream in `HALF_CLOSED_REMOTE` so the subsequent `SubmitResponse` can emit the final block on the same stream.
- **`final_response_submitted_`** — per-stream boolean flag set in `SubmitResponse` on success. `SubmitInterimHeaders` refuses to submit when the flag is set, preventing a late 1xx from racing or corrupting a stream nghttp2 already considers half-closed.
- **Dispatcher-thread-only contract** — `Http2ConnectionHandler::SendInterimResponse` rejects calls from foreign threads with a warn log, rather than silently mutating nghttp2 state across a thread boundary. Async code that lives off-dispatcher (e.g. an upstream completion thread) must hop via `RunOnDispatcher()` before calling `send_interim`.
- **Peer-closed-stream safety** — if the client RST's the stream or drops the transport before the interim fires, `SubmitInterimHeaders` observes a missing/closed stream and drops the submit without crashing. No special teardown is needed in the handler.
- **`send_interim(100, ...)`** — rejected. The framework already emits `100 Continue` automatically when the client includes `Expect: 100-continue`; application code cannot emit additional 100s.
- **`send_interim(101, ...)`** — rejected. `101 Switching Protocols` is invalid in HTTP/2 (RFC 9113 §8.6).
- **Forbidden headers** — `Connection`, `Keep-Alive`, `Proxy-Connection`, `TE`, `Transfer-Encoding`, `Upgrade`, `Content-Length`, any `Proxy-*`, and the HTTP/2 pseudo-headers are stripped before serialization.

## Server Push

HTTP/2 server push (RFC 9113 §8.4) is **opt-in** via `http2.enable_push` (default `false`). When enabled, request handlers can pre-send resources the client is about to need — typically critical CSS / JS referenced from a parent HTML response — before the client has parsed the parent and discovered the dependency.

> **⚠ Modern browser caveat:** Chrome and Firefox have **removed client-side push support**. As of this writing, the only realistic consumers are tooling, internal RPC clients, and curated deployments where the client is known to honor pushes. For browser performance, prefer 103 Early Hints (preload hints) over server push.

### Enabling

```jsonc
// config/server.json
{
  "http2": {
    "enabled": true,
    "enable_push": true
  }
}
```

Or via env: `REACTOR_HTTP2_ENABLE_PUSH=true`.

The flag controls the outbound `SETTINGS_ENABLE_PUSH` byte in the server preface (RFC 9113 §7):
- `enable_push=false`: server advertises `{ENABLE_PUSH, 0}` — clients are notified push is disabled.
- `enable_push=true`: the entry is **omitted entirely** — a server MUST NOT advertise the value `1` per the RFC. nghttp2's local default of 1 then applies internally so push submission works.

### Async handler — bound `ResourcePusher`

```cpp
server.GetAsync("/page",
    [&](const HttpRequest&,
        HttpRouter::InterimResponseSender /*send_interim*/,
        HttpRouter::ResourcePusher        push_resource,
        HttpRouter::AsyncCompletionCallback complete) {
    HttpResponse pushed_css;
    pushed_css.Status(200).Body(css_bytes, "text/css");
    int32_t promised_id = push_resource(
        "GET", "https", "example.com", "/style.css", pushed_css);
    // promised_id > 0 on success; -1 on validation/state failure
    // (push disabled, peer refused, parent closed, GOAWAY, etc.)

    HttpResponse main;
    main.Status(200).Body(html_bytes, "text/html");
    complete(std::move(main));
});
```

### Sync handler — `http::PushResource()`

Sync handlers can't grow extra parameters without breaking every existing signature, so push is exposed via a free function that reads a thread-local pointer installed around `router_.Dispatch`:

```cpp
#include "http/push_helper.h"

server.Get("/page", [](const HttpRequest&, HttpResponse& res) {
    HttpResponse pushed_css;
    pushed_css.Status(200).Body(css_bytes, "text/css");
    int32_t promised = http::PushResource(
        "GET", "https", "example.com", "/style.css", pushed_css);
    (void)promised;  // best-effort
    res.Status(200).Body(html_bytes, "text/html");
});
```

`http::PushResource()` returns `-1` (with a debug log) when called outside a sync H2 dispatch — including from any HTTP/1.x handler. **Push is HTTP/2 only.**

### Contract

| Constraint | Behavior |
|---|---|
| Method | Only `GET` or `HEAD` (RFC 9113 §8.4 — server push is for safe, body-less methods). Anything else returns -1 + warn. |
| Scheme | Only `http` or `https`. |
| Path | Must be non-empty and start with `/`. |
| Authority | Must be non-empty. |
| Local config | `http2.enable_push` must be true. |
| Peer | Client's `SETTINGS_ENABLE_PUSH` must not be 0 (peer can refuse via its preface). |
| Parent stream | Must exist and be open at submit time. |
| Connection | `GOAWAY` must not have been sent. |
| Thread | **Dispatcher-thread only.** Off-thread callers must hop via `conn->RunOnDispatcher()`. |
| HEAD body | Pushed `HEAD` responses get headers but **no DATA frame** (per RFC 9110 §9.3.2). |
| Failure mode | Best-effort. A failed push (any reason) returns -1 and **never breaks** the parent response. |

### Stream accounting

Pushed (server-initiated) streams have their own lifecycle that intentionally bypasses the request-parsing safety nets:

- **Not counted in `total_requests`** — that counter is for client-initiated requests only.
- **Not eligible for `parse_timeout_sec`** — pushed streams skip `OnStreamBecameIncomplete()` so `OldestIncompleteStreamStart()` never observes them, and `ResetExpiredStreams`'s parse-timeout branch can't RST a push mid-response.
- **Counted in per-connection `local_stream_count_`** — incremented by `PushResource` on success, decremented by the stream-close callback. Used for abrupt-close compensation.
- **Drained at shutdown** — pushed streams are normal HTTP/2 streams from nghttp2's perspective, so the existing graceful-shutdown drain (`shutdown_drain_timeout_sec`) waits for them like any other active stream.

## Limitations

- No WebSocket-over-HTTP/2 (Extended CONNECT, RFC 8441)
- No HTTP/2 priority tree optimization (nghttp2 handles basic priority)
- No manual flow control (nghttp2 automatic mode)

## Third-Party Dependency

**nghttp2** (v1.64.0) — HTTP/2 C library. Vendored at `third_party/nghttp2/`. Compiled as C99 objects, linked with C++ code. Hidden behind pimpl pattern in `Http2Session` — no nghttp2 types in public headers. MIT license.
