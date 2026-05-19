# Callback Architecture

The server uses a 3-layer callback chain for separation of concerns. All callback types are centralized in registry headers with struct grouping.

## Callback Registries

- **`include/callbacks.h`** — Core reactor callbacks (`CALLBACKS_NAMESPACE`)
  - `ConnCallbacks` — ConnectionHandler: message, complete, close, error
  - `ChannelCallbacks` — Channel: read, write, close, error
  - `NetSrvCallbacks` — NetServer: new connection, close, error, message, send complete, timer
  - `DispatcherCallbacks` — Dispatcher: timeout trigger, timer handler
- **`include/http/http_callbacks.h`** — HTTP/WS protocol callbacks (`HTTP_CALLBACKS_NAMESPACE`)
  - `HttpConnCallbacks` — HttpConnectionHandler: request, route check, middleware (sync + async), upgrade, request count, shutdown check, resolve-route-options
  - `WsCallbacks` — WebSocketConnection: message, close, ping, error
  - `AsyncCompletionCallback` / `AsyncHandler` / `InterimResponseSender` / `ResourcePusher` — async route plumbing (final response, 1xx interim, H2 push)
  - `BodyStreamDataAvailableCallback` / `BodyStreamBytesConsumedCallback` / `BodyStreamBelowLowWaterCallback` — `BodyStream` consumer / producer notification (re-exported by `BodyStream::DataAvailableCallback` etc.)
  - `HttpParserHeadersCompleteCallback` / `HttpParserStreamingBodyCompleteCallback` — `HttpParser` → `HttpConnectionHandler` notifications (re-exported by `HttpParser::HeadersCompleteCallback` etc.)
- **`include/http2/http2_callbacks.h`** — HTTP/2 protocol callbacks (`HTTP2_CALLBACKS_NAMESPACE`)
  - `Http2SessionCallbacks` — Http2ConnectionHandler request / stream-open / stream-close / request-count / route-options resolver
  - `Http2DrainCompleteCallback` — graceful-shutdown drain completion (re-exported by `Http2ConnectionHandler::DrainCompleteCallback`)
- **`include/upstream/upstream_callbacks.h`** — Upstream pool callbacks (`UPSTREAM_CALLBACKS_NAMESPACE`)
  - `ReadyCallback` — Delivers a valid UpstreamLease on successful checkout
  - `ErrorCallback` — Delivers a PoolPartition error code on checkout failure
  - `H2StreamingAbortCallback` — Per-H2-stream keepalive + deferred terminal-error callable; used by `UpstreamH2Stream::streaming_abort_callback` and `UpstreamResponseSink::MakeDeferredErrorCallback()`

**Re-export pattern.** Callback aliases live in their layer's `*_callbacks.h`. Class headers (`ConnectionHandler`, `HttpConnectionHandler`, `Http2ConnectionHandler`, `BodyStream`, `HttpParser`) re-export the short class-scope name via `using LocalAlias = NAMESPACE::CanonicalAlias;` so caller source stays stable.

## Layer 1: Channel (fd event dispatch)

```
EPOLLIN  → read_callback  → ConnectionHandler::OnMessage()
EPOLLOUT → write_callback → ConnectionHandler::CallWriteCb()
EPOLLRDHUP/HUP → close_callback → ConnectionHandler::CallCloseCb()
EPOLLERR → error_callback → ConnectionHandler::CallErroCb()
```

## Layer 2: NetServer (connection lifecycle)

```
HandleNewConnection()    → creates ConnectionHandler, stores in map
HandleCloseConnection()  → removes from map, calls app callback
HandleErrorConnection()  → removes from map on error
HandleSendComplete()     → delegates to app callback
OnMessage()              → delegates to app callback with buffered data
```

## Layer 3: Application (business logic)

```
new_conn_callback_       → new connection established
close_conn_callback_     → connection cleanup
error_callback_          → connection error
on_message_callback_     → process incoming data
send_complete_callback_  → output buffer fully sent
```

## Key Design Patterns

### Weak Pointer Callbacks (Two-Phase Initialization)

Callbacks capture `weak_ptr<ConnectionHandler>` instead of `shared_ptr` to break circular references (Handler → Channel → Callback → Handler). `RegisterCallbacks()` is called after the object is wrapped in `shared_ptr`. Callbacks check `weak_ptr.lock()` before invoking.

### Edge-Triggered Semantics

All callbacks must handle partial reads/writes (EAGAIN/EWOULDBLOCK). Read loops continue until EAGAIN. Write buffers accumulate data until the socket is writable.

## Callback Type Reference

### ConnectionHandler (`ConnCallbacks`)

| Type | Signature | Purpose |
|------|-----------|---------|
| `ConnOnMsgCallback` | `void(shared_ptr<ConnectionHandler>, string&)` | Data received |
| `ConnCompleteCallback` | `void(shared_ptr<ConnectionHandler>)` | Send completed |
| `ConnCloseCallback` | `void(shared_ptr<ConnectionHandler>)` | Connection closed |
| `ConnErrorCallback` | `void(shared_ptr<ConnectionHandler>)` | Error occurred |
| `ConnWriteProgressCallback` | `void(shared_ptr<ConnectionHandler>, size_t)` | Partial write — resume deferred output at low watermark |
| `ConnConnectCompleteCallback` | `void(shared_ptr<ConnectionHandler>)` | TCP connect transitioned to CONNECTED (outbound) |
| `ConnHandshakeCompleteCallback` | `void()` | TLS handshake transitioned to READY |
| `ConnDeadlineTimeoutCallback` | `bool()` | Deadline timer fired; return `true` to keep the connection alive |

### NetServer (`NetSrvCallbacks`)

| Type | Signature | Purpose |
|------|-----------|---------|
| `NetSrvConnCallback` | `void(shared_ptr<ConnectionHandler>)` | New connection |
| `NetSrvCloseConnCallback` | `void(shared_ptr<ConnectionHandler>)` | Close notification |
| `NetSrvErrorCallback` | `void(shared_ptr<ConnectionHandler>)` | Error notification |
| `NetSrvOnMsgCallback` | `void(shared_ptr<ConnectionHandler>, string&)` | Incoming message |
| `NetSrvSendCompleteCallback` | `void(shared_ptr<ConnectionHandler>)` | Send completion |
| `NetSrvTimerCallback` | `void(shared_ptr<Dispatcher>)` | Timer event |

### Channel (`ChannelCallbacks`)

| Type | Signature | Purpose |
|------|-----------|---------|
| `ChannelReadCallback` | `void()` | Read event |
| `ChannelWriteCallback` | `void()` | Write ready |
| `ChannelCloseCallback` | `void()` | Channel closed |
| `ChannelErrorCallback` | `void()` | Channel error |

### Dispatcher (`DispatcherCallbacks`)

| Type | Signature | Purpose |
|------|-----------|---------|
| `DispatcherTOTriggerCallback` | `void(shared_ptr<Dispatcher>)` | Timeout trigger |
| `DispatcherTimerCallback` | `void(int)` | Timer handler |

### HTTP Async Callbacks (`HTTP_CALLBACKS_NAMESPACE`)

| Type | Signature | Purpose |
|------|-----------|---------|
| `AsyncCompletionCallback` | `void(HttpResponse)` | Deliver async final response to client |
| `AsyncHandler` | `void(HttpRequest&, InterimResponseSender, ResourcePusher, StreamingResponseSender, AsyncCompletionCallback)` | Async request handler — buffered OR streaming completion |
| `InterimResponseSender` | `void(int status, headers)` | Send a non-final 1xx (RFC 8297 Early Hints, etc.) before complete() |
| `ResourcePusher` | `int32_t(method, scheme, authority, path, response)` | HTTP/2 server push (returns promised stream_id, or -1) |

### BodyStream / HttpParser callbacks (`HTTP_CALLBACKS_NAMESPACE`)

| Type | Signature | Purpose |
|------|-----------|---------|
| `BodyStreamDataAvailableCallback` | `void()` | One-shot resume fired on `Push` / EOS / Abort |
| `BodyStreamBytesConsumedCallback` | `void(size_t)` | Producer-side: bytes drained by consumer — used to emit WINDOW_UPDATE on H2 inbound |
| `BodyStreamBelowLowWaterCallback` | `void()` | Producer-side: queue depth crossed low-water — clears backpressure |
| `HttpParserHeadersCompleteCallback` | `void()` | Fires from llhttp on_headers_complete (synchronous, pre-body) |
| `HttpParserStreamingBodyCompleteCallback` | `void()` | Fires from on_message_complete when a streaming body is active |

### HTTP/2 Callbacks (`HTTP2_CALLBACKS_NAMESPACE`)

| Type | Signature | Purpose |
|------|-----------|---------|
| `Http2RequestCallback` | `void(shared_ptr<Http2ConnectionHandler>, stream_id, request, response)` | Complete HTTP/2 request ready for dispatch |
| `Http2StreamCloseCallback` | `void(shared_ptr<Http2ConnectionHandler>, stream_id, error_code)` | Stream closed (RST_STREAM, END_STREAM, or error) |
| `Http2StreamOpenCallback` | `void(shared_ptr<Http2ConnectionHandler>, stream_id)` | New stream (HEADERS received) |
| `Http2RequestCountCallback` | `void()` | Bookkeeping — every dispatched request including rejects |
| `ResolveRouteOptionsCallback` | `RouteOptions(method, path)` | Route-mode resolver fired at HEADERS-complete |
| `Http2DrainCompleteCallback` | `void()` | Once when the connection finishes draining all active streams on graceful shutdown |

### Upstream Pool Callbacks (`UPSTREAM_CALLBACKS_NAMESPACE`)

| Type | Signature | Purpose |
|------|-----------|---------|
| `ReadyCallback` | `void(UpstreamLease)` | Successful checkout — delivers RAII lease |
| `ErrorCallback` | `void(int error_code)` | Failed checkout — delivers error code |
| `H2StreamingAbortCallback` | `void(int code, string msg)` | Per-H2-stream txn keepalive + deferred terminal-error callable; used by `UpstreamH2Stream::streaming_abort_callback` |

**Checkout error codes** (defined on `PoolPartition`):

| Code | Constant | Meaning |
|------|----------|---------|
| -1 | `CHECKOUT_POOL_EXHAUSTED` | All connections busy, wait queue full |
| -2 | `CHECKOUT_CONNECT_FAILED` | TCP connect error |
| -3 | `CHECKOUT_CONNECT_TIMEOUT` | Connect deadline expired |
| -4 | `CHECKOUT_SHUTTING_DOWN` | Pool is shutting down |
| -5 | `CHECKOUT_QUEUE_TIMEOUT` | Wait queue entry expired |
