# Callback Architecture

The server uses a 3-layer callback chain for separation of concerns. All callback types are centralized in registry headers with struct grouping.

## Callback Registries

- **`include/callbacks.h`** — Core reactor callbacks (`CALLBACKS_NAMESPACE`)
  - `ConnCallbacks` — ConnectionHandler: message, complete, close, error
  - `ChannelCallbacks` — Channel: read, write, close, error
  - `NetSrvCallbacks` — NetServer: new connection, close, error, message, send complete, timer
  - `DispatcherCallbacks` — Dispatcher: timeout trigger, timer handler
- **`include/http/http_callbacks.h`** — HTTP/WS protocol callbacks (`HTTP_CALLBACKS_NAMESPACE`)
  - `HttpConnCallbacks` — HttpConnectionHandler: request, route check, middleware, upgrade, request count, shutdown check
  - `WsCallbacks` — WebSocketConnection: message, close, ping, error
  - `AsyncCompletionCallback` — Delivers final HttpResponse to client (async routes)
  - `AsyncHandler` — Async request handler receiving request + completion callback
- **`include/upstream/upstream_callbacks.h`** — Upstream pool callbacks (`UPSTREAM_CALLBACKS_NAMESPACE`)
  - `ReadyCallback` — Delivers a valid UpstreamLease on successful checkout
  - `ErrorCallback` — Delivers a PoolPartition error code on checkout failure

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
| `AsyncCompletionCallback` | `void(HttpResponse)` | Deliver async response to client |
| `AsyncHandler` | `void(const HttpRequest&, AsyncCompletionCallback)` | Async request handler |

### Upstream Pool Callbacks (`UPSTREAM_CALLBACKS_NAMESPACE`)

| Type | Signature | Purpose |
|------|-----------|---------|
| `ReadyCallback` | `void(UpstreamLease)` | Successful checkout — delivers RAII lease |
| `ErrorCallback` | `void(int error_code)` | Failed checkout — delivers error code |

**Checkout error codes** (defined on `PoolPartition`):

| Code | Constant | Meaning |
|------|----------|---------|
| -1 | `CHECKOUT_POOL_EXHAUSTED` | All connections busy, wait queue full |
| -2 | `CHECKOUT_CONNECT_FAILED` | TCP connect error |
| -3 | `CHECKOUT_CONNECT_TIMEOUT` | Connect deadline expired |
| -4 | `CHECKOUT_SHUTTING_DOWN` | Pool is shutting down |
| -5 | `CHECKOUT_QUEUE_TIMEOUT` | Wait queue entry expired |
