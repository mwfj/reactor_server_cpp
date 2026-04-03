# Architecture

## Reactor Pattern

The server uses the [Reactor pattern](https://en.wikipedia.org/wiki/Reactor_pattern) with edge-triggered I/O multiplexing. A single event loop per dispatcher thread waits for I/O readiness on all registered file descriptors, then dispatches events to the appropriate handlers.

```
                    ┌──────────────────────────────────┐
                    │     Dispatcher (Event Loop)      │
                    │                                  │
                    │  while (is_running_) {           │
                    │    channels = WaitForEvent()     │
                    │    for ch : channels             │
                    │      ch->HandleEvent()           │
                    │  }                               │
                    └───────────────┬──────────────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              ▼                     ▼                     ▼
     ┌────────────────┐   ┌────────────────┐   ┌────────────────┐
     │ Accept Channel │   │ Client Channel │   │  Wake Channel  │
     │ (listen fd)    │   │ (conn fd)      │   │ (eventfd/pipe) │
     └────────────────┘   └────────────────┘   └────────────────┘
```

## Layered Design

```
Layer 5: HttpServer                          (application entry point)
Layer 4: HttpRouter, WebSocketConnection    (routing, WS message API)
Layer 3: HttpParser, WebSocketParser        (HTTP/1.1 protocol parsing)
         HttpConnectionHandler              (HTTP/1.1 state machine)
         Http2Session, Http2Stream          (HTTP/2 session/stream management)
         Http2ConnectionHandler             (HTTP/2 state machine, nghttp2 bridge)
         ProtocolDetector                   (HTTP/1.x vs HTTP/2 auto-detection)
Layer 2: TlsContext, TlsConnection          (optional TLS, ALPN negotiation)
Layer 1: ConnectionHandler, Channel,        (reactor core)
         Dispatcher, EventHandler
```

Layers 1–2 are the transport. Layers 3–5 are the protocol. HTTP/1.x and HTTP/2 are parallel handlers at Layer 3, selected by `ProtocolDetector` at connection time. Both converge on the same `HttpRouter` at Layer 4.

## Core Components

### Dispatcher
Central event loop coordinator. Wraps the platform-specific `EventHandler` (epoll on Linux, kqueue on macOS). Supports cross-thread task queueing via `EnQueue()`/`WakeUp()` using eventfd (Linux) or pipe (macOS). Connection timeout scanning via timerfd.

### Channel
Represents a file descriptor + its event callbacks (read, write, close, error). Uses edge-triggered mode for client connections. Holds a `weak_ptr<Dispatcher>` to avoid circular references.

### ConnectionHandler
Per-connection state: socket, channel, I/O buffers, TLS state machine. Two-phase initialization with `RegisterCallbacks()` using weak_ptr captures for safe destruction. Supports both length-prefixed (`SendData`) and raw (`SendRaw`) output modes.

### NetServer
Orchestrates the acceptor, dispatchers, and connection lifecycle. Multi-threaded: one acceptor dispatcher + N socket dispatchers (one per worker thread). Thread-safe connection map with mutex protection.

### Acceptor
Listening socket setup with optimal TCP options (SO_REUSEADDR, SO_REUSEPORT, TCP_NODELAY, SO_KEEPALIVE). Uses `accept4()` with SOCK_NONBLOCK for atomic non-blocking accept.

## Data Flow

```
Client connects → Acceptor → NetServer::HandleNewConnection
                              → creates ConnectionHandler + Channel
                              → registers with Dispatcher (EPOLLIN | EPOLLET)

Client sends    → epoll_wait → Channel::HandleEvent (EPOLLIN)
                              → ConnectionHandler::OnMessage (read until EAGAIN)
                              → application callback with buffered data

Server replies  → SendData/SendRaw → direct send or buffer + EPOLLOUT
                → epoll_wait → Channel::HandleEvent (EPOLLOUT)
                              → CallWriteCb (drain buffer, disable EPOLLOUT when empty)

Client closes   → EPOLLRDHUP → CallCloseCb → HandleCloseConnection
                              → remove from map, close fd
```

## Memory Management

- `unique_ptr`: sole ownership (Dispatcher→EventHandler, Acceptor→SocketHandler, ConnectionHandler→SocketHandler)
- `shared_ptr`: shared ownership (Channels in epoll map, ConnectionHandlers in connections map)
- `weak_ptr`: non-owning observers (Channel→Dispatcher, callback captures)
- Two-phase init: callbacks registered after object is wrapped in shared_ptr, using weak_ptr captures to break circular references

## Cross-Thread Communication

```
Other Thread                         Dispatcher Thread
     │                                      │
     │ EnQueue(task)                        │
     ├─ lock mutex, push task, unlock       │
     │                                      │
     │ WakeUp()                             │
     │  write(eventfd/pipe) ───────────────▶ EPOLLIN on wake_fd
     │                                      │
     │                                  HandleEventId()
     │                                      ├─ read(wake_fd)
     │                                      ├─ copy tasks → local (under lock)
     │                                      └─ execute tasks (outside lock)
```

## Cross-Platform Support

| Platform | I/O Multiplexing | Wakeup Mechanism | Timer | Status |
|----------|-----------------|------------------|-------|--------|
| Linux | epoll (edge-triggered) | eventfd | timerfd | Production-ready |
| macOS | kqueue (EV_CLEAR) | pipe | EVFILT_TIMER | Production-tested |
| Windows | IOCP (planned) | — | — | Not started |

## Operational Endpoints

The production server (`server_runner`) registers operational endpoints when started via `main.cc`:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Liveness check. Returns `{"status":"ok"}` with uptime and connection count. Disabled with `--no-health-endpoint`. |
| `/stats` | GET | Runtime metrics snapshot. Returns JSON with active connections (by protocol), stream counts, request counters, uptime, and reload-safe config values. Disabled with `--no-stats-endpoint`. |

Stats counters use `memory_order_relaxed` atomics — snapshots are approximate but never stale by more than one operation.

## Config Hot-Reload

SIGHUP triggers config reload in daemon mode (foreground: triggers shutdown). Reload-safe fields are applied immediately to running connections:

| Reload-safe | Restart-required |
|-------------|-----------------|
| `idle_timeout_sec`, `request_timeout_sec` | `bind_host`, `bind_port` |
| `max_connections`, `max_body_size` | `tls.*`, `worker_threads` |
| `max_header_size`, `max_ws_message_size` | `http2.enabled` |
| `log.level`, `log.file`, `log.max_*` | |
| `http2.max_concurrent_streams`, etc. | |
| `shutdown_drain_timeout_sec` | |

The reload path is transactional: log changes are applied first, then server limits. If server limits are rejected, log changes are rolled back. Log file pruning is deferred until the full reload commits.

## Graceful Shutdown

Shutdown follows a protocol-aware drain sequence:

1. **Stop accepting** — close listen socket, set `closing_` flag on acceptor
2. **WS close handshake** — send 1001 "Going Away", track in `ws_draining_`, wait up to 6s
3. **H2 GOAWAY + stream drain** — send GOAWAY, wait for active streams, bounded by `shutdown_drain_timeout_sec`
4. **HTTP/1 output drain** — wait up to 2s for in-flight responses to flush under backpressure
5. **Late H2 re-drain** — catch sessions detected after the initial drain wait
6. **Close sweep** — `CloseAfterWrite` on remaining connections (exempt: draining H2/WS)
7. **Stop event loops** — `StopEventLoop` on all dispatchers
8. **Join workers** — `sock_workers_.Stop()`

During shutdown, HTTP/1 responses include `Connection: close`, WS upgrades are rejected with 503, and late H2 detections get immediate `RequestShutdown`.
