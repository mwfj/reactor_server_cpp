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
Layer 7: AuthManager, AuthMiddleware,       (inbound middleware stack)
         RateLimitManager, RateLimitZone,
         TokenBucket, CircuitBreakerManager
Layer 6: UpstreamManager, UpstreamHostPool, (upstream connection pooling)
         PoolPartition, UpstreamConnection,
         UpstreamLease, TlsClientContext
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

Layers 1–2 are the transport. Layers 3–5 are the protocol. Layer 6 is the gateway (upstream connectivity). Layer 7 is the inbound traffic-management middleware (auth, rate limiting, circuit breaking). HTTP/1.x and HTTP/2 are parallel handlers at Layer 3, selected by `ProtocolDetector` at connection time. Both converge on the same `HttpRouter` at Layer 4. ConnectionHandler supports both inbound (server) and outbound (client) connections.

**Middleware execution order on inbound requests**: auth → rate-limit → circuit-breaker (admission) → router dispatch. Authentication runs first so rate-limit and circuit-breaker counters don't consume quota on rejected traffic. See `HttpServer::MarkServerReady` for the exact install order; `HttpRouter::PrependMiddleware` pushes to the front of the chain, so the **last** prepend runs **first**.

> **OAuth 2.0 token validation.** The gateway ships with a real JWT-mode resource-server validator. `AuthManager` (owned by `HttpServer`) installs a middleware at Layer 7 that matches per-route policies, verifies bearer tokens against cached JWKS keys, enforces scope / audience / algorithm constraints, and injects a sanitized identity overlay for the outbound hop. Introspection mode (RFC 7662) is scaffolded but deferred. See [docs/oauth2.md](oauth2.md) for the operator guide and [docs/configuration.md](configuration.md) for the full field reference.

## Core Components

### Dispatcher
Central event loop coordinator. Wraps the platform-specific `EventHandler` (epoll on Linux, kqueue on macOS). Supports cross-thread task queueing via `EnQueue()`/`WakeUp()` using eventfd (Linux) or pipe (macOS). Connection timeout scanning via timerfd. Also exposes `EnQueueDelayed(fn, delay)` — a min-heap of deadline-ordered callbacks used by the upstream retry path for sub-second timer-based backoff without blocking the event loop thread.

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

## Upstream Connection Pool (Layer 6)

The upstream pool provides persistent, per-dispatcher connections to backend services for proxying and async route handlers.

```
HttpServer
  └── UpstreamManager (owns all host pools)
        └── UpstreamHostPool (per-service, e.g. "api-backend")
              └── PoolPartition × N (one per dispatcher, lock-free on hot path)
                    ├── idle_conns_      (ready for checkout)
                    ├── active_conns_    (leased to callers)
                    └── connecting_conns_ (TCP/TLS handshake in progress)
```

**Key design points:**
- **Per-dispatcher partitions** — checkout/return never cross threads, so no locks on the hot path
- **`UpstreamLease`** — RAII checkout handle (move-only). When it goes out of scope or is explicitly released, the connection returns to the pool automatically
- **`alive_` guard** — `shared_ptr<atomic<bool>>` detects partition destruction from callbacks, preventing use-after-free when the pool shuts down while async work is in flight
- **Wait queue** — when all connections are busy and capacity is available, waiters queue until a connection frees up or a timeout fires (`CHECKOUT_QUEUE_TIMEOUT`)

## Rate Limiting (Layer 7)

Inbound request rate limiting is implemented as a middleware inserted at the front of the router's middleware chain. Token bucket with lazy refill; per-key state in sharded hash maps for bounded contention.

```
HttpServer
  └── RateLimitManager (always created, even when disabled)
        ├── atomic<bool> enabled_, dry_run_, include_headers_
        ├── atomic<int>  status_code_
        └── shared_ptr<ZoneList>                  (atomically swapped on reload)
              └── vector<shared_ptr<RateLimitZone>>
                    ├── shared_ptr<const ZonePolicy>  (atomically swapped on UpdateConfig)
                    └── vector<Shard>[16]
                          └── unordered_map<string, unique_ptr<Entry>>
                                └── TokenBucket (integer millitokens, lazy refill)
```

**Key design points:**
- **Always registered** — middleware is prepended in `MarkServerReady()` regardless of config, so `Reload()` can enable or add zones without re-registration (blocked by `RejectIfServerLive()` after Start)
- **Sharded mutex** — 16 shards per zone, each with its own `std::mutex` + `unordered_map` + intrusive LRU list. Worst-case contention is 1/16 across dispatcher threads
- **Immutable snapshots** — `ZoneList` (manager) and `ZonePolicy` (zone) are `shared_ptr<const T>` swapped atomically. In-flight `Check()` calls hold their own refcounted copy — old state stays alive until the last reader releases it. No mutex on the hot path beyond the shard lock
- **First-deny wins** — multi-zone denial breaks the iteration on the first denying zone (matches Nginx). Trailing zones are not consulted, preventing unnecessary token debit
- **Synchronous LRU eviction on insert** — `FindOrCreate` evicts LRU tail before creating a new entry if the shard is at capacity, guaranteeing `max_entries` is honored even under high-cardinality bursts
- **Disable-first / enable-last reload ordering** — ensures no request can observe `enabled=true` with the previous (stale) zone list during a `(false,[])→(true,[Z])` transition

See `docs/configuration.md` for the full config reference.

## Memory Management

- `unique_ptr`: sole ownership (Dispatcher→EventHandler, Acceptor→SocketHandler, ConnectionHandler→SocketHandler, HttpServer→UpstreamManager, HttpServer→RateLimitManager, HttpServer→AuthManager, PoolPartition→UpstreamConnection)
- `shared_ptr`: shared ownership (Channels in epoll map, ConnectionHandlers in connections map, TlsContext shared between HttpServer and NetServer, TlsClientContext shared across PoolPartitions)
- `weak_ptr`: non-owning observers (Channel→Dispatcher, callback captures)
- Two-phase init: callbacks registered after object is wrapped in shared_ptr, using weak_ptr captures to break circular references
- Upstream pool: pool always owns UpstreamConnection (never transferred to caller); callers get `UpstreamLease` RAII handle (non-owning raw ptr + auto-return)

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
| `log.level`, `log.file`, `log.max_*` | `upstreams` (pool rebuild needed) |
| `http2.max_concurrent_streams`, etc. | `auth` topology (issuers, policy `applies_to`) |
| `shutdown_drain_timeout_sec` | |
| `auth.enabled`, `auth.forward.*` | |
| Per-issuer reloadable: `audiences`, `algorithms`, `leeway_sec`, `jwks_cache_sec`, `required_claims` | |
| Per-policy reloadable: `enabled`, `required_scopes`, `required_audience`, `on_undetermined`, `realm` | |

The reload path is transactional: log changes are applied first, then server limits. If server limits are rejected, log changes are rolled back. Log file pruning is deferred until the full reload commits.

**Live reload to existing connections:** Size limits (`max_body_size`, `max_header_size`, `max_ws_message_size`) and `request_timeout_sec` are pushed to all existing HTTP/1, HTTP/2, and pending-detection connections via dispatcher-enqueued tasks. Already-armed deadlines are reconciled: enabling a timeout installs the 408 callback; disabling clears the deadline; changing re-arms from the request's start time.

## Graceful Shutdown

Shutdown follows a protocol-aware drain sequence:

1. **Stop accepting** — close listen socket, set `closing_` flag on acceptor
2. **WS close handshake** — send 1001 "Going Away", track in `ws_draining_`, wait up to 6s
3. **H2 GOAWAY + stream drain** — send GOAWAY, wait for active streams, bounded by `shutdown_drain_timeout_sec`
4. **Upstream pool drain** — `UpstreamManager::InitiateShutdown()` rejects new checkouts, wait for outstanding connections to return, force-close after timeout
5. **HTTP/1 output drain** — wait for in-flight responses (including async) to flush under backpressure, bounded by `shutdown_drain_timeout_sec`
6. **Late H2 re-drain** — catch sessions detected after the initial drain wait (clears pre-armed `CloseAfterWrite` before `Initialize`)
7. **Close sweep** — `CloseAfterWrite` on remaining connections (exempt: draining H2/WS, async in-flight via `shutdown_exempt_`)
8. **Stop event loops** — `StopEventLoop` on all dispatchers
9. **Join workers** — `sock_workers_.Stop()`

During shutdown, HTTP/1 responses include `Connection: close`, WS upgrades are rejected with 503, late H2 detections get immediate `RequestShutdown`, and async route handlers mark their connections shutdown-exempt until the completion callback fires.
