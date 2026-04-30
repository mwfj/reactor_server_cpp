# Test Suite

Comprehensive test coverage across the reactor core, HTTP/1.1, HTTP/2, WebSocket, TLS, configuration, CLI, route matching, upstream/proxy, rate limiting, circuit breaker, OAuth, and DNS / dual-stack networking. Total at HEAD: 1021 tests across 35+ suites.

## Running Tests

```bash
make clean && make -j4    # Build test_runner and server_runner
./test_runner             # Run all tests (no-arg full sweep)
./test_runner <suite>     # Run a specific suite (see table below)
./test_runner help        # List every supported flag
```

All tests use ephemeral ports (port 0) to avoid conflicts. The test runner automatically raises the fd limit on macOS where the default soft limit (256) is insufficient.

### Single-suite categories

| Suite | Command | Short | What It Validates |
|-------|---------|-------|-------------------|
| basic | `./test_runner basic` | `-b` | Connection lifecycle, echo, sequential/concurrent connections, large messages, quick disconnect |
| stress | `./test_runner stress` | `-s` | 1000 concurrent clients (200 in CI); validates no crashes under load |
| race | `./test_runner race` | `-r` | Reactor core race conditions: dispatcher init, deadlock prevention, double close, concurrent events, channel_map races, TOCTOU, atomic flags |
| timeout | `./test_runner timeout` | `-t` | Idle connection timeout with custom and default timer parameters |
| config | `./test_runner config` | `-c` | JSON config loading, environment variable overrides, validation, serialization |
| http | `./test_runner http` | `-H` | HTTP/1.1 internal regressions + parsing/routing/middleware/integration |
| ws | `./test_runner ws` | `-w` | WebSocket handshake validation, frame serialization, parser, close handling, integration |
| tls | `./test_runner tls` | `-T` | TLS context creation and HTTPS request/response |
| http2 | `./test_runner http2` | `-2` | HTTP/2 internal regressions + protocol detection, ALPN, stream lifecycle, H2C, settings |
| cli | `./test_runner cli` | `-C` | CLI argument parsing, signal handling, PID file management, logging, config reload, /stats |
| route | `./test_runner route` | `-R` | Route trie + HttpRouter dispatch, middleware, WebSocket routes |
| upstream | `./test_runner upstream` | `-U` | Upstream connection pool — partitions, lease lifecycle, connect, drain |
| rate_limit | `./test_runner rate_limit` | `-L` | Token bucket, sharded zones, hot-reload, IETF headers |
| kqueue | `./test_runner kqueue` | `-K` | macOS-only: EVFILT_TIMER, EV_EOF on write filter, pipe wakeup, filter consolidation |

### Feature-family umbrellas

A single CLI flag runs every sub-suite in the family. Sub-suites stay accessible via the no-arg full sweep and (for auth) via individual flags.

| Family | Command | Short | Sub-suites covered |
|--------|---------|-------|---------------------|
| Auth | `./test_runner auth` | `-A` | foundation, JWT verifier, JWKS cache, OIDC discovery, header rewriter overlay, AuthManager, integration, failure modes, reload, multi-issuer, WS upgrade, race, router async, introspection cache + client + integration, observability |
| Circuit breaker | `./test_runner circuit_breaker` | `-B` | state machine, components, integration, retry budget, drain, observability, reload |
| Proxy | `./test_runner proxy` | `-P` | internal proxy-transaction regressions + end-to-end engine |
| DNS / dual-stack | `./test_runner dns` | `-D` | DnsResolver primitives + dual-stack integration (alias: `dual_stack`) |

### Auth sub-suite drill-down

Every auth sub-suite has its own flag. Use these when you only want to exercise one aspect.

```bash
./test_runner auth_foundation        # foundation: token_hasher / claims / policy matcher
./test_runner jwt                    # JWT verifier
./test_runner jwks                   # JWKS cache
./test_runner oidc                   # OIDC discovery
./test_runner hrauth                 # HeaderRewriter auth overlay
./test_runner auth_mgr               # AuthManager unit tests
./test_runner auth2                  # auth integration (HttpServer + middleware)
./test_runner auth_fail              # auth failure-mode tests
./test_runner auth_reload            # auth reload tests
./test_runner auth_multi             # auth multi-issuer tests
./test_runner auth_ws                # auth WebSocket-upgrade tests
./test_runner auth_race              # auth race-condition tests
./test_runner router_async           # router async-middleware tests
./test_runner introspection_cache    # introspection cache unit tests
./test_runner intro_client           # introspection client + AsyncPendingState
./test_runner auth_intro             # introspection integration tests
./test_runner auth_observability     # debug response headers + per-policy counters
```

### Make Targets

```bash
make test                    # Build and run the full sweep
make test_basic              # Single-suite targets — one per CLI flag above
make test_stress
make test_race
make test_config
make test_http
make test_ws
make test_tls
make test_http2
make test_cli
make test_upstream
make test_rate_limit

# Family umbrellas
make test_auth               # full auth feature family
make test_circuit_breaker    # full circuit-breaker feature family
make test_proxy              # full proxy feature family
make test_dns                # full DNS / dual-stack feature family (alias: test_dual_stack)

# Auth sub-suite targets exist for every auth flag (test_auth_foundation,
# test_jwt, test_jwks, test_oidc, test_hrauth, test_auth_mgr, ...).
```

## Test Infrastructure

| File | Purpose |
|------|---------|
| `run_test.cc` | Main entry point — suite selection, fd limit setup |
| `test_framework.h/cc` | Test result tracking, categorized summary output |
| `test_server_runner.h` | `TestServerRunner<T>` — RAII template that starts any server in a background thread, blocks until the ready callback fires, and stops + joins on destruction |
| `http_test_client.h` | `TestHttpClient` namespace — shared helpers: `ConnectRawSocket`, `SendHttpRequest`, `HttpGet`, `HttpPost`, `HasStatus`, `ExtractBody`, `WaitForServerClose`, `SetupEchoRoutes`, `MakeTestConfig` |

## Suite Details

### Basic (6 tests)

Validates fundamental reactor core functionality through HttpServer:
- Single client connection and health check
- Echo (POST body round-trip)
- 5 sequential connections
- 10 concurrent connections (all must succeed)
- 512-byte large message transfer
- Rapid connect/disconnect without sending data

### Stress (1 test)

Spawns 1000 concurrent threads (200 in CI via `$CI` env var), each sending an HTTP GET. Validates no crashes and >95% success rate locally (>90% in CI). Tests reactor core scalability under extreme connection pressure.

### Race Condition (7 tests)

Targets specific reactor core race conditions documented in `EVENTFD_RACE_CONDITION_FIXES.md`:

| Test | Validates |
|------|-----------|
| RC-1: Dispatcher Initialization | Two-phase init pattern — no `bad_weak_ptr` from `shared_from_this()` in constructor |
| RC-2: EnQueue No Deadlock | Concurrent task enqueue under load — no mutex deadlock |
| RC-3: Double Close Prevention | 50 rapid connect/disconnect — atomic close guards prevent double-close |
| RC-4: Concurrent Event Handling | Send + immediate close — EPOLLRDHUP + EPOLLIN handled correctly |
| RC-5: channel_map_ Race | 20 threads x 10 connections — no segfault from concurrent map access |
| RC-6: TOCTOU Race epoll_ctl | Send + immediate close — no "Bad file descriptor" from stale epoll state |
| RC-7: Atomic Closed Flag | 25 sequential rapid cycles — atomic compare-exchange prevents duplicate ops |

### Timeout (3 tests)

Validates idle connection timeout through HttpServer with `ServerConfig`:
- Custom timer parameters (10s idle timeout)
- Default timer parameters (300s idle, 30s request)
- Active connections unaffected by timer (10 sequential requests with 1s delays)

### Config (8 tests)

Tests `ConfigLoader` and `ServerConfig`:
- JSON parsing, default values, validation
- Environment variable overrides (`REACTOR_HOST`, `REACTOR_PORT`, etc.)
- Invalid config rejection, serialization round-trip

### HTTP (14 tests)

Tests HTTP/1.1 layer:
- **Parser**: GET, POST with body, WebSocket upgrade, invalid request, keep-alive, HTTP/1.0
- **Router**: Exact match, 404, 405 Method Not Allowed, middleware chain
- **Integration**: Full request/response cycle (health, echo, 404), request timeout (slow client gets 408 or connection close)

### WebSocket (10 tests)

Tests RFC 6455 WebSocket implementation:
- Handshake validation, accept key computation, missing header rejection
- Frame serialization (text, close)
- Parser: masked frames, 16-bit/64-bit length, binary frames
- Close frame: code + reason extraction
- Integration: HTTP upgrade to WebSocket

### TLS (2 tests)

- TLS context creation with certificate and key files
- Full HTTPS request/response cycle over TLS

### HTTP/2 (37 tests)

Tests RFC 9113 HTTP/2 implementation:
- **Protocol detection**: ALPN (h2, http/1.1, empty), client preface, partial preface, MinDetectionBytes
- **Stream**: Pseudo-headers, header lowercase, invalid header rejection, cookie concatenation, body accumulation, state lifecycle, request completeness
- **H2C cleartext**: GET, POST with body, 404, middleware, multiple streams, large body, invalid preface, body-too-large rejection
- **Config**: Default values, JSON parsing, validation, env overrides, disabled state, serialization, shutdown drain timeout

### CLI (79 tests)

Tests the CLI entry point (`cli_parser.h`, `signal_handler.h`, `pid_file.h`, `logger.h`):
- **Argument parsing**: All commands (start, stop, status, reload, validate, config) with flags (-p, -c, -l, -w, -P, -d, --no-health-endpoint, --no-stats-endpoint)
- **Validation**: Missing config file, port ranges, invalid flags per command
- **Signal handling**: SIGTERM shutdown, SIGHUP reload, signal mask cleanup/restore
- **PID file**: Creation, locking, stale detection, removal
- **Logging**: Init, level setting, console enable/disable, file rotation, date-based naming, reopen, log markers, sanitize path
- **Config reload**: Limit changes, restart-required fields ignored, missing/invalid file handling, log level changes
- **Server endpoints**: /stats JSON shape, uptime, config section, connection/request counters under concurrent load

### Route (44 tests)

Tests `RouteTrie` (compressed radix trie) and `HttpRouter` pattern matching:
- **RouteTrie**: Exact static match, parameter extraction (`:id`), multiple parameters, regex constraints (`:id(\d+)`), catch-all wildcards (`*filepath`), priority (static > param > catch-all), conflict detection (duplicate routes, conflicting constraints), edge cases (empty param, catch-all not last, invalid regex, percent-encoded paths, slash boundaries)
- **HttpRouter**: Pattern dispatch, 405 + Allow header, HEAD fallback to GET, middleware on pattern routes, params cleared between dispatches, WebSocket pattern routes

### Kqueue (7 tests, macOS only)

Tests macOS kqueue-specific behaviors (skipped on Linux):
- EVFILT_TIMER drives idle timeout correctly (3s timeout, verified timing window)
- EV_EOF detected on EVFILT_WRITE when peer closes
- Pipe wakeup under concurrent load (10 threads x 100 tasks)
- Filter consolidation: read + write events on same fd, read-before-write ordering
- Churn stability: 100 rapid connect/disconnect, server remains healthy
- Timer re-arm: second client timeout after first (timer doesn't stop after first fire)
- SO_NOSIGPIPE set on accepted sockets (verified via forked child write to dead peer)

## CI

Tests run on both Linux (`ubuntu-latest`) and macOS (`macos-14`) via GitHub Actions. The stress test adapts to CI environments automatically (`$CI` env var reduces client count from 1000 to 200). Kqueue tests only run on macOS.

## Debugging Failed Tests

```bash
# Run a specific suite with full output
./test_runner race

# Run under address sanitizer (rebuild required)
# Add -fsanitize=address to CXXFLAGS in Makefile

# Run under valgrind (Linux)
valgrind --leak-check=full ./test_runner race

# Run under GDB
gdb ./test_runner
(gdb) run race
(gdb) bt          # on crash
```

For race condition and stress test failures, the key metric is **no crashes/segfaults** — success rates below 100% are expected under extreme load due to OS resource limits.
