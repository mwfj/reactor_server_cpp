# Testing

## Running Tests

```bash
make test               # Build and run all tests (796 tests across 35 suites)
./test_runner                   # Run all tests directly (after building)

# Individual test suites
./test_runner basic             # Basic functionality (or: ./test_runner -b)
./test_runner stress            # Stress tests — 100 concurrent clients (or: ./test_runner -s)
./test_runner race              # Race condition tests (or: ./test_runner -r)
./test_runner timeout           # Connection timeout tests (or: ./test_runner -t)
./test_runner config            # Configuration tests (or: ./test_runner -c)
./test_runner http              # HTTP protocol tests (or: ./test_runner -H)
./test_runner ws                # WebSocket protocol tests (or: ./test_runner -w)
./test_runner tls               # TLS/SSL tests (or: ./test_runner -T)
./test_runner http2             # HTTP/2 protocol tests (or: ./test_runner -2)
./test_runner cli               # CLI entry point tests (or: ./test_runner -C)
./test_runner route             # Route trie/pattern matching tests (or: ./test_runner -R)
./test_runner upstream          # Upstream connection pool tests (or: ./test_runner -U)
./test_runner proxy             # Proxy engine tests (or: ./test_runner -P)
./test_runner rate_limit        # Rate limit tests (or: ./test_runner -L)
./test_runner circuit_breaker   # Circuit breaker tests (or: ./test_runner -B)
./test_runner auth              # OAuth foundation tests — Phase 1a utils (or: ./test_runner -A)
./test_runner jwt               # JWT verifier unit tests (or: ./test_runner -J)
./test_runner jwks              # JWKS cache unit tests (or: ./test_runner -j)
./test_runner oidc              # OIDC discovery unit tests (or: ./test_runner -O)
./test_runner hrauth            # HeaderRewriter auth-overlay tests (or: ./test_runner -W)
./test_runner auth_mgr          # AuthManager unit tests (or: ./test_runner -M)
./test_runner auth2             # Auth integration tests — Phase 2 (or: ./test_runner -V)
./test_runner auth_fail         # Auth failure-mode tests (or: ./test_runner -F)
./test_runner auth_reload       # Auth reload tests (or: ./test_runner -X)
./test_runner auth_multi        # Auth multi-issuer tests (or: ./test_runner -I)
./test_runner auth_ws           # Auth WebSocket-upgrade tests (or: ./test_runner -G)
./test_runner auth_race         # Auth race-condition tests (or: ./test_runner -Q)
./test_runner kqueue            # macOS kqueue platform tests (or: ./test_runner -K)
./test_runner help              # Show all options

# Make targets for individual suites
make test_basic         # Build and run basic tests
make test_stress        # Build and run stress tests
make test_race          # Build and run race condition tests
make test_config        # Build and run config tests
make test_http          # Build and run HTTP tests
make test_ws            # Build and run WebSocket tests
make test_tls           # Build and run TLS tests
make test_http2         # Build and run HTTP/2 tests
make test_cli           # Build and run CLI tests
make test_upstream      # Build and run upstream pool tests
make test_proxy         # Build and run proxy engine tests
make test_rate_limit    # Build and run rate limit tests
make test_circuit_breaker # Build and run circuit breaker tests
make test_auth          # Build and run OAuth foundation tests (41)
make test_jwt           # Build and run JWT verifier unit tests (21)
make test_jwks          # Build and run JWKS cache unit tests (20)
make test_oidc          # Build and run OIDC discovery unit tests (14)
make test_hrauth        # Build and run HeaderRewriter auth-overlay tests (18)
make test_auth_mgr      # Build and run AuthManager unit tests (20)
make test_auth2         # Build and run auth integration tests (20)
make test_auth_fail     # Build and run auth failure-mode tests (15)
make test_auth_reload   # Build and run auth reload tests (14)
make test_auth_multi    # Build and run auth multi-issuer tests (8)
make test_auth_ws       # Build and run auth WebSocket-upgrade tests (6)
make test_auth_race     # Build and run auth race-condition tests (10)
```

At current head, `./test_runner` reports **795 / 796 passing**. The single failure is a pre-existing slow-client streaming backpressure test that is unrelated to the auth work and has been tracked separately.

## Test Suites

| Suite | Tests | Port | File | Command |
|-------|-------|------|------|---------|
| Basic | 9 | ephemeral | `test/basic_test.h` | `./test_runner basic` |
| Stress | 3 | ephemeral | `test/stress_test.h` | `./test_runner stress` |
| Race Condition | 9 | ephemeral | `test/race_condition_test.h` | `./test_runner race` |
| Timeout | 6 | ephemeral | `test/timeout_test.h` | `./test_runner timeout` |
| Config | 8 | N/A | `test/config_test.h` | `./test_runner config` |
| HTTP | 21 | ephemeral | `test/http_test.h` | `./test_runner http` |
| WebSocket | 10 | ephemeral | `test/websocket_test.h` | `./test_runner ws` |
| TLS | 2 | ephemeral | `test/tls_test.h` | `./test_runner tls` |
| HTTP/2 | 37 | ephemeral | `test/http2_test.h` | `./test_runner http2` |
| CLI | 79 | N/A | `test/cli_test.h` | `./test_runner cli` |
| Route | 50 | ephemeral | `test/route_test.h` | `./test_runner route` |
| Upstream Pool | 30 | ephemeral | `test/upstream_pool_test.h` | `./test_runner upstream` |
| Proxy | 56 | ephemeral | `test/proxy_test.h` | `./test_runner proxy` |
| Rate Limit | 46 | ephemeral | `test/rate_limit_test.h` | `./test_runner rate_limit` |
| Circuit Breaker (state machine + window) | 45 | N/A | `test/circuit_breaker_test.h` | `./test_runner circuit_breaker` |
| Circuit Breaker (components) | 11 | N/A | `test/circuit_breaker_components_test.h` | (bundled with `circuit_breaker`) |
| Circuit Breaker (integration) | 14 | ephemeral | `test/circuit_breaker_integration_test.h` | (bundled with `circuit_breaker`) |
| Circuit Breaker (retry budget) | 4 | ephemeral | `test/circuit_breaker_retry_budget_test.h` | (bundled with `circuit_breaker`) |
| Circuit Breaker (wait-queue drain) | 2 | ephemeral | `test/circuit_breaker_wait_queue_drain_test.h` | (bundled with `circuit_breaker`) |
| Circuit Breaker (observability) | 3 | ephemeral | `test/circuit_breaker_observability_test.h` | (bundled with `circuit_breaker`) |
| Circuit Breaker (reload) | 7 | ephemeral | `test/circuit_breaker_reload_test.h` | (bundled with `circuit_breaker`) |
| Auth Foundation (Phase 1a utilities) | 41 | N/A | `test/auth_foundation_test.h` | `./test_runner auth` |
| JWT Verifier (Phase 2 unit) | 21 | N/A | `test/jwt_verifier_test.h` | `./test_runner jwt` |
| JWKS Cache (Phase 2 unit) | 20 | N/A | `test/jwks_cache_test.h` | `./test_runner jwks` |
| OIDC Discovery (Phase 2 unit) | 14 | N/A | `test/oidc_discovery_test.h` | `./test_runner oidc` |
| HeaderRewriter Auth Overlay | 18 | N/A | `test/header_rewriter_auth_test.h` | `./test_runner hrauth` |
| AuthManager (Phase 2 unit) | 20 | N/A | `test/auth_manager_test.h` | `./test_runner auth_mgr` |
| Auth Integration (HTTP end-to-end) | 20 | ephemeral | `test/auth_integration_test.h` | `./test_runner auth2` |
| Auth Failure Modes | 15 | ephemeral | `test/auth_failure_mode_test.h` | `./test_runner auth_fail` |
| Auth Reload | 14 | ephemeral | `test/auth_reload_test.h` | `./test_runner auth_reload` |
| Auth Multi-Issuer | 8 | ephemeral | `test/auth_multi_issuer_test.h` | `./test_runner auth_multi` |
| Auth WebSocket Upgrade | 6 | ephemeral | `test/auth_websocket_upgrade_test.h` | `./test_runner auth_ws` |
| Auth Race Conditions | 10 | ephemeral | `test/auth_race_test.h` | `./test_runner auth_race` |
| Kqueue | 7 | ephemeral | `test/kqueue_test.h` | `./test_runner kqueue` (macOS only, skipped on Linux) |

### Basic Tests
- Single client connection
- Echo functionality
- Multiple sequential connections (5 clients)
- Concurrent connections (10 clients)
- Large message transfer (512 bytes)
- Quick connect/disconnect

### Stress Tests
- High load: 100 concurrent clients sending messages simultaneously

### Race Condition Tests

Validates all fixes from the [EventFD race condition investigation](bug-fix-history.md#eventfd-race-conditions):

| Test | What It Validates |
|------|------------------|
| RC-1: Dispatcher Initialization | Two-phase init, wake channel setup |
| RC-2: EnQueue No Deadlock | Lock-free task execution pattern |
| RC-3: Double Close Prevention | Atomic close guards |
| RC-4: Concurrent Event Handling | Priority-based EPOLLRDHUP handling |
| RC-5: channel_map_ Race Condition | Mutex-protected map access (critical -- prevents segfault) |
| RC-6: TOCTOU Race epoll_ctl | Defense-in-depth fd validation |
| RC-7: Atomic Closed Flag | Atomic bool operations across threads |

RC-5 is the most critical test -- it directly prevents the segfault (`Channel::HandleEvent(this=0x0)`) that triggered the race condition investigation.

### Timeout Tests
- Custom timer configuration
- Default timer parameters
- Idle connection detection

### HTTP Tests
- Request parsing and routing
- Keep-alive and pipelining
- Middleware chain execution
- Error responses (400, 404, 405, 413, 417, 505)
- HEAD method handling
- Response serialization
- Async route middleware gating and rejection with headers
- Async route pipeline ordering on keep-alive connections
- Async HEAD fallback rewriting method to GET
- Async 405 includes async methods in Allow header
- Async HEAD body stripping
- Async route client Connection: close header handling

### WebSocket Tests
- Handshake validation (RFC 6455)
- Frame parsing (text, binary, control frames)
- Fragmentation and reassembly
- Close handshake with code validation
- Masking requirement enforcement
- RSV bit validation
- UTF-8 validation

### TLS Tests
- Certificate loading and validation
- TLS 1.2/1.3 minimum version enforcement

### HTTP/2 Tests

**Configuration (6 tests):** Http2Config defaults, JSON parsing, RFC 9113 validation, env overrides, disabled mode, serialization round-trip.

**Protocol Detection (8 tests):** ALPN h2/http1.1/empty, preface detection, HTTP/1.1 fallback, short data, partial preface, MinDetectionBytes constant.

**Stream Unit Tests (7 tests):** Pseudo-header mapping (:method, :path, :authority), regular headers lowercase, cookie concatenation (RFC 9113 Section 8.2.3), body accumulation, stream state lifecycle, request completeness, path without query.

**H2C Functional (6 tests):** Simple GET via cleartext h2c, POST with body, 404 routing, middleware execution, multiple concurrent streams on one connection, large body within limit.

**Error Handling (2 tests):** Invalid preface (garbage bytes), body exceeding max_body_size (RST_STREAM).

**Race Conditions (2 tests):** Concurrent HTTP/2 clients, mixed HTTP/1.1 + HTTP/2 clients.

Uses `Http2TestClient` -- a test helper wrapping nghttp2 in client mode with `mem_recv`/`mem_send` for frame-level control.

### Upstream Pool Tests

**Unit Tests (13 tests):** SocketHandler connect-refused behavior, UpstreamConnection state transitions (CONNECTING→READY→IN_USE), expiration by lifetime/request count, IsAlive checks, fd() with null transport, UpstreamLease default/move/release semantics, PoolPartition error code constants, UpstreamHostPool partition-per-dispatcher and accessors.

**Integration Tests (11 tests):** HasUpstream lookup, checkout from unknown service, shutdown drain, EvictExpired no-crash, CheckoutAsync valid connection, connection reuse (same fd after return), connect failure fires error callback, wait-queue overflow (POOL_EXHAUSTED), upstream drops connection while lease held, multi-dispatcher concurrency.

Uses a real `HttpServer` instance as the upstream backend with ephemeral ports. Tests validate the full lifecycle: checkout → use → return → reuse, including error paths and graceful shutdown.

### Rate Limit Tests

**TokenBucket unit (7 tests):** Fresh bucket full, lazy refill, capacity limit, UpdateConfig rate/capacity change, low-rate fractional credit preservation, SecondsUntilAvailable accuracy.

**RateLimitZone tests (8 tests):** Key extractor types (client_ip, header, composite, empty-key skip), `applies_to` prefix filter with segment-boundary matching, LRU eviction after timer sweep, synchronous `max_entries` enforcement on insert (no timer dependency).

**RateLimitManager tests (11 tests):** Single-zone allow/deny, multi-zone all-pass, multi-zone one-denies (first-deny-wins), stops-debiting-after-denial, skips non-applicable zones when building headers, RateLimit/Retry-After header generation, large-policy-window overflow safety, reset-header on empty bucket, disabled short-circuit.

**Hot-reload tests (6 tests):** Enable/disable toggle, rate change on existing buckets, add/remove zone, status_code and dry_run changes visible to next request.

**Integration tests — full HTTP (5 tests):** 200 with `RateLimit-*` headers, 429 with `Retry-After`, custom status code (503), dry-run allows and strips `Retry-After`, middleware applies to all routes.

**Configuration tests (6 tests):** JSON round-trip, validation errors (rate≤0, unknown key_type, duplicate names, enabled+empty zones, empty `applies_to` entry rejection).

**Edge cases (3 tests):** Empty client_ip skip, capacity=1, very high rate (1e6) without integer overflow.

Total: 46 tests. Uses ephemeral ports via `TestServerRunner<HttpServer>` for integration paths.

### OAuth 2.0 Auth Tests

Auth coverage is split across 12 suites (41 Phase 1a foundation + 166 Phase 1b/2 — 207 tests total):

- **Foundation** (41) — token hashing, claim extraction, policy matcher, config schema / validation / reload-safety. Pure utilities; no server needed.
- **JWT Verifier** (21) — jwt-cpp wrapping, algorithm allowlist, signature / exp / nbf / aud / iss failures, `alg:none` rejection, leeway handling.
- **JWKS Cache** (20) — installs + lookups, TTL expiry, kid miss, stale-on-error, coalesced refresh CAS, hard-cap trimming, snapshot stats.
- **OIDC Discovery** (14) — `.well-known/openid-configuration` parsing, retry-on-failure with shared-pointer cancel token, malformed-JSON containment, `Cancel()` idempotency.
- **HeaderRewriter Auth Overlay** (18) — strip-then-inject ordering, `claims_to_headers`, `preserve_authorization`, `raw_jwt_header` opt-in, client-spoof defense on `X-Auth-Undetermined`, reserved-name enforcement.
- **AuthManager unit** (20) — policy matching, bearer extraction, reload-safe snapshots, generation counter, issuer topology stability.
- **Integration** (20) — end-to-end through `HttpServer` + `AuthManager` middleware with fake IdP: ALLOW / 401 / 403 / 503 paths, multi-issuer routing, `on_undetermined: allow`.
- **Failure modes** (15) — IdP unreachable, JWKS fetch timeout, kid miss with stale-served fallback, malformed token containment.
- **Reload** (14) — live-reloadable field propagation, restart-required topology warns, in-flight-request snapshot consistency across reload.
- **Multi-issuer** (8) — `PeekIssuer` routing, allowlist enforcement, cross-issuer claim rejection.
- **WebSocket upgrade** (6) — auth enforcement through the HTTP/1.1 upgrade handshake.
- **Race conditions** (10) — concurrent kid-miss refreshes, reload-while-verifying, issuer destruction with in-flight OIDC retry.

### Kqueue Tests (macOS only)
- EVFILT_TIMER idle timeout verification
- EV_EOF detected on write filter (peer close)
- Pipe wakeup cross-thread signaling
- Filter consolidation (read + write on same fd)
- Channel churn stability (rapid add/remove)
- Timer re-arm after fire
- SO_NOSIGPIPE on accepted sockets (forked child write test)

### Route Tests
- Compressed radix trie insert/search
- Wildcard parameter matching (`:id`, `*path`)
- Overlapping routes, edge cases, trailing slashes

### Configuration Tests
- Default values, JSON loading, file I/O
- Invalid JSON handling, port validation
- TLS cert validation, environment variable overrides

## Port Configuration

All test suites use ephemeral ports (port 0 + `getsockname()`) via the `TestServerRunner<T>` RAII harness. This eliminates port conflicts and startup sleeps. The OS assigns an available port, and the test harness communicates it via a promise/future.

## Test Framework

### Core Components

- **`TestFramework`** (`test/test_framework.h`/`.cc`) -- Result tracking with automatic categorization
- **`TestServerRunner<T>`** -- RAII template harness for server thread lifecycle. Works with any server type exposing `SetReadyCallback`/`GetBoundPort`/`Start`/`Stop`. Uses exception-safe constructor with promise/future synchronization to communicate the ephemeral port back to the test. Automatically stops the server and joins the thread on destruction.
- **`TestHttpClient`** (`test/http_test_client.h`) -- Shared HTTP test client helpers: raw socket connect, HTTP GET/POST, response parsing, server-close detection

### Test Categories

Tests are automatically grouped by category in the results output:

```cpp
enum class TestCategory { BASIC, STRESS, RACE_CONDITION, TIMEOUT, CONFIG, HTTP, WEBSOCKET, TLS, OTHER };

// Recording a test result with category:
TestFramework::RecordTest("My Test", true, "", TestFramework::TestCategory::BASIC);
```

### Results Output

Results are displayed with per-category statistics:

```
======================================================================
                    TEST RESULTS SUMMARY
======================================================================

Basic Tests (9/9 passed)
----------------------------------------------------------------------
  [PASS] Single Client Connection
  [PASS] Echo Functionality
  ...

Race Condition Tests (9/9 passed)
----------------------------------------------------------------------
  [PASS] RC-1: Dispatcher Initialization
  ...

======================================================================
OVERALL SUMMARY
----------------------------------------------------------------------
  Basic Tests: 9/9 (100%)
  Stress Tests: 3/3 (100%)
  Race Condition Tests: 9/9 (100%)
  ...
----------------------------------------------------------------------
Total Tests: 196 | Passed: 196 | Failed: 0
Success Rate: 100%
======================================================================
```

### Writing New Tests

1. Create or update a test header in `test/` (e.g., `test/my_test.h`)
2. Use `TestServerRunner<T>` for automatic server lifecycle management with ephemeral ports
3. Set receive timeouts on all test client sockets (`client.SetReceiveTimeout(5)`)
4. Record results with appropriate category: `TestFramework::RecordTest(name, passed, error, category)`
5. Integrate into `test/run_test.cc` and update the `Makefile`

### Test Design Patterns

- **RAII `TestServerRunner<T>`**: Automatically stops server and joins thread on destruction; uses promise/future for ephemeral port synchronization
- **Exception-safe recording**: Wrap test logic in try/catch, record failure on exception
- **Atomic result tracking**: Use `std::atomic<int>` counters for multi-threaded test result aggregation
- **Timeout on all sockets**: Prevents tests from hanging indefinitely on server failure

## Thread Pool Tests

The `thread_pool/` subproject has its own test suite:

```bash
cd thread_pool && make clean && make && \./test_runner
```

Tests include:
- Basic execution, exception propagation, cooperative cancellation
- Stop cancels pending tasks, restartability, start validation
- High concurrency stress test
- **Lost wakeup regression tests**: `NoLostWakeupOnShutdown`, `StopWithIdleThreads`, `RapidStartStop`

The lost wakeup tests use timing validation (Stop must complete in < 1000ms) and multiple iterations to catch race conditions. See [design-decisions.md](design-decisions.md#threadpool-synchronization-lost-wakeup-prevention) for background.
