# Testing

## Running Tests

```bash
make test               # Build and run all suites (1021 tests across 35+ suites at HEAD)
./test_runner                   # Run all tests directly (after building)
./test_runner help              # Print every supported flag

# Single-suite categories
./test_runner basic             # Basic functionality (or: ./test_runner -b)
./test_runner stress            # Stress tests — 100 concurrent clients (or: ./test_runner -s)
./test_runner race              # Race condition tests (or: ./test_runner -r)
./test_runner timeout           # Connection timeout tests (or: ./test_runner -t)
./test_runner config            # Configuration tests (or: ./test_runner -c)
./test_runner http              # HTTP/1.1 internal regressions + integration (or: ./test_runner -H)
./test_runner ws                # WebSocket protocol tests (or: ./test_runner -w)
./test_runner tls               # TLS/SSL tests (or: ./test_runner -T)
./test_runner http2             # HTTP/2 internal regressions + integration (or: ./test_runner -2)
./test_runner cli               # CLI entry point tests (or: ./test_runner -C)
./test_runner route             # Route trie / pattern matching (or: ./test_runner -R)
./test_runner upstream          # Upstream connection pool tests (or: ./test_runner -U)
./test_runner rate_limit        # Rate limit tests (or: ./test_runner -L)
./test_runner kqueue            # macOS kqueue platform tests (or: ./test_runner -K)

# Feature-family umbrellas (each runs every sub-suite in the family)
./test_runner auth              # full auth feature family (or: ./test_runner -A)
./test_runner circuit_breaker   # full circuit-breaker feature family (or: ./test_runner -B)
./test_runner proxy             # full proxy feature family — internal regressions + engine (or: ./test_runner -P)
./test_runner dns               # full DNS / dual-stack feature family (or: ./test_runner -D)
./test_runner dual_stack        # sub-suite — dual-stack integration only (OS-sensitive; macOS CI subset)
./test_runner dns_resolver      # sub-suite — DnsResolver primitives only (timing-sensitive)

# Auth sub-suites (drill into one aspect)
./test_runner auth_foundation
./test_runner jwt               # JWT verifier (or: ./test_runner -J)
./test_runner jwks              # JWKS cache (or: ./test_runner -j)
./test_runner oidc              # OIDC discovery (or: ./test_runner -O)
./test_runner hrauth            # HeaderRewriter auth overlay (or: ./test_runner -W)
./test_runner auth_mgr          # AuthManager unit tests (or: ./test_runner -M)
./test_runner auth2             # Auth integration tests (or: ./test_runner -V)
./test_runner auth_fail         # Auth failure-mode tests (or: ./test_runner -F)
./test_runner auth_reload       # Auth reload tests (or: ./test_runner -X)
./test_runner auth_multi        # Auth multi-issuer tests (or: ./test_runner -I)
./test_runner auth_ws           # Auth WebSocket-upgrade tests (or: ./test_runner -G)
./test_runner auth_race         # Auth race-condition tests (or: ./test_runner -Q)
./test_runner router_async      # Router async-middleware tests (or: ./test_runner -N)
./test_runner introspection_cache  # (or: ./test_runner -Y)
./test_runner intro_client      # Introspection client + AsyncPendingState (or: ./test_runner -y)
./test_runner auth_intro        # Introspection integration (or: ./test_runner -Z)
./test_runner auth_observability  # Debug response headers + per-policy counters (or: ./test_runner -o)

# Make targets — single-suite
make test_basic
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

# Make targets — feature-family umbrellas
make test_auth                  # full auth feature family
make test_circuit_breaker       # full circuit-breaker feature family
make test_proxy                 # full proxy feature family
make test_dns                   # full DNS / dual-stack feature family
make test_dual_stack            # sub-suite — dual-stack integration only (OS-sensitive)
make test_dns_resolver          # sub-suite — DnsResolver primitives only

# Make targets — auth sub-suites
make test_auth_foundation
make test_jwt
make test_jwks
make test_oidc
make test_hrauth
make test_auth_mgr
make test_auth2
make test_auth_fail
make test_auth_reload
make test_auth_multi
make test_auth_ws
make test_auth_race
make test_auth_observability
```

At current head, `./test_runner` reports **1021 / 1021 passing** (100 %).

## Test Suites

| Suite | Port | File | Command |
|-------|------|------|---------|
| Basic | ephemeral | `test/basic_test.h` | `./test_runner basic` |
| Stress | ephemeral | `test/stress_test.h` | `./test_runner stress` |
| Race Condition | ephemeral | `test/race_condition_test.h` | `./test_runner race` |
| Timeout | ephemeral | `test/timeout_test.h` | `./test_runner timeout` |
| Config | N/A | `test/config_test.h` | `./test_runner config` |
| HTTP (internal + integration) | ephemeral | `test/http_test.h`, `test/http_internal_test.h` | `./test_runner http` |
| WebSocket | ephemeral | `test/websocket_test.h` | `./test_runner ws` |
| TLS | ephemeral | `test/tls_test.h` | `./test_runner tls` |
| HTTP/2 (internal + integration) | ephemeral | `test/http2_test.h`, `test/http2_internal_test.h` | `./test_runner http2` |
| CLI | N/A | `test/cli_test.h` | `./test_runner cli` |
| Route | ephemeral | `test/route_test.h` | `./test_runner route` |
| Upstream Pool | ephemeral | `test/upstream_pool_test.h` | `./test_runner upstream` |
| Proxy (engine) | ephemeral | `test/proxy_test.h` | `./test_runner proxy` (umbrella runs internal regressions too) |
| Rate Limit | ephemeral | `test/rate_limit_test.h` | `./test_runner rate_limit` |
| Circuit Breaker (state machine + window) | N/A | `test/circuit_breaker_test.h` | `./test_runner circuit_breaker` (umbrella) |
| Circuit Breaker (components) | N/A | `test/circuit_breaker_components_test.h` | (bundled with `circuit_breaker`) |
| Circuit Breaker (integration) | ephemeral | `test/circuit_breaker_integration_test.h` | (bundled with `circuit_breaker`) |
| Circuit Breaker (retry budget) | ephemeral | `test/circuit_breaker_retry_budget_test.h` | (bundled with `circuit_breaker`) |
| Circuit Breaker (wait-queue drain) | ephemeral | `test/circuit_breaker_wait_queue_drain_test.h` | (bundled with `circuit_breaker`) |
| Circuit Breaker (observability) | ephemeral | `test/circuit_breaker_observability_test.h` | (bundled with `circuit_breaker`) |
| Circuit Breaker (reload) | ephemeral | `test/circuit_breaker_reload_test.h` | (bundled with `circuit_breaker`) |
| Auth Foundation | N/A | `test/auth_foundation_test.h` | `./test_runner auth_foundation` (or via `auth` umbrella) |
| JWT Verifier | N/A | `test/jwt_verifier_test.h` | `./test_runner jwt` (or via `auth` umbrella) |
| JWKS Cache | N/A | `test/jwks_cache_test.h` | `./test_runner jwks` (or via `auth` umbrella) |
| OIDC Discovery | N/A | `test/oidc_discovery_test.h` | `./test_runner oidc` (or via `auth` umbrella) |
| HeaderRewriter Auth Overlay | N/A | `test/header_rewriter_auth_test.h` | `./test_runner hrauth` (or via `auth` umbrella) |
| AuthManager unit | N/A | `test/auth_manager_test.h` | `./test_runner auth_mgr` (or via `auth` umbrella) |
| Auth Integration (HTTP end-to-end) | ephemeral | `test/auth_integration_test.h` | `./test_runner auth2` (or via `auth` umbrella) |
| Auth Failure Modes | ephemeral | `test/auth_failure_mode_test.h` | `./test_runner auth_fail` (or via `auth` umbrella) |
| Auth Reload | ephemeral | `test/auth_reload_test.h` | `./test_runner auth_reload` (or via `auth` umbrella) |
| Auth Multi-Issuer | ephemeral | `test/auth_multi_issuer_test.h` | `./test_runner auth_multi` (or via `auth` umbrella) |
| Auth WebSocket Upgrade | ephemeral | `test/auth_websocket_upgrade_test.h` | `./test_runner auth_ws` (or via `auth` umbrella) |
| Auth Race Conditions | ephemeral | `test/auth_race_test.h` | `./test_runner auth_race` (or via `auth` umbrella) |
| Router Async-Middleware | N/A | `test/router_async_middleware_test.h` | `./test_runner router_async` (or via `auth` umbrella) |
| Introspection Cache | N/A | `test/introspection_cache_test.h` | `./test_runner introspection_cache` (or via `auth` umbrella) |
| Introspection Client | N/A | `test/introspection_client_test.h` | `./test_runner intro_client` (or via `auth` umbrella) |
| Auth Introspection Integration | ephemeral | `test/auth_introspection_integration_test.h` | `./test_runner auth_intro` (or via `auth` umbrella) |
| Auth Observability | ephemeral | `test/auth_observability_test.h` | `./test_runner auth_observability` (or via `auth` umbrella) |
| Proxy Transaction Internal | N/A | `test/proxy_transaction_internal_test.h` | (bundled with `proxy`) |
| DnsResolver | N/A | `test/dns_resolver_test.h` | (bundled with `dns`) |
| DualStack | ephemeral | `test/dual_stack_test.h` | (bundled with `dns`) |
| Kqueue | ephemeral | `test/kqueue_test.h` | `./test_runner kqueue` (macOS only, skipped on Linux) |

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

## Continuous Integration

CI workflows live in `.github/workflows/` and run in three cadences. Stress and valgrind never gate PRs — both run on cron and are independent of the per-PR matrix.

Stress is also gated out of the per-PR no-arg `./test_runner` invocation: `RunAllTest()` checks `getenv("GITHUB_ACTIONS")` and skips `StressTests::RunStressTests()` when set. GitHub Actions sets `GITHUB_ACTIONS=true` automatically on its runners, so the per-PR matrix runs every other suite but never stress; `nightly-stress.yml` invokes `./test_runner stress` directly (the explicit-flag path bypasses `RunAllTest`). Local runs and Codespaces (which do NOT set `GITHUB_ACTIONS`) include stress so developers get full coverage from `make test`.

Stress runs with `continue-on-error: true` because high-concurrency suites are legitimately flake-prone on shared runners. Valgrind does NOT use `continue-on-error`: a memory error caught by `valgrind --error-exitcode=1` should surface as a red scheduled run, otherwise the weekly job is just burning runner-minutes.

### Per-PR (`.github/workflows/ci.yml`)

Six parallel jobs gate every PR. Cheap dimensions run all suites; the slow dimension (TSan) is sharded by hand-curated buckets so the critical path stays under ~13 minutes.

| Job | Runner | What it runs |
|-----|--------|--------------|
| `build-linux-gcc` | ubuntu-latest | All suites under gcc, no sanitizers — fastest signal that the build links and the suite passes. (Stress is skipped via the `GITHUB_ACTIONS` gate; see above.) |
| `build-linux-clang` | ubuntu-latest | All suites under clang. Catches warnings / codegen-driven UB that gcc misses. (Stress is skipped via the `GITHUB_ACTIONS` gate.) |
| `build-linux-asan` | ubuntu-latest | All suites under AddressSanitizer + UndefinedBehaviorSanitizer. Catches UAF, heap/stack overflows, signed overflow, alignment, null deref. `detect_leaks=0` to tolerate test-harness teardown. (Stress is skipped via the `GITHUB_ACTIONS` gate.) |
| `build-linux-tsan-heavy` | ubuntu-latest | ThreadSanitizer on the two slowest umbrellas: `race` and `auth`. (TSan amplifies runtime ~5–10x; isolating these lets the rest finish in parallel.) |
| `build-linux-tsan-rest` | ubuntu-latest | ThreadSanitizer on every other suite enumerated explicitly (basic, http, http2, ws, tls, cli, route, kqueue, upstream, proxy, rate_limit, circuit_breaker, dns, the obs_* family). |
| `build-macos` | macos-14 | OS-sensitive subset only — kqueue, race, timeout, tls, cli, upstream, proxy, http, http2, ws, dual_stack, obs_e2e. Pure-logic suites are platform-deterministic and already covered by the Linux jobs. |

The PR matrix uses GitHub Actions `concurrency: cancel-in-progress: true`, so a follow-up commit on the same branch automatically cancels the in-flight run.

### Nightly cron (`.github/workflows/nightly-stress.yml`)

Runs at 07:00 UTC (= 00:00 PT). Stress suites are noisy on shared CI runners (200 concurrent clients with an 85% success-rate threshold under `CI=true`; 1000 clients with 95% threshold locally) — a failure here means "investigate flake," not "investigate code". The workflow uses `continue-on-error: true` and does not red-X the badge. Each job invokes `./test_runner stress` directly, which bypasses the `RunAllTest()` `GITHUB_ACTIONS` gate that excludes stress from the per-PR matrix.

- `stress-linux` — ubuntu-latest, full stress sweep
- `stress-macos` — macos-14, full stress sweep

### Weekly cron (`.github/workflows/weekly-valgrind.yml`)

Runs Sundays at 09:00 UTC. Valgrind catches reads-of-uninitialized-memory and pointer-validity bugs that AddressSanitizer cannot, but its 10–50x runtime overhead makes it unsuitable for PR-blocking CI. The workflow has a 6-hour timeout cap and runs against a curated subset (excludes `stress`, `timeout`, `race`, `obs_stress`, `obs_export` — interpreter slowdown collapses their timing assertions). Unlike `nightly-stress.yml`, this workflow does NOT set `continue-on-error: true`: a memory error from `valgrind --error-exitcode=1` must surface as a red scheduled run so the failure is actionable, not silently swallowed.

### Adding a new test suite to CI

When adding a suite to `test/run_test.cc::RunAllTest()`:

1. The Linux gcc / clang / ASan jobs auto-pick it up (all suites).
2. **Add the new flag to the loop in `build-linux-tsan-rest`** — TSan does not auto-pick-up. If the new suite is heavy (>30s base runtime) or is itself a multi-suite umbrella, add it to `build-linux-tsan-heavy` instead.
3. If the suite touches OS-level primitives (sockets, signals, FDs, kqueue, TLS, DNS) add it to the macOS subset in `build-macos`.
4. If it's stress-shaped, add it to `nightly-stress.yml` (invoked via an explicit `./test_runner <flag>` step). If the suite has heavy variants you also want to gate out of the per-PR no-arg invocation, mirror the existing stress pattern: gate the call site in `RunAllTest()` on `getenv("GITHUB_ACTIONS")` so local runs include it but the GitHub Actions PR matrix skips it.
5. If it's memory-safety-flavored and not timing-sensitive, add it to the loop in `weekly-valgrind.yml`.

Internal contributors: see `.claude/rules/DEVELOPMENT_RULES.md` "CI workflow maintenance" for the full pre-PR audit checklist.

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
