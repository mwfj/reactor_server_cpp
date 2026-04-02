# Testing

## Running Tests

```bash
make test               # Build and run all tests (196 tests across 13 suites)
./run                   # Run all tests directly (after building)

# Individual test suites
./run basic             # Basic functionality (or: ./run -b)
./run stress            # Stress tests — 100 concurrent clients (or: ./run -s)
./run race              # Race condition tests (or: ./run -r)
./run timeout           # Connection timeout tests (or: ./run -t)
./run config            # Configuration tests (or: ./run -c)
./run http              # HTTP protocol tests (or: ./run -H)
./run ws                # WebSocket protocol tests (or: ./run -w)
./run tls               # TLS/SSL tests (or: ./run -T)
./run http2             # HTTP/2 protocol tests (or: ./run -2)
./run cli               # CLI entry point tests (or: ./run -C)
./run route             # Route trie/pattern matching tests (or: ./run -R)
./run kqueue            # macOS kqueue platform tests (or: ./run -K)
./run help              # Show all options

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
```

## Test Suites

| Suite | Tests | Port | File | Command |
|-------|-------|------|------|---------|
| Basic | 9 | ephemeral | `test/basic_test.h` | `./run basic` |
| Stress | 3 | ephemeral | `test/stress_test.h` | `./run stress` |
| Race Condition | 9 | ephemeral | `test/race_condition_test.h` | `./run race` |
| Timeout | 3 | ephemeral | `test/timeout_test.h` | `./run timeout` |
| Config | 8 | N/A | `test/config_test.h` | `./run config` |
| HTTP | 13 | ephemeral | `test/http_test.h` | `./run http` |
| WebSocket | 10 | ephemeral | `test/websocket_test.h` | `./run ws` |
| TLS | 2 | ephemeral | `test/tls_test.h` | `./run tls` |
| HTTP/2 | 31 | ephemeral | `test/http2_test.h` | `./run http2` |
| CLI | 69 | N/A | `test/cli_test.h` | `./run cli` |
| Route | 44 | ephemeral | `test/route_test.h` | `./run route` |
| Kqueue | 7 | ephemeral | `test/kqueue_test.h` | `./run kqueue` (macOS only, skipped on Linux) |

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
- **`TestServerRunner<T>`** -- RAII template harness for server thread lifecycle. Works with both `ReactorServer` and `HttpServer`. Uses exception-safe constructor with promise/future synchronization to communicate the ephemeral port back to the test. Automatically stops the server and joins the thread on destruction.
- **`Client`** (`test/client.h`) -- Test client helper with timeout support

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
cd thread_pool && make clean && make && ./run
```

Tests include:
- Basic execution, exception propagation, cooperative cancellation
- Stop cancels pending tasks, restartability, start validation
- High concurrency stress test
- **Lost wakeup regression tests**: `NoLostWakeupOnShutdown`, `StopWithIdleThreads`, `RapidStartStop`

The lost wakeup tests use timing validation (Stop must complete in < 1000ms) and multiple iterations to catch race conditions. See [design-decisions.md](design-decisions.md#threadpool-synchronization-lost-wakeup-prevention) for background.
