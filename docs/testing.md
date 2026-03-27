# Testing

## Running Tests

```bash
make test               # Build and run all tests (101 tests across 9 suites)
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
./run cli               # CLI entry point tests (or: ./run -C)
./run help              # Show all options

# Make targets for individual suites
make test_basic         # Build and run basic tests
make test_stress        # Build and run stress tests
make test_race          # Build and run race condition tests
make test_config        # Build and run config tests
make test_http          # Build and run HTTP tests
make test_ws            # Build and run WebSocket tests
make test_tls           # Build and run TLS tests
make test_cli           # Build and run CLI tests
```

## Test Suites

| Suite | Tests | Port | File | Command |
|-------|-------|------|------|---------|
| Basic | 6 | 9888 | `test/basic_test.h` | `./run basic` |
| Stress | 1 | 9889 | `test/stress_test.h` | `./run stress` |
| Race Condition | 7 | 10000 | `test/race_condition_test.h` | `./run race` |
| Timeout | 3 | 10100 | `test/timeout_test.h` | `./run timeout` |
| Config | 8 | N/A | `test/config_test.h` | `./run config` |
| HTTP | 13 | 10201 | `test/http_test.h` | `./run http` |
| WebSocket | 10 | 10301 | `test/websocket_test.h` | `./run ws` |
| TLS | 2 | 10401 | `test/tls_test.h` | `./run tls` |
| CLI | 50 | N/A | `test/cli_test.h` | `./run cli` |

### Basic Tests (port 9888)
- Single client connection
- Echo functionality
- Multiple sequential connections (5 clients)
- Concurrent connections (10 clients)
- Large message transfer (512 bytes)
- Quick connect/disconnect

### Stress Tests (port 9889)
- High load: 100 concurrent clients sending messages simultaneously

### Race Condition Tests (port 10000)

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

### Timeout Tests (port 10100)
- Custom timer configuration
- Default timer parameters
- Idle connection detection

### HTTP Tests (port 10201)
- Request parsing and routing
- Keep-alive and pipelining
- Middleware chain execution
- Error responses (400, 404, 405, 413, 417, 505)
- HEAD method handling
- Response serialization

### WebSocket Tests (port 10301)
- Handshake validation (RFC 6455)
- Frame parsing (text, binary, control frames)
- Fragmentation and reassembly
- Close handshake with code validation
- Masking requirement enforcement
- RSV bit validation
- UTF-8 validation

### TLS Tests (port 10401)
- Certificate loading and validation
- TLS 1.2/1.3 minimum version enforcement

### Configuration Tests
- Default values, JSON loading, file I/O
- Invalid JSON handling, port validation
- TLS cert validation, environment variable overrides

## Port Configuration

Each test suite uses separate ports (9800-10500 range) to allow independent execution. If you see "Address already in use" errors, check for conflicting services or wait for TIME_WAIT to expire.

## Test Framework

### Core Components

- **`TestFramework`** (`test/test_framework.h`/`.cc`) -- Result tracking with automatic categorization
- **`ServerRunner`** -- RAII wrapper for server thread lifecycle (starts server, joins on destruction)
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

Basic Tests (6/6 passed)
----------------------------------------------------------------------
  [PASS] Single Client Connection
  [PASS] Echo Functionality
  ...

Race Condition Tests (7/7 passed)
----------------------------------------------------------------------
  [PASS] RC-1: Dispatcher Initialization
  ...

======================================================================
OVERALL SUMMARY
----------------------------------------------------------------------
  Basic Tests: 6/6 (100%)
  Stress Tests: 1/1 (100%)
  Race Condition Tests: 7/7 (100%)
  ...
----------------------------------------------------------------------
Total Tests: 51 | Passed: 51 | Failed: 0
Success Rate: 100%
======================================================================
```

### Writing New Tests

1. Create or update a test header in `test/` (e.g., `test/my_test.h`)
2. Use `ServerRunner` for automatic server lifecycle management
3. Set receive timeouts on all test client sockets (`client.SetReceiveTimeout(5)`)
4. Record results with appropriate category: `TestFramework::RecordTest(name, passed, error, category)`
5. Integrate into `test/run_test.cc` and update the `Makefile`

### Test Design Patterns

- **RAII `ServerRunner`**: Automatically stops server and joins thread on destruction
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
