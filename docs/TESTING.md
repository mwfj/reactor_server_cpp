# Testing

## Running Tests

```bash
make test               # Build and run all tests
./run                   # Run all tests directly (after building)

# Individual test suites
./run basic             # Basic functionality (or: ./run -b)
./run stress            # Stress tests — 100 concurrent clients (or: ./run -s)
./run race              # Race condition tests (or: ./run -r)
./run timeout           # Connection timeout tests (or: ./run -t)
./run http              # HTTP protocol tests (or: ./run -h)
./run ws                # WebSocket protocol tests (or: ./run -w)
./run tls               # TLS/SSL tests
./run config            # Configuration loading tests
./run help              # Show all options
```

## Test Suites

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
- EventFD race conditions
- Concurrent connection handling
- Double close prevention
- EPOLLRDHUP + EPOLLIN concurrent events
- channel_map_ multi-threaded access
- TOCTOU race in epoll_ctl
- Atomic is_channel_closed_ flag

### Timeout Tests (port 10100)
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
- Cipher configuration

### Configuration Tests
- JSON config parsing
- Environment variable overrides
- Validation of limits and parameters

## Port Configuration

Each test suite uses separate ports (9800–10200 range) to allow independent execution. If you see "Address already in use" errors, check for conflicting services.

## Test Framework

Tests use `TestFramework` (`test/test_framework.h`) for result tracking and `ServerRunner` RAII wrappers for automatic server thread lifecycle management.
