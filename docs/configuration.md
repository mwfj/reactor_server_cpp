# Configuration and Logging

JSON-based configuration loading with environment variable overrides and structured logging via spdlog.

## Configuration

### ServerConfig

Three config structs with sensible defaults:

```cpp
struct TlsConfig {
    bool enabled = false;
    std::string cert_file;
    std::string key_file;
    std::string min_version = "1.2";
};

struct LogConfig {
    std::string level = "info";     // trace, debug, info, warn, error, critical
    std::string file;               // empty = stdout only
    size_t max_file_size = 10485760; // 10 MB
    int max_files = 3;
};

struct Http2Config {
    bool enabled = true;                   // Enable HTTP/2 (h2 + h2c)
    uint32_t max_concurrent_streams = 100; // Max simultaneous streams
    uint32_t initial_window_size = 65535;  // Flow control window (64 KB - 1)
    uint32_t max_frame_size = 16384;       // Max frame payload (16 KB)
    uint32_t max_header_list_size = 65536; // Max header block size (64 KB)
};

struct ServerConfig {
    std::string bind_host = "127.0.0.1";
    int bind_port = 8080;
    TlsConfig tls;
    LogConfig log;
    Http2Config http2;
    int max_connections = 10000;
    int idle_timeout_sec = 300;      // 5 minutes
    int worker_threads = 3;
    size_t max_header_size = 8192;       // 8 KB
    size_t max_body_size = 1048576;      // 1 MB
    size_t max_ws_message_size = 16777216; // 16 MB
    int request_timeout_sec = 30;        // Slowloris protection
    int shutdown_drain_timeout_sec = 30; // Max wait for in-flight H2 streams
};
```

### Loading Configuration

```cpp
#include "config/config_loader.h"

// From JSON file
ServerConfig config = ConfigLoader::LoadFromFile("config/server.json");

// From JSON string
ServerConfig config = ConfigLoader::LoadFromString(R"({"bind_port": 9090})");

// Default values
ServerConfig config = ConfigLoader::Default();

// Apply environment variable overrides (takes precedence)
ConfigLoader::ApplyEnvOverrides(config);

// Validate (throws on invalid)
ConfigLoader::Validate(config);

// Use with HttpServer
HttpServer server(config);
```

### JSON Config File

Reference config at `config/server.example.json`:

```json
{
    "bind_host": "127.0.0.1",
    "bind_port": 8080,
    "max_connections": 10000,
    "idle_timeout_sec": 300,
    "worker_threads": 3,
    "max_header_size": 8192,
    "max_body_size": 1048576,
    "max_ws_message_size": 16777216,
    "request_timeout_sec": 30,
    "tls": {
        "enabled": false,
        "cert_file": "",
        "key_file": "",
        "min_version": "1.2"
    },
    "http2": {
        "enabled": true,
        "max_concurrent_streams": 100,
        "initial_window_size": 65535,
        "max_frame_size": 16384,
        "max_header_list_size": 65536
    },
    "log": {
        "level": "info",
        "file": "",
        "max_file_size": 10485760,
        "max_files": 3
    }
}
```

Missing fields in the JSON file retain their default values. When `log.file` is empty (default), the server logs to console only. Set to a path (e.g., `"logs/reactor.log"`) to enable file logging with date-based rotation. Set `max_files` to `1` for external logrotate compatibility (no automatic rotation).

### Environment Variable Overrides

Environment variables take precedence over JSON file values:

| Variable | Config Field | Type |
|----------|-------------|------|
| `REACTOR_BIND_HOST` | `bind_host` | string |
| `REACTOR_BIND_PORT` | `bind_port` | int |
| `REACTOR_TLS_ENABLED` | `tls.enabled` | bool (`true`/`false`) |
| `REACTOR_TLS_CERT` | `tls.cert_file` | string |
| `REACTOR_TLS_KEY` | `tls.key_file` | string |
| `REACTOR_LOG_LEVEL` | `log.level` | string |
| `REACTOR_LOG_FILE` | `log.file` | string |
| `REACTOR_MAX_CONNECTIONS` | `max_connections` | int |
| `REACTOR_IDLE_TIMEOUT` | `idle_timeout_sec` | int |
| `REACTOR_WORKER_THREADS` | `worker_threads` | int |
| `REACTOR_REQUEST_TIMEOUT` | `request_timeout_sec` | int |
| `REACTOR_SHUTDOWN_DRAIN_TIMEOUT` | `shutdown_drain_timeout_sec` | int |
| `REACTOR_HTTP2_ENABLED` | `http2.enabled` | bool (`1`/`true`/`yes`) |
| `REACTOR_HTTP2_MAX_CONCURRENT_STREAMS` | `http2.max_concurrent_streams` | int |
| `REACTOR_HTTP2_INITIAL_WINDOW_SIZE` | `http2.initial_window_size` | int |
| `REACTOR_HTTP2_MAX_FRAME_SIZE` | `http2.max_frame_size` | int |
| `REACTOR_HTTP2_MAX_HEADER_LIST_SIZE` | `http2.max_header_list_size` | int |

### Validation

`ConfigLoader::Validate()` checks:
- Port in valid range (1-65535)
- Worker threads > 0
- If TLS enabled, cert_file and key_file must be non-empty
- shutdown_drain_timeout_sec: 0-300 (0 = immediate close)
- If HTTP/2 enabled: max_concurrent_streams >= 1, initial_window_size 1 to 2^31-1, max_frame_size 16384 to 16777215, max_header_list_size >= 1

Throws `std::invalid_argument` on validation failure.

### Type Safety

- `size_t` fields (`max_header_size`, `max_body_size`, `max_ws_message_size`) use `is_number_unsigned()` to reject negative JSON values (prevents unsigned wrap-around)
- Integer env vars use `std::stoi()` (not `atoi()`) for proper error detection on non-numeric input

## Structured Logging

### API

```cpp
#include "log/logger.h"
#include "log/log_utils.h"  // SanitizePath helper

// Create log directory if needed
logging::EnsureLogDir("logs");

// Initialize (call once, before spawning threads)
// File path uses date-based naming: "logs/reactor.log" →
//   "logs/reactor-2026-03-30.log" (actual file)
logging::Init(
    "reactor",                     // Logger name
    spdlog::level::info,          // Minimum level
    "logs/reactor.log",           // Log file path (empty = stdout only)
    10485760,                     // Max file size per log file (10 MB)
    3                             // Max total log files to keep
);

// System markers for visual separation
logging::WriteMarker("SERVER START");

// Use throughout the application
logging::Get()->info("Server starting on {}:{}", host, port);
logging::Get()->debug("New connection fd={}", fd);
logging::Get()->warn("Connection limit reached: {}", max_connections);
logging::Get()->error("TLS handshake failed fd={}", fd);

// Periodic size-based rotation check
logging::CheckRotation();

// Log file reopen (e.g., on SIGHUP)
logging::Reopen();

// Shutdown
logging::WriteMarker("SERVER STOP");
logging::Shutdown();
```

### Date-Based File Naming

Log files use the naming pattern `{prefix}-{YYYY-MM-DD}[-{seq}].log`:

```
logs/reactor-2026-03-30.log       (first file of the day)
logs/reactor-2026-03-30-1.log     (after first size rotation)
logs/reactor-2026-03-30-2.log     (after second rotation)
```

On restart, the logger appends to the latest non-full file for today's date. The `logs/` directory is created automatically when the server starts (if `log.file` has a directory component).

### Log Levels

| Level | Use Case |
|-------|----------|
| `trace` | Detailed debugging (frame bytes, buffer contents, timer ticks) |
| `debug` | Construction, internal invocations, state transitions |
| `info` | Server lifecycle, key trajectory stages, request received |
| `warn` | Limits exceeded, timeouts, non-fatal operational errors |
| `error` | Logic failures that don't crash the system |
| `critical` | System or critical-component crash |

### Output Format

```
[2026-03-30 12:34:56.789] [reactor] [info] ================================ SERVER START ================================
[2026-03-30 12:34:56.790] [reactor] [info] reactor_server version 0.1.0 starting
[2026-03-30 12:34:56.791] [reactor] [debug] New connection fd=5
[2026-03-30 12:34:57.001] [reactor] [warn] Request timeout fd=5
[2026-03-30 12:34:57.002] [reactor] [error] TLS handshake failed fd=5
```

### Trace Correlation

All log entries include contextual identifiers for correlation:
- **Connection**: `fd=N` (file descriptor)
- **HTTP/2 streams**: `stream=N`
- **Requests**: method + sanitized path (no query params)

### Sensitive Data Protection

Use `logging::SanitizePath(path)` to strip query parameters and fragments from URLs before logging. Never log API keys, authorization headers, cookie values, message content, or full URLs with query parameters.

### Sinks

- **Console sink**: Active by default, with color output (disabled in daemon mode)
- **File sink**: Configured via `log.file` in ServerConfig
  - Uses `basic_file_sink_mt` with date-based path resolution
  - Size-based rotation via `CheckRotation()` (called periodically)
  - Default file: `logs/reactor.log` → `logs/reactor-{date}.log`

### Thread Safety

- `Init()` must be called before spawning threads (sets up spdlog registry)
- `Get()` is thread-safe after initialization
- `CheckRotation()` is thread-safe (acquires internal mutex)
- If `Init()` not called, `Get()` returns spdlog's default logger

## Third-Party Dependencies

| Library | Version | Path | Purpose |
|---------|---------|------|---------|
| nlohmann/json | 3.11.3 | `third_party/nlohmann/json.hpp` | Single-header JSON parsing |
| spdlog | 1.15.1 | `third_party/spdlog/` | Header-only structured logging |

Both are MIT-licensed, vendored in the repository.
