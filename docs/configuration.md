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

struct ServerConfig {
    std::string bind_host = "127.0.0.1";
    int bind_port = 8080;
    TlsConfig tls;
    LogConfig log;
    int max_connections = 10000;
    int idle_timeout_sec = 300;      // 5 minutes
    int worker_threads = 3;
    size_t max_header_size = 8192;       // 8 KB
    size_t max_body_size = 1048576;      // 1 MB
    size_t max_ws_message_size = 16777216; // 16 MB
    int request_timeout_sec = 30;        // Slowloris protection
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
    "log": {
        "level": "info",
        "file": "",
        "max_file_size": 10485760,
        "max_files": 3
    }
}
```

Missing fields in the JSON file retain their default values.

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

### Validation

`ConfigLoader::Validate()` checks:
- Port in valid range (1-65535)
- Worker threads > 0
- If TLS enabled, cert_file and key_file must be non-empty

Throws `std::invalid_argument` on validation failure.

### Type Safety

- `size_t` fields (`max_header_size`, `max_body_size`, `max_ws_message_size`) use `is_number_unsigned()` to reject negative JSON values (prevents unsigned wrap-around)
- Integer env vars use `std::stoi()` (not `atoi()`) for proper error detection on non-numeric input

## Structured Logging

### API

```cpp
#include "log/logger.h"

// Initialize (call once, before spawning threads)
logging::Init(
    "myserver",                    // Logger name
    spdlog::level::info,          // Minimum level
    "/var/log/server.log",        // Optional file path (empty = stdout only)
    10485760,                     // Max file size (10 MB)
    3                             // Max rotated files
);

// Use throughout the application
logging::Get()->info("Server starting on {}:{}", host, port);
logging::Get()->debug("New connection fd={}", fd);
logging::Get()->warn("Connection limit reached: {}", max_connections);
logging::Get()->error("TLS handshake failed: {}", error);

// Shutdown (flush and cleanup)
logging::Shutdown();
```

### Log Levels

| Level | Use Case |
|-------|----------|
| `trace` | Detailed debugging (frame bytes, buffer contents) |
| `debug` | Connection events, state transitions |
| `info` | Server lifecycle, configuration summary |
| `warn` | Recoverable issues, approaching limits |
| `error` | Failures requiring attention |
| `critical` | Fatal conditions |

### Output Format

```
[2026-03-19 12:34:56.789] [reactor] [info] Server starting on 0.0.0.0:8080
[2026-03-19 12:34:56.790] [reactor] [debug] New connection fd=5
[2026-03-19 12:34:57.001] [reactor] [error] TLS handshake failed: certificate verify failed
```

### Sinks

- **Console sink**: Always active, with color output
- **Rotating file sink**: Optional, configured via `log.file` in ServerConfig
  - Rotates when file reaches `max_file_size` (default 10 MB)
  - Keeps `max_files` rotated files (default 3)

### Thread Safety

- `Init()` must be called before spawning threads (sets up spdlog registry)
- `Get()` is thread-safe after initialization
- If `Init()` not called, `Get()` returns spdlog's default logger

## Third-Party Dependencies

| Library | Version | Path | Purpose |
|---------|---------|------|---------|
| nlohmann/json | 3.11.3 | `third_party/nlohmann/json.hpp` | Single-header JSON parsing |
| spdlog | 1.15.1 | `third_party/spdlog/` | Header-only structured logging |

Both are MIT-licensed, vendored in the repository.
