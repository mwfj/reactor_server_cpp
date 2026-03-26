# CLI Command-Line Interface

The `reactor_server` binary provides a production entry point for running, managing, and inspecting the server.

## Quick Start

```bash
# Build the server
make server

# Start with default config
./reactor_server start

# Start with custom config and port
./reactor_server start -c config/server.example.json -p 9090

# Check if the server is running
./reactor_server status

# Graceful shutdown
./reactor_server stop
```

## Usage

```
Usage: reactor_server <command> [options]

Commands:
  start       Start the server (foreground, or -d for daemon)
  stop        Stop a running server
  status      Check server status
  validate    Validate configuration
  config      Show effective configuration
  version     Show version information
  help        Show this help

Start options:
  -c, --config <file>         Config file (default: config/server.json)
  -p, --port <port>           Override bind port (1-65535)
  -H, --host <address>        Override bind address (numeric IPv4 only)
  -l, --log-level <level>     Override log level
                              (trace, debug, info, warn, error, critical)
  -w, --workers <N>           Override worker thread count (0 = auto)
  -P, --pid-file <file>       PID file path (default: /tmp/reactor_server.pid)
  -d, --daemonize             Run as a background daemon
  --no-health-endpoint       Disable the /health endpoint

Stop/status options:
  -P, --pid-file <file>       PID file path (default: /tmp/reactor_server.pid)

Validate/config options:
  -c, --config <file>         Config file
  -p, --port <port>           Override bind port
  -H, --host <address>        Override bind address
  -l, --log-level <level>     Override log level
  -w, --workers <N>           Override worker threads

Global options:
  -v, --version               Same as 'version'
  -V, --version-verbose       Verbose version with build details
  -h, --help                  Same as 'help'
```

Running `./reactor_server` with no arguments prints the usage summary.

## Config Override Precedence

Values are resolved in this order (highest wins):

```
4. CLI flags      (-p 9090, -H 0.0.0.0, -l debug, -w 4)
3. Environment    (REACTOR_BIND_PORT=9090)
2. Config file    (config/server.example.json: {"bind_port": 9090})
1. Defaults       (ServerConfig{} defaults: bind_port=8080)
```

## Config Validation

Validate a configuration file without starting the server:

```bash
./reactor_server validate -c config/server.example.json
# Output: "Configuration is valid." (exit 0) or error (exit 1)
```

## Effective Config Dump

Show the fully resolved config (after applying file, env, and CLI overrides):

```bash
./reactor_server config -p 9090 -l debug
```

This outputs formatted JSON that can be redirected to a file and used as a config:

```bash
./reactor_server config -p 9090 > my_config.json
./reactor_server start -c my_config.json
```

## Server Management

### Start

```bash
./reactor_server start
./reactor_server start -p 9090 -l debug
./reactor_server start -c config/server.example.json --no-health-endpoint
```

### Status Check

```bash
./reactor_server status
# reactor_server is running
#   PID:        12345
#   PID file:   /tmp/reactor_server.pid
```

### Daemon Mode

Run the server as a background daemon:

```bash
# Requires a log file (daemon has no terminal)
./reactor_server start -d -c config/production.json

# Or set log file via environment variable
REACTOR_LOG_FILE=/var/log/reactor.log ./reactor_server start -d

# Verify it started
./reactor_server status
```

**Daemon mode requirements:**
- A log file must be configured (`log.file` in config or `REACTOR_LOG_FILE` env var)
- Log file, PID file, and TLS cert/key paths must be absolute
- The launching shell sees exit code 0 immediately after fork; use `status` to verify

### Graceful Stop

```bash
./reactor_server stop
# Sent SIGTERM to reactor_server (PID 12345)
```

You can also send signals directly:

```bash
kill -TERM $(cat /tmp/reactor_server.pid)
```

## Signal Handling

| Signal | Behavior |
|--------|----------|
| `SIGTERM` | Graceful shutdown (sends WS Close 1001, drains connections, exits) |
| `SIGINT` | Same as SIGTERM (Ctrl+C in foreground) |
| `SIGHUP` | Reopen log files (for log rotation with `logrotate`) |
| `SIGPIPE` | Ignored (handled by MSG_NOSIGNAL) |

Signal handling uses `sigwait()` (POSIX synchronous signal wait). Signals are blocked in all threads via `pthread_sigmask`; the main thread loops on `sigwait()` which synchronously dequeues blocked signals. SIGHUP triggers log file rotation; SIGTERM/SIGINT break the loop and call `HttpServer::Stop()`.

### Log Rotation

The server supports `logrotate`-style log rotation via SIGHUP:

```bash
# Manual rotation
kill -HUP $(cat /tmp/reactor_server.pid)

# logrotate config example (/etc/logrotate.d/reactor_server):
# /var/log/reactor.log {
#     daily
#     rotate 7
#     postrotate
#         kill -HUP $(cat /tmp/reactor_server.pid) 2>/dev/null || true
#     endscript
# }
```

## PID File

The server writes its PID to a file on startup and removes it on exit. The PID file uses `flock()` for race-free singleton enforcement.

- Default path: `/tmp/reactor_server.pid`
- Override: `-P /path/to/custom.pid`
- If the server crashes (SIGKILL), the stale PID file is automatically detected on the next start

### Multiple Instances

Run multiple instances with different PID files and ports:

```bash
./reactor_server start -p 8080 -P /tmp/reactor_8080.pid &
./reactor_server start -p 8081 -P /tmp/reactor_8081.pid &
```

## Health Endpoint

By default, the server registers a `/health` endpoint:

```bash
curl http://127.0.0.1:8080/health
# {"status":"ok","pid":12345,"uptime_seconds":3600}
```

Disable it with `--no-health-endpoint`.

## Version Info

```bash
./reactor_server version
# reactor_server version 1.0.0

./reactor_server version -V
# reactor_server version 1.0.0
#   Compiler:  13.3.0 (C++17)
#   OpenSSL:   OpenSSL 3.0.13 30 Jan 2024
#   Platform:  Linux
#   Features:  HTTP/1.1, WebSocket (RFC 6455), TLS/SSL
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (normal exit, config valid, status confirms running, stop sent) |
| 1 | General error (config invalid, bind failure, server not running) |
| 2 | Usage error (unknown command, invalid option) |

## Build

```bash
make server         # Build only the production binary
make all            # Build both test runner (./run) and server (./reactor_server)
make clean          # Remove both binaries
```
