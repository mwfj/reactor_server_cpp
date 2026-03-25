# CLI Command-Line Interface

The `reactor_server` binary provides a production entry point for running, managing, and inspecting the server.

## Quick Start

```bash
# Build the server
make server

# Start with default config
./reactor_server

# Start with custom config and port
./reactor_server -c config/server.json -p 9090

# Check if the server is running
./reactor_server -s status

# Graceful shutdown
./reactor_server -s stop
```

## Usage

```
reactor_server [options]

Server Control:
  -c, --config <file>         Config file path (default: config/server.json)
  -t, --test-config           Validate config and exit
  -s, --signal <action>       Send signal to running instance (stop, status)
  --dump-effective-config     Show resolved config and exit

Runtime Overrides:
  -p, --port <port>           Override bind port (1-65535)
  -H, --host <address>        Override bind address (numeric IPv4 only)
  -l, --log-level <level>     Override log level
                              (trace, debug, info, warn, error, critical)
  -w, --workers <N>           Override worker thread count

Process Management:
  -P, --pid-file <file>       PID file path (default: /tmp/reactor_server.pid)
  --no-health-endpoint       Disable the /health endpoint

Info:
  -v, --version               Print version and exit
  -V, --version-verbose       Print version with build details and exit
  -h, --help                  Print this help and exit
```

## Config Override Precedence

Values are resolved in this order (highest wins):

```
4. CLI flags      (-p 9090, -H 0.0.0.0, -l debug, -w 4)
3. Environment    (REACTOR_BIND_PORT=9090)
2. Config file    (config/server.json: {"bind_port": 9090})
1. Defaults       (ServerConfig{} defaults: bind_port=8080)
```

## Config Validation

Validate a configuration file without starting the server:

```bash
./reactor_server -t -c config/server.json
# Output: "Configuration is valid." (exit 0) or error (exit 1)
```

## Effective Config Dump

Show the fully resolved config (after applying file, env, and CLI overrides):

```bash
./reactor_server --dump-effective-config -p 9090 -l debug
```

This outputs formatted JSON that can be redirected to a file and used as a config:

```bash
./reactor_server --dump-effective-config -p 9090 > my_config.json
./reactor_server -c my_config.json
```

## Signal Management

### Status Check

```bash
./reactor_server -s status
# reactor_server is running
#   PID:        12345
#   PID file:   /tmp/reactor_server.pid
```

### Graceful Stop

```bash
./reactor_server -s stop
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
| `SIGPIPE` | Ignored (handled by MSG_NOSIGNAL) |

Signal handling uses the self-pipe pattern for async-signal-safety. The signal handler only calls `write()` to a pipe; a dedicated thread reads the pipe and calls `HttpServer::Stop()` from a normal execution context.

## PID File

The server writes its PID to a file on startup and removes it on exit. The PID file uses `flock()` for race-free singleton enforcement.

- Default path: `/tmp/reactor_server.pid`
- Override: `-P /path/to/custom.pid`
- If the server crashes (SIGKILL), the stale PID file is automatically detected and removed on the next start

### Multiple Instances

Run multiple instances with different PID files and ports:

```bash
./reactor_server -p 8080 -P /tmp/reactor_8080.pid &
./reactor_server -p 8081 -P /tmp/reactor_8081.pid &
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
./reactor_server -v
# reactor_server version 1.0.0

./reactor_server -V
# reactor_server version 1.0.0
#   Compiler:  13.3.0 (C++17)
#   OpenSSL:   OpenSSL 3.0.13 30 Jan 2024
#   Platform:  Linux
#   Features:  HTTP/1.1, WebSocket (RFC 6455), TLS/SSL
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (normal exit, config test passed, status check) |
| 1 | General error (config invalid, bind failure, signal send failure) |
| 2 | Usage error (invalid CLI arguments) |

## Build

```bash
make server         # Build only the production binary
make all            # Build both test runner (./run) and server (./reactor_server)
make clean          # Remove both binaries
```
