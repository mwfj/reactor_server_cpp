# WebSocket Protocol Layer

WebSocket (RFC 6455) support layered on top of the HTTP layer. Connections begin as HTTP GET requests with `Upgrade: websocket`, transition via a 101 Switching Protocols response, and then operate on a binary frame protocol for bidirectional messaging.

## Quick Start

```cpp
#include "http/http_server.h"

HttpServer server("0.0.0.0", 8080);

server.WebSocket("/ws", [](WebSocketConnection& ws) {
    ws.OnMessage([](WebSocketConnection& ws, const std::string& msg, bool is_binary) {
        ws.SendText("Echo: " + msg);
    });

    ws.OnClose([](WebSocketConnection& ws, uint16_t code, const std::string& reason) {
        logging::Get()->info("WS closed: {} {}", code, reason);
    });
});

server.Start();
```

## Components

| Component | Header | Role |
|-----------|--------|------|
| `WebSocketConnection` | `include/ws/websocket_connection.h` | Message-level API with fragmentation |
| `WebSocketParser` | `include/ws/websocket_parser.h` | Binary frame parser state machine |
| `WebSocketFrame` | `include/ws/websocket_frame.h` | Frame struct, serialization, factory methods |
| `WebSocketHandshake` | `include/ws/websocket_handshake.h` | RFC 6455 handshake validation |
| `utf8_validate.h` | `include/ws/utf8_validate.h` | RFC 3629 UTF-8 validation |

## WebSocketConnection API

### Callbacks

```cpp
// Message received (text or binary)
ws.OnMessage([](WebSocketConnection& ws, const std::string& msg, bool is_binary) {
    if (is_binary) {
        process_binary(msg);
    } else {
        process_text(msg);
    }
});

// Connection closed (with close code and reason)
ws.OnClose([](WebSocketConnection& ws, uint16_t code, const std::string& reason) {
    // code: 1000 (normal), 1001 (going away), 1002 (protocol error), etc.
});

// Ping received (auto-pong is sent automatically)
ws.OnPing([](WebSocketConnection& ws, const std::string& payload) {
    // informational — pong already sent
});

// Protocol error
ws.OnError([](WebSocketConnection& ws, const std::string& error) {
    logging::Get()->error("WS error: {}", error);
});
```

### Send Operations

```cpp
ws.SendText("Hello, World!");            // Text frame
ws.SendBinary(binary_data);              // Binary frame
ws.SendClose(1000, "Normal closure");    // Close frame
ws.SendPing("heartbeat");               // Ping frame
ws.SendPong("heartbeat");               // Pong frame (usually automatic)
```

### Connection State

```cpp
ws.IsOpen();  // true if connection is active and no Close sent
ws.fd();      // Underlying file descriptor
```

## Upgrade Flow

```
1. Client sends HTTP GET with:
     Upgrade: websocket
     Connection: Upgrade
     Sec-WebSocket-Key: <base64>
     Sec-WebSocket-Version: 13
     Host: example.com

2. HttpConnectionHandler detects req.upgrade && req.method == "GET"

3. WebSocketHandshake::Validate() checks RFC 6455 §4.2.1:
     ✓ GET method
     ✓ No request body (Content-Length == 0, empty body, no Transfer-Encoding)
     ✓ HTTP/1.1 or higher
     ✓ Host header present
     ✓ Upgrade: websocket
     ✓ Connection: Upgrade
     ✓ Sec-WebSocket-Key present
     ✓ Sec-WebSocket-Version: 13

4. Router checks HasWebSocketRoute(path) — BEFORE sending 101
     If no route → 404 (client stays in HTTP mode)

5. Middleware chain runs (auth, CORS, etc.)
     If middleware short-circuits → response sent (client stays in HTTP)

6. Server sends 101 Switching Protocols:
     HTTP/1.1 101 Switching Protocols
     Upgrade: websocket
     Connection: Upgrade
     Sec-WebSocket-Accept: <SHA-1(key + GUID) base64>

7. Create WebSocketConnection wrapping the ConnectionHandler

8. WS route handler invoked — wire OnMessage/OnClose callbacks

9. Input buffer cap switches from HTTP limit to max_ws_message_size

10. Any trailing bytes after HTTP headers forwarded as WebSocket data
```

**Key design decision:** Route existence is checked BEFORE sending 101 to avoid upgrading connections for unregistered paths.

## Frame Types

| Opcode | Name | Description |
|--------|------|-------------|
| 0x0 | Continuation | Fragment continuation |
| 0x1 | Text | UTF-8 text data |
| 0x2 | Binary | Binary data |
| 0x8 | Close | Connection close with optional code+reason |
| 0x9 | Ping | Keep-alive ping |
| 0xA | Pong | Keep-alive pong |

### Frame Serialization

Server-to-client frames are NOT masked (per RFC 6455). Handles 7-bit, 16-bit, and 64-bit payload length encoding.

### Close Codes

| Code | Meaning | Direction |
|------|---------|-----------|
| 1000 | Normal Closure | Both |
| 1001 | Going Away | Both |
| 1002 | Protocol Error | Both |
| 1003 | Unsupported Data | Both |
| 1007 | Invalid Payload | Both |
| 1008 | Policy Violation | Both |
| 1009 | Message Too Big | Both |
| 1010 | Missing Extension | Client → Server only |
| 1011 | Unexpected Condition | Server only |
| 1012-1014 | Reserved | Both |
| 3000-4999 | Application-defined | Both |

- Server cannot send 1010 (client-only). If client sends 1010, server echoes 1000 instead.
- `IsValidCloseCode()` / `IsValidServerCloseCode()` enforce these rules.

## Fragmentation

Large messages can be split across multiple frames:

```
Text(fin=0, "Hello, ")  → start fragment
Continuation(fin=0, "World")  → continue
Continuation(fin=1, "!")  → final fragment → delivers "Hello, World!"
```

- Continuation frames accumulated in `fragment_buffer_`
- Delivered as a single reassembled message on the final frame
- Size limit: `max_message_size` (configurable, default 16 MB). Uses strict `>` — exact limit is valid
- New Text/Binary frame during active fragmentation → Close 1002 (Protocol Error)

## Auto Ping/Pong

- Received Ping → automatic Pong with matching payload (RFC 6455 §5.5.3)
- Auto-pong calls `SendFrame` directly, bypassing the public API's close-state guard (MUST respond during close handshake per spec)
- Application-level `OnPing` callback is informational — pong is already sent

## Close Handshake

```
Normal close (server-initiated):
  Server: SendClose(1000) → sets close_sent_ = true
  Client: receives Close, sends Close reply
  Server: receives Close reply → CallCloseCb → transport close

Normal close (client-initiated):
  Client: sends Close
  Server: receives Close → echoes Close → sets is_open_ = false → CloseAfterWrite

Abnormal close (transport disconnect):
  NotifyTransportClose() → fires close callback with sent close code or 1006
```

### Ordering Guarantees

- `close_sent_` set BEFORE `SendFrame()` in `SendClose()` to prevent re-entrant duplicate Close frames
- `is_open_` set to false BEFORE sending reply Close to prevent duplicate close callbacks from synchronous send failures
- All sends serialized via `recursive_mutex send_mtx_` to prevent data frames after Close

## RFC 6455 Compliance

| Requirement | Implementation |
|-------------|---------------|
| Client frames must be masked (§5.1) | Parser rejects unmasked frames |
| RSV bits must be 0 without extensions (§5.2) | Parser rejects non-zero RSV |
| Control frames ≤ 125 bytes (§5.5) | Parser validates |
| Control frames must be fin=true (§5.5) | Parser validates |
| Server frames must NOT be masked | Serialize() never masks |
| Respond to Ping with Pong (§5.5.3) | Auto-pong, even during close handshake |
| UTF-8 validation for text frames | `IsValidUtf8()` on text/close reason |
| Close code validation (§7.4) | `IsValidCloseCode()` / `IsValidServerCloseCode()` |
| No data frames after Close (§5.5.1) | `send_mtx_` + `close_sent_` guard |

## Graceful Shutdown

`HttpServer::Stop()` sends Close(1001 "Going Away") to all upgraded connections:
1. Collect WS connections under `conn_mtx_`, then release lock
2. Send Close frames outside lock (prevents deadlock from inline send failures)
3. `CloseAfterWrite()` after each `SendClose()` (no need to wait for peer reply during shutdown)
4. `NetServer::Stop()` skips connections already marked `IsCloseDeferred()`

## Input Buffer Cap

After WS upgrade, the input buffer cap switches from the HTTP limit (`max_header_size + max_body_size`) to `max_ws_message_size`. The read loop stops at the cap (data stays in kernel buffer, nothing discarded) and requeues, bounding per-cycle memory allocation while the WS parser enforces frame/message limits independently.

## Ownership After Upgrade

```
HttpServer → http_connections_ map → HttpConnectionHandler
                                        ↓ unique_ptr
                                     WebSocketConnection
                                        ↓ shared_ptr
                                     ConnectionHandler (reactor core)
```

No circular references. `ConnectionHandler` does not reference back to its owners.
