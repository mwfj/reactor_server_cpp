# HTTP/1.1 Layer

The HTTP layer sits between the reactor core (`ConnectionHandler`) and application logic, parsing raw bytes into structured requests and serializing responses to the wire.

## Quick Start

```cpp
#include "http/http_server.h"

HttpServer server("0.0.0.0", 8080);

server.Get("/health", [](const HttpRequest& req, HttpResponse& res) {
    res.Status(200).Json(R"({"status":"ok"})");
});

server.Start();  // blocks in event loop
```

## Components

| Component | Header | Role |
|-----------|--------|------|
| `HttpServer` | `include/http/http_server.h` | Top-level entry point, owns NetServer + HttpRouter |
| `HttpRouter` | `include/http/http_router.h` | Route registration, dispatch, middleware chain |
| `HttpConnectionHandler` | `include/http/http_connection_handler.h` | Per-connection HTTP state machine |
| `HttpParser` | `include/http/http_parser.h` | llhttp wrapper (pimpl, no C types exposed) |
| `HttpRequest` | `include/http/http_request.h` | Parsed request struct |
| `HttpResponse` | `include/http/http_response.h` | Response builder with factory methods |

## Route Registration

```cpp
HttpServer server("0.0.0.0", 8080);

// Method-specific helpers
server.Get("/users", handler);
server.Post("/users", handler);
server.Put("/users", handler);
server.Delete("/users", handler);

// Generic method registration
server.Route("PATCH", "/users", handler);

// WebSocket upgrade route
server.WebSocket("/ws", ws_handler);
```

### Handler Signature

```cpp
using Handler = std::function<void(const HttpRequest& request, HttpResponse& response)>;
```

Handlers receive a const reference to the parsed request and a mutable reference to the response. Set status, headers, and body on the response object.

### Route Matching

- **Exact path matching** — no wildcards, no pattern matching, no path parameters
- **405 Method Not Allowed** — automatically returned when path matches but method doesn't
- **HEAD fallback** — if no HEAD handler registered, GET handler is invoked with a cloned request (`method = "GET"`) per RFC 7231 §4.3.2

## Middleware

```cpp
// Logging middleware
server.Use([](const HttpRequest& req, HttpResponse& res) {
    logging::Get()->info("{} {}", req.method, req.path);
    return true;  // continue chain
});

// Auth middleware (short-circuits on failure)
server.Use([](const HttpRequest& req, HttpResponse& res) {
    if (!check_auth(req.GetHeader("Authorization"))) {
        res.Status(401).Json(R"({"error":"unauthorized"})");
        return false;  // stop chain, send 401
    }
    return true;
});

// CORS middleware
server.Use([](const HttpRequest& req, HttpResponse& res) {
    res.Header("Access-Control-Allow-Origin", "*");
    return true;
});
```

- Middleware executes in registration order before route handlers
- Return `true` to continue the chain, `false` to short-circuit (response is sent immediately)
- **Headers survive fallbacks**: middleware-set headers are preserved even on 404/405 responses because `Dispatch()` sets status on the existing response object rather than replacing it

## HttpRequest

```cpp
struct HttpRequest {
    std::string method;       // "GET", "POST", etc.
    std::string url;          // Full URL as received
    std::string path;         // URL path component ("/users")
    std::string query;        // Query string ("page=1&limit=10")
    int http_major, http_minor;
    std::map<std::string, std::string> headers;  // Lowercase keys
    std::string body;
    bool keep_alive;
    bool upgrade;             // Connection: Upgrade (WebSocket)
    size_t content_length;
    bool complete;

    std::string GetHeader(const std::string& name) const;  // Case-insensitive
    bool HasHeader(const std::string& name) const;
};
```

### Absolute-Form URI Support

Proxied requests using absolute-form URIs (`GET http://example.com/foo HTTP/1.1`) are handled correctly:
- Scheme + authority stripped, path extracted
- Case-insensitive scheme detection (RFC 3986 §3.1): `HTTP://` and `http://` both recognized
- Empty path + query: `http://example.com?x=1` → `path="/", query="x=1"`

## HttpResponse

### Builder Pattern

```cpp
// Chained builder
HttpResponse().Status(200).Header("X-Custom", "value").Json(R"({"ok":true})")

// Content type helpers
res.Json(json_string);   // Sets Content-Type: application/json
res.Text(text_string);   // Sets Content-Type: text/plain
res.Html(html_string);   // Sets Content-Type: text/html
res.Body(data, "image/png");  // Custom content type
```

### Factory Methods

| Method | Status | Use Case |
|--------|--------|----------|
| `Ok()` | 200 | Success |
| `BadRequest(msg)` | 400 | Malformed request |
| `Unauthorized(msg)` | 401 | Authentication required |
| `Forbidden()` | 403 | Access denied |
| `NotFound()` | 404 | No matching route |
| `MethodNotAllowed()` | 405 | Wrong HTTP method |
| `RequestTimeout()` | 408 | Slowloris timeout |
| `PayloadTooLarge()` | 413 | Body exceeds limit |
| `HeaderTooLarge()` | 431 | Headers exceed limit |
| `InternalError(msg)` | 500 | Server error |
| `ServiceUnavailable()` | 503 | Overloaded |
| `HttpVersionNotSupported()` | 505 | Non-1.x HTTP version |

### Header Behavior

`Header()` uses **set-semantics**: replaces any existing header with the same name (case-insensitive). This prevents conflicting duplicates (e.g., middleware sets Content-Type, then handler sets another).

**Exception**: `Set-Cookie` and `WWW-Authenticate` append rather than replace, as these are legally repeatable per RFC 6265/7235.

### Serialization

`Serialize()` produces standard HTTP wire format:
- Auto-generates `Content-Length` header
- Includes `Content-Length: 0` for empty-body responses (required for keep-alive on non-204/304)

## Pipelining and Keep-Alive

- HTTP/1.1 keep-alive is supported by default
- `OnRawData()` loops to process all complete requests in a single data buffer
- Parser resets between pipelined requests
- `consumed == 0` guard prevents infinite loop at buffer boundaries

## Size Limits and Security

| Limit | Default | Config Field |
|-------|---------|-------------|
| Max header size | 8 KB | `max_header_size` |
| Max body size | 1 MB | `max_body_size` |
| Request timeout | 30s | `request_timeout_sec` |

- Headers exceeding `max_header_size` → 431 Header Too Large
- Body exceeding `max_body_size` → 413 Payload Too Large
- Request timeout (Slowloris protection): deadline armed on first data byte, sends 408 on expiry

## Expect Header Handling

- `Expect: 100-continue` → sends `100 Continue` interim response, then waits for body
- Unsupported Expect values → 417 Expectation Failed (checked in both complete and incomplete request paths)
- WS upgrade with `Expect: 100-continue` → 400 Bad Request (body contradicts upgrade)

## Error Handling

- Internal errors are logged via spdlog, generic error responses sent to clients
- Parse errors → 400 Bad Request
- HTTP version != 1.x → 505 HTTP Version Not Supported
- Unregistered paths → 404 Not Found (with middleware headers preserved)
- Wrong method on registered path → 405 Method Not Allowed

## Data Flow

```
epoll_wait → Channel::HandleEvent → ConnectionHandler::OnMessage (read into input_bf_)
  → [TLS: SSL_read]
  → HttpConnectionHandler::OnRawData
  → HttpParser::Parse → HttpRequest
  → Expect header check
  → HttpRouter::RunMiddleware → HttpRouter::Dispatch
  → handler(request, response)
  → HttpResponse::Serialize → ConnectionHandler::SendRaw
  → [TLS: SSL_write]
```

## Third-Party Dependency

**llhttp** (v9.2.1) — HTTP/1.1 parser from Node.js. Vendored at `third_party/llhttp/`. Compiled as C objects, linked with C++ code. Hidden behind pimpl pattern — no llhttp types in public headers.
