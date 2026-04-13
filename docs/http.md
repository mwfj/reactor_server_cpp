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

Routes support exact paths, path parameters, regex constraints, and catch-all wildcards. The router uses a compressed radix trie (`RouteTrie`) per HTTP method for efficient lookup.

- **405 Method Not Allowed** — automatically returned when path matches but method doesn't
- **HEAD fallback** — if no HEAD handler registered, GET handler is invoked with a cloned request (`method = "GET"`) per RFC 7231 §4.3.2

### Route Pattern Syntax

#### Static routes

Exact literal paths. Highest priority during matching.

```cpp
server.Get("/health", handler);
server.Get("/api/v1/status", handler);
```

#### Path parameters (`:name`)

Capture a single path segment (everything between `/` separators). Accessed via `request.params`.

```cpp
server.Get("/users/:id", [](const HttpRequest& req, HttpResponse& res) {
    std::string user_id = req.params["id"];  // guaranteed present when handler runs
    res.Status(200).Json(R"({"id":")" + user_id + R"("})");
});

server.Get("/users/:user_id/posts/:post_id", [](const HttpRequest& req, HttpResponse& res) {
    // req.params["user_id"] and req.params["post_id"] are both populated
});
```

#### Regex constraints (`:name(regex)`)

Restrict a parameter to values matching a regex pattern. The regex is placed in parentheses after the parameter name. Non-matching values fall through to other routes or 404.

```cpp
// Only match numeric IDs
server.Get("/users/:id([0-9]+)", handler);

// Only match UUIDs
server.Get("/items/:uuid([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", handler);
```

#### Catch-all wildcards (`*name`)

Capture the entire remaining path (zero or more segments). Must be the last element in the pattern.

```cpp
server.Get("/static/*filepath", [](const HttpRequest& req, HttpResponse& res) {
    // GET /static/css/style.css → req.params["filepath"] = "css/style.css"
});
```

The captured value is the raw remaining path after the prefix. For normal paths, it does not include a leading `/` because the prefix consumed the separator (e.g., `"css/style.css"` for `/static/css/style.css`). Paths with `//` are passed through as-is.

### Priority Rules

When multiple patterns could match, the router uses this priority order:

1. **Static segments** — exact literal matches are tried first
2. **Parameter segments** — `:name` patterns are tried next
3. **Catch-all** — `*name` is tried last (lowest priority)

This means `/users/admin` (static) takes precedence over `/users/:id` (param) when the request path is `/users/admin`.

### Route Conflicts

The router rejects conflicting routes at registration time (throws `std::invalid_argument`):

- Duplicate exact routes: `Get("/users", h1)` then `Get("/users", h2)`
- Conflicting parameter constraints at the same position: `/:id([0-9]+)` vs `/:id([a-z]+)`
- Duplicate catch-all routes at the same level

### Non-Origin-Form Routes

The router supports non-origin-form request targets used by CONNECT and OPTIONS methods:

- **CONNECT authority-form**: `server.Route("CONNECT", "example.com:443", handler)` -- matches `CONNECT example.com:443 HTTP/1.1` (no leading `/`)
- **OPTIONS asterisk-form**: `server.Route("OPTIONS", "*", handler)` -- matches `OPTIONS * HTTP/1.1`

These are registered as exact-match patterns in the `RouteTrie`.

## Async Route Registration

Async routes are for handlers that need to perform async work (e.g., upstream proxy, database queries) and deliver the response later via a completion callback.

```cpp
#include "http/http_server.h"

HttpServer server(config);

// Async route — receives request + completion callback
server.GetAsync("/proxy/users", [&](const HttpRequest& req,
                                     HttpRouter::AsyncCompletionCallback complete) {
    // Checkout an upstream connection (non-blocking)
    upstream_manager->CheckoutAsync("api-backend", dispatcher_index,
        [complete](UpstreamLease lease) {
            // ... forward request to upstream, get response ...
            HttpResponse resp;
            resp.Status(200).Json(upstream_body);
            complete(std::move(resp));  // delivers response to client
        },
        [complete](int error_code) {
            complete(HttpResponse::ServiceUnavailable());
        });
});

// Method-specific async helpers
server.PostAsync("/proxy/data", async_handler);
server.PutAsync("/proxy/data", async_handler);
server.DeleteAsync("/proxy/data", async_handler);
server.RouteAsync("PATCH", "/proxy/data", async_handler);
```

### Async Handler Signature

```cpp
using AsyncCompletionCallback = std::function<void(HttpResponse)>;
using AsyncHandler = std::function<void(const HttpRequest& request,
                                         AsyncCompletionCallback complete)>;
```

The handler receives a const request reference and a completion callback. Call `complete(response)` exactly once to deliver the response. Both types are defined in `include/http/http_callbacks.h` (`HTTP_CALLBACKS_NAMESPACE`).

### Async Route Behavior

- **Middleware runs first** — same as sync routes (auth, CORS, logging all apply)
- **Parser blocked** — HTTP/1 parser pauses until completion fires, preserving pipeline response ordering
- **Shutdown-exempt** — the connection is marked exempt from graceful shutdown's close sweep while async work is pending
- **HEAD fallback** — if no async HEAD handler is registered, async GET handler is used (same as sync)
- **405 Allow** — async routes are included in the `Allow` header for 405 responses
- **Thread safety** — the completion callback MUST be invoked on the dispatcher thread that owns the connection. Upstream pool `CheckoutAsync` naturally routes callbacks to the correct dispatcher.
- **HTTP/2 support** — async routes work identically for H2 streams; the framework binds `SubmitStreamResponse` internally

## Proxy Routes

Proxy routes forward client requests to an upstream backend service. They are built on top of the async-route framework and require a matching `upstreams[]` entry in the server config so the connection pool, TLS client context, and retry/header policies exist. See [docs/configuration.md](configuration.md#proxy-route-configuration) for the full set of config fields.

### Auto-registration from config

The simplest way to use a proxy route is to set `proxy.route_prefix` in the upstream config. `HttpServer::Start()` walks every upstream with a non-empty `route_prefix` and registers the route automatically — no application code required.

```json
{
    "upstreams": [
        {
            "name": "api-backend",
            "host": "10.0.1.5",
            "port": 8080,
            "pool": { "max_connections": 64 },
            "proxy": {
                "route_prefix": "/api/v1/*rest",
                "strip_prefix": true,
                "methods": ["GET", "POST", "PUT", "DELETE"]
            }
        }
    ]
}
```

Any `GET/POST/PUT/DELETE` under `/api/v1/` is forwarded to `api-backend`, with the `/api/v1` prefix stripped before forwarding (so upstream sees `/users/123` instead of `/api/v1/users/123`).

### Programmatic registration

Applications that construct their own config in code can use `HttpServer::Proxy()`:

```cpp
#include "http/http_server.h"

HttpServer server(config);

// Register a proxy route on an already-configured upstream.
// Reuses the proxy fields (methods, strip_prefix, header_rewrite, retry,
// response_timeout_ms) from config.upstreams[i].proxy — only route_prefix
// is overridden by the first argument.
server.Proxy("/api/v1/*rest", "api-backend");

server.Start();
```

`Proxy()` calls must happen before `Start()`. Calling it afterwards — or naming an upstream that is not in the config — raises `std::invalid_argument`.

### HEAD precedence and companion methods

Proxy registrations interact with the HEAD-fallback rule from [Route Matching](#route-matching) as follows:

- **Paired HEAD + GET on the same registration** (both in `methods`): HEAD goes to the proxy, GET goes to the proxy. No fallback.
- **HEAD only** (no GET in `methods`): HEAD is registered as a proxy *default*. If a user async handler later registers GET on the same pattern, the router uses the user's GET for HEAD fallback and silently drops the proxy HEAD. This prevents accidental conflicts between library-provided proxies and application-defined GETs.
- **Companion methods**: If a proxy registers `OPTIONS` for a pattern that also has a user-registered async GET, the router marks the proxy pattern as a *companion*. At dispatch time, if the companion proxy route wins (e.g. for a non-matching method), it yields to the user handler via a runtime decision rather than a registration-time rejection — because the conflict is method-level and only detectable per-request.
- Per-`(method, pattern)` conflict markers are stored separately so two proxies registering disjoint methods on the same pattern do not contaminate each other's HEAD pairing.

### Request lifecycle and client abort

Each proxy request is handled by a per-request `ProxyTransaction`:

1. `CHECKOUT_PENDING` — wait for an idle pooled connection (or open a new one, subject to `pool.max_connections`)
2. `SENDING_REQUEST` — serialize and write the HTTP/1.1 request, with header rewriting applied
3. `AWAITING_RESPONSE` — wait for response headers (bounded by `proxy.response_timeout_ms`)
4. `RECEIVING_BODY` — stream the body back to the client
5. `COMPLETE` / `FAILED` — return the connection to the pool or discard it

If the client disconnects mid-request, the framework's async-abort hook calls `ProxyTransaction::Cancel()`, which:

- Sets a `cancelled_` flag guarding every callback entry point
- Signals the pool wait-queue via a shared cancel token so `PoolPartition` can purge the dead entry
- Poisons the upstream connection (`MarkClosing()`) if any bytes have already been written — retrying a partially-sent request on a reused connection is unsafe
- Returns the connection to the pool (or destroys it) without further I/O

### Response timeouts and the async safety cap

`proxy.response_timeout_ms` is the hard deadline for receiving response headers after the request is fully sent. Its valid values are:

- **`>= 1000`** — normal case. The deadline is armed when the request is flushed and cleared when headers arrive. If it fires, the transaction retries (if policy allows) or responds with 504.
- **`0`** — disables the per-request deadline *and* disables the server-wide async safety cap (`max_async_deferred_sec_`) for this request only. The `ProxyHandler` sets `request.async_cap_sec_override = 0` before dispatching. Use this only for intentionally long-polling backends; normal requests should keep a bounded timeout.
- **Other positive values below 1000** — rejected at config load (the 1 s floor matches the timer scan resolution).

Retries are bounded by `proxy.retry.max_retries` and never fire after any response bytes have reached the client. Backoff between attempts is scheduled via the dispatcher's delayed task queue using full jitter (1–250 ms window) — the event loop thread is never blocked. Connection-level retry conditions (connect failure, upstream disconnect) skip backoff on the first retry for stale-keep-alive recovery; response-level conditions (5xx, timeout) always back off. See [docs/configuration.md](configuration.md#proxy-route-configuration) for the full retry matrix.

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

- Route matching runs first (populating `request.params`), then middleware executes in registration order, then the matched handler runs. This means middleware can read route parameters (e.g., `req.params["id"]` for authorization decisions)
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

    // Route parameters populated by HttpRouter during dispatch.
    mutable std::unordered_map<std::string, std::string> params;

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
#include "http/http_status.h"

// Chained builder — use HttpStatus::* constants (see include/http/http_status.h)
HttpResponse().Status(HttpStatus::OK).Header("X-Custom", "value").Json(R"({"ok":true})")

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
| `BadGateway()` | 502 | Upstream unreachable |
| `ServiceUnavailable()` | 503 | Overloaded |
| `GatewayTimeout()` | 504 | Upstream timeout |
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
