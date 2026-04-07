#pragma once

#include "common.h"
// <functional>, <memory>, <string>, <cstdint> provided by common.h

// Forward declarations
class HttpConnectionHandler;
class ConnectionHandler;
class WebSocketConnection;
struct HttpRequest;
class HttpResponse;

namespace HTTP_CALLBACKS_NAMESPACE {

    // ---- HttpConnectionHandler callbacks ------------------------------------
    using HttpConnRequestCallback = std::function<void(
        std::shared_ptr<HttpConnectionHandler> self,
        const HttpRequest& request,
        HttpResponse& response
    )>;
    using HttpConnRouteCheckCallback = std::function<bool(const HttpRequest& request)>;
    using HttpConnMiddlewareCallback = std::function<bool(
        const HttpRequest& request,
        HttpResponse& response
    )>;
    using HttpConnUpgradeCallback = std::function<void(
        std::shared_ptr<HttpConnectionHandler> self,
        const HttpRequest& request
    )>;

    // Fires for every completed HTTP parse (dispatched, rejected, or upgraded).
    // Used by HttpServer to count all requests, not just successfully dispatched ones.
    using HttpConnRequestCountCallback = std::function<void()>;

    // Returns true if the server is shutting down. Used as a late gate
    // in WS upgrade to prevent upgrades that slipped past the early check.
    using HttpConnShutdownCheckCallback = std::function<bool()>;

    struct HttpConnCallbacks {
        HttpConnRequestCallback       request_callback       = nullptr;
        HttpConnRouteCheckCallback    route_check_callback    = nullptr;
        HttpConnMiddlewareCallback    middleware_callback     = nullptr;
        HttpConnUpgradeCallback       upgrade_callback       = nullptr;
        HttpConnRequestCountCallback  request_count_callback  = nullptr;
        HttpConnShutdownCheckCallback shutdown_check_callback = nullptr;
    };

    // ---- HttpRouter async callbacks -------------------------------------------

    // Completion callback handed to async handlers. When invoked it delivers
    // the final HttpResponse to the client. Protocol-agnostic — the framework
    // binds protocol-specific plumbing (HTTP/1 client transport or HTTP/2
    // stream submission) at dispatch time so the user handler is the same
    // regardless of whether the request arrived over H1 or H2.
    //
    // Thread safety: the completion callback MUST be invoked on the
    // dispatcher thread that owns the request's connection. Async work
    // (e.g. upstream pool CheckoutAsync) naturally routes callbacks back
    // to that dispatcher. If your async work runs elsewhere, route the
    // completion via EnQueue.
    using AsyncCompletionCallback = std::function<void(HttpResponse)>;

    // Async handler for HTTP requests. Used when the request handler needs to
    // dispatch async work (e.g. upstream proxy via UpstreamManager::CheckoutAsync)
    // and deliver the response later. The handler receives the request plus
    // a completion callback and is responsible for invoking `complete(resp)`
    // exactly once. The framework:
    //   - Runs middleware before invoking the async handler (auth, CORS, etc.)
    //   - Blocks the HTTP/1 parser from accepting new requests until the
    //     completion fires, preserving response ordering on keep-alive
    //   - Marks the connection as shutdown-exempt while the async work is
    //     pending so graceful shutdown waits for the reply
    //   - Applies Connection: close / keep-alive / HEAD body-stripping to
    //     the completion response using the original request's metadata
    using AsyncHandler = std::function<void(
        const HttpRequest& request,
        AsyncCompletionCallback complete
    )>;

    // ---- WebSocketConnection callbacks --------------------------------------
    using WsMessageCallback = std::function<void(
        WebSocketConnection& ws, const std::string& message, bool is_binary
    )>;
    using WsCloseCallback = std::function<void(
        WebSocketConnection& ws, uint16_t code, const std::string& reason
    )>;
    using WsPingCallback = std::function<void(
        WebSocketConnection& ws, const std::string& payload
    )>;
    using WsErrorCallback = std::function<void(
        WebSocketConnection& ws, const std::string& error
    )>;

    struct WsCallbacks {
        WsMessageCallback message_callback = nullptr;
        WsCloseCallback   close_callback   = nullptr;
        WsPingCallback    ping_callback    = nullptr;
        WsErrorCallback   error_callback   = nullptr;
    };

} // namespace HTTP_CALLBACKS_NAMESPACE
