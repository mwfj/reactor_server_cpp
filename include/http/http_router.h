#pragma once

#include "http/http_request.h"
#include "http/http_response.h"
#include "http/route_trie.h"
// <string>, <vector>, <functional>, <memory>, <unordered_map> provided by
// common.h (via http_request.h) and route_trie.h

// Forward declaration
class HttpConnectionHandler;
class WebSocketConnection;

class HttpRouter {
public:
    // Handler for HTTP requests
    using Handler = std::function<void(
        const HttpRequest& request,
        HttpResponse& response
    )>;

    // Async handler for HTTP requests. Used when the request handler needs to
    // dispatch async work (e.g. upstream proxy via UpstreamManager::CheckoutAsync)
    // and deliver the response later. The framework skips the automatic
    // post-dispatch send for async handlers — the handler is responsible for
    // calling conn->SendResponse() from its completion callback.
    //
    // The handler receives the HttpConnectionHandler shared_ptr so it can:
    //   1. Call conn->SetShutdownExempt(true) to protect the connection from
    //      the graceful-shutdown close sweep while the async work is pending
    //   2. Capture the shared_ptr into the async completion callback
    //   3. Call conn->SendResponse(final_response) when the reply is ready
    //      (and conn->SetShutdownExempt(false) beforehand)
    using AsyncHandler = std::function<void(
        std::shared_ptr<HttpConnectionHandler> conn,
        const HttpRequest& request
    )>;

    // Middleware -- return true to continue, false to stop
    using Middleware = std::function<bool(
        const HttpRequest& request,
        HttpResponse& response
    )>;

    // WebSocket upgrade handler
    using WsUpgradeHandler = std::function<void(WebSocketConnection& ws)>;

    // Route registration (sync)
    void Get(const std::string& path, Handler handler);
    void Post(const std::string& path, Handler handler);
    void Put(const std::string& path, Handler handler);
    void Delete(const std::string& path, Handler handler);
    void Route(const std::string& method, const std::string& path, Handler handler);

    // Route registration (async). Async routes take precedence over sync
    // routes for the same method+path pair — if both are registered, the
    // async handler is used.
    void RouteAsync(const std::string& method, const std::string& path,
                    AsyncHandler handler);

    // WebSocket route
    void WebSocket(const std::string& path, WsUpgradeHandler handler);

    // Middleware registration (executed in registration order)
    void Use(Middleware middleware);

    // Dispatch request to matching handler.
    // Returns true if route found, false if no match (caller should send 404).
    bool Dispatch(const HttpRequest& request, HttpResponse& response);

    // Async-route lookup. Returns an empty function if no async route matches.
    // Populates request.params with extracted path parameters on match.
    AsyncHandler GetAsyncHandler(const HttpRequest& request) const;

    // Run middleware chain only (for WebSocket upgrades that need auth/CORS/etc.)
    // Returns true if all middleware passed, false if any short-circuited.
    bool RunMiddleware(const HttpRequest& request, HttpResponse& response);

    // WebSocket route lookup
    bool HasWebSocketRoute(const std::string& path) const;

    // WebSocket route lookup with param extraction (populates request.params)
    WsUpgradeHandler GetWebSocketHandler(const HttpRequest& request) const;

private:
    // Per-method route tries (one trie per HTTP method)
    std::unordered_map<std::string, RouteTrie<Handler>> method_tries_;

    // Per-method async route tries — checked before sync tries during dispatch.
    std::unordered_map<std::string, RouteTrie<AsyncHandler>> async_method_tries_;

    // WebSocket route trie
    RouteTrie<WsUpgradeHandler> ws_trie_;

    // Middleware chain (unchanged)
    std::vector<Middleware> middlewares_;
};
