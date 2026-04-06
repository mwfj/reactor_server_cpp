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
    // When `head_fallback_out` is non-null, it is set to true iff the match
    // came via the HEAD → GET fallback path — the caller must rewrite the
    // request method to "GET" before invoking the handler (mirroring sync
    // Dispatch), otherwise the user's handler sees "HEAD" but the framework
    // applies GET-style response normalization + body stripping, which
    // diverges between sync and async routes.
    AsyncHandler GetAsyncHandler(const HttpRequest& request,
                                 bool* head_fallback_out = nullptr) const;

    // Run middleware chain only (for WebSocket upgrades that need auth/CORS/etc.)
    // Returns true if all middleware passed, false if any short-circuited.
    bool RunMiddleware(const HttpRequest& request, HttpResponse& response);

    // Ensure a middleware-rejected response carries a meaningful payload:
    // if middleware returned false but left the response untouched, fill
    // it with 403 Forbidden. Called from all middleware-rejection sites
    // (sync Dispatch, async H1 dispatch, async H2 dispatch) so the default
    // is consistent.
    static void FillDefaultRejectionResponse(HttpResponse& response);

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
