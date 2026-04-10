#pragma once

#include "http/http_request.h"
#include "http/http_response.h"
#include "http/http_callbacks.h"
#include "http/route_trie.h"
#include <unordered_set>
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

    // Async callback types — defined in http_callbacks.h for centralization,
    // aliased here for backward compatibility with existing call sites.
    using AsyncCompletionCallback = HTTP_CALLBACKS_NAMESPACE::AsyncCompletionCallback;
    using AsyncHandler = HTTP_CALLBACKS_NAMESPACE::AsyncHandler;

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

    // Disable the async HEAD→GET fallback for a specific registered
    // pattern. Used by proxy routes that explicitly exclude HEAD from
    // the accepted method list — without this, GetAsyncHandler would
    // route HEAD requests through the matching async GET route, which
    // bypasses the user's method filter.
    void DisableHeadFallback(const std::string& pattern);

    // Check whether an async route for the given method+pattern is
    // already registered. Used by proxy registration to pre-validate all
    // (method, pattern) combinations in a batch so a multi-method insert
    // can bail atomically before any RouteAsync call mutates the trie —
    // avoiding partial-commit state where some methods are live in the
    // router but bookkeeping is skipped.
    bool HasAsyncRoute(const std::string& method,
                       const std::string& pattern) const;

private:
    // Per-method route tries (one trie per HTTP method)
    std::unordered_map<std::string, RouteTrie<Handler>> method_tries_;

    // Per-method async route tries — checked before sync tries during dispatch.
    std::unordered_map<std::string, RouteTrie<AsyncHandler>> async_method_tries_;

    // WebSocket route trie
    RouteTrie<WsUpgradeHandler> ws_trie_;

    // Middleware chain (unchanged)
    std::vector<Middleware> middlewares_;

    // Async GET patterns that opt out of HEAD→GET fallback. Populated via
    // DisableHeadFallback() — currently only by proxy routes whose
    // proxy.methods explicitly exclude HEAD.
    std::unordered_set<std::string> head_fallback_blocked_;

    // Literal async patterns registered per method. Mirrors
    // async_method_tries_ at the "exact pattern" level so callers can
    // pre-check whether RouteAsync would throw on a duplicate without
    // actually attempting the insert. Populated in RouteAsync.
    std::unordered_map<std::string, std::unordered_set<std::string>>
        async_patterns_;
};
