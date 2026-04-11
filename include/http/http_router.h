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

    // Mark an async HEAD route as "installed by proxy defaults" so a
    // user-registered sync Head() handler on the same path wins. The
    // router's normal contract is async-over-sync for the same
    // method/path; this marker carves out a narrow exception ONLY for
    // proxy routes that got HEAD via default_methods (not via the
    // user's explicit proxy.methods list), so that an explicit sync
    // Head() handler isn't silently shadowed by a catch-all proxy
    // default. Patterns registered here are consulted in
    // GetAsyncHandler() — see the HEAD-handling branch.
    void MarkProxyDefaultHead(const std::string& pattern);

    // Mark a pattern as having its async GET method owned by a proxy
    // handler (i.e. the proxy successfully registered GET for this
    // pattern during its registration pass). Used by GetAsyncHandler's
    // HEAD precedence logic so HEAD follows the **owner** of GET, not
    // just "some route with the same pattern string." When a proxy
    // registers HEAD by default but its GET gets filtered out by the
    // conflict check (because an earlier async GET for the same path
    // already exists), the proxy's HEAD is kept in
    // proxy_default_head_patterns_ but NOT in this set — so the HEAD
    // lookup can detect that and yield to the async GET owner.
    void MarkProxyOwnedGet(const std::string& pattern);

    // Check whether an async route for the given method+pattern would
    // conflict with an already-registered async route on the same trie.
    // This is a SEMANTIC conflict check, not a literal string match:
    // /users/:id and /users/:user map to the same key because RouteTrie
    // rejects both at the same PARAM leaf. Used by proxy registration
    // to pre-validate all (method, pattern) combinations so a
    // multi-method insert can bail atomically before any RouteAsync
    // call mutates the trie — avoiding partial-commit state where some
    // methods are live in the router but bookkeeping is skipped.
    bool HasAsyncRouteConflict(const std::string& method,
                                const std::string& pattern) const;

    // Check whether a registered SYNC route would conflict with the
    // given method+pattern. This is a PATTERN-level (semantic) check,
    // not a literal-path match: it uses the same normalization as
    // HasAsyncRouteConflict, so /api/:id and /api/:user map to the same
    // key, and /api/:id([0-9]+) is caught even though the literal string
    // "/api/:id([0-9]+)" is not itself a request path. Used by proxy
    // registration to prevent a derived bare-prefix companion from
    // silently hijacking a pre-existing sync handler via async-over-sync
    // dispatch precedence.
    bool HasSyncRouteConflict(const std::string& method,
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

    // Async HEAD patterns installed by proxy defaults (user did not
    // explicitly include HEAD in proxy.methods). For these specific
    // patterns, an explicit sync Head() handler on the same path takes
    // precedence over the async default — elsewhere the normal
    // async-over-sync contract is preserved.
    std::unordered_set<std::string> proxy_default_head_patterns_;

    // Async GET patterns that are actually owned by a proxy handler.
    // Populated whenever a proxy's GET registration succeeds (i.e. the
    // method-level conflict pre-check did not filter it out). Used by
    // GetAsyncHandler's proxy-default HEAD precedence logic to decide
    // whether the proxy also owns GET for a matched HEAD pattern: if
    // not, the HEAD match is dropped so HEAD follows the async GET
    // OWNER rather than just "whatever matches the same pattern string."
    std::unordered_set<std::string> proxy_owned_get_patterns_;

    // Normalized-pattern keys for async routes, tracked per method.
    // Each registered pattern is reduced to a "semantic shape" key
    // (param/catch-all names and regex constraints stripped) that
    // matches the equivalence relation RouteTrie uses for conflict
    // detection. Pre-checked by HasAsyncRouteConflict() so a multi-
    // method proxy insert can bail atomically on any conflict — whether
    // the collision is a literal string duplicate OR a semantically
    // equivalent pattern like /users/:id vs /users/:user.
    std::unordered_map<std::string, std::unordered_set<std::string>>
        async_pattern_keys_;

    // SYNC route fingerprints, tracked per method. Each registered
    // sync route is reduced to a structural shape (strip key, without
    // param names or constraints) plus a per-param-position list of
    // constraint strings (empty string = unconstrained). Used by
    // HasSyncRouteConflict() to detect whether a new proxy companion
    // pattern would hijack or be hijacked by an existing sync route.
    //
    // This is richer than a single normalized-string key because the
    // conflict rule is asymmetric:
    //   - /users/:id([0-9]+) vs /users/:slug([a-z]+)  → disjoint (no conflict)
    //   - /users/:id([0-9]+) vs /users/:slug          → CONFLICT (unconstrained
    //                                                  hijacks the constrained one)
    //   - /users/:id         vs /users/:slug          → CONFLICT (same shape,
    //                                                  both unconstrained)
    // Two shape-matching routes are disjoint iff at least one param
    // position has BOTH constrained AND their constraint strings
    // differ. Everything else overlaps and counts as a conflict.
    struct RouteFingerprint {
        std::string strip_key;              // structural shape (no names/constraints)
        // One entry per PARAM/CATCH_ALL position in pattern order.
        // Empty string = no constraint (matches anything at that
        // position). Catch-all positions always have empty constraints.
        std::vector<std::string> constraints;
    };
    // Extract a full route fingerprint from a pattern. Implementation
    // in http_router.cc — private static so HasSyncRouteConflict can
    // access RouteFingerprint without exposing the type publicly.
    static RouteFingerprint ExtractFingerprint(const std::string& pattern);

    std::unordered_map<std::string, std::vector<RouteFingerprint>>
        sync_pattern_fingerprints_;
};
