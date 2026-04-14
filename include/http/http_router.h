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
    using InterimResponseSender   = HTTP_CALLBACKS_NAMESPACE::InterimResponseSender;
    using ResourcePusher          = HTTP_CALLBACKS_NAMESPACE::ResourcePusher;
    using AsyncHandler            = HTTP_CALLBACKS_NAMESPACE::AsyncHandler;

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

    // Prepend middleware at the front of the chain (runs before Use()-registered middleware).
    // Used by HttpServer to ensure rate limiting runs first.
    void PrependMiddleware(Middleware middleware);

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
    // default.
    //
    // `paired_with_get` is set to true when the SAME proxy registration
    // that inserted this HEAD also successfully registered GET on the
    // same pattern. It is used by GetAsyncHandler's HEAD precedence
    // logic to decide whether keeping the proxy HEAD is safe: safe
    // only if the same proxy owns both GET and HEAD on this pattern,
    // because only then is HEAD guaranteed to be served by the same
    // handler GET would route through. When paired_with_get is false
    // (e.g. the proxy's GET was skipped by the async-conflict filter
    // because an EARLIER proxy already owned GET on this pattern),
    // the HEAD precedence drops the proxy HEAD and falls through to
    // the async HEAD→GET fallback, which dispatches HEAD through the
    // actual GET owner.
    //
    // Tracking paired_with_get per REGISTRATION (not by "does any
    // proxy own GET for this pattern") is required because multiple
    // proxies can share a pattern with only partial method overlap,
    // and the global "some proxy owns GET" view conflates registrations.
    void MarkProxyDefaultHead(const std::string& pattern, bool paired_with_get);

    // Mark a pattern as a proxy's derived bare-prefix companion for
    // a SPECIFIC METHOD. These patterns are registered to catch
    // requests that the corresponding catch-all pattern (/api/*rest)
    // would miss (e.g. /api with no trailing slash). Because
    // async-over-sync precedence means a catch-all async companion
    // would otherwise silently shadow an existing sync route with an
    // overlapping regex constraint, GetAsyncHandler YIELDS to a
    // matching sync route at runtime when the matched async pattern
    // is a companion for that method.
    //
    // Keying by (method, pattern) — not just pattern — is required
    // because a later async registration (e.g. RouteAsync("POST",
    // "/api", ...)) on the SAME pattern MUST NOT inherit the
    // yield-to-sync behavior: the new POST route is not a companion,
    // and yielding to a sync POST /api would incorrectly drop a
    // first-class async registration. Only the methods the proxy
    // actually registered on the companion pattern should yield.
    //
    // The runtime yield replaces the pre-check that used to drop
    // companions whenever any same-shape sync route existed. The
    // pre-check was unsafe in both directions:
    //   - Too permissive (textual regex inequality ≠ disjointness)
    //     → hijack.
    //   - Too conservative (collapse to strip key) → 404 for
    //     disjoint-regex companions that should have served the
    //     request. Runtime yield resolves per-request: sync wins
    //     when its regex matches THIS path, proxy companion wins
    //     otherwise.
    void MarkProxyCompanion(const std::string& method,
                             const std::string& pattern);

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

    // Async HEAD patterns installed by proxy defaults. The value is
    // `true` when the SAME proxy registration that inserted this HEAD
    // also successfully registered GET on the pattern — i.e. keeping
    // the proxy HEAD at dispatch time is safe because GET and HEAD
    // are owned by the same registration. When `false`, the proxy's
    // GET was filtered out (typically because an earlier proxy or
    // user route already owns GET on this pattern), so HEAD must
    // YIELD at dispatch time and fall through to the HEAD→GET
    // fallback that routes through the actual GET owner.
    //
    // Tracking this per REGISTRATION is required because two proxies
    // can share a pattern with only partial method overlap; a global
    // "does any proxy own GET for this pattern" check conflates them
    // and causes HEAD to stick on a proxy that does NOT own GET. See
    // MarkProxyDefaultHead for the full rationale.
    std::unordered_map<std::string, bool> proxy_default_head_patterns_;

    // Proxy derived bare-prefix companion markers, keyed by method.
    // `proxy_companion_patterns_[method]` is the set of patterns this
    // method treats as a companion. GetAsyncHandler checks the
    // (request.method, matched_pattern) pair — not just the pattern —
    // so an unrelated first-class async route later registered on the
    // same pattern with a different method (e.g. POST /api while
    // /api is only a GET companion) does NOT inherit the yield-to-sync
    // behavior. See MarkProxyCompanion for the full rationale.
    std::unordered_map<std::string, std::unordered_set<std::string>>
        proxy_companion_patterns_;

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

    // SYNC route structural keys, tracked per method. Used by
    // HasSyncRouteConflict() to detect whether a new proxy companion
    // pattern would hijack or be hijacked by an existing sync route.
    //
    // CONSERVATIVE rule: two routes with matching structural shape
    // (strip_key, i.e. param/catch-all names and regex constraints
    // stripped) are treated as CONFLICTING regardless of whether their
    // regex constraints are syntactically identical. Textual regex
    // inequality does NOT prove non-overlap — e.g. `\d+` and
    // `[0-9]{1,3}` both match "123". Regex-intersection emptiness is
    // undecidable in general, so we must assume overlap whenever the
    // shapes match. See HasSyncRouteConflict for the full rationale.
    std::unordered_map<std::string, std::unordered_set<std::string>>
        sync_pattern_keys_;
};
