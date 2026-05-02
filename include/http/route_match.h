#pragma once

// RouteMatch — the resolved route's identity, attached to HttpRequest
// before middleware runs. Read by observability middleware (per-route
// sampling, http.route metric label) and by the dispatch site (which
// branches on `kind` to pick the right handler shape).
//
// Header is intentionally minimal: <cstdint>, <string> only — no project
// includes — so it can be #included from both http_request.h AND
// http_router.h without creating an include cycle. <cstdint> is required
// for `uint8_t` (the RouteKind underlying type); omitting it causes a
// libstdc++/libc++ compile error on the enum declaration.

#include <cstdint>
#include <string>

// Dispatch-path tag set by the resolver (HttpRouter::ResolveRouteMatch).
// The resolver sets `RouteMatch::kind` on the first precedence-chain hit;
// the dispatch site then switches on this value to pick the handler shape.
enum class RouteKind : uint8_t {
    None      = 0,  // No route matched, or pre-resolution default.
    Sync      = 1,  // HttpRouter::Handler at this path.
    Async     = 2,  // HttpRouter::AsyncHandler, NOT proxy-installed.
    Proxy     = 3,  // HttpRouter::AsyncHandler installed via
                    // HttpServer::Proxy / RegisterProxyRoutes.
    WsUpgrade = 4,  // HttpRouter::WsUpgradeHandler — RFC 6455 upgrade.
    Shutdown  = 5,  // HttpServer::ShutdownRoute (reserved; not yet wired).
};

struct RouteMatch {
    // Owned strings — async finalization can outlive the source request,
    // so we cannot use string_view that borrows from RouteTrie nodes.
    std::string pattern;              // The matched pattern (e.g. "/api/v1/*rest").
    std::string method_for_dispatch;  // Method the handler was selected under
                                      // (HEAD-fallback may set this to "GET").

    // Authoritative dispatch-path tag.
    RouteKind kind = RouteKind::None;

    // Legacy boolean markers — kept for backward-compat with existing
    // readers (route trie, header rewriter). The resolver sets BOTH
    // `kind` AND the matching legacy flag; new readers should prefer
    // `kind` as the single source of truth.
    bool head_fallback = false;
    bool is_websocket  = false;
    bool is_proxy      = false;
};
