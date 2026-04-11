#include "http/http_router.h"
#include "log/logger.h"
#include "log/log_utils.h"
// <algorithm> provided by common.h (via http_request.h)

// Reduce a route pattern to its structural shape for conflict detection.
// Param/catch-all names AND regex constraints are stripped, so two
// patterns that produce the same key match RouteTrie's insert-time
// equivalence (the trie throws on two params at the same structural
// position regardless of names and constraint regexes).
//
// Used by HasAsyncRouteConflict: the trie throws on different
// constraints at the same param position, so collapsing constraints
// to a single "has param here" marker is CONSERVATIVE (catches more
// as conflict) and keeps proxy multi-method registration atomic —
// the pre-check bails before RouteAsync would throw mid-loop, leaving
// a partial commit.
//
// Examples:
//   "/users/:id"            -> "/users/:"
//   "/users/:user"          -> "/users/:"        (same key -> conflict)
//   "/users/:id([0-9]+)"    -> "/users/:"        (constraint stripped)
//   "/users/:id/a"          -> "/users/:/a"
//   "/users/:name/b"        -> "/users/:/b"      (different tail -> no conflict)
//   "/api/*rest"            -> "/api/*"
//   "/api/*tail"            -> "/api/*"          (same key -> conflict)
static std::string NormalizePatternKey(const std::string& pattern) {
    std::string result;
    result.reserve(pattern.size());
    size_t i = 0;
    while (i < pattern.size()) {
        bool at_seg_start = (i == 0) || (result.back() == '/');
        if (at_seg_start && pattern[i] == ':') {
            result += ':';
            ++i;
            // Skip param name until '/', '(' (constraint), or end
            while (i < pattern.size() && pattern[i] != '/' && pattern[i] != '(') {
                ++i;
            }
            // Skip the entire balanced constraint block if present.
            if (i < pattern.size() && pattern[i] == '(') {
                int depth = 0;
                while (i < pattern.size()) {
                    char c = pattern[i];
                    if (c == '\\' && i + 1 < pattern.size()) {
                        i += 2;
                        continue;
                    }
                    if (c == '(') ++depth;
                    else if (c == ')') --depth;
                    ++i;
                    if (depth == 0) break;
                }
            }
        } else if (at_seg_start && pattern[i] == '*') {
            // Catch-all is always the last segment per trie validator.
            result += '*';
            break;
        } else {
            result += pattern[i];
            ++i;
        }
    }
    return result;
}

// Build a full route fingerprint: strip key + per-param-position
// constraint list. The constraint at each position is the balanced
// "(regex)" block exactly as it appeared in the pattern (including
// the parentheses), or an empty string if the param was unconstrained.
// Catch-all positions always contribute an empty-constraint entry.
//
// Used by HasSyncRouteConflict to detect conflict between a new
// proxy-companion pattern and existing sync routes. Two fingerprints
// with matching strip_keys are DISJOINT iff there exists at least one
// param position where BOTH routes have a constraint AND those
// constraints differ (truly non-overlapping regexes). Otherwise they
// OVERLAP: either they are the exact same pattern (same constraints
// at every position) or one has an unconstrained param where the
// other is constrained (in which case the unconstrained route covers
// the constrained subset and must be flagged as a conflict).
HttpRouter::RouteFingerprint HttpRouter::ExtractFingerprint(const std::string& pattern) {
    RouteFingerprint fp;
    std::string& result = fp.strip_key;
    result.reserve(pattern.size());
    size_t i = 0;
    while (i < pattern.size()) {
        bool at_seg_start = (i == 0) || (result.back() == '/');
        if (at_seg_start && pattern[i] == ':') {
            result += ':';
            ++i;
            // Skip param name
            while (i < pattern.size() && pattern[i] != '/' && pattern[i] != '(') {
                ++i;
            }
            // Capture constraint (if any) at THIS param position.
            if (i < pattern.size() && pattern[i] == '(') {
                std::string constraint;
                int depth = 0;
                while (i < pattern.size()) {
                    char c = pattern[i];
                    if (c == '\\' && i + 1 < pattern.size()) {
                        constraint += c;
                        constraint += pattern[i + 1];
                        i += 2;
                        continue;
                    }
                    if (c == '(') ++depth;
                    else if (c == ')') --depth;
                    constraint += c;
                    ++i;
                    if (depth == 0) break;
                }
                fp.constraints.push_back(std::move(constraint));
            } else {
                fp.constraints.push_back("");  // unconstrained
            }
        } else if (at_seg_start && pattern[i] == '*') {
            // Catch-all — always the last segment. No regex constraint.
            result += '*';
            fp.constraints.push_back("");
            break;
        } else {
            result += pattern[i];
            ++i;
        }
    }
    return fp;
}

void HttpRouter::Get(const std::string& path, Handler handler) {
    Route("GET", path, std::move(handler));
}

void HttpRouter::Post(const std::string& path, Handler handler) {
    Route("POST", path, std::move(handler));
}

void HttpRouter::Put(const std::string& path, Handler handler) {
    Route("PUT", path, std::move(handler));
}

void HttpRouter::Delete(const std::string& path, Handler handler) {
    Route("DELETE", path, std::move(handler));
}

void HttpRouter::Route(const std::string& method, const std::string& path, Handler handler) {
    // Insert into the trie first so any duplicate-pattern exception
    // surfaces before we mirror it into sync_pattern_fingerprints_.
    // If the trie throws, the tracking set stays consistent.
    method_tries_[method].Insert(path, std::move(handler));
    // Record a full fingerprint (strip key + per-position constraint
    // list) so HasSyncRouteConflict can detect constrained-vs-
    // unconstrained overlap in addition to exact structural matches.
    sync_pattern_fingerprints_[method].push_back(ExtractFingerprint(path));
}

void HttpRouter::RouteAsync(const std::string& method, const std::string& path,
                            AsyncHandler handler) {
    // Insert into the trie first so any duplicate-pattern exception
    // surfaces before we mirror it into async_pattern_keys_. If the trie
    // throws, async_pattern_keys_ stays consistent.
    async_method_tries_[method].Insert(path, std::move(handler));
    // async_pattern_keys_ is consulted by HasAsyncRouteConflict, a
    // same-trie pre-check used to make multi-method proxy
    // registration atomic. Use a constraint-STRIPPING key here so
    // different-constraint routes at the same param position are
    // flagged conservatively — the trie throws on them, and we want
    // the pre-check to bail before RouteAsync would throw mid-loop
    // and leave a partial commit.
    async_pattern_keys_[method].insert(NormalizePatternKey(path));
}

bool HttpRouter::HasAsyncRouteConflict(const std::string& method,
                                        const std::string& pattern) const {
    auto it = async_pattern_keys_.find(method);
    if (it == async_pattern_keys_.end()) return false;
    return it->second.count(NormalizePatternKey(pattern)) > 0;
}

bool HttpRouter::HasSyncRouteConflict(const std::string& method,
                                        const std::string& pattern) const {
    auto it = sync_pattern_fingerprints_.find(method);
    if (it == sync_pattern_fingerprints_.end()) return false;
    // Fingerprint-based overlap check. Two routes with matching
    // structural shapes OVERLAP (conflict) unless at least one param
    // position has BOTH constraints set AND they differ. The net
    // effect on the sync-vs-proxy companion scenarios:
    //   - /users/:id([0-9]+) vs /users/:slug([a-z]+) -> disjoint,
    //     no conflict (position 0 has distinct constraints).
    //   - /users/:id([0-9]+) vs /users/:slug        -> CONFLICT
    //     (position 0: one constrained, one unconstrained — the
    //     unconstrained hijacks the constrained subset).
    //   - /users/:id         vs /users/:slug        -> CONFLICT
    //     (same structural shape, neither disambiguates).
    RouteFingerprint new_fp = ExtractFingerprint(pattern);
    for (const auto& existing : it->second) {
        if (existing.strip_key != new_fp.strip_key) continue;
        bool disjoint = false;
        size_t n = std::min(existing.constraints.size(),
                            new_fp.constraints.size());
        for (size_t i = 0; i < n; ++i) {
            if (!existing.constraints[i].empty() &&
                !new_fp.constraints[i].empty() &&
                existing.constraints[i] != new_fp.constraints[i]) {
                disjoint = true;
                break;
            }
        }
        if (!disjoint) return true;
    }
    return false;
}

HttpRouter::AsyncHandler HttpRouter::GetAsyncHandler(
    const HttpRequest& request, bool* head_fallback_out) const {
    if (head_fallback_out) *head_fallback_out = false;

    // 1. Try exact method match in the async trie.
    //    Contract: async routes win over sync routes for the same
    //    method/path. The one narrow exception is HEAD routes that the
    //    proxy registered as DEFAULTS (not via the user's explicit
    //    proxy.methods) — for those, an explicit sync Head() handler on
    //    the same path takes precedence so that catch-all proxies don't
    //    silently shadow user-registered sync HEAD handlers. Checked
    //    per-pattern via proxy_default_head_patterns_ so user-registered
    //    async HEAD routes retain normal async-over-sync precedence.
    auto it = async_method_tries_.find(request.method);
    const AsyncHandler* exact_match_handler = nullptr;
    std::unordered_map<std::string, std::string> exact_match_params;
    std::string exact_match_pattern;
    if (it != async_method_tries_.end()) {
        auto result = it->second.Search(request.path, exact_match_params);
        if (result.handler) {
            exact_match_handler = result.handler;
            exact_match_pattern = result.matched_pattern;
        }
    }

    if (exact_match_handler && request.method == "HEAD" &&
        proxy_default_head_patterns_.count(exact_match_pattern)) {
        // Proxy-default HEAD match. Decide whether to keep this
        // handler or yield so HEAD follows whichever route actually
        // owns GET for this path.
        //
        //  (a) Explicit sync Head() match → always yield.
        //
        //  (b) Proxy does NOT own GET for this pattern (either
        //      because the proxy's GET was filtered out by the
        //      async-conflict pre-check, or because another handler
        //      on a different pattern matches first at request time)
        //      → drop the proxy-default HEAD and fall through to the
        //      async HEAD→GET fallback below. That ensures HEAD is
        //      served by the SAME async handler GET resolves to,
        //      instead of silently routing HEAD to the proxy while
        //      GET goes to a different owner.
        //
        //  (c) Proxy owns GET for this pattern AND the winning async
        //      GET at request time IS that same pattern → keep the
        //      proxy HEAD (GET and HEAD both go to the same route).
        //
        //  (d) No async GET match at request time: sync Head()/
        //      HEAD→GET fallback takes priority if a sync handler
        //      matches; otherwise keep the proxy-default HEAD.
        auto sync_head = method_tries_.find("HEAD");
        if (sync_head != method_tries_.end() &&
            sync_head->second.HasMatch(request.path)) {
            return nullptr;  // explicit sync HEAD always wins
        }

        // Probe the async GET trie to find the actual winning pattern
        // for this path (not just "some pattern matches").
        bool async_get_matches = false;
        std::string async_get_pattern;
        auto async_get_it = async_method_tries_.find("GET");
        if (async_get_it != async_method_tries_.end()) {
            std::unordered_map<std::string, std::string> tmp;
            auto async_get_result =
                async_get_it->second.Search(request.path, tmp);
            if (async_get_result.handler) {
                async_get_matches = true;
                async_get_pattern = async_get_result.matched_pattern;
            }
        }

        if (async_get_matches) {
            // HEAD should follow GET's OWNER. Two conditions must hold
            // to keep the proxy HEAD:
            //   1. The proxy owns GET for this exact pattern (so GET
            //      and HEAD are both implemented by the proxy).
            //   2. The winning async GET at request time IS the same
            //      pattern (so a broader async GET catch-all that
            //      overlaps with this proxy's HEAD pattern doesn't
            //      steal GET while HEAD stays on the proxy).
            // If either condition fails, drop the proxy HEAD and let
            // the async HEAD→GET fallback route HEAD through the same
            // handler GET resolves to.
            bool proxy_owns_get =
                proxy_owned_get_patterns_.count(exact_match_pattern) > 0;
            if (!proxy_owns_get ||
                async_get_pattern != exact_match_pattern) {
                exact_match_handler = nullptr;
            }
            // else: proxy owns BOTH on this pattern and it's also the
            // runtime winner — keep exact_match_handler.
        } else {
            // No async GET match. Sync HEAD→GET fallback owns the
            // path if a sync GET matches; yield in that case.
            auto sync_get = method_tries_.find("GET");
            if (sync_get != method_tries_.end() &&
                sync_get->second.HasMatch(request.path)) {
                return nullptr;  // sync HEAD→GET fallback owns this path
            }
            // No sync GET either — keep exact_match_handler (proxy
            // HEAD is the only thing that would serve this path).
        }
    }

    if (exact_match_handler) {
        request.params = std::move(exact_match_params);
        return *exact_match_handler;
    }
    // Path miss (or proxy-default HEAD deliberately dropped above) —
    // fall through to HEAD→GET fallback below.

    // 2. HEAD fallback to async GET (mirrors sync Dispatch behavior).
    //    Only attempt if the exact async HEAD search above failed OR the
    //    path didn't match — this handles the case where an unrelated async
    //    HEAD route exists (e.g. /health) but the requested path (e.g.
    //    /items) is only registered via GetAsync.
    //
    //    Before falling back to async GET, yield to an explicit sync
    //    Head() handler on the same path. Otherwise, a path with
    //    Head(path, sync) + GetAsync(path, async) would dispatch HEAD
    //    through the async GET route (invisible to the sync HEAD
    //    handler) — and for proxied async GETs it would turn a cheap
    //    HEAD into a full forwarded GET.
    //
    //    Skip the async fallback when the matched GET pattern opted
    //    out via DisableHeadFallback() (currently used by proxy routes
    //    whose proxy.methods explicitly exclude HEAD). Without this,
    //    the method filter would be silently bypassed for HEAD requests.
    if (request.method == "HEAD") {
        // Explicit sync HEAD wins over async GET fallback.
        auto sync_head_it = method_tries_.find("HEAD");
        if (sync_head_it != method_tries_.end() &&
            sync_head_it->second.HasMatch(request.path)) {
            return nullptr;  // let sync Dispatch handle the explicit HEAD
        }
        auto get_it = async_method_tries_.find("GET");
        if (get_it != async_method_tries_.end()) {
            std::unordered_map<std::string, std::string> params;
            auto result = get_it->second.Search(request.path, params);
            if (result.handler) {
                if (head_fallback_blocked_.count(result.matched_pattern)) {
                    // Pattern opted out of HEAD fallback — let sync
                    // Dispatch produce a 405 via its allowed-method scan.
                    return nullptr;
                }
                request.params = std::move(params);
                if (head_fallback_out) *head_fallback_out = true;
                return *result.handler;
            }
        }
    }

    return nullptr;
}

void HttpRouter::DisableHeadFallback(const std::string& pattern) {
    head_fallback_blocked_.insert(pattern);
}

void HttpRouter::MarkProxyDefaultHead(const std::string& pattern) {
    proxy_default_head_patterns_.insert(pattern);
}

void HttpRouter::MarkProxyOwnedGet(const std::string& pattern) {
    proxy_owned_get_patterns_.insert(pattern);
}

void HttpRouter::WebSocket(const std::string& path, WsUpgradeHandler handler) {
    ws_trie_.Insert(path, std::move(handler));
}

void HttpRouter::Use(Middleware middleware) {
    middlewares_.push_back(std::move(middleware));
}

bool HttpRouter::Dispatch(const HttpRequest& request, HttpResponse& response) {
    // Clear params from any previous dispatch on this request object.
    request.params.clear();

    // Search for a matching route BEFORE running middleware, so that
    // request.params is populated during middleware execution. This allows
    // middleware to authorize or rate-limit based on route parameters
    // (e.g., /users/:id → middleware reads request.params["id"]).
    const Handler* matched_handler = nullptr;
    std::string matched_pattern;
    bool head_fallback = false;

    auto it = method_tries_.find(request.method);
    if (it != method_tries_.end()) {
        std::unordered_map<std::string, std::string> params;
        auto result = it->second.Search(request.path, params);
        if (result.handler) {
            request.params = std::move(params);
            matched_handler = result.handler;
            matched_pattern = std::move(result.matched_pattern);
        }
    }

    // HEAD fallback to GET (RFC 7231 §4.3.2).
    // Skip the fallback if an async GET route matching the same path
    // has opted out via DisableHeadFallback() — i.e. a proxy explicitly
    // excluded HEAD from its methods. Without this check, a sync GET on
    // the same path would still answer HEAD via fallback, silently
    // bypassing the user's proxy.methods filter in the overlap case the
    // async-side guard is meant to protect.
    if (!matched_handler && request.method == "HEAD") {
        bool head_blocked_by_async = false;
        auto async_get_it = async_method_tries_.find("GET");
        if (async_get_it != async_method_tries_.end()) {
            std::unordered_map<std::string, std::string> tmp;
            auto async_result = async_get_it->second.Search(request.path, tmp);
            if (async_result.handler &&
                head_fallback_blocked_.count(async_result.matched_pattern)) {
                head_blocked_by_async = true;
            }
        }
        if (!head_blocked_by_async) {
            auto get_it = method_tries_.find("GET");
            if (get_it != method_tries_.end()) {
                std::unordered_map<std::string, std::string> params;
                auto result = get_it->second.Search(request.path, params);
                if (result.handler) {
                    request.params = std::move(params);
                    matched_handler = result.handler;
                    matched_pattern = std::move(result.matched_pattern);
                    head_fallback = true;
                }
            }
        }
    }

    // Run middleware chain — params are already populated for matched routes.
    for (const auto& mw : middlewares_) {
        if (!mw(request, response)) {
            FillDefaultRejectionResponse(response);
            logging::Get()->debug("Middleware rejected request: {} {}",
                                  request.method, logging::SanitizePath(request.path));
            return true;
        }
    }

    // Dispatch to matched handler
    if (matched_handler) {
        logging::Get()->debug("Route matched: {} {} -> pattern {}",
                              request.method, logging::SanitizePath(request.path),
                              matched_pattern);
        if (head_fallback) {
            // HEAD fallback: clone with method="GET" so handlers see "GET"
            // (body stripping happens in HttpConnectionHandler)
            HttpRequest get_req = request;
            get_req.method = "GET";
            (*matched_handler)(get_req, response);
        } else {
            (*matched_handler)(request, response);
        }
        return true;
    }

    // Check if path exists with different method (405 vs 404). Must consult
    // BOTH the sync and async trees — a path registered exclusively via
    // PostAsync would otherwise return 404 for a mismatched GET instead of
    // advertising the allowed POST.
    std::vector<std::string> allowed_methods;
    bool has_get = false;
    bool has_head = false;
    auto record = [&](const std::string& method) {
        if (method == request.method) return;
        if (std::find(allowed_methods.begin(), allowed_methods.end(), method)
                != allowed_methods.end()) return;
        allowed_methods.push_back(method);
        if (method == "GET") has_get = true;
        if (method == "HEAD") has_head = true;
    };
    for (const auto& [method, trie] : method_tries_) {
        if (method == request.method) continue;
        if (trie.HasMatch(request.path)) record(method);
    }
    for (const auto& [method, trie] : async_method_tries_) {
        if (method == request.method) continue;
        if (trie.HasMatch(request.path)) record(method);
    }
    // Infer HEAD from GET (RFC 7231 §4.3.2) only when HEAD→GET fallback
    // would actually succeed for this path:
    //   - Sync GET: HEAD fallback is unconditional (see line 125).
    //   - Async GET: only when the matched pattern is NOT in
    //     head_fallback_blocked_ (proxies with GET but no HEAD opt out
    //     via DisableHeadFallback). Advertising HEAD when it's blocked
    //     would tell clients a method is allowed that actually returns
    //     405, creating inconsistent method discovery.
    if (has_get && !has_head) {
        // First, check whether the async GET route for this path is
        // in head_fallback_blocked_ (proxy with GET but no HEAD). If
        // it is, BOTH the async HEAD→GET and sync HEAD→GET fallbacks
        // are suppressed for this path — so an actual HEAD request
        // will return 405. Don't advertise HEAD in the Allow header
        // in that case, even if a sync GET otherwise matches. The
        // goal is Allow-header/dispatch consistency: we only claim a
        // method is allowed if the dispatch path will actually serve
        // it.
        bool async_get_blocks_head = false;
        bool async_get_matches = false;
        auto async_get_it = async_method_tries_.find("GET");
        if (async_get_it != async_method_tries_.end()) {
            std::unordered_map<std::string, std::string> dummy_params;
            auto result = async_get_it->second.Search(
                request.path, dummy_params);
            if (result.handler) {
                async_get_matches = true;
                if (head_fallback_blocked_.count(result.matched_pattern)) {
                    async_get_blocks_head = true;
                }
            }
        }

        if (!async_get_blocks_head) {
            bool head_would_succeed = false;
            auto sync_get_it = method_tries_.find("GET");
            if (sync_get_it != method_tries_.end() &&
                sync_get_it->second.HasMatch(request.path)) {
                head_would_succeed = true;
            }
            if (!head_would_succeed && async_get_matches) {
                // async GET matched above and is not blocked — the
                // async HEAD→GET fallback would serve it.
                head_would_succeed = true;
            }
            if (head_would_succeed) {
                record("HEAD");
            }
        }
    }
    if (!allowed_methods.empty()) {
        std::sort(allowed_methods.begin(), allowed_methods.end());
        std::string allowed;
        for (const auto& m : allowed_methods) {
            if (!allowed.empty()) allowed += ", ";
            allowed += m;
        }
        logging::Get()->debug("Method not allowed: {} {}",
                              request.method, logging::SanitizePath(request.path));
        // Set status on the existing response to preserve any headers that
        // middleware already added (CORS, request-id, auth tokens, etc.).
        response.Status(405).Text("Method Not Allowed");
        response.Header("Allow", allowed);
        return true;
    }

    logging::Get()->debug("No route found: {} {}",
                          request.method, logging::SanitizePath(request.path));
    return false;
}

bool HttpRouter::RunMiddleware(const HttpRequest& request, HttpResponse& response) {
    for (const auto& mw : middlewares_) {
        if (!mw(request, response)) {
            return false;
        }
    }
    return true;
}

void HttpRouter::FillDefaultRejectionResponse(HttpResponse& response) {
    // Upgrade to 403 when middleware rejected (returned false) but left
    // the status code unchanged from the HttpResponse default (200). The
    // headers check used to be part of this guard, but middleware that
    // legitimately adds CORS / request-id / auth headers before rejecting
    // would then leave a 200 status on what is supposed to be a failure
    // response, and the client would silently succeed. We keep the empty-
    // body check so a middleware that explicitly populated a 200-status
    // body (unusual but well-defined) is still preserved.
    if (response.GetStatusCode() == 200 && response.GetBody().empty()) {
        response.Status(403).Text("Forbidden");
    }
}

bool HttpRouter::HasWebSocketRoute(const std::string& path) const {
    return ws_trie_.HasMatch(path);
}

HttpRouter::WsUpgradeHandler HttpRouter::GetWebSocketHandler(const HttpRequest& request) const {
    request.params.clear();
    std::unordered_map<std::string, std::string> params;
    auto result = ws_trie_.Search(request.path, params);
    if (result.handler) {
        request.params = std::move(params);
        return *result.handler;
    }
    return nullptr;
}
