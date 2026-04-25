#include "http/http_router.h"
#include "http/http_status.h"
#include "log/logger.h"
#include "log/log_utils.h"
// <algorithm> provided by common.h (via http_request.h)

// AsyncPendingState invariants:
//   - resume_cb_ fires exactly once, always OUTSIDE mu_.
//   - active_counter_ is decremented exactly once via bookkeeping_done_
//     (TripCancel and DecrementOnce share the exchange).
//   - cancel_cb_ fires exactly once when TripCancel wins the exchange
//     (move-and-clear, exception-safe).

void AsyncPendingState::Complete(AsyncMiddlewarePayload payload) {
    std::function<void(AsyncMiddlewarePayload)> cb_to_fire;
    AsyncMiddlewarePayload payload_to_fire;
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (completed_) return;            // one-shot
        completed_ = true;
        if (resume_armed_) {
            cb_to_fire = resume_cb_;       // copy under lock
            payload_to_fire = std::move(payload);
        } else {
            result_slot_ = std::move(payload);
            completion_pending_ = true;
        }
    }
    if (cb_to_fire) {
        cb_to_fire(std::move(payload_to_fire));
    }
}

void AsyncPendingState::ArmResume(
    std::function<void(AsyncMiddlewarePayload)> resume_cb,
    std::shared_ptr<std::atomic<int64_t>> active_counter) {
    std::function<void(AsyncMiddlewarePayload)> cb_to_fire;
    AsyncMiddlewarePayload payload_to_fire;
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (resume_armed_) return;         // one-shot
        resume_cb_ = std::move(resume_cb);
        active_counter_ = std::move(active_counter);
        resume_armed_ = true;
        if (completion_pending_) {
            cb_to_fire = resume_cb_;       // copy under lock
            payload_to_fire = std::move(result_slot_);
            completion_pending_ = false;
        }
    }
    if (cb_to_fire) {
        cb_to_fire(std::move(payload_to_fire));
    }
}

void AsyncPendingState::TripCancel() {
    if (bookkeeping_done_.exchange(true, std::memory_order_acq_rel)) return;

    // Decrement under mu_ so the read of active_counter_ is synchronized
    // with the unlock that ended ArmResume's critical section. On the
    // pre-ArmResume path active_counter_ is null — skip the fetch_sub
    // (the original stack RequestGuard is still armed and will fire on
    // scope exit).
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (active_counter_) {
            active_counter_->fetch_sub(1, std::memory_order_relaxed);
        }
    }
    cancelled_.store(true, std::memory_order_release);

    // Fire cancel_cb_ exactly once — move out under the lock first so a
    // throwing cancel hook cannot be re-entered.
    std::function<void()> local;
    {
        std::lock_guard<std::mutex> lk(mu_);
        local = std::move(cancel_cb_);
    }
    if (local) {
        try { local(); }
        catch (const std::exception& e) {
            logging::Get()->error("Async cancel hook threw: {}", e.what());
        }
    }
}

void AsyncPendingState::DecrementOnce() {
    if (bookkeeping_done_.exchange(true, std::memory_order_acq_rel)) return;
    std::shared_ptr<std::atomic<int64_t>> counter;
    {
        std::lock_guard<std::mutex> lk(mu_);
        counter = active_counter_;
    }
    if (counter) {
        counter->fetch_sub(1, std::memory_order_relaxed);
    }
}

void AsyncPendingState::SetCancelCb(std::function<void()> cb) {
    std::lock_guard<std::mutex> lk(mu_);
    cancel_cb_ = std::move(cb);
}

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
    // surfaces before we mirror it into sync_pattern_keys_. If the trie
    // throws, the tracking set stays consistent.
    method_tries_[method].Insert(path, std::move(handler));
    // Record the structural shape (strip key — param/catch-all names
    // and regex constraints stripped) so HasSyncRouteConflict can
    // conservatively flag any same-shape route as a conflict.
    sync_pattern_keys_[method].insert(NormalizePatternKey(path));
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
    auto it = sync_pattern_keys_.find(method);
    if (it == sync_pattern_keys_.end()) return false;
    // CONSERVATIVE overlap check: two routes with matching structural
    // shapes (strip_keys) are treated as CONFLICTING regardless of
    // whether their param constraints are syntactically identical.
    //
    // Previously this helper treated different constraint strings as
    // proof of disjointness (e.g. /users/:id([0-9]+) vs /users/:slug([a-z]+)
    // returning false). That assumption is unsound — textual inequality
    // of regexes does NOT prove non-overlap. For example the sync route
    //   /users/:id(\d+)
    // and a proxy companion
    //   /users/:uid([0-9]{1,3})
    // both match /users/123, so allowing the async companion to register
    // would silently shadow the sync handler via async-over-sync
    // precedence. General regex-intersection emptiness is undecidable,
    // so we cannot verify disjointness in the router. Collapse to a
    // shape-only check: any same-shape sync route is a conflict.
    //
    // Consequence: a proxy companion with a different-but-potentially-
    // overlapping constraint is dropped. The catch-all part of the
    // proxy is still registered (that insertion goes through RouteAsync
    // into a different trie than the sync route), so the proxy still
    // serves paths with a trailing slash — only the bare-prefix
    // companion is suppressed.
    return it->second.count(NormalizePatternKey(pattern)) > 0;
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

    // PROXY BARE-PREFIX COMPANION runtime yield.
    //
    // Proxy registration installs a derived bare-prefix companion
    // (e.g. /api/:version for a /api/:version/*rest catch-all) so
    // requests without a trailing path like /api/v1 still reach the
    // proxy. That companion shares a structural shape with any
    // pre-existing sync route that uses a param at the same position,
    // and its regex may or may not overlap — we cannot determine that
    // statically (regex-intersection emptiness is undecidable).
    //
    // Handle the ambiguity at RUNTIME: if the matched async pattern
    // was installed as a proxy companion AND the sync trie for this
    // method (or its HEAD→GET fallback) has a match for the current
    // request path, YIELD to sync. The sync route's regex has already
    // accepted this path, so it's the owner; the proxy companion was
    // only supposed to serve paths the sync route wouldn't.
    //
    // - Disjoint regexes (e.g. sync /:id([0-9]+) + companion
    //   /:slug([a-z]+)): /users/123 → sync accepts, companion yields,
    //   sync serves. /users/abc → sync's regex rejects (no HasMatch),
    //   companion proceeds.
    // - Overlapping regexes (e.g. sync /:id(\d+) + companion
    //   /:uid([0-9]{1,3})): /users/12 → both regexes accept, companion
    //   yields to sync. The companion only serves paths sync rejects.
    //
    // This runs BEFORE the proxy-default HEAD branch because the
    // companion yield is a stricter precedence rule — if a sync
    // handler for the request's method matches, it wins regardless of
    // async/HEAD bookkeeping.
    // Companion check is keyed by (method, pattern). A pattern may be
    // a companion for SOME methods (the ones the proxy registered on
    // its derived bare-prefix companion) without being a companion for
    // OTHER methods. A later unrelated async route on the same pattern
    // but a different method MUST NOT inherit the yield behavior.
    bool is_proxy_companion_for_method = false;
    if (exact_match_handler) {
        auto c_it = proxy_companion_patterns_.find(request.method);
        if (c_it != proxy_companion_patterns_.end() &&
            c_it->second.count(exact_match_pattern) > 0) {
            is_proxy_companion_for_method = true;
        }
    }
    if (is_proxy_companion_for_method) {
        auto sync_it = method_tries_.find(request.method);
        bool sync_matches =
            (sync_it != method_tries_.end() &&
             sync_it->second.HasMatch(request.path));
        // For HEAD requests, the sync layer also does HEAD→GET
        // fallback — so a sync GET that matches this path would
        // also "win" over the async companion. Consult that too.
        if (!sync_matches && request.method == "HEAD") {
            auto sync_get = method_tries_.find("GET");
            if (sync_get != method_tries_.end() &&
                sync_get->second.HasMatch(request.path)) {
                sync_matches = true;
            }
        }
        if (sync_matches) {
            exact_match_handler = nullptr;
        }
    }

    if (exact_match_handler && request.method == "HEAD") {
        auto head_it =
            proxy_default_head_patterns_.find(exact_match_pattern);
        if (head_it != proxy_default_head_patterns_.end()) {
            // Proxy-default HEAD match. Decide whether to keep this
            // handler or yield so HEAD follows whichever route actually
            // owns GET for this path.
            //
            //  (a) Explicit sync Head() match → always yield.
            //
            //  (b) The SAME proxy registration that added this HEAD
            //      did NOT also register GET (paired_with_get == false).
            //      The proxy's GET was filtered out (typically because
            //      an earlier route already owns GET on this pattern).
            //      Drop the proxy-default HEAD and fall through to the
            //      async HEAD→GET fallback below so HEAD is served by
            //      the SAME handler GET would resolve to.
            //
            //  (c) Same proxy owns both, AND the winning async GET at
            //      request time IS the same pattern → keep the proxy
            //      HEAD. The second condition still matters because a
            //      broader async GET catch-all registered elsewhere
            //      can win over this pattern at request time, in
            //      which case HEAD should also track that winner.
            //
            //  (d) No async GET match at request time: sync Head()/
            //      HEAD→GET fallback takes priority if a sync handler
            //      matches; otherwise keep the proxy-default HEAD.
            //
            // Tracking paired_with_get per REGISTRATION (not by
            // a global "proxy_owned_get_patterns_" set) is required
            // because two proxies can share a pattern with only
            // partial method overlap — see the comment on
            // proxy_default_head_patterns_ in http_router.h.
            auto sync_head = method_tries_.find("HEAD");
            if (sync_head != method_tries_.end() &&
                sync_head->second.HasMatch(request.path)) {
                return nullptr;  // explicit sync HEAD always wins
            }

            bool paired_with_get = head_it->second;
            if (!paired_with_get) {
                // The proxy that installed this HEAD did not also
                // register GET on the same pattern; drop and let the
                // async HEAD→GET fallback reach the real GET owner.
                exact_match_handler = nullptr;
            } else {
                // Probe the async GET trie to find the actual winning
                // pattern for this path (not just "some pattern
                // matches"). If it is a DIFFERENT pattern, a broader
                // catch-all owns GET at runtime and we should yield.
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
                    if (async_get_pattern != exact_match_pattern) {
                        exact_match_handler = nullptr;
                    }
                    // else: same pattern, same owner — keep HEAD.
                } else {
                    // No async GET match. Sync HEAD→GET fallback owns
                    // the path if a sync GET matches; yield in that
                    // case. Otherwise keep the proxy-default HEAD.
                    auto sync_get = method_tries_.find("GET");
                    if (sync_get != method_tries_.end() &&
                        sync_get->second.HasMatch(request.path)) {
                        return nullptr;
                    }
                }
            }
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

void HttpRouter::MarkProxyDefaultHead(const std::string& pattern,
                                       bool paired_with_get) {
    // Last write wins if a pattern is re-registered. In practice the
    // async trie rejects duplicate HEAD registrations on the same
    // pattern, so this map is effectively single-entry per pattern.
    proxy_default_head_patterns_[pattern] = paired_with_get;
}

void HttpRouter::MarkProxyCompanion(const std::string& method,
                                     const std::string& pattern) {
    proxy_companion_patterns_[method].insert(pattern);
}

void HttpRouter::WebSocket(const std::string& path, WsUpgradeHandler handler) {
    ws_trie_.Insert(path, std::move(handler));
}

void HttpRouter::Use(Middleware middleware) {
    middlewares_.push_back(std::move(middleware));
}

void HttpRouter::PrependMiddleware(Middleware middleware) {
    middlewares_.insert(middlewares_.begin(), std::move(middleware));
}

void HttpRouter::PrependAsyncMiddleware(AsyncMiddleware middleware) {
    async_middlewares_.insert(
        async_middlewares_.begin(), std::move(middleware));
}

bool HttpRouter::RunAsyncMiddleware(
    const HttpRequest& request, HttpResponse& response,
    std::shared_ptr<AsyncPendingState>& out_state) {
    // out_state is never null on return — callsites uniformly read
    // sync_result(), with or without registered middleware.
    out_state = std::make_shared<AsyncPendingState>();

    if (async_middlewares_.empty()) {
        out_state->SetSyncResult(AsyncMiddlewareResult::PASS);
        out_state->MarkCompletedSync();
        return true;
    }

    // TODO: per-middleware state if/when multiple async middlewares are
    // registered. The current iteration shares one state across the chain.
    for (const auto& mw : async_middlewares_) {
        mw(request, response, out_state);
        if (!out_state->completed_sync()) {
            return false;
        }
        if (out_state->sync_result() == AsyncMiddlewareResult::DENY) {
            return true;
        }
    }
    return true;
}

bool HttpRouter::Dispatch(const HttpRequest& request, HttpResponse& response) {
    // Compat shim for sync-only callers. If async middleware is
    // registered, those callers cannot honor the suspend contract — we
    // warn and skip the async chain rather than execute it synchronously.
    if (!RunMiddleware(request, response)) {
        FillDefaultRejectionResponse(response);
        return true;
    }
    if (!async_middlewares_.empty()) {
        logging::Get()->warn(
            "HttpRouter::Dispatch called with async middleware registered; "
            "skipping async chain. The phased dispatch (RunMiddleware → "
            "RunAsyncMiddleware → DispatchHandler) must be used by callers "
            "that wire the suspend trampoline.");
    }
    return DispatchHandler(request, response);
}

bool HttpRouter::DispatchHandler(const HttpRequest& request, HttpResponse& response) {
    // Clear params from any previous dispatch on this request object.
    request.params.clear();

    // Search for a matching route BEFORE running middleware, so that
    // request.params is populated during middleware execution. This allows
    // middleware to authorize or rate-limit based on route parameters
    // (e.g., /users/:id → middleware reads request.params["id"]).
    //
    // Note: middleware ALREADY ran before this method (see Dispatch
    // compat shim and the H1/H2 phased callsites). DispatchHandler is
    // strictly the "find route + invoke handler" step.
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
    //
    // Exception: when the matched async GET is a proxy-companion
    // pattern that YIELDS to sync GET at runtime (see
    // proxy_companion_patterns_ and the runtime-yield logic in
    // GetAsyncHandler), the sync GET is the effective owner of GET
    // for this path and sync HEAD→GET fallback should work through
    // it. Otherwise HEAD returns 405 even though GET is actually
    // served by the sync route.
    if (!matched_handler && request.method == "HEAD") {
        bool head_blocked_by_async = false;
        auto async_get_it = async_method_tries_.find("GET");
        if (async_get_it != async_method_tries_.end()) {
            std::unordered_map<std::string, std::string> tmp;
            auto async_result = async_get_it->second.Search(request.path, tmp);
            if (async_result.handler &&
                head_fallback_blocked_.count(async_result.matched_pattern)) {
                // Check for the proxy-companion yield case: if the
                // matched pattern is registered as a proxy companion
                // FOR GET (keyed by method + pattern) AND a sync GET
                // exists for this exact path, the sync route wins at
                // runtime for GET (and therefore for HEAD→GET too).
                bool companion_yields_to_sync = false;
                auto comp_get_it = proxy_companion_patterns_.find("GET");
                if (comp_get_it != proxy_companion_patterns_.end() &&
                    comp_get_it->second.count(
                        async_result.matched_pattern) > 0) {
                    auto sync_get_it = method_tries_.find("GET");
                    if (sync_get_it != method_tries_.end() &&
                        sync_get_it->second.HasMatch(request.path)) {
                        companion_yields_to_sync = true;
                    }
                }
                if (!companion_yields_to_sync) {
                    head_blocked_by_async = true;
                }
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

    // Middleware ran in the caller (Dispatch compat shim or the H1/H2
    // phased dispatch site). DispatchHandler is the route-lookup +
    // handler-invocation step only.

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
                    // Same proxy-companion-yield exception as the
                    // HEAD dispatch branch above: if the blocked
                    // async GET is a proxy companion FOR GET AND a
                    // sync GET matches this path, the sync route
                    // wins at runtime so HEAD would actually be
                    // served. Companion check is keyed by (method,
                    // pattern) — we look up "GET" explicitly because
                    // we are reasoning about the async GET match
                    // that feeds the HEAD→GET fallback.
                    bool companion_yields_to_sync = false;
                    auto comp_get_it =
                        proxy_companion_patterns_.find("GET");
                    if (comp_get_it != proxy_companion_patterns_.end() &&
                        comp_get_it->second.count(result.matched_pattern) > 0) {
                        auto sync_get_it = method_tries_.find("GET");
                        if (sync_get_it != method_tries_.end() &&
                            sync_get_it->second.HasMatch(request.path)) {
                            companion_yields_to_sync = true;
                        }
                    }
                    if (!companion_yields_to_sync) {
                        async_get_blocks_head = true;
                    }
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
        response.Status(HttpStatus::METHOD_NOT_ALLOWED).Text("Method Not Allowed");
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
    if (response.GetStatusCode() == HttpStatus::OK && response.GetBody().empty()) {
        response.Status(HttpStatus::FORBIDDEN).Text("Forbidden");
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
