#include "http/http_router.h"
#include "http/http_status.h"
#include "log/logger.h"
#include "log/log_utils.h"
#include "observability/span.h"
#include "ws/websocket_handshake.h"
// <algorithm> provided by common.h (via http_request.h)

// AsyncPendingState invariants:
//   - resume_cb_ fires exactly once, always OUTSIDE mu_.
//   - active_counter_ is decremented exactly once via bookkeeping_done_
//     (TripCancel and DecrementOnce share the exchange).
//   - cancel_cb_ fires exactly once when TripCancel wins the exchange
//     (move-and-clear, exception-safe).

AsyncPendingState::~AsyncPendingState() {
    // Backstop for the dropped-state case: a successful resume clears
    // both fields, so this body is a no-op on the happy path. End() /
    // AddEvent are dispatcher-thread-only per Span docs; the dtor may
    // run anywhere, so we use `DropWithoutEnd` (atomic only) for the
    // span and skip the event emission entirely. Logged at debug
    // because a graceful shutdown of N in-flight requests fires this
    // dtor N times — warn-level would spam the operator log under
    // routine drain.
    if (auth_idp_check_span) {
        auth_idp_check_span->DropWithoutEnd();
        auth_idp_check_span.reset();
        logging::Get()->debug(
            "AsyncPendingState dtor: dropped auth.idp_check span "
            "without End() (async resume bypassed)");
    }
    if (emit_pending_end_event) {
        emit_pending_end_event = false;
        logging::Get()->debug(
            "AsyncPendingState dtor: skipped auth.pending_end event "
            "(cross-thread AddEvent unsafe)");
    }
}

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
    std::shared_ptr<std::atomic<int64_t>> consume_now;
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (resume_armed_) return;         // one-shot
        resume_cb_ = std::move(resume_cb);
        active_counter_ = std::move(active_counter);
        resume_armed_ = true;
        // Consume an owed decrement deferred by an earlier TripCancel that
        // ran before active_counter_ was wired. Without this hand-off,
        // a cancel that purges the queued upstream work (silently, no
        // completion callback) leaves bookkeeping unclaimed and
        // active_requests_ leaks — DecrementOnce never runs because the
        // resume closure never fires.
        if (decrement_owed_ && active_counter_ &&
            !bookkeeping_done_.exchange(true, std::memory_order_acq_rel)) {
            consume_now = active_counter_;
            decrement_owed_ = false;
        }
        if (completion_pending_) {
            cb_to_fire = resume_cb_;       // copy under lock
            payload_to_fire = std::move(result_slot_);
            completion_pending_ = false;
        }
    }
    if (consume_now) {
        consume_now->fetch_sub(1, std::memory_order_relaxed);
    }
    if (cb_to_fire) {
        cb_to_fire(std::move(payload_to_fire));
    }
}

void AsyncPendingState::TripCancel() {
    cancelled_.store(true, std::memory_order_release);

    // Bookkeeping is gated independently from cancel-cb firing. Two cases:
    //
    //   (a) active_counter_ was wired by ArmResume before us — claim the
    //       bookkeeping one-shot and decrement now. A subsequent
    //       DecrementOnce from the resume path no-ops.
    //   (b) ArmResume hasn't run yet — leave bookkeeping_done_ unset so
    //       the eventual DecrementOnce (when resume_cb fires post-ArmResume)
    //       can claim the slot and decrement. The dispatch caller releases
    //       the original RequestGuard right after ArmResume, so without
    //       this deferral the counter would leak: TripCancel would have
    //       claimed bookkeeping_done_=true with no counter wired, the
    //       guard would release without decrementing, and DecrementOnce
    //       would no-op.
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (active_counter_ &&
            !bookkeeping_done_.exchange(true, std::memory_order_acq_rel)) {
            active_counter_->fetch_sub(1, std::memory_order_relaxed);
        } else if (!active_counter_) {
            // Case (b) deferral: ArmResume hasn't wired active_counter_ yet.
            // Mark the decrement as owed so ArmResume consumes it on
            // wire-in. Without this, a cancel that subsequently purges
            // the queued upstream work without a completion callback
            // leaves bookkeeping_done_ unset forever and active_requests_
            // never decrements (the resume closure never runs to call
            // DecrementOnce).
            decrement_owed_ = true;
        }
    }

    // Cancel callback fires exactly once via its own dedicated one-shot.
    // Move it out under the lock to keep a throwing hook from re-entering.
    if (cancel_fired_.exchange(true, std::memory_order_acq_rel)) return;
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

void HttpRouter::RouteProxyAsync(const std::string& method,
                                  const std::string& path,
                                  AsyncHandler handler) {
    // Insert into the async trie via the same path RouteAsync uses, then
    // mark the (method, pattern) pair as proxy-owned. The trie itself
    // does not know whether an entry came from RouteAsync or
    // RouteProxyAsync; the proxy_async_patterns_ side map is the
    // authoritative ownership marker that ResolveRouteMatch reads to
    // demux step (2). Insert first so any duplicate-pattern exception
    // from the trie leaves proxy_async_patterns_ consistent (matches
    // the RouteAsync ordering rule).
    RouteAsync(method, path, std::move(handler));
    proxy_async_patterns_[method].insert(path);
}

void HttpRouter::Route(const std::string& method, const std::string& path,
                        Handler handler, http::RouteOptions options) {
    // Trie insert first so duplicate-pattern exception surfaces before
    // route_options_ commit (mirrors the 3-arg sync_pattern_keys_ ordering).
    Route(method, path, std::move(handler));
    route_options_[method][path] = options;
}

void HttpRouter::RouteAsync(const std::string& method, const std::string& path,
                             AsyncHandler handler, http::RouteOptions options) {
    RouteAsync(method, path, std::move(handler));
    route_options_[method][path] = options;
}

void HttpRouter::RouteProxyAsync(const std::string& method,
                                  const std::string& path,
                                  AsyncHandler handler,
                                  http::RouteOptions options) {
    RouteProxyAsync(method, path, std::move(handler));
    route_options_[method][path] = options;
}

http::RouteOptions HttpRouter::ResolveOptionsAtHeaders(
    const std::string& method, const std::string& path) const {
    // Reuse the GetAsyncHandler precedence walk to find a matching pattern
    // without populating req.params. GetAsyncHandler takes an HttpRequest
    // and mutates params, so we use a throw-away request whose params we
    // discard. HEAD→GET fallback resolves to the GET route's options.
    HttpRequest scratch;
    scratch.method = method;
    scratch.path = path;
    std::string matched_pattern;
    bool head_fallback = false;

    // Async-trie precedence first (matches step 2 of ResolveRouteMatch).
    auto async_handler = GetAsyncHandler(scratch, &head_fallback, &matched_pattern);
    std::string lookup_method = method;
    if (head_fallback && method == "HEAD") {
        lookup_method = "GET";
    }
    if (async_handler) {
        auto mit = route_options_.find(lookup_method);
        if (mit != route_options_.end()) {
            auto pit = mit->second.find(matched_pattern);
            if (pit != mit->second.end()) {
                return pit->second;
            }
        }
        return {};
    }

    // Sync-trie precedence (matches step 3 of ResolveRouteMatch).
    auto try_sync = [&](const std::string& m) -> const http::RouteOptions* {
        auto it = method_tries_.find(m);
        if (it == method_tries_.end()) return nullptr;
        std::unordered_map<std::string, std::string> tmp_params;
        auto r = it->second.Search(path, tmp_params);
        if (!r.handler) return nullptr;
        auto mit = route_options_.find(m);
        if (mit == route_options_.end()) return nullptr;
        auto pit = mit->second.find(r.matched_pattern);
        if (pit == mit->second.end()) return nullptr;
        return &pit->second;
    };
    if (const auto* opts = try_sync(method)) return *opts;
    // HEAD → GET fallback for the sync trie.
    if (method == "HEAD") {
        if (const auto* opts = try_sync("GET")) return *opts;
    }
    return {};
}

bool HttpRouter::IsProxyAsyncPattern(const std::string& method,
                                      const std::string& pattern) const {
    auto it = proxy_async_patterns_.find(method);
    if (it == proxy_async_patterns_.end()) return false;
    return it->second.count(pattern) > 0;
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
    HttpRequest& request, bool* head_fallback_out,
    std::string* matched_pattern_out) const {
    if (head_fallback_out) *head_fallback_out = false;
    // matched_pattern_out is left untouched on miss; populated below on
    // every return-with-handler path.

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
        if (matched_pattern_out) *matched_pattern_out = exact_match_pattern;
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
                if (matched_pattern_out) *matched_pattern_out = result.matched_pattern;
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
    // Multi-async-middleware support is not yet implemented (see FIXME in
    // RunAsyncMiddleware). Silently dropping a second registration would be
    // a security regression: when AuthManager installs the introspection
    // middleware in MarkServerReady, an embedder-provided async middleware
    // already at the head would cause auth to be skipped for opaque-token
    // routes. Fail closed instead — the throw propagates out of
    // MarkServerReady and NetServer::Start cleans up partial startup.
    if (!async_middlewares_.empty()) {
        logging::Get()->error(
            "PrependAsyncMiddleware: chain already has an async middleware; "
            "multi-async-middleware chains are not supported");
        throw std::logic_error(
            "PrependAsyncMiddleware: only one async middleware may be "
            "registered (auth introspection conflicts with prior async "
            "middleware registration)");
    }
    async_middlewares_.insert(
        async_middlewares_.begin(), std::move(middleware));
}

bool HttpRouter::RunAsyncMiddleware(
    HttpRequest& request, HttpResponse& response,
    std::shared_ptr<AsyncPendingState>& out_state) {
    // Empty chain: implicit sync PASS. Leave out_state null so callers skip
    // the heap allocation on the hot path; sync DENY is impossible without
    // middleware actually running.
    if (async_middlewares_.empty()) {
        out_state.reset();
        return true;
    }

    out_state = std::make_shared<AsyncPendingState>();

    // FIXME: when multi-middleware support lands (today PrependAsyncMiddleware
    // hard-rejects N>1 to enforce single-registration), each middleware must
    // either get its own AsyncPendingState OR the loop must reset
    // completed_sync/sync_result between iterations. Reusing the same state
    // would silently overwrite the prior middleware's verdict on the next
    // SetSyncResult call. The single-middleware contract makes today's reuse
    // safe; the comment + greppable FIXME ensures future contributors fix
    // the reuse before lifting the registration gate.
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

bool HttpRouter::Dispatch(HttpRequest& request, HttpResponse& response) {
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

bool HttpRouter::DispatchHandler(HttpRequest& request, HttpResponse& response) {
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

void HttpRouter::PopulateRouteParams(HttpRequest& request) {
    // Delegates to ResolveRouteMatch — the single source of truth for
    // route resolution. ResolveRouteMatch populates BOTH
    // request.params (via the trie walks it performs) AND
    // request.route_match (kind / pattern / legacy bools). Legacy
    // callers that only cared about params get the same params they
    // would have gotten before; new callers reading route_match.kind
    // get the full precedence-chain decision.
    //
    // The earlier short-circuit `if (!request.params.empty()) return;`
    // is preserved by ResolveRouteMatch's own idempotency guard
    // (route_match.kind != None) — once any dispatch site has run the
    // resolver, subsequent calls no-op.
    ResolveRouteMatch(request);
}

// FIXME: Is some potential issue on this logic: either all success or all failed?
//        Should we convert it to accept the partial success?
bool HttpRouter::RunMiddleware(HttpRequest& request, HttpResponse& response) {
    PopulateRouteParams(request);
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

// RFC 7230 §3.2.6 token-list match. The Connection / Upgrade headers
// are comma-separated token lists; an individual token compares
// case-insensitively. A naive substring match misclassifies values
// like `Connection: notupgrade` or `Upgrade: xwebsocketx`, which on
// short-circuit would mark a normal GET as a WebSocket candidate
// and deprive routing/middleware of the real match. Tokenise on
// commas, trim OWS, and compare each token case-insensitively.
namespace {
bool HeaderHasTokenCI(const std::string& header_value,
                       const std::string& needle_lower) {
    if (header_value.empty()) return false;
    auto is_ows = [](char c) { return c == ' ' || c == '\t'; };
    size_t n = header_value.size();
    size_t i = 0;
    while (i < n) {
        // Skip leading OWS.
        while (i < n && is_ows(header_value[i])) ++i;
        size_t start = i;
        while (i < n && header_value[i] != ',') ++i;
        size_t end = i;
        // Trim trailing OWS within this token.
        while (end > start && is_ows(header_value[end - 1])) --end;
        if (end > start) {
            const size_t tok_len = end - start;
            if (tok_len == needle_lower.size()) {
                bool match = true;
                for (size_t k = 0; k < tok_len; ++k) {
                    char c = header_value[start + k];
                    char lc = static_cast<char>(
                        std::tolower(static_cast<unsigned char>(c)));
                    if (lc != needle_lower[k]) { match = false; break; }
                }
                if (match) return true;
            }
        }
        if (i < n && header_value[i] == ',') ++i;
    }
    return false;
}

// Cheap WebSocket-upgrade-candidate detection: method == "GET" AND a
// case-insensitive "Connection: Upgrade" token AND
// "Upgrade: websocket". Structural intent only, NOT full RFC 6455
// validation. Once this returns true, the resolver short-circuits;
// later precedence-chain steps are unreachable regardless of the
// follow-up validation outcome — so the match must be exact (token
// equality), not substring.
//
// PRECONDITION: HttpParser comma-folds repeated header lines per
// RFC 7230 §3.2.2 (see http_parser.cc on_header_field — duplicate
// non-singleton headers are concatenated with ", " before being
// stored in HttpRequest::headers). HeaderHasTokenCI therefore sees
// the FULL combined token list in a single string and correctly
// matches a `Connection: Upgrade` token even when the client sent
// `Connection: keep-alive\r\nConnection: Upgrade`. Iterating
// per-header is unnecessary as long as that parser invariant holds.
bool IsWebSocketUpgradeCandidate(const HttpRequest& request) {
    if (request.method != "GET") return false;
    if (!HeaderHasTokenCI(request.GetHeader("Connection"), "upgrade")) {
        return false;
    }
    if (!HeaderHasTokenCI(request.GetHeader("Upgrade"), "websocket")) {
        return false;
    }
    return true;
}
}  // namespace

HttpRouter::WsUpgradeHandler HttpRouter::GetWebSocketHandler(
    HttpRequest& request, std::string* matched_pattern_out) const {
    request.params.clear();
    std::unordered_map<std::string, std::string> params;
    auto result = ws_trie_.Search(request.path, params);
    if (result.handler) {
        request.params = std::move(params);
        if (matched_pattern_out) *matched_pattern_out = result.matched_pattern;
        return *result.handler;
    }
    return nullptr;
}

void HttpRouter::ResolveRouteMatch(HttpRequest& request) const {
    // Idempotent: if a previous call populated route_match.kind, do
    // nothing. The H1/H2 dispatch frames may invoke ResolveRouteMatch
    // both pre-middleware (for observability / per-route sampling) AND
    // at dispatch (for the kind-branch). The first call wins.
    if (request.route_match.kind != RouteKind::None) return;
    // Same idempotency for the legacy is_websocket flag — once a step-(0)
    // outcome was recorded as kind=None+is_websocket=true (path miss or
    // invalid upgrade), subsequent calls must not overwrite it.
    if (request.route_match.is_websocket) return;

    // Step (0a) — WS upgrade-candidate detection. Cheap presence check;
    // structural intent only. Once tripped, the resolver is committed
    // to a step-(0) outcome regardless of (0b).
    if (IsWebSocketUpgradeCandidate(request)) {
        // Step (0b) — full RFC 6455 validation. The dispatch site reads
        // route_match.kind / is_websocket to pick the correct response
        // status (101 / 426 / 400).
        std::string err;
        bool valid = WebSocketHandshake::Validate(request, err);
        request.route_match.is_websocket = true;
        request.route_match.method_for_dispatch = "GET";
        if (valid) {
            std::string ws_pattern;
            auto handler = GetWebSocketHandler(request, &ws_pattern);
            if (handler) {
                // VALID + path hit.
                request.route_match.kind = RouteKind::WsUpgrade;
                request.route_match.pattern = std::move(ws_pattern);
            }
            // VALID + path miss falls through with kind=None +
            // is_websocket=true so the dispatch site emits 404/426
            // instead of routing to a non-WS handler.
        }
        // INVALID falls through with kind=None + is_websocket=true so
        // the dispatch site emits 400 per RFC 6455 §4.2.2. Forbid
        // fallthrough: do NOT consult kinds (1)–(5) on a malformed
        // upgrade attempt — the existing H1 connection handler rejects
        // malformed upgrades BEFORE route-existence decisions, and the
        // resolver MUST mirror that contract.
        return;
    }

    // Step (1) — shutdown route. Not yet wired on this branch; the
    // ShutdownRoute API doesn't exist. When wired, this section will
    // consult GetShutdownHandler and set kind=Shutdown BEFORE step (2).

    // Step (2) — async route. GetAsyncHandler already encodes the
    // async-over-sync precedence + proxy-companion runtime yield + the
    // proxy-default-HEAD precedence + HEAD→GET fallback. We only need
    // to read the matched pattern and demux Async vs Proxy via the
    // ownership marker.
    std::string async_pattern;
    bool head_fb = false;
    auto async = GetAsyncHandler(request, &head_fb, &async_pattern);
    if (async) {
        // On HEAD→GET fallback the matched pattern + handler come from
        // the GET trie, and proxy ownership is recorded in
        // proxy_async_patterns_["GET"]. Looking up under "HEAD" would
        // miss a GET-owned proxy and misclassify the route as Async even
        // though Dispatch invokes the proxy handler.
        const std::string& lookup_method = head_fb ? "GET" : request.method;
        if (IsProxyAsyncPattern(lookup_method, async_pattern)) {
            request.route_match.kind     = RouteKind::Proxy;
            request.route_match.is_proxy = true;
        } else {
            request.route_match.kind = RouteKind::Async;
        }
        request.route_match.pattern             = std::move(async_pattern);
        request.route_match.method_for_dispatch =
            head_fb ? "GET" : request.method;
        request.route_match.head_fallback       = head_fb;
        return;
    }
    // GetAsyncHandler may have set head_fallback_out/matched_pattern_out
    // in non-trivial paths even when returning null (e.g. companion
    // yield). Reset for the sync walk below — its own bookkeeping
    // overwrites these.
    head_fb = false;

    // Step (3) — sync route, with HEAD→GET fallback to mirror sync
    // Dispatch's behavior. Walk the trie directly (we don't want
    // DispatchHandler to ALSO invoke a handler — ResolveRouteMatch is
    // resolution-only).
    auto sync_it = method_tries_.find(request.method);
    if (sync_it != method_tries_.end()) {
        std::unordered_map<std::string, std::string> params;
        auto result = sync_it->second.Search(request.path, params);
        if (result.handler) {
            request.params                          = std::move(params);
            request.route_match.kind                = RouteKind::Sync;
            request.route_match.pattern             = std::move(result.matched_pattern);
            request.route_match.method_for_dispatch = request.method;
            return;
        }
    }
    if (request.method == "HEAD") {
        // Mirror DispatchHandler's head_blocked_by_async gate: if an
        // async/proxy GET pattern at this path opted out of HEAD
        // fallback (DisableHeadFallback registered the pattern in
        // head_fallback_blocked_), the dispatch path returns 405
        // even when a sync GET is registered. Resolving to
        // RouteKind::Sync with head_fallback=true would tell the
        // observability middleware that the sync route handled the
        // request — when DispatchHandler later rejects it. Apply
        // the same proxy-companion yield rule (a sync GET on the
        // exact path overrides a companion-blocked async pattern).
        bool head_blocked_by_async = false;
        auto async_get_it = async_method_tries_.find("GET");
        if (async_get_it != async_method_tries_.end()) {
            std::unordered_map<std::string, std::string> tmp;
            auto async_result =
                async_get_it->second.Search(request.path, tmp);
            if (async_result.handler &&
                head_fallback_blocked_.count(async_result.matched_pattern)) {
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
                    request.params                          = std::move(params);
                    request.route_match.kind                = RouteKind::Sync;
                    request.route_match.pattern             = std::move(result.matched_pattern);
                    request.route_match.method_for_dispatch = "GET";
                    request.route_match.head_fallback       = true;
                    return;
                }
            }
        }
    }

    // No match — kind stays None. Dispatch path emits 404/405 as it
    // would have without ResolveRouteMatch.
}
