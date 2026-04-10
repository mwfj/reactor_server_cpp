#include "http/http_router.h"
#include "log/logger.h"
#include "log/log_utils.h"
// <algorithm> provided by common.h (via http_request.h)

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
    method_tries_[method].Insert(path, std::move(handler));
}

void HttpRouter::RouteAsync(const std::string& method, const std::string& path,
                            AsyncHandler handler) {
    // Insert into the trie first so any duplicate-pattern exception
    // surfaces before we mirror it into async_patterns_. If the trie
    // throws, async_patterns_ stays consistent.
    async_method_tries_[method].Insert(path, std::move(handler));
    async_patterns_[method].insert(path);
}

bool HttpRouter::HasAsyncRoute(const std::string& method,
                                const std::string& pattern) const {
    auto it = async_patterns_.find(method);
    if (it == async_patterns_.end()) return false;
    return it->second.count(pattern) > 0;
}

HttpRouter::AsyncHandler HttpRouter::GetAsyncHandler(
    const HttpRequest& request, bool* head_fallback_out) const {
    if (head_fallback_out) *head_fallback_out = false;

    // For HEAD requests, an explicit sync HEAD handler takes priority over
    // any async HEAD handler (including proxy catch-all routes). Check sync
    // HEAD BEFORE async lookup so that user-registered Head() handlers are
    // not shadowed by proxy's async HEAD registration.
    if (request.method == "HEAD") {
        auto sync_head = method_tries_.find("HEAD");
        if (sync_head != method_tries_.end() &&
            sync_head->second.HasMatch(request.path)) {
            return nullptr;  // let sync Dispatch handle explicit HEAD
        }
    }

    // 1. Try exact method match in the async trie.
    auto it = async_method_tries_.find(request.method);
    if (it != async_method_tries_.end()) {
        std::unordered_map<std::string, std::string> params;
        auto result = it->second.Search(request.path, params);
        if (result.handler) {
            request.params = std::move(params);
            return *result.handler;
        }
        // Path miss — fall through to HEAD→GET fallback below.
    }

    // 2. HEAD fallback to async GET (mirrors sync Dispatch behavior).
    //    Only attempt if the exact async HEAD search above failed OR the
    //    path didn't match — this handles the case where an unrelated async
    //    HEAD route exists (e.g. /health) but the requested path (e.g.
    //    /items) is only registered via GetAsync.
    //    Skip the fallback when the matched GET pattern opted out via
    //    DisableHeadFallback() (currently used by proxy routes whose
    //    proxy.methods explicitly exclude HEAD). Without this, the method
    //    filter would be silently bypassed for HEAD requests.
    if (request.method == "HEAD") {
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

    // HEAD fallback to GET (RFC 7231 §4.3.2)
    if (!matched_handler && request.method == "HEAD") {
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
        bool head_would_succeed = false;
        auto sync_get_it = method_tries_.find("GET");
        if (sync_get_it != method_tries_.end() &&
            sync_get_it->second.HasMatch(request.path)) {
            head_would_succeed = true;
        }
        if (!head_would_succeed) {
            auto async_get_it = async_method_tries_.find("GET");
            if (async_get_it != async_method_tries_.end()) {
                std::unordered_map<std::string, std::string> dummy_params;
                auto result = async_get_it->second.Search(
                    request.path, dummy_params);
                if (result.handler &&
                    !head_fallback_blocked_.count(result.matched_pattern)) {
                    head_would_succeed = true;
                }
            }
        }
        if (head_would_succeed) {
            record("HEAD");
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
