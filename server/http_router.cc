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
    async_method_tries_[method].Insert(path, std::move(handler));
}

HttpRouter::AsyncHandler HttpRouter::GetAsyncHandler(const HttpRequest& request) const {
    auto it = async_method_tries_.find(request.method);
    if (it == async_method_tries_.end()) {
        // HEAD fallback to GET for async routes (consistent with sync path).
        if (request.method != "HEAD") return nullptr;
        it = async_method_tries_.find("GET");
        if (it == async_method_tries_.end()) return nullptr;
    }
    std::unordered_map<std::string, std::string> params;
    auto result = it->second.Search(request.path, params);
    if (!result.handler) return nullptr;
    request.params = std::move(params);
    return *result.handler;
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

    // Check if path exists with different method (405 vs 404)
    std::vector<std::string> allowed_methods;
    bool has_get = false;
    bool has_head = false;
    for (const auto& [method, trie] : method_tries_) {
        if (method == request.method) continue;
        if (trie.HasMatch(request.path)) {
            allowed_methods.push_back(method);
            if (method == "GET") has_get = true;
            if (method == "HEAD") has_head = true;
        }
    }
    if (has_get && !has_head) {
        allowed_methods.push_back("HEAD");
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
    if (response.GetStatusCode() == 200 &&
        response.GetBody().empty() &&
        response.GetHeaders().empty()) {
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
