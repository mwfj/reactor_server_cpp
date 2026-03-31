#include "http/http_router.h"
#include "log/logger.h"
#include "log/log_utils.h"

#include <algorithm>

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

void HttpRouter::WebSocket(const std::string& path, WsUpgradeHandler handler) {
    ws_trie_.Insert(path, std::move(handler));
}

void HttpRouter::Use(Middleware middleware) {
    middlewares_.push_back(std::move(middleware));
}

bool HttpRouter::Dispatch(const HttpRequest& request, HttpResponse& response) {
    // Run middleware chain first
    for (const auto& mw : middlewares_) {
        if (!mw(request, response)) {
            // If middleware returned false without setting anything, default to 403.
            // Only when the response is completely untouched (default status +
            // no body + no headers). Allows intentional 200 OK + headers.
            if (response.GetStatusCode() == 200 &&
                response.GetBody().empty() &&
                response.GetHeaders().empty()) {
                response.Status(403).Text("Forbidden");
            }
            logging::Get()->debug("Middleware rejected request: {} {}",
                                  request.method, logging::SanitizePath(request.path));
            return true;
        }
    }

    // Find matching route in the method's trie
    auto it = method_tries_.find(request.method);
    if (it != method_tries_.end()) {
        std::unordered_map<std::string, std::string> params;
        auto result = it->second.Search(request.path, params);
        if (result.handler) {
            request.params = std::move(params);
            logging::Get()->debug("Route matched: {} {} -> pattern {}",
                                  request.method, logging::SanitizePath(request.path),
                                  result.matched_pattern);
            (*result.handler)(request, response);
            return true;
        }
    }

    // HEAD fallback: if no explicit HEAD handler, try GET (RFC 7231 §4.3.2)
    // Clone the request with method = "GET" so handlers that branch on
    // req.method see "GET" and behave correctly (body stripping happens later
    // in HttpConnectionHandler).
    if (request.method == "HEAD") {
        auto get_it = method_tries_.find("GET");
        if (get_it != method_tries_.end()) {
            std::unordered_map<std::string, std::string> params;
            auto result = get_it->second.Search(request.path, params);
            if (result.handler) {
                HttpRequest get_req = request;
                get_req.method = "GET";
                get_req.params = std::move(params);
                logging::Get()->debug("Route matched (HEAD->GET fallback): {} -> pattern {}",
                                      logging::SanitizePath(request.path),
                                      result.matched_pattern);
                (*result.handler)(get_req, response);
                return true;
            }
        }
    }

    // Check if path exists with different method (405 vs 404)
    // Collect allowed methods for the Allow header (RFC 7231 §6.5.5)
    std::vector<std::string> allowed_methods;
    bool has_get = false;
    bool has_head = false;
    for (const auto& [method, trie] : method_tries_) {
        if (method == request.method) continue;  // already checked
        if (trie.HasMatch(request.path)) {
            allowed_methods.push_back(method);
            if (method == "GET") has_get = true;
            if (method == "HEAD") has_head = true;
        }
    }
    // Implicit HEAD support for GET routes (RFC 7231 §4.3.2)
    if (has_get && !has_head) {
        allowed_methods.push_back("HEAD");
    }
    if (!allowed_methods.empty()) {
        // Sort for deterministic output across runs/compilers
        std::sort(allowed_methods.begin(), allowed_methods.end());
        std::string allowed;
        for (const auto& m : allowed_methods) {
            if (!allowed.empty()) allowed += ", ";
            allowed += m;
        }
        logging::Get()->debug("Method not allowed: {} {}",
                              request.method, logging::SanitizePath(request.path));
        response = HttpResponse::MethodNotAllowed();
        response.Header("Allow", allowed);
        return true;
    }

    logging::Get()->debug("No route found: {} {}",
                          request.method, logging::SanitizePath(request.path));
    return false;  // No route found -- caller sends 404
}

bool HttpRouter::RunMiddleware(const HttpRequest& request, HttpResponse& response) {
    for (const auto& mw : middlewares_) {
        if (!mw(request, response)) {
            return false;  // Middleware short-circuited
        }
    }
    return true;  // All middleware passed
}

bool HttpRouter::HasWebSocketRoute(const std::string& path) const {
    return ws_trie_.HasMatch(path);
}

HttpRouter::WsUpgradeHandler HttpRouter::GetWebSocketHandler(const std::string& path) const {
    std::unordered_map<std::string, std::string> params;
    auto result = ws_trie_.Search(path, params);
    if (result.handler) {
        return *result.handler;
    }
    return nullptr;
}

HttpRouter::WsUpgradeHandler HttpRouter::GetWebSocketHandler(const HttpRequest& request) const {
    std::unordered_map<std::string, std::string> params;
    auto result = ws_trie_.Search(request.path, params);
    if (result.handler) {
        request.params = std::move(params);
        return *result.handler;
    }
    return nullptr;
}
