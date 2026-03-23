#include "http/http_router.h"

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
    routes_.push_back({method, path, std::move(handler)});
}

void HttpRouter::WebSocket(const std::string& path, WsUpgradeHandler handler) {
    ws_routes_.push_back({path, std::move(handler)});
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
            return true;
        }
    }

    // Find matching route — exact method match first
    for (const auto& route : routes_) {
        if (route.path == request.path && route.method == request.method) {
            route.handler(request, response);
            return true;
        }
    }

    // HEAD fallback: if no explicit HEAD handler, try GET (RFC 7231 §4.3.2)
    if (request.method == "HEAD") {
        for (const auto& route : routes_) {
            if (route.path == request.path && route.method == "GET") {
                route.handler(request, response);
                return true;
            }
        }
    }

    // Check if path exists with different method (405 vs 404)
    // Collect allowed methods for the Allow header (RFC 7231 §6.5.5)
    std::string allowed;
    bool has_get = false;
    bool has_head = false;
    for (const auto& route : routes_) {
        if (route.path == request.path) {
            if (!allowed.empty()) allowed += ", ";
            allowed += route.method;
            if (route.method == "GET") has_get = true;
            if (route.method == "HEAD") has_head = true;
        }
    }
    // Implicit HEAD support for GET routes (RFC 7231 §4.3.2)
    if (has_get && !has_head) {
        allowed += ", HEAD";
    }
    if (!allowed.empty()) {
        response = HttpResponse::MethodNotAllowed();
        response.Header("Allow", allowed);
        return true;
    }

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
    for (const auto& ws : ws_routes_) {
        if (ws.path == path) return true;
    }
    return false;
}

HttpRouter::WsUpgradeHandler HttpRouter::GetWebSocketHandler(const std::string& path) const {
    for (const auto& ws : ws_routes_) {
        if (ws.path == path) return ws.handler;
    }
    return nullptr;
}
