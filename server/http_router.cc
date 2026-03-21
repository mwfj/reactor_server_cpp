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
            return true;  // Middleware short-circuited, response is set
        }
    }

    // Find matching route (exact path + method match)
    // HEAD requests also match GET handlers (RFC 7231 §4.3.2)
    for (const auto& route : routes_) {
        if (route.path == request.path &&
            (route.method == request.method ||
             (request.method == "HEAD" && route.method == "GET"))) {
            route.handler(request, response);
            return true;
        }
    }

    // Check if path exists with different method (405 vs 404)
    for (const auto& route : routes_) {
        if (route.path == request.path) {
            response = HttpResponse::MethodNotAllowed();
            return true;
        }
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
