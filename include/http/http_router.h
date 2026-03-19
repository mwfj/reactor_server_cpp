#pragma once

#include "http/http_request.h"
#include "http/http_response.h"

#include <string>
#include <vector>
#include <functional>
#include <memory>

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

    // Middleware -- return true to continue, false to stop
    using Middleware = std::function<bool(
        const HttpRequest& request,
        HttpResponse& response
    )>;

    // WebSocket upgrade handler
    using WsUpgradeHandler = std::function<void(WebSocketConnection& ws)>;

    // Route registration
    void Get(const std::string& path, Handler handler);
    void Post(const std::string& path, Handler handler);
    void Put(const std::string& path, Handler handler);
    void Delete(const std::string& path, Handler handler);
    void Route(const std::string& method, const std::string& path, Handler handler);

    // WebSocket route
    void WebSocket(const std::string& path, WsUpgradeHandler handler);

    // Middleware registration (executed in registration order)
    void Use(Middleware middleware);

    // Dispatch request to matching handler.
    // Returns true if route found, false if no match (caller should send 404).
    bool Dispatch(const HttpRequest& request, HttpResponse& response);

    // WebSocket route lookup
    bool HasWebSocketRoute(const std::string& path) const;
    WsUpgradeHandler GetWebSocketHandler(const std::string& path) const;

private:
    struct RouteEntry {
        std::string method;
        std::string path;
        Handler handler;
    };
    std::vector<RouteEntry> routes_;
    std::vector<Middleware> middlewares_;

    struct WsRouteEntry {
        std::string path;
        WsUpgradeHandler handler;
    };
    std::vector<WsRouteEntry> ws_routes_;
};
