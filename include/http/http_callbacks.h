#pragma once

#include "common.h"
// <functional>, <memory>, <string>, <cstdint> provided by common.h

// Forward declarations
class HttpConnectionHandler;
class ConnectionHandler;
class WebSocketConnection;
struct HttpRequest;
class HttpResponse;

namespace HTTP_CALLBACKS_NAMESPACE {

    // ---- HttpConnectionHandler callbacks ------------------------------------
    using HttpConnRequestCallback = std::function<void(
        std::shared_ptr<HttpConnectionHandler> self,
        const HttpRequest& request,
        HttpResponse& response
    )>;
    using HttpConnRouteCheckCallback = std::function<bool(const std::string& path)>;
    using HttpConnMiddlewareCallback = std::function<bool(
        const HttpRequest& request,
        HttpResponse& response
    )>;
    using HttpConnUpgradeCallback = std::function<void(
        std::shared_ptr<HttpConnectionHandler> self,
        const HttpRequest& request
    )>;

    struct HttpConnCallbacks {
        HttpConnRequestCallback    request_callback    = nullptr;
        HttpConnRouteCheckCallback route_check_callback = nullptr;
        HttpConnMiddlewareCallback middleware_callback  = nullptr;
        HttpConnUpgradeCallback    upgrade_callback    = nullptr;
    };

    // ---- WebSocketConnection callbacks --------------------------------------
    using WsMessageCallback = std::function<void(
        WebSocketConnection& ws, const std::string& message, bool is_binary
    )>;
    using WsCloseCallback = std::function<void(
        WebSocketConnection& ws, uint16_t code, const std::string& reason
    )>;
    using WsPingCallback = std::function<void(
        WebSocketConnection& ws, const std::string& payload
    )>;
    using WsErrorCallback = std::function<void(
        WebSocketConnection& ws, const std::string& error
    )>;

    struct WsCallbacks {
        WsMessageCallback message_callback = nullptr;
        WsCloseCallback   close_callback   = nullptr;
        WsPingCallback    ping_callback    = nullptr;
        WsErrorCallback   error_callback   = nullptr;
    };

} // namespace HTTP_CALLBACKS_NAMESPACE
