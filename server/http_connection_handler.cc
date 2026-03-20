#include "http/http_connection_handler.h"

HttpConnectionHandler::HttpConnectionHandler(std::shared_ptr<ConnectionHandler> conn)
    : conn_(std::move(conn)) {}

void HttpConnectionHandler::SetRequestHandler(RequestHandler handler) {
    request_handler_ = std::move(handler);
}

void HttpConnectionHandler::SetUpgradeHandler(UpgradeHandler handler) {
    upgrade_handler_ = std::move(handler);
}

void HttpConnectionHandler::SendResponse(const HttpResponse& response) {
    std::string wire = response.Serialize();
    conn_->SendRaw(wire.data(), wire.size());
}

void HttpConnectionHandler::OnRawData(std::shared_ptr<ConnectionHandler> conn, std::string& data) {
    // If upgraded to WebSocket, forward raw bytes to WebSocketConnection
    if (upgraded_ && ws_conn_) {
        ws_conn_->OnRawData(data);
        return;
    }

    const char* buf = data.data();
    size_t remaining = data.size();

    // Loop to handle pipelining: a single data buffer may contain multiple HTTP requests
    while (remaining > 0) {
        size_t consumed = parser_.Parse(buf, remaining);

        if (parser_.HasError()) {
            // Send 400 Bad Request with Connection: close.
            // Don't just reset the parser — the stream is in an unknown state,
            // so the only safe action is to close the connection.
            HttpResponse err_resp = HttpResponse::BadRequest(parser_.GetError());
            err_resp.Header("Connection", "close");
            SendResponse(err_resp);
            return;
        }

        // Safety guard: if parser consumed 0 bytes, avoid infinite loop
        if (consumed == 0) break;

        if (parser_.GetRequest().complete) {
            const HttpRequest& req = parser_.GetRequest();

            // Enforce body size limit
            if (max_body_size_ > 0 && req.body.size() > max_body_size_) {
                HttpResponse err_resp = HttpResponse::PayloadTooLarge();
                err_resp.Header("Connection", "close");
                SendResponse(err_resp);
                return;
            }

            // Check for WebSocket upgrade
            if (req.upgrade && upgrade_handler_) {
                // Validate WebSocket handshake per RFC 6455
                std::string ws_error;
                if (!WebSocketHandshake::Validate(req, ws_error)) {
                    SendResponse(WebSocketHandshake::Reject(400, ws_error));
                    return;
                }

                // Check route existence BEFORE sending 101
                // upgrade_handler_ returns true if a WS route exists for this path
                auto self = shared_from_this();
                if (!upgrade_handler_(self, req, conn_)) {
                    SendResponse(HttpResponse::NotFound());
                    return;
                }

                // Route confirmed — send 101 Switching Protocols
                SendResponse(WebSocketHandshake::Accept(req));

                // Create WebSocket connection and wire up callbacks
                ws_conn_ = std::make_unique<WebSocketConnection>(conn_);
                upgraded_ = true;

                // Invoke handler again to wire WS callbacks (ws_conn_ now exists).
                // The handler is idempotent: first call checks route, second call wires callbacks.
                upgrade_handler_(self, req, conn_);

                // Forward any trailing bytes after the HTTP headers as WebSocket data
                buf += consumed;
                remaining -= consumed;
                if (remaining > 0 && ws_conn_) {
                    std::string trailing(buf, remaining);
                    ws_conn_->OnRawData(trailing);
                }
                return;
            }

            // Normal HTTP request -- dispatch to handler
            if (request_handler_) {
                HttpResponse response;
                request_handler_(shared_from_this(), req, response);
                SendResponse(response);
            }

            // Advance past consumed bytes
            buf += consumed;
            remaining -= consumed;

            // Reset parser for next request (keep-alive / pipelining)
            parser_.Reset();
        } else {
            // Incomplete request -- need more data
            break;
        }
    }
}
