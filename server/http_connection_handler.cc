#include "http/http_connection_handler.h"

HttpConnectionHandler::HttpConnectionHandler(std::shared_ptr<ConnectionHandler> conn)
    : conn_(std::move(conn)) {}

void HttpConnectionHandler::SetRequestHandler(RequestHandler handler) {
    request_handler_ = std::move(handler);
}

void HttpConnectionHandler::SetRouteChecker(RouteChecker checker) {
    route_checker_ = std::move(checker);
}

void HttpConnectionHandler::SetMiddlewareRunner(MiddlewareRunner runner) {
    middleware_runner_ = std::move(runner);
}

void HttpConnectionHandler::SetUpgradeHandler(UpgradeHandler handler) {
    upgrade_handler_ = std::move(handler);
}

void HttpConnectionHandler::SetMaxBodySize(size_t max) {
    max_body_size_ = max;
    parser_.SetMaxBodySize(max);
}

void HttpConnectionHandler::SetMaxHeaderSize(size_t max) {
    max_header_size_ = max;
    parser_.SetMaxHeaderSize(max);
}

void HttpConnectionHandler::SendResponse(const HttpResponse& response) {
    std::string wire = response.Serialize();
    conn_->SendRaw(wire.data(), wire.size());
}

void HttpConnectionHandler::CloseConnection() {
    conn_->CloseAfterWrite();
}

void HttpConnectionHandler::OnRawData(std::shared_ptr<ConnectionHandler> conn, std::string& data) {
    // If upgraded to WebSocket, forward raw bytes to WebSocketConnection
    if (upgraded_ && ws_conn_) {
        ws_conn_->OnRawData(data);
        return;
    }

    const char* buf = data.data();
    size_t remaining = data.size();

    // Slowloris protection: track when the current incomplete request started.
    // Two enforcement mechanisms:
    // 1. On data arrival: check elapsed time here (catches slow-trickle attacks)
    // 2. Timer scan: ConnectionHandler::IsTimeOut checks the deadline even when
    //    no data arrives (catches clients that send one partial request then go silent)
    if (request_timeout_sec_ > 0) {
        if (!request_in_progress_) {
            // First bytes of a new request — start the clock
            request_in_progress_ = true;
            request_start_ = std::chrono::steady_clock::now();
            // Set deadline on the connection so the timer scanner can enforce it
            // even if the client stops sending entirely
            conn_->SetDeadline(request_start_ + std::chrono::seconds(request_timeout_sec_));
            // Set callback so timer-driven timeout sends 408 before close
            std::weak_ptr<HttpConnectionHandler> weak_self = shared_from_this();
            conn_->SetDeadlineTimeoutCb([weak_self]() {
                if (auto self = weak_self.lock()) {
                    HttpResponse timeout_resp = HttpResponse::RequestTimeout();
                    timeout_resp.Header("Connection", "close");
                    self->SendResponse(timeout_resp);
                }
            });
        } else {
            // Request still in progress — check elapsed time
            auto elapsed = std::chrono::steady_clock::now() - request_start_;
            if (elapsed > std::chrono::seconds(request_timeout_sec_)) {
                HttpResponse timeout_resp = HttpResponse::RequestTimeout();
                timeout_resp.Header("Connection", "close");
                SendResponse(timeout_resp);
                CloseConnection();
                return;
            }
        }
    }

    // Loop to handle pipelining: a single data buffer may contain multiple HTTP requests
    while (remaining > 0) {
        size_t consumed = parser_.Parse(buf, remaining);

        if (parser_.HasError()) {
            // Determine appropriate error response based on parser error type
            HttpResponse err_resp;
            switch (parser_.GetErrorType()) {
                case HttpParser::ParseError::BODY_TOO_LARGE:
                    err_resp = HttpResponse::PayloadTooLarge();
                    break;
                case HttpParser::ParseError::HEADER_TOO_LARGE:
                    err_resp = HttpResponse::HeaderTooLarge();
                    break;
                default:
                    err_resp = HttpResponse::BadRequest(parser_.GetError());
                    break;
            }
            err_resp.Header("Connection", "close");
            SendResponse(err_resp);
            // Actually close the connection — the stream is in an unknown state
            CloseConnection();
            return;
        }

        // Safety guard: if parser consumed 0 bytes, avoid infinite loop
        if (consumed == 0) break;

        if (parser_.GetRequest().complete) {
            const HttpRequest& req = parser_.GetRequest();

            // Check for WebSocket upgrade
            if (req.upgrade && route_checker_) {
                // Run middleware before upgrade (auth, CORS, rate limiting, etc.)
                if (middleware_runner_) {
                    HttpResponse mw_response;
                    if (!middleware_runner_(req, mw_response)) {
                        // Middleware rejected the request
                        mw_response.Header("Connection", "close");
                        SendResponse(mw_response);
                        CloseConnection();
                        return;
                    }
                }

                // Validate WebSocket handshake per RFC 6455
                std::string ws_error;
                if (!WebSocketHandshake::Validate(req, ws_error)) {
                    HttpResponse reject = WebSocketHandshake::Reject(400, ws_error);
                    reject.Header("Connection", "close");
                    SendResponse(reject);
                    CloseConnection();
                    return;
                }

                // Check route existence BEFORE sending 101
                if (!route_checker_(req.path)) {
                    auto not_found = HttpResponse::NotFound();
                    not_found.Header("Connection", "close");
                    SendResponse(not_found);
                    CloseConnection();
                    return;
                }

                // Request completed (as upgrade) — reset timeout tracking
                request_in_progress_ = false;
                conn_->ClearDeadline();
                conn_->SetDeadlineTimeoutCb(nullptr);

                // Route confirmed — send 101 Switching Protocols
                SendResponse(WebSocketHandshake::Accept(req));

                // Create WebSocket connection
                ws_conn_ = std::make_unique<WebSocketConnection>(conn_);
                if (max_ws_message_size_ > 0) {
                    ws_conn_->GetParser().SetMaxPayloadSize(max_ws_message_size_);
                    ws_conn_->SetMaxMessageSize(max_ws_message_size_);
                }
                upgraded_ = true;

                // Wire WS callbacks (called exactly once, ws_conn_ guaranteed to exist)
                if (upgrade_handler_) {
                    upgrade_handler_(shared_from_this(), req);
                }

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

                // Close if request is non-keep-alive OR response sets Connection: close
                const auto& resp_headers = response.GetHeaders();
                auto conn_hdr = resp_headers.find("Connection");
                bool resp_close = (conn_hdr != resp_headers.end() && conn_hdr->second == "close");
                if (!req.keep_alive || resp_close) {
                    CloseConnection();
                    return;
                }
            }

            // Request completed — reset timeout tracking for next request
            request_in_progress_ = false;
            conn_->ClearDeadline();
            conn_->SetDeadlineTimeoutCb(nullptr);

            // Advance past consumed bytes
            buf += consumed;
            remaining -= consumed;

            // Reset parser for next request (keep-alive / pipelining)
            parser_.Reset();

            // If there are remaining bytes (pipelined request), arm a new deadline
            // AND re-install the 408 callback so timer-driven timeout sends proper response
            if (remaining > 0 && request_timeout_sec_ > 0) {
                request_in_progress_ = true;
                request_start_ = std::chrono::steady_clock::now();
                conn_->SetDeadline(request_start_ + std::chrono::seconds(request_timeout_sec_));
                std::weak_ptr<HttpConnectionHandler> weak_self = shared_from_this();
                conn_->SetDeadlineTimeoutCb([weak_self]() {
                    if (auto self = weak_self.lock()) {
                        HttpResponse timeout_resp = HttpResponse::RequestTimeout();
                        timeout_resp.Header("Connection", "close");
                        self->SendResponse(timeout_resp);
                    }
                });
            }
        } else {
            // Incomplete request -- need more data
            break;
        }
    }
}
