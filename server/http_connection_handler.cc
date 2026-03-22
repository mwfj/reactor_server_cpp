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

void HttpConnectionHandler::SetRequestTimeout(int seconds) {
    request_timeout_sec_ = seconds;
    // Don't arm deadline here — for TLS connections, the handshake hasn't
    // completed yet. The deadline is armed on the first OnRawData call
    // (which only fires after TLS handshake completes).
}

void HttpConnectionHandler::SendResponse(const HttpResponse& response) {
    std::string wire = response.Serialize();
    conn_->SendRaw(wire.data(), wire.size());
}

void HttpConnectionHandler::CloseConnection() {
    request_in_progress_ = false;
    conn_->SetDeadlineTimeoutCb(nullptr);
    conn_->SetDeadline(std::chrono::steady_clock::now() + std::chrono::seconds(30));
    conn_->CloseAfterWrite();
}

void HttpConnectionHandler::OnRawData(std::shared_ptr<ConnectionHandler> conn, std::string& data) {
    // If upgraded to WebSocket, forward raw bytes to WebSocketConnection
    if (upgraded_ && ws_conn_) {
        try {
            ws_conn_->OnRawData(data);
        } catch (const std::exception& e) {
            // App handler threw — send WS close 1011 instead of bare transport close
            if (ws_conn_->IsOpen()) {
                ws_conn_->SendClose(1011, "Internal error");
            }
            CloseConnection();
        }
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

            // RFC 7230 §5.4: HTTP/1.1 requests MUST include Host header
            if (req.http_major >= 1 && req.http_minor >= 1 && !req.HasHeader("host")) {
                HttpResponse bad_req = HttpResponse::BadRequest("Missing Host header");
                bad_req.Header("Connection", "close");
                SendResponse(bad_req);
                CloseConnection();
                return;
            }

            // Check for WebSocket upgrade
            if (req.upgrade && route_checker_) {
                try {
                // Run middleware before upgrade (auth, CORS, rate limiting, etc.)
                // Hoist mw_response so successful middleware headers can be merged
                // into the 101 response (e.g., Set-Cookie, auth tokens).
                HttpResponse mw_response;
                if (middleware_runner_) {
                    if (!middleware_runner_(req, mw_response)) {
                        // Middleware rejected — default to 403 if no status was set.
                        // Preserve middleware-added headers (e.g., WWW-Authenticate).
                        if (mw_response.GetStatusCode() == 200 && mw_response.GetBody().empty()) {
                            mw_response.Status(403).Text("Forbidden");
                        }
                        mw_response.Header("Connection", "close");
                        SendResponse(mw_response);
                        CloseConnection();
                        return;
                    }
                }

                // Validate WebSocket handshake per RFC 6455
                std::string ws_error;
                if (!WebSocketHandshake::Validate(req, ws_error)) {
                    int reject_code = 400;
                    // RFC 6455 §4.4: wrong version → 426 + Sec-WebSocket-Version
                    if (ws_error.find("version") != std::string::npos ||
                        ws_error.find("Version") != std::string::npos) {
                        reject_code = 426;
                    }
                    HttpResponse reject = WebSocketHandshake::Reject(reject_code, ws_error);
                    if (reject_code == 426) {
                        reject.Header("Sec-WebSocket-Version", "13");
                    }
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

                // Route confirmed — send 101 Switching Protocols.
                // Merge safe middleware headers (e.g., Set-Cookie, auth tokens).
                // Skip headers that are mandatory parts of the 101 handshake response
                // to avoid corruption.
                HttpResponse upgrade_resp = WebSocketHandshake::Accept(req);
                for (const auto& hdr : mw_response.GetHeaders()) {
                    std::string key = hdr.first;
                    std::transform(key.begin(), key.end(), key.begin(), ::tolower);
                    // Skip 101 mandatory headers and framing headers
                    if (key == "connection" || key == "upgrade" ||
                        key == "sec-websocket-accept" || key == "content-length" ||
                        key == "transfer-encoding") {
                        continue;
                    }
                    upgrade_resp.Header(hdr.first, hdr.second);
                }
                SendResponse(upgrade_resp);

                // If the send failed (client disconnected), don't proceed with upgrade.
                // SendRaw may have triggered CallCloseCb via EPIPE/ECONNRESET.
                if (conn_->IsClosing()) {
                    return;
                }

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

                } catch (const std::exception& e) {
                    // Exception in middleware/upgrade handler — send appropriate error
                    if (!upgraded_) {
                        // Pre-101: send HTTP 500
                        HttpResponse err = HttpResponse::InternalError(e.what());
                        err.Header("Connection", "close");
                        SendResponse(err);
                    } else if (ws_conn_) {
                        // Post-101: send WS close 1011 (Internal Error)
                        ws_conn_->SendClose(1011, "Internal error");
                    }
                    CloseConnection();
                    return;
                }
            }

            // Normal HTTP request -- dispatch to handler
            if (request_handler_) {
                HttpResponse response;
                try {
                    request_handler_(shared_from_this(), req, response);
                } catch (const std::exception& e) {
                    response = HttpResponse::InternalError(e.what());
                    response.Header("Connection", "close");
                    SendResponse(response);
                    CloseConnection();
                    return;
                }

                // RFC 7231 §4.3.2: HEAD responses MUST NOT include a body,
                // but MUST include the same headers as the GET response (including
                // Content-Length reflecting the GET body size).
                if (req.method == "HEAD") {
                    // Serialize the full response to get auto-computed Content-Length,
                    // then strip the body from the wire output.
                    std::string wire = response.Serialize();
                    // Find the end of headers (blank line)
                    auto header_end = wire.find("\r\n\r\n");
                    if (header_end != std::string::npos) {
                        wire = wire.substr(0, header_end + 4);  // Include the blank line
                    }
                    conn_->SendRaw(wire.data(), wire.size());
                } else {
                    SendResponse(response);
                }

                // If SendResponse triggered a connection close (e.g., EPIPE),
                // stop processing pipelined requests.
                if (conn_->IsClosing()) {
                    return;
                }

                // Close if request is non-keep-alive OR response sets Connection: close.
                // Check case-insensitively for both the header name and value.
                bool resp_close = false;
                for (const auto& hdr : response.GetHeaders()) {
                    std::string key = hdr.first;
                    std::transform(key.begin(), key.end(), key.begin(), ::tolower);
                    if (key == "connection") {
                        std::string val = hdr.second;
                        std::transform(val.begin(), val.end(), val.begin(), ::tolower);
                        if (val == "close") {
                            resp_close = true;
                        }
                        break;
                    }
                }
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
