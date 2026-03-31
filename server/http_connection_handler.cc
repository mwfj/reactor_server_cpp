#include "http/http_connection_handler.h"
#include "log/logger.h"
#include "log/log_utils.h"
#include <sstream>

HttpConnectionHandler::HttpConnectionHandler(std::shared_ptr<ConnectionHandler> conn)
    : conn_(std::move(conn)) {}

void HttpConnectionHandler::SetRequestCallback(RequestCallback callback) {
    callbacks_.request_callback = std::move(callback);
}

void HttpConnectionHandler::SetRouteCheckCallback(RouteCheckCallback callback) {
    callbacks_.route_check_callback = std::move(callback);
}

void HttpConnectionHandler::SetMiddlewareCallback(MiddlewareCallback callback) {
    callbacks_.middleware_callback = std::move(callback);
}

void HttpConnectionHandler::SetUpgradeCallback(UpgradeCallback callback) {
    callbacks_.upgrade_callback = std::move(callback);
}

void HttpConnectionHandler::SetRequestCountCallback(
    HTTP_CALLBACKS_NAMESPACE::HttpConnRequestCountCallback callback) {
    callbacks_.request_count_callback = std::move(callback);
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
    // Stamp the response with the current request's HTTP version so the
    // status line matches (e.g. HTTP/1.0 for 1.0 clients, HTTP/1.1 for 1.1).
    // For pre-parse errors, current_http_minor_ is 1 (default = HTTP/1.1).
    HttpResponse versioned = response;
    versioned.Version(1, current_http_minor_);
    std::string wire = versioned.Serialize();
    conn_->SendRaw(wire.data(), wire.size());
}

void HttpConnectionHandler::CloseConnection() {
    request_in_progress_ = false;
    conn_->SetDeadlineTimeoutCb(nullptr);
    conn_->SetDeadline(std::chrono::steady_clock::now() + std::chrono::seconds(30));
    conn_->CloseAfterWrite();
}

// ---- Internal phase methods (split from OnRawData for readability) --------

void HttpConnectionHandler::HandleUpgradedData(const std::string& data) {
    try {
        ws_conn_->OnRawData(data);
    } catch (const std::exception& e) {
        // App handler threw — log server-side, send WS close 1011.
        // Don't call CloseConnection afterward: SendClose arms a 5s deadline
        // for the close handshake. CloseConnection would overwrite that deadline
        // and tear down the transport before the peer can send their Close reply.
        logging::Get()->error("Exception in WS handler: {}", e.what());
        if (ws_conn_->IsOpen()) {
            ws_conn_->SendClose(1011, "Internal error");
        }
        // If !IsOpen(), a close is already in progress (close_sent_ or !is_open_).
    }
}

void HttpConnectionHandler::HandleParseError() {
    logging::Get()->warn("HTTP parse error fd={}: {}", conn_->fd(), parser_.GetError());
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
}

bool HttpConnectionHandler::HandleCompleteRequest(const char*& buf, size_t& remaining, size_t consumed) {
    const HttpRequest& req = parser_.GetRequest();

    // Count every completed request parse — dispatched, rejected, or upgraded.
    if (callbacks_.request_count_callback) {
        callbacks_.request_count_callback();
    }

    // Reject unsupported HTTP versions — only HTTP/1.0 and HTTP/1.1 supported.
    // llhttp will parse any major.minor (e.g. HTTP/2.0, HTTP/0.9), but this
    // server only speaks HTTP/1.x, so dispatch would produce wrong responses.
    if (req.http_major != 1 || (req.http_minor != 0 && req.http_minor != 1)) {
        logging::Get()->warn("Unsupported HTTP version fd={}: {}.{}",
                             conn_->fd(), req.http_major, req.http_minor);
        HttpResponse ver_resp = HttpResponse::HttpVersionNotSupported();
        ver_resp.Header("Connection", "close");
        SendResponse(ver_resp);
        CloseConnection();
        return false;
    }

    // Track the request's HTTP version so SendResponse echoes it correctly
    // (e.g. HTTP/1.0 for 1.0 clients). Must be set after the version check.
    current_http_minor_ = req.http_minor;

    // RFC 7230 §5.4: HTTP/1.1 requests MUST include Host header
    if (req.http_minor >= 1 && !req.HasHeader("host")) {
        logging::Get()->debug("Missing Host header fd={}", conn_->fd());
        HttpResponse bad_req = HttpResponse::BadRequest("Missing Host header");
        bad_req.Header("Connection", "close");
        SendResponse(bad_req);
        CloseConnection();
        return false;
    }

    // RFC 7231 §5.1.1: reject unsupported Expect values.
    // For complete requests, 100-continue is a no-op (body already arrived).
    // Any other value must be rejected with 417.
    if (req.HasHeader("expect")) {
        std::string expect = req.GetHeader("expect");
        std::transform(expect.begin(), expect.end(), expect.begin(), ::tolower);
        while (!expect.empty() && (expect.front() == ' ' || expect.front() == '\t'))
            expect.erase(expect.begin());
        while (!expect.empty() && (expect.back() == ' ' || expect.back() == '\t'))
            expect.pop_back();
        if (expect != "100-continue") {
            logging::Get()->debug("Unsupported Expect value fd={}", conn_->fd());
            HttpResponse err;
            err.Status(417, "Expectation Failed");
            err.Header("Connection", "close");
            SendResponse(err);
            CloseConnection();
            return false;
        }
    }

    // Check for WebSocket upgrade.
    // Guard on method == GET: llhttp sets upgrade=1 for CONNECT too,
    // but RFC 6455 §4.1 requires GET. Without this, Route("CONNECT", ...)
    // is unreachable — CONNECT enters the WS path and fails validation.
    if (req.upgrade && req.method == "GET" && callbacks_.route_check_callback) {
        try {
        // Run middleware before upgrade (auth, CORS, rate limiting, etc.)
        // Hoist mw_response so successful middleware headers can be merged
        // into the 101 response (e.g., Set-Cookie, auth tokens).
        HttpResponse mw_response;
        if (callbacks_.middleware_callback) {
            if (!callbacks_.middleware_callback(req, mw_response)) {
                // Middleware rejected — default to 403 if nothing was set.
                if (mw_response.GetStatusCode() == 200 &&
                    mw_response.GetBody().empty() &&
                    mw_response.GetHeaders().empty()) {
                    mw_response.Status(403).Text("Forbidden");
                }
                logging::Get()->debug("WebSocket upgrade rejected by middleware fd={} path={}",
                                      conn_->fd(), req.path);
                mw_response.Header("Connection", "close");
                SendResponse(mw_response);
                CloseConnection();
                return false;
            }
        }

        // Validate WebSocket handshake per RFC 6455
        std::string ws_error;
        if (!WebSocketHandshake::Validate(req, ws_error)) {
            logging::Get()->debug("WebSocket handshake rejected fd={}: {}",
                                  conn_->fd(), ws_error);
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
            return false;
        }

        // Check route existence BEFORE sending 101
        if (!callbacks_.route_check_callback(req.path)) {
            logging::Get()->debug("WebSocket route not found fd={} path={}",
                                  conn_->fd(), logging::SanitizePath(req.path));
            auto not_found = HttpResponse::NotFound();
            not_found.Header("Connection", "close");
            SendResponse(not_found);
            CloseConnection();
            return false;
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
            // Skip 101 mandatory headers, framing headers, and WS
            // negotiation headers. This server doesn't implement WS
            // extensions or subprotocol negotiation, so allowing
            // middleware to inject Sec-WebSocket-Extensions (e.g.,
            // permessage-deflate) would cause clients to send RSV1
            // frames that the parser rejects as protocol errors.
            if (key == "connection" || key == "upgrade" ||
                key == "sec-websocket-accept" || key == "content-length" ||
                key == "transfer-encoding" ||
                key == "sec-websocket-extensions" ||
                key == "sec-websocket-protocol") {
                continue;
            }
            upgrade_resp.Header(hdr.first, hdr.second);
        }
        SendResponse(upgrade_resp);

        // If the send failed (client disconnected), don't proceed with upgrade.
        // SendRaw may have triggered CallCloseCb via EPIPE/ECONNRESET.
        if (conn_->IsClosing()) {
            logging::Get()->debug("WS upgrade: connection closed during 101 send fd={}",
                                  conn_->fd());
            return false;
        }

        // Mark as upgraded IMMEDIATELY after 101 is sent, before any
        // code that could throw. This ensures the catch block correctly
        // identifies post-101 exceptions and sends WS close 1011
        // instead of raw HTTP 500 on an already-upgraded connection.
        upgraded_ = true;

        // Create WebSocket connection
        ws_conn_ = std::make_unique<WebSocketConnection>(conn_);
        if (max_ws_message_size_ > 0) {
            ws_conn_->GetParser().SetMaxPayloadSize(max_ws_message_size_);
            ws_conn_->SetMaxMessageSize(max_ws_message_size_);
        }
        // Switch input cap to the WS message size limit. The read loop
        // stops at the cap (data stays in kernel buffer, nothing is
        // discarded) and requeues, so no parser desync. This bounds
        // per-cycle memory allocation against a fast peer while the
        // WS parser enforces frame/message limits independently.
        if (max_ws_message_size_ > 0) {
            conn_->SetMaxInputSize(max_ws_message_size_);
        }

        // Wire WS callbacks (called exactly once, ws_conn_ guaranteed to exist)
        if (callbacks_.upgrade_callback) {
            callbacks_.upgrade_callback(shared_from_this(), req);
        }

        // Forward any trailing bytes after the HTTP headers as WebSocket data
        buf += consumed;
        remaining -= consumed;
        if (remaining > 0 && ws_conn_) {
            std::string trailing(buf, remaining);
            ws_conn_->OnRawData(trailing);
        }
        return false;

        } catch (const std::exception& e) {
            // Exception in middleware/upgrade handler — log server-side,
            // send generic 500 to client (never leak e.what() over the wire).
            logging::Get()->error("Exception in upgrade handler: {}", e.what());
            if (!upgraded_) {
                // Pre-101: send HTTP 500, close via HTTP path
                HttpResponse err = HttpResponse::InternalError();
                err.Header("Connection", "close");
                SendResponse(err);
                CloseConnection();
            } else if (ws_conn_) {
                // Post-101 with WS connection: send close 1011.
                // SendClose now includes CloseAfterWrite for proper drain.
                ws_conn_->SendClose(1011, "Internal error");
            } else {
                // Post-101 but ws_conn_ is null — make_unique threw (OOM).
                // Connection is in a bad state (101 sent, no WS handler).
                // Force close the transport immediately.
                conn_->ForceClose();
            }
            return false;
        }
    }

    // Normal HTTP request -- dispatch to handler
    if (callbacks_.request_callback) {
        HttpResponse response;
        try {
            callbacks_.request_callback(shared_from_this(), req, response);
        } catch (const std::exception& e) {
            // Log the exception server-side; never send e.what() to the
            // client — it can contain stack traces, file paths, DB strings.
            logging::Get()->error("Exception in request handler: {}", e.what());
            response = HttpResponse::InternalError();
            response.Header("Connection", "close");
            SendResponse(response);
            CloseConnection();
            return false;
        }

        // Determine if response sets Connection: close (needed for
        // keep-alive logic AND the close decision after sending).
        // Scan ALL Connection headers and parse each as a comma-separated
        // token list (RFC 7230 §6.1). Values like "keep-alive, close" or
        // "upgrade, close" must be recognized, not just exact "close".
        bool resp_close = false;
        for (const auto& hdr : response.GetHeaders()) {
            std::string key = hdr.first;
            std::transform(key.begin(), key.end(), key.begin(), ::tolower);
            if (key == "connection") {
                std::string val = hdr.second;
                std::transform(val.begin(), val.end(), val.begin(), ::tolower);
                std::istringstream ss(val);
                std::string token;
                while (std::getline(ss, token, ',')) {
                    while (!token.empty() && (token.front() == ' ' || token.front() == '\t'))
                        token.erase(token.begin());
                    while (!token.empty() && (token.back() == ' ' || token.back() == '\t'))
                        token.pop_back();
                    if (token == "close") {
                        resp_close = true;
                    }
                }
            }
        }

        // HTTP/1.0 persistence requires explicit Connection: keep-alive
        // in the response. Without it, a compliant 1.0 client treats the
        // response as close-delimited and closes its end, while the server
        // keeps waiting — stranding the connection until idle timeout.
        if (req.http_minor == 0 && req.keep_alive && !resp_close) {
            response.Header("Connection", "keep-alive");
        }

        // If the server will close after this response (client sent
        // Connection: close, or HTTP/1.0 without keep-alive), the response
        // must include Connection: close so the wire semantics match.
        // Without this, an HTTP/1.1 response implies persistence but the
        // server tears the socket down immediately after sending.
        if (!req.keep_alive && !resp_close) {
            response.Header("Connection", "close");
        }

        // RFC 7231 §4.3.2: HEAD responses MUST NOT include a body,
        // but MUST include the same headers as the GET response (including
        // Content-Length reflecting the GET body size).
        if (req.method == "HEAD") {
            // Serialize the full response to get auto-computed Content-Length,
            // then strip the body from the wire output.
            response.Version(1, current_http_minor_);
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
            return false;
        }

        if (!req.keep_alive || resp_close) {
            CloseConnection();
            return false;
        }
    }

    // Request completed — reset timeout tracking for next request
    request_in_progress_ = false;
    conn_->ClearDeadline();
    conn_->SetDeadlineTimeoutCb(nullptr);

    // Advance past consumed bytes
    buf += consumed;
    remaining -= consumed;

    // Reset parser and per-request state for next request (keep-alive / pipelining)
    parser_.Reset();
    sent_100_continue_ = false;

    // If there are remaining bytes (pipelined request), arm a new deadline
    // AND re-install the 408 callback so timer-driven timeout sends proper response
    if (remaining > 0 && request_timeout_sec_ > 0) {
        request_in_progress_ = true;
        request_start_ = std::chrono::steady_clock::now();
        conn_->SetDeadline(request_start_ + std::chrono::seconds(request_timeout_sec_));
        std::weak_ptr<HttpConnectionHandler> weak_self = shared_from_this();
        conn_->SetDeadlineTimeoutCb([weak_self]() -> bool {
            if (auto self = weak_self.lock()) {
                HttpResponse timeout_resp = HttpResponse::RequestTimeout();
                timeout_resp.Header("Connection", "close");
                self->SendResponse(timeout_resp);
            }
            return false;  // Proceed with connection close
        });
    }

    return true;  // Continue pipelining loop
}

void HttpConnectionHandler::HandleIncompleteRequest() {
    // Incomplete request -- need more data.
    // If the peer already closed (close_after_write_ set), no more bytes
    // will arrive — the request can never complete. Close immediately
    // instead of leaking the connection slot until timeout.
    if (conn_->IsCloseDeferred()) {
        logging::Get()->debug("Incomplete request, peer EOF fd={}, force-closing",
                              conn_->fd());
        conn_->ForceClose();
        return;
    }
    // Perform early validation once headers are complete to avoid
    // holding connection slots for requests that can never succeed.
    if (!sent_100_continue_ && parser_.GetRequest().headers_complete) {
        const auto& partial = parser_.GetRequest();

        // Early reject: unsupported HTTP version
        if (partial.http_major != 1 ||
            (partial.http_minor != 0 && partial.http_minor != 1)) {
            logging::Get()->warn("Early reject: unsupported HTTP version fd={}",
                                 conn_->fd());
            HttpResponse ver_resp = HttpResponse::HttpVersionNotSupported();
            ver_resp.Header("Connection", "close");
            SendResponse(ver_resp);
            CloseConnection();
            return;
        }

        // Early reject: HTTP/1.1 missing Host
        if (partial.http_minor >= 1 && !partial.HasHeader("host")) {
            logging::Get()->debug("Early reject: missing Host fd={}", conn_->fd());
            HttpResponse bad_req = HttpResponse::BadRequest("Missing Host header");
            bad_req.Header("Connection", "close");
            SendResponse(bad_req);
            CloseConnection();
            return;
        }

        // Early reject: Content-Length exceeds body size limit.
        // Without this, a client can send headers with a huge Content-Length
        // and no body, occupying a connection slot until request timeout.
        if (max_body_size_ > 0 &&
            partial.content_length > max_body_size_) {
            logging::Get()->warn("Early reject: Content-Length exceeds limit fd={}",
                                 conn_->fd());
            HttpResponse err = HttpResponse::PayloadTooLarge();
            err.Header("Connection", "close");
            SendResponse(err);
            CloseConnection();
            return;
        }

        // RFC 7231 §5.1.1: handle Expect header
        if (partial.HasHeader("expect")) {
            std::string expect = partial.GetHeader("expect");
            std::transform(expect.begin(), expect.end(), expect.begin(), ::tolower);
            // Trim OWS (SP/HTAB per RFC 7230 §3.2.3)
            while (!expect.empty() && (expect.front() == ' ' || expect.front() == '\t'))
                expect.erase(expect.begin());
            while (!expect.empty() && (expect.back() == ' ' || expect.back() == '\t'))
                expect.pop_back();
            if (expect == "100-continue") {
                // Don't send 100 Continue for WebSocket upgrade requests —
                // WebSocketHandshake::Validate() rejects body-bearing
                // upgrades, so acknowledging the body is contradictory.
                if (partial.upgrade) {
                    HttpResponse bad_req = HttpResponse::BadRequest(
                        "WebSocket upgrade must not have a request body");
                    bad_req.Header("Connection", "close");
                    SendResponse(bad_req);
                    CloseConnection();
                    return;
                }
                HttpResponse cont;
                cont.Status(100, "Continue");
                SendResponse(cont);
                sent_100_continue_ = true;
                logging::Get()->debug("Sent 100 Continue fd={}", conn_->fd());
            } else {
                // Unrecognized Expect value — RFC 7231 §5.1.1: 417
                logging::Get()->debug("Early reject: unsupported Expect fd={}", conn_->fd());
                HttpResponse err;
                err.Status(417, "Expectation Failed");
                err.Header("Connection", "close");
                SendResponse(err);
                CloseConnection();
                return;
            }
        }
    }
}

// ---- Main entry point -----------------------------------------------------

void HttpConnectionHandler::OnRawData(std::shared_ptr<ConnectionHandler> conn, std::string& data) {
    // For HTTP connections draining a response (close_after_write set),
    // don't process new data. The parser wasn't Reset after the last
    // HPE_PAUSED return when CloseConnection was called — feeding new
    // bytes to a paused parser causes llhttp_get_error_pos() to reference
    // old data, producing underflow/bogus consumed counts.
    // WebSocket connections must NOT be blocked here — the peer's Close
    // reply must reach ProcessFrame for a clean close handshake.
    if (conn->IsCloseDeferred() && !upgraded_) {
        logging::Get()->debug("Skipping data for close-deferred fd={}", conn->fd());
        return;
    }

    // If upgraded to WebSocket, forward raw bytes to WebSocketConnection
    if (upgraded_ && ws_conn_) {
        HandleUpgradedData(data);
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
            conn_->SetDeadlineTimeoutCb([weak_self]() -> bool {
                if (auto self = weak_self.lock()) {
                    HttpResponse timeout_resp = HttpResponse::RequestTimeout();
                    timeout_resp.Header("Connection", "close");
                    self->SendResponse(timeout_resp);
                }
                return false;  // Proceed with connection close
            });
        } else {
            // Request still in progress — check elapsed time
            auto elapsed = std::chrono::steady_clock::now() - request_start_;
            if (elapsed > std::chrono::seconds(request_timeout_sec_)) {
                logging::Get()->warn("Request timeout fd={}", conn_->fd());
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

        // Update HTTP version as early as headers are available — needed for
        // error responses (413, 431, 400) that fire before request completion.
        // Only for valid versions (1.0/1.1); unsupported versions keep the default.
        if (parser_.GetRequest().headers_complete &&
            parser_.GetRequest().http_major == 1 &&
            (parser_.GetRequest().http_minor == 0 || parser_.GetRequest().http_minor == 1)) {
            current_http_minor_ = parser_.GetRequest().http_minor;
        }

        if (parser_.HasError()) {
            HandleParseError();
            return;
        }

        // Safety guard: if parser consumed 0 bytes, avoid infinite loop
        if (consumed == 0) break;

        if (parser_.GetRequest().complete) {
            if (!HandleCompleteRequest(buf, remaining, consumed)) {
                return;
            }
            // Continue pipelining loop
        } else {
            HandleIncompleteRequest();
            break;
        }
    }
}
