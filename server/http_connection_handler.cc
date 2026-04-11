#include "http/http_connection_handler.h"
#include "log/logger.h"
#include "log/log_utils.h"
#include <sstream>

namespace {
// Overhead budget above max_body_size_ + max_header_size_ for any extra
// request-line, headers, and framing bytes that may accumulate while an
// async response is pending on a pipelined keep-alive connection.
constexpr size_t DEFERRED_STASH_OVERHEAD = 8192;
// Fallback cap when one or both request-size axes is 0 ("unlimited").
// The sync parser only buffers one request body at a time, so unlimited
// body size doesn't cause OOM there. But the deferred stash accumulates
// raw bytes from ALL pipelined requests across read cycles without
// parsing. A generous-but-finite safety valve prevents OOM while still
// accepting large uploads (the parser enforces the real per-request
// limits when it processes the buffered bytes after the async response).
constexpr size_t DEFERRED_STASH_FALLBACK_CAP = 64 * 1024 * 1024;  // 64 MiB
}  // namespace

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

void HttpConnectionHandler::SetShutdownCheckCallback(
    HTTP_CALLBACKS_NAMESPACE::HttpConnShutdownCheckCallback callback) {
    callbacks_.shutdown_check_callback = std::move(callback);
}

void HttpConnectionHandler::SetMaxBodySize(size_t max) {
    max_body_size_ = max;
    parser_.SetMaxBodySize(max);
}

void HttpConnectionHandler::SetMaxHeaderSize(size_t max) {
    max_header_size_ = max;
    parser_.SetMaxHeaderSize(max);
}

void HttpConnectionHandler::UpdateSizeLimits(size_t body, size_t header,
                                              size_t ws, size_t http_input_cap) {
    SetMaxBodySize(body);
    SetMaxHeaderSize(header);
    max_ws_message_size_ = ws;

    if (upgraded_ && ws_conn_) {
        // WS-upgraded connection: update parser + message limits, and switch
        // transport cap to the WS-specific value (0 = unlimited).
        ws_conn_->GetParser().SetMaxPayloadSize(ws);
        ws_conn_->SetMaxMessageSize(ws);
        conn_->SetMaxInputSize(ws);
    } else {
        // HTTP-mode connection: use the composite HTTP input cap.
        conn_->SetMaxInputSize(http_input_cap);
    }
}

void HttpConnectionHandler::SetMaxAsyncDeferredSec(int sec) {
    max_async_deferred_sec_ = sec;
    // Not applied retroactively to an already-armed deferred heartbeat:
    // the per-request cap uses whatever value was in effect when the
    // deferred state began. Reload-driven config changes only affect
    // subsequent deferred requests — matching the pattern used for
    // other request-scoped settings.
}

void HttpConnectionHandler::SetRequestTimeout(int seconds) {
    request_timeout_sec_ = seconds;
    // Don't arm deadline at initialization — for TLS connections, the
    // handshake hasn't completed yet. The deadline is armed on the first
    // OnRawData call (which only fires after TLS handshake completes).
    //
    // During reload (request_in_progress_ == true), reconcile the already-
    // armed deadline with the new timeout. Without this, the old deadline
    // fires at the wrong time: too early if the operator extended it, or
    // at all when the operator disabled timeouts (sending 408 on a valid
    // in-flight request).
    if (request_in_progress_) {
        if (seconds > 0) {
            conn_->SetDeadline(request_start_ +
                               std::chrono::seconds(seconds));
            // (Re-)install the 408 callback. When the previous timeout was 0,
            // no callback was ever installed for this in-flight request —
            // without this, expiry produces a bare close instead of 408.
            // When the previous timeout was >0, reinstalling is a cheap no-op
            // (same lambda shape).
            std::weak_ptr<HttpConnectionHandler> weak_self = shared_from_this();
            conn_->SetDeadlineTimeoutCb([weak_self]() -> bool {
                if (auto self = weak_self.lock()) {
                    HttpResponse timeout_resp = HttpResponse::RequestTimeout();
                    timeout_resp.Header("Connection", "close");
                    self->SendResponse(timeout_resp);
                }
                return false;
            });
        } else {
            conn_->ClearDeadline();
            conn_->SetDeadlineTimeoutCb(nullptr);
        }
    }
}

bool HttpConnectionHandler::NormalizeOutgoingResponse(HttpResponse& response,
                                                      bool client_keep_alive,
                                                      int /*client_http_minor*/) {
    // Scan all Connection headers for a "close" token (RFC 7230 §6.1).
    bool resp_close = false;
    for (const auto& hdr : response.GetHeaders()) {
        std::string key = hdr.first;
        std::transform(key.begin(), key.end(), key.begin(),
                       [](unsigned char c){ return std::tolower(c); });
        if (key != "connection") continue;
        std::string val = hdr.second;
        std::transform(val.begin(), val.end(), val.begin(),
                       [](unsigned char c){ return std::tolower(c); });
        std::istringstream ss(val);
        std::string token;
        while (std::getline(ss, token, ',')) {
            while (!token.empty() && (token.front() == ' ' || token.front() == '\t'))
                token.erase(token.begin());
            while (!token.empty() && (token.back() == ' ' || token.back() == '\t'))
                token.pop_back();
            if (token == "close") resp_close = true;
        }
    }

    // HTTP/1.0 persistence requires explicit Connection: keep-alive in the
    // response; without it a compliant 1.0 client treats the response as
    // close-delimited.
    if (current_http_minor_ == 0 && client_keep_alive && !resp_close) {
        response.Header("Connection", "keep-alive");
    }
    // When the client did not request keep-alive, echo Connection: close so
    // the wire semantics match the server's intent to tear down the socket.
    if (!client_keep_alive && !resp_close) {
        response.Header("Connection", "close");
        resp_close = true;
    }
    return !client_keep_alive || resp_close;
}

void HttpConnectionHandler::StripResponseBodyForHead(std::string& wire) {
    auto header_end = wire.find("\r\n\r\n");
    if (header_end != std::string::npos) {
        wire.resize(header_end + 4);
    }
}

void HttpConnectionHandler::BeginAsyncResponse(const HttpRequest& req) {
    deferred_response_pending_ = true;
    deferred_was_head_ = (req.method == "HEAD");
    deferred_keep_alive_ = req.keep_alive;
    // current_http_minor_ was updated by the parser when headers completed
    // and persists across the deferred window, so no separate capture is
    // needed. Mark the transport exempt from NetServer::Stop()'s close
    // sweep until CompleteAsyncResponse runs; the sweep live-checks this
    // flag on each iteration so a request entering the async handler just
    // before the sweep cannot be dropped on an empty output buffer.
    if (conn_) conn_->SetShutdownExempt(true);
}

void HttpConnectionHandler::CancelAsyncResponse() {
    deferred_response_pending_ = false;
    deferred_was_head_ = false;
    deferred_keep_alive_ = true;
    deferred_pending_buf_.clear();
    deferred_start_ = std::chrono::steady_clock::time_point{};
    if (conn_) conn_->SetShutdownExempt(false);
}

void HttpConnectionHandler::StashDeferredBytes(const std::string& data) {
    if (data.empty()) return;
    // Bound memory while an async response is pending so a client
    // pipelining bytes behind a deferred response can't OOM us.
    //
    // When both limits are set: cap = (body + header) * pipeline_depth.
    // When one or both is 0 ("unlimited"): use a generous fallback cap.
    // The sync parser only buffers one request body at a time so unlimited
    // body size doesn't cause OOM there, but the deferred stash accumulates
    // raw bytes from ALL pipelined requests across read cycles without
    // parsing. The fallback safety valve prevents OOM while still accepting
    // the vast majority of legitimate uploads; the parser enforces the
    // real per-request limits when it processes the buffered bytes.
    static constexpr size_t PIPELINE_DEPTH = 4;
    size_t cap;
    if (max_body_size_ > 0 && max_header_size_ > 0) {
        size_t one_request = max_body_size_ + max_header_size_;
        if (one_request < max_body_size_) {
            cap = SIZE_MAX;  // addition overflowed
        } else if (one_request <= SIZE_MAX / PIPELINE_DEPTH) {
            cap = one_request * PIPELINE_DEPTH;
        } else {
            cap = SIZE_MAX;  // multiplication would overflow
        }
        if (cap <= SIZE_MAX - DEFERRED_STASH_OVERHEAD) {
            cap += DEFERRED_STASH_OVERHEAD;
        }
    } else {
        // One or both axes unlimited — use the fallback safety valve.
        cap = DEFERRED_STASH_FALLBACK_CAP;
    }
    if (deferred_pending_buf_.size() + data.size() > cap) {
        logging::Get()->warn(
            "Deferred pipeline buffer cap exceeded fd={} ({} + {} > {}), "
            "force-closing connection",
            conn_ ? conn_->fd() : -1, deferred_pending_buf_.size(),
            data.size(), cap);
        deferred_pending_buf_.clear();
        if (conn_ && !conn_->IsClosing()) conn_->ForceClose();
        return;
    }
    deferred_pending_buf_.append(data);
}

void HttpConnectionHandler::CompleteAsyncResponse(HttpResponse response) {
    if (!deferred_response_pending_) {
        logging::Get()->warn(
            "CompleteAsyncResponse called without a pending deferred response "
            "(fd={})", conn_ ? conn_->fd() : -1);
        return;
    }

    const bool was_head = deferred_was_head_;
    // If shutdown has started (either signaled by the server-wide check
    // callback, or observed via close_after_write_ already set by the
    // generic close sweep before exempt was flipped), force Connection:
    // close on the reply regardless of the client's keep-alive preference.
    // The synchronous request path does the same via SetupHandlers' lambda;
    // deferred completions must not leave the socket reusable during
    // shutdown, otherwise CompleteAsyncResponse could resume parsing
    // buffered pipeline bytes while the server is tearing down.
    const bool shutting_down =
        (callbacks_.shutdown_check_callback &&
         callbacks_.shutdown_check_callback()) ||
        (conn_ && conn_->IsCloseDeferred());
    const bool effective_keep_alive = deferred_keep_alive_ && !shutting_down;
    const bool should_close = NormalizeOutgoingResponse(
        response, effective_keep_alive, current_http_minor_);

    response.Version(1, current_http_minor_);
    std::string wire = response.Serialize();
    if (was_head) StripResponseBodyForHead(wire);
    conn_->SendRaw(wire.data(), wire.size());

    // Clear deferred state BEFORE resuming parsing/closing — subsequent
    // OnRawData or CloseConnection calls must see the connection as idle.
    // BUT: delay clearing shutdown_exempt_ until AFTER CloseConnection
    // arms close_after_write_. During graceful shutdown, HasPendingH1Output
    // polls both IsShutdownExempt() and IsCloseDeferred(). If we clear
    // exempt before close_after_write_ is armed, a brief window where both
    // flags are false causes the drain loop to exit and stop the event
    // loop, truncating the response bytes we just queued with SendRaw.
    deferred_response_pending_ = false;
    deferred_was_head_ = false;
    deferred_keep_alive_ = true;
    deferred_start_ = std::chrono::steady_clock::time_point{};

    if (conn_->IsClosing()) {
        if (conn_) conn_->SetShutdownExempt(false);
        deferred_pending_buf_.clear();
        return;
    }
    if (should_close) {
        deferred_pending_buf_.clear();
        // CloseConnection arms close_after_write_ — clear exempt AFTER
        // so HasPendingH1Output always sees at least one flag true.
        CloseConnection();
        if (conn_) conn_->SetShutdownExempt(false);
        return;
    }

    // Connection stays open (keep-alive) — clear exempt now. No drain-loop
    // race: the response bytes are already buffered and the connection
    // is not closing.
    if (conn_) conn_->SetShutdownExempt(false);

    // Clear the async timeout deadline: the response has been delivered,
    // so the connection should revert to idle_timeout_sec behavior until
    // the next request arrives. Without this, the stale 504 callback
    // would fire at the deferred deadline and close a healthy keep-alive
    // connection (HandleCompleteRequest installed this deadline + callback
    // when the response was marked deferred).
    conn_->ClearDeadline();
    conn_->SetDeadlineTimeoutCb(nullptr);

    // Resume parsing any pipelined bytes that arrived during the deferred
    // window. Move out of the member first so a nested BeginAsyncResponse
    // triggered by the next parsed async request can cleanly re-populate
    // deferred_pending_buf_ without stomping our state.
    if (!deferred_pending_buf_.empty()) {
        std::string pending = std::move(deferred_pending_buf_);
        deferred_pending_buf_.clear();
        OnRawData(conn_, pending);
    }
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
    // Count parse errors as requests for stats consistency with HTTP/2
    if (callbacks_.request_count_callback) {
        callbacks_.request_count_callback();
    }
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

    // Propagate dispatcher index for upstream pool partition affinity
    req.dispatcher_index = conn_->dispatcher_index();

    // Propagate peer connection metadata for proxy header rewriting
    // (X-Forwarded-For, X-Forwarded-Proto) and log correlation (client_fd).
    req.client_ip = conn_->ip_addr();
    req.client_tls = conn_->HasTls();
    req.client_fd = conn_->fd();

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
        std::transform(expect.begin(), expect.end(), expect.begin(), [](unsigned char c){ return std::tolower(c); });
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
        // Probe route existence to populate request.params for pattern routes
        // (e.g., /ws/:room → req.params["room"]). The bool result is checked
        // AFTER handshake validation and middleware to avoid leaking route
        // existence through different error codes (404 vs 400/426).
        bool ws_route_found = callbacks_.route_check_callback(req);

        // Run middleware — always, regardless of route match.
        // request.params is populated for matched routes; empty for misses.
        // Hoist mw_response so successful middleware headers can be merged
        // into the 101 response (e.g., Set-Cookie, auth tokens).
        HttpResponse mw_response;
        if (callbacks_.middleware_callback) {
            if (!callbacks_.middleware_callback(req, mw_response)) {
                // Middleware rejected — default to 403 if status is still the
                // HttpResponse default (200) and no body was set. The headers
                // check was intentionally removed: middleware that stamps CORS
                // or auth headers before rejecting should still produce 403,
                // not leak a 200 OK on a denied WebSocket upgrade. Matches
                // the async HTTP path (FillDefaultRejectionResponse).
                if (mw_response.GetStatusCode() == 200 &&
                    mw_response.GetBody().empty()) {
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

        // Validate WebSocket handshake per RFC 6455.
        // Must happen BEFORE the route-miss check so that malformed upgrades
        // always get 400/426 regardless of whether the route exists — prevents
        // leaking route existence through different error codes.
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

        // Now check route existence (after middleware and validation)
        if (!ws_route_found) {
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
            std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c){ return std::tolower(c); });
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
        // Late shutdown gate: the early route_check ran before middleware/101.
        // Must check BEFORE sending 101 — once 101 is on the wire, clients
        // expect a WebSocket session. Sending 101 then closing the TCP
        // connection without a WS close frame is a protocol violation.
        if (callbacks_.shutdown_check_callback &&
            callbacks_.shutdown_check_callback()) {
            logging::Get()->debug("WS upgrade rejected: server shutting down fd={}",
                                  conn_->fd());
            HttpResponse shutdown_resp;
            shutdown_resp.Status(503).Text("Service Unavailable");
            shutdown_resp.Header("Connection", "close");
            SendResponse(shutdown_resp);
            CloseConnection();
            return false;
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

        // Async handler path: the framework marked the response as deferred
        // before invoking the async handler (BeginAsyncResponse captured
        // request context). Any bytes after `consumed` belong to pipelined
        // requests that MUST NOT be parsed until the deferred response has
        // been sent — otherwise HTTP/1 response ordering is violated.
        // Route them through StashDeferredBytes so the same size cap and
        // force-close-on-overflow logic as OnRawData's top-level stash
        // applies.
        if (response.IsDeferred()) {
            request_in_progress_ = false;
            // Arm a ROLLING heartbeat deadline that re-arms itself on
            // fire to suppress idle_timeout while the async handler
            // runs. The handler (proxy or custom) bounds its own
            // response wait via its own timeout (proxy.response_timeout_ms,
            // custom handler deadlines) — this heartbeat just keeps
            // idle_timeout from closing the connection.
            //
            // An OPTIONAL absolute cap (max_async_deferred_sec_) acts
            // as a last-resort safety net for stuck handlers that
            // never call complete(). Computed by HttpServer from
            // upstream configs so it honors the largest configured
            // proxy.response_timeout_ms (with buffer). When 0, the
            // cap is disabled entirely — that mode is selected
            // automatically when any upstream has
            // proxy.response_timeout_ms=0 (operator explicitly opted
            // out of bounded async lifetime).
            //
            // When request_timeout_sec == 0 ("disabled" per config),
            // still install the heartbeat using a fallback interval —
            // otherwise idle_timeout would close quiet async work
            // mid-flight, which is a supported configuration per the
            // validator.
            static constexpr int ASYNC_HEARTBEAT_FALLBACK_SEC = 60;
            int heartbeat_sec = request_timeout_sec_ > 0
                              ? request_timeout_sec_
                              : ASYNC_HEARTBEAT_FALLBACK_SEC;
            int cap_sec = max_async_deferred_sec_;  // 0 = no cap
            deferred_start_ = std::chrono::steady_clock::now();
            conn_->SetDeadline(deferred_start_ +
                               std::chrono::seconds(heartbeat_sec));
            std::weak_ptr<HttpConnectionHandler> weak_self =
                shared_from_this();
            conn_->SetDeadlineTimeoutCb(
                [weak_self, heartbeat_sec, cap_sec]() -> bool {
                auto self = weak_self.lock();
                if (!self) return false;
                if (!self->deferred_response_pending_) {
                    // Response already delivered; let the normal close
                    // path run (callback shouldn't normally fire here
                    // because CompleteAsyncResponse clears the deadline,
                    // but handle defensively).
                    return false;
                }
                // Absolute safety cap: if configured AND exceeded,
                // abort the deferred state and send 504. This catches
                // stuck handlers without overriding operator-configured
                // timeouts — the cap is computed to be at least as
                // large as the longest configured proxy response
                // timeout (see HttpServer::max_async_deferred_sec_).
                if (cap_sec > 0) {
                    auto elapsed = std::chrono::duration_cast<
                        std::chrono::seconds>(
                        std::chrono::steady_clock::now() -
                        self->deferred_start_).count();
                    if (elapsed >= cap_sec) {
                        logging::Get()->warn(
                            "HTTP/1 async deferred response exceeded "
                            "safety cap ({}s) without completion fd={}; "
                            "aborting and sending 504",
                            cap_sec,
                            self->conn_ ? self->conn_->fd() : -1);
                        // Route through CompleteAsyncResponse so HEAD
                        // body stripping, shutdown-exempt clearing, and
                        // pipelined-buffer handling all run. Do NOT
                        // call CancelAsyncResponse first — that wipes
                        // deferred_was_head_, which CompleteAsyncResponse
                        // needs to know whether to strip the body.
                        // Forcing Connection: close on the synthetic 504
                        // ensures NormalizeOutgoingResponse returns
                        // should_close=true so the socket is torn down
                        // (the handler may still be running in the
                        // background and must not see a reusable
                        // connection).
                        HttpResponse timeout_resp =
                            HttpResponse::GatewayTimeout();
                        timeout_resp.Header("Connection", "close");
                        self->CompleteAsyncResponse(std::move(timeout_resp));
                        return false;
                    }
                }
                // Heartbeat: re-arm the deadline from now.
                self->conn_->SetDeadline(
                    std::chrono::steady_clock::now() +
                    std::chrono::seconds(heartbeat_sec));
                return true;  // handled, keep connection alive
            });
            buf += consumed;
            remaining -= consumed;
            if (remaining > 0) {
                StashDeferredBytes(std::string(buf, remaining));
            }
            parser_.Reset();
            sent_100_continue_ = false;
            return false;
        }

        const bool should_close = NormalizeOutgoingResponse(
            response, req.keep_alive, req.http_minor);

        // RFC 7231 §4.3.2: HEAD responses carry the GET headers (including
        // Content-Length) but MUST NOT include a body. Serialize first so
        // the framework's auto-computed Content-Length is preserved, then
        // strip the body from the wire.
        if (req.method == "HEAD") {
            response.Version(1, current_http_minor_);
            std::string wire = response.Serialize();
            StripResponseBodyForHead(wire);
            conn_->SendRaw(wire.data(), wire.size());
        } else {
            SendResponse(response);
        }

        // If SendResponse triggered a connection close (e.g., EPIPE),
        // stop processing pipelined requests.
        if (conn_->IsClosing()) {
            return false;
        }

        if (should_close) {
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

        // Count early-rejected requests for stats consistency — these are
        // valid request attempts rejected based on header content, before the
        // body arrives. Matches HandleCompleteRequest + HandleParseError counting.
        auto count_request = [this]() {
            if (callbacks_.request_count_callback)
                callbacks_.request_count_callback();
        };

        // Early reject: unsupported HTTP version
        if (partial.http_major != 1 ||
            (partial.http_minor != 0 && partial.http_minor != 1)) {
            logging::Get()->warn("Early reject: unsupported HTTP version fd={}",
                                 conn_->fd());
            count_request();
            HttpResponse ver_resp = HttpResponse::HttpVersionNotSupported();
            ver_resp.Header("Connection", "close");
            SendResponse(ver_resp);
            CloseConnection();
            return;
        }

        // Early reject: HTTP/1.1 missing Host
        if (partial.http_minor >= 1 && !partial.HasHeader("host")) {
            logging::Get()->debug("Early reject: missing Host fd={}", conn_->fd());
            count_request();
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
            count_request();
            HttpResponse err = HttpResponse::PayloadTooLarge();
            err.Header("Connection", "close");
            SendResponse(err);
            CloseConnection();
            return;
        }

        // RFC 7231 §5.1.1: handle Expect header
        if (partial.HasHeader("expect")) {
            std::string expect = partial.GetHeader("expect");
            std::transform(expect.begin(), expect.end(), expect.begin(), [](unsigned char c){ return std::tolower(c); });
            // Trim OWS (SP/HTAB per RFC 7230 §3.2.3)
            while (!expect.empty() && (expect.front() == ' ' || expect.front() == '\t'))
                expect.erase(expect.begin());
            while (!expect.empty() && (expect.back() == ' ' || expect.back() == '\t'))
                expect.pop_back();
            if (expect == "100-continue") {
                // Don't send 100 Continue for WebSocket upgrade requests —
                // WebSocketHandshake::Validate() rejects body-bearing
                // upgrades, so acknowledging the body is contradictory.
                // llhttp sets upgrade=1 on both WebSocket GET and CONNECT.
                // Only reject Expect: 100-continue for actual WS upgrades
                // (GET). CONNECT with Expect is a valid HTTP/1.1 pattern.
                if (partial.upgrade && partial.method == "GET") {
                    count_request();
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
                count_request();
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

    // If an async response is still pending, buffer the incoming bytes
    // instead of parsing new requests. This preserves HTTP/1 response
    // ordering on keep-alive connections: a pipelined request MUST NOT
    // be answered before the deferred response in front of it has been
    // sent. CompleteAsyncResponse feeds this buffer back through
    // OnRawData once the deferred response is delivered.
    //
    // NetServer clears the input buffer after on_message_callback returns,
    // so without this stash the pipelined bytes would be lost entirely.
    if (deferred_response_pending_) {
        StashDeferredBytes(data);
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
