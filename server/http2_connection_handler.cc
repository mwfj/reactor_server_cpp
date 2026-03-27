#include "http2/http2_connection_handler.h"
#include "http/http_response.h"
#include "log/logger.h"

Http2ConnectionHandler::Http2ConnectionHandler(
    std::shared_ptr<ConnectionHandler> conn,
    const Http2Session::Settings& settings)
    : conn_(std::move(conn))
    , settings_(settings) {}

Http2ConnectionHandler::~Http2ConnectionHandler() = default;

void Http2ConnectionHandler::SetRequestCallback(RequestCallback callback) {
    pending_request_cb_ = callback;  // Store for Initialize()
    if (session_) {
        session_->SetRequestCallback(std::move(callback));
    }
}

void Http2ConnectionHandler::SetStreamCloseCallback(StreamCloseCallback callback) {
    pending_stream_close_cb_ = callback;  // Store for Initialize()
    if (session_) {
        session_->SetStreamCloseCallback(std::move(callback));
    }
}

void Http2ConnectionHandler::SetMaxBodySize(size_t max) {
    max_body_size_ = max;
    if (session_) {
        session_->SetMaxBodySize(max);
    }
}

void Http2ConnectionHandler::SetMaxHeaderSize(size_t max) {
    max_header_size_ = max;
    if (session_) {
        session_->SetMaxHeaderListSize(max);
    }
}

void Http2ConnectionHandler::Initialize(const std::string& initial_data) {
    if (initialized_) return;
    initialized_ = true;

    // Create the HTTP/2 session
    session_ = std::make_unique<Http2Session>(conn_, settings_);
    session_->SetOwner(weak_from_this());

    // Apply stored callbacks, then clear them (no longer needed)
    if (pending_request_cb_) {
        session_->SetRequestCallback(std::move(pending_request_cb_));
        pending_request_cb_ = nullptr;
    }
    if (pending_stream_close_cb_) {
        session_->SetStreamCloseCallback(std::move(pending_stream_close_cb_));
        pending_stream_close_cb_ = nullptr;
    }

    // Apply body size limit. Header list size comes from h2_settings_
    // (passed to Http2Session constructor) and is advertised in SETTINGS.
    if (max_body_size_ > 0) {
        session_->SetMaxBodySize(max_body_size_);
    }

    // Send server connection preface (SETTINGS)
    session_->SendServerPreface();

    // Arm deadline for the initial SETTINGS exchange / first request.
    // Will be managed by UpdateDeadline() based on active stream count.
    if (request_timeout_sec_ > 0) {
        conn_->SetDeadline(std::chrono::steady_clock::now() +
                           std::chrono::seconds(request_timeout_sec_));
    }

    // If there's initial data (buffered during detection), process it now
    if (!initial_data.empty()) {
        ssize_t consumed = session_->ReceiveData(initial_data.data(),
                                                  initial_data.size());
        if (consumed < 0) {
            logging::Get()->error("HTTP/2 initial data processing failed");
            conn_->CloseAfterWrite();
            return;
        }

        // Dispatch any complete requests from initial data
        DispatchPendingRequests();

        // Send any pending frames (SETTINGS ACK, responses, etc.)
        session_->SendPendingFrames();

        // Update deadline based on what initial_data contained:
        // - If streams are still open → reset deadline (active request)
        // - If streams opened AND completed → clear deadline (idle keep-alive)
        // - If no streams opened (preface-only) → keep deadline armed
        //   (client must send a request within request_timeout_sec)
        if (request_timeout_sec_ > 0 && session_->ActiveStreamCount() > 0) {
            conn_->SetDeadline(std::chrono::steady_clock::now() +
                               std::chrono::seconds(request_timeout_sec_));
        } else if (request_timeout_sec_ > 0 && session_->LastStreamId() > 0 &&
                   session_->ActiveStreamCount() == 0) {
            // Streams were processed and completed — idle keep-alive
            conn_->ClearDeadline();
        }
        // else: preface-only, no streams seen yet — keep original deadline
    }
}

void Http2ConnectionHandler::OnRawData(
    std::shared_ptr<ConnectionHandler> conn, std::string& data) {

    if (!initialized_ || !session_) {
        logging::Get()->error("HTTP/2 OnRawData called before Initialize()");
        return;
    }

    // Feed data to nghttp2
    ssize_t consumed = session_->ReceiveData(data.data(), data.size());
    if (consumed < 0) {
        logging::Get()->error("HTTP/2 session error, closing connection");
        session_->SendGoaway(HTTP2_CONSTANTS::ERROR_INTERNAL_ERROR);
        session_->SendPendingFrames();
        conn_->CloseAfterWrite();
        return;
    }

    // Dispatch any complete requests
    DispatchPendingRequests();

    // Send pending frames (responses, WINDOW_UPDATEs, etc.)
    session_->SendPendingFrames();

    // Manage deadline based on active stream count:
    // - If streams are open, reset the deadline (data arrived, connection active)
    // - If no streams remain, clear the deadline — let idle_timeout handle it
    //   (prevents killing healthy keep-alive h2 connections after request_timeout)
    if (request_timeout_sec_ > 0) {
        if (session_->ActiveStreamCount() > 0) {
            conn_->SetDeadline(std::chrono::steady_clock::now() +
                               std::chrono::seconds(request_timeout_sec_));
        } else {
            conn_->ClearDeadline();
        }
    }

    // Check if session wants to close
    if (!session_->IsAlive()) {
        conn_->CloseAfterWrite();
    }
}

void Http2ConnectionHandler::SendGoaway() {
    if (session_) {
        conn_->ClearDeadline();
        session_->SendGoaway(HTTP2_CONSTANTS::ERROR_NO_ERROR);
        session_->SendPendingFrames();
    }
}

void Http2ConnectionHandler::DispatchPendingRequests() {
    // No-op: request dispatch happens synchronously during ReceiveData via
    // nghttp2's on_frame_recv_callback, which invokes the request_callback
    // and queues the response through SubmitResponse. SendPendingFrames()
    // called after ReceiveData flushes the queued frames.
}
