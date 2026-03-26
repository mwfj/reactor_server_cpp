#include "http2/http2_connection_handler.h"
#include "http/http_response.h"
#include "log/logger.h"

// nghttp2 error codes used for GOAWAY/RST_STREAM.
// Duplicated here to avoid including nghttp2.h in this file.
// Values from nghttp2.h (RFC 9113 Section 7).
static constexpr uint32_t H2_NO_ERROR        = 0x0;
static constexpr uint32_t H2_INTERNAL_ERROR  = 0x2;

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

    // Apply stored callbacks, then clear them (no longer needed)
    if (pending_request_cb_) {
        session_->SetRequestCallback(std::move(pending_request_cb_));
        pending_request_cb_ = nullptr;
    }
    if (pending_stream_close_cb_) {
        session_->SetStreamCloseCallback(std::move(pending_stream_close_cb_));
        pending_stream_close_cb_ = nullptr;
    }

    // Apply limits
    if (max_body_size_ > 0) {
        session_->SetMaxBodySize(max_body_size_);
    }
    if (max_header_size_ > 0) {
        session_->SetMaxHeaderListSize(max_header_size_);
    }

    // Send server connection preface (SETTINGS)
    session_->SendServerPreface();

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
        session_->SendGoaway(H2_INTERNAL_ERROR);
        session_->SendPendingFrames();
        conn_->CloseAfterWrite();
        return;
    }

    // Dispatch any complete requests
    DispatchPendingRequests();

    // Send pending frames (responses, WINDOW_UPDATEs, etc.)
    session_->SendPendingFrames();

    // Check if session wants to close
    if (!session_->IsAlive()) {
        conn_->CloseAfterWrite();
    }
}

void Http2ConnectionHandler::SendGoaway() {
    if (session_) {
        session_->SendGoaway(H2_NO_ERROR);
        session_->SendPendingFrames();
    }
}

void Http2ConnectionHandler::DispatchPendingRequests() {
    // No-op: request dispatch happens synchronously during ReceiveData via
    // nghttp2's on_frame_recv_callback, which invokes the request_callback
    // and queues the response through SubmitResponse. SendPendingFrames()
    // called after ReceiveData flushes the queued frames.
}
