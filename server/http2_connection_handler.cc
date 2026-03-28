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

    // Install HTTP/2 deadline timeout callback. When the deadline fires,
    // RST expired streams instead of closing the whole connection.
    // Returns true (handled) if any streams remain after RST, keeping
    // the connection alive for healthy streams.
    if (request_timeout_sec_ > 0) {
        std::weak_ptr<Http2ConnectionHandler> weak_self = weak_from_this();
        conn_->SetDeadlineTimeoutCb([weak_self]() -> bool {
            auto self = weak_self.lock();
            if (!self || !self->session_) return false;

            size_t reset = self->session_->ResetExpiredStreams(
                self->request_timeout_sec_);
            if (reset > 0) {
                self->session_->SendPendingFrames();
            }
            // Handle graceful shutdown on dispatcher thread
            if (self->shutdown_requested_.load(std::memory_order_acquire) &&
                !self->session_->IsGoawaySent()) {
                self->session_->SendGoaway(HTTP2_CONSTANTS::ERROR_NO_ERROR);
                self->session_->SendPendingFrames();
            }

            self->UpdateDeadline();

            // Preface-only idle client — close
            if (self->session_->LastStreamId() == 0) {
                return false;
            }

            // During shutdown: if all active streams completed, close now.
            if (self->shutdown_requested_.load(std::memory_order_acquire) &&
                self->session_->ActiveStreamCount() == 0) {
                return false;  // Quiescent — proceed with close
            }

            // Otherwise keep connection alive (deadline re-armed or idle).
            return self->session_->IsAlive();
        });

        // Arm initial deadline for SETTINGS exchange / first request.
        conn_->SetDeadline(std::chrono::steady_clock::now() +
                           std::chrono::seconds(request_timeout_sec_));
        deadline_armed_ = true;
    }

    // If there's initial data (buffered during detection), process it now
    if (!initial_data.empty()) {
        ssize_t consumed = session_->ReceiveData(initial_data.data(),
                                                  initial_data.size());
        if (consumed < 0) {
            logging::Get()->error("HTTP/2 initial data processing failed");
            // Flush any queued error frames (GOAWAY from flood detection, etc.)
            // before closing, so the peer sees the HTTP/2 error rather than
            // a bare TCP close.
            session_->SendPendingFrames();
            conn_->CloseAfterWrite();
            return;
        }

        // Dispatch any complete requests from initial data
        DispatchPendingRequests();

        // Send any pending frames (SETTINGS ACK, responses, etc.)
        session_->SendPendingFrames();

        UpdateDeadline();
    }
}

void Http2ConnectionHandler::OnRawData(
    std::shared_ptr<ConnectionHandler> conn, std::string& data) {

    if (!initialized_ || !session_) {
        logging::Get()->error("HTTP/2 OnRawData called before Initialize()");
        return;
    }

    // Handle pending shutdown request (from Stop()) on the dispatcher thread.
    // Send GOAWAY, then let existing streams drain. New stream creation is
    // blocked in OnBeginHeadersCallback via the goaway_sent_ flag.
    if (shutdown_requested_.load(std::memory_order_acquire) &&
        session_ && !session_->IsGoawaySent()) {
        session_->SendGoaway(HTTP2_CONSTANTS::ERROR_NO_ERROR);
        session_->SendPendingFrames();
    }

    // Feed data to nghttp2 — during shutdown drain, we continue processing
    // frames so that WINDOW_UPDATE/SETTINGS/RST_STREAM reach nghttp2 and
    // in-flight responses can complete.
    ssize_t consumed = session_->ReceiveData(data.data(), data.size());
    if (consumed < 0) {
        // ReceiveData failures are almost always caused by malformed peer
        // frames (bad preface, protocol violations, etc.). Use PROTOCOL_ERROR
        // so clients get the correct retry/diagnostic signal.
        logging::Get()->error("HTTP/2 session recv error, closing connection");
        session_->SendGoaway(HTTP2_CONSTANTS::ERROR_PROTOCOL_ERROR);
        session_->SendPendingFrames();
        conn_->CloseAfterWrite();
        return;
    }

    // Dispatch any complete requests
    DispatchPendingRequests();

    // Send pending frames (responses, WINDOW_UPDATEs, etc.)
    session_->SendPendingFrames();

    // Manage deadline based on the OLDEST incomplete stream's creation time.
    // The deadline = oldest_start + request_timeout_sec. New streams cannot
    // extend the deadline for older stalled streams, which closes the bypass
    // where fresh streams keep a stalled stream alive indefinitely.
    UpdateDeadline();

    // Check if session wants to close
    if (!session_->IsAlive()) {
        conn_->CloseAfterWrite();
        return;
    }

    // During shutdown drain: close once all active streams have completed.
    if (shutdown_requested_.load(std::memory_order_acquire) &&
        session_->ActiveStreamCount() == 0) {
        conn_->CloseAfterWrite();
    }
}

void Http2ConnectionHandler::RequestShutdown() {
    shutdown_requested_.store(true, std::memory_order_release);
    if (!conn_) return;

    // Send a raw GOAWAY frame via SendRaw (thread-safe via EnQueue).
    // We can't use nghttp2 here (not thread-safe), so we manually
    // serialize the GOAWAY frame (fixed format, 17 bytes total).
    // last_stream_id_ is atomic, safe to read from any thread.
    int32_t last_id = session_ ? session_->LastStreamId() : 0;
    uint8_t goaway[17] = {
        0x00, 0x00, 0x08,              // Length: 8 bytes payload
        0x07,                           // Type: GOAWAY
        0x00,                           // Flags: none
        0x00, 0x00, 0x00, 0x00,        // Stream ID: 0 (connection-level)
        // Last-Stream-ID (4 bytes, network byte order)
        static_cast<uint8_t>((last_id >> 24) & 0x7F),  // clear R bit
        static_cast<uint8_t>((last_id >> 16) & 0xFF),
        static_cast<uint8_t>((last_id >> 8) & 0xFF),
        static_cast<uint8_t>(last_id & 0xFF),
        // Error Code: NO_ERROR (0x00000000)
        0x00, 0x00, 0x00, 0x00
    };
    conn_->SendRaw(reinterpret_cast<const char*>(goaway), sizeof(goaway));
    conn_->CloseAfterWrite();
}

void Http2ConnectionHandler::DispatchPendingRequests() {
    // No-op: request dispatch happens synchronously during ReceiveData via
    // nghttp2's on_frame_recv_callback, which invokes the request_callback
    // and queues the response through SubmitResponse. SendPendingFrames()
    // called after ReceiveData flushes the queued frames.
}

void Http2ConnectionHandler::UpdateDeadline() {
    if (request_timeout_sec_ <= 0 || !session_) return;

    auto oldest = session_->OldestIncompleteStreamStart();
    if (oldest != std::chrono::steady_clock::time_point::max()) {
        // Set deadline based on the oldest incomplete stream's start time.
        // New streams cannot extend the deadline for older stalled streams.
        auto deadline = oldest + std::chrono::seconds(request_timeout_sec_);
        // Only call SetDeadline when the value actually changes to avoid
        // unnecessary atomic operations on every frame batch.
        if (!deadline_armed_ || deadline != last_deadline_) {
            conn_->SetDeadline(deadline);
            deadline_armed_ = true;
            last_deadline_ = deadline;
        }
    } else if (deadline_armed_ && session_->LastStreamId() > 0) {
        // No incomplete streams and streams were seen — idle keep-alive
        conn_->ClearDeadline();
        deadline_armed_ = false;
    }
    // If no streams ever opened (preface-only), keep the initial deadline.
}
