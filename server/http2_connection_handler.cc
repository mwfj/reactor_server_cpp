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

void Http2ConnectionHandler::SetStreamOpenCallback(StreamOpenCallback callback) {
    pending_stream_open_cb_ = callback;  // Store for Initialize()
    if (session_) {
        session_->SetStreamOpenCallback(std::move(callback));
    }
}

void Http2ConnectionHandler::SetRequestCountCallback(
    HTTP2_CALLBACKS_NAMESPACE::Http2RequestCountCallback callback) {
    pending_request_count_cb_ = callback;
    if (session_) {
        session_->SetRequestCountCallback(std::move(callback));
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

void Http2ConnectionHandler::SetMaxAsyncDeferredSec(int sec) {
    max_async_deferred_sec_ = sec;
}

void Http2ConnectionHandler::SetRequestTimeout(int seconds) {
    request_timeout_sec_ = seconds;
    // Reconcile deadline state with the new timeout value. At
    // initialization time deadline_armed_ is false, so this is a no-op.
    // During live reload, stale deadlines must be updated.
    if (!session_) return;  // Initialize() will arm the initial deadline
    if (seconds <= 0 && deadline_armed_) {
        // Timeout disabled — clear the stale deadline first so
        // UpdateDeadline recomputes from scratch. Don't just leave
        // the deadline cleared: when active streams still exist,
        // UpdateDeadline's has_active branch arms the
        // ASYNC_HEARTBEAT_FALLBACK_SEC heartbeat so the deadline-
        // driven timer keeps firing. That heartbeat is the only
        // thing that drives ResetExpiredStreams for the
        // max_async_deferred_sec_ safety cap; without it a stuck
        // async stream could live forever after a live reload from
        // positive → 0 request_timeout_sec.
        conn_->ClearDeadline();
        deadline_armed_ = false;
    }
    // Always recompute. When seconds > 0 this re-anchors parse-timeout
    // and/or heartbeat deadlines. When seconds == 0, UpdateDeadline
    // installs the active-stream heartbeat (or leaves the connection
    // idle if no streams are active).
    UpdateDeadline();
}

void Http2ConnectionHandler::Initialize(const std::string& initial_data) {
    if (initialized_) {
        logging::Get()->debug("H2 Initialize called twice fd={}", conn_ ? conn_->fd() : -1);
        return;
    }
    initialized_ = true;
    initializing_ = true;  // suppress OnSendComplete drain during init

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
    if (pending_stream_open_cb_) {
        session_->SetStreamOpenCallback(std::move(pending_stream_open_cb_));
        pending_stream_open_cb_ = nullptr;
    }
    if (pending_request_count_cb_) {
        session_->SetRequestCountCallback(std::move(pending_request_count_cb_));
        pending_request_count_cb_ = nullptr;
    }

    // Apply body size limit. Header list size comes from h2_settings_
    // (passed to Http2Session constructor) and is advertised in SETTINGS.
    if (max_body_size_ > 0) {
        session_->SetMaxBodySize(max_body_size_);
    }

    // Send server connection preface (SETTINGS)
    session_->SendServerPreface();

    // Install HTTP/2 deadline timeout callback. Always installed (not gated
    // on request_timeout_sec_) because it also handles shutdown drain logic.
    // Per-stream RST only runs when request_timeout_sec_ > 0.
    {
        std::weak_ptr<Http2ConnectionHandler> weak_self = weak_from_this();
        conn_->SetDeadlineTimeoutCb([weak_self]() -> bool {
            auto self = weak_self.lock();
            if (!self || !self->session_) return false;

            // ResetExpiredStreams enforces two independent caps:
            //   - parse_timeout: request_timeout_sec (0 = skip).
            //   - async_cap: max_async_deferred_sec (0 = skip). This
            //     is a last-resort safety net for async streams whose
            //     handler never submits a response.
            // Run whenever either is set so the async cap still applies
            // when request_timeout_sec is disabled. The async-cap-reset
            // stream IDs are captured so we can fire per-stream abort
            // hooks — without that, a stuck handler's stored complete()
            // closure would keep active_requests_ elevated even after
            // the stream has been RST'd off the wire.
            size_t reset = 0;
            std::vector<int32_t> async_cap_reset_ids;
            if (self->request_timeout_sec_ > 0 ||
                self->max_async_deferred_sec_ > 0) {
                reset = self->session_->ResetExpiredStreams(
                    self->request_timeout_sec_,
                    self->max_async_deferred_sec_,
                    &async_cap_reset_ids);
                if (reset > 0) {
                    self->session_->SendPendingFrames();
                }
                for (int32_t id : async_cap_reset_ids) {
                    self->FireAndEraseStreamAbortHook(id);
                }
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

            // During shutdown: if all active streams completed, start flushing.
            // NotifyDrainComplete deferred to OnSendComplete (wire drain).
            if (self->shutdown_requested_.load(std::memory_order_acquire) &&
                self->session_->ActiveStreamCount() == 0 &&
                !self->drain_notified_) {
                self->conn_->CloseAfterWrite();
                return true;  // keep alive until OnSendComplete fires
            }

            // During shutdown drain, keep alive until all streams finish
            // (WaitForH2Drain provides the bounded timeout, not idle timeout).
            if (self->shutdown_requested_.load(std::memory_order_acquire)) {
                return true;
            }

            // If we just reset expired streams, keep the connection alive.
            // Re-arm a safety deadline only when the connection is truly idle
            // (no incomplete AND no active streams) to handle idle_timeout_sec=0.
            // Don't re-arm when active streams exist — the connection-wide
            // deadline would tear down healthy sibling streams.
            if (reset > 0) {
                if (!self->deadline_armed_ && self->request_timeout_sec_ > 0 &&
                    self->session_->ActiveStreamCount() == 0) {
                    self->conn_->SetDeadline(
                        std::chrono::steady_clock::now() +
                        std::chrono::seconds(self->request_timeout_sec_));
                    self->deadline_armed_ = true;
                }
                return true;
            }

            // deadline_armed_ reflects whether incomplete streams exist.
            // If true, keep alive. If false, let idle timeout proceed.
            return self->deadline_armed_;
        });
    }

    // Arm initial deadline for SETTINGS exchange / first request.
    if (request_timeout_sec_ > 0) {
        conn_->SetDeadline(std::chrono::steady_clock::now() +
                           std::chrono::seconds(request_timeout_sec_));
        deadline_armed_ = true;
    }

    // If there's initial data (buffered during detection), process it now.
    // This MUST happen before GOAWAY: requests in the buffered packet were
    // already accepted (the client sent them before the server announced
    // shutdown). Sending GOAWAY first would reject them with REFUSED_STREAM,
    // which is the opposite of graceful drain.
    if (!initial_data.empty()) {
        ssize_t consumed = session_->ReceiveData(initial_data.data(),
                                                  initial_data.size());
        if (consumed < 0) {
            logging::Get()->error("HTTP/2 initial data processing failed");
            initializing_ = false;
            session_->SendPendingFrames();
            conn_->CloseAfterWrite();
            return;
        }

        // Send any pending frames (SETTINGS ACK, responses, etc.)
        session_->SendPendingFrames();

        UpdateDeadline();
    }

    // If shutdown was requested before session_ existed (race with Stop()),
    // replay the shutdown now. Done AFTER initial_data processing so any
    // buffered request is dispatched before GOAWAY closes the session.
    if (shutdown_requested_.load(std::memory_order_acquire)) {
        logging::Get()->debug("H2 shutdown replay: sending GOAWAY fd={}", conn_ ? conn_->fd() : -1);
        if (!session_->IsGoawaySent()) {
            session_->SendGoaway(HTTP2_CONSTANTS::ERROR_NO_ERROR);
            session_->SendPendingFrames();
        }
        if (session_->ActiveStreamCount() == 0) {
            // Flush deferred output BEFORE arming CloseAfterWrite.
            // If the initial request's response or the GOAWAY write hit
            // nghttp2's high-water mark, SendPendingFrames left deferred
            // output queued. CloseAfterWrite suppresses OnSendComplete,
            // so those deferred frames would never be resumed and the
            // tail of a large first response would be silently dropped.
            if (session_->HasDeferredOutput()) {
                session_->ResumeOutput();
            }
            conn_->CloseAfterWrite();
        }
    }
    initializing_ = false;
}

void Http2ConnectionHandler::OnRawData(
    std::shared_ptr<ConnectionHandler> conn, std::string& data) {

    if (!initialized_ || !session_) {
        logging::Get()->error("HTTP/2 OnRawData called before Initialize()");
        return;
    }

    // If shutdown requested but GOAWAY not yet sent (RequestShutdown's enqueued
    // task hasn't run yet), send it now before feeding new frames. This prevents
    // HEADERS in the current batch from being accepted as new requests.
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
        logging::Get()->error("HTTP/2 session recv error fd={}, closing connection",
                              conn_ ? conn_->fd() : -1);
        // Flush ALL deferred response frames before GOAWAY. A single
        // ResumeOutput may not drain everything under backpressure (nghttp2
        // defers when the output buffer is full). Loop until empty so
        // CloseAfterWrite (which suppresses complete_callback) doesn't
        // strand remaining frames.
        resume_scheduled_ = false;
        static constexpr int MAX_RESUME_ROUNDS = 64;  // prevent infinite loop
        for (int i = 0; i < MAX_RESUME_ROUNDS && session_->HasDeferredOutput(); ++i) {
            session_->ResumeOutput();
        }
        if (session_->HasDeferredOutput()) {
            // Still deferred after max rounds — drop remaining to avoid hang
            session_->ClearDeferredOutput();
        }
        session_->SendGoaway(HTTP2_CONSTANTS::ERROR_PROTOCOL_ERROR);
        session_->SendPendingFrames();
        conn_->CloseAfterWrite();
        return;
    }

    // Send pending frames (responses, WINDOW_UPDATEs, etc.)
    session_->SendPendingFrames();

    // Manage deadline based on the OLDEST incomplete stream's creation time.
    // The deadline = oldest_start + request_timeout_sec. New streams cannot
    // extend the deadline for older stalled streams, which closes the bypass
    // where fresh streams keep a stalled stream alive indefinitely.
    UpdateDeadline();

    // Check if session wants to close
    if (!session_->IsAlive()) {
        logging::Get()->debug("H2 session not alive fd={}, closing", conn_ ? conn_->fd() : -1);
        conn_->CloseAfterWrite();
        return;
    }

    // During shutdown drain: when all streams complete, start flushing.
    // If deferred output exists, resume it first — CloseAfterWrite skips
    // complete_callback so OnSendComplete would never fire to pull remaining
    // frames. Only close once nghttp2 has no more deferred output.
    if (shutdown_requested_.load(std::memory_order_acquire) &&
        session_->ActiveStreamCount() == 0 && !drain_notified_) {
        if (session_->HasDeferredOutput()) {
            session_->ResumeOutput();
        }
        if (!session_->HasDeferredOutput()) {
            conn_->CloseAfterWrite();
        }
        // else: still deferred — OnSendComplete/OnWriteProgress will retry
    }
}

void Http2ConnectionHandler::RequestShutdown() {
    if (shutdown_requested_.exchange(true)) return;  // already requested
    if (!conn_) return;
    logging::Get()->debug("H2 shutdown requested fd={}", conn_->fd());

    // Enqueue GOAWAY + drain check on the dispatcher thread.
    // RunOnDispatcher uses EnQueue — runs on the next event loop iteration.
    // This avoids touching nghttp2 from the stopper thread.
    std::weak_ptr<Http2ConnectionHandler> weak_self = weak_from_this();
    conn_->RunOnDispatcher([weak_self]() {
        auto self = weak_self.lock();
        if (!self || !self->session_) return;

        // Send GOAWAY via nghttp2 (on dispatcher thread — safe)
        if (!self->session_->IsGoawaySent()) {
            self->session_->SendGoaway(HTTP2_CONSTANTS::ERROR_NO_ERROR);
            self->session_->SendPendingFrames();
        }

        // If already idle, start flushing GOAWAY. If deferred output
        // exists (watermark hit), resume it first — CloseAfterWrite skips
        // complete_callback so OnSendComplete would never flush deferred frames.
        if (self->session_->ActiveStreamCount() == 0) {
            if (self->session_->HasDeferredOutput()) {
                self->session_->ResumeOutput();
            }
            if (!self->session_->HasDeferredOutput()) {
                self->conn_->CloseAfterWrite();
            }
            // else: still deferred — OnSendComplete/OnWriteProgress will retry
        }
        // else: active streams exist — drain continues via OnRawData.
        // They'll call NotifyDrainComplete when ActiveStreamCount() == 0.
    });
}

void Http2ConnectionHandler::SetDrainCompleteCallback(DrainCompleteCallback cb) {
    drain_complete_cb_ = std::move(cb);
}

void Http2ConnectionHandler::SubmitStreamResponse(int32_t stream_id,
                                                  const HttpResponse& response) {
    if (!session_) {
        logging::Get()->warn(
            "SubmitStreamResponse called on destroyed H2 session (stream={})",
            stream_id);
        return;
    }
    session_->SubmitResponse(stream_id, response);
    // Flush nghttp2's outgoing frame queue onto the transport. The sync H2
    // path hits the SendPendingFrames call at the tail of OnRawData after
    // ReceiveData → OnRequest → SubmitResponse returns. Async completions
    // come from outside that loop (user code via RunOnDispatcher), so if
    // we don't flush here the response sits queued until some unrelated
    // inbound frame, shutdown, or timeout happens to flush it — hanging
    // any async H2 route.
    session_->SendPendingFrames();

    // Check if this async response was the last active stream during a
    // graceful shutdown drain. The normal drain check in OnRawData runs
    // after ReceiveData, but async completions arrive via RunOnDispatcher
    // — no inbound data triggers OnRawData. OnSendComplete can also miss
    // this: it fires when the output buffer empties, but the stream close
    // callback inside nghttp2_session_send (called by SendPendingFrames)
    // fires during the send, before FlushDeferredRemovals updates
    // ActiveStreamCount. By the time SendPendingFrames returns, the count
    // IS updated, but OnSendComplete already ran and saw a stale count.
    // Without this check, the connection waits until the drain timeout.
    if (shutdown_requested_.load(std::memory_order_acquire) &&
        session_->ActiveStreamCount() == 0 && !drain_notified_) {
        // Do NOT call UpdateDeadline() here. Clearing has_deadline_ during
        // shutdown drain would expose the connection to idle-timeout closure
        // while response/GOAWAY bytes are still buffered to a slow client.
        // The existing deadline keeps has_deadline_ true, which suppresses
        // idle timeout in IsTimeOut(). NotifyDrainComplete → CloseAfterWrite
        // takes over the connection lifecycle once all bytes are flushed.
        if (session_->HasDeferredOutput()) {
            session_->ResumeOutput();
        }
        // Only signal drain completion if the transport output buffer is
        // also empty. SendPendingFrames may have written response/GOAWAY
        // bytes that haven't been flushed to the kernel yet (slow client,
        // backpressure). NotifyDrainComplete fires drain_complete_cb_
        // which releases WaitForH2Drain → NetServer::Stop proceeds →
        // StopEventLoop can run before the buffered bytes are written.
        // When the buffer IS non-empty, OnSendComplete will fire once
        // the write completes and re-check this same condition — at that
        // point OutputBufferSize() is guaranteed 0 because OnSendComplete
        // only fires on a fully-drained buffer.
        if (!session_->HasDeferredOutput() && !session_->WantWrite() &&
            conn_->OutputBufferSize() == 0) {
            NotifyDrainComplete();
        }
    } else {
        // Normal operation or shutdown with active streams remaining:
        // recompute deadline so it tracks the oldest incomplete stream,
        // or clears it when no streams remain (idle keep-alive).
        UpdateDeadline();
    }
}

void Http2ConnectionHandler::NotifyDrainComplete() {
    if (drain_notified_) return;
    drain_notified_ = true;
    logging::Get()->debug("H2 drain complete fd={}", conn_ ? conn_->fd() : -1);
    resume_scheduled_ = false;  // no more resumes needed
    conn_->CloseAfterWrite();
    if (drain_complete_cb_) {
        try { drain_complete_cb_(); }
        catch (const std::exception& e) {
            logging::Get()->error("Exception in H2 drain-complete callback: {}", e.what());
        }
        catch (...) {
            logging::Get()->error("Unknown exception in H2 drain-complete callback");
        }
    }
}

void Http2ConnectionHandler::OnSendComplete() {
    if (!session_) return;
    // Suppress during Initialize() — SendServerPreface can trigger this
    // callback synchronously before initial_data is processed.
    if (initializing_) return;

    // If deferred output exists, resume — pull remaining frames from nghttp2.
    if (session_->HasDeferredOutput()) {
        if (resume_scheduled_) return;
        resume_scheduled_ = true;
        std::weak_ptr<Http2ConnectionHandler> weak_self = weak_from_this();
        conn_->RunOnDispatcher([weak_self]() {
            auto self = weak_self.lock();
            if (!self) return;
            self->resume_scheduled_ = false;
            if (!self->session_) return;
            self->session_->ResumeOutput();
            // If ResumeOutput added bytes, the next OnSendComplete (buffer
            // empty) will re-check. But if it was a no-op (mem_send2==0 and
            // buffer already empty), no write event will fire, so check now.
            if (self->conn_->OutputBufferSize() == 0) {
                self->OnSendComplete();  // re-enter — resume_scheduled_ is false
            }
        });
        return;
    }

    // Output buffer drained to zero AND no deferred nghttp2 frames AND
    // nghttp2 has nothing more to send. All bytes are on the wire.
    // If shutdown drain is active and all streams completed, drain is done.
    if (shutdown_requested_.load(std::memory_order_acquire) &&
        session_->ActiveStreamCount() == 0 &&
        !resume_scheduled_ &&
        !session_->HasDeferredOutput() &&
        !session_->WantWrite()) {
        NotifyDrainComplete();
    }
}

void Http2ConnectionHandler::OnWriteProgress(size_t remaining_bytes) {
    if (!session_ || initializing_) return;
    // Resume deferred output when buffer drops below the high watermark.
    // This lets multiplexed streams make progress without waiting for the
    // buffer to fully drain to zero.
    if (session_->HasDeferredOutput() &&
        remaining_bytes <= session_->OutputHighWatermark()) {
        if (resume_scheduled_) return;
        resume_scheduled_ = true;
        std::weak_ptr<Http2ConnectionHandler> weak_self = weak_from_this();
        conn_->RunOnDispatcher([weak_self]() {
            auto self = weak_self.lock();
            if (!self) return;
            self->resume_scheduled_ = false;
            if (self->session_) {
                self->session_->ResumeOutput();
            }
        });
    }
}


void Http2ConnectionHandler::UpdateDeadline() {
    if (!session_) return;

    auto oldest = session_->OldestIncompleteStreamStart();
    bool has_incomplete =
        (oldest != std::chrono::steady_clock::time_point::max());
    bool has_active = (session_->ActiveStreamCount() > 0);

    // Fallback heartbeat interval used when request_timeout_sec is disabled
    // (0) but active streams still need idle_timeout suppression.
    static constexpr int ASYNC_HEARTBEAT_FALLBACK_SEC = 60;

    if (has_incomplete && request_timeout_sec_ > 0) {
        // Per-stream request-parsing timeout — anchor at the oldest
        // incomplete stream's creation time. New streams cannot extend
        // the deadline for older stalled streams.
        auto deadline = oldest + std::chrono::seconds(request_timeout_sec_);
        if (!deadline_armed_ || deadline != last_deadline_) {
            conn_->SetDeadline(deadline);
            deadline_armed_ = true;
            last_deadline_ = deadline;
        }
    } else if (has_active) {
        // Either:
        //  (a) has_incomplete && request_timeout_sec_ == 0 — no hard parse
        //      timeout, but we still need to suppress idle_timeout so
        //      slow-but-legitimate parses aren't dropped.
        //  (b) !has_incomplete — all streams are past parsing and waiting
        //      on async handler work (e.g., proxy upstream response).
        // In both cases, arm a rolling heartbeat deadline from NOW. The
        // actual response-wait bound is enforced by the handler itself
        // (proxy.response_timeout_ms for proxies). When this heartbeat
        // fires and streams are still active, the timeout callback
        // re-arms it — effectively a keep-alive.
        //
        // NOTE: This branch is ALSO reached when request_timeout_sec_ == 0
        // and has_incomplete is true. Without this, a stale heartbeat
        // from a prior "all-active" state could expire and keep firing
        // the callback every scan tick, because the incomplete branch
        // above wouldn't touch the deadline — creating a tight retry
        // loop where the deadline stays in the past.
        int heartbeat_sec = request_timeout_sec_ > 0
                          ? request_timeout_sec_
                          : ASYNC_HEARTBEAT_FALLBACK_SEC;
        auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::seconds(heartbeat_sec);
        conn_->SetDeadline(deadline);
        deadline_armed_ = true;
        last_deadline_ = deadline;
    } else if (deadline_armed_ && session_->LastStreamId() > 0) {
        // No active streams at all — idle keep-alive, let idle_timeout
        // take over.
        conn_->ClearDeadline();
        deadline_armed_ = false;
    }
    // If no streams ever opened (preface-only), keep the initial deadline.
}
