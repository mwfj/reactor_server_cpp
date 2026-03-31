#include "http2/http2_session.h"
#include "http2/http2_connection_handler.h"
#include "http/http_response.h"
#include "log/logger.h"

#include <nghttp2/nghttp2.h>

// --- nghttp2 Pimpl ---

struct Http2Session::Impl {
    nghttp2_session* session = nullptr;
    nghttp2_session_callbacks* callbacks = nullptr;
    nghttp2_option* option = nullptr;

    ~Impl() {
        if (session) nghttp2_session_del(session);
        if (callbacks) nghttp2_session_callbacks_del(callbacks);
        if (option) nghttp2_option_del(option);
    }
};

// Data source read callback: nghttp2 calls this to pull response body chunks.
static ssize_t DataSourceReadCallback(
    nghttp2_session* /*session*/, int32_t /*stream_id*/,
    uint8_t* buf, size_t length, uint32_t* data_flags,
    nghttp2_data_source* source, void* /*user_data*/) {

    auto* src = static_cast<ResponseDataSource*>(source->ptr);
    size_t remaining = src->body.size() - src->offset;
    size_t to_copy = std::min(remaining, length);

    if (to_copy > 0) {
        std::memcpy(buf, src->body.data() + src->offset, to_copy);
        src->offset += to_copy;
    }

    if (src->offset >= src->body.size()) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    }

    return static_cast<ssize_t>(to_copy);
}

// --- Static nghttp2 callback functions ---
// Each retrieves Http2Session* via nghttp2_session_get_user_data().

static int OnBeginHeadersCallback(
    nghttp2_session* session, const nghttp2_frame* frame, void* user_data) {
    auto* self = static_cast<Http2Session*>(user_data);

    if (frame->hd.type != NGHTTP2_HEADERS) {
        return 0;
    }

    if (frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
        // During shutdown drain, reject new streams. Control frames
        // (WINDOW_UPDATE, SETTINGS, RST_STREAM) are still processed so
        // in-flight responses can complete.
        // Also check owner's shutdown_requested_ for the race window where
        // the atomic flag is set but GOAWAY hasn't been submitted yet.
        auto owner = self->Owner();
        // During Initialize (initializing_), don't reject streams based on
        // owner's shutdown flag — the initial_data contains pre-shutdown
        // requests that should be processed. The shutdown replay at the end
        // of Initialize sends GOAWAY after those requests are dispatched.
        bool owner_shutting_down = owner && owner->IsShutdownRequested()
                                   && !owner->IsInitializing();
        // Don't use IsCloseDeferred() here — it's also set on peer EOF,
        // and streams in the same read batch as FIN should be serviced.
        bool shutdown_in_progress = self->IsGoawaySent() ||
            owner_shutting_down;
        if (shutdown_in_progress) {
            logging::Get()->debug("H2 stream {} rejected during shutdown fd={}",
                                  frame->hd.stream_id, self->GetConnection()->fd());
            nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                      frame->hd.stream_id, NGHTTP2_REFUSED_STREAM);
            return 0;
        }

        // New request — create stream
        int32_t stream_id = frame->hd.stream_id;
        auto* stream = self->CreateStream(stream_id);
        if (!stream) {
            logging::Get()->error("H2 failed to create stream {} fd={}",
                                  stream_id, self->GetConnection()->fd());
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        stream->SetState(Http2Stream::State::OPEN);
    } else {
        // Trailer headers — reset per-block header size counter.
        // SETTINGS_MAX_HEADER_LIST_SIZE applies per header block, not
        // cumulatively across all header blocks on a stream.
        auto* stream = self->FindStream(frame->hd.stream_id);
        if (stream) {
            stream->ResetHeaderSize();
        }
    }

    return 0;
}

static int OnHeaderCallback(
    nghttp2_session* session, const nghttp2_frame* frame,
    const uint8_t* name, size_t namelen,
    const uint8_t* value, size_t valuelen,
    uint8_t /*flags*/, void* user_data) {

    auto* self = static_cast<Http2Session*>(user_data);

    if (frame->hd.type != NGHTTP2_HEADERS) {
        return 0;
    }

    auto* stream = self->FindStream(frame->hd.stream_id);
    if (!stream) return 0;

    // Skip remaining headers if this stream was already rejected (RST queued).
    // Without this, a malformed HEADERS block continues accumulating strings
    // past the configured limit until the block ends.
    if (stream->IsRejected()) {
        logging::Get()->debug("H2 stream {} rejected, skipping header fd={}",
                              frame->hd.stream_id, self->GetConnection()->fd());
        return 0;
    }

    // Enforce max_header_list_size on ALL header frames (request + trailers).
    // RFC 7541 Section 4.1: entry size = name + value + 32.
    // nghttp2 advertises this in SETTINGS but does NOT enforce it on the receive side.
    stream->AddHeaderBytes(namelen, valuelen);
    if (self->MaxHeaderListSize() > 0 &&
        stream->AccumulatedHeaderSize() > self->MaxHeaderListSize()) {
        logging::Get()->warn("HTTP/2 stream {} header list size ({}) exceeds limit ({})",
                             frame->hd.stream_id, stream->AccumulatedHeaderSize(),
                             self->MaxHeaderListSize());
        if (!stream->IsRejected() && self->Callbacks().request_count_callback)
            self->Callbacks().request_count_callback();
        stream->MarkRejected();
        nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                  frame->hd.stream_id, NGHTTP2_ENHANCE_YOUR_CALM);
        return 0;
    }

    std::string hdr_name(reinterpret_cast<const char*>(name), namelen);
    std::string hdr_value(reinterpret_cast<const char*>(value), valuelen);

    // Helper: mark stream rejected, submit RST_STREAM(PROTOCOL_ERROR), return 0.
    // We use explicit RST + return 0 instead of NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE
    // because TEMPORAL makes nghttp2 send RST(INTERNAL_ERROR), which misrepresents
    // client protocol violations as server faults. MarkRejected() prevents
    // OnFrameRecvCallback from dispatching the malformed request.
    auto reject_protocol_error = [&]() -> int {
        if (!stream->IsRejected() && self->Callbacks().request_count_callback)
            self->Callbacks().request_count_callback();
        stream->MarkRejected();
        nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                  frame->hd.stream_id, NGHTTP2_PROTOCOL_ERROR);
        return 0;
    };

    // RFC 9113 Section 8.1: trailers MUST NOT contain pseudo-headers.
    // Forbidden connection-level headers are still invalid in trailers.
    if (frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
        if (!hdr_name.empty() && hdr_name[0] == ':') {
            logging::Get()->warn("HTTP/2 stream {} pseudo-header in trailers: {}",
                                 frame->hd.stream_id, hdr_name);
            return reject_protocol_error();
        }
        // RFC 9110 Section 6.5.1: trailers MUST NOT include fields used for
        // message framing, routing, request modifiers, authentication, or
        // representation metadata that must be received before the body.
        if (hdr_name == "connection" || hdr_name == "keep-alive" ||
            hdr_name == "proxy-connection" || hdr_name == "transfer-encoding" ||
            hdr_name == "upgrade" || hdr_name == "te" ||
            hdr_name == "content-length" || hdr_name == "host" ||
            hdr_name == "authorization" || hdr_name == "content-type" ||
            hdr_name == "content-encoding" || hdr_name == "content-range") {
            logging::Get()->warn("HTTP/2 stream {} forbidden header in trailers: {}",
                                 frame->hd.stream_id, hdr_name);
            return reject_protocol_error();
        }
        // Valid trailer field — discard content (application doesn't use trailers)
        return 0;
    }

    // --- Request headers below ---

    // Validate forbidden HTTP/2 connection-level headers (RFC 9113 Section 8.2.2)
    if (hdr_name == "connection" || hdr_name == "keep-alive" ||
        hdr_name == "proxy-connection" || hdr_name == "transfer-encoding" ||
        hdr_name == "upgrade") {
        logging::Get()->warn("HTTP/2 stream {} received forbidden header: {}",
                             frame->hd.stream_id, hdr_name);
        return reject_protocol_error();
    }

    // TE header: only "trailers" is allowed in HTTP/2 (RFC 9113 Section 8.2.2).
    // Trim OWS (RFC 9110 Section 5.5) and compare case-insensitively.
    if (hdr_name == "te") {
        std::string te_lower = hdr_value;
        // Trim leading/trailing whitespace (OWS = SP / HTAB)
        size_t start = te_lower.find_first_not_of(" \t");
        size_t end = te_lower.find_last_not_of(" \t");
        if (start != std::string::npos) {
            te_lower = te_lower.substr(start, end - start + 1);
        }
        std::transform(te_lower.begin(), te_lower.end(), te_lower.begin(), ::tolower);
        if (te_lower != "trailers") {
            logging::Get()->warn("HTTP/2 stream {} received invalid TE value: {}",
                                 frame->hd.stream_id, hdr_value);
            return reject_protocol_error();
        }
    }

    int add_rv = stream->AddHeader(hdr_name, hdr_value);
    if (add_rv != 0) {
        logging::Get()->warn("HTTP/2 stream {} invalid header value for: {}",
                             frame->hd.stream_id, hdr_name);
        return reject_protocol_error();
    }
    return 0;
}

static int OnDataChunkRecvCallback(
    nghttp2_session* session, uint8_t /*flags*/,
    int32_t stream_id, const uint8_t* data, size_t len, void* user_data) {

    auto* self = static_cast<Http2Session*>(user_data);
    auto* stream = self->FindStream(stream_id);
    if (!stream) return 0;

    // Check body size limit
    if (self->MaxBodySize() > 0 &&
        stream->AccumulatedBodySize() + len > self->MaxBodySize()) {
        logging::Get()->warn("HTTP/2 stream {} body exceeds max size ({})",
                             stream_id, self->MaxBodySize());
        // Only count if not already counted/rejected in the HEADERS path
        if (!stream->IsRejected() && self->Callbacks().request_count_callback)
            self->Callbacks().request_count_callback();
        stream->MarkRejected();
        int rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                           stream_id, NGHTTP2_CANCEL);
        if (rv < 0) {
            logging::Get()->error("nghttp2_submit_rst_stream failed: {}", nghttp2_strerror(rv));
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        return 0;
    }

    // Skip body accumulation on rejected streams (RST_STREAM already sent)
    if (stream->IsRejected()) return 0;

    // Reject DATA that exceeds the declared Content-Length, or any DATA
    // when content-length: 0 was declared. Without this, a malformed peer
    // can force unbounded body buffering when max_body_size is high.
    const auto& req = stream->GetRequest();
    bool cl_violated = false;
    if (stream->HasContentLength() && len > 0) {
        if (req.content_length == 0) {
            cl_violated = true;  // content-length: 0 but non-empty DATA
        } else if (stream->AccumulatedBodySize() + len > req.content_length) {
            cl_violated = true;  // body exceeds declared length
        }
    }
    if (cl_violated) {
        logging::Get()->warn("HTTP/2 stream {} DATA exceeds declared content-length {}",
                             stream_id, req.content_length);
        if (!stream->IsRejected() && self->Callbacks().request_count_callback)
            self->Callbacks().request_count_callback();
        stream->MarkRejected();
        int rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                           stream_id, NGHTTP2_PROTOCOL_ERROR);
        if (rv < 0) {
            logging::Get()->error("nghttp2_submit_rst_stream failed: {}", nghttp2_strerror(rv));
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        return 0;
    }

    stream->AppendBody(reinterpret_cast<const char*>(data), len);
    return 0;
}

static int OnFrameRecvCallback(
    nghttp2_session* session, const nghttp2_frame* frame, void* user_data) {
    auto* self = static_cast<Http2Session*>(user_data);

    // Flood protection check
    if (!self->CheckFloodProtection(frame->hd.type, frame->hd.flags,
                                    frame->hd.stream_id)) {
        // Flood detected — GOAWAY will be sent by CheckFloodProtection
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    switch (frame->hd.type) {
    case NGHTTP2_HEADERS: {
        auto* stream = self->FindStream(frame->hd.stream_id);
        if (!stream) break;
        // Short-circuit: stream already rejected in OnHeaderCallback
        // (header-list overflow, forbidden headers, bad TE, etc.)
        if (stream->IsRejected()) break;

        if (frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
            // Initial request headers
            stream->MarkHeadersComplete();

            // Validate required pseudo-headers (RFC 9113 Section 8.3.1).
            const auto& req = stream->GetRequest();
            bool valid = true;

            if (req.method == "CONNECT") {
                // CONNECT: MUST have :method + :authority. MUST NOT have :path/:scheme.
                // Check HasPath() (presence), not req.path.empty() (value) —
                // an explicit empty :path ("") is still a protocol error.
                if (!stream->HasAuthority()) valid = false;
                if (stream->HasPath() || stream->HasScheme()) valid = false;
            } else {
                // Non-CONNECT: MUST have :method, :path, :scheme (RFC 9113 §8.3.1).
                if (req.method.empty() || req.path.empty() || !stream->HasScheme()) {
                    valid = false;
                }
                // :authority/host is SHOULD, not MUST (RFC 9113 §8.3.1).
                // Don't reject — some valid requests (e.g., OPTIONS *) omit it.
            }

            if (!valid) {
                logging::Get()->warn("HTTP/2 stream {} invalid pseudo-headers for {} request",
                                     frame->hd.stream_id, req.method);
                if (self->Callbacks().request_count_callback)
                    self->Callbacks().request_count_callback();
                int rst_rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                                       frame->hd.stream_id, NGHTTP2_PROTOCOL_ERROR);
                if (rst_rv < 0) {
                    logging::Get()->error("nghttp2_submit_rst_stream failed: {}",
                                          nghttp2_strerror(rst_rv));
                    return NGHTTP2_ERR_CALLBACK_FAILURE;
                }
                stream->MarkRejected();
                break;
            }
            // Early reject: if content-length exceeds body size limit, RST now
            // instead of waiting for DATA frames that will be rejected anyway.
            // Prevents stream slot exhaustion from impossible uploads.
            if (self->MaxBodySize() > 0 && req.content_length > self->MaxBodySize()) {
                logging::Get()->warn("HTTP/2 stream {} content-length {} exceeds max body size {}",
                                     frame->hd.stream_id, req.content_length, self->MaxBodySize());
                if (self->Callbacks().request_count_callback)
                    self->Callbacks().request_count_callback();
                nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                          frame->hd.stream_id, NGHTTP2_CANCEL);
                stream->MarkRejected();
                break;
            }

            // Handle Expect: 100-continue (RFC 9110 Section 10.1.1).
            // HTTP/2 clients may wait for 100 before sending the body.
            // Must respond before END_STREAM to avoid stalling the upload.
            if (req.HasHeader("expect")) {
                std::string expect = req.GetHeader("expect");
                std::transform(expect.begin(), expect.end(), expect.begin(), ::tolower);
                while (!expect.empty() && (expect.front() == ' ' || expect.front() == '\t'))
                    expect.erase(expect.begin());
                while (!expect.empty() && (expect.back() == ' ' || expect.back() == '\t'))
                    expect.pop_back();
                if (expect == "100-continue") {
                    // Send 100 Continue — the client can proceed with body
                    nghttp2_nv nva_100[] = {
                        {const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(":status")),
                         const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>("100")),
                         7, 3, NGHTTP2_NV_FLAG_NONE}
                    };
                    nghttp2_submit_headers(session, NGHTTP2_FLAG_NONE,
                                           frame->hd.stream_id, nullptr,
                                           nva_100, 1, nullptr);
                } else {
                    // Unsupported Expect value — reject with 417.
                    logging::Get()->warn("HTTP/2 stream {} unsupported Expect: {}",
                                         frame->hd.stream_id, expect);
                    if (self->Callbacks().request_count_callback)
                        self->Callbacks().request_count_callback();
                    // submit_response2 queues the HTTP response (END_STREAM).
                    nghttp2_nv nva_417[] = {
                        {const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(":status")),
                         const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>("417")),
                         7, 3, NGHTTP2_NV_FLAG_NONE}
                    };
                    nghttp2_submit_response2(session, frame->hd.stream_id,
                                             nva_417, 1, nullptr);
                    // RST only when the client side is still open (no END_STREAM
                    // on request). If HEADERS had END_STREAM, submit_response2
                    // closes both sides cleanly — RST would be redundant and
                    // some clients treat it as a transport failure.
                    if (!(frame->hd.flags & NGHTTP2_FLAG_END_STREAM)) {
                        nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                                  frame->hd.stream_id, NGHTTP2_NO_ERROR);
                    }
                    stream->MarkRejected();
                    break;
                }
            }
        }
        // else: NGHTTP2_HCAT_HEADERS = trailing headers (trailers).
        // We don't process trailer content, but we do need to check END_STREAM.

        // Check END_STREAM on both request headers and trailers
        if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
            stream->MarkEndStream();
        }

        // If request is complete, dispatch now.
        // Skip if stream was rejected (RST_STREAM sent for body-too-large, etc.)
        if (stream->IsRequestComplete() && !stream->IsRejected() &&
            self->Callbacks().request_callback) {
            self->DispatchStreamRequest(stream, frame->hd.stream_id);
        }
        break;
    }
    case NGHTTP2_DATA: {
        auto* stream = self->FindStream(frame->hd.stream_id);
        if (!stream) break;

        if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
            stream->MarkEndStream();

            // Request with body is now complete — dispatch.
            // Skip if stream was rejected (RST_STREAM sent for body-too-large, etc.)
            if (stream->IsRequestComplete() && !stream->IsRejected() &&
                self->Callbacks().request_callback) {
                self->DispatchStreamRequest(stream, frame->hd.stream_id);
            }
        }
        break;
    }
    case NGHTTP2_GOAWAY:
        logging::Get()->info("H2 received GOAWAY fd={}", self->GetConnection()->fd());
        break;
    default:
        break;
    }

    return 0;
}

static int OnStreamCloseCallback(
    nghttp2_session* session, int32_t stream_id,
    uint32_t error_code, void* user_data) {
    auto* self = static_cast<Http2Session*>(user_data);

    auto* stream = self->FindStream(stream_id);
    if (stream) {
        // Decrement incomplete counter if not already done by DispatchStreamRequest.
        if (!stream->IsCounterDecremented()) {
            self->OnStreamNoLongerIncomplete();
        }
        stream->SetState(Http2Stream::State::CLOSED);
    }

    // Defer removal — never delete during nghttp2 callback
    self->MarkStreamForRemoval(stream_id);

    // Only notify if the stream was actually created (found in our map).
    // Refused shutdown streams (RST_STREAM in OnBeginHeadersCallback)
    // never call CreateStream(), so stream_open_callback never fired and
    // counters were never incremented. Firing close_callback here would
    // drive counters negative.
    if (stream && self->Callbacks().stream_close_callback) {
        try {
            self->Callbacks().stream_close_callback(self->Owner(), stream_id, error_code);
        } catch (const std::exception& e) {
            logging::Get()->error("Exception in stream close callback: {}", e.what());
        }
    }

    return 0;
}

static int OnFrameSendCallback(
    nghttp2_session* session, const nghttp2_frame* frame, void* user_data) {
    // Debug logging only
    logging::Get()->debug("HTTP/2 frame sent: type={} stream={} flags={}",
                          frame->hd.type, frame->hd.stream_id, frame->hd.flags);
    return 0;
}

static int OnInvalidFrameRecvCallback(
    nghttp2_session* session, const nghttp2_frame* frame,
    int lib_error_code, void* user_data) {
    logging::Get()->warn("HTTP/2 invalid frame: type={} stream={} error={}",
                         frame->hd.type, frame->hd.stream_id,
                         nghttp2_strerror(lib_error_code));
    return 0;
}

// --- Http2Session implementation ---

Http2Session::Http2Session(std::shared_ptr<ConnectionHandler> conn,
                           const Settings& settings)
    : impl_(std::make_unique<Impl>())
    , conn_(std::move(conn))
    , settings_(settings)
    , flood_window_start_(std::chrono::steady_clock::now()) {

    // Create callbacks — check for allocation failure (OOM)
    if (nghttp2_session_callbacks_new(&impl_->callbacks) != 0) {
        throw std::runtime_error("Failed to allocate nghttp2 session callbacks");
    }
    nghttp2_session_callbacks_set_on_begin_headers_callback(
        impl_->callbacks, OnBeginHeadersCallback);
    nghttp2_session_callbacks_set_on_header_callback(
        impl_->callbacks, OnHeaderCallback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
        impl_->callbacks, OnDataChunkRecvCallback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(
        impl_->callbacks, OnFrameRecvCallback);
    nghttp2_session_callbacks_set_on_stream_close_callback(
        impl_->callbacks, OnStreamCloseCallback);
    nghttp2_session_callbacks_set_on_frame_send_callback(
        impl_->callbacks, OnFrameSendCallback);
    nghttp2_session_callbacks_set_on_invalid_frame_recv_callback(
        impl_->callbacks, OnInvalidFrameRecvCallback);

    // Create options — check for allocation failure (OOM)
    if (nghttp2_option_new(&impl_->option) != 0) {
        throw std::runtime_error("Failed to allocate nghttp2 session options");
    }
    // Don't track closed streams for priority (saves memory)
    nghttp2_option_set_no_closed_streams(impl_->option, 1);

    // Create server session
    int rv = nghttp2_session_server_new2(
        &impl_->session, impl_->callbacks, this, impl_->option);
    if (rv != 0) {
        throw std::runtime_error(
            std::string("Failed to create nghttp2 session: ") +
            nghttp2_strerror(rv));
    }
}

Http2Session::~Http2Session() = default;

void Http2Session::SendServerPreface() {
    // Submit SETTINGS frame with our server settings
    nghttp2_settings_entry iv[] = {
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, settings_.max_concurrent_streams},
        {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,    settings_.initial_window_size},
        {NGHTTP2_SETTINGS_MAX_FRAME_SIZE,         settings_.max_frame_size},
        {NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE,   settings_.max_header_list_size},
        // Disable server push
        {NGHTTP2_SETTINGS_ENABLE_PUSH, 0}
    };

    int rv = nghttp2_submit_settings(
        impl_->session, NGHTTP2_FLAG_NONE,
        iv, sizeof(iv) / sizeof(iv[0]));
    if (rv != 0) {
        logging::Get()->error("Failed to submit SETTINGS: {}",
                              nghttp2_strerror(rv));
        return;
    }

    SendPendingFrames();
}

ssize_t Http2Session::ReceiveData(const char* data, size_t len) {
    ssize_t rv = nghttp2_session_mem_recv2(
        impl_->session,
        reinterpret_cast<const uint8_t*>(data), len);

    // Always update last_stream_id_ — even on error, nghttp2 may have
    // processed valid streams before hitting the bad frame. Using a stale
    // value in GOAWAY would tell clients to retry already-processed requests.
    last_stream_id_.store(
        nghttp2_session_get_last_proc_stream_id(impl_->session),
        std::memory_order_release);

    if (rv < 0) {
        logging::Get()->error("nghttp2_session_mem_recv2 error: {}",
                              nghttp2_strerror(static_cast<int>(rv)));
        return rv;
    }

    // Flush deferred stream removals now that we're outside callbacks
    FlushDeferredRemovals();

    return rv;
}

bool Http2Session::SendPendingFrames() {
    // If already deferred (watermark exceeded on a previous call), don't
    // pull any frames. ResumeOutput clears this flag when the buffer drains.
    // Control frames queued by ReceiveData callbacks will be pulled on the
    // next ResumeOutput — delay is bounded by one buffer drain cycle.
    if (output_deferred_) return false;

    bool sent_any = false;
    for (;;) {
        // After ≥1 frame, check output buffer against watermark.
        // The first frame is always pulled so control frames (SETTINGS ACK,
        // GOAWAY, WINDOW_UPDATE) from THIS ReceiveData call are delivered.
        if (sent_any && conn_->OutputBufferSize() > OutputHighWatermark()) {
            output_deferred_ = true;
            break;
        }

        const uint8_t* data;
        ssize_t len = nghttp2_session_mem_send2(impl_->session, &data);
        if (len < 0) {
            logging::Get()->error("nghttp2_session_mem_send2 error: {}",
                                  nghttp2_strerror(static_cast<int>(len)));
            break;
        }
        if (len == 0) {
            output_deferred_ = false;
            break;
        }

        conn_->SendRaw(reinterpret_cast<const char*>(data),
                        static_cast<size_t>(len));
        sent_any = true;

        // Stop serializing if the transport is closing — remaining frames
        // would just be discarded, wasting CPU on aborted downloads.
        if (conn_->IsClosing()) break;
    }

    // Flush deferred stream removals. OnStreamCloseCallback can fire during
    // mem_send2 (when nghttp2 finalizes response frames). Without this,
    // closed streams and their ResponseDataSource stay resident until the
    // next ReceiveData call, which may not come on idle keep-alive connections.
    FlushDeferredRemovals();

    return sent_any;
}

void Http2Session::ResumeOutput() {
    if (!output_deferred_) return;
    output_deferred_ = false;  // clear before re-entering SendPendingFrames
    SendPendingFrames();
}

bool Http2Session::WantWrite() const {
    return nghttp2_session_want_write(impl_->session) != 0;
}

bool Http2Session::IsAlive() const {
    return nghttp2_session_want_read(impl_->session) != 0 ||
           nghttp2_session_want_write(impl_->session) != 0;
}

int Http2Session::SubmitResponse(int32_t stream_id, const HttpResponse& response) {
    auto* stream = FindStream(stream_id);
    if (!stream || stream->IsClosed()) {
        logging::Get()->debug("Cannot submit response: stream {} not found or closed",
                              stream_id);
        return -1;
    }

    int status_code = response.GetStatusCode();

    // 1xx informational responses must not come through SubmitResponse.
    // Internal 100-continue uses nghttp2_submit_headers in OnFrameRecvCallback.
    // 101 is invalid in HTTP/2 (RFC 9113 Section 8.6).
    // Other 1xx (103 Early Hints etc.) need a separate non-final API.
    // Reject all 1xx here — they would be sent as final with END_STREAM,
    // closing the stream before the real response.
    if (status_code < 200) {
        logging::Get()->error("HTTP/2 stream {} SubmitResponse called with {} "
                              "(1xx not supported as app response)", stream_id, status_code);
        nghttp2_submit_rst_stream(impl_->session, NGHTTP2_FLAG_NONE,
                                  stream_id, NGHTTP2_INTERNAL_ERROR);
        return -1;
    }

    // Determine if the response body must be suppressed.
    // RFC 9110 Section 9.3.2: HEAD responses include headers as if GET but no body.
    // RFC 9110 Section 15.3.5/15.3.6/15.4.5: 204, 205, 304 MUST NOT contain a body.
    const HttpRequest& req = stream->GetRequest();
    bool suppress_body = (req.method == "HEAD" ||
                          status_code == 204 || status_code == 205 ||
                          status_code == 304);

    // Build nghttp2 header name-value pairs.
    // We do NOT use NGHTTP2_NV_FLAG_NO_COPY_NAME or NO_COPY_VALUE:
    // those flags skip nghttp2's internal copy, but we cannot guarantee
    // the string storage (status_str, content_length_str, and the
    // HttpResponse headers) outlives the nghttp2_submit_response2 call.
    // Without NO_COPY, nghttp2 copies the name/value data internally.
    std::string status_str = std::to_string(status_code);

    std::vector<nghttp2_nv> nva;
    // :status pseudo-header (required first)
    nva.push_back({
        const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(":status")),
        const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(status_str.c_str())),
        7, status_str.size(),
        NGHTTP2_NV_FLAG_NONE
    });

    // Regular headers — lowercase names (RFC 9113 Section 8.2: field names MUST
    // be lowercase). Skip forbidden and server-managed headers.
    const auto& headers = response.GetHeaders();
    std::vector<std::string> lowered_names;  // storage for lowered name strings
    lowered_names.reserve(headers.size());
    for (const auto& hdr : headers) {
        std::string key = hdr.first;
        std::transform(key.begin(), key.end(), key.begin(), ::tolower);
        // Skip HTTP/1.x connection-level headers (RFC 9113 Section 8.2.2)
        if (key == "connection" || key == "keep-alive" ||
            key == "proxy-connection" || key == "te" ||
            key == "transfer-encoding" || key == "upgrade") {
            continue;
        }
        // Skip content-length — we compute the correct value below to
        // prevent mismatches between declared and actual body size.
        // Exception: for HEAD with empty body, preserve the caller-supplied
        // content-length (the handler knows the representation size).
        if (key == "content-length") {
            if (req.method == "HEAD" && response.GetBody().empty()) {
                // Keep it — the handler explicitly set the representation length
            } else {
                continue;
            }
        }
        lowered_names.push_back(std::move(key));
        nva.push_back({
            const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(lowered_names.back().c_str())),
            const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(hdr.second.c_str())),
            lowered_names.back().size(), hdr.second.size(),
            NGHTTP2_NV_FLAG_NONE
        });
    }

    // Determine the effective body for the wire
    const std::string& raw_body = response.GetBody();
    bool has_body = !raw_body.empty() && !suppress_body;

    // Compute correct content-length. Always server-managed to prevent
    // mismatches between declared length and actual body size.
    // HEAD: content-length reflects the GET body size (RFC 9110 §9.3.2)
    // 204/205/304: no content-length (body suppressed)
    // Normal: content-length = actual body size
    std::string content_length_str;
    if (!raw_body.empty() && (!suppress_body || req.method == "HEAD")) {
        content_length_str = std::to_string(raw_body.size());
        nva.push_back({
            const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>("content-length")),
            const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(content_length_str.c_str())),
            14, content_length_str.size(),
            NGHTTP2_NV_FLAG_NONE
        });
    }

    // Note: 1xx informational responses (100-continue, 103 Early Hints) are
    // handled internally via nghttp2_submit_headers in OnFrameRecvCallback,
    // not through this method. If an app handler returns <200, it's treated
    // as a normal final response (which is likely a bug in the handler, but
    // sending it with END_STREAM is safer than leaving the stream open).
    int rv;
    if (!has_body) {
        // No body (or body suppressed for HEAD/204/304) — submit headers with END_STREAM
        rv = nghttp2_submit_response2(impl_->session, stream_id,
                                      nva.data(), nva.size(), nullptr);
    } else {
        // Body present — use data provider.
        // Store the ResponseDataSource on the stream so it is owned and freed
        // when the stream is destroyed (avoids the prior raw-new leak).
        auto src_owned = std::make_unique<ResponseDataSource>(ResponseDataSource{raw_body, 0});
        ResponseDataSource* src = src_owned.get();

        nghttp2_data_provider2 data_prd;
        data_prd.source.ptr = src;
        data_prd.read_callback = DataSourceReadCallback;

        rv = nghttp2_submit_response2(impl_->session, stream_id,
                                      nva.data(), nva.size(), &data_prd);
        if (rv == 0) {
            // Transfer ownership to the stream — src pointer remains valid
            // for the lifetime of the stream (and thus the data provider).
            stream->SetDataSource(std::move(src_owned));
        }
        // If rv != 0, src_owned goes out of scope here and frees the allocation.
    }

    if (rv != 0) {
        logging::Get()->error("Failed to submit response for stream {}: {}",
                              stream_id, nghttp2_strerror(rv));
        return rv;
    }

    stream->MarkResponseHeadersSent();
    return 0;
}

void Http2Session::DispatchStreamRequest(Http2Stream* stream, int32_t stream_id) {
    // Count every dispatched request — including those rejected below by
    // content-length checks. Matches HTTP/1's request_count_callback which
    // fires at HandleCompleteRequest entry before any rejection.
    if (callbacks_.request_count_callback) {
        callbacks_.request_count_callback();
    }

    // Request is complete — no longer incomplete for timeout purposes.
    OnStreamNoLongerIncomplete();
    stream->MarkCounterDecremented();

    const HttpRequest& req = stream->GetRequest();

    // RFC 9110 Section 8.6: If content-length is declared, the actual body
    // size must match. A mismatch means the message is malformed.
    if (req.content_length > 0 &&
        stream->AccumulatedBodySize() != req.content_length) {
        logging::Get()->warn("HTTP/2 stream {} content-length mismatch: "
                             "declared={} actual={}",
                             stream_id, req.content_length,
                             stream->AccumulatedBodySize());
        nghttp2_submit_rst_stream(impl_->session, NGHTTP2_FLAG_NONE,
                                  stream_id, NGHTTP2_PROTOCOL_ERROR);
        stream->MarkRejected();
        return;
    }
    // Also reject: content-length: 0 but body is non-empty
    if (req.HasHeader("content-length") && req.content_length == 0 &&
        stream->AccumulatedBodySize() > 0) {
        logging::Get()->warn("HTTP/2 stream {} content-length:0 but body present",
                             stream_id);
        nghttp2_submit_rst_stream(impl_->session, NGHTTP2_FLAG_NONE,
                                  stream_id, NGHTTP2_PROTOCOL_ERROR);
        stream->MarkRejected();
        return;
    }

    HttpResponse response;
    try {
        callbacks_.request_callback(Owner(), stream_id, req, response);
    } catch (const std::exception& e) {
        logging::Get()->error("Exception in HTTP/2 request handler: {}", e.what());
        response = HttpResponse::InternalError();
    }
    SubmitResponse(stream_id, response);
}

void Http2Session::SendGoaway(uint32_t error_code) {
    if (goaway_sent_) return;
    goaway_sent_ = true;
    logging::Get()->info("H2 sending GOAWAY fd={}", conn_->fd());

    nghttp2_submit_goaway(impl_->session, NGHTTP2_FLAG_NONE,
                          last_stream_id_, error_code,
                          nullptr, 0);
    SendPendingFrames();
}

void Http2Session::ResetStream(int32_t stream_id, uint32_t error_code) {
    nghttp2_submit_rst_stream(impl_->session, NGHTTP2_FLAG_NONE,
                              stream_id, error_code);
    SendPendingFrames();
}

// --- Stream management ---

Http2Stream* Http2Session::FindStream(int32_t stream_id) {
    auto it = streams_.find(stream_id);
    return (it != streams_.end()) ? it->second.get() : nullptr;
}

Http2Stream* Http2Session::CreateStream(int32_t stream_id) {
    auto [it, inserted] = streams_.emplace(
        stream_id, std::make_unique<Http2Stream>(stream_id));
    if (!inserted) {
        logging::Get()->warn("Stream {} already exists", stream_id);
        return it->second.get();
    }
    OnStreamBecameIncomplete();
    // Notify observer (HttpServer counters) of stream creation
    if (callbacks_.stream_open_callback) {
        try { callbacks_.stream_open_callback(Owner(), stream_id); }
        catch (const std::exception& e) {
            logging::Get()->error("Stream open callback error: {}", e.what());
        }
    }
    return it->second.get();
}

void Http2Session::MarkStreamForRemoval(int32_t stream_id) {
    streams_to_remove_.push_back(stream_id);
}

void Http2Session::FlushDeferredRemovals() {
    for (int32_t id : streams_to_remove_) {
        streams_.erase(id);
    }
    streams_to_remove_.clear();
}

size_t Http2Session::ActiveStreamCount() const {
    return streams_.size();
}

size_t Http2Session::UnclosedStreamCount() const {
    size_t total = streams_.size();
    size_t closing = streams_to_remove_.size();
    return total > closing ? total - closing : 0;
}

std::chrono::steady_clock::time_point Http2Session::OldestIncompleteStreamStart() const {
    // streams_ is std::map<int32_t, ...> sorted by stream ID.
    // HTTP/2 stream IDs are monotonically increasing, so the first
    // non-counter-decremented stream is the oldest needing a deadline.
    // Includes rejected streams (e.g. 417 half-open) so they get RST'd
    // by ResetExpiredStreams on schedule. Newer streams cannot push the
    // deadline past an older rejected stream's timeout.
    // Idle timeout suppression during this window is acceptable — bounded
    // by request_timeout_sec and only affects misbehaving clients.
    for (const auto& [id, stream] : streams_) {
        if (!stream->IsCounterDecremented()) {
            return stream->CreatedAt();
        }
    }
    return std::chrono::steady_clock::time_point::max();
}

size_t Http2Session::ResetExpiredStreams(int timeout_sec) {
    auto now = std::chrono::steady_clock::now();
    auto limit = std::chrono::seconds(timeout_sec);
    size_t count = 0;

    for (auto& [id, stream] : streams_) {
        if (stream->IsCounterDecremented()) continue;
        // Check incomplete AND rejected-but-not-closed streams.
        // Rejected streams (e.g. 417 Expect) may be half-open on the client
        // side — RST them to free nghttp2 max_concurrent_streams slots.
        if (now - stream->CreatedAt() > limit) {
            logging::Get()->warn("HTTP/2 stream {} timed out ({}s)", id, timeout_sec);
            stream->MarkRejected();
            nghttp2_submit_rst_stream(impl_->session, NGHTTP2_FLAG_NONE,
                                      id, NGHTTP2_CANCEL);
            OnStreamNoLongerIncomplete();
            stream->MarkCounterDecremented();
            ++count;
        }
    }
    return count;
}

// --- Callbacks ---

void Http2Session::SetRequestCallback(
    HTTP2_CALLBACKS_NAMESPACE::Http2RequestCallback cb) {
    callbacks_.request_callback = std::move(cb);
}

void Http2Session::SetStreamCloseCallback(
    HTTP2_CALLBACKS_NAMESPACE::Http2StreamCloseCallback cb) {
    callbacks_.stream_close_callback = std::move(cb);
}

void Http2Session::SetStreamOpenCallback(
    HTTP2_CALLBACKS_NAMESPACE::Http2StreamOpenCallback cb) {
    callbacks_.stream_open_callback = std::move(cb);
}

void Http2Session::SetRequestCountCallback(
    HTTP2_CALLBACKS_NAMESPACE::Http2RequestCountCallback cb) {
    callbacks_.request_count_callback = std::move(cb);
}

// --- Flood protection ---

bool Http2Session::CheckFloodProtection(
    uint8_t frame_type, uint8_t flags, int32_t stream_id) {

    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - flood_window_start_);

    // Reset counters when the window expires
    if (elapsed.count() >= HTTP2_CONSTANTS::FLOOD_CHECK_INTERVAL_SEC) {
        settings_count_ = 0;
        ping_count_ = 0;
        rst_stream_count_ = 0;
        flood_window_start_ = now;
    }

    switch (frame_type) {
    case NGHTTP2_SETTINGS:
        // Don't count ACK — only count new SETTINGS frames
        if (!(flags & NGHTTP2_FLAG_ACK)) {
            ++settings_count_;
            if (settings_count_ > HTTP2_CONSTANTS::MAX_SETTINGS_PER_INTERVAL) {
                logging::Get()->warn("HTTP/2 SETTINGS flood detected fd={}",
                                     conn_ ? conn_->fd() : -1);
                // Queue GOAWAY only — do NOT call SendPendingFrames() here.
                // This callback runs inside nghttp2_session_mem_recv2; flushing
                // output now (via mem_send2) while mem_recv2 is on the call stack
                // is unsafe. SendPendingFrames() will be called after ReceiveData
                // returns in Http2ConnectionHandler::OnRawData().
                if (!goaway_sent_) {
                    goaway_sent_ = true;
                    // Use live stream ID — last_stream_id_ may be stale mid-recv
                    int32_t live_last = nghttp2_session_get_last_proc_stream_id(
                        impl_->session);
                    nghttp2_submit_goaway(impl_->session, NGHTTP2_FLAG_NONE,
                                         live_last, NGHTTP2_ENHANCE_YOUR_CALM,
                                         nullptr, 0);
                }
                return false;
            }
        }
        break;
    case NGHTTP2_PING:
        if (!(flags & NGHTTP2_FLAG_ACK)) {
            ++ping_count_;
            if (ping_count_ > HTTP2_CONSTANTS::MAX_PING_PER_INTERVAL) {
                logging::Get()->warn("HTTP/2 PING flood detected fd={}",
                                     conn_ ? conn_->fd() : -1);
                if (!goaway_sent_) {
                    goaway_sent_ = true;
                    int32_t live_last = nghttp2_session_get_last_proc_stream_id(
                        impl_->session);
                    nghttp2_submit_goaway(impl_->session, NGHTTP2_FLAG_NONE,
                                         live_last, NGHTTP2_ENHANCE_YOUR_CALM,
                                         nullptr, 0);
                }
                return false;
            }
        }
        break;
    case NGHTTP2_RST_STREAM:
        ++rst_stream_count_;
        if (rst_stream_count_ > HTTP2_CONSTANTS::MAX_RST_STREAM_PER_INTERVAL) {
            logging::Get()->warn("HTTP/2 RST_STREAM flood detected (rapid reset) fd={}",
                                 conn_ ? conn_->fd() : -1);
            if (!goaway_sent_) {
                goaway_sent_ = true;
                int32_t live_last = nghttp2_session_get_last_proc_stream_id(
                    impl_->session);
                nghttp2_submit_goaway(impl_->session, NGHTTP2_FLAG_NONE,
                                     live_last, NGHTTP2_ENHANCE_YOUR_CALM,
                                     nullptr, 0);
            }
            return false;
        }
        break;
    default:
        break;
    }

    return true;
}
