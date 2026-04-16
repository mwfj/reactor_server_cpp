#include "http2/http2_session.h"
#include "http2/http2_connection_handler.h"
#include "http/http_response.h"
#include "http/http_status.h"
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

    if (!source || !source->ptr) {
        logging::Get()->error("H2 data source callback invoked with null source");
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    auto* src = static_cast<ResponseDataSource*>(source->ptr);
    return src->ReadChunk(buf, length, data_flags);
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
        // Only count as a request if this is the initial header block, not
        // trailers. Trailers arrive after MarkHeadersComplete, so the stream
        // was already counted/dispatched.
        if (!stream->IsRejected() && !stream->GetRequest().headers_complete
            && self->Callbacks().request_count_callback)
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
        // Only count as a request for initial headers, not trailers
        if (!stream->IsRejected() && !stream->GetRequest().headers_complete
            && self->Callbacks().request_count_callback)
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
        std::transform(te_lower.begin(), te_lower.end(), te_lower.begin(), [](unsigned char c){ return std::tolower(c); });
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
                std::transform(expect.begin(), expect.end(), expect.begin(), [](unsigned char c){ return std::tolower(c); });
                while (!expect.empty() && (expect.front() == ' ' || expect.front() == '\t'))
                    expect.erase(expect.begin());
                while (!expect.empty() && (expect.back() == ' ' || expect.back() == '\t'))
                    expect.pop_back();
                if (expect == "100-continue") {
                    // Send 100 Continue — the client can proceed with body.
                    // Silent-failure scenario: nghttp2_submit_headers could
                    // fail (NGHTTP2_ERR_NOMEM etc.). Without a check, the
                    // client waits forever for 100 before sending the body
                    // and the stream slot stays occupied until request
                    // timeout. RST the stream as a fallback so the client
                    // retries without Expect.
                    nghttp2_nv nva_100[] = {
                        {const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(":status")),
                         const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>("100")),
                         7, 3, NGHTTP2_NV_FLAG_NONE}
                    };
                    int rv100 = nghttp2_submit_headers(
                        session, NGHTTP2_FLAG_NONE,
                        frame->hd.stream_id, nullptr,
                        nva_100, 1, nullptr);
                    if (rv100 != 0) {
                        logging::Get()->warn(
                            "HTTP/2 100-Continue submit failed stream={} rv={} ({})",
                            frame->hd.stream_id, rv100, nghttp2_strerror(rv100));
                        int rv_rst = nghttp2_submit_rst_stream(
                            session, NGHTTP2_FLAG_NONE,
                            frame->hd.stream_id, NGHTTP2_INTERNAL_ERROR);
                        if (rv_rst != 0) {
                            // Dual-NOMEM path: neither the 100 nor the RST
                            // was queued, so nghttp2 will never fire
                            // on_stream_close for this stream. The
                            // stream_open_callback already fired in
                            // CreateStream, leaving active_h2_streams_ and
                            // local_stream_count_ both +1. Mirror the
                            // push-rollback reconciliation pattern: fire a
                            // synthetic stream_close_callback +
                            // MarkStreamForRemoval so counters stay
                            // balanced. FlushDeferredRemovals will erase
                            // the entry. Any later spurious nghttp2 close
                            // callback for this id is a FindStream no-op.
                            logging::Get()->warn(
                                "HTTP/2 100-Continue RST submit also failed "
                                "stream={} rv={} ({}) — firing synthetic "
                                "close_callback to reconcile counters",
                                frame->hd.stream_id, rv_rst,
                                nghttp2_strerror(rv_rst));
                            if (self->Callbacks().stream_close_callback) {
                                try {
                                    self->Callbacks().stream_close_callback(
                                        self->Owner(), frame->hd.stream_id,
                                        NGHTTP2_INTERNAL_ERROR);
                                } catch (const std::exception& e) {
                                    logging::Get()->error(
                                        "Synthetic close_callback threw: {}",
                                        e.what());
                                }
                            }
                            self->MarkStreamForRemoval(frame->hd.stream_id);
                        }
                        stream->MarkRejected();
                        break;
                    }
                } else {
                    // Unsupported Expect value — reject with 417.
                    logging::Get()->warn("HTTP/2 stream {} unsupported Expect: {}",
                                         frame->hd.stream_id, expect);
                    if (self->Callbacks().request_count_callback)
                        self->Callbacks().request_count_callback();
                    // submit_response2 queues the HTTP response (END_STREAM).
                    // A silent failure here would leave the client hanging
                    // until request timeout; RST as fallback so the stream
                    // is cleanly torn down and the client fails fast.
                    nghttp2_nv nva_417[] = {
                        {const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(":status")),
                         const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>("417")),
                         7, 3, NGHTTP2_NV_FLAG_NONE}
                    };
                    int rv417 = nghttp2_submit_response2(
                        session, frame->hd.stream_id, nva_417, 1, nullptr);
                    if (rv417 != 0) {
                        logging::Get()->warn(
                            "HTTP/2 417 response submit failed stream={} rv={} ({})",
                            frame->hd.stream_id, rv417, nghttp2_strerror(rv417));
                        // Fall through to RST below — force stream teardown.
                    }
                    // RST only when the client side is still open (no END_STREAM
                    // on request). If HEADERS had END_STREAM, submit_response2
                    // closes both sides cleanly — RST would be redundant and
                    // some clients treat it as a transport failure. When the
                    // response submit itself failed, always RST so the client
                    // stops waiting on a response that will never arrive.
                    if (rv417 != 0 ||
                        !(frame->hd.flags & NGHTTP2_FLAG_END_STREAM)) {
                        uint32_t rst_code = (rv417 != 0)
                            ? NGHTTP2_INTERNAL_ERROR
                            : NGHTTP2_NO_ERROR;
                        int rv_rst = nghttp2_submit_rst_stream(
                            session, NGHTTP2_FLAG_NONE,
                            frame->hd.stream_id, rst_code);
                        if (rv_rst != 0) {
                            logging::Get()->warn(
                                "HTTP/2 417 RST submit failed stream={} rv={} ({})",
                                frame->hd.stream_id, rv_rst,
                                nghttp2_strerror(rv_rst));
                            // Dual-failure reconciliation: when both the
                            // response and the RST submits fail (NOMEM),
                            // nghttp2 never fires on_stream_close and the
                            // stream_open_callback's +1 on active_h2_streams_
                            // / local_stream_count_ leaks. Fire a synthetic
                            // close_callback to balance, matching the
                            // 100-Continue and push-rollback paths. Only
                            // reconcile when the response submit ALSO
                            // failed — if only the RST failed but the
                            // response succeeded, submit_response2 closes
                            // both sides cleanly and nghttp2 will fire
                            // close on its own via END_STREAM.
                            if (rv417 != 0) {
                                logging::Get()->warn(
                                    "HTTP/2 417 dual-failure stream={} — "
                                    "firing synthetic close_callback",
                                    frame->hd.stream_id);
                                if (self->Callbacks().stream_close_callback) {
                                    try {
                                        self->Callbacks().stream_close_callback(
                                            self->Owner(), frame->hd.stream_id,
                                            NGHTTP2_INTERNAL_ERROR);
                                    } catch (const std::exception& e) {
                                        logging::Get()->error(
                                            "Synthetic close_callback threw: {}",
                                            e.what());
                                    }
                                }
                                self->MarkStreamForRemoval(frame->hd.stream_id);
                            }
                        }
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
    // Submit SETTINGS frame with our server settings.
    //
    // SETTINGS_ENABLE_PUSH (RFC 9113 §6.5.2 + §7) is direction-asymmetric on
    // the server: a server MUST NOT send a value of 1, and the absence of
    // an entry leaves the peer's view at the protocol default of 1. So:
    //   - enable_push = false (default): advertise {ENABLE_PUSH, 0} so the
    //     client knows we will never push and can reject a stray
    //     PUSH_PROMISE. nghttp2's local_settings ENABLE_PUSH stays 0,
    //     refusing PUSH_PROMISE submission.
    //   - enable_push = true: OMIT the entry entirely. nghttp2's local
    //     setting falls back to its internal default of 1, allowing
    //     PUSH_PROMISE emission, while we never write the forbidden value
    //     1 onto the wire.
    std::vector<nghttp2_settings_entry> iv;
    iv.reserve(5);
    iv.push_back({NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, settings_.max_concurrent_streams});
    iv.push_back({NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,    settings_.initial_window_size});
    iv.push_back({NGHTTP2_SETTINGS_MAX_FRAME_SIZE,         settings_.max_frame_size});
    iv.push_back({NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE,   settings_.max_header_list_size});
    if (!settings_.enable_push) {
        iv.push_back({NGHTTP2_SETTINGS_ENABLE_PUSH, 0});
    }

    int rv = nghttp2_submit_settings(
        impl_->session, NGHTTP2_FLAG_NONE,
        iv.data(), iv.size());
    if (rv != 0) {
        logging::Get()->error("Failed to submit SETTINGS: {}",
                              nghttp2_strerror(rv));
        return;
    }

    SendPendingFrames();
}

ssize_t Http2Session::ReceiveData(const char* data, size_t len) {
    // Mark that we are inside nghttp2_session_mem_recv2 so that any
    // send_interim / push_resource invocation from an inline sync
    // handler (running inside an on_frame_recv callback) can skip its
    // inline SendPendingFrames() — calling nghttp2_session_mem_send2
    // reentrantly from a recv callback is unsafe. The caller of
    // ReceiveData() flushes on the way out (see OnRawData tail).
    // RAII guard covers both the normal return and the error return.
    in_receive_data_ = true;
    struct RecvGuard {
        bool& flag;
        ~RecvGuard() { flag = false; }
    } recv_guard{in_receive_data_};

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
    if (status_code < HttpStatus::OK) {
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
                          status_code == HttpStatus::NO_CONTENT ||
                          status_code == HttpStatus::RESET_CONTENT ||
                          status_code == HttpStatus::NOT_MODIFIED);

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
        std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c){ return std::tolower(c); });
        // Skip HTTP/1.x connection-level headers (RFC 9113 Section 8.2.2)
        if (key == "connection" || key == "keep-alive" ||
            key == "proxy-connection" || key == "te" ||
            key == "transfer-encoding" || key == "upgrade") {
            continue;
        }
        // Always strip caller-set content-length — we compute the
        // authoritative value below via HttpResponse::ComputeWireContentLength
        // (which mirrors the HTTP/1 Serialize() rules: 304 metadata
        // preservation, 205 zeroing, HEAD auto-compute vs. preserve flag).
        // The previous "HEAD && empty body keeps caller value" special-case
        // let stale CL headers leak into HEAD responses without any
        // PreserveContentLength opt-in, and silently dropped 304 CL
        // metadata that HTTP/1 preserves.
        if (key == "content-length") continue;
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

    // Compute the Content-Length header via the shared helper so HTTP/2
    // stays in lockstep with HTTP/1 Serialize():
    //   - 1xx/101/204: no CL
    //   - 205:         CL = "0"
    //   - 304:         preserve first caller-set CL, else no CL
    //   - otherwise:   PreserveContentLength → first caller-set CL,
    //                  else auto-compute from body_.size()
    // For HEAD the helper returns body_.size() (auto) or the preserved
    // value — matching HTTP/1 which also computes CL from body_ before
    // stripping the body on the wire. `content_length_str` must live
    // until nghttp2_submit_response2 returns because nva holds raw
    // pointers into its storage.
    std::string content_length_str;
    if (auto effective_cl = response.ComputeWireContentLength(status_code)) {
        content_length_str = std::move(*effective_cl);
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
        auto src_owned =
            std::make_shared<BufferedResponseDataSource>(raw_body);
        ResponseDataSource* src = src_owned.get();

        nghttp2_data_provider2 data_prd;
        data_prd.source.ptr = src;
        data_prd.read_callback = DataSourceReadCallback;

        rv = nghttp2_submit_response2(impl_->session, stream_id,
                                      nva.data(), nva.size(), &data_prd);
        if (rv == 0) {
            stream->SetDataSource(std::move(src_owned));
        }
    }

    if (rv != 0) {
        logging::Get()->error("Failed to submit response for stream {}: {}",
                              stream_id, nghttp2_strerror(rv));
        return rv;
    }

    stream->MarkResponseHeadersSent();
    // Final response (>=200) is now in nghttp2's send queue. Lock out any
    // late SubmitInterimHeaders so a stray 1xx cannot interleave with — or
    // race ahead of — the final block on the wire.
    stream->MarkFinalResponseSubmitted();
    return 0;
}

int Http2Session::SubmitInterimHeaders(
    int32_t stream_id, int status_code,
    const std::vector<std::pair<std::string, std::string>>& headers) {
    // Valid range: [PROCESSING (102), OK). 100 is framework-managed
    // (auto-emitted for Expect: 100-continue); 101 is an HTTP/1 Upgrade
    // status and MUST NOT appear in HTTP/2 (RFC 9113 Section 8.6).
    if (status_code < HttpStatus::PROCESSING || status_code >= HttpStatus::OK) {
        logging::Get()->warn(
            "H2 SubmitInterimHeaders invalid status {} stream={}",
            status_code, stream_id);
        return -1;
    }
    auto* stream = FindStream(stream_id);
    if (!stream || stream->IsClosed()) {
        logging::Get()->debug(
            "H2 SubmitInterimHeaders: stream {} missing/closed; drop",
            stream_id);
        return -1;
    }
    if (stream->FinalResponseSubmitted()) {
        logging::Get()->warn(
            "H2 SubmitInterimHeaders after final stream={} status={}; drop",
            stream_id, status_code);
        return -1;
    }

    // Build the nva. nghttp2 copies bytes because we do not use
    // NGHTTP2_NV_FLAG_NO_COPY_NAME/VALUE, so local storage is safe.
    std::string status_str = std::to_string(status_code);
    std::vector<nghttp2_nv> nva;
    nva.reserve(1 + headers.size());
    nva.push_back({
        const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(":status")),
        const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(status_str.c_str())),
        7, status_str.size(),
        NGHTTP2_NV_FLAG_NONE
    });

    // Forbidden-header strip: same list SubmitResponse enforces, plus
    // pseudo-headers which are response-only on the server side (":status")
    // or request-only but defensively scrubbed here.
    std::vector<std::string> lowered_names;
    lowered_names.reserve(headers.size());
    for (const auto& [key, value] : headers) {
        std::string lower = key;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        if (lower == "connection" || lower == "keep-alive" ||
            lower == "proxy-connection" || lower == "te" ||
            lower == "transfer-encoding" || lower == "upgrade" ||
            lower == "content-length" ||
            (lower.size() >= 6 && lower.compare(0, 6, "proxy-") == 0) ||
            lower == ":status" || lower == ":path" || lower == ":method" ||
            lower == ":scheme" || lower == ":authority") {
            logging::Get()->debug(
                "H2 interim: forbidden header '{}' stripped stream={}",
                key, stream_id);
            continue;
        }
        lowered_names.push_back(std::move(lower));
        nva.push_back({
            const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(lowered_names.back().c_str())),
            const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(value.c_str())),
            lowered_names.back().size(), value.size(),
            NGHTTP2_NV_FLAG_NONE
        });
    }

    // NGHTTP2_FLAG_NONE — no END_STREAM so the stream stays open for the
    // subsequent final response. nghttp2 itself treats 1xx headers as
    // non-final and allows further HEADERS on the same stream.
    int rv = nghttp2_submit_headers(impl_->session, NGHTTP2_FLAG_NONE,
                                    stream_id, nullptr,
                                    nva.data(), nva.size(), nullptr);
    if (rv != 0) {
        logging::Get()->warn(
            "nghttp2_submit_headers(interim) stream={} status={} rv={} ({})",
            stream_id, status_code, rv, nghttp2_strerror(rv));
        return -1;
    }
    logging::Get()->debug(
        "H2 SubmitInterimHeaders queued stream={} status={}",
        stream_id, status_code);
    return 0;
}

int Http2Session::SubmitStreamingResponse(
    int32_t stream_id,
    const HttpResponse& response,
    std::shared_ptr<ResponseDataSource> data_source) {
    auto* stream = FindStream(stream_id);
    if (!stream || stream->IsClosed()) {
        logging::Get()->debug(
            "Cannot submit streaming response: stream {} not found or closed",
            stream_id);
        return -1;
    }

    int status_code = response.GetStatusCode();
    if (status_code < HttpStatus::OK) {
        logging::Get()->error(
            "HTTP/2 stream {} SubmitStreamingResponse called with {} "
            "(1xx not supported as app response)",
            stream_id, status_code);
        int rv_rst = nghttp2_submit_rst_stream(
            impl_->session, NGHTTP2_FLAG_NONE,
            stream_id, NGHTTP2_INTERNAL_ERROR);
        if (rv_rst != 0) {
            logging::Get()->warn(
                "nghttp2_submit_rst_stream failed stream={} rv={} ({})",
                stream_id, rv_rst, nghttp2_strerror(rv_rst));
        }
        return -1;
    }

    const HttpRequest& req = stream->GetRequest();
    bool suppress_body = (req.method == "HEAD" ||
                          status_code == HttpStatus::NO_CONTENT ||
                          status_code == HttpStatus::RESET_CONTENT ||
                          status_code == HttpStatus::NOT_MODIFIED);

    std::string status_str = std::to_string(status_code);
    std::vector<nghttp2_nv> nva;
    nva.push_back({
        const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(":status")),
        const_cast<uint8_t*>(
            reinterpret_cast<const uint8_t*>(status_str.c_str())),
        7, status_str.size(),
        NGHTTP2_NV_FLAG_NONE
    });

    const auto& headers = response.GetHeaders();
    std::vector<std::string> lowered_names;
    lowered_names.reserve(headers.size());
    for (const auto& hdr : headers) {
        std::string key = hdr.first;
        std::transform(key.begin(), key.end(), key.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        if (key == "connection" || key == "keep-alive" ||
            key == "proxy-connection" || key == "te" ||
            key == "transfer-encoding" || key == "upgrade") {
            continue;
        }
        if (key == "content-length") continue;
        lowered_names.push_back(std::move(key));
        nva.push_back({
            const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(
                lowered_names.back().c_str())),
            const_cast<uint8_t*>(
                reinterpret_cast<const uint8_t*>(hdr.second.c_str())),
            lowered_names.back().size(), hdr.second.size(),
            NGHTTP2_NV_FLAG_NONE
        });
    }

    // Streaming responses submit headers before body bytes exist. Auto-
    // computing Content-Length from a headers-only response body would inject
    // CL=0 on unknown-length streams that will later send DATA frames.
    // Preserve CL only when the caller explicitly marked a known length, or
    // when the status code itself defines the wire value (205 / 304).
    std::string content_length_str;
    bool emit_known_length =
        response.IsContentLengthPreserved() ||
        status_code == HttpStatus::RESET_CONTENT ||
        status_code == HttpStatus::NOT_MODIFIED;
    if (emit_known_length) {
        auto effective_cl = response.ComputeWireContentLength(status_code);
        if (effective_cl) {
            content_length_str = std::move(*effective_cl);
            nva.push_back({
                const_cast<uint8_t*>(
                    reinterpret_cast<const uint8_t*>("content-length")),
                const_cast<uint8_t*>(
                    reinterpret_cast<const uint8_t*>(content_length_str.c_str())),
                14, content_length_str.size(),
                NGHTTP2_NV_FLAG_NONE
            });
        }
    }

    int rv;
    if (suppress_body || !data_source) {
        rv = nghttp2_submit_response2(
            impl_->session, stream_id, nva.data(), nva.size(), nullptr);
    } else {
        nghttp2_data_provider2 data_prd;
        data_prd.source.ptr = data_source.get();
        data_prd.read_callback = DataSourceReadCallback;
        rv = nghttp2_submit_response2(
            impl_->session, stream_id, nva.data(), nva.size(), &data_prd);
        if (rv == 0) {
            stream->SetDataSource(std::move(data_source));
        }
    }

    if (rv != 0) {
        logging::Get()->error(
            "Failed to submit streaming response for stream {}: {}",
            stream_id, nghttp2_strerror(rv));
        return rv;
    }

    stream->MarkResponseHeadersSent();
    stream->MarkFinalResponseSubmitted();
    return 0;
}

// ---- HTTP/2 server push (RFC 9113 §8.4) ----

bool Http2Session::PushEnabled() const {
    if (!settings_.enable_push) return false;
    // nghttp2 tracks the peer's most-recently-ACKed remote settings; the
    // getter returns the protocol default (1 for ENABLE_PUSH) until the
    // peer ACKs an explicit value, so a brand-new connection treats push
    // as allowed unless the peer explicitly refuses.
    uint32_t remote = nghttp2_session_get_remote_settings(
        impl_->session, NGHTTP2_SETTINGS_ENABLE_PUSH);
    return remote != 0;
}

Http2Stream* Http2Session::CreateServerInitiatedStream(int32_t stream_id) {
    auto [it, inserted] = streams_.emplace(
        stream_id, std::make_unique<Http2Stream>(stream_id));
    if (!inserted) {
        logging::Get()->warn(
            "CreateServerInitiatedStream: stream {} already exists; reusing",
            stream_id);
        return it->second.get();
    }
    // IMPORTANT: do NOT call OnStreamBecameIncomplete() here. Pushed streams
    // bypass the request-parsing lifecycle entirely — they are synthetic
    // server-side responses with no client request to parse. Including them
    // in the incomplete counter would (a) inflate OldestIncompleteStreamStart,
    // and (b) make the parse_timeout_sec branch of ResetExpiredStreams RST
    // a perfectly healthy push mid-response.
    //
    // MarkCounterDecremented sets dispatched_at_ to now() so the
    // async-deferred safety-cap timer is anchored from the moment the
    // push begins streaming, matching the contract of regular async
    // responses entering their handler-response budget.
    it->second->MarkCounterDecremented();
    // Fire stream_open_callback symmetrically with CreateStream so
    // per-connection (local_stream_count_) and per-server (active_h2_streams_)
    // counters stay balanced against the stream_close_callback that nghttp2
    // WILL fire when the pushed stream finalizes. Without this, pushed
    // streams would only decrement those counters — /stats would drift
    // negative by one per push and CompensateH2Streams could over-subtract
    // on abrupt close.
    if (callbacks_.stream_open_callback) {
        try { callbacks_.stream_open_callback(Owner(), stream_id); }
        catch (const std::exception& e) {
            logging::Get()->error("Stream open callback error (pushed): {}",
                                  e.what());
        }
    }
    return it->second.get();
}

void Http2Session::EraseStream(int32_t stream_id) {
    streams_.erase(stream_id);
}

int32_t Http2Session::SubmitPushPromise(
    int32_t parent_stream_id,
    const std::string& method, const std::string& scheme,
    const std::string& authority, const std::string& path,
    const HttpResponse& response) {
    // ---- Boundary validation ----
    // RFC 9113 §8.4: a server MUST only push GET or HEAD; clients MUST
    // reject anything else with PROTOCOL_ERROR. Reject locally so we
    // never produce a non-conforming PUSH_PROMISE on the wire.
    if (method != "GET" && method != "HEAD") {
        logging::Get()->warn(
            "push: invalid method '{}' (must be GET or HEAD) parent={}",
            method, parent_stream_id);
        return -1;
    }
    // URI schemes are case-insensitive per RFC 3986 §3.1. Lowercase once
    // for validation AND for the value we put on the wire — pseudo-header
    // values in HTTP/2 should be in canonical (lowercase) form so the
    // peer's HPACK decoder doesn't trip and so a misbehaving client that
    // passes :scheme=HTTPS here does not cause us to emit the same
    // non-canonical value in the PUSH_PROMISE.
    std::string scheme_lower = scheme;
    std::transform(scheme_lower.begin(), scheme_lower.end(),
                   scheme_lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    if (scheme_lower != "http" && scheme_lower != "https") {
        logging::Get()->warn(
            "push: invalid scheme '{}' parent={}", scheme, parent_stream_id);
        return -1;
    }
    if (authority.empty()) {
        logging::Get()->warn(
            "push: empty authority parent={}", parent_stream_id);
        return -1;
    }
    if (path.empty() || path[0] != '/') {
        logging::Get()->warn(
            "push: invalid path '{}' (must start with /) parent={}",
            path, parent_stream_id);
        return -1;
    }
    if (!PushEnabled()) {
        logging::Get()->debug(
            "push: disabled (local config or peer refused) parent={}",
            parent_stream_id);
        return -1;
    }
    if (IsGoawaySent()) {
        logging::Get()->debug(
            "push: GOAWAY already sent — refusing new promise parent={}",
            parent_stream_id);
        return -1;
    }
    auto* parent = FindStream(parent_stream_id);
    if (!parent || parent->IsClosed()) {
        logging::Get()->debug(
            "push: parent stream {} not open", parent_stream_id);
        return -1;
    }
    // Reject pushes once the parent's final response has been handed to
    // nghttp2. IsClosed() only transitions when nghttp2 actually closes
    // the stream (after the last DATA frame is sent to the peer); on a
    // large or backpressured body the parent can remain Open for a long
    // time AFTER SubmitResponse has already committed the terminal
    // response. Without this check, a stale push_resource closure
    // captured by an async handler could land a PUSH_PROMISE after
    // complete() — violating the ordering guarantee that pushes must
    // precede the final response bytes. FinalResponseSubmitted() is
    // set synchronously inside SubmitResponse on success, so it closes
    // the window regardless of how slowly the peer drains.
    if (parent->FinalResponseSubmitted()) {
        logging::Get()->debug(
            "push: parent stream {} final response already submitted; "
            "rejecting stale push", parent_stream_id);
        return -1;
    }
    // Pre-validate the pushed response BEFORE we announce a PUSH_PROMISE
    // on the wire. If we skipped this, a handler passing an invalid
    // response (e.g. status < 200) would cause the promise to go out,
    // followed by an immediate RST when SubmitResponse rejects the
    // response in the post-announce path — a benign but observable
    // failure on the wire. Gating here keeps the wire clean in the
    // expected rejection case. SubmitResponse itself rejects any 1xx
    // as a final response, so mirror that single check.
    if (response.GetStatusCode() < HttpStatus::OK) {
        logging::Get()->warn(
            "push: invalid response status {} (< 200) parent={}; rejecting "
            "before PUSH_PROMISE",
            response.GetStatusCode(), parent_stream_id);
        return -1;
    }

    // ---- Build the promise pseudo-headers ----
    // Local storage holds the pseudo-header strings until nghttp2 has
    // copied them. nghttp2 copies because we don't pass NO_COPY flags.
    std::vector<nghttp2_nv> promise_nva;
    promise_nva.reserve(4);
    auto add_ph = [&](const char* name, size_t name_len,
                      const std::string& value) {
        promise_nva.push_back({
            const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(name)),
            const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(value.c_str())),
            name_len, value.size(),
            NGHTTP2_NV_FLAG_NONE
        });
    };
    add_ph(":method",    7, method);
    // Emit the canonical (lowercase) scheme regardless of what the
    // caller passed — consistent with HTTP/2 lowercase conventions and
    // ensures a peer's HPACK decoder sees a well-formed value.
    add_ph(":scheme",    7, scheme_lower);
    add_ph(":authority", 10, authority);
    add_ph(":path",      5, path);

    int32_t promised = nghttp2_submit_push_promise(
        impl_->session, NGHTTP2_FLAG_NONE, parent_stream_id,
        promise_nva.data(), promise_nva.size(), nullptr);
    if (promised < 0) {
        logging::Get()->warn(
            "nghttp2_submit_push_promise failed parent={} rv={} ({})",
            parent_stream_id, promised, nghttp2_strerror(promised));
        return -1;
    }

    // ---- Register the synthetic stream AFTER nghttp2 accepted ----
    // Populate the request so SubmitResponse's HEAD body suppression
    // (req.method == "HEAD") and req.headers["host"] (used by header
    // rewriting / log correlation) reflect the pushed request.
    Http2Stream* pushed = CreateServerInitiatedStream(promised);
    HttpRequest& req = pushed->GetRequest();
    req.method  = method;
    req.path    = path;
    req.headers["host"] = authority;
    pushed->MarkHeadersComplete();
    pushed->MarkEndStream();

    // ---- Submit the response on the promised stream ----
    int rv = SubmitResponse(promised, response);
    if (rv != 0) {
        logging::Get()->warn(
            "push: SubmitResponse failed on promised stream {} rv={}",
            promised, rv);
        // Best-effort RST so the client releases bookkeeping for the
        // promised id. Do NOT EraseStream here — nghttp2 will fire
        // on_stream_close for the RST'd stream, and our
        // OnStreamCloseCallback must see the stream in streams_ so
        // stream_close_callback runs and decrements active_h2_streams_
        // + local_stream_count_ symmetrically with the +1 CreateServer
        // InitiatedStream applied via stream_open_callback. Erasing
        // eagerly would leave FindStream() returning nullptr when the
        // close callback fires, skipping the decrements and leaking
        // +1 on both counters per failed push. The normal cleanup path
        // (MarkStreamForRemoval + FlushDeferredRemovals) handles final
        // erase.
        int rv_rst = nghttp2_submit_rst_stream(
            impl_->session, NGHTTP2_FLAG_NONE,
            promised, NGHTTP2_INTERNAL_ERROR);
        if (rv_rst != 0) {
            // Extremely unlikely path, but if the RST itself fails
            // nghttp2 will never fire on_stream_close for this stream,
            // so the counter +1 from stream_open_callback would leak.
            // Fire a synthetic close_callback + MarkStreamForRemoval
            // to reconcile. We can safely MarkStreamForRemoval because
            // the next FlushDeferredRemovals will erase the entry and
            // nghttp2 treats its internal stream as already-reset
            // (or will at session teardown).
            logging::Get()->warn(
                "push: rollback RST submit failed stream={} rv={} ({}) — "
                "firing synthetic close_callback to reconcile counters",
                promised, rv_rst, nghttp2_strerror(rv_rst));
            if (callbacks_.stream_close_callback) {
                try {
                    callbacks_.stream_close_callback(
                        Owner(), promised, NGHTTP2_INTERNAL_ERROR);
                } catch (const std::exception& e) {
                    logging::Get()->error(
                        "Synthetic close_callback threw: {}", e.what());
                }
            }
            MarkStreamForRemoval(promised);
        }
        return -1;
    }
    logging::Get()->debug(
        "push: PUSH_PROMISE+response queued parent={} promised={} {} {}",
        parent_stream_id, promised, method, path);
    return promised;
}

void Http2Session::DispatchStreamRequest(Http2Stream* stream, int32_t stream_id) {
    // Count every dispatched request — including those rejected below by
    // content-length checks. Matches HTTP/1's request_count_callback which
    // fires at HandleCompleteRequest entry before any rejection.
    if (callbacks_.request_count_callback) {
        callbacks_.request_count_callback();
    }

    // Request parsing is complete — decrement the "incomplete" counter so
    // request_timeout_sec no longer applies to this stream. For async
    // (deferred) responses, the connection is kept alive via
    // Http2ConnectionHandler::UpdateDeadline's safety-deadline path (active
    // streams with zero incomplete), NOT by leaving the stream counted as
    // incomplete. That was tried but made request_timeout_sec cap the full
    // async handler lifetime, RST'ing proxy streams whose upstream was
    // still responding within the longer proxy.response_timeout_ms budget.
    OnStreamNoLongerIncomplete();
    stream->MarkCounterDecremented();

    const HttpRequest& req = stream->GetRequest();

    // Propagate dispatcher index for upstream pool partition affinity
    if (conn_) {
        req.dispatcher_index = conn_->dispatcher_index();
        // Propagate peer connection metadata for proxy header rewriting
        // (X-Forwarded-For, X-Forwarded-Proto) and log correlation (client_fd).
        req.client_ip = conn_->ip_addr();
        req.client_tls = conn_->HasTls();
        req.client_fd = conn_->fd();
    }

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
    // Async handler path: the framework has dispatched an async route and
    // will submit the real response on this stream later via
    // Http2ConnectionHandler::SubmitStreamResponse. Skipping here leaves the
    // stream open; H2's graceful-shutdown drain already waits on open
    // streams, and Http2ConnectionHandler::UpdateDeadline arms a rolling
    // safety deadline while active streams exist to suppress idle_timeout.
    if (response.IsDeferred()) {
        return;
    }
    SubmitResponse(stream_id, response);
}

void Http2Session::SubmitGoawayChecked(uint32_t error_code,
                                        int32_t last_stream_id_override,
                                        bool flush) {
    if (goaway_sent_) return;

    int32_t last_id = (last_stream_id_override >= 0)
        ? last_stream_id_override
        : last_stream_id_.load(std::memory_order_acquire);

    // Audit log BEFORE submit so flood-triggered GOAWAYs are visible in
    // operator logs alongside the flood warn — previously only the
    // dedicated SendGoaway() path emitted an info line, leaving the
    // SETTINGS/PING/RST flood branches with no GOAWAY audit trail.
    logging::Get()->info(
        "H2 sending GOAWAY fd={} last_stream_id={} error_code={}",
        conn_ ? conn_->fd() : -1, last_id, error_code);

    int rv = nghttp2_submit_goaway(impl_->session, NGHTTP2_FLAG_NONE,
                                    last_id, error_code, nullptr, 0);
    if (rv != 0) {
        // A failed submit does NOT latch the flag — leaving goaway_sent_
        // false lets later logic retry or proceed. Previously the flag
        // was set before the rv check, so a failed submit would make
        // WaitForH2Drain wait for the full shutdown_drain_timeout_sec
        // even though no GOAWAY was ever queued.
        logging::Get()->warn(
            "nghttp2_submit_goaway failed fd={} rv={} ({}) — drain may wait",
            conn_ ? conn_->fd() : -1, rv, nghttp2_strerror(rv));
        if (flush) SendPendingFrames();
        return;
    }
    goaway_sent_ = true;
    if (flush) SendPendingFrames();
}

void Http2Session::SendGoaway(uint32_t error_code) {
    // Audit log is emitted inside SubmitGoawayChecked so flood-path
    // callers get the same entry.
    SubmitGoawayChecked(error_code, /*last_stream_id_override=*/-1, /*flush=*/true);
}

void Http2Session::ResetStream(int32_t stream_id, uint32_t error_code) {
    int rv = nghttp2_submit_rst_stream(
        impl_->session, NGHTTP2_FLAG_NONE, stream_id, error_code);
    if (rv != 0) {
        logging::Get()->warn(
            "nghttp2_submit_rst_stream failed stream={} rv={} ({})",
            stream_id, rv, nghttp2_strerror(rv));
    }
    SendPendingFrames();
}

int Http2Session::ResumeStreamData(int32_t stream_id) {
    int rv = nghttp2_session_resume_data(impl_->session, stream_id);
    if (rv != 0) {
        logging::Get()->warn(
            "nghttp2_session_resume_data failed stream={} rv={} ({})",
            stream_id, rv, nghttp2_strerror(rv));
    }
    return rv;
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

size_t Http2Session::ResetExpiredStreams(int parse_timeout_sec,
                                          int async_cap_sec,
                                          std::vector<int32_t>* async_cap_reset_ids) {
    auto now = std::chrono::steady_clock::now();
    auto parse_limit = std::chrono::seconds(parse_timeout_sec);
    size_t count = 0;

    for (auto& [id, stream] : streams_) {
        if (stream->IsCounterDecremented()) {
            // Once the handler has submitted response headers the stream
            // is no longer "awaiting async completion" — it is streaming
            // a real response (sync responses, async responses post-
            // completion, long downloads, SSE, etc.). nghttp2 owns body
            // delivery from here on out; flow control + client backpressure
            // govern the timing. Applying the async safety cap to these
            // streams would spuriously RST legitimate long downloads.
            if (stream->IsResponseHeadersSent()) continue;

            // Async streams whose handler has NOT yet submitted headers:
            // normally bounded by the handler's own timeout
            // (proxy.response_timeout_ms, custom deadlines). The
            // async_cap_sec here is an absolute safety net for stuck
            // handlers that never submit a response. The effective cap
            // is PER-STREAM: if the request set an override
            // (req.async_cap_sec_override >= 0) that wins for THIS
            // stream. Otherwise fall back to the connection-level
            // async_cap_sec parameter. An override of 0 disables the
            // cap entirely for that stream (used by proxies with
            // response_timeout_ms=0 to support SSE / long-poll /
            // intentionally unbounded backends — the operator's
            // configured "disabled" semantic).
            //
            // Anchor the check at DispatchedAt() (when the stream
            // transitioned from "being parsed" to "awaiting async
            // response"), NOT CreatedAt(). Uploads on slow links can
            // consume minutes before DispatchStreamRequest fires; using
            // CreatedAt() would cause the cap to trip immediately after
            // dispatch even though the handler has barely started its
            // work. DispatchedAt() == time_point::max() when the stream
            // has not been dispatched — and in that case IsCounterDecremented
            // is false, so we never hit this branch with the sentinel.
            const auto& req = stream->GetRequest();
            int effective_cap = (req.async_cap_sec_override >= 0)
                              ? req.async_cap_sec_override
                              : async_cap_sec;
            if (effective_cap > 0 &&
                now - stream->DispatchedAt() > std::chrono::seconds(effective_cap)) {
                logging::Get()->warn(
                    "HTTP/2 async stream {} exceeded async cap ({}s) "
                    "without completion; RST'ing to release slot",
                    id, effective_cap);
                stream->MarkRejected();
                nghttp2_submit_rst_stream(impl_->session, NGHTTP2_FLAG_NONE,
                                          id, NGHTTP2_CANCEL);
                if (async_cap_reset_ids) {
                    async_cap_reset_ids->push_back(id);
                }
                ++count;
            }
            continue;
        }
        // Incomplete stream parse timeout — only when configured.
        if (parse_timeout_sec <= 0) continue;
        // Check incomplete AND rejected-but-not-closed streams.
        // Rejected streams (e.g. 417 Expect) may be half-open on the client
        // side — RST them to free nghttp2 max_concurrent_streams slots.
        if (now - stream->CreatedAt() > parse_limit) {
            logging::Get()->warn("HTTP/2 stream {} timed out ({}s)", id, parse_timeout_sec);
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
                // Queue GOAWAY via the checked helper. flush=false because
                // this runs inside nghttp2_session_mem_recv2; the caller
                // flushes after recv returns. Use live stream ID — the
                // cached last_stream_id_ may be stale mid-recv.
                int32_t live_last = nghttp2_session_get_last_proc_stream_id(
                    impl_->session);
                SubmitGoawayChecked(NGHTTP2_ENHANCE_YOUR_CALM,
                                    live_last, /*flush=*/false);
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
                int32_t live_last = nghttp2_session_get_last_proc_stream_id(
                    impl_->session);
                SubmitGoawayChecked(NGHTTP2_ENHANCE_YOUR_CALM,
                                    live_last, /*flush=*/false);
                return false;
            }
        }
        break;
    case NGHTTP2_RST_STREAM:
        ++rst_stream_count_;
        if (rst_stream_count_ > HTTP2_CONSTANTS::MAX_RST_STREAM_PER_INTERVAL) {
            logging::Get()->warn("HTTP/2 RST_STREAM flood detected (rapid reset) fd={}",
                                 conn_ ? conn_->fd() : -1);
            int32_t live_last = nghttp2_session_get_last_proc_stream_id(
                impl_->session);
            SubmitGoawayChecked(NGHTTP2_ENHANCE_YOUR_CALM,
                                live_last, /*flush=*/false);
            return false;
        }
        break;
    default:
        break;
    }

    return true;
}
