#include "http2/http2_session.h"
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
        if (self->IsGoawaySent() || self->GetConnection()->IsCloseDeferred()) {
            nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                      frame->hd.stream_id, NGHTTP2_REFUSED_STREAM);
            return 0;
        }

        // New request — create stream
        int32_t stream_id = frame->hd.stream_id;
        auto* stream = self->CreateStream(stream_id);
        if (!stream) {
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

    // Enforce max_header_list_size on ALL header frames (request + trailers).
    // RFC 7541 Section 4.1: entry size = name + value + 32.
    // nghttp2 advertises this in SETTINGS but does NOT enforce it on the receive side.
    stream->AddHeaderBytes(namelen, valuelen);
    if (self->MaxHeaderListSize() > 0 &&
        stream->AccumulatedHeaderSize() > self->MaxHeaderListSize()) {
        logging::Get()->warn("HTTP/2 stream {} header list size ({}) exceeds limit ({})",
                             frame->hd.stream_id, stream->AccumulatedHeaderSize(),
                             self->MaxHeaderListSize());
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
        if (hdr_name == "connection" || hdr_name == "keep-alive" ||
            hdr_name == "proxy-connection" || hdr_name == "transfer-encoding" ||
            hdr_name == "upgrade" || hdr_name == "te") {
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
    // Comparison is case-insensitive per RFC 9110 Section 5.6.2 (HTTP tokens).
    if (hdr_name == "te") {
        std::string te_lower = hdr_value;
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

        if (frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
            // Initial request headers
            stream->MarkHeadersComplete();

            // Validate required pseudo-headers (RFC 9113 Section 8.3.1).
            const auto& req = stream->GetRequest();
            bool valid = true;

            if (req.method == "CONNECT") {
                // CONNECT: MUST have :method + :authority. MUST NOT have :path/:scheme.
                // Check HasAuthority (not HasHeader("host")) — a regular host header
                // is not a substitute for the :authority pseudo-header.
                if (!stream->HasAuthority()) valid = false;
                if (!req.path.empty() || stream->HasScheme()) valid = false;
            } else {
                // Non-CONNECT: MUST have :method, :path, :scheme.
                if (req.method.empty() || req.path.empty() || !stream->HasScheme()) {
                    valid = false;
                }
                // :authority or host SHOULD be present
                if (!req.HasHeader("host")) valid = false;
            }

            if (!valid) {
                logging::Get()->warn("HTTP/2 stream {} invalid pseudo-headers for {} request",
                                     frame->hd.stream_id, req.method);
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
                    // Unsupported Expect value — reject with 417 and RST.
                    // submit_response2 with no data provider sends END_STREAM
                    // from the server side. RST_STREAM then closes the client
                    // side so the stream doesn't linger in half-closed state.
                    nghttp2_nv nva_417[] = {
                        {const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(":status")),
                         const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>("417")),
                         7, 3, NGHTTP2_NV_FLAG_NONE}
                    };
                    nghttp2_submit_response2(session, frame->hd.stream_id,
                                             nva_417, 1, nullptr);
                    nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                              frame->hd.stream_id, NGHTTP2_NO_ERROR);
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

    // Notify the connection handler. It is safe to invoke std::function
    // callbacks from within nghttp2 callbacks as long as we do not modify
    // nghttp2 state (e.g., submit frames) inside the callback.
    if (self->Callbacks().stream_close_callback) {
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
    bool sent_any = false;
    for (;;) {
        const uint8_t* data;
        ssize_t len = nghttp2_session_mem_send2(impl_->session, &data);
        if (len < 0) {
            logging::Get()->error("nghttp2_session_mem_send2 error: {}",
                                  nghttp2_strerror(static_cast<int>(len)));
            break;
        }
        if (len == 0) break;

        conn_->SendRaw(reinterpret_cast<const char*>(data),
                        static_cast<size_t>(len));
        sent_any = true;
    }

    // Flush deferred stream removals. OnStreamCloseCallback can fire during
    // mem_send2 (when nghttp2 finalizes response frames). Without this,
    // closed streams and their ResponseDataSource stay resident until the
    // next ReceiveData call, which may not come on idle keep-alive connections.
    FlushDeferredRemovals();

    return sent_any;
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

    // Determine if the response body must be suppressed.
    // RFC 9110 Section 9.3.2: HEAD responses include headers as if GET but no body.
    // RFC 9110 Section 15.3.5: 204 MUST NOT contain a body.
    // RFC 9110 Section 15.3.6: 205 MUST NOT generate content.
    // RFC 9110 Section 15.4.5: 304 MUST NOT contain a body.
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
        if (key == "content-length") {
            continue;
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

std::chrono::steady_clock::time_point Http2Session::OldestIncompleteStreamStart() const {
    // streams_ is std::map<int32_t, ...> sorted by stream ID.
    // HTTP/2 stream IDs are monotonically increasing, so the first
    // non-dispatched, non-rejected stream is the oldest incomplete one.
    for (const auto& [id, stream] : streams_) {
        if (!stream->IsCounterDecremented() && !stream->IsRejected()) {
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
        if (stream->IsCounterDecremented() || stream->IsRejected()) continue;
        // This stream is incomplete — check if it's expired
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
                logging::Get()->warn("HTTP/2 SETTINGS flood detected");
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
                logging::Get()->warn("HTTP/2 PING flood detected");
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
            logging::Get()->warn("HTTP/2 RST_STREAM flood detected (rapid reset)");
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
