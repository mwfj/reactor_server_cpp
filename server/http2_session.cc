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

    if (frame->hd.type != NGHTTP2_HEADERS ||
        frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
        return 0;
    }

    int32_t stream_id = frame->hd.stream_id;
    auto* stream = self->CreateStream(stream_id);
    if (!stream) {
        // Too many streams or allocation failure
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    stream->SetState(Http2Stream::State::OPEN);

    return 0;
}

static int OnHeaderCallback(
    nghttp2_session* session, const nghttp2_frame* frame,
    const uint8_t* name, size_t namelen,
    const uint8_t* value, size_t valuelen,
    uint8_t /*flags*/, void* user_data) {

    auto* self = static_cast<Http2Session*>(user_data);

    if (frame->hd.type != NGHTTP2_HEADERS ||
        frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
        return 0;
    }

    auto* stream = self->FindStream(frame->hd.stream_id);
    if (!stream) return 0;

    std::string hdr_name(reinterpret_cast<const char*>(name), namelen);
    std::string hdr_value(reinterpret_cast<const char*>(value), valuelen);

    // Validate forbidden HTTP/2 connection-level headers (RFC 9113 Section 8.2.2)
    if (hdr_name == "connection" || hdr_name == "keep-alive" ||
        hdr_name == "proxy-connection" || hdr_name == "transfer-encoding" ||
        hdr_name == "upgrade") {
        logging::Get()->warn("HTTP/2 stream {} received forbidden header: {}",
                             frame->hd.stream_id, hdr_name);
        int rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                           frame->hd.stream_id, NGHTTP2_PROTOCOL_ERROR);
        if (rv < 0) {
            logging::Get()->error("nghttp2_submit_rst_stream failed: {}", nghttp2_strerror(rv));
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }

    // TE header: only "trailers" is allowed in HTTP/2 (RFC 9113 Section 8.2.2)
    if (hdr_name == "te" && hdr_value != "trailers") {
        logging::Get()->warn("HTTP/2 stream {} received invalid TE value: {}",
                             frame->hd.stream_id, hdr_value);
        int rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                           frame->hd.stream_id, NGHTTP2_PROTOCOL_ERROR);
        if (rv < 0) {
            logging::Get()->error("nghttp2_submit_rst_stream failed: {}", nghttp2_strerror(rv));
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }

    stream->AddHeader(hdr_name, hdr_value);
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
        int rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                           stream_id, NGHTTP2_CANCEL);
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
        if (frame->headers.cat != NGHTTP2_HCAT_REQUEST) break;

        auto* stream = self->FindStream(frame->hd.stream_id);
        if (!stream) break;

        stream->MarkHeadersComplete();

        // Validate required pseudo-headers
        const auto& req = stream->GetRequest();
        if (req.method.empty() || req.path.empty()) {
            logging::Get()->warn("HTTP/2 stream {} missing required pseudo-headers",
                                 frame->hd.stream_id);
            int rst_rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                                   frame->hd.stream_id, NGHTTP2_PROTOCOL_ERROR);
            if (rst_rv < 0) {
                logging::Get()->error("nghttp2_submit_rst_stream failed: {}",
                                      nghttp2_strerror(rst_rv));
                return NGHTTP2_ERR_CALLBACK_FAILURE;
            }
            break;
        }

        // If END_STREAM is set on HEADERS, the request has no body
        if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
            stream->MarkEndStream();
        }

        // If request is complete (END_STREAM on HEADERS), dispatch now.
        // It is safe to call nghttp2_submit_response from within
        // on_frame_recv_callback — the response is queued internally
        // and flushed by the next SendPendingFrames() call.
        if (stream->IsRequestComplete() && self->Callbacks().request_callback) {
            HttpResponse response;
            try {
                // nullptr is intentional: Http2Session has no reference to
                // Http2ConnectionHandler. The HttpServer callback captures
                // its context via lambda and ignores this parameter.
                self->Callbacks().request_callback(
                    nullptr, frame->hd.stream_id,
                    stream->GetRequest(), response);
            } catch (const std::exception& e) {
                logging::Get()->error("Exception in HTTP/2 request handler: {}",
                                      e.what());
                response = HttpResponse::InternalError();
            }
            self->SubmitResponse(frame->hd.stream_id, response);
        }
        break;
    }
    case NGHTTP2_DATA: {
        auto* stream = self->FindStream(frame->hd.stream_id);
        if (!stream) break;

        if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
            stream->MarkEndStream();

            // Request with body is now complete — dispatch
            if (stream->IsRequestComplete() && self->Callbacks().request_callback) {
                HttpResponse response;
                try {
                    // nullptr is intentional: see HEADERS case above.
                    self->Callbacks().request_callback(
                        nullptr, frame->hd.stream_id,
                        stream->GetRequest(), response);
                } catch (const std::exception& e) {
                    logging::Get()->error("Exception in HTTP/2 request handler: {}",
                                          e.what());
                    response = HttpResponse::InternalError();
                }
                self->SubmitResponse(frame->hd.stream_id, response);
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
        stream->SetState(Http2Stream::State::CLOSED);
    }

    // Defer removal — never delete during nghttp2 callback
    self->MarkStreamForRemoval(stream_id);

    // Notify the connection handler. It is safe to invoke std::function
    // callbacks from within nghttp2 callbacks as long as we do not modify
    // nghttp2 state (e.g., submit frames) inside the callback.
    if (self->Callbacks().stream_close_callback) {
        try {
            self->Callbacks().stream_close_callback(nullptr, stream_id, error_code);
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

    // Create callbacks
    nghttp2_session_callbacks_new(&impl_->callbacks);
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

    // Create options
    nghttp2_option_new(&impl_->option);
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

    if (rv < 0) {
        logging::Get()->error("nghttp2_session_mem_recv2 error: {}",
                              nghttp2_strerror(static_cast<int>(rv)));
        return rv;
    }

    // Update last_stream_id_ for GOAWAY
    last_stream_id_ = nghttp2_session_get_last_proc_stream_id(impl_->session);

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

    // Build nghttp2 header name-value pairs.
    // We do NOT use NGHTTP2_NV_FLAG_NO_COPY_NAME or NO_COPY_VALUE:
    // those flags skip nghttp2's internal copy, but we cannot guarantee
    // the string storage (status_str, content_length_str, and the
    // HttpResponse headers) outlives the nghttp2_submit_response2 call.
    // Without NO_COPY, nghttp2 copies the name/value data internally.
    std::string status_str = std::to_string(response.GetStatusCode());

    std::vector<nghttp2_nv> nva;
    // :status pseudo-header (required first)
    nva.push_back({
        const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(":status")),
        const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(status_str.c_str())),
        7, status_str.size(),
        NGHTTP2_NV_FLAG_NONE
    });

    // Regular headers
    const auto& headers = response.GetHeaders();
    for (const auto& hdr : headers) {
        nva.push_back({
            const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(hdr.first.c_str())),
            const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(hdr.second.c_str())),
            hdr.first.size(), hdr.second.size(),
            NGHTTP2_NV_FLAG_NONE
        });
    }

    // Add content-length if body is non-empty and not already present
    std::string content_length_str;
    const std::string& body = response.GetBody();
    bool has_content_length = false;
    for (const auto& hdr : headers) {
        std::string key = hdr.first;
        std::transform(key.begin(), key.end(), key.begin(), ::tolower);
        if (key == "content-length") {
            has_content_length = true;
            break;
        }
    }
    if (!body.empty() && !has_content_length) {
        content_length_str = std::to_string(body.size());
        nva.push_back({
            const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>("content-length")),
            const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(content_length_str.c_str())),
            14, content_length_str.size(),
            NGHTTP2_NV_FLAG_NONE
        });
    }

    int rv;
    if (body.empty()) {
        // No body — submit headers with END_STREAM
        rv = nghttp2_submit_response2(impl_->session, stream_id,
                                      nva.data(), nva.size(), nullptr);
    } else {
        // Body present — use data provider.
        // Store the ResponseDataSource on the stream so it is owned and freed
        // when the stream is destroyed (avoids the prior raw-new leak).
        auto src_owned = std::make_unique<ResponseDataSource>(ResponseDataSource{body, 0});
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
        empty_frame_count_ = 0;
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
                    nghttp2_submit_goaway(impl_->session, NGHTTP2_FLAG_NONE,
                                         last_stream_id_, NGHTTP2_ENHANCE_YOUR_CALM,
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
                    nghttp2_submit_goaway(impl_->session, NGHTTP2_FLAG_NONE,
                                         last_stream_id_, NGHTTP2_ENHANCE_YOUR_CALM,
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
                nghttp2_submit_goaway(impl_->session, NGHTTP2_FLAG_NONE,
                                     last_stream_id_, NGHTTP2_ENHANCE_YOUR_CALM,
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
