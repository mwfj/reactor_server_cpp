#include "http/http_connection_handler.h"
#include "http/http_router.h"   // AsyncPendingState / AsyncMiddlewarePayload
#include "http/http_server.h"   // HttpServer::FinalizeIfSnapshot
#include "http/http_status.h"
#include "http/trailer_policy.h"
#include "http/streaming_response_sender_utils.h"
#include "http/body_stream_impl.h"
#include "log/logger.h"
#include "log/log_utils.h"
#include "observability/observability_manager.h"  // ->FinalizeFromSnapshot mgr-method calls
#include "observability/observability_snapshot.h"
#include <cstdio>
#include <sstream>
#include <unordered_set>

namespace {
static constexpr size_t DEFAULT_STREAM_HIGH_WATER_BYTES = 1024 * 1024;
static constexpr size_t DEFAULT_STREAM_LOW_WATER_BYTES =
    DEFAULT_STREAM_HIGH_WATER_BYTES / 2;

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

// Returns true if `lower_name` (must already be lowercased) is a
// hop-by-hop or framing header that is forbidden in 1xx interim responses
// per RFC 9110 §15.2 and RFC 7230 §6.1.
bool IsForbiddenInterimHeader(const std::string& lower_name) {
    if (lower_name == "connection" || lower_name == "keep-alive" ||
        lower_name == "proxy-connection" ||
        lower_name == "transfer-encoding" || lower_name == "content-length" ||
        lower_name == "te" || lower_name == "upgrade") {
        return true;
    }
    // Proxy-*  (Proxy-Authenticate, Proxy-Authorization, etc.)
    if (lower_name.size() >= 6 && lower_name.compare(0, 6, "proxy-") == 0) {
        return true;
    }
    return false;
}

// Returns the standard reason phrase for 1xx status codes.
const char* InterimReasonPhrase(int code) {
    switch (code) {
        case 100: return "Continue";
        case 102: return "Processing";
        case 103: return "Early Hints";
        default:  return "Interim";
    }
}

std::optional<std::string> FirstHeaderValueCI(
    const std::vector<std::pair<std::string, std::string>>& headers,
    const std::string& lower_name) {
    for (const auto& [key, value] : headers) {
        std::string lower = key;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        if (lower == lower_name) return value;
    }
    return std::nullopt;
}

struct PreparedStreamingHead {
    std::string wire;
    bool use_chunked = false;
    bool should_close = false;
    bool body_suppressed = false;
};

using AllowedTrailerNameSet = std::unordered_set<std::string>;

AllowedTrailerNameSet CollectAllowedTrailerNames(
    const std::vector<std::pair<std::string, std::string>>& headers,
    std::vector<std::string>* declared_names = nullptr) {
    AllowedTrailerNameSet allowed_names;
    for (const auto& [key, value] : headers) {
        std::string lower = key;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        if (lower != "trailer") {
            continue;
        }

        size_t start = 0;
        while (start <= value.size()) {
            size_t comma = value.find(',', start);
            std::string token = TrimOptionalWhitespace(
                value.substr(start, comma == std::string::npos
                                        ? std::string::npos
                                        : comma - start));
            if (!token.empty()) {
                std::string lower_token = token;
                std::transform(lower_token.begin(), lower_token.end(),
                               lower_token.begin(),
                               [](unsigned char c) { return std::tolower(c); });
                if (!IsForbiddenTrailerFieldName(lower_token)) {
                    if (declared_names) {
                        declared_names->push_back(token);
                    }
                    allowed_names.insert(std::move(lower_token));
                }
            }
            if (comma == std::string::npos) {
                break;
            }
            start = comma + 1;
        }
    }

    return allowed_names;
}

std::optional<std::string> MergeAllowedTrailerDeclarations(
    const std::vector<std::pair<std::string, std::string>>& headers) {
    std::vector<std::string> declared_names;
    CollectAllowedTrailerNames(headers, &declared_names);

    if (declared_names.empty()) {
        return std::nullopt;
    }

    std::string merged = declared_names.front();
    for (size_t i = 1; i < declared_names.size(); ++i) {
        merged += ", ";
        merged += declared_names[i];
    }
    return merged;
}

std::optional<std::string> ComputeEffectiveStreamingContentLength(
    const HttpResponse& response) {
    const int status_code = response.GetStatusCode();
    if (response.IsContentLengthPreserved() ||
        status_code == HttpStatus::RESET_CONTENT ||
        status_code == HttpStatus::NOT_MODIFIED) {
        return response.ComputeWireContentLength(status_code);
    }
    return std::nullopt;
}

std::string SerializeStreamingHead(const HttpResponse& response,
                                   int http_minor,
                                   bool use_chunked,
                                   bool allow_content_length = true) {
    std::ostringstream oss;
    // Streaming headers are emitted before the final body length is known. Only
    // preserve an explicit known length (or status-defined wire values like
    // 205/304); never auto-compute from the empty headers-only body.
    std::optional<std::string> effective_cl =
        (!allow_content_length || use_chunked) ? std::nullopt
                                               : ComputeEffectiveStreamingContentLength(response);
    auto merged_trailer = MergeAllowedTrailerDeclarations(response.GetHeaders());

    oss << "HTTP/1." << http_minor << " " << response.GetStatusCode()
        << " " << response.GetStatusReason() << "\r\n";
    for (const auto& [key, value] : response.GetHeaders()) {
        std::string lower = key;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        if (lower == "transfer-encoding") continue;
        if (lower == "content-length") continue;
        if (lower == "trailer") continue;
        oss << key << ": " << value << "\r\n";
    }
    if (use_chunked && merged_trailer) {
        oss << "Trailer: " << *merged_trailer << "\r\n";
    }
    if (effective_cl) {
        oss << "Content-Length: " << *effective_cl << "\r\n";
    }
    if (use_chunked) {
        oss << "Transfer-Encoding: chunked\r\n";
    }
    oss << "\r\n";
    return oss.str();
}

std::string EncodeChunkTerminator(
    const std::vector<std::pair<std::string, std::string>>& trailers,
    const AllowedTrailerNameSet& declared_trailer_names) {
    auto strip_crlf = [](std::string s) -> std::string {
        s.erase(std::remove(s.begin(), s.end(), '\r'), s.end());
        s.erase(std::remove(s.begin(), s.end(), '\n'), s.end());
        return s;
    };

    std::string out = "0\r\n";
    for (const auto& [key, value] : trailers) {
        std::string sanitized_key = strip_crlf(key);
        std::string sanitized_value = strip_crlf(value);
        std::string lower = sanitized_key;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        if (IsForbiddenTrailerFieldName(lower)) {
            logging::Get()->warn(
                "H1 streaming dropped forbidden trailer field '{}'",
                key);
            continue;
        }
        if (declared_trailer_names.find(lower) ==
            declared_trailer_names.end()) {
            logging::Get()->warn(
                "H1 streaming dropped undeclared trailer field '{}'",
                key);
            continue;
        }
        out += sanitized_key;
        out += ": ";
        out += sanitized_value;
        out += "\r\n";
    }
    out += "\r\n";
    return out;
}

class H1StreamingResponseSenderImpl final
    : public HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::Impl,
      public std::enable_shared_from_this<H1StreamingResponseSenderImpl> {
public:
    using SendResult =
        HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::SendResult;
    using AbortReason =
        HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::AbortReason;
    using DrainListener =
        HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::DrainListener;

    using PrepareHeadCallback = std::function<std::optional<PreparedStreamingHead>(
        const HttpResponse&)>;
    using FinalizeResponseCallback = std::function<void(bool)>;
    using AbortResponseCallback = std::function<void()>;

    H1StreamingResponseSenderImpl(
        std::shared_ptr<ConnectionHandler> conn,
        std::function<bool()> claim_response,
        std::function<void(int, uint64_t, std::string)> finalize_request,
        PrepareHeadCallback prepare_head,
        FinalizeResponseCallback finalize_response,
        AbortResponseCallback abort_response,
        std::function<void()> mark_response_committed)
        : conn_(std::move(conn)),
          claim_response_(std::move(claim_response)),
          finalize_request_(std::move(finalize_request)),
          prepare_head_(std::move(prepare_head)),
          finalize_response_(std::move(finalize_response)),
          abort_response_(std::move(abort_response)),
          mark_response_committed_(std::move(mark_response_committed)) {}

    int SendHeaders(const HttpResponse& headers_only_response) override {
        if (!conn_ || conn_->IsClosing()) {
            logging::Get()->debug(
                "H1 streaming SendHeaders rejected fd={} connection unavailable",
                conn_ ? conn_->fd() : -1);
            return -1;
        }
        if (!conn_->IsOnDispatcherThread()) {
            logging::Get()->error(
                "H1 streaming SendHeaders called off dispatcher fd={}",
                conn_->fd());
            return -1;
        }
        if (terminal_ || programmer_error_ || headers_sent_) {
            logging::Get()->debug(
                "H1 streaming SendHeaders rejected fd={} terminal={} programmer_error={} headers_sent={}",
                conn_->fd(), terminal_, programmer_error_, headers_sent_);
            return -1;
        }
        if (headers_only_response.GetStatusCode() < HttpStatus::OK) {
            logging::Get()->error(
                "H1 streaming SendHeaders called with {} "
                "(1xx not supported as app final response) fd={}",
                headers_only_response.GetStatusCode(),
                conn_->fd());
            return -1;
        }
        auto prepared = prepare_head_ ? prepare_head_(headers_only_response)
                                      : std::nullopt;
        if (!prepared) {
            logging::Get()->debug(
                "H1 streaming SendHeaders prepare_head rejected fd={} closing={}",
                conn_ ? conn_->fd() : -1,
                conn_ ? conn_->IsClosing() : true);
            terminal_ = true;
            return -1;
        }
        if (!claimed_response_) {
            if (!claim_response_ || !claim_response_()) {
                terminal_ = true;
                logging::Get()->debug(
                    "H1 streaming SendHeaders failed to claim final response fd={}",
                    conn_->fd());
                return -1;
            }
            claimed_response_ = true;
        }

        use_chunked_ = prepared->use_chunked;
        should_close_ = prepared->should_close;
        body_suppressed_ = prepared->body_suppressed;
        declared_trailer_names_ =
            CollectAllowedTrailerNames(headers_only_response.GetHeaders());
        headers_sent_ = true;
        last_status_code_ = headers_only_response.GetStatusCode();
        if (mark_response_committed_) {
            mark_response_committed_();
        }
        conn_->SendRaw(prepared->wire.data(), prepared->wire.size());
        if (body_suppressed_) {
            // Mirrors the H2 SendHeaders fix: body-suppressed responses
            // (HEAD / 204 / 205 / 304 / 1xx) are fully on the wire after
            // the head bytes are flushed — there's no body, no chunked
            // terminator, and no trailers (PrepareHead disables chunked
            // for these). If the handler returns without End(), the
            // async-dispatch finalizers never run: active_requests_
            // stays elevated, observability records never close, and
            // crucially `finalize_response_` never clears
            // `deferred_response_pending_`, so on a keep-alive socket
            // the next pipelined bytes are stashed in
            // deferred_pending_buf_ and never parsed — the connection
            // wedges until the client gives up. End()'s body-suppressed
            // path runs the SAME two finalisers in the SAME order; we
            // run them here so handlers that omit End() still complete
            // cleanly. End() called afterward early-returns on
            // `terminal_` (no-op) so it remains safe to call.
            terminal_ = true;
            if (finalize_request_) {
                finalize_request_(last_status_code_, bytes_sent_,
                                    std::string{});
            }
            if (finalize_response_) {
                finalize_response_(should_close_);
            }
        }
        return 0;
    }

    SendResult SendData(const char* data, size_t len) override {
        if (!conn_ || conn_->IsClosing()) {
            logging::Get()->debug(
                "H1 streaming SendData rejected fd={} connection unavailable len={}",
                conn_ ? conn_->fd() : -1, len);
            return SendResult::CLOSED;
        }
        if (!conn_->IsOnDispatcherThread()) {
            logging::Get()->error(
                "H1 streaming SendData called off dispatcher fd={}",
                conn_->fd());
            return SendResult::CLOSED;
        }
        if (!headers_sent_) {
            return HandleProgrammerError("SendData");
        }
        // Body-suppressed (HEAD / 1xx / 204 / 205 / 304) silently drops
        // body bytes — there's no body on the wire. Must run BEFORE the
        // terminal_ guard because SendHeaders for body-suppressed
        // responses now sets terminal_=true (see SendHeaders body-
        // suppressed finalize path); a handler that follows SendHeaders
        // with SendData would otherwise observe CLOSED instead of the
        // ACCEPTED contract this branch documents.
        if (body_suppressed_) {
            return SendResult::ACCEPTED_BELOW_WATER;
        }
        if (terminal_ || programmer_error_) {
            logging::Get()->debug(
                "H1 streaming SendData rejected fd={} terminal={} programmer_error={} len={}",
                conn_->fd(), terminal_, programmer_error_, len);
            return SendResult::CLOSED;
        }
        if (use_chunked_) {
            if (len == 0) {
                return EvaluateOccupancy();
            }
            static constexpr size_t CHUNK_HEADER_BUF_SIZE = 32;
            char header[CHUNK_HEADER_BUF_SIZE];
            int header_len = std::snprintf(header, sizeof(header),
                                           "%zx\r\n", len);
            if (header_len <= 0 ||
                static_cast<size_t>(header_len) >= sizeof(header)) {
                logging::Get()->error(
                    "H1 streaming chunk header encode failed fd={} len={}",
                    conn_->fd(), len);
                AbortInternal(
                    true,
                    AbortReason::UPSTREAM_ERROR);
                return SendResult::CLOSED;
            }
            conn_->SendRaw(header, static_cast<size_t>(header_len));
            conn_->SendRaw(data, len);
            conn_->SendRaw("\r\n", 2);
        } else {
            conn_->SendRaw(data, len);
        }
        // Account bytes only after the SendRaw calls succeeded — the
        // chunk-encode-failure branch above aborts the stream BEFORE
        // any bytes hit the wire and must not contribute to
        // http.server.response.body.size.
        bytes_sent_ += len;
        return EvaluateOccupancy();
    }

    SendResult End(
        const std::vector<std::pair<std::string, std::string>>& trailers) override {
        if (!conn_ || conn_->IsClosing()) {
            logging::Get()->debug(
                "H1 streaming End rejected fd={} connection unavailable",
                conn_ ? conn_->fd() : -1);
            return SendResult::CLOSED;
        }
        if (!conn_->IsOnDispatcherThread()) {
            logging::Get()->error(
                "H1 streaming End called off dispatcher fd={}",
                conn_->fd());
            return SendResult::CLOSED;
        }
        if (!headers_sent_) {
            HandleProgrammerError("End");
            return SendResult::CLOSED;
        }
        if (terminal_ || programmer_error_) {
            logging::Get()->debug(
                "H1 streaming End rejected fd={} terminal={} programmer_error={}",
                conn_->fd(), terminal_, programmer_error_);
            return SendResult::CLOSED;
        }
        if (!use_chunked_ && !trailers.empty()) {
            logging::Get()->debug(
                "H1 streaming End dropping trailers on non-chunked response fd={} trailer_count={}",
                conn_->fd(), trailers.size());
        }
        terminal_ = true;
        if (use_chunked_) {
            std::string final_chunk = EncodeChunkTerminator(
                trailers, declared_trailer_names_);
            conn_->SendRaw(final_chunk.data(), final_chunk.size());
        }
        // finalize_request_ MUST run before finalize_response_:
        // finalize_response_ clears the deferred state and can
        // synchronously replay deferred_pending_buf_ back through
        // OnRawData, which begins parsing the next pipelined request
        // and (for keep-alive) starts request B's snapshot. Reversing
        // the order means request A's metric / span finalize lands
        // AFTER request B's middleware has registered, briefly
        // overlapping the two snapshots.
        if (finalize_request_) {
            finalize_request_(last_status_code_, bytes_sent_, std::string{});
        }
        if (finalize_response_) {
            finalize_response_(should_close_);
        }
        return SendResult::ACCEPTED_BELOW_WATER;
    }

    void Abort(AbortReason reason) override {
        if (!conn_ || conn_->IsClosing()) {
            return;
        }
        if (!conn_->IsOnDispatcherThread()) {
            logging::Get()->error(
                "H1 streaming Abort called off dispatcher fd={}",
                conn_->fd());
            return;
        }
        AbortInternal(false, reason);
    }

    void SetDrainListener(DrainListener listener) override {
        if (!conn_ || conn_->IsClosing()) {
            return;
        }
        if (!conn_->IsOnDispatcherThread()) {
            logging::Get()->error(
                "H1 streaming SetDrainListener called off dispatcher fd={}",
                conn_->fd());
            return;
        }
        drain_listener_ = std::move(listener);
        ++drain_listener_generation_;
        drain_listener_scheduled_ = false;
        if (!drain_listener_) {
            above_high_water_ = false;
            return;
        }
        MaybeFireDrainListener(conn_->OutputBufferSize());
    }

    void ConfigureWatermarks(size_t high_water_bytes) override {
        if (!conn_ || conn_->IsClosing()) {
            return;
        }
        if (!conn_->IsOnDispatcherThread()) {
            logging::Get()->error(
                "H1 streaming ConfigureWatermarks called off dispatcher fd={}",
                conn_->fd());
            return;
        }
        if (high_water_bytes == 0) return;
        high_water_ = high_water_bytes;
        low_water_ = high_water_ / 2;
    }

    Dispatcher* GetDispatcher() override {
        return conn_ ? conn_->GetDispatcher() : nullptr;
    }

    void OnDownstreamWriteProgress(size_t remaining_bytes) override {
        MaybeFireDrainListener(remaining_bytes);
    }

    void OnDownstreamWriteComplete() override {
        MaybeFireDrainListener(0);
    }

private:
    SendResult HandleProgrammerError(const char* op) {
        if (!programmer_error_) {
            logging::Get()->error(
                "H1 streaming {} called before SendHeaders — programmer error fd={}",
                op, conn_ ? conn_->fd() : -1);
            programmer_error_ = true;
            AbortInternal(true, AbortReason::UPSTREAM_ERROR);
        }
        return SendResult::CLOSED;
    }

    void AbortInternal(bool from_programmer_error, AbortReason reason) {
        if (terminal_ && !from_programmer_error) return;
        terminal_ = true;
        drain_listener_ = nullptr;
        ++drain_listener_generation_;
        above_high_water_ = false;
        drain_listener_scheduled_ = false;
        if (!claimed_response_) {
            if (!claim_response_ || !claim_response_()) {
                return;
            }
            claimed_response_ = true;
        }
        if (mark_response_committed_) {
            mark_response_committed_();
        }
        logging::Get()->debug(
            "H1 streaming abort fd={} reason={} programmer_error={}",
            conn_ ? conn_->fd() : -1,
            StreamingAbortReasonToString(reason),
            from_programmer_error);
        if (abort_response_) {
            abort_response_();
        }
        if (finalize_request_) {
            // last_status_code_ may be 0 if Abort fired before
            // SendHeaders — that's deliberately propagated so the
            // observability finalize knows the wire never carried a
            // status. bytes_sent_ is whatever was accepted before
            // the abort.
            finalize_request_(last_status_code_, bytes_sent_,
                                StreamingAbortReasonToString(reason));
        }
    }

    SendResult EvaluateOccupancy() {
        if (!conn_ || conn_->IsClosing()) {
            return SendResult::CLOSED;
        }
        if (conn_->OutputBufferSize() >= high_water_) {
            above_high_water_ = true;
            return SendResult::ACCEPTED_ABOVE_HIGH_WATER;
        }
        return SendResult::ACCEPTED_BELOW_WATER;
    }

    void MaybeFireDrainListener(size_t remaining_bytes) {
        if (!above_high_water_ || !drain_listener_ || drain_listener_scheduled_) {
            return;
        }
        if (remaining_bytes > low_water_) {
            return;
        }
        above_high_water_ = false;
        drain_listener_scheduled_ = true;
        auto listener = drain_listener_;
        const uint64_t generation = drain_listener_generation_;
        std::weak_ptr<H1StreamingResponseSenderImpl> weak_self =
            shared_from_this();
        conn_->RunOnDispatcher(
            [weak_self, listener = std::move(listener), generation]() mutable {
                if (auto self = weak_self.lock()) {
                    if (self->drain_listener_generation_ != generation) {
                        return;
                    }
                    self->drain_listener_scheduled_ = false;
                    if (listener) listener();
                }
            });
    }

    std::shared_ptr<ConnectionHandler> conn_;
    std::function<bool()> claim_response_;
    std::function<void(int, uint64_t, std::string)> finalize_request_;
    PrepareHeadCallback prepare_head_;
    FinalizeResponseCallback finalize_response_;
    AbortResponseCallback abort_response_;
    std::function<void()> mark_response_committed_;
    // State observed by SendHeaders/SendData/Abort and replayed to
    // finalize_request_ on End/Abort. Dispatcher-thread-only writes
    // and reads — no synchronization needed.
    int last_status_code_ = 0;
    uint64_t bytes_sent_ = 0;
    DrainListener drain_listener_;
    bool claimed_response_ = false;
    bool headers_sent_ = false;
    bool terminal_ = false;
    bool programmer_error_ = false;
    bool use_chunked_ = false;
    bool should_close_ = false;
    bool body_suppressed_ = false;
    AllowedTrailerNameSet declared_trailer_names_;
    bool above_high_water_ = false;
    bool drain_listener_scheduled_ = false;
    uint64_t drain_listener_generation_ = 0;
    size_t high_water_ = DEFAULT_STREAM_HIGH_WATER_BYTES;
    size_t low_water_ = DEFAULT_STREAM_LOW_WATER_BYTES;
};

}  // namespace

HttpConnectionHandler::HttpConnectionHandler(std::shared_ptr<ConnectionHandler> conn)
    : conn_(std::move(conn)) {
    // Wire parser streaming hooks once at construction — they capture `this`
    // directly (safe: parser_ is a member, lifetime matches).
    parser_.SetHeadersCompleteCallback([this]() {
        if (!callbacks_.resolve_route_options_callback) return;
        const HttpRequest& req = parser_.GetRequest();
        auto opts = callbacks_.resolve_route_options_callback(req.method, req.path);
        if (opts.request_mode != http::RouteRequestMode::Streaming) return;
        if (req.complete) return;  // END_STREAM on headers — no body coming

        std::weak_ptr<HttpConnectionHandler> weak_self = weak_from_this();
        http::ChunkQueueBodyStream::Config cfg;
        // Configured watermarks override the class defaults. 0 means
        // "no operator config supplied" (e.g. direct-ctor test paths).
        cfg.high_water_bytes = (streaming_high_water_bytes_ > 0)
            ? streaming_high_water_bytes_ : DEFAULT_STREAM_HIGH_WATER_BYTES;
        cfg.low_water_bytes  = (streaming_low_water_bytes_ > 0)
            ? streaming_low_water_bytes_ : DEFAULT_STREAM_LOW_WATER_BYTES;
        // Bind producer-side dispatcher so the watermark callbacks (which
        // touch transport read-pump state) always fire on the dispatcher
        // thread, even when the body stream's consumer drains from a
        // different dispatcher (the proxy/upstream side).
        if (conn_) {
            cfg.producer_dispatcher = conn_->dispatcher_ptr();
        }
        cfg.on_above_high_water = [weak_self]() {
            if (auto self = weak_self.lock()) {
                // Only pause the read pump once a consumer exists to drain.
                // Today the handler dispatches at message-complete; firing
                // IncReadDisable before then would stall the recv side mid-
                // upload and deadlock (no one to call DecReadDisable).
                if (!self->streaming_dispatched_) return;
                if (self->h1_streaming_pump_paused_) return;  // idempotent
                if (self->conn_) {
                    self->conn_->IncReadDisable();
                    self->h1_streaming_pump_paused_ = true;
                }
            }
        };
        cfg.on_below_low_water = [weak_self]() {
            if (auto self = weak_self.lock()) {
                // Pair the resume strictly with a previous pause — covers
                // the case where streaming_dispatched_ flips true between
                // the high-water and low-water fires (high-water observed
                // false, low-water observes true; without the paired flag
                // we'd over-enable the ReadDisable counter).
                if (!self->h1_streaming_pump_paused_) return;
                self->h1_streaming_pump_paused_ = false;
                if (self->conn_) self->conn_->DecReadDisable();
            }
        };
        auto body_stream = std::make_shared<http::ChunkQueueBodyStream>(std::move(cfg));
        parser_.set_streaming_body_stream(body_stream);
        parser_.GetRequest().body_stream = body_stream;
        streaming_upload_in_flight_ = true;
        // Signal the OnRawData loop to invoke the route handler immediately
        // after Parse() returns (outside the llhttp callback chain), so the
        // handler starts consuming body_stream as bytes arrive rather than
        // waiting for message-complete.
        streaming_dispatch_pending_ = true;
    });

    parser_.SetStreamingBodyCompleteCallback([this]() {
        streaming_upload_in_flight_ = false;
    });
}

void HttpConnectionHandler::SetRequestCallback(RequestCallback callback) {
    callbacks_.request_callback = std::move(callback);
}

void HttpConnectionHandler::SetRouteCheckCallback(RouteCheckCallback callback) {
    callbacks_.route_check_callback = std::move(callback);
}

void HttpConnectionHandler::SetMiddlewareCallback(MiddlewareCallback callback) {
    callbacks_.middleware_callback = std::move(callback);
}

void HttpConnectionHandler::SetResolveRouteOptionsCallback(
    HTTP_CALLBACKS_NAMESPACE::HttpConnResolveRouteOptionsCallback callback) {
    callbacks_.resolve_route_options_callback = std::move(callback);
}

void HttpConnectionHandler::SetAsyncMiddlewareCallback(
    HTTP_CALLBACKS_NAMESPACE::HttpConnAsyncMiddlewareCallback callback) {
    callbacks_.async_middleware_callback = std::move(callback);
}

void HttpConnectionHandler::SetUpgradeCallback(UpgradeCallback callback) {
    callbacks_.upgrade_callback = std::move(callback);
}

void HttpConnectionHandler::SetStreamingWatermarks(
    size_t high_water_bytes, size_t low_water_bytes) {
    streaming_high_water_bytes_ = high_water_bytes;
    streaming_low_water_bytes_  = low_water_bytes;
}

HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender
HttpConnectionHandler::CreateStreamingResponseSender(
    std::function<bool()> claim_response,
    std::function<void(int, uint64_t, std::string)> finalize_request) {
    auto weak_self = weak_from_this();
    auto prepare_head =
        [weak_self](const HttpResponse& input)
            -> std::optional<PreparedStreamingHead> {
        auto self = weak_self.lock();
        if (!self || !self->conn_ || self->conn_->IsClosing()) {
            return std::nullopt;
        }

        HttpResponse response = input;
        const int status_code = response.GetStatusCode();
        bool body_suppressed =
            self->deferred_was_head_ ||
            status_code < HttpStatus::OK ||
            status_code == HttpStatus::SWITCHING_PROTOCOLS ||
            status_code == HttpStatus::NO_CONTENT ||
            status_code == HttpStatus::RESET_CONTENT ||
            status_code == HttpStatus::NOT_MODIFIED;
        if (status_code == HttpStatus::RESET_CONTENT &&
            !FirstHeaderValueCI(response.GetHeaders(), "content-length")) {
            response.Header("Content-Length", "0");
        }

        const bool shutting_down =
            (self->callbacks_.shutdown_check_callback &&
             self->callbacks_.shutdown_check_callback()) ||
            (self->conn_ && self->conn_->IsCloseDeferred());
        const bool effective_keep_alive =
            self->deferred_keep_alive_ && !shutting_down;
        const int http_minor =
            self->current_http_minor_.load(std::memory_order_acquire);
        bool should_close = self->NormalizeOutgoingResponse(
            response, effective_keep_alive, http_minor);

        const bool has_effective_content_length =
            ComputeEffectiveStreamingContentLength(response).has_value();
        bool use_chunked = false;
        bool allow_content_length = true;
        if (!body_suppressed) {
            if (http_minor == 0) {
                // H1.0 streaming fallback is close-delimited, even when a
                // handler supplied a fixed length. This keeps the generic
                // streaming API aligned with the documented EOF-framed mode.
                response.Header("Connection", "close");
                should_close = true;
                allow_content_length = false;
            } else if (!has_effective_content_length) {
                use_chunked = true;
            }
        }

        return PreparedStreamingHead{
            SerializeStreamingHead(
                response, http_minor, use_chunked, allow_content_length),
            use_chunked,
            should_close,
            body_suppressed};
    };

    auto finalize_response = [weak_self](bool should_close) {
        auto self = weak_self.lock();
        if (!self || !self->conn_) return;

        self->deferred_response_pending_ = false;
        self->deferred_response_committed_ = false;
        self->deferred_was_head_ = false;
        self->deferred_keep_alive_ = true;
        self->deferred_start_ = std::chrono::steady_clock::time_point{};
        self->deferred_obs_snapshot_.reset();
        self->async_abort_hook_ = nullptr;

        if (self->conn_->IsClosing()) {
            self->conn_->SetShutdownExempt(false);
            self->deferred_pending_buf_.clear();
            return;
        }
        if (should_close) {
            self->deferred_pending_buf_.clear();
            self->CloseConnection();
            self->conn_->SetShutdownExempt(false);
            return;
        }

        self->conn_->SetShutdownExempt(false);
        self->conn_->ClearDeadline();
        self->conn_->SetDeadlineTimeoutCb(nullptr);

        if (!self->deferred_pending_buf_.empty()) {
            std::string pending = std::move(self->deferred_pending_buf_);
            self->deferred_pending_buf_.clear();
            self->OnRawData(self->conn_, pending);
        }
    };

    auto abort_response = [weak_self]() {
        auto self = weak_self.lock();
        if (!self || !self->conn_) return;

        self->deferred_response_pending_ = false;
        self->deferred_response_committed_ = false;
        self->deferred_was_head_ = false;
        self->deferred_keep_alive_ = true;
        self->deferred_pending_buf_.clear();
        self->deferred_start_ = std::chrono::steady_clock::time_point{};
        self->deferred_obs_snapshot_.reset();
        self->async_abort_hook_ = nullptr;
        self->conn_->SetShutdownExempt(false);
        self->conn_->ClearDeadline();
        self->conn_->SetDeadlineTimeoutCb(nullptr);
        if (!self->conn_->IsClosing()) {
            self->conn_->ForceClose();
        }
    };

    auto mark_response_committed = [weak_self]() {
        if (auto self = weak_self.lock()) {
            self->final_response_sent_.store(true, std::memory_order_release);
            self->deferred_response_committed_ = true;
        }
    };

    auto impl = std::make_shared<H1StreamingResponseSenderImpl>(
        conn_, std::move(claim_response), std::move(finalize_request),
        std::move(prepare_head), std::move(finalize_response),
        std::move(abort_response), std::move(mark_response_committed));
    active_stream_sender_impl_ = impl;
    return HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender(std::move(impl));
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
                    // Finalize any observability snapshot middleware
                    // attached to the in-flight request before the 408
                    // hits the wire — otherwise inflight_finalizations_
                    // leaks and the shutdown drain stalls.
                    // parser_.GetRequest() is the live request slot on
                    // the dispatcher thread that owns this callback;
                    // FinalizeIfSnapshot no-ops
                    // when no snapshot is attached (early-arrival case).
                    HttpServer::FinalizeIfSnapshot(
                        self->parser_.GetRequest(), timeout_resp,
                        "request_timeout");
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
    if (current_http_minor_.load(std::memory_order_acquire) == 0 && client_keep_alive && !resp_close) {
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
    deferred_response_committed_ = false;
    deferred_was_head_ = (req.method == "HEAD");
    deferred_keep_alive_ = req.keep_alive;
    // Capture obs_snapshot before the parser request slot gets Reset()
    // so the cap-fire safety-cap path can finalize against the
    // ORIGINAL deferred request, not whatever (empty) request slot
    // the parser owns by the time the deadline callback runs.
    deferred_obs_snapshot_ = req.obs_snapshot;
    // Reset so interim responses can be emitted before the final response
    // on this new async cycle. Without this, back-to-back requests on a
    // keep-alive connection would inherit the previous request's
    // final_response_sent_ = true and block all interims.
    final_response_sent_.store(false, std::memory_order_release);
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
    deferred_response_committed_ = false;
    deferred_was_head_ = false;
    deferred_keep_alive_ = true;
    deferred_pending_buf_.clear();
    deferred_start_ = std::chrono::steady_clock::time_point{};
    deferred_obs_snapshot_.reset();
    // Release the abort hook's captured shared_ptrs so the request's
    // atomic flags and active_counter handle can be freed. The throw
    // path that calls CancelAsyncResponse already has its own
    // bookkeeping (the RequestGuard still fires on stack unwinding),
    // so we do NOT invoke the hook here.
    async_abort_hook_ = nullptr;
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
    CompleteAsyncResponseBeforeReplay(std::move(response), nullptr);
}

void HttpConnectionHandler::CompleteAsyncResponseBeforeReplay(
        HttpResponse response, std::function<void()> before_replay) {
    if (!deferred_response_pending_) {
        logging::Get()->warn(
            "CompleteAsyncResponse called without a pending deferred response "
            "(fd={})", conn_ ? conn_->fd() : -1);
        if (before_replay) before_replay();
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
    const int http_minor = current_http_minor_.load(std::memory_order_acquire);
    const bool should_close = NormalizeOutgoingResponse(
        response, effective_keep_alive, http_minor);

    final_response_sent_.store(true, std::memory_order_release);
    response.Version(1, http_minor);
    std::string wire = response.Serialize();
    if (was_head) StripResponseBodyForHead(wire);
    conn_->SendRaw(wire.data(), wire.size());

    // Fire the per-request post-wire notifier: the wire bytes are now
    // buffered for send. Fired AFTER SendRaw so the ordering is
    // "bytes buffered → notifier flipped".
    if (post_write_notify_) {
        post_write_notify_->store(true, std::memory_order_release);
        post_write_notify_.reset();
    }

    // Clear deferred state BEFORE resuming parsing/closing — subsequent
    // OnRawData or CloseConnection calls must see the connection as idle.
    // BUT: delay clearing shutdown_exempt_ until AFTER CloseConnection
    // arms close_after_write_. During graceful shutdown, HasPendingH1Output
    // polls both IsShutdownExempt() and IsCloseDeferred(). If we clear
    // exempt before close_after_write_ is armed, a brief window where both
    // flags are false causes the drain loop to exit and stop the event
    // loop, truncating the response bytes we just queued with SendRaw.
    deferred_response_pending_ = false;
    deferred_response_committed_ = false;
    deferred_was_head_ = false;
    deferred_keep_alive_ = true;
    deferred_start_ = std::chrono::steady_clock::time_point{};
    deferred_obs_snapshot_.reset();
    // Release the abort hook's captures — by the time CompleteAsyncResponse
    // runs on the normal path, the complete closure already owns the
    // bookkeeping and the safety cap no longer needs to fire.
    async_abort_hook_ = nullptr;

    if (conn_->IsClosing()) {
        if (conn_) conn_->SetShutdownExempt(false);
        deferred_pending_buf_.clear();
        // Fire before_replay (no replay will happen on this branch);
        // the hook documents itself as "after wire bytes queued and
        // deferred state cleared, before parsing resumes" — both
        // hold here.
        if (before_replay) before_replay();
        return;
    }
    if (should_close) {
        deferred_pending_buf_.clear();
        // CloseConnection arms close_after_write_ — clear exempt AFTER
        // so HasPendingH1Output always sees at least one flag true.
        CloseConnection();
        if (conn_) conn_->SetShutdownExempt(false);
        if (before_replay) before_replay();
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

    // Fire `before_replay` AFTER state-clear / deadline-clear but
    // BEFORE the deferred-pipeline replay loop. The replay calls
    // OnRawData() which can synchronously parse the next pipelined
    // request and register its observability snapshot — firing the
    // request-A finalize hook here keeps the "A finalize before B
    // register" ordering the wrapper contract requires.
    if (before_replay) before_replay();

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
    //
    // Mark the final response sent only for actual terminal (2xx+) responses.
    // The framework sends 1xx responses (e.g. 100 Continue) through this path
    // before the request is complete; those MUST NOT set the flag so that
    // SendInterimResponse (103 Early Hints) can still fire after the 100.
    if (response.GetStatusCode() >= HttpStatus::OK) {
        final_response_sent_.store(true, std::memory_order_release);
    }
    HttpResponse versioned = response;
    versioned.Version(1, current_http_minor_.load(std::memory_order_acquire));
    std::string wire = versioned.Serialize();
    conn_->SendRaw(wire.data(), wire.size());
    // Fire the per-request post-wire notifier: the wire bytes are now
    // buffered for send; downstream pumps key on this.
    if (post_write_notify_) {
        post_write_notify_->store(true, std::memory_order_release);
        post_write_notify_.reset();
    }
}

namespace {

// Compute the body size that ACTUALLY landed on the wire after
// normalization. HEAD-stripped responses + 1xx / 204 / 304 produce
// 0 (no body emitted); everything else returns the response body's
// post-normalization byte count. The result is the
// `http.server.response.body.size` semconv value.
inline uint64_t ComputeWireBodySize(const HttpResponse& response,
                                      bool was_head_request) noexcept {
    if (was_head_request) return 0;
    const int status = response.GetStatusCode();
    // 1xx / 204 / 205 / 304 — bodyless per HTTP semantics.
    // The wire serialiser strips the body for these statuses.
    if (status >= 100 && status < 200) return 0;
    if (status == 204 || status == 205 || status == 304) return 0;
    return static_cast<uint64_t>(response.GetBody().size());
}

}  // namespace

void HttpConnectionHandler::SetPostWriteNotifyOnce(
    std::shared_ptr<std::atomic<bool>> notify_sent) {
    post_write_notify_ = std::move(notify_sent);
}

bool HttpConnectionHandler::SendInterimResponse(
    int status_code,
    const std::vector<std::pair<std::string, std::string>>& headers) {
    if (!conn_) return false;

    // Valid range: [PROCESSING (102), OK). 100 is framework-managed
    // (internal Continue); 101 is reserved for WebSocket upgrade.
    // Validate synchronously so we don't enqueue work for a bad status.
    if (status_code < HttpStatus::PROCESSING || status_code >= HttpStatus::OK) {
        logging::Get()->warn(
            "SendInterimResponse invalid status {} fd={}",
            status_code, conn_->fd());
        return false;
    }

    // Off-dispatcher hop: preserve write ordering against CompleteAsync
    // Response. When a handler on a worker thread calls complete() then
    // send_interim() in sequence, complete() enqueues the final response
    // lambda onto the dispatcher; final_response_sent_ only becomes true
    // when that lambda RUNS. If we checked the flag here and called
    // SendRaw directly from the worker, SendRaw would enqueue its own
    // lambda AFTER complete's — and the flag check would pass even though
    // the client would observe 200 followed by 103 on the wire. Hopping
    // so both the flag check AND the wire write happen on the dispatcher
    // after complete's lambda has run makes the drop/emit decision
    // strictly ordered. The EnQueue preserves the worker's call order:
    // if complete() was called before send_interim(), the final lambda
    // runs first, final_response_sent_ is set, and the hopped interim
    // observes it and drops. If the interim was called first (legal on
    // a sync request before calling complete), it runs first and emits.
    if (!conn_->IsOnDispatcherThread()) {
        std::weak_ptr<HttpConnectionHandler> weak_self = weak_from_this();
        auto headers_copy = headers;  // deep-copy strings for the hop
        conn_->RunOnDispatcher(
            [weak_self, status_code,
             headers_copy = std::move(headers_copy)]() {
            if (auto self = weak_self.lock()) {
                self->SendInterimResponse(status_code, headers_copy);
            }
        });
        return true;  // queued; final drop/emit decided on dispatcher
    }

    // ---- On dispatcher thread from here on ----

    // Drop if the final response has already been written.
    if (final_response_sent_.load(std::memory_order_acquire)) {
        logging::Get()->warn(
            "SendInterimResponse after final fd={} status={}; dropped",
            conn_->fd(), status_code);
        return false;
    }
    // HTTP/1.0: interim responses require HTTP/1.1+ (RFC 8297).
    if (current_http_minor_.load(std::memory_order_acquire) < 1) {
        logging::Get()->debug(
            "SendInterimResponse rejected on HTTP/1.0 fd={}", conn_->fd());
        return false;
    }

    // Build the wire bytes: status line + filtered/sanitized headers +
    // blank line. We mirror HttpResponse::Header's CR/LF sanitization
    // because this path appends raw bytes to the transport — without
    // stripping \r and \n, a handler that forwards a header value
    // containing CRLF (e.g. an upstream Link header spliced with
    // attacker-controlled data) could inject arbitrary response
    // headers or body bytes into the 1xx block. Response splitting.
    auto strip_crlf = [](std::string s) -> std::string {
        s.erase(std::remove(s.begin(), s.end(), '\r'), s.end());
        s.erase(std::remove(s.begin(), s.end(), '\n'), s.end());
        return s;
    };

    std::string out;
    out.reserve(256);
    out += "HTTP/1.1 ";
    out += std::to_string(status_code);
    out += ' ';
    out += InterimReasonPhrase(status_code);
    out += "\r\n";
    for (const auto& [key, value] : headers) {
        std::string lower = key;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        if (IsForbiddenInterimHeader(lower)) {
            logging::Get()->debug(
                "Interim: forbidden header '{}' stripped fd={}", key, conn_->fd());
            continue;
        }
        out += strip_crlf(key);
        out += ": ";
        out += strip_crlf(value);
        out += "\r\n";
    }
    out += "\r\n";

    // Size cap using max_header_size_ (0 means unlimited — skip the check).
    if (max_header_size_ > 0 && out.size() > max_header_size_) {
        logging::Get()->warn(
            "SendInterimResponse oversize ({} > {}) fd={}",
            out.size(), max_header_size_, conn_->fd());
        return false;
    }

    conn_->SendRaw(out.data(), out.size());
    logging::Get()->debug(
        "SendInterimResponse sent status={} fd={}", status_code, conn_->fd());
    return true;
}

void HttpConnectionHandler::OnSendComplete() {
    if (auto impl = active_stream_sender_impl_.lock()) {
        impl->OnDownstreamWriteComplete();
    }
}

void HttpConnectionHandler::OnWriteProgress(size_t remaining_bytes) {
    if (auto impl = active_stream_sender_impl_.lock()) {
        impl->OnDownstreamWriteProgress(remaining_bytes);
    }
}

void HttpConnectionHandler::CloseConnection() {
    streaming_upload_in_flight_ = false;
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
    streaming_upload_in_flight_ = false;
    logging::Get()->warn("HTTP parse error fd={}: {}", conn_->fd(), parser_.GetError());

    // Streaming early-dispatch path: a deferred handler is still running
    // and owns the response. The parser error (typically BODY_TOO_LARGE)
    // already aborted body_stream, which the handler will observe and use
    // to deliver the terminal 413 via CompleteAsyncResponse. Sending a
    // second direct 413 here would put two responses on the wire and
    // double-count the request (counted once at the dispatch site).
    // Force Connection: close on the eventual deferred response (parser
    // is unrecoverable) by clearing deferred_keep_alive_.
    // Gate on BOTH flags: if the handler already completed (deferred not
    // pending), no async response is coming — fall through to direct send.
    // Clear streaming_dispatched_ on the same return so a SECOND parse
    // error (after CompleteAsyncResponse replays buffered pipelined bytes
    // through OnRawData) doesn't see the stale flag and skip the count +
    // direct-send when no deferred handler exists.
    if (streaming_dispatched_ && deferred_response_pending_) {
        streaming_dispatched_ = false;
        // Also clear the pipelined-stash gate so the post-replay parser
        // reset path (OnRawData @ ~L2681) doesn't misfire against state
        // left over from this aborted request. No concrete trigger today
        // because subsequent on_headers_complete resets the gate, but
        // defensive — keeps the two streaming-dispatch flags in lockstep.
        streaming_dispatch_pending_ = false;
        deferred_keep_alive_ = false;
        return;
    }

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
    // Already dispatched at headers-complete; here we only do the bookkeeping
    // that the dispatch site couldn't: parser reset + pipelined-next-request
    // stash. body_stream was closed by the parser's on_message_complete.
    if (streaming_dispatched_) {
        streaming_dispatched_ = false;
        buf      += consumed;
        remaining -= consumed;
        if (remaining > 0) {
            StashDeferredBytes(std::string(buf, remaining));
            buf      += remaining;
            remaining = 0;
        }
        streaming_upload_in_flight_ = false;
        parser_.Reset();
        sent_100_continue_ = false;
        return false;  // deferred response in flight; stop pipelining loop
    }

    HttpRequest& req = parser_.GetRequest();

    // Propagate dispatcher index for upstream pool partition affinity
    req.dispatcher_index = conn_->dispatcher_index();

    // Propagate peer connection metadata for proxy header rewriting
    // (X-Forwarded-For, X-Forwarded-Proto) and log correlation (client_fd).
    req.client_ip = conn_->ip_addr();
    req.client_tls = conn_->HasTls();
    req.client_fd = conn_->fd();

    // Populate observability fields BEFORE dispatch / middleware so the
    // observability middleware sees non-empty url.scheme,
    // network.protocol.version, and the owning dispatcher pointer
    // needed by the kill-marshal target.
    req.url_scheme = conn_->HasTls() ? "https" : "http";
    {
        char ver[8];
        std::snprintf(ver, sizeof(ver), "%d.%d",
                      req.http_major, req.http_minor);
        req.network_protocol_version = ver;
    }
    req.owning_dispatcher = conn_->GetDispatcher();

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
    // Release store pairs with the acquire loads in SendInterimResponse
    // / NormalizeOutgoingResponse paths that may read from worker threads.
    current_http_minor_.store(req.http_minor, std::memory_order_release);

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
            err.Status(HttpStatus::EXPECTATION_FAILED, "Expectation Failed");
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
        // (Currently unused outside ContinueWsUpgradeAfterAuth, but kept
        // here to populate request.params before middleware runs so
        // middleware that authorizes on route params keeps working.)
        (void)callbacks_.route_check_callback(req);

        // Sync middleware (rate-limit, sync auth). Default to 403 on
        // reject if the middleware didn't set a status — avoids leaking
        // 200 OK on a denied upgrade.
        HttpResponse mw_response;
        if (callbacks_.middleware_callback) {
            if (!callbacks_.middleware_callback(req, mw_response)) {
                if (mw_response.GetStatusCode() == HttpStatus::OK &&
                    mw_response.GetBody().empty()) {
                    mw_response.Status(HttpStatus::FORBIDDEN).Text("Forbidden");
                }
                logging::Get()->debug("WebSocket upgrade rejected by middleware fd={} path={}",
                                      conn_->fd(), req.path);
                mw_response.Header("Connection", "close");
                HttpServer::FinalizeIfSnapshot(req, mw_response,
                                                "rejected_by_middleware");
                SendResponse(mw_response);
                CloseConnection();
                return false;
            }
        }

        // Async middleware (optional). Pass mw_response so async sees
        // any sync-stamped headers.
        if (callbacks_.async_middleware_callback) {
            std::shared_ptr<AsyncPendingState> state;
            bool sync_complete = callbacks_.async_middleware_callback(
                req, mw_response, state);
            if (!sync_complete) {
                // Suspend: install cancel hook, build resume closure,
                // ArmResume. Resume re-enters ContinueWsUpgradeAfterAuth
                // on PASS or sends the populated rejection on DENY.
                // WS upgrade is not instrumented for active_requests_
                // (request_count fired pre-upgrade), so DecrementOnce
                // is a no-op via null active_counter.
                mw_response.Defer();

                auto req_copy  = std::make_shared<HttpRequest>(req);
                auto resp_copy = std::make_shared<HttpResponse>(std::move(mw_response));
                auto self      = shared_from_this();

                self->BeginAsyncResponse(*req_copy);

                // Same finalize-on-abort contract as the H1/H2 sync-route
                // suspends — without this, a WS upgrade whose async
                // middleware is mid-IdP-introspection when the client
                // disconnects leaves the snapshot registered until the
                // shutdown kill loop runs.
                auto suspend_obs_snap = req_copy->obs_snapshot;
                self->SetAsyncAbortHook([state, suspend_obs_snap]() {
                    state->TripCancel();
                    if (suspend_obs_snap) {
                        if (auto mgr = suspend_obs_snap->manager.lock()) {
                            mgr->FinalizeFromSnapshot(
                                *suspend_obs_snap,
                                /*status_code=*/0,
                                /*wire_body_size=*/0,
                                /*error_type=*/"client_disconnect");
                        }
                    }
                });

                auto resume_cb =
                    [self, req_copy, resp_copy, state]
                    (HttpRouter::AsyncMiddlewarePayload payload) {
                    auto do_bookkeeping = [state]() {
                        state->DecrementOnce();
                    };
                    auto shared_payload =
                        std::make_shared<HttpRouter::AsyncMiddlewarePayload>(
                            std::move(payload));
                    self->conn_->RunOnDispatcher(
                        [self, req_copy, resp_copy, state,
                         shared_payload, do_bookkeeping]() mutable {
                        if (state->cancelled()) {
                            do_bookkeeping();
                            return;
                        }
                        if (!self->IsAsyncResponsePending()) {
                            do_bookkeeping();
                            return;
                        }
                        // Mirror MakeAsyncResumeCallback's catch envelope:
                        // a throwing user finalizer or any escape from
                        // ContinueWsUpgradeAfterAuth must not bypass
                        // do_bookkeeping(). Without this, active_requests_
                        // / inflight_finalizations_ leak and the request
                        // hangs. 101 has not yet hit the wire on the
                        // async-resume path, so a generic 500 + Connection:
                        // close is wire-legal and rollback of
                        // upgraded_ / ws_conn_ is safe.
                        try {
                            if (shared_payload->finalizer) {
                                shared_payload->finalizer(*req_copy, *resp_copy);
                            }
                            if (shared_payload->result ==
                                    HttpRouter::AsyncMiddlewareResult::DENY) {
                                resp_copy->Header("Connection", "close");
                                HttpServer::FinalizeIfSnapshot(
                                    *req_copy, *resp_copy,
                                    "rejected_by_async_middleware");
                                resp_copy->ClearDeferred();
                                self->CompleteAsyncResponse(std::move(*resp_copy));
                                self->CloseConnection();
                            } else {
                                // Trailing bytes were buffered during the
                                // suspend window and are flushed by
                                // CompleteAsyncResponse → OnRawData →
                                // HandleUpgradedData once upgraded_ is set.
                                self->ContinueWsUpgradeAfterAuth(
                                    *req_copy, std::move(*resp_copy),
                                    /*from_async_resume=*/true,
                                    /*trailing_buf=*/nullptr,
                                    /*trailing_len=*/0);
                            }
                        } catch (const std::exception& e) {
                            logging::Get()->error(
                                "Exception in resumed WS-upgrade handler: {}",
                                e.what());
                            self->upgraded_ = false;
                            self->ws_conn_.reset();
                            HttpResponse err = HttpResponse::InternalError();
                            err.Header("Connection", "close");
                            HttpServer::FinalizeIfSnapshot(
                                *req_copy, err, "ws_upgrade_resume_threw");
                            err.ClearDeferred();
                            try {
                                self->CompleteAsyncResponse(std::move(err));
                                self->CloseConnection();
                            } catch (const std::exception& e2) {
                                logging::Get()->error(
                                    "Failed to send 500 after WS-upgrade "
                                    "resume throw: {}", e2.what());
                            }
                        }
                        do_bookkeeping();
                    });
                };

                state->ArmResume(std::move(resume_cb), nullptr);

                // Preserve any bytes already received AFTER the upgrade
                // request (a client that pipelines the first WS frame
                // with the GET / Upgrade request leaves them in `buf`
                // past `consumed`). Without this stash, those bytes are
                // dropped when HandleCompleteRequest returns — OnRawData
                // only routes LATER-arriving bytes through
                // StashDeferredBytes, and the post-101 deferred-buf
                // flush would fire empty, costing the client its first
                // frame.
                if (remaining > consumed) {
                    StashDeferredBytes(
                        std::string(buf + consumed, remaining - consumed));
                }
                buf += remaining;
                remaining = 0;

                return false;  // upgrade suspended; peer is awaiting 101/reject
            }

            // Sync fast-path: DENY → reject (default 403); PASS → fall
            // through to ContinueWsUpgradeAfterAuth. `state` is null on
            // empty-chain implicit PASS.
            if (state && state->sync_result() ==
                    HttpRouter::AsyncMiddlewareResult::DENY) {
                if (mw_response.GetStatusCode() == HttpStatus::OK &&
                    mw_response.GetBody().empty()) {
                    mw_response.Status(HttpStatus::FORBIDDEN).Text("Forbidden");
                }
                logging::Get()->debug(
                    "WebSocket upgrade rejected by async middleware fd={} path={}",
                    conn_->fd(), req.path);
                mw_response.Header("Connection", "close");
                HttpServer::FinalizeIfSnapshot(req, mw_response,
                                                "rejected_by_async_middleware");
                SendResponse(mw_response);
                CloseConnection();
                return false;
            }
        }

        // Handshake validation + 101 send.
        bool result = ContinueWsUpgradeAfterAuth(
            req, std::move(mw_response),
            /*from_async_resume=*/false,
            buf + consumed, remaining - consumed);
        // ContinueWsUpgradeAfterAuth returns true on success (101 sent,
        // ws_conn_ live, trailing bytes forwarded) and false on any
        // rejection — both cases want HandleCompleteRequest to return
        // false (the connection is now WS-mode or closing; either way
        // do not attempt to parse a pipelined HTTP request).
        (void)result;
        return false;

        } catch (const std::exception& e) {
            // Exception in middleware/upgrade handler — log server-side,
            // send generic 500 to client (never leak e.what() over the wire).
            logging::Get()->error("Exception in upgrade handler: {}", e.what());
            if (!upgraded_) {
                // Pre-101: send HTTP 500, close via HTTP path
                HttpResponse err = HttpResponse::InternalError();
                err.Header("Connection", "close");
                HttpServer::FinalizeIfSnapshot(req, err, "ws_upgrade_handler_threw");
                SendResponse(err);
                CloseConnection();
            } else if (ws_conn_) {
                // Post-101 with WS connection: send close 1011.
                // SendClose now includes CloseAfterWrite for proper drain.
                // Snapshot was already finalized at 101 success.
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
            // Finalize the snapshot here too: the sync-handler exception
            // path bypasses the FinalizeIfSnapshot calls in
            // request_callback's normal return paths, leaving
            // inflight_finalizations_ elevated and the SERVER span open.
            HttpServer::FinalizeIfSnapshot(req, response, "handler_threw");
            SendResponse(response);
            CloseConnection();
            return false;
        }

        // Streaming sender that finalised synchronously inside the
        // handler (e.g. SendHeaders for HEAD/204/205/304, or
        // SendHeaders+End on the dispatcher) has already called
        // `finalize_response_`, which clears `deferred_response_pending_`,
        // delivers any earlier-stashed pipelined bytes, and — when the
        // response asked to close — calls CloseConnection. We must
        // NOT take the deferred-stash branch below (bytes after
        // `consumed` belong to the next pipelined request and must be
        // parsed normally, not re-stashed into a buffer nothing will
        // ever replay) and we must NOT call SendResponse(response) (it
        // would write a stale empty response on top of the wire bytes
        // already flushed by the streaming sender). We DO want to fall
        // through to the post-response cleanup at the bottom of this
        // function so the request-timeout deadline is re-armed when
        // `remaining > 0` — finalize_response_ already cleared the
        // previous deadline, so without that re-arm a partial pipelined
        // request following a body-suppressed streaming response has
        // no slowloris protection until the (much longer) idle timeout
        // fires.
        const bool streaming_finalised_sync =
            response.IsDeferred() && !deferred_response_pending_;
        if (streaming_finalised_sync && conn_->IsClosing()) {
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
        if (response.IsDeferred() && !streaming_finalised_sync) {
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
            // Per-request override takes precedence over the global cap.
            // A handler (e.g. ProxyHandler with response_timeout_ms=0)
            // may set req.async_cap_sec_override to 0 to disable the
            // cap for unbounded requests (SSE, long-poll) without
            // affecting unrelated routes on the same connection. See
            // HttpRequest::async_cap_sec_override for the full
            // rationale and sentinel semantics.
            int cap_sec = (req.async_cap_sec_override >= 0)
                        ? req.async_cap_sec_override
                        : max_async_deferred_sec_;  // 0 = no cap
            ArmAsyncDeferredDeadline(heartbeat_sec, cap_sec);
            buf += consumed;
            remaining -= consumed;
            if (remaining > 0) {
                StashDeferredBytes(std::string(buf, remaining));
            }
            streaming_upload_in_flight_ = false;
            parser_.Reset();
            sent_100_continue_ = false;
            return false;
        }

        // Sync-response path. Skipped when the streaming sender already
        // finalised inline (the response is on the wire and CloseConnection
        // / keep-alive accounting were handled by `finalize_response_`).
        if (!streaming_finalised_sync) {
            const bool should_close = NormalizeOutgoingResponse(
                response, req.keep_alive, req.http_minor);

            // RFC 7231 §4.3.2: HEAD responses carry the GET headers (including
            // Content-Length) but MUST NOT include a body. Serialize first so
            // the framework's auto-computed Content-Length is preserved, then
            // strip the body from the wire.
            if (req.method == "HEAD") {
                response.Version(1, current_http_minor_.load(std::memory_order_acquire));
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
    }

    // Request completed — reset timeout tracking for next request
    request_in_progress_ = false;
    conn_->ClearDeadline();
    conn_->SetDeadlineTimeoutCb(nullptr);

    // Advance past consumed bytes
    buf += consumed;
    remaining -= consumed;

    // Reset parser and per-request state for next request (keep-alive / pipelining)
    streaming_upload_in_flight_ = false;
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
                HttpServer::FinalizeIfSnapshot(
                    self->parser_.GetRequest(), timeout_resp,
                    "request_timeout");
                self->SendResponse(timeout_resp);
            }
            return false;  // Proceed with connection close
        });
    }

    return true;  // Continue pipelining loop
}

// WebSocket-upgrade post-middleware path. Extracted from the inline
// block in HandleCompleteRequest so the async-middleware resume path
// can re-enter at the same point.
//
// Sync invocation path (from_async_resume=false): callers have the
// trailing `buf` / `consumed` parameters in scope and pass them through
// for the post-101 ws_conn_->OnRawData forward. The 101 response is
// sent via SendResponse.
//
// Async-resume path (from_async_resume=true): no trailing `buf` is in
// scope (the deferred completion fired from a different stack); any
// bytes that arrived during the suspend window were buffered into
// deferred_pending_buf_ via OnRawData and are flushed by
// CompleteAsyncResponse after we transition to upgraded_ state. We
// pass nullptr/0 for trailing — the deferred-buf flush handles them.
//
// Returns true on successful upgrade (101 sent, ws_conn_ live), false
// on rejection (response sent, connection closed). Callers ignore the
// return value: the WS upgrade decision is final and the parser is
// either in WS mode or the connection is closing.
bool HttpConnectionHandler::ContinueWsUpgradeAfterAuth(
    HttpRequest& req,
    HttpResponse mw_response,
    bool from_async_resume,
    const char* trailing_buf,
    size_t trailing_len) {
    // The probe at the top of HandleCompleteRequest's WS branch already
    // populated request.params for pattern routes via route_check.

    // Validate WebSocket handshake per RFC 6455.
    // Must happen BEFORE the route-miss check so that malformed upgrades
    // always get 400/426 regardless of whether the route exists —
    // prevents leaking route existence through different error codes.
    std::string ws_error;
    if (!WebSocketHandshake::Validate(req, ws_error)) {
        logging::Get()->debug("WebSocket handshake rejected fd={}: {}",
                              conn_->fd(), ws_error);
        int reject_code = 400;
        if (ws_error.find("version") != std::string::npos ||
            ws_error.find("Version") != std::string::npos) {
            reject_code = 426;
        }
        HttpResponse reject = WebSocketHandshake::Reject(reject_code, ws_error);
        if (reject_code == 426) {
            reject.Header("Sec-WebSocket-Version", "13");
        }
        reject.Header("Connection", "close");
        // Finalize BEFORE the response leaves: CompleteAsyncResponse
        // can synchronously start the next pipelined request, and
        // SendResponse may also trigger pipeline replay on keep-alive.
        // FinalizeIfSnapshot is a no-op when obs is disabled.
        HttpServer::FinalizeIfSnapshot(req, reject, "ws_handshake_invalid");
        if (from_async_resume) {
            reject.ClearDeferred();
            CompleteAsyncResponse(std::move(reject));
        } else {
            SendResponse(reject);
        }
        CloseConnection();
        return false;
    }

    // Route existence check (after middleware + handshake validation).
    // The route_check_callback is the canonical source of truth for
    // both sync and async-resume paths.
    bool ws_route_found =
        callbacks_.route_check_callback &&
        callbacks_.route_check_callback(req);
    if (!ws_route_found) {
        logging::Get()->debug("WebSocket route not found fd={} path={}",
                              conn_->fd(), logging::SanitizePath(req.path));
        auto not_found = HttpResponse::NotFound();
        not_found.Header("Connection", "close");
        HttpServer::FinalizeIfSnapshot(req, not_found, "ws_route_not_found");
        if (from_async_resume) {
            not_found.ClearDeferred();
            CompleteAsyncResponse(std::move(not_found));
        } else {
            SendResponse(not_found);
        }
        CloseConnection();
        return false;
    }

    // Request completed (as upgrade) — reset timeout tracking
    request_in_progress_ = false;
    conn_->ClearDeadline();
    conn_->SetDeadlineTimeoutCb(nullptr);

    // Build the 101 response, merging safe middleware headers.
    HttpResponse upgrade_resp = WebSocketHandshake::Accept(req);
    for (const auto& hdr : mw_response.GetHeaders()) {
        std::string key = hdr.first;
        std::transform(key.begin(), key.end(), key.begin(),
                       [](unsigned char c){ return std::tolower(c); });
        // Skip 101 mandatory headers, framing headers, and WS
        // negotiation headers. This server doesn't implement WS
        // extensions or subprotocol negotiation, so allowing middleware
        // to inject Sec-WebSocket-Extensions (e.g. permessage-deflate)
        // would cause clients to send RSV1 frames that the parser
        // rejects as protocol errors.
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
        shutdown_resp.Status(HttpStatus::SERVICE_UNAVAILABLE).Text("Service Unavailable");
        shutdown_resp.Header("Connection", "close");
        HttpServer::FinalizeIfSnapshot(req, shutdown_resp, "shutting_down");
        if (from_async_resume) {
            shutdown_resp.ClearDeferred();
            CompleteAsyncResponse(std::move(shutdown_resp));
        } else {
            SendResponse(shutdown_resp);
        }
        CloseConnection();
        return false;
    }

    // For the async-resume path we must transition to upgraded_ + create
    // ws_conn_ BEFORE CompleteAsyncResponse, so the deferred-buf flush
    // (which OnRawData routes through HandleUpgradedData when upgraded_
    // is set) reaches the WebSocket connection rather than the HTTP
    // parser. The sync path keeps the historical ordering (101 first,
    // then upgraded_ + ws_conn_) so the existing exception-handling
    // contract (catch block sends WS 1011 if upgraded_ is true) is
    // preserved unchanged.
    if (from_async_resume) {
        upgraded_ = true;
        ws_conn_ = std::make_unique<WebSocketConnection>(conn_);
        if (max_ws_message_size_ > 0) {
            ws_conn_->GetParser().SetMaxPayloadSize(max_ws_message_size_);
            ws_conn_->SetMaxMessageSize(max_ws_message_size_);
            conn_->SetMaxInputSize(max_ws_message_size_);
        }
        // Release the http/1.1 slot BEFORE wiring the WS snapshot's +1 so
        // a /metrics scrape racing the handoff (Prometheus scrapes run on
        // whichever socket dispatcher accepted the scrape connection, not
        // necessarily this dispatcher) sees a transient under-count rather
        // than an over-count of sum(http.connections.active{protocol=*}).
        // The upgrade_callback also calls HandOffToWebSocket; the second
        // call is an idempotent no-op (http_protocol_label_ now null).
        conn_->HandOffToWebSocket();
        ws_conn_->SetObservabilitySnapshot(req.obs_snapshot);
        // Install user-registered WebSocket handlers (OnMessage / OnClose
        // / etc.) BEFORE CompleteAsyncResponse fires the deferred-buf
        // flush. CompleteAsyncResponse routes deferred_pending_buf_
        // through OnRawData → HandleUpgradedData → ws_conn_->OnRawData,
        // which parses any frames the client pipelined with the upgrade
        // (or sent during the suspend window) and dispatches them via
        // OnMessage. Calling upgrade_callback AFTER the flush would mean
        // those early frames are parsed against a still-null OnMessage
        // handler and silently dropped.
        // Wrap upgrade_callback so a throwing user handler doesn't
        // leave the connection half-upgraded with the 101 unsent. On
        // the async-resume path, upgraded_ + ws_conn_ are set BEFORE
        // CompleteAsyncResponse runs, so the sync-path post-101 catch
        // (which sends WS close 1011) doesn't apply — 101 is not yet
        // on the wire. Roll back the in-progress upgrade and respond
        // with HTTP 500 + Connection: close instead. CompleteAsyncResponse
        // clears deferred_pending_buf_ on close so any pipelined WS
        // frames the client sent during suspend are discarded rather
        // than misparsed as HTTP.
        try {
            if (callbacks_.upgrade_callback) {
                callbacks_.upgrade_callback(shared_from_this(), req);
            }
        } catch (const std::exception& e) {
            logging::Get()->error(
                "Exception in resumed WS upgrade handler: {}", e.what());
            upgraded_ = false;
            ws_conn_.reset();
            HttpResponse err = HttpResponse::InternalError();
            err.Header("Connection", "close");
            HttpServer::FinalizeIfSnapshot(req, err, "ws_upgrade_handler_threw");
            err.ClearDeferred();
            CompleteAsyncResponse(std::move(err));
            return false;
        }
        // 101 success — finalize the SERVER span. The HTTP request is
        // terminal at the upgrade; subsequent WS frames are out of
        // scope for this span.
        HttpServer::FinalizeIfSnapshot(req, upgrade_resp, std::string{});
        upgrade_resp.ClearDeferred();
        CompleteAsyncResponse(std::move(upgrade_resp));
        if (conn_->IsClosing()) {
            logging::Get()->debug(
                "WS upgrade: connection closed during 101 send fd={}",
                conn_->fd());
            return false;
        }
        // Trailing bytes (if any) were stashed via OnRawData during the
        // suspend window AND by the WS-suspend site in HandleCompleteRequest
        // for bytes already in `buf` past `consumed` at suspend time. Both
        // sources are flushed by CompleteAsyncResponse →
        // OnRawData → HandleUpgradedData above, so no work needed here.
        // trailing_buf/_len are nullptr/0 by contract on this path.
        (void)trailing_buf;
        (void)trailing_len;
        return true;
    }

    // ---- Sync path ----
    // Finalize BEFORE the 101 leaves the wire so the SERVER span is
    // closed in lock-step with the upgrade completion.
    HttpServer::FinalizeIfSnapshot(req, upgrade_resp, std::string{});
    SendResponse(upgrade_resp);

    if (conn_->IsClosing()) {
        logging::Get()->debug("WS upgrade: connection closed during 101 send fd={}",
                              conn_->fd());
        return false;
    }

    // Mark as upgraded IMMEDIATELY after 101 is sent, before any code
    // that could throw. This ensures the catch block (in
    // HandleCompleteRequest) correctly identifies post-101 exceptions
    // and sends WS close 1011 instead of raw HTTP 500.
    upgraded_ = true;

    ws_conn_ = std::make_unique<WebSocketConnection>(conn_);
    if (max_ws_message_size_ > 0) {
        ws_conn_->GetParser().SetMaxPayloadSize(max_ws_message_size_);
        ws_conn_->SetMaxMessageSize(max_ws_message_size_);
        conn_->SetMaxInputSize(max_ws_message_size_);
    }
    // Release the http/1.1 slot BEFORE wiring the WS snapshot's +1 so a
    // /metrics scrape racing the handoff (Prometheus scrapes run on
    // whichever socket dispatcher accepted the scrape connection, not
    // necessarily this dispatcher) sees a transient under-count rather
    // than an over-count of sum(http.connections.active{protocol=*}).
    // The upgrade_callback also calls HandOffToWebSocket; the second
    // call is an idempotent no-op (http_protocol_label_ now null).
    conn_->HandOffToWebSocket();
    ws_conn_->SetObservabilitySnapshot(req.obs_snapshot);

    if (callbacks_.upgrade_callback) {
        callbacks_.upgrade_callback(shared_from_this(), req);
    }

    // Forward any trailing bytes after the HTTP headers as WS data.
    if (trailing_len > 0 && trailing_buf && ws_conn_) {
        std::string trailing(trailing_buf, trailing_len);
        ws_conn_->OnRawData(trailing);
    }
    return true;
}

void HttpConnectionHandler::ArmAsyncDeferredDeadline(int heartbeat_sec,
                                                     int cap_sec) {
    deferred_start_ = std::chrono::steady_clock::now();
    // Arm the FIRST deadline at min(heartbeat_sec, cap_sec) when the cap is
    // smaller — otherwise a tight cap would only be checked at heartbeat
    // boundaries and the request could outlive its declared cap.
    int initial_sec = heartbeat_sec;
    if (cap_sec > 0 && cap_sec < initial_sec) initial_sec = cap_sec;
    conn_->SetDeadline(deferred_start_ + std::chrono::seconds(initial_sec));

    std::weak_ptr<HttpConnectionHandler> weak_self = shared_from_this();
    conn_->SetDeadlineTimeoutCb(
        [weak_self, heartbeat_sec, cap_sec]() -> bool {
        auto self = weak_self.lock();
        if (!self) return false;
        if (!self->deferred_response_pending_) {
            // CompleteAsyncResponse normally clears the deadline before
            // the callback fires; handle defensively if it didn't.
            return false;
        }
        if (self->deferred_response_committed_) {
            // Streaming response is mid-body — never trip the cap.
            auto now_steady = std::chrono::steady_clock::now();
            self->conn_->SetDeadline(
                now_steady + std::chrono::seconds(heartbeat_sec));
            return true;
        }
        if (cap_sec > 0) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() -
                self->deferred_start_).count();
            if (elapsed >= cap_sec) {
                logging::Get()->warn(
                    "HTTP/1 async deferred response exceeded safety cap "
                    "({}s) without completion fd={}; aborting and sending 504",
                    cap_sec, self->conn_ ? self->conn_->fd() : -1);
                HttpResponse timeout_resp = HttpResponse::GatewayTimeout();
                timeout_resp.Header("Connection", "close");
                // Pre-finalize against the snapshot captured at
                // BeginAsyncResponse time. The parser slot may have been
                // Reset() between dispatch and now; the abort hook's later
                // client_disconnect attempt loses the CAS gate, so the
                // server_timeout label here is what gets exported.
                if (self->deferred_obs_snapshot_) {
                    if (auto mgr = self->deferred_obs_snapshot_->manager.lock()) {
                        const uint64_t wire_size =
                            self->deferred_was_head_
                                ? 0u
                                : ComputeWireBodySize(timeout_resp,
                                                      self->deferred_was_head_);
                        mgr->FinalizeFromSnapshot(
                            *self->deferred_obs_snapshot_,
                            timeout_resp.GetStatusCode(),
                            wire_size, "server_timeout");
                    }
                }
                // Move out before invoking so CompleteAsyncResponse can't
                // free the std::function while we're in it.
                auto abort_hook = std::move(self->async_abort_hook_);
                if (abort_hook) abort_hook();
                self->CompleteAsyncResponse(std::move(timeout_resp));
                return false;
            }
        }
        // Heartbeat: re-arm, clamping next wakeup so the FOLLOW-UP
        // doesn't overshoot a tight cap.
        auto now_steady = std::chrono::steady_clock::now();
        auto next_sec = std::chrono::seconds(heartbeat_sec);
        if (cap_sec > 0) {
            auto elapsed_sec = std::chrono::duration_cast<std::chrono::seconds>(
                now_steady - self->deferred_start_).count();
            auto remaining = static_cast<long long>(cap_sec) - elapsed_sec;
            if (remaining > 0 && remaining < heartbeat_sec) {
                next_sec = std::chrono::seconds(remaining);
            }
        }
        self->conn_->SetDeadline(now_steady + next_sec);
        return true;
    });
}

bool HttpConnectionHandler::DispatchStreamingRouteFromHeaders() {
    HttpRequest& req = parser_.GetRequest();

    // Per-request fields normally populated at the top of HandleCompleteRequest.
    const bool has_tls = conn_->HasTls();
    req.dispatcher_index = conn_->dispatcher_index();
    req.client_ip        = conn_->ip_addr();
    req.client_tls       = has_tls;
    req.client_fd        = conn_->fd();
    req.url_scheme       = has_tls ? "https" : "http";
    req.network_protocol_version = (req.http_minor == 0) ? "1.0" : "1.1";
    req.owning_dispatcher = conn_->GetDispatcher();

    if (callbacks_.request_count_callback) {
        callbacks_.request_count_callback();
    }

    // Validation. Errors here predate the body and force Connection: close
    // because the body is still streaming and we have no way to drain it.
    // Abort body_stream on every early-reject path: the parser will keep
    // pushing bytes into body_stream (on_body fires regardless of route
    // disposition), and on_above_high_water would call IncReadDisable
    // against a connection we just told to close — leaving a pinned
    // read-disable count without a matching DecReadDisable. Mirrors the
    // Content-Length cap reject below.
    if (req.http_major != 1 || (req.http_minor != 0 && req.http_minor != 1)) {
        logging::Get()->warn("Unsupported HTTP version fd={}: {}.{}",
                             conn_->fd(), req.http_major, req.http_minor);
        if (auto* body_stream = req.body_stream.get()) {
            body_stream->Abort("unsupported_http_version");
        }
        HttpResponse resp = HttpResponse::HttpVersionNotSupported();
        resp.Header("Connection", "close");
        SendResponse(resp);
        CloseConnection();
        return false;
    }
    current_http_minor_.store(req.http_minor, std::memory_order_release);

    if (req.http_minor >= 1 && !req.HasHeader("host")) {
        logging::Get()->debug("Missing Host header fd={}", conn_->fd());
        if (auto* body_stream = req.body_stream.get()) {
            body_stream->Abort("missing_host_header");
        }
        HttpResponse resp = HttpResponse::BadRequest("Missing Host header");
        resp.Header("Connection", "close");
        SendResponse(resp);
        CloseConnection();
        return false;
    }

    // Early Content-Length cap reject. Must run BEFORE Expect handling so
    // we don't send 100 Continue right before rejecting (which would have
    // the client start uploading a body we've already decided to reject)
    // AND before handler dispatch so the route never commits to an upstream.
    // Mirrors HandleIncompleteRequest's buffered-path check and
    // OnDataChunkRecvCallback's H2 check.
    if (max_body_size_ > 0 && req.content_length > max_body_size_) {
        logging::Get()->warn(
            "Early reject: Content-Length ({}) exceeds limit ({}) fd={}",
            req.content_length, max_body_size_, conn_->fd());
        if (auto* body_stream = req.body_stream.get()) {
            body_stream->Abort("content_length_exceeds_limit");
        }
        HttpResponse err = HttpResponse::PayloadTooLarge();
        err.Header("Connection", "close");
        SendResponse(err);
        CloseConnection();
        return false;
    }

    // Expect handling. Unlike HandleCompleteRequest (body already arrived),
    // here the body is still streaming — if the client sent Expect: 100-continue
    // we send 100 Continue now so the client proceeds with the upload.
    if (req.HasHeader("expect")) {
        std::string expect = req.GetHeader("expect");
        std::transform(expect.begin(), expect.end(), expect.begin(),
                       [](unsigned char c){ return std::tolower(c); });
        while (!expect.empty() && (expect.front() == ' ' || expect.front() == '\t'))
            expect.erase(expect.begin());
        while (!expect.empty() && (expect.back() == ' ' || expect.back() == '\t'))
            expect.pop_back();
        if (expect == "100-continue") {
            if (!sent_100_continue_) {
                static const char kCont[] = "HTTP/1.1 100 Continue\r\n\r\n";
                conn_->SendRaw(kCont, sizeof(kCont) - 1);
                sent_100_continue_ = true;
            }
        } else {
            logging::Get()->debug("Unsupported Expect value fd={}", conn_->fd());
            if (auto* body_stream = req.body_stream.get()) {
                body_stream->Abort("unsupported_expect_value");
            }
            HttpResponse err;
            err.Status(HttpStatus::EXPECTATION_FAILED, "Expectation Failed");
            err.Header("Connection", "close");
            SendResponse(err);
            CloseConnection();
            return false;
        }
    }

    // Mark dispatched BEFORE invoking the handler so the body_stream
    // watermark callbacks engage for the handler's lifetime (pause/resume
    // the read pump while body_stream queue exceeds high_water).
    streaming_dispatched_ = true;

    // Catch-up pause: the parser callback chain (on_body) may have pushed
    // body bytes that crossed high_water BEFORE this dispatch ran. The
    // on_above_high_water callback returned early because
    // streaming_dispatched_ was still false (see Setup), and the latch
    // (above_high_water_latched_) in body_stream prevents the callback
    // from firing again until the queue drains below low_water. Without
    // a catch-up pause here, a large headers+body in a single TCP segment
    // can buffer up to the connection input cap before the handler starts
    // consuming. Pause now if we're already above water; the matching
    // on_below_low_water resume will fire naturally when the consumer
    // drains the queue.
    if (auto* body_stream = parser_.GetRequest().body_stream.get()) {
        const size_t hw = (streaming_high_water_bytes_ > 0)
            ? streaming_high_water_bytes_
            : 262144;  // matches DEFAULT_STREAM_HIGH_WATER_BYTES
        if (!h1_streaming_pump_paused_ &&
            body_stream->BytesQueued() >= hw &&
            conn_) {
            conn_->IncReadDisable();
            h1_streaming_pump_paused_ = true;
        }
    }

    HttpResponse response;
    try {
        callbacks_.request_callback(shared_from_this(), req, response);
    } catch (const std::exception& e) {
        logging::Get()->error("Exception in streaming request handler: {}",
                              e.what());
        streaming_dispatched_ = false;
        // Roll back any read-pump pause armed by the watermark callback
        // before the handler threw; otherwise the connection wedges.
        if (h1_streaming_pump_paused_) {
            h1_streaming_pump_paused_ = false;
            if (conn_) conn_->DecReadDisable();
        }
        if (auto* body_stream = req.body_stream.get()) {
            body_stream->Abort("handler_threw");
        }
        response = HttpResponse::InternalError();
        response.Header("Connection", "close");
        HttpServer::FinalizeIfSnapshot(req, response, "handler_threw");
        SendResponse(response);
        CloseConnection();
        return false;
    }

    if (response.IsDeferred()) {
        request_in_progress_ = false;
        static constexpr int ASYNC_HEARTBEAT_FALLBACK_SEC = 60;
        int heartbeat_sec = request_timeout_sec_ > 0
                          ? request_timeout_sec_
                          : ASYNC_HEARTBEAT_FALLBACK_SEC;
        int cap_sec = (req.async_cap_sec_override >= 0)
                    ? req.async_cap_sec_override
                    : max_async_deferred_sec_;
        ArmAsyncDeferredDeadline(heartbeat_sec, cap_sec);
        return true;
    }

    // Sync response. The handler decided based on headers alone (e.g.,
    // middleware rejected via the router callback). Abort the body — we
    // are not going to read it — and close after sending. Cannot continue
    // keep-alive: the parser is mid-body and re-syncing would require
    // discarding the remainder, which is unsafe (trailers, framing).
    streaming_dispatched_ = false;
    if (h1_streaming_pump_paused_) {
        h1_streaming_pump_paused_ = false;
        if (conn_) conn_->DecReadDisable();
    }
    if (auto* body_stream = req.body_stream.get()) {
        body_stream->Abort("handler_responded_sync_mid_body");
    }
    response.Header("Connection", "close");
    HttpServer::FinalizeIfSnapshot(
        req, response, "streaming_handler_sync_response");
    SendResponse(response);
    CloseConnection();
    return false;
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
    // Streaming routes already passed through the same validation inside
    // DispatchStreamingRouteFromHeaders; skip to avoid re-checking the
    // same headers and to keep the handler the sole owner of the deferred
    // response.
    if (streaming_dispatched_) {
        return;
    }
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
                cont.Status(HttpStatus::CONTINUE, "Continue");
                SendResponse(cont);
                sent_100_continue_ = true;
                logging::Get()->debug("Sent 100 Continue fd={}", conn_->fd());
            } else {
                // Unrecognized Expect value — RFC 7231 §5.1.1: 417
                logging::Get()->debug("Early reject: unsupported Expect fd={}", conn_->fd());
                count_request();
                HttpResponse err;
                err.Status(HttpStatus::EXPECTATION_FAILED, "Expectation Failed");
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
    //
    // Exception: when a streaming upload is in flight, body bytes must
    // reach the parser (on_body → body_stream->Push), not be stashed.
    // The deferred async request will have been started by the upstream
    // path; the parser stays active until on_message_complete fires and
    // clears streaming_upload_in_flight_.
    if (deferred_response_pending_ && !streaming_upload_in_flight_) {
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
                    HttpServer::FinalizeIfSnapshot(
                        self->parser_.GetRequest(), timeout_resp,
                        "request_timeout");
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
                HttpServer::FinalizeIfSnapshot(
                    parser_.GetRequest(), timeout_resp, "request_timeout");
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
            current_http_minor_.store(parser_.GetRequest().http_minor,
                                       std::memory_order_release);
            conn_->MarkApplicationProtocolConfirmed("http/1.1");
        }

        if (parser_.HasError()) {
            HandleParseError();
            return;
        }

        // Safety guard: if parser consumed 0 bytes, avoid infinite loop
        if (consumed == 0) break;

        // Dispatch outside the parser callback chain. Fall through so a
        // small body that fits in one Parse — firing message-complete in
        // the same call — still goes through HandleCompleteRequest's
        // streaming_dispatched_ skip path for parser reset + stash.
        if (streaming_dispatch_pending_ && !streaming_dispatched_) {
            streaming_dispatch_pending_ = false;
            if (!DispatchStreamingRouteFromHeaders()) {
                return;
            }
        }

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
