#include "upstream/upstream_h2_connection.h"
#include "upstream/h2_settings.h"
#include "upstream/proxy_transaction.h"  // for RESULT_UPSTREAM_DISCONNECT
#include "upstream/upstream_connection.h"
#include "upstream/upstream_http_codec.h"
#include "upstream/header_rewriter.h"
#include "connection_handler.h"
#include "log/logger.h"
#include <charconv>
#include <cstring>

namespace {

// FlushSend uses nghttp2_session_mem_send2 which returns bytes directly
// to the caller — the send callback is not invoked. We deliberately do
// not register one to keep readers from assuming there's a wired send
// path.

int OnFrameRecvCallback(nghttp2_session* /*session*/,
                        const nghttp2_frame* frame, void* user_data)
{
    auto* self = static_cast<UpstreamH2Connection*>(user_data);
    switch (frame->hd.type) {
    case NGHTTP2_HEADERS: {
        if (!(frame->hd.flags & NGHTTP2_FLAG_END_HEADERS)) break;
        bool end_stream =
            (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0;
        auto cat = frame->headers.cat;
        if (cat == NGHTTP2_HCAT_RESPONSE ||
            cat == NGHTTP2_HCAT_PUSH_RESPONSE) {
            // First HEADERS for this stream. Status < 200 is an
            // informational interim (e.g. 103 Early Hints) — capture but
            // don't dispatch as the final response head; the next
            // HEADERS frame (HCAT_HEADERS) will carry either another
            // interim or the final response.
            auto* stream = self->GetStream(frame->hd.stream_id);
            if (stream && stream->response_head.status_code >= 100 &&
                stream->response_head.status_code < 200) {
                stream->saw_1xx_interim = true;
            } else {
                self->OnHeadersComplete(frame->hd.stream_id, end_stream);
            }
        } else if (cat == NGHTTP2_HCAT_HEADERS) {
            // HCAT_HEADERS after the first HEADERS frame: either the
            // final response (when the first was 1xx), another 1xx
            // interim (chained interims like 100 Continue → 103 Early
            // Hints → final), or trailers.
            auto* stream = self->GetStream(frame->hd.stream_id);
            if (stream && !stream->head_dispatched) {
                if (stream->response_head.status_code >= 100 &&
                    stream->response_head.status_code < 200) {
                    // Another interim — keep waiting for the final.
                    stream->saw_1xx_interim = true;
                } else {
                    self->OnHeadersComplete(frame->hd.stream_id, end_stream);
                }
            } else if (stream && stream->head_dispatched) {
                self->OnTrailersComplete(frame->hd.stream_id);
            }
        }
        break;
    }
    case NGHTTP2_GOAWAY:
        self->OnGoawayReceived(frame->goaway.last_stream_id);
        break;
    case NGHTTP2_PING:
        if (frame->hd.flags & NGHTTP2_FLAG_ACK) {
            self->OnPingAck();
        }
        break;
    default:
        break;
    }
    return 0;
}

int OnBeginHeadersCallback(nghttp2_session* /*session*/,
                           const nghttp2_frame* frame, void* user_data)
{
    if (frame->hd.type != NGHTTP2_HEADERS) return 0;
    auto* self = static_cast<UpstreamH2Connection*>(user_data);
    auto* stream = self->GetStream(frame->hd.stream_id);
    if (!stream) return 0;
    // Transitioning from 1xx interim to the final response: clear the
    // accumulated interim values so OnHeaderCallback overlays cleanly
    // for the final HEADERS block.
    if (frame->headers.cat == NGHTTP2_HCAT_HEADERS &&
        !stream->head_dispatched && stream->saw_1xx_interim) {
        stream->response_head.headers.clear();
        stream->response_head.status_code = 0;
    }
    return 0;
}

int OnStreamCloseCallback(nghttp2_session* /*session*/, int32_t stream_id,
                          uint32_t error_code, void* user_data)
{
    auto* self = static_cast<UpstreamH2Connection*>(user_data);
    self->OnStreamClose(stream_id, error_code);
    return 0;
}

int OnHeaderCallback(nghttp2_session* /*session*/, const nghttp2_frame* frame,
                     const uint8_t* name, size_t namelen,
                     const uint8_t* value, size_t valuelen,
                     uint8_t /*flags*/, void* user_data)
{
    if (frame->hd.type != NGHTTP2_HEADERS) return 0;
    auto cat = frame->headers.cat;
    if (cat == NGHTTP2_HCAT_REQUEST) {
        // Promised request header on a server-pushed stream — server
        // push is disabled (SETTINGS_ENABLE_PUSH=0), but defensively skip.
        return 0;
    }
    auto* self = static_cast<UpstreamH2Connection*>(user_data);
    auto* stream = self->GetStream(frame->hd.stream_id);
    if (!stream) return 0;

    std::string nm(reinterpret_cast<const char*>(name), namelen);
    std::string val(reinterpret_cast<const char*>(value), valuelen);

    // Route by HEADERS-block kind:
    //   HCAT_RESPONSE / HCAT_PUSH_RESPONSE → the first response HEADERS
    //   (interim 1xx or final). Accumulate into response_head.
    //   HCAT_HEADERS && !head_dispatched   → post-1xx final HEADERS.
    //   Accumulate into response_head (cleared by on_begin_headers when
    //   transitioning from 1xx interim).
    //   HCAT_HEADERS && head_dispatched    → trailers. Accumulate into
    //   stream->trailers.
    bool to_trailers = (cat == NGHTTP2_HCAT_HEADERS && stream->head_dispatched);

    if (!nm.empty() && nm[0] == ':') {
        if (!to_trailers && nm == ":status") {
            // from_chars: no leading-whitespace skip, no exceptions, and
            // the (ptr == end) check enforces strict full-string consume.
            // std::stoi would silently accept " 200" (skipped whitespace
            // counts toward `consumed`).
            int s = 0;
            const char* end = val.data() + val.size();
            auto [ptr, ec] = std::from_chars(val.data(), end, s);
            bool ok = (ec == std::errc()) && (ptr == end)
                      && s >= 100 && s < 600;
            if (!ok) {
                logging::Get()->warn(
                    "UpstreamH2Connection: invalid :status '{}' on stream {}",
                    val, frame->hd.stream_id);
                // nghttp2 RSTs the stream with INTERNAL_ERROR on
                // NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE; the eventual
                // OnStreamClose then fires sink->OnError so the proxy
                // transaction can fail/retry. Calling ResetStream
                // ourselves would detach the sink and silently swallow
                // that signal.
                return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
            }
            stream->response_head.status_code = s;
        }
        // Other pseudo-headers (request pseudos in trailers are illegal,
        // unknown response pseudos are reserved) — drop silently.
        return 0;
    }

    if (to_trailers) {
        stream->trailers.emplace_back(std::move(nm), std::move(val));
    } else {
        stream->response_head.headers.emplace_back(std::move(nm),
                                                   std::move(val));
    }
    return 0;
}

ssize_t H2BodyReadCallback(nghttp2_session* /*session*/, int32_t /*stream_id*/,
                           uint8_t* buf, size_t length,
                           uint32_t* data_flags, nghttp2_data_source* source,
                           void* /*user_data*/)
{
    auto* src = static_cast<UpstreamH2BodySource*>(source->ptr);
    if (!src) {
        // SubmitRequest always sets source.ptr before passing the
        // provider to nghttp2; reaching here means a regression.
        // Returning 0 + END_STREAM would silently send the upstream a
        // truncated request body. Returning TEMPORAL_CALLBACK_FAILURE
        // makes nghttp2 RST_STREAM the request — the proxy then sees a
        // stream-close-with-error and surfaces a 502 (or retries on the
        // standard path), failure-loud all the way through.
        logging::Get()->error(
            "BUG: H2BodyReadCallback invoked with null source->ptr — "
            "RST_STREAM via TEMPORAL_CALLBACK_FAILURE");
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    size_t remaining = src->body.size() - src->offset;
    size_t copy = std::min(remaining, length);
    if (copy > 0) {
        std::memcpy(buf, src->body.data() + src->offset, copy);
        src->offset += copy;
    }
    if (src->offset >= src->body.size()) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    }
    return static_cast<ssize_t>(copy);
}

int OnDataChunkRecvCallback(nghttp2_session* /*session*/, uint8_t /*flags*/,
                            int32_t stream_id, const uint8_t* data,
                            size_t len, void* user_data)
{
    auto* self = static_cast<UpstreamH2Connection*>(user_data);
    auto* stream = self->GetStream(stream_id);
    if (!stream || !stream->sink) return 0;

    // Defense-in-depth: nghttp2's HTTP-messaging enforcement normally
    // catches NO_BODY / Content-Length violations before we get here.
    // Kept active as a backstop for callers that opt out of enforcement.
    // ResetStream (not raw nghttp2_submit_rst_stream) so in_receive_data_
    // defers the inline FlushSend until the post-receive flush.
    using Framing = UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead::Framing;
    // Detach sink before OnError so a synchronous teardown chain
    // (sink OnError → Cleanup → ResetStream) does not re-dispatch on
    // an already-failed path.
    auto reject_truncation = [&](const char* msg) {
        auto* sink = stream->sink;
        stream->sink = nullptr;
        if (sink) {
            sink->OnError(ProxyTransaction::RESULT_TRUNCATED_RESPONSE, msg);
        }
        self->ResetStream(stream_id);
    };
    if (stream->response_head.framing == Framing::NO_BODY && len > 0) {
        reject_truncation("body bytes on NO_BODY response");
        return 0;
    }
    if (stream->response_head.framing == Framing::CONTENT_LENGTH &&
        stream->response_head.expected_length >= 0 &&
        static_cast<int64_t>(len) >
            stream->response_head.expected_length -
            stream->body_bytes_received) {
        reject_truncation("body exceeds Content-Length");
        return 0;
    }

    stream->body_bytes_received += static_cast<int64_t>(len);
    const bool keep = stream->sink->OnBodyChunk(
        reinterpret_cast<const char*>(data), len);
    if (!keep) {
        // Sink refused further body — detach + RST_STREAM(CANCEL) so
        // the upstream stops sending. Session stays alive for sibling
        // streams. The pre-null guards against ResetStream's dead_
        // short-circuit.
        stream->sink = nullptr;
        self->ResetStream(stream_id);
    }
    return 0;
}

// Enqueue EVERY serialized frame for byte-accurate drain tracking.
// Request-side HEADERS / DATA frames eventually fire sink virtuals from
// the transport-drain hooks; control frames (PING / SETTINGS /
// WINDOW_UPDATE / RST_STREAM / GOAWAY / PRIORITY) are tracked as
// is_control entries so the bytes they consume in the transport buffer
// are correctly attributed (without this, a PING flushed before a fresh
// request would shrink the transport's remaining-bytes counter and
// mis-attribute the PING's drain to the request's first frame, firing
// OnRequestSubmitted before the request's bytes actually hit the wire).
int OnFrameSendCallback(nghttp2_session* /*session*/,
                        const nghttp2_frame* frame, void* user_data)
{
    if (!frame) return 0;
    auto* self = static_cast<UpstreamH2Connection*>(user_data);
    // Wire size = 9-byte frame header + payload length. nghttp2's
    // frame->hd.length is the payload size; framework adds 9 for the
    // fixed header regardless of frame type.
    const size_t frame_bytes = 9 + static_cast<size_t>(frame->hd.length);
    const bool is_request_frame =
        (frame->hd.type == NGHTTP2_HEADERS ||
         frame->hd.type == NGHTTP2_DATA);
    if (is_request_frame) {
        auto* stream = self->GetStream(frame->hd.stream_id);
        if (!stream || !stream->sink) {
            // Stream missing or sink detached — still track the bytes
            // as a control entry so the FIFO byte accounting stays
            // accurate. The dispatch lookup at fire-time will short-
            // circuit on the missing stream regardless.
            self->EnqueueFrameForDrain(frame->hd.stream_id, frame_bytes,
                                        /*is_data=*/false,
                                        /*is_end_stream=*/false,
                                        /*is_control=*/true);
            return 0;
        }
        const bool is_data = (frame->hd.type == NGHTTP2_DATA);
        const bool eos = (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0;
        self->EnqueueFrameForDrain(frame->hd.stream_id, frame_bytes,
                                    is_data, eos, /*is_control=*/false);
        return 0;
    }
    // Control frame: track bytes but never dispatch sink virtuals.
    self->EnqueueFrameForDrain(/*stream_id=*/0, frame_bytes,
                                /*is_data=*/false,
                                /*is_end_stream=*/false,
                                /*is_control=*/true);
    return 0;
}

// RAII guard for the receive-reentrancy flag. Constructed on each
// HandleBytes call; restored on scope exit so the flag tracks the
// recursion edge cleanly even when nghttp2 callbacks throw.
struct ReceiveDataGuard {
    bool& flag;
    bool prev;
    explicit ReceiveDataGuard(bool& f) : flag(f), prev(f) { flag = true; }
    ~ReceiveDataGuard() { flag = prev; }
};

}  // namespace

UpstreamH2Connection::UpstreamH2Connection(
    UpstreamConnection* transport,
    std::shared_ptr<const Http2UpstreamConfig> cfg)
    : transport_(transport), cfg_(std::move(cfg))
{
    last_activity_at_ = std::chrono::steady_clock::now();
}

UpstreamH2Connection::~UpstreamH2Connection() {
    // Null H2-session-bound transport callbacks FIRST so incoming bytes
    // arriving mid-dtor cannot reenter HandleBytes and trigger a
    // FlushSend on a session that's about to be torn down. This also
    // closes the door on the pool re-wire path (WirePoolCallbacks)
    // observing closures that capture a now-expired weak_ptr to *this.
    if (transport_) {
        if (auto t = transport_->GetTransport()) {
            t->SetOnMessageCb(nullptr);
            t->SetCloseCb(nullptr);
            t->SetErrorCb(nullptr);
            // Write-progress / completion hooks installed by
            // AcquireH2Connection — must also be cleared before the
            // transport returns to the pool, otherwise the next
            // borrower inherits closures pointing at a destroyed
            // session.
            t->SetWriteProgressCb(nullptr);
            t->SetCompletionCb(nullptr);
        }
    }
    if (session_) {
        // Defense-in-depth: callers may destroy with active streams
        // (future evict+replace path, unit test, etc.); FailAllStreams
        // prevents sink leak. MarkDead first so any reentrant call
        // from a sink's OnError closure observes IsUsable()==false
        // and does not attempt further work on the session about to
        // be torn down below.
        MarkDead();
        FailAllStreams(ProxyTransaction::RESULT_UPSTREAM_DISCONNECT,
                       "h2 session destroyed");
        // Best-effort polite shutdown. Failure is non-fatal — the
        // transport will be torn down regardless when the lease ends.
        nghttp2_session_terminate_session(session_, NGHTTP2_NO_ERROR);
        FlushSend();
        nghttp2_session_del(session_);
        session_ = nullptr;
    }
    // Lease destructor returns the underlying transport to the pool.
}

bool UpstreamH2Connection::Init() {
    if (session_) return true;

    nghttp2_session_callbacks* cbs = nullptr;
    if (nghttp2_session_callbacks_new(&cbs) != 0) {
        logging::Get()->error("UpstreamH2Connection: callbacks_new failed");
        return false;
    }
    // No send_callback registered: FlushSend uses nghttp2_session_mem_send2
    // which returns the bytes directly. Registering one would make a
    // future maintainer assume the path is wired.
    nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, &OnFrameRecvCallback);
    nghttp2_session_callbacks_set_on_stream_close_callback(cbs, &OnStreamCloseCallback);
    nghttp2_session_callbacks_set_on_header_callback(cbs, &OnHeaderCallback);
    nghttp2_session_callbacks_set_on_begin_headers_callback(cbs, &OnBeginHeadersCallback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, &OnDataChunkRecvCallback);
    nghttp2_session_callbacks_set_on_frame_send_callback(cbs, &OnFrameSendCallback);

    int rv = nghttp2_session_client_new(&session_, cbs, this);
    nghttp2_session_callbacks_del(cbs);
    if (rv != 0) {
        logging::Get()->error("UpstreamH2Connection: session_client_new failed rv={}", rv);
        session_ = nullptr;
        return false;
    }

    auto settings = UPSTREAM_H2_SETTINGS::BuildSettingsArray(*cfg_);
    rv = nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE,
                                  settings.data(), settings.size());
    if (rv != 0) {
        logging::Get()->error("UpstreamH2Connection: submit_settings failed rv={}", rv);
        nghttp2_session_del(session_);
        session_ = nullptr;
        return false;
    }
    return FlushSend();
}

ssize_t UpstreamH2Connection::HandleBytes(const char* data, size_t len) {
    if (!session_) return -1;
    last_activity_at_ = std::chrono::steady_clock::now();
    ssize_t consumed = 0;
    {
        ReceiveDataGuard g(in_receive_data_);
        consumed = nghttp2_session_mem_recv2(
            session_, reinterpret_cast<const uint8_t*>(data), len);
    }
    if (consumed < 0) {
        logging::Get()->warn(
            "UpstreamH2Connection: mem_recv2 failed rv={}", consumed);
        return consumed;
    }
    if (!FlushSend()) return -1;
    return consumed;
}

bool UpstreamH2Connection::FlushSend() {
    if (!session_) return false;
    while (nghttp2_session_want_write(session_)) {
        const uint8_t* buf = nullptr;
        ssize_t n = nghttp2_session_mem_send2(session_, &buf);
        if (n < 0) {
            logging::Get()->warn(
                "UpstreamH2Connection: mem_send2 failed rv={}", n);
            return false;
        }
        if (n == 0) break;
        if (transport_) {
            if (auto t = transport_->GetTransport()) {
                t->SendRaw(reinterpret_cast<const char*>(buf), n);
            }
        }
    }
    return true;
}

bool UpstreamH2Connection::SendPing(
    std::chrono::steady_clock::time_point now)
{
    if (!session_ || goaway_seen_) return false;
    if (pending_ping_at_.has_value()) return false;

    uint8_t opaque[8];
    uint64_t seq = ++ping_seq_;
    std::memcpy(opaque, &seq, sizeof(opaque));
    int rv = nghttp2_submit_ping(session_, NGHTTP2_FLAG_NONE, opaque);
    if (rv != 0) {
        logging::Get()->warn(
            "UpstreamH2Connection: submit_ping failed rv={}", rv);
        return false;
    }
    pending_ping_at_ = now;
    last_activity_at_ = now;
    return FlushSend();
}

bool UpstreamH2Connection::Tick(std::chrono::steady_clock::time_point now,
                                 int ping_idle_sec, int ping_timeout_sec,
                                 int goaway_drain_timeout_sec)
{
    if (!session_) return false;

    if (pending_ping_at_.has_value() && ping_timeout_sec > 0) {
        auto elapsed =
            std::chrono::duration_cast<std::chrono::seconds>(
                now - *pending_ping_at_).count();
        if (elapsed >= ping_timeout_sec) {
            logging::Get()->warn(
                "UpstreamH2Connection: PING timeout after {}s — closing",
                elapsed);
            return false;
        }
    }

    // GOAWAY drain bound. Once the peer has signaled GOAWAY and the
    // configured drain window has elapsed without every in-flight stream
    // completing, retire the connection so the partition slot can be
    // reclaimed. The reap walker still removes a fully-drained
    // (active_stream_count() == 0) GOAWAY'd session inline; this branch
    // catches the stuck case the walker can never observe.
    if (goaway_seen_ && goaway_drain_timeout_sec > 0 && !streams_.empty()) {
        auto elapsed =
            std::chrono::duration_cast<std::chrono::seconds>(
                now - goaway_seen_at_).count();
        if (elapsed >= goaway_drain_timeout_sec) {
            logging::Get()->warn(
                "UpstreamH2Connection: GOAWAY drain timeout after {}s with "
                "{} stream(s) still active — closing",
                elapsed, streams_.size());
            return false;
        }
    }

    if (!pending_ping_at_.has_value() && ping_idle_sec > 0 && !goaway_seen_) {
        auto idle =
            std::chrono::duration_cast<std::chrono::seconds>(
                now - last_activity_at_).count();
        if (idle >= ping_idle_sec) {
            SendPing(now);
        }
    }
    return true;
}

void UpstreamH2Connection::OnPingAck() {
    pending_ping_at_.reset();
    last_activity_at_ = std::chrono::steady_clock::now();
}

void UpstreamH2Connection::OnGoawayReceived(int32_t last_stream_id) {
    auto now = std::chrono::steady_clock::now();
    // Set goaway_seen_=true BEFORE the fan-out below: a sink's OnError
    // closure can synchronously call back into TryDispatchExistingH2Session
    // / IsUsable() — both check goaway_seen_ and reject this connection,
    // which is required to prevent the same-conn from being reselected
    // and a fresh stream submitted onto a session that's already
    // draining. Reordering the assignment after fan-out would silently
    // break the guarantee.
    goaway_seen_ = true;
    goaway_last_stream_id_ = last_stream_id;
    goaway_seen_at_ = now;
    last_activity_at_ = now;
    // SendPing returns false when goaway_seen_, so no NEW PINGs fire
    // after this point. But an outstanding PING (sent before GOAWAY)
    // would still let Tick evict at min(ping_timeout_sec,
    // goaway_drain_timeout_sec) instead of the documented bound of
    // goaway_drain_timeout_sec. Clearing pending_ping_at_ keeps the
    // drain window honest — a peer mid-shutdown is unlikely to PONG,
    // and a missed PONG ACK after GOAWAY is uninteresting anyway.
    pending_ping_at_.reset();

    // RFC 9113 §6.8: streams whose id > last_stream_id were not processed
    // by the peer and MUST be safe to retry on a fresh connection. Fail
    // them now with a retryable error so the proxy retry policy kicks
    // in immediately instead of waiting for transport close or the
    // per-attempt response timeout. Streams with id <= last_stream_id
    // continue draining naturally.
    if (streams_.empty()) return;
    std::vector<int32_t> to_fail;
    to_fail.reserve(streams_.size());
    for (auto& kv : streams_) {
        if (kv.first > last_stream_id) to_fail.push_back(kv.first);
    }
    // Fail in ascending stream_id order (= oldest first). streams_ is
    // unordered_map so the iteration above produces an unspecified order;
    // sorting gives deterministic fan-out so a sink's reentrant
    // ResetStream can reliably detach a later-numbered sibling before its
    // turn comes — matches the per-stream lifecycle invariant the
    // sink-detach race depends on.
    std::sort(to_fail.begin(), to_fail.end());
    for (int32_t sid : to_fail) {
        auto it = streams_.find(sid);
        if (it == streams_.end()) continue;
        auto stream = it->second;
        streams_.erase(it);
        if (stream && stream->sink) {
            stream->sink->OnError(
                ProxyTransaction::RESULT_UPSTREAM_DISCONNECT,
                "h2 stream above GOAWAY last_stream_id — peer did not process");
        }
    }
}

void UpstreamH2Connection::OnStreamClose(int32_t stream_id,
                                         uint32_t error_code) {
    auto it = streams_.find(stream_id);
    if (it != streams_.end()) {
        // Erase BEFORE firing the sink so any re-entrant SubmitRequest /
        // ResetStream calls see a clean stream table. Keep the shared_ptr
        // alive on the stack so the stream object survives the callback.
        auto stream = it->second;
        streams_.erase(it);
        if (stream && stream->sink) {
            using Framing = UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead::Framing;
            if (error_code == NGHTTP2_NO_ERROR) {
                // Content-Length short-read: peer ended the stream cleanly
                // but delivered fewer bytes than declared. Surface a
                // truncation error in place of the OnComplete dispatch so
                // downstream consumers see RESULT_TRUNCATED_RESPONSE rather
                // than a successful response with a short body.
                //
                // In production this branch is also a defense-in-depth
                // backstop: nghttp2's HTTP messaging enforcement
                // (default-on) intercepts CL/NO_BODY violations and
                // delivers them via the non-NO_ERROR fan-out above
                // (OnDataChunkRecvCallback's Step 1.5 is a parallel
                // backstop for the same enforcement-disabled future).
                // The active value of THIS branch is the silent-short-
                // close case where the peer respects framing on the wire
                // but lies about Content-Length — neither nghttp2 nor
                // Step 1.5 can detect that until the clean END_STREAM
                // arrives short.
                if (stream->response_head.framing == Framing::CONTENT_LENGTH &&
                    stream->response_head.expected_length >= 0 &&
                    stream->body_bytes_received <
                        stream->response_head.expected_length) {
                    stream->sink->OnError(
                        ProxyTransaction::RESULT_TRUNCATED_RESPONSE,
                        "Content-Length short read");
                } else {
                    stream->sink->OnComplete();
                }
            } else if (error_code == NGHTTP2_HTTP_1_1_REQUIRED) {
                // RFC 9113 §13 (error code 0xd): peer indicates THIS
                // request must be retried over HTTP/1.1. Retrying on H2
                // will fail again — under prefer=always there is no H1
                // fallback, and even under prefer=auto a fresh H2 session
                // may hit the same response-side rejection. Two actions:
                //   1. Mark the H2 connection dead so future
                //      AcquireH2Connection callers skip it (a fresh
                //      transport will renegotiate ALPN; under
                //      prefer=auto an h1-only peer would land on H1).
                //   2. Surface RESULT_PARSE_ERROR (terminal, 502) to
                //      bypass ProxyTransaction::OnError's H2 retry
                //      escape hatch (which only fires for
                //      UPSTREAM_DISCONNECT). Without #2, the retry
                //      budget would burn looping against an H2 session
                //      that fundamentally rejects this request shape.
                MarkDead();
                stream->sink->OnError(
                    ProxyTransaction::RESULT_PARSE_ERROR,
                    "h2 peer sent HTTP_1_1_REQUIRED — set "
                    "upstream http2.prefer=never or reconfigure "
                    "upstream H2 routing");
            } else {
                // Translate the H2 stream error to a proxy RESULT_* code.
                // Without this translation the raw nghttp2 code (positive
                // int) falls through ProxyTransaction::MakeErrorResponse's
                // RESULT_* allowlist to InternalError() — surfacing a 500
                // for what is fundamentally an upstream/transport failure.
                // RESULT_UPSTREAM_DISCONNECT maps to 502 BadGateway and is
                // retryable: covers REFUSED_STREAM (peer didn't process,
                // safe to retry), CANCEL (peer aborted), PROTOCOL_ERROR /
                // INTERNAL_ERROR (upstream-side malformed response —
                // distinct from a local PARSE_ERROR which is also 502).
                stream->sink->OnError(
                    ProxyTransaction::RESULT_UPSTREAM_DISCONNECT,
                    "h2 stream closed with error code=" +
                        std::to_string(error_code));
            }
        }
    }
    last_activity_at_ = std::chrono::steady_clock::now();
}

void UpstreamH2Connection::OnHeadersComplete(int32_t stream_id,
                                              bool end_stream) {
    auto it = streams_.find(stream_id);
    if (it == streams_.end()) return;
    auto& stream = it->second;
    if (!stream || stream->head_dispatched || !stream->sink) return;
    stream->head_dispatched = true;

    // H2 connections are multiplexed — the transport is never returned to
    // the H1 idle pool, so keep_alive=true prevents poison_connection_
    // from flipping gratuitously on every successful H2 response.
    stream->response_head.keep_alive = true;

    // Map H2 framing to UpstreamResponseHead::Framing. H2 streams are
    // always either NO_BODY (END_STREAM on HEADERS frame) or
    // CHUNKED-equivalent; check for Content-Length to prefer exact framing.
    using Framing = UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead::Framing;
    // Parse Content-Length regardless of end_stream so the HEADERS-only
    // short-read case (end_stream on HEADERS with CL > 0) can be
    // classified as CONTENT_LENGTH and detected by OnStreamClose's CL
    // short-read check.
    int64_t cl = -1;
    for (const auto& [nm, val] : stream->response_head.headers) {
        if (nm == "content-length") {
            // from_chars: strict full-string consume; std::stoll
            // skips leading whitespace and would accept "  42".
            cl = -1;
            const char* end = val.data() + val.size();
            int64_t parsed = 0;
            auto [ptr, ec] = std::from_chars(val.data(), end, parsed);
            if (ec == std::errc() && ptr == end && parsed >= 0) {
                cl = parsed;
            }
            if (cl > static_cast<int64_t>(
                    UpstreamHttpCodec::MAX_RESPONSE_BODY_SIZE)) {
                logging::Get()->warn(
                    "UpstreamH2Connection: content-length {} exceeds cap "
                    "{} on stream {}; treating as chunked",
                    val,
                    UpstreamHttpCodec::MAX_RESPONSE_BODY_SIZE,
                    stream_id);
                cl = -1;
            }
            break;
        }
    }

    const bool bodyless_status =
        (stream->response_head.status_code == 204 ||
         stream->response_head.status_code == 304 ||
         stream->request_method == "HEAD");

    if (bodyless_status) {
        // RFC 9110 §15.4 / §15.4.5 / §9.3.2: 204 / 304 / HEAD responses
        // MUST NOT carry a body. Content-Length on these is allowed
        // as informational (RFC 9110 §9.3.2 specifically permits CL on
        // HEAD to advertise the equivalent-GET body size) and does NOT
        // trigger a short-read check. Classify as NO_BODY so Step 1.5
        // in OnDataChunkRecvCallback rejects any subsequent body bytes
        // from a misbehaving peer with RESULT_TRUNCATED_RESPONSE.
        stream->response_head.framing = Framing::NO_BODY;
    } else if (end_stream) {
        // END_STREAM on HEADERS with a non-bodyless status. If CL > 0
        // was declared, peer promised N body bytes and delivered zero
        // — that's a framing violation. Classify as CONTENT_LENGTH
        // with expected_length=cl so OnStreamClose's existing CL
        // short-read check fires RESULT_TRUNCATED_RESPONSE (defense
        // in depth — nghttp2's HTTP messaging enforcement normally
        // catches this first via the non-NO_ERROR fan-out, but the
        // backstop covers the no-messaging-enforcement future).
        // CL == 0 or absent CL → legitimate empty-body response,
        // classify as NO_BODY.
        if (cl > 0) {
            stream->response_head.framing = Framing::CONTENT_LENGTH;
            stream->response_head.expected_length = cl;
        } else {
            stream->response_head.framing = Framing::NO_BODY;
        }
    } else if (cl >= 0) {
        stream->response_head.framing = Framing::CONTENT_LENGTH;
        stream->response_head.expected_length = cl;
    } else {
        stream->response_head.framing = Framing::CHUNKED;
    }

    if (!stream->sink->OnHeaders(stream->response_head)) {
        // Sink rejected the response head (e.g. client disconnect during
        // commit). Cancel the stream — same semantic as H1 returning
        // false from the headers_complete callback.
        ResetStream(stream_id);
    }
}

void UpstreamH2Connection::OnTrailersComplete(int32_t stream_id) {
    auto it = streams_.find(stream_id);
    if (it == streams_.end()) return;
    auto& stream = it->second;
    if (!stream || !stream->sink) return;
    // Elide an empty trailers HEADERS block (legal per RFC 9113 §8.1):
    // sinks observe stream completion via OnComplete (driven by
    // OnStreamClose), so dispatching a zero-pair OnTrailers here would
    // be a no-op for every existing sink.
    if (stream->trailers.empty()) return;
    stream->sink->OnTrailers(stream->trailers);
}

UpstreamH2Stream* UpstreamH2Connection::GetStream(int32_t stream_id) {
    auto it = streams_.find(stream_id);
    return it == streams_.end() ? nullptr : it->second.get();
}

bool UpstreamH2Connection::IsUsable() const {
    if (dead_ || !session_ || goaway_seen_ || !cfg_) return false;
    if (cfg_->max_concurrent_streams_pref == 0) return false;
    return streams_.size() < cfg_->max_concurrent_streams_pref;
}

void UpstreamH2Connection::MarkDead() {
    dead_ = true;
}

void UpstreamH2Connection::AdoptLease(UpstreamLease lease) {
    lease_ = std::move(lease);
}

void UpstreamH2Connection::FailAllStreams(int error_code,
                                          const std::string& reason) {
    if (streams_.empty()) return;
    auto streams = std::move(streams_);
    streams_.clear();
    // Drain queue entries for these streams are now stale — sinks are
    // about to be invoked via OnError and must not fire request-side
    // virtuals afterwards. Clear the whole queue: no other streams are
    // left to attribute drained bytes to.
    drain_queue_.clear();
    bytes_in_drain_queue_ = 0;
    for (auto& kv : streams) {
        if (kv.second && kv.second->sink) {
            kv.second->sink->OnError(error_code, reason);
        }
    }
}

void UpstreamH2Connection::ResetStream(int32_t stream_id) {
    if (!session_) return;
    // dead_ guard: during dtor teardown, MarkDead runs before
    // FailAllStreams fan-out; if any sink's OnError closure reentrantly
    // calls ResetStream, the submit below would warn-spam against an
    // about-to-be-freed session.
    if (dead_) return;
    auto it = streams_.find(stream_id);
    if (it == streams_.end()) return;
    // Detach the sink before submitting RST_STREAM so the eventual
    // OnStreamClose does not fire OnError on a transaction that has
    // already moved on (e.g. a retry in progress). The drain-queue
    // sweep removes any not-yet-fired progress/submitted entries for
    // this stream so they don't later dispatch to the nulled sink.
    if (it->second) it->second->sink = nullptr;
    DropDrainEntriesForStream(stream_id);
    int rv = nghttp2_submit_rst_stream(session_, NGHTTP2_FLAG_NONE, stream_id, NGHTTP2_CANCEL);

    if (rv != 0) {
        logging::Get()->warn(
            "UpstreamH2Connection: submit_rst_stream sid={} rv={}",
            stream_id, rv);
    }
    if (!in_receive_data_) FlushSend();
}

void UpstreamH2Connection::EnqueueFrameForDrain(int32_t stream_id,
                                                size_t bytes,
                                                bool is_data_frame,
                                                bool is_end_stream,
                                                bool is_control) {
    drain_queue_.push_back(
        PendingFrameDrain{stream_id, bytes, is_data_frame, is_end_stream,
                          is_control});
    bytes_in_drain_queue_ += bytes;
}

void UpstreamH2Connection::FireSinkForDrainEntry(const PendingFrameDrain& entry) {
    // Control frames are tracked for byte accounting only — never
    // dispatch sink virtuals for them (no stream to look up; the
    // sentinel stream_id is meaningless).
    if (entry.is_control) return;
    // Stream may have been reset between serialization and drain — the
    // sink is nulled by ResetStream / FailAllStreams in that case, so
    // a stale lookup short-circuits here.
    auto it = streams_.find(entry.stream_id);
    if (it == streams_.end() || !it->second || !it->second->sink) return;
    if (entry.is_end_stream) {
        it->second->sink->OnRequestSubmitted();
    } else if (entry.is_data_frame) {
        it->second->sink->OnRequestBodyProgress();
    }
}

void UpstreamH2Connection::DropDrainEntriesForStream(int32_t stream_id) {
    if (drain_queue_.empty()) return;
    // TOMBSTONE — do NOT erase. The reset stream's bytes are already
    // sitting in the shared transport buffer ahead of (or interleaved
    // with) sibling streams' bytes; erasing the entries and subtracting
    // their bytes would skew bytes_in_drain_queue_ vs transport's
    // `remaining` count, causing OnTransportWriteProgress's
    // `remaining >= bytes_in_drain_queue_` early-return to skip
    // attribution while the reset stream's leftover bytes drain. That
    // starves sibling streams' OnRequestBodyProgress / OnRequestSubmitted
    // until the reset stream's bytes fully clear — and if the reset
    // stream's transport-buffered tail stalls, sibling streams can hit
    // false send-stall timeouts. Convert the entries to is_control so
    // FireSinkForDrainEntry skips dispatch, but keep their bytes in the
    // FIFO sum so accounting stays byte-accurate to the wire.
    for (auto& e : drain_queue_) {
        if (!e.is_control && e.stream_id == stream_id) {
            e.is_control = true;
            e.is_data_frame = false;
            e.is_end_stream = false;
        }
    }
}

void UpstreamH2Connection::OnTransportWriteProgress(size_t remaining) {
    if (dead_) return;
    if (drain_queue_.empty()) return;
    // The transport buffer may contain bytes we did NOT push through
    // on_frame_send (e.g. the 24-byte HTTP/2 client connection preface
    // magic string at session start). When `remaining` exceeds our
    // tracked queue total, those untracked bytes are still draining
    // ahead of our first queued frame — leave the queue total alone
    // and wait. Updating bytes_in_drain_queue_ = remaining here would
    // inflate the tracked sum and over-attribute drained bytes to the
    // front entry on the next fire.
    if (remaining >= bytes_in_drain_queue_) return;
    size_t drained = bytes_in_drain_queue_ - remaining;
    bytes_in_drain_queue_ = remaining;
    while (drained > 0 && !drain_queue_.empty()) {
        PendingFrameDrain& front = drain_queue_.front();
        if (drained >= front.bytes) {
            drained -= front.bytes;
            PendingFrameDrain entry = front;
            drain_queue_.pop_front();
            // Fire AFTER pop so a sink callback that re-enters
            // (e.g., Cleanup → ResetStream → DropDrainEntriesForStream)
            // does not invalidate `front`.
            FireSinkForDrainEntry(entry);
        } else {
            // Partial drain: refresh the per-stream stall timestamp via
            // OnRequestBodyProgress regardless of END_STREAM. A single
            // DATA frame body or the trailing DATA frame of a multi-
            // frame upload would otherwise never see progress while
            // its bytes are actively leaving the socket — the stall
            // budget would expire mid-drain even though the wire is
            // healthy. OnRequestSubmitted is reserved for the
            // FULL-drain branch above, so firing progress here cannot
            // race the submitted dispatch. Control-frame entries
            // (is_control=true) skip dispatch via FireSinkForDrainEntry.
            front.bytes -= drained;
            drained = 0;
            if (front.is_data_frame && !front.is_control) {
                PendingFrameDrain partial_entry{
                    front.stream_id, 0, /*is_data=*/true,
                    /*is_end_stream=*/false, /*is_control=*/false};
                FireSinkForDrainEntry(partial_entry);
            }
        }
    }
}

void UpstreamH2Connection::OnTransportWriteComplete() {
    if (dead_) return;
    if (drain_queue_.empty()) {
        bytes_in_drain_queue_ = 0;
        return;
    }
    // Transport buffer is empty — every queued frame is on the wire.
    auto pending = std::move(drain_queue_);
    drain_queue_.clear();
    bytes_in_drain_queue_ = 0;
    for (auto& entry : pending) {
        FireSinkForDrainEntry(entry);
    }
}

namespace {

// Hop-by-hop and pseudo-header gate for outbound H2 requests. Reuses
// HeaderRewriter::IsHopByHopHeader for the RFC 7230 hop-by-hop set
// (which already includes connection / keep-alive / proxy-connection /
// te / transfer-encoding / upgrade / trailer / proxy-authenticate /
// proxy-authorization). Also strips Host because the H2 wire conveys
// it via :authority.
bool IsForbiddenH2RequestHeader(const std::string& lower_name) {
    // HeaderRewriter::IsHopByHopHeader covers the RFC 7230 §6.1 set;
    // host is conveyed via :authority on the H2 wire; expect is illegal
    // on H2 per RFC 9113 §8.2.2 and HeaderRewriter strips it upstream,
    // but list it explicitly as defense-in-depth so this gate stays
    // self-contained.
    return HeaderRewriter::IsHopByHopHeader(lower_name) ||
           lower_name == "host" ||
           lower_name == "expect";
}

}  // namespace

int32_t UpstreamH2Connection::SubmitRequest(
    const std::string& method,
    const std::string& scheme,
    const std::string& authority,
    const std::string& path,
    const std::map<std::string, std::string>& headers,
    const std::string& body,
    UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseSink* sink,
    bool client_te_trailers)
{
    if (!IsUsable()) return -1;

    // Secondary CONNECT-rejection gate. Primary gate lives in
    // ProxyTransaction::DispatchH2; this catches direct callers that
    // bypass it (unit tests / future code paths). Sink->OnError fires
    // here, so callers that also run their own rollback on a -1 return
    // must be idempotent on the error path.
    if (method == "CONNECT") {
        const std::string host = transport_ ? transport_->upstream_host()
                                            : std::string("?");
        logging::Get()->warn(
            "UpstreamH2Connection: rejecting CONNECT secondary gate "
            "(primary gate bypassed?) host={}", host);
        if (sink) {
            sink->OnError(
                ProxyTransaction::RESULT_H2_METHOD_NOT_SUPPORTED,
                "CONNECT not supported on H2 upstream");
        }
        return -1;
    }

    // Build lowercased header-name backing store FIRST so the nghttp2_nv
    // pointers we build next stay valid for the synchronous submit call.
    std::vector<std::string> lower_names;
    lower_names.reserve(headers.size());
    for (const auto& kv : headers) {
        std::string lower = kv.first;
        // RFC 9113 §8.2 mandates ASCII-lowercase header names. std::tolower
        // is locale-dependent (e.g. Turkish locale would lowercase 'I' to
        // 'ı', producing a non-ASCII byte sequence that nghttp2 rejects).
        // The explicit branch is locale-independent and faster.
        for (char& c : lower) {
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c | 0x20);
        }
        lower_names.push_back(std::move(lower));
    }

    std::vector<nghttp2_nv> nva;
    nva.reserve(4 + headers.size());
    // Pointer-and-length API only: passing pseudo-header NAMES as const
    // std::string& would create per-call temporaries (the literal bytes
    // copied into a stack-local string), and the pointers we store into
    // `nva` would dangle after the statement ends. nghttp2_submit_request2
    // memcpy's the bytes synchronously below — but ASan sees the read of
    // freed-scope storage between push and submit (stack-use-after-scope).
    // String literals have static storage duration; passing them directly
    // sidesteps the issue, and value-side pointers come from caller-owned
    // std::string refs (method/scheme/authority/path/headers) that outlive
    // this function.
    auto push_nv = [&nva](const char* name, size_t namelen,
                          const char* value, size_t valuelen) {
        nghttp2_nv nv;
        nv.name = reinterpret_cast<uint8_t*>(const_cast<char*>(name));
        nv.namelen = namelen;
        nv.value = reinterpret_cast<uint8_t*>(const_cast<char*>(value));
        nv.valuelen = valuelen;
        nv.flags = NGHTTP2_NV_FLAG_NONE;
        nva.push_back(nv);
    };

    push_nv(":method", 7, method.data(), method.size());
    push_nv(":scheme", 7, scheme.data(), scheme.size());
    push_nv(":authority", 10, authority.data(), authority.size());
    push_nv(":path", 5, path.data(), path.size());

    size_t i = 0;
    for (const auto& kv : headers) {
        const std::string& lower = lower_names[i++];
        if (IsForbiddenH2RequestHeader(lower)) continue;
        push_nv(lower.data(), lower.size(),
                kv.second.data(), kv.second.size());
    }

    // Re-emit te: trailers after the rewriter's strip pass. RFC 9113
    // §8.2.2 permits exactly this token; gRPC clients require it for
    // trailer support negotiation. Static literals have program-lifetime
    // storage, safe to reference for the synchronous submit call.
    if (client_te_trailers) {
        push_nv("te", 2, "trailers", 8);
    }

    auto stream = std::make_shared<UpstreamH2Stream>();
    stream->sink = sink;
    stream->request_method = method;

    nghttp2_data_provider2 provider = {};
    nghttp2_data_provider2* data_prd = nullptr;
    if (!body.empty()) {
        // body_source lifetime equals this streams_ entry; nghttp2 stops
        // invoking the read_callback once on_stream_close fires.
        // Body is COPIED into body_source rather than aliased: the caller
        // (ProxyTransaction) owns the original `request_body_` for retry
        // replay, and an alias would couple body_source's lifetime to a
        // ProxyTransaction member that may outlive the H2 stream (or, on
        // retry-then-detach, be moved out from under us). Same memory
        // profile as the H1 path during dispatch (txn copy + transport
        // buffer copy); H2 holds the body_source until nghttp2 has read
        // the full body, which can be slow with small per-stream windows.
        stream->body_source = std::make_unique<UpstreamH2BodySource>();
        stream->body_source->body = body;
        provider.source.ptr = stream->body_source.get();
        provider.read_callback = &H2BodyReadCallback;
        data_prd = &provider;
        // nghttp2_submit_request2 copies the provider2 into the session's
        // stream state — the stack-local provider is not referenced after
        // this call returns.
    }

    int32_t stream_id = nghttp2_submit_request2(
        session_, nullptr, nva.data(), nva.size(),
        data_prd, stream.get());
    if (stream_id < 0) {
        logging::Get()->warn(
            "UpstreamH2Connection: submit_request2 failed rv={}", stream_id);
        return -1;
    }

    stream->stream_id = stream_id;
    streams_[stream_id] = std::move(stream);
    last_activity_at_ = std::chrono::steady_clock::now();

    if (!in_receive_data_) {
        if (!FlushSend()) {
            // Session is in a bad state — detach the sink and erase the
            // stream so the eventual session-teardown OnStreamClose
            // can't fire OnError on a transaction that already moved on
            // to a fresh attempt with a new stream_id (the caller treats
            // -1 as CONNECT_FAILURE and retries). Mark the connection
            // dead so FindUsable evicts it instead of handing it to
            // another caller for SubmitRequest, which would also fail.
            auto it = streams_.find(stream_id);
            if (it != streams_.end()) {
                if (it->second) it->second->sink = nullptr;
                streams_.erase(it);
            }
            MarkDead();
            return -1;
        }
    }
    return stream_id;
}
