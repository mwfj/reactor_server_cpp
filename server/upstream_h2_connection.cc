#include "upstream/upstream_h2_connection.h"
#include "upstream/h2_settings.h"
#include "upstream/upstream_connection.h"
#include "upstream/upstream_http_codec.h"
#include "upstream/header_rewriter.h"
#include "connection_handler.h"
#include "log/logger.h"
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
        stream->response.headers.clear();
        stream->response.status_code = 0;
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
            int s = 0;
            bool ok = false;
            try {
                size_t consumed = 0;
                s = std::stoi(val, &consumed);
                ok = (consumed == val.size()) && s >= 100 && s < 600;
            } catch (...) {
                ok = false;
            }
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
            stream->response.status_code = s;
        }
        // Other pseudo-headers (request pseudos in trailers are illegal,
        // unknown response pseudos are reserved) — drop silently.
        return 0;
    }

    if (to_trailers) {
        stream->trailers.emplace_back(std::move(nm), std::move(val));
    } else {
        stream->response_head.headers.emplace_back(nm, val);
        stream->response.headers.emplace_back(std::move(nm), std::move(val));
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
        // Log loudly so it surfaces in CI / production rather than
        // silently truncating the request body.
        logging::Get()->error(
            "BUG: H2BodyReadCallback invoked with null source->ptr");
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        return 0;
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
    // Look up via the connection's own stream table rather than casting
    // nghttp2's raw user_data pointer directly.
    auto* self = static_cast<UpstreamH2Connection*>(user_data);
    auto* stream = self->GetStream(stream_id);
    if (!stream || !stream->sink) return 0;
    stream->sink->OnBodyChunk(reinterpret_cast<const char*>(data), len);
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
    if (session_) {
        // Best-effort polite shutdown. Failure is non-fatal — the
        // transport will be torn down regardless when the lease ends.
        nghttp2_session_terminate_session(session_, NGHTTP2_NO_ERROR);
        FlushSend();
        nghttp2_session_del(session_);
        session_ = nullptr;
    }
    // Clear H2-session-bound transport callbacks before the lease
    // destructor returns the transport to the pool. Without this, the
    // pool's re-wire path (WirePoolCallbacks) would see closures that
    // capture a now-expired weak_ptr to *this.
    if (transport_) {
        if (auto t = transport_->GetTransport()) {
            t->SetOnMessageCb(nullptr);
            t->SetCloseCb(nullptr);
        }
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
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
        cbs, &OnDataChunkRecvCallback);

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
                                 int ping_idle_sec, int ping_timeout_sec)
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
    goaway_seen_ = true;
    goaway_last_stream_id_ = last_stream_id;
    last_activity_at_ = std::chrono::steady_clock::now();
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
            if (error_code == NGHTTP2_NO_ERROR) {
                stream->sink->OnComplete();
            } else {
                stream->sink->OnError(
                    static_cast<int>(error_code),
                    "h2 stream closed with error");
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
    stream->response.headers_complete = true;

    // H2 connections are multiplexed — the transport is never returned to
    // the H1 idle pool, so keep_alive=true prevents poison_connection_
    // from flipping gratuitously on every successful H2 response.
    stream->response_head.keep_alive = true;

    // Map H2 framing to UpstreamResponseHead::Framing. H2 streams are
    // always either NO_BODY (END_STREAM on HEADERS frame) or
    // CHUNKED-equivalent; check for Content-Length to prefer exact framing.
    using Framing = UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead::Framing;
    if (end_stream) {
        stream->response_head.framing = Framing::NO_BODY;
    } else {
        // Scan accumulated headers for content-length. Cap at the H1
        // codec's MAX_RESPONSE_BODY_SIZE to defend against malicious or
        // buggy upstreams advertising absurd values (e.g. 1e18 bytes)
        // that would propagate through expected_length into snapshot
        // truncation arithmetic. RFC 9113 lets us treat the header as
        // informational, so on an over-cap value we fall through to
        // CHUNKED-equivalent framing and rely on END_STREAM as the
        // authoritative end-of-body signal.
        int64_t cl = -1;
        for (const auto& [nm, val] : stream->response_head.headers) {
            if (nm == "content-length") {
                size_t consumed = 0;
                try { cl = std::stoll(val, &consumed); } catch (...) { cl = -1; }
                if (consumed != val.size()) cl = -1;
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
        if (cl >= 0) {
            stream->response_head.framing = Framing::CONTENT_LENGTH;
            stream->response_head.expected_length = cl;
        } else {
            stream->response_head.framing = Framing::CHUNKED;
        }
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
    for (auto& kv : streams) {
        if (kv.second && kv.second->sink) {
            kv.second->sink->OnError(error_code, reason);
        }
    }
}

void UpstreamH2Connection::ResetStream(int32_t stream_id) {
    if (!session_) return;
    auto it = streams_.find(stream_id);
    if (it == streams_.end()) return;
    // Detach the sink before submitting RST_STREAM so the eventual
    // OnStreamClose does not fire OnError on a transaction that has
    // already moved on (e.g. a retry in progress).
    if (it->second) it->second->sink = nullptr;
    int rv = nghttp2_submit_rst_stream(
        session_, NGHTTP2_FLAG_NONE, stream_id, NGHTTP2_CANCEL);
    if (rv != 0) {
        logging::Get()->warn(
            "UpstreamH2Connection: submit_rst_stream sid={} rv={}",
            stream_id, rv);
    }
    if (!in_receive_data_) FlushSend();
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
    UpstreamH2Codec* codec,
    UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseSink* sink)
{
    if (!IsUsable()) return -1;

    // Build lowercased header-name backing store FIRST so the nghttp2_nv
    // pointers we build next stay valid for the synchronous submit call.
    std::vector<std::string> lower_names;
    lower_names.reserve(headers.size());
    for (const auto& kv : headers) {
        std::string lower = kv.first;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        lower_names.push_back(std::move(lower));
    }

    std::vector<nghttp2_nv> nva;
    nva.reserve(4 + headers.size());
    auto push_nv = [&nva](const std::string& name, const std::string& value) {
        nghttp2_nv nv;
        nv.name = reinterpret_cast<uint8_t*>(const_cast<char*>(name.data()));
        nv.namelen = name.size();
        nv.value = reinterpret_cast<uint8_t*>(const_cast<char*>(value.data()));
        nv.valuelen = value.size();
        nv.flags = NGHTTP2_NV_FLAG_NONE;
        nva.push_back(nv);
    };

    push_nv(":method", method);
    push_nv(":scheme", scheme);
    push_nv(":authority", authority);
    push_nv(":path", path);

    size_t i = 0;
    for (const auto& kv : headers) {
        const std::string& lower = lower_names[i++];
        if (IsForbiddenH2RequestHeader(lower)) continue;
        push_nv(lower, kv.second);
    }

    auto stream = std::make_shared<UpstreamH2Stream>();
    stream->codec = codec;
    stream->sink = sink;

    nghttp2_data_provider2 provider = {};
    nghttp2_data_provider2* data_prd = nullptr;
    if (!body.empty()) {
        // body_source lifetime equals this streams_ entry; nghttp2 stops
        // invoking the read_callback once on_stream_close fires.
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
