#pragma once

#include "common.h"
#include "config/server_config.h"
#include "upstream/upstream_h2_stream.h"
#include "upstream/upstream_lease.h"
#include "upstream/upstream_callbacks.h"
#include <nghttp2/nghttp2.h>
#include <chrono>
#include <optional>
// <unordered_map>, <memory>, <string>, <cstdint>, <map> provided by common.h

class UpstreamConnection;
class UpstreamH2Codec;

// Multiplexed H2 client session bound to one upstream transport. Owns
// the nghttp2_session* and the per-stream table for its lifetime. The
// transport pointer is non-owning — the UpstreamConnection is owned by
// PoolPartition and is guaranteed to outlive every UpstreamH2Connection
// that references it.
class UpstreamH2Connection {
public:
    UpstreamH2Connection(UpstreamConnection* transport,
                         std::shared_ptr<const Http2UpstreamConfig> cfg);
    ~UpstreamH2Connection();

    UpstreamH2Connection(const UpstreamH2Connection&) = delete;
    UpstreamH2Connection& operator=(const UpstreamH2Connection&) = delete;

    // One-time setup: builds the nghttp2_session, registers callbacks,
    // and submits the client preface SETTINGS. Returns false on
    // allocation failure or callback registration failure (logged).
    // Must be called before any HandleBytes / SendPing call.
    bool Init();

    // Feed bytes received from the transport. Returns the number of
    // bytes consumed by nghttp2 (always == len in practice; nghttp2
    // either consumes everything or returns a hard error). Returns
    // negative on session-fatal error — caller should close the
    // transport.
    ssize_t HandleBytes(const char* data, size_t len);

    // Drain pending frames from the session and write them to the
    // transport via SendRaw. Idempotent — safe to call after every
    // submit / receive batch. Returns false if the session reports a
    // hard error.
    bool FlushSend();

    // Submit a PING with `now`-derived opaque data. Records
    // pending_ping_at_ = now. No-op (returns false) when a PING is
    // already pending or when goaway_seen_ is set.
    bool SendPing(std::chrono::steady_clock::time_point now);

    // Periodic liveness check. Emits a PING when idle for >=
    // ping_idle_sec; closes the connection (returns false) if a PING
    // sent earlier hasn't ACKed within ping_timeout_sec, or if a
    // peer-initiated GOAWAY has been observed for >=
    // goaway_drain_timeout_sec without all in-flight streams completing.
    // Caller must pass the live snapshot's timer values; INT_MAX-or-zero
    // values disable the corresponding check.
    bool Tick(std::chrono::steady_clock::time_point now,
              int ping_idle_sec, int ping_timeout_sec,
              int goaway_drain_timeout_sec);

    // Transport accessor (non-owning). Used by the connection table on
    // reap to verify the underlying transport is still alive.
    UpstreamConnection* transport() const { return transport_; }

    // True when the underlying nghttp2_session has emitted or received
    // a GOAWAY. Once true, no new streams may be submitted on this
    // connection — the table walker reaps it once the live stream
    // count reaches zero.
    bool goaway_seen() const { return goaway_seen_; }

    // Last stream id from the most recent GOAWAY, or -1 if none.
    int32_t goaway_last_stream_id() const { return goaway_last_stream_id_; }

    // Active stream count (used by GOAWAY drain accounting and by the
    // reap walker to decide when this connection can be retired).
    size_t active_stream_count() const { return streams_.size(); }

    // Per-upstream H2 sub-config snapshot captured at construction.
    // Reference is valid for the lifetime of *this — `cfg_` is never
    // reassigned. Reload publishes new snapshots via
    // PoolPartition::ApplyHttp2ConfigCommit only for FRESH connections.
    const std::shared_ptr<const Http2UpstreamConfig>& config_snapshot() const {
        return cfg_;
    }

    // Submit an outbound HTTP request as a new H2 stream. Returns the
    // nghttp2 stream_id on success (>= 1), or -1 on submit failure or
    // when this connection is no longer usable.
    int32_t SubmitRequest(
        const std::string& method,
        const std::string& scheme,
        const std::string& authority,
        const std::string& path,
        const std::map<std::string, std::string>& headers,
        const std::string& body,
        UpstreamH2Codec* codec,
        UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseSink* sink);

    // Cancel an in-flight stream. Submits RST_STREAM with NGHTTP2_CANCEL
    // and flushes; defers the flush when called from inside HandleBytes
    // so the post-receive flush in the caller picks it up safely.
    void ResetStream(int32_t stream_id);

    // Take ownership of the lease that funded this connection's
    // transport. Released in ~UpstreamH2Connection so the transport
    // returns to the pool only after every stream has exited.
    void AdoptLease(UpstreamLease lease);

    // Fan out an error to every active stream (transport closed, PING
    // timeout, session-fatal nghttp2 error). Each stream's sink receives
    // OnError; streams_ is cleared.
    void FailAllStreams(int error_code, const std::string& reason);

    // True iff this connection can host a new stream right now: session
    // established, no GOAWAY observed, active stream count below the
    // per-upstream max_concurrent_streams_pref cap.
    bool IsUsable() const;

    // Frame-callback hooks. Public so the static C callbacks in the .cc
    // can forward to them via `static_cast<UpstreamH2Connection*>(user)`.
    void OnPingAck();
    void OnGoawayReceived(int32_t last_stream_id);
    void OnStreamClose(int32_t stream_id, uint32_t error_code);
    void OnHeadersComplete(int32_t stream_id, bool end_stream);
    // Trailing HEADERS block complete (HCAT_HEADERS after the response
    // head). Dispatches accumulated stream->trailers via sink->OnTrailers.
    void OnTrailersComplete(int32_t stream_id);
    UpstreamH2Stream* GetStream(int32_t stream_id);

    // Mark this connection permanently unusable (e.g. transport closed).
    // IsUsable() returns false after this; the table walker reaps it on
    // the next FindUsable / TickAll pass.
    void MarkDead();

    // True after MarkDead() has been called.
    bool IsDead() const { return dead_; }

    // True while a HandleBytes call is active. Submit / ResetStream check
    // this to defer the inline FlushSend so we never re-enter
    // nghttp2_session_mem_send2 from inside an mem_recv2 callback chain.
    bool in_receive_data() const { return in_receive_data_; }

private:
    // Non-owning. Lifetime contract: PoolPartition owns the transport
    // and never reclaims it while this connection's stream count > 0.
    UpstreamConnection* transport_ = nullptr;

    // Captured at construction; never reassigned. A new commit on the
    // partition publishes a new snapshot for FRESH connections; this
    // one keeps its original until retirement.
    std::shared_ptr<const Http2UpstreamConfig> cfg_;

    // Owned nghttp2_session pointer; nullptr until Init() runs.
    nghttp2_session* session_ = nullptr;

    // Per-stream table keyed by nghttp2 stream_id.
    std::unordered_map<int32_t, std::shared_ptr<UpstreamH2Stream>> streams_;

    // Permanently dead flag: set by MarkDead() (e.g. transport closed)
    // so IsUsable() returns false and the next table walk evicts this entry.
    bool dead_ = false;

    bool goaway_seen_ = false;
    int32_t goaway_last_stream_id_ = -1;
    // Timestamp at which goaway_seen_ flipped true. Tick uses this with
    // cfg_->goaway_drain_timeout_sec to evict a connection whose peer
    // has signaled close but where in-flight streams never finished —
    // without this bound, a stuck stream would pin the partition slot
    // forever.
    std::chrono::steady_clock::time_point goaway_seen_at_{};
    std::chrono::steady_clock::time_point last_activity_at_{};
    std::optional<std::chrono::steady_clock::time_point> pending_ping_at_;

    // Counter for PING opaque data (nghttp2 requires 8 bytes per PING).
    uint64_t ping_seq_ = 0;

    // Lease holding the underlying transport while this multiplexed
    // session is alive. Released in the destructor; the transport
    // returns to the pool only after every active stream has exited.
    std::optional<UpstreamLease> lease_;

    // Set true while inside HandleBytes so Submit / ResetStream callers
    // know to skip the inline FlushSend — the post-receive flush in
    // HandleBytes will pick up any frames they queued. Prevents
    // re-entering nghttp2_session_mem_send2 from a mem_recv2 callback.
    bool in_receive_data_ = false;
};
