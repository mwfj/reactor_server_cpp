#pragma once

#include "common.h"
#include "config/server_config.h"
#include "upstream/upstream_h2_stream.h"
#include "upstream/upstream_lease.h"
#include "upstream/upstream_callbacks.h"
#include <nghttp2/nghttp2.h>
// <unordered_map>, <memory>, <string>, <cstdint>, <map>, <optional> provided by common.h

class UpstreamConnection;
class UpstreamH2Codec;
class ConnectionHandler;
class PoolPartition;

// Null every callback an H2 session installed on its transport so a
// late epoll/kqueue event cannot dispatch into a destroyed session.
// Called from DestroyOnDispatcher AND the dtor safety net. Safe from
// any thread because each setter is a plain field write under
// ConnectionHandler's normal ABI.
void ClearH2TransportCallbacks(ConnectionHandler* transport);

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

    // Active stream count. Incremented in SubmitRequest; decremented in
    // RunDeferredEraseWalk (the sole per-stream decrement site).
    // FailAllStreams resets to 0 as part of the bulk fan-out.
    size_t active_stream_count() const {
        return static_cast<size_t>(active_streams_);
    }

    // Liveness token. Flipped to false by destroy paths before any other
    // state mutation; transport-callback captures consult this via
    // memory_order_acquire load before dereferencing the raw connection
    // pointer.
    std::shared_ptr<std::atomic<bool>> alive_token() const {
        return conn_alive_;
    }

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
    //
    // `client_te_trailers`: if true, the nv-array build appends a
    // synthetic `te: trailers` entry after the rewriter's strip pass.
    // Defaulted false to keep existing test callers compiling unchanged.
    int32_t SubmitRequest(
        const std::string& method,
        const std::string& scheme,
        const std::string& authority,
        const std::string& path,
        const std::map<std::string, std::string>& headers,
        const std::string& body,
        UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseSink* sink,
        bool client_te_trailers = false);

    // Cancel an in-flight stream. Submits RST_STREAM with NGHTTP2_CANCEL
    // and flushes; defers the flush when called from inside HandleBytes
    // so the post-receive flush in the caller picks it up safely.
    void ResetStream(int32_t stream_id);

    // Null the stream's sink and, if peer has already closed, enqueue
    // the entry for the deferred-erase walker. Callers that submit RST
    // (ResetStream) also call this; callers that observe peer-close
    // (OnStreamClose) do so directly inline.
    void DetachSink(int32_t stream_id);

    // Erase entries flagged pending_erase_. Must run on dispatcher and
    // outside any nghttp2 callback frame — HandleBytes calls this after
    // FlushSend.
    void RunDeferredEraseWalk();

    // Take ownership of the lease that funded this connection's
    // transport. Released in ~UpstreamH2Connection so the transport
    // returns to the pool only after every stream has exited.
    void AdoptLease(UpstreamLease lease);

    // Bind this session to its owning partition. Set by every code path
    // that installs an H2 session: AcquireH2Connection (in-place
    // promotion), OnH2ConnectHandshakeComplete (cold-start probe
    // success), and InsertH2ConnectionForTesting. Never reassigned
    // after install. Needed by HandleBytes to drive the post-recv
    // pending_destroy reap and by DestroyOnDispatcher to clean up
    // timer registrations.
    void SetPartition(PoolPartition* partition) { partition_ = partition; }

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

    // Dispatcher-thread polite teardown. Six-step ordering:
    //   1. Flip conn_alive_ → false so in-flight dual-token captures
    //      observe destruction on next acquire-load.
    //   2. Null every transport callback so a queued epoll/kqueue
    //      event cannot dispatch into the dying session.
    //   3. Remove any deadline-timer registration for this fd.
    //   4. Mark the transport CLOSING so ReturnConnection routes
    //      through DestroyConnection (transport teardown + outstanding
    //      conn accounting) instead of returning to idle.
    //   5. Reset the donated lease — its destructor fires
    //      ReturnConnection, which observes the CLOSING flag and
    //      destroys the transport.
    //   6. Set destroyed_on_dispatcher_ so the destructor's safety net
    //      no-ops on the eventual unique_ptr drop.
    // Idempotent on second call; short-circuits when `transferred_`
    // (H1 adoption path) has consumed the transport.
    void DestroyOnDispatcher();

    // True after a TakeShellForH1Adoption hand-off has consumed the
    // transport. The dtor MUST suppress its callback-null / lease
    // teardown when set — the adopted H1 connection now owns the
    // transport and the pool accounting it carries.
    bool transferred() const { return transferred_; }

    // Mark this shell as having donated its transport to the H1
    // adoption path. Set BEFORE DestroyOnDispatcher / dtor so both
    // skip every step — the new H1 owner keeps the transport and its
    // outstanding_conns_ contribution. Safe because adoption only
    // reaches shells that never called Init() (no nghttp2_session_*
    // to release).
    void MarkTransferred() { transferred_ = true; }

    // True while a HandleBytes call is active. Submit / ResetStream check
    // this to defer the inline FlushSend so we never re-enter
    // nghttp2_session_mem_send2 from inside an mem_recv2 callback chain.
    bool in_receive_data() const { return in_receive_data_; }

    // Transport-drain hooks. Wired in PoolPartition::AcquireH2Connection
    // to the underlying transport's write_progress / completion callbacks.
    // Each call walks drain_queue_ in serialization order and fires the
    // per-stream sink virtuals (OnRequestBodyProgress / OnRequestSubmitted)
    // for bytes that have actually drained to the wire — NOT when nghttp2
    // serialized them into its internal buffer.
    //
    // `remaining` is the transport's current output_buf size after the
    // partial write. We compute drained = bytes_in_drain_queue_ - remaining
    // and attribute that many bytes to the front of drain_queue_.
    void OnTransportWriteProgress(size_t remaining);
    // Transport buffer fully drained — every frame in drain_queue_ is on
    // the wire. Fire any remaining sink virtuals and clear the queue.
    void OnTransportWriteComplete();
    // Called from the static on_frame_send_callback for EVERY serialized
    // frame (request HEADERS/DATA AND control frames). Push the frame's
    // wire-byte count onto drain_queue_; the sink virtuals fire from
    // the transport-drain hooks above, not here. Control frames carry
    // is_control=true so dispatch skips them but byte accounting stays
    // accurate (control bytes interleaved with request bytes in the
    // transport buffer would otherwise be mis-attributed).
    void EnqueueFrameForDrain(int32_t stream_id, size_t bytes,
                              bool is_data_frame, bool is_end_stream,
                              bool is_control);

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

    // Submitted-stream count. Diverges from streams_.size() once
    // pending_erase_ entries accumulate before the walker reaps them.
    int active_streams_ = 0;

    // Heap-allocated liveness flag. Initialized to true at construction.
    // Destroy paths must store false BEFORE any other state mutation so
    // callback captures observing the acquire-load no-op cleanly.
    std::shared_ptr<std::atomic<bool>> conn_alive_;

    // Permanently dead flag: set by MarkDead() (e.g. transport closed)
    // so IsUsable() returns false and the next table walk evicts this entry.
    bool dead_ = false;

    // Set by DestroyOnDispatcher; consulted by the dtor's safety-net
    // path to skip the teardown that already ran. Atomic so the dtor
    // can observe the set from a different thread if the dtor races.
    std::atomic<bool> destroyed_on_dispatcher_{false};

    // Set by MarkTransferred when the transport has been adopted out
    // to the H1 idle pool on ALPN-h1 fallback. Both DestroyOnDispatcher
    // and the dtor MUST suppress transport teardown when set, so the
    // new H1 borrower owns the pool accounting.
    bool transferred_ = false;

    // Non-owning back-pointer to the owning partition. Null in unit
    // tests that construct an H2 conn without a real pool. Set by
    // AcquireH2Connection via SetPartition.
    PoolPartition* partition_ = nullptr;

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

    // Per-frame drain tracking. Populated in on_frame_send_callback for
    // EVERY serialized frame (request HEADERS/DATA AND control frames
    // like PING, SETTINGS, WINDOW_UPDATE, RST_STREAM); consumed in
    // OnTransportWriteProgress / OnTransportWriteComplete as bytes drain
    // off the transport buffer. Each entry sums to the frame's wire size
    // (9-byte header + payload). Control-frame entries are tracked
    // purely for accurate byte accounting — they fire no sink virtuals.
    // Without this, a session reused for a fresh request after a PING
    // would mis-attribute the PING's drain to the new request's first
    // frame, firing OnRequestBodyProgress / OnRequestSubmitted before
    // the request's own bytes had drained.
    struct PendingFrameDrain {
        int32_t stream_id;
        size_t bytes;          // Remaining bytes for this frame on the wire
        bool is_data_frame;    // OnRequestBodyProgress dispatch (DATA only)
        bool is_end_stream;    // OnRequestSubmitted dispatch (END_STREAM)
        bool is_control;       // PING/SETTINGS/WINDOW_UPDATE/RST/etc — no sink
    };
    std::deque<PendingFrameDrain> drain_queue_;

    // Stream ids awaiting deferred erase from streams_. Pushed by
    // OnStreamClose / DetachSink; drained by RunDeferredEraseWalk.
    std::deque<int32_t> pending_erase_streams_;
    // Total bytes queued on the transport on our behalf — sum of every
    // bytes field in drain_queue_. Maintained alongside the queue so we
    // can compute drained-since-last-fire as
    //   drained = bytes_in_drain_queue_ - remaining
    // from the transport's reported `remaining`.
    size_t bytes_in_drain_queue_ = 0;

    // Pop the front entry of drain_queue_ and fire its sink virtuals.
    // Caller owns the streams_ lookup. Used by both progress and
    // complete paths.
    void FireSinkForDrainEntry(const PendingFrameDrain& entry);
    // Drop drain_queue_ entries that belong to a stream that has just
    // been failed / reset. The sink is about to be detached so its
    // virtuals must not fire post-detach.
    void DropDrainEntriesForStream(int32_t stream_id);

};
