#pragma once

#include "common.h"
#include "upstream/upstream_h2_connection.h"
// <unordered_map>, <memory>, <string> provided by common.h

// Per-PoolPartition table mapping upstream service name → list of live
// multiplexed H2 connections. Each `UpstreamH2Connection` may host many
// concurrent streams (subject to the peer's `MAX_CONCURRENT_STREAMS`),
// so the table is the routing layer between the per-partition pool and
// the per-stream `UpstreamH2Codec` callers.
//
// Dispatcher-thread-only — every method assumes it runs on the
// partition's owning dispatcher. PoolPartition's destructor must call
// `Clear()` on the dispatcher thread before returning so per-connection
// `nghttp2_session*` destruction does not race with dispatcher teardown.
class H2ConnectionTable {
public:
    H2ConnectionTable() = default;
    ~H2ConnectionTable() = default;

    H2ConnectionTable(const H2ConnectionTable&) = delete;
    H2ConnectionTable& operator=(const H2ConnectionTable&) = delete;

    // Returns the number of tracked H2 connections across all upstreams.
    // Used by stats / shutdown drain accounting.
    size_t TotalConnections() const;

    // Returns the number of tracked H2 connections for a single upstream
    // service. Used by saturation-routing decisions when picking among
    // multiple multiplexed sessions for the same upstream.
    size_t ConnectionsForUpstream(const std::string& upstream_name) const;

    // Drop every tracked connection. Called by PoolPartition shutdown
    // path. Does NOT call nghttp2_session_terminate — that's the caller's
    // responsibility before erasing.
    void Clear();

    // Walk every tracked connection and drop those that have observed
    // GOAWAY and have zero active streams. Returns the number of
    // entries removed. Called periodically from the partition's timer
    // tick after a GOAWAY arrives so drained sessions retire promptly
    // instead of waiting for the next acquire attempt.
    size_t ReapDrained();

    // Find the first usable H2 connection for `upstream_name`. Reaps
    // drained entries inline as a side benefit. Returns null when no
    // tracked connection can host a new stream right now. Lifetime is
    // owned by the table; callers that need destroy-safety capture
    // `conn->alive_token()` alongside the raw pointer.
    UpstreamH2Connection* FindUsable(const std::string& upstream_name);

    // Multi-conn-per-host selection helper. Returns every usable
    // connection for `upstream_name` in insertion order, reaping
    // expired entries inline. Caller is expected to apply per-candidate
    // predicates (endpoint freshness, saturation threshold) and pick
    // one. Pointers are non-owning and only valid on the dispatcher;
    // FIFO order matches admission order so the oldest session is
    // preferred when other criteria tie.
    std::vector<UpstreamH2Connection*> CollectUsableForUpstream(
        const std::string& upstream_name);

    // Append a freshly Init()'d connection. Caller has already donated
    // the lease via UpstreamH2Connection::AdoptLease.
    void Insert(const std::string& upstream_name,
                std::unique_ptr<UpstreamH2Connection> conn);

    // Run the per-connection liveness Tick on every tracked connection.
    // Connections whose Tick returns false (PING timeout, session-fatal
    // error, GOAWAY drained) get FailAllStreams + erased. Caller must
    // already be on the partition's owning dispatcher thread.
    void TickAll(std::chrono::steady_clock::time_point now);

    // Extract the owning unique_ptr for `conn` out of the table.
    // Returns null if `conn` is not tracked. Used by
    // PoolPartition::MoveConnToPendingDestroy to hand ownership to the
    // post-recv-tick destroy stash without invoking the conn's dtor
    // inline (which would re-enter callbacks from within a recv
    // callback).
    std::unique_ptr<UpstreamH2Connection> Extract(UpstreamH2Connection* conn);

    // Move every tracked connection out of the table. Returned vector
    // owns the conns; the table is left empty. Used by
    // PoolPartition::InitiateShutdown to retire H2 sessions via
    // DestroyOnDispatcher on the partition's dispatcher thread so the
    // donated leases drop and the partition's outstanding_conns_
    // counter reaches zero before WaitForDrain times out.
    std::vector<std::unique_ptr<UpstreamH2Connection>> ExtractAll();

    // Same as ExtractAll but preserves the upstream-name key for each
    // entry. Used by PoolPartition::InitiateShutdown's graceful-drain
    // path to take ownership across the BeginShutdownDrain loop (whose
    // synchronous FlushSend can fire transport close-cb → FailAllStreams
    // → sink OnError → reentrant FindUsable → reap of expired entries
    // — destroying the unique_ptr the loop is still working through).
    // Caller re-inserts each entry under its preserved key after the
    // unsafe section completes; PollShutdownDrain then walks the
    // re-populated table normally.
    std::vector<std::pair<std::string, std::unique_ptr<UpstreamH2Connection>>>
        ExtractAllWithKeys();

    // Non-destructive snapshot of every tracked connection — returns raw
    // pointers in arbitrary upstream-bucket order, preserving per-bucket
    // insertion order. Lifetime contract: pointers are non-owning AND
    // are only safe to use on the dispatcher AND must be Extract'd with
    // a null-check (a concurrent reap chain may have moved the conn to
    // pending_destroy_h2_conns_ between snapshot and Extract). Used by
    // PoolPartition::InitiateShutdown's graceful-drain poll loop so
    // walk-and-erase iteration over by_upstream_ does not invalidate
    // its own iterators. Distinct from ExtractAll which is destructive.
    std::vector<UpstreamH2Connection*> CollectAll() const;

private:
    std::unordered_map<std::string,
        std::vector<std::unique_ptr<UpstreamH2Connection>>> by_upstream_;
};
