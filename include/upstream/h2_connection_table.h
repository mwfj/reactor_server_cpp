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
    // tracked connection can host a new stream right now.
    std::shared_ptr<UpstreamH2Connection> FindUsable(
        const std::string& upstream_name);

    // Append a freshly Init()'d connection. Caller has already donated
    // the lease via UpstreamH2Connection::AdoptLease.
    void Insert(const std::string& upstream_name,
                std::shared_ptr<UpstreamH2Connection> conn);

    // Run the per-connection liveness Tick on every tracked connection.
    // Connections whose Tick returns false (PING timeout, session-fatal
    // error, GOAWAY drained) get FailAllStreams + erased. Caller must
    // already be on the partition's owning dispatcher thread.
    void TickAll(std::chrono::steady_clock::time_point now);

private:
    std::unordered_map<std::string,
        std::vector<std::shared_ptr<UpstreamH2Connection>>> by_upstream_;
};
