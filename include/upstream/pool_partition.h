#pragma once

#include "common.h"
#include "dispatcher.h"
#include "upstream/upstream_connection.h"
#include "upstream/upstream_lease.h"
#include "upstream/upstream_callbacks.h"
#include "upstream/h2_connection_table.h"
#include "upstream/host_port_key.h"
#include "config/server_config.h"
#include "net/dns_resolver.h"    // ResolvedEndpoint — held via atomic shared_ptr
#include <condition_variable>
#include <unordered_set>
// <memory>, <functional>, <deque>, <vector>, <chrono>, <atomic>, <mutex> provided by common.h

// Forward declaration
class TlsClientContext;

class PoolPartition {
public:
    // Checkout callback aliases — defined in upstream_callbacks.h,
    // aliased here for backward compatibility with existing call sites.
    using ReadyCallback = UPSTREAM_CALLBACKS_NAMESPACE::ReadyCallback;
    using ErrorCallback = UPSTREAM_CALLBACKS_NAMESPACE::ErrorCallback;

    // Checkout error codes
    // Success sentinel — emitted on the wait-queue admission path so
    // callers using the same int channel for outcome and error code
    // can disambiguate "admitted" from "rejected with code N".
    static constexpr int CHECKOUT_OK              =  0;
    static constexpr int CHECKOUT_POOL_EXHAUSTED  = -1;
    static constexpr int CHECKOUT_CONNECT_FAILED  = -2;
    static constexpr int CHECKOUT_CONNECT_TIMEOUT = -3;
    static constexpr int CHECKOUT_SHUTTING_DOWN   = -4;
    static constexpr int CHECKOUT_QUEUE_TIMEOUT   = -5;
    // Delivered to wait-queue waiters drained on a breaker trip by
    // DrainWaitQueueOnTrip. ProxyTransaction::OnCheckoutError maps
    // this to RESULT_CIRCUIT_OPEN so the queued client gets the same
    // circuit-open response a fresh requester would get.
    static constexpr int CHECKOUT_CIRCUIT_OPEN    = -6;
    // Wait queue rejected the enqueue at the MAX_WAIT_QUEUE_SIZE cap.
    // Used by EnqueueH2StreamSlotWaiter when the bounded queue is full
    // even after PurgeCancelledWaitEntries.
    static constexpr int CHECKOUT_QUEUE_FULL      = -7;

    PoolPartition(std::shared_ptr<Dispatcher> dispatcher,
                  const std::string& upstream_host, int upstream_port,
                  const std::string& sni_hostname,
                  std::shared_ptr<const NET_DNS_NAMESPACE::ResolvedEndpoint> resolved_endpoint,
                  const UpstreamPoolConfig& config,
                  std::shared_ptr<TlsClientContext> tls_ctx,
                  std::atomic<int64_t>& outstanding_conns,
                  std::atomic<int64_t>& inflight_leases,
                  std::atomic<bool>& manager_shutting_down,
                  std::mutex& drain_mtx,
                  std::condition_variable& drain_cv);
    ~PoolPartition();

    // Non-copyable, non-movable
    PoolPartition(const PoolPartition&) = delete;
    PoolPartition& operator=(const PoolPartition&) = delete;

    // Async checkout (dispatcher-thread-only, no locking).
    // NOTE: ready_cb or error_cb may be invoked synchronously before this
    // function returns (e.g., when a valid idle connection is available or
    // the pool is immediately exhausted). Callers must not hold any lock
    // that the callback itself might attempt to acquire.
    //
    // Optional `cancel_token`: a shared atomic flag the caller may set
    // to abort a queued checkout. The pool checks it on every pop and
    // also proactively sweeps the queue for cancelled entries when the
    // queue would otherwise reject a new CheckoutAsync for fullness.
    // Cancelled entries are dropped without firing any callback. This
    // prevents a burst of disconnected clients from filling the bounded
    // wait queue with dead waiters that would otherwise block live
    // requests with queue-full / queue-timeout errors.
    void CheckoutAsync(ReadyCallback ready_cb, ErrorCallback error_cb,
                       std::shared_ptr<std::atomic<bool>> cancel_token = nullptr);

    // Return a connection to the pool. Called by UpstreamLease destructor.
    void ReturnConnection(UpstreamConnection* conn);

    // Return an H2 stream slot to the partition. Alive tokens were
    // validated by the lease before this call.
    // TODO: dispatch DrainH2StreamWaitersForHost from the body so
    // queued H2_STREAM_SLOT waiters get admitted on slot release.
    void ReturnH2Stream(UpstreamH2Connection* h2_conn, int32_t stream_id,
                        std::shared_ptr<std::atomic<bool>> partition_alive,
                        std::shared_ptr<std::atomic<bool>> conn_alive);

    // Push an H2_STREAM_SLOT entry onto the wait queue. Called from
    // CheckoutAsync's H2-cold-start path and from H2 capacity-defer
    // sites.
    void EnqueueH2StreamSlotWaiter(
        const std::string& host, int port,
        ReadyCallback ready_cb, ErrorCallback error_cb,
        std::shared_ptr<std::atomic<bool>> cancel_token);

    // Walk wait_queue_, admit every H2_STREAM_SLOT entry targeting
    // (host, port) onto a usable H2 connection. Called by
    // UpstreamH2Connection::RunDeferredEraseWalk when a slot frees, and
    // by ALPN-h2-success paths once a fresh session is in h2_table_.
    void DrainH2StreamWaitersForHost(const std::string& host, int port);

    // Walk wait_queue_, fire `error_cb(connect_outcome)` for every
    // H2_STREAM_SLOT entry targeting (host, port). Called on
    // replacement-connect failure / ALPN-not-h2-under-prefer-always /
    // shutdown teardown of in-flight probes.
    void FailH2StreamSlotWaiters(const std::string& host, int port,
                                 int connect_outcome,
                                 const std::string& reason);

    // Extract `conn`'s owning unique_ptr from `h2_table_` and push onto
    // `pending_destroy_h2_conns_` for post-recv-tick destruction.
    // Called from OnGoawayReceived's GOAWAY-idle branch (no surviving
    // streams).
    void MoveConnToPendingDestroy(UpstreamH2Connection* conn);

    // Snapshot pending_destroy_h2_conns_ into a local vector, then
    // invoke `DestroyOnDispatcher` on each before letting the local
    // vector lapse. Called at the tail of the H2 recv chain
    // (HandleBytes post-flush) and from shutdown paths.
    void ReapPendingDestroyH2Conns();

    // Idempotent replacement-connect: skip if (host, port) already has
    // an in-flight probe in h2_connecting_conns_, an active session in
    // h2_table_, or the pool is at cap. Called from
    // OnGoawayReceived's GOAWAY-idle branch to start a fresh session
    // before existing waiters time out.
    void StartH2ReplacementConnect(const std::string& host, int port);

    // ALPN-h1 adoption: claim an H2 probe's transport for the H1 idle
    // pool. Called from OnH2ConnectHandshakeComplete's ALPN-h1 branch
    // under prefer="auto". Re-wires pool callbacks, marks the conn
    // idle, sets a far-future deadline, and pushes into idle_conns_.
    // outstanding_conns_ is NOT touched — the H2 probe already
    // accounted for it; ownership simply transfers.
    void AdoptAsH1Connection(std::unique_ptr<UpstreamConnection> conn);

    // Flip every H2_STREAM_SLOT waiter targeting (host, port) to
    // kind=ANY so the next ServiceWaitQueue idle-pop admits them from
    // the adopted H1 idle pool. Called after AdoptAsH1Connection.
    void ReclassifyH2WaitersToAny(const std::string& host, int port);

    // Evict expired idle connections. Called by timer handler.
    void EvictExpired();

    // Shutdown: close idle, reject new checkouts, force-close connecting.
    // Must run on the partition's dispatcher thread (mutates containers).
    void InitiateShutdown();

    // Cross-thread safe variant of InitiateShutdown: enqueues the work
    // onto the owning dispatcher, tracked by inflight_tasks_ so the
    // PoolPartition destructor blocks on completion. Guarded by alive_
    // so that if the partition is destroyed before the lambda runs, the
    // task is a no-op instead of a use-after-free on freed containers.
    // Called by UpstreamHostPool::InitiateShutdown from the stopper thread.
    void ScheduleInitiateShutdown();

    // Force-close all active connections. Called after drain timeout.
    // Must run on the partition's dispatcher thread.
    void ForceCloseActive();

    // Cross-thread safe variant: enqueues ForceCloseActive on the owning
    // dispatcher, tracked by inflight_tasks_ so ~PoolPartition blocks on
    // completion. Same pattern as ScheduleInitiateShutdown.
    void ScheduleForceCloseActive();

    // Drain the wait queue on a CLOSED → OPEN breaker trip.
    //
    // Every live waiter receives CHECKOUT_CIRCUIT_OPEN (mapped by
    // ProxyTransaction::OnCheckoutError to RESULT_CIRCUIT_OPEN, emitting
    // the §12.1 circuit-open response). Cancelled waiters are dropped
    // silently — the transaction already tore its side down via the
    // framework abort hook. Does NOT set shutting_down_ (this is a
    // transient drain, not a shutdown); the partition keeps its
    // connections for HALF_OPEN probing when the open window elapses.
    //
    // Dispatcher-thread-only. The breaker's transition callback fires
    // on the slice's owning dispatcher thread — the SAME dispatcher
    // that owns this partition (one slice ↔ one partition by
    // dispatcher_index). No enqueue needed.
    //
    // Rationale: without this drain, a queued waiter admitted by
    // ConsultBreaker just before the trip would wait out the full
    // `open_duration_ms` (up to 60s by default) before the pool's
    // queue timeout rejects it. That's a visible latency spike for
    // clients who are about to be served 503 anyway.
    void DrainWaitQueueOnTrip();

    bool IsShuttingDown() const {
        return shutting_down_.load(std::memory_order_acquire);
    }

    // Reload-time endpoint publication. Release-store; observable to any
    // subsequent atomic_load_explicit(acquire) in CreateNewConnection.
    // Callable from ANY thread (typically the reload thread holding
    // HttpServer::reload_mtx_).
    void StoreResolvedEndpoint(
        std::shared_ptr<const NET_DNS_NAMESPACE::ResolvedEndpoint> new_ep);

    // Acquire-load of the current resolved endpoint. Used by
    // UpstreamHostPool::UpdateResolvedEndpoint to read the old value
    // before swapping so it can compare for no-change short-circuit.
    std::shared_ptr<const NET_DNS_NAMESPACE::ResolvedEndpoint>
    LoadResolvedEndpoint() const {
        return std::atomic_load_explicit(&resolved_endpoint_,
                                         std::memory_order_acquire);
    }

    // Best-effort: schedule a one-shot dispatcher-thread task that closes
    // idle_conns_ entries whose captured_endpoint() matches old_ep. NO-OP
    // if old_ep is null or the partition is shutting down. Does NOT block;
    // cleanup runs via dispatcher_->EnQueue.
    void EnqueueIdleCleanupOnEndpointChange(
        std::shared_ptr<const NET_DNS_NAMESPACE::ResolvedEndpoint> old_ep);

    // Reload-time H2 sub-config commit. Release-store of the new snapshot;
    // observable to any subsequent atomic_load_explicit(acquire) on the
    // hot path. Callable from ANY thread (typically the reload thread
    // holding HttpServer::reload_mtx_). Passing null deliberately clears
    // the cache (used on enabled→false toggles).
    void ApplyHttp2ConfigCommit(
        std::shared_ptr<const Http2UpstreamConfig> snapshot);

    // Acquire-load of the current H2 snapshot. Returns null when no
    // commit has happened yet, or when the staged set explicitly
    // disabled H2 for this entry.
    std::shared_ptr<const Http2UpstreamConfig> LoadHttp2ConfigSnapshot() const {
        return std::atomic_load_explicit(&http2_config_snapshot_,
                                         std::memory_order_acquire);
    }

    // Acquire a usable H2 connection for `upstream_name`.
    //
    // Lease handover contract — three branches, three lifetimes:
    //
    //   reuse branch     (return non-null, fast path) → lease UNTOUCHED;
    //                      caller releases the lease back to the pool.
    //   construct branch (return non-null, slow path) → lease MOVED into
    //                      the new UpstreamH2Connection (donated). Pool
    //                      accounting follows the lease destructor when
    //                      the H2 connection retires. Caller's lease is
    //                      empty after the call.
    //   Init() failure   (return null)               → lease UNTOUCHED;
    //                      caller MUST decide what to do (fall back to
    //                      H1 with the same lease, retry, or release).
    //                      Defensive: never assume the failure branch
    //                      released the lease — it does not.
    //
    // Dispatcher-thread-only — runs on the same dispatcher as
    // ProxyTransaction since `dispatcher_index_` lines up.
    UpstreamH2Connection* AcquireH2Connection(
        const std::string& upstream_name, UpstreamLease& lease);

    // Pre-checkout fast path: returns a usable H2 session for
    // `upstream_name` if one already exists in the partition's H2 table
    // AND its transport matches the partition's currently-published
    // resolved_endpoint_. Returns null otherwise. Used by
    // ProxyTransaction::AttemptCheckout to bypass CheckoutAsync when a
    // multiplexed session is reusable — without this, with
    // pool.max_connections set near 1 the donated H2 transport
    // permanently occupies the only pool slot and subsequent requests
    // would queue forever instead of multiplexing onto the existing
    // session. Idempotent with AcquireH2Connection's reuse branch.
    // Lifetime is owned by the partition's H2 table; callers should
    // capture `conn->alive_token()` if they need destroy-safe access.
    // Dispatcher-thread-only.
    UpstreamH2Connection* FindUsableH2Connection(
        const std::string& upstream_name);

    // Stats (dispatcher-thread-only reads)
    size_t IdleCount() const { return idle_conns_.size(); }
    size_t ActiveCount() const { return active_conns_.size(); }
    size_t ConnectingCount() const { return connecting_conns_.size(); }
    size_t H2TableCount() const { return h2_table_.TotalConnections(); }
    size_t H2ConnectingCount() const { return h2_connecting_conns_.size(); }
    size_t TotalCount() const {
        // Multiplexed H2 sessions + in-flight H2 probes count against the
        // partition's max_connections cap. Draining / pending-destroy
        // entries are excluded — they no longer accept new work and
        // would otherwise prevent admission of their replacements.
        return idle_conns_.size() + active_conns_.size() +
               connecting_conns_.size() + h2_table_.TotalConnections() +
               h2_connecting_conns_.size();
    }
    size_t WaitQueueSize() const { return wait_queue_.size(); }

    // Non-owning observer of the owning dispatcher. Used by H2 conns
    // (via the partition back-pointer) to drive timer cleanup during
    // DestroyOnDispatcher's step 3.
    Dispatcher* dispatcher() const { return dispatcher_.get(); }

    // Test-only: the effective SNI string the partition forwards to
    // `TlsConnection` when it originates TLS to the upstream. Empty
    // means "no SNI sent" (TlsConnection skips
    // `SSL_set_tlsext_host_name` + `SSL_set1_host`). hostname-fallback ON, IP-literal-
    // fallback OFF — can be pinned by unit tests without spinning up
    // a real TLS handshake. Safe to call from any thread because
    // `sni_hostname_` is ctor-initialised and never mutated.
    const std::string& sni_hostname_for_testing() const {
        return sni_hostname_;
    }

private:
    std::shared_ptr<Dispatcher> dispatcher_;
    std::string upstream_host_;     // Original operator host (hostname OR literal). LOGGING ONLY — connect reads resolved_endpoint_.
    int upstream_port_;              // Original operator port. Logs / fallback SNI port.
    std::string sni_hostname_;       // Empty = use upstream_host_ for SNI
    UpstreamPoolConfig config_;
    std::shared_ptr<TlsClientContext> tls_ctx_;

    // C++17 note: `std::atomic_load_explicit(shared_ptr*)` is the
    // standard-compliant form. C++20 deprecates the free-function
    // overloads in favor of `std::atomic<std::shared_ptr<T>>`.
    std::shared_ptr<const NET_DNS_NAMESPACE::ResolvedEndpoint> resolved_endpoint_;

    // Atomic-snapshot of the per-partition H2 sub-config. Written by the
    // reload thread via ApplyHttp2ConfigCommit (release-store); read on
    // the hot path by the partition's dispatcher via
    // LoadHttp2ConfigSnapshot (acquire-load). Null when H2 is disabled
    // for this entry — observers skip the H2 path.
    std::shared_ptr<const Http2UpstreamConfig> http2_config_snapshot_;

    // Manager-owned drain coordination — partitions signal when empty
    std::atomic<int64_t>& outstanding_conns_;
    // Manager-owned: leases currently checked out. Bumped before
    // ready_cb is invoked with a fresh lease; decremented in
    // ReturnConnection when the lease's destructor releases.
    std::atomic<int64_t>& inflight_leases_;
    std::atomic<bool>& manager_shutting_down_;  // Set immediately by manager
    std::mutex& drain_mtx_;
    std::condition_variable& drain_cv_;

    // Idle connections (front = most recently used, LRU eviction from back)
    std::deque<std::unique_ptr<UpstreamConnection>> idle_conns_;

    // Connections currently checked out (pool retains ownership)
    std::vector<std::unique_ptr<UpstreamConnection>> active_conns_;

    // Connections in the process of connecting
    std::vector<std::unique_ptr<UpstreamConnection>> connecting_conns_;

    // Zombie connections: force-closed after drain timeout but kept alive
    // because outstanding UpstreamLease objects still hold raw pointers.
    // Cleaned up when leases release them via ReturnConnection.
    std::vector<std::unique_ptr<UpstreamConnection>> zombie_conns_;

    // Wait-queue discriminator.
    //   ANY: caller accepts the next available H1 idle connection OR a
    //        fresh H2 session — the CheckoutAsync default.
    //   H2_STREAM_SLOT: caller specifically wants an H2 stream slot on
    //        a session for host:port. ServiceWaitQueue's idle-pop branch
    //        must skip these entries; admission flows through
    //        DrainH2StreamWaitersForHost.
    enum class WaiterKind { ANY, H2_STREAM_SLOT };

    // Bounded wait queue
    struct WaitEntry {
        ReadyCallback ready_callback;
        ErrorCallback error_callback;
        std::chrono::steady_clock::time_point queued_at;
        // Optional cancel flag set by the caller (e.g. via
        // ProxyTransaction::Cancel) to short-circuit this entry. When
        // true, the pool drops the entry on pop and skips firing its
        // callbacks. Nullable — regular checkouts leave this empty.
        std::shared_ptr<std::atomic<bool>> cancel_token;
        WaiterKind kind = WaiterKind::ANY;
        // Populated when kind == H2_STREAM_SLOT for replacement-connect
        // targeting and DrainH2StreamWaitersForHost lookups. Ignored
        // when kind == ANY.
        std::string host;
        int port = 0;
    };
    std::deque<WaitEntry> wait_queue_;
    static constexpr size_t MAX_WAIT_QUEUE_SIZE = 256;

    // Helper: returns true if this entry's cancel token is set.
    static bool IsEntryCancelled(const WaitEntry& e) {
        return e.cancel_token && e.cancel_token->load(std::memory_order_acquire);
    }
    // Walk the wait queue and erase cancelled entries in-place.
    // Called by CheckoutAsync before rejecting on a full queue so a
    // burst of disconnected clients doesn't permanently consume slots.
    // Returns the number of entries removed.
    size_t PurgeCancelledWaitEntries();

    // Returns true when the connection's captured endpoint pointer
    // matches the partition's currently-published resolved_endpoint_.
    // Mismatch means a hostname-aware reload atomic-stored a new endpoint
    // after this connection was created — the keepalive is still bound
    // to the old IP and must not be handed back out.
    // resolved_endpoint_ never changes after construction,
    // so this check is a same-pointer compare and always true;
    // the wiring is in place for when reload-time endpoint replacement lands.
    bool ConnectionEndpointMatches(const UpstreamConnection& c) const;

    size_t partition_max_connections_;

    // Shared atomic flag cleared in destructor. Atomic because it's written
    // from the teardown thread and read from dispatcher lambdas.
    // Captured by deferred purge tasks via weak_ptr to detect partition
    // destruction and avoid use-after-free.
    std::shared_ptr<std::atomic<bool>> alive_ =
        std::make_shared<std::atomic<bool>>(true);

    // Count of dispatcher tasks that may dereference `this`. Incremented
    // BEFORE each EnQueue/EnQueueDeferred, decremented inside the lambda
    // on ALL return paths. Destructor waits for this to reach 0 before
    // returning, guaranteeing no lambda can access freed members.
    std::shared_ptr<std::atomic<int>> inflight_tasks_ =
        std::make_shared<std::atomic<int>>(0);

    // Multiplexed H2 sessions held by this partition. Keyed by upstream
    // service name. Populated by AcquireH2Connection on first H2 dispatch
    // for a given upstream and reused for the lifetime of each session
    // (until GOAWAY drains the streams or PING timeout closes it).
    H2ConnectionTable h2_table_;

    // Owned stash for H2 connection shells in TCP_CONNECTING /
    // TLS_HANDSHAKE state — not yet visible to FindUsable on
    // h2_table_. The keyset doubles as the in-flight-probe reservation
    // set: concurrent CheckoutAsync calls for the same (host, port)
    // dedup onto the existing probe by checking `.count(key) > 0`.
    // Promoted into h2_table_ on ALPN-h2 success; destroyed via
    // DestroyOnDispatcher on connect-fail / ALPN-h1-fallback / shutdown.
    std::unordered_map<HostPortKey,
        std::unique_ptr<UpstreamH2Connection>> h2_connecting_conns_;

    // H2 connections whose sessions are fully retired (GOAWAY drained
    // with no remaining active streams) and waiting for the post-recv
    // tick to invoke DestroyOnDispatcher on each. Holding them here —
    // rather than destroying inline — keeps nghttp2's stream-close
    // callbacks from re-entering a partially-destroyed conn from
    // inside the recv chain.
    std::vector<std::unique_ptr<UpstreamH2Connection>> pending_destroy_h2_conns_;

    // True when a self-rescheduling wait-queue purge chain is already
    // scheduled. Prevents spawning duplicate chains per queued waiter.
    // Cleared when the chain terminates (queue empty or shutdown).
    bool purge_chain_active_ = false;
    // Written by InitiateShutdown (dispatcher thread); read by
    // EnqueueIdleCleanupOnEndpointChange (reload thread) — must be atomic.
    // Mirror of manager_shutting_down_ which is already std::atomic<bool>.
    std::atomic<bool> shutting_down_{false};

    // Internal helpers
    void CreateNewConnection(ReadyCallback ready_cb, ErrorCallback error_cb);
    void OnConnectComplete(UpstreamConnection* conn,
                           ReadyCallback ready_cb, ErrorCallback error_cb);
    void OnConnectionClosed(UpstreamConnection* conn);
    bool ValidateConnection(UpstreamConnection* conn);
    void ServiceWaitQueue();
    void PurgeExpiredWaitEntries();

    // Initiate a fresh H2 connect probe to (host, port). Mirrors
    // CreateNewConnection for the TCP/TLS connect machinery but wires
    // a TLS handshake-complete hook that resolves the ALPN outcome and
    // calls OnH2ConnectHandshakeComplete. Pre-condition: caller has
    // already gated on cap (TotalCount() < partition_max_connections_)
    // and shutdown, AND verified `h2_connecting_conns_.count(key)==0`
    // to avoid duplicate probes. TLS is required (h2c is not supported
    // for cold-start probes); returns false if tls_ctx_ is null.
    bool OpenNewH2Connection(const std::string& host, int port);

    // ALPN-resolve state machine. Called from the H2 shell's transport
    // handshake-complete / close / error callbacks. `outcome` is one of
    // the CHECKOUT_* sentinels (OK on TLS-handshake-success; FAILED /
    // TIMEOUT / SHUTTING_DOWN on the failure paths). `alpn` is the
    // negotiated ALPN string on the success path, empty on failure.
    void OnH2ConnectHandshakeComplete(const std::string& host, int port,
                                      int outcome,
                                      const std::string& alpn);


    // Dispatcher-thread-only: close idle connections that captured old_ep.
    // Called from EnqueueIdleCleanupOnEndpointChange's enqueued task.
    void CloseIdleMatchingEndpointOnDispatcher(
        const std::shared_ptr<const NET_DNS_NAMESPACE::ResolvedEndpoint>& old_ep);
    // Create new connections for queued waiters after a pool slot opens.
    // Loops while capacity is available and waiters remain. Checks alive_
    // after each callback (user callbacks may tear down the partition).
    void CreateForWaiters();
    void ScheduleWaitQueuePurge();
    void DestroyConnection(std::unique_ptr<UpstreamConnection> conn);

    // Re-wire pool-owned close/error callbacks on a connection's transport.
    // Called when returning a connection to idle — borrowers may have
    // overwritten the callbacks during their request.
    void WirePoolCallbacks(UpstreamConnection* conn);

    // Install the multiplexed-H2-session transport callbacks (OnMessage,
    // Close, Error, WriteProgress, Completion). Both the in-place promotion
    // path (AcquireH2Connection) and the cold-start probe-success path
    // (OnH2ConnectHandshakeComplete ALPN-h2 branch) must wire these
    // BEFORE Init() — Init's preface flush can fire the completion
    // callback synchronously on a writable transport.
    void WireH2SessionTransportCallbacks(UpstreamConnection* up,
                                         UpstreamH2Connection* raw);

    // Increment inflight_tasks_ and return an RAII guard that decrements it
    // on destruction. Capture the returned shared_ptr into any lambda
    // enqueued on the dispatcher: if EnQueue accepts the lambda, the guard
    // fires when the lambda completes; if EnQueue drops the lambda (stopped
    // dispatcher), the lambda is destroyed without running and the guard
    // still fires. Either way, exactly one decrement per increment.
    // The destructor's wait-for-zero loop uses this counter as its barrier.
    std::shared_ptr<void> MakeInflightGuard();

    // Find and extract a unique_ptr from a container by raw pointer
    std::unique_ptr<UpstreamConnection> ExtractFromIdle(UpstreamConnection* conn);
    std::unique_ptr<UpstreamConnection> ExtractFromActive(UpstreamConnection* conn);
    std::unique_ptr<UpstreamConnection> ExtractFromConnecting(UpstreamConnection* conn);

    // Signal drain completion if shutting down and all connections closed
    void MaybeSignalDrain();
};
