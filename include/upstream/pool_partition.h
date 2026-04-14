#pragma once

#include "common.h"
#include "dispatcher.h"
#include "upstream/upstream_connection.h"
#include "upstream/upstream_lease.h"
#include "upstream/upstream_callbacks.h"
#include "config/server_config.h"
#include <condition_variable>
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

    PoolPartition(std::shared_ptr<Dispatcher> dispatcher,
                  const std::string& upstream_host, int upstream_port,
                  const std::string& sni_hostname,
                  const UpstreamPoolConfig& config,
                  std::shared_ptr<TlsClientContext> tls_ctx,
                  std::atomic<int64_t>& outstanding_conns,
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

    bool IsShuttingDown() const { return shutting_down_; }

    // Stats (dispatcher-thread-only reads)
    size_t IdleCount() const { return idle_conns_.size(); }
    size_t ActiveCount() const { return active_conns_.size(); }
    size_t ConnectingCount() const { return connecting_conns_.size(); }
    size_t TotalCount() const {
        return idle_conns_.size() + active_conns_.size() + connecting_conns_.size();
    }
    size_t WaitQueueSize() const { return wait_queue_.size(); }

private:
    std::shared_ptr<Dispatcher> dispatcher_;
    std::string upstream_host_;
    int upstream_port_;
    std::string sni_hostname_;  // Empty = use upstream_host_ for SNI
    UpstreamPoolConfig config_;
    std::shared_ptr<TlsClientContext> tls_ctx_;

    // Manager-owned drain coordination — partitions signal when empty
    std::atomic<int64_t>& outstanding_conns_;
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

    // True when a self-rescheduling wait-queue purge chain is already
    // scheduled. Prevents spawning duplicate chains per queued waiter.
    // Cleared when the chain terminates (queue empty or shutdown).
    bool purge_chain_active_ = false;
    bool shutting_down_ = false;

    // Internal helpers
    void CreateNewConnection(ReadyCallback ready_cb, ErrorCallback error_cb);
    void OnConnectComplete(UpstreamConnection* conn,
                           ReadyCallback ready_cb, ErrorCallback error_cb);
    void OnConnectionClosed(UpstreamConnection* conn);
    bool ValidateConnection(UpstreamConnection* conn);
    void ServiceWaitQueue();
    void PurgeExpiredWaitEntries();
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
