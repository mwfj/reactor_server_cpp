#pragma once

#include "common.h"
#include "dispatcher.h"
#include "upstream/upstream_connection.h"
#include "upstream/upstream_lease.h"
#include "config/server_config.h"
#include <condition_variable>
// <memory>, <functional>, <deque>, <vector>, <chrono>, <atomic>, <mutex> provided by common.h

// Forward declaration
class TlsClientContext;

class PoolPartition {
public:
    // Checkout callbacks — invoked on the dispatcher thread
    using ReadyCallback = std::function<void(UpstreamLease)>;
    using ErrorCallback = std::function<void(int error_code)>;

    // Checkout error codes
    static constexpr int CHECKOUT_POOL_EXHAUSTED  = -1;
    static constexpr int CHECKOUT_CONNECT_FAILED  = -2;
    static constexpr int CHECKOUT_CONNECT_TIMEOUT = -3;
    static constexpr int CHECKOUT_SHUTTING_DOWN   = -4;
    static constexpr int CHECKOUT_QUEUE_TIMEOUT   = -5;

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
    void CheckoutAsync(ReadyCallback ready_cb, ErrorCallback error_cb);

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
    };
    std::deque<WaitEntry> wait_queue_;
    static constexpr size_t MAX_WAIT_QUEUE_SIZE = 256;

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
