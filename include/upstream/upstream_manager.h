#pragma once

#include "common.h"
#include "upstream/upstream_host_pool.h"
#include "upstream/pool_partition.h"
#include "config/server_config.h"
#include <condition_variable>
// <memory>, <unordered_map>, <atomic>, <mutex> provided by common.h

class TlsClientContext;

namespace CIRCUIT_BREAKER_NAMESPACE {
class CircuitBreakerManager;
}

class UpstreamManager {
public:
    UpstreamManager(const std::vector<UpstreamConfig>& upstreams,
                    const std::vector<std::shared_ptr<Dispatcher>>& dispatchers);
    ~UpstreamManager();

    // Non-copyable, non-movable
    UpstreamManager(const UpstreamManager&) = delete;
    UpstreamManager& operator=(const UpstreamManager&) = delete;

    // Async checkout — delegates to the correct PoolPartition.
    // Must be called on the dispatcher thread identified by dispatcher_index.
    // `cancel_token` is an optional shared atomic flag. When set by the
    // caller (e.g. ProxyTransaction::Cancel on client disconnect), the
    // pool drops the queued waiter on pop and proactively sweeps it out
    // if the wait queue is full. See PoolPartition::CheckoutAsync for
    // the full semantics.
    void CheckoutAsync(const std::string& service_name,
                       size_t dispatcher_index,
                       PoolPartition::ReadyCallback ready_cb,
                       PoolPartition::ErrorCallback error_cb,
                       std::shared_ptr<std::atomic<bool>> cancel_token = nullptr);

    // Evict expired connections across all pools (called by timer handler)
    void EvictExpired(size_t dispatcher_index);

    // Initiate graceful shutdown of all pools.
    void InitiateShutdown();

    // Blocking wait for upstream connections to drain. On timeout, enqueues
    // ForceCloseActive which zombifies active connections but does NOT destroy
    // them (leases may still hold raw pointers). The manager must NOT be
    // destroyed until all dispatcher threads are joined — HttpServer::Stop()
    // ensures this by calling upstream_manager_.reset() after net_server_.Stop().
    void WaitForDrain(std::chrono::seconds timeout);

    // Non-blocking check: true if outstanding_conns_ == 0.
    bool AllDrained() const;

    // Force-close all remaining connections (enqueues to each dispatcher).
    void ForceCloseRemaining();

    // Get the dispatcher for the given index. Returns nullptr if index is
    // out of range. Used by ProxyTransaction to schedule delayed retries
    // on the correct dispatcher thread.
    Dispatcher* GetDispatcherForIndex(size_t index) const;

    // Check if an upstream service is configured
    bool HasUpstream(const std::string& service_name) const;

    // Look up the PoolPartition for (service_name, dispatcher_index).
    // Returns nullptr if service is unknown or dispatcher_index is out
    // of range. Used by the circuit-breaker transition callback (wired
    // in HttpServer::MarkServerReady) to drain the wait queue on a
    // CLOSED → OPEN trip. Must be called on the dispatcher thread
    // identified by `dispatcher_index` — the returned partition's
    // DrainWaitQueueOnTrip is dispatcher-thread-only.
    PoolPartition* GetPoolPartition(const std::string& service_name,
                                    size_t dispatcher_index);

    // Install a non-owning pointer to the server's CircuitBreakerManager.
    // Called once from HttpServer::MarkServerReady after both managers are
    // constructed (§3.1). Lifetime guarantee: the CircuitBreakerManager
    // is declared AFTER upstream_manager_ on HttpServer, so it destructs
    // FIRST — UpstreamManager never reads through a dangling pointer on
    // shutdown. Passing nullptr is allowed (detaches).
    void AttachCircuitBreakerManager(CIRCUIT_BREAKER_NAMESPACE::CircuitBreakerManager* mgr) {
        breaker_manager_.store(mgr, std::memory_order_release);
    }

    // Returns the attached breaker manager, or nullptr if no manager is
    // attached. Safe from any thread (atomic load, acquire so any
    // Attach-time publication is visible).
    CIRCUIT_BREAKER_NAMESPACE::CircuitBreakerManager* GetCircuitBreakerManager() const {
        return breaker_manager_.load(std::memory_order_acquire);
    }

private:
    // service_name → host pool. Built once at construction, never modified.
    std::unordered_map<std::string, std::unique_ptr<UpstreamHostPool>> pools_;

    // TLS contexts per upstream (shared with all partitions)
    std::unordered_map<std::string, std::shared_ptr<TlsClientContext>> tls_contexts_;

    // All dispatchers (for shutdown coordination)
    std::vector<std::shared_ptr<Dispatcher>> dispatchers_;

    // Set immediately by InitiateShutdown — checked by CheckoutAsync to
    // reject new checkouts before per-partition shutdown tasks execute.
    std::atomic<bool> shutting_down_{false};

    // Non-owning pointer to the circuit-breaker manager, installed by
    // HttpServer::MarkServerReady after both managers exist. Atomic so
    // late-arriving hot-path reads in ProxyTransaction see either a
    // coherent pointer or nullptr (never torn). Owned by HttpServer;
    // lifetime outlives UpstreamManager (breaker destructs first —
    // §3.1 ownership). Default nullptr — breaker is an opt-in layer.
    std::atomic<CIRCUIT_BREAKER_NAMESPACE::CircuitBreakerManager*> breaker_manager_{nullptr};

    // Manager-owned atomic counter: total outstanding connections
    std::atomic<int64_t> outstanding_conns_{0};

    std::mutex drain_mtx_;
    std::condition_variable drain_cv_;
};
