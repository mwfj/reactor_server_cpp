#pragma once

#include "common.h"
#include "upstream/upstream_host_pool.h"
#include "upstream/pool_partition.h"
#include "config/server_config.h"
#include <condition_variable>
// <memory>, <unordered_map>, <atomic>, <mutex> provided by common.h

class TlsClientContext;

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
    void CheckoutAsync(const std::string& service_name,
                       size_t dispatcher_index,
                       PoolPartition::ReadyCallback ready_cb,
                       PoolPartition::ErrorCallback error_cb);

    // Evict expired connections across all pools (called by timer handler)
    void EvictExpired(size_t dispatcher_index);

    // Initiate graceful shutdown of all pools.
    void InitiateShutdown();

    // Blocking wait for all upstream connections to close.
    void WaitForDrain(std::chrono::seconds timeout);

    // Non-blocking check: true if outstanding_conns_ == 0.
    bool AllDrained() const;

    // Force-close all remaining connections (enqueues to each dispatcher).
    void ForceCloseRemaining();

    // Check if an upstream service is configured
    bool HasUpstream(const std::string& service_name) const;

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

    // Manager-owned atomic counter: total outstanding connections
    std::atomic<int64_t> outstanding_conns_{0};

    std::mutex drain_mtx_;
    std::condition_variable drain_cv_;
};
