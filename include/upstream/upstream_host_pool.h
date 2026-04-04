#pragma once

#include "common.h"
#include "upstream/pool_partition.h"
#include "config/server_config.h"
// <memory>, <vector>, <string> provided by common.h

class TlsClientContext;

class UpstreamHostPool {
public:
    UpstreamHostPool(const std::string& service_name,
                     const std::string& host, int port,
                     const std::string& sni_hostname,
                     const UpstreamPoolConfig& config,
                     const std::vector<std::shared_ptr<Dispatcher>>& dispatchers,
                     std::shared_ptr<TlsClientContext> tls_ctx,
                     std::atomic<int64_t>& outstanding_conns,
                     std::atomic<bool>& manager_shutting_down,
                     std::mutex& drain_mtx,
                     std::condition_variable& drain_cv);
    ~UpstreamHostPool();

    // Non-copyable, non-movable
    UpstreamHostPool(const UpstreamHostPool&) = delete;
    UpstreamHostPool& operator=(const UpstreamHostPool&) = delete;

    // Get the partition for a specific dispatcher (by index)
    PoolPartition* GetPartition(size_t dispatcher_index);

    // Shutdown all partitions (enqueues to each dispatcher)
    void InitiateShutdown();

    const std::string& service_name() const { return service_name_; }
    const std::string& host() const { return host_; }
    int port() const { return port_; }
    size_t partition_count() const { return partitions_.size(); }

private:
    std::string service_name_;
    std::string host_;
    int port_;
    UpstreamPoolConfig config_;

    // One partition per dispatcher. Index matches dispatcher index.
    std::vector<std::unique_ptr<PoolPartition>> partitions_;
    // Keep dispatcher references for shutdown enqueue
    std::vector<std::shared_ptr<Dispatcher>> dispatchers_;
};
