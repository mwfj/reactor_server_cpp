#include "upstream/upstream_host_pool.h"
#include "tls/tls_client_context.h"
#include "log/logger.h"

UpstreamHostPool::UpstreamHostPool(
    const std::string& service_name,
    const std::string& host, int port,
    const UpstreamPoolConfig& config,
    const std::vector<std::shared_ptr<Dispatcher>>& dispatchers,
    std::shared_ptr<TlsClientContext> tls_ctx,
    std::atomic<int64_t>& outstanding_conns,
    std::condition_variable& drain_cv)
    : service_name_(service_name)
    , host_(host)
    , port_(port)
    , config_(config)
    , dispatchers_(dispatchers)
{
    // Create one partition per dispatcher
    size_t num_dispatchers = dispatchers.size();
    partitions_.reserve(num_dispatchers);

    // Per-partition connection limit = ceil(max_connections / num_dispatchers)
    size_t per_partition = (num_dispatchers > 0)
        ? (static_cast<size_t>(config.max_connections) + num_dispatchers - 1)
          / num_dispatchers
        : static_cast<size_t>(config.max_connections);

    for (size_t i = 0; i < num_dispatchers; ++i) {
        // Create a config copy with the per-partition limit
        UpstreamPoolConfig partition_config = config;
        partition_config.max_connections = static_cast<int>(per_partition);
        // Scale max_idle proportionally
        size_t per_partition_idle = (num_dispatchers > 0)
            ? (static_cast<size_t>(config.max_idle_connections) + num_dispatchers - 1)
              / num_dispatchers
            : static_cast<size_t>(config.max_idle_connections);
        // Ensure at least 1 idle per partition if configured
        if (config.max_idle_connections > 0 && per_partition_idle == 0) {
            per_partition_idle = 1;
        }
        partition_config.max_idle_connections = static_cast<int>(per_partition_idle);

        partitions_.push_back(std::make_unique<PoolPartition>(
            dispatchers[i], host, port, partition_config, tls_ctx,
            outstanding_conns, drain_cv));
    }

    logging::Get()->info("UpstreamHostPool '{}' created for {}:{} with {} "
                         "partitions (max_conn={} per partition)",
                         service_name_, host_, port_, num_dispatchers,
                         per_partition);
}

UpstreamHostPool::~UpstreamHostPool() {
    logging::Get()->debug("UpstreamHostPool '{}' destroyed", service_name_);
}

PoolPartition* UpstreamHostPool::GetPartition(size_t dispatcher_index) {
    if (dispatcher_index >= partitions_.size()) {
        logging::Get()->error("Invalid dispatcher index {} for pool '{}' "
                              "(partitions={})", dispatcher_index,
                              service_name_, partitions_.size());
        return nullptr;
    }
    return partitions_[dispatcher_index].get();
}

void UpstreamHostPool::InitiateShutdown() {
    for (size_t i = 0; i < partitions_.size(); ++i) {
        auto* partition = partitions_[i].get();
        dispatchers_[i]->EnQueue([partition]() {
            partition->InitiateShutdown();
        });
    }
}
