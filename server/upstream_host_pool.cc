#include "upstream/upstream_host_pool.h"
#include "tls/tls_client_context.h"
#include "log/logger.h"

UpstreamHostPool::UpstreamHostPool(
    const std::string& service_name,
    const std::string& host, int port,
    const std::string& sni_hostname,
    const UpstreamPoolConfig& config,
    const std::vector<std::shared_ptr<Dispatcher>>& dispatchers,
    std::shared_ptr<TlsClientContext> tls_ctx,
    std::atomic<int64_t>& outstanding_conns,
    std::mutex& drain_mtx,
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

    // Distribute limits across partitions using floor division + remainder.
    // The first R partitions get floor+1, the rest get floor. This ensures
    // the aggregate never exceeds the configured global cap.
    // Example: max_connections=5 over 4 dispatchers → [2, 1, 1, 1] (sum=5).
    size_t total_conn = static_cast<size_t>(config.max_connections);
    size_t total_idle = static_cast<size_t>(config.max_idle_connections);
    size_t conn_floor = (num_dispatchers > 0) ? total_conn / num_dispatchers : total_conn;
    size_t conn_remainder = (num_dispatchers > 0) ? total_conn % num_dispatchers : 0;
    size_t idle_floor = (num_dispatchers > 0) ? total_idle / num_dispatchers : total_idle;
    size_t idle_remainder = (num_dispatchers > 0) ? total_idle % num_dispatchers : 0;

    for (size_t i = 0; i < num_dispatchers; ++i) {
        UpstreamPoolConfig partition_config = config;
        size_t per_partition = conn_floor + (i < conn_remainder ? 1 : 0);
        // Ensure at least 1 per partition: zero-capacity partitions cause
        // requests on that dispatcher to always fail (POOL_EXHAUSTED) since
        // checkout is dispatcher-affine with no cross-partition fallback.
        // When max_connections < num_dispatchers, this inflates the effective
        // cap. We log a warning below so operators know the actual limit.
        if (per_partition == 0) per_partition = 1;
        partition_config.max_connections = static_cast<int>(per_partition);

        size_t per_partition_idle = idle_floor + (i < idle_remainder ? 1 : 0);
        partition_config.max_idle_connections = static_cast<int>(per_partition_idle);

        partitions_.push_back(std::make_unique<PoolPartition>(
            dispatchers[i], host, port, sni_hostname, partition_config, tls_ctx,
            outstanding_conns, drain_mtx, drain_cv));
    }

    // Warn if effective cap exceeds configured cap due to per-partition minimum of 1
    size_t effective_total = 0;
    for (size_t i = 0; i < num_dispatchers; ++i) {
        size_t pp = conn_floor + (i < conn_remainder ? 1 : 0);
        if (pp == 0) pp = 1;
        effective_total += pp;
    }
    if (effective_total > total_conn) {
        logging::Get()->warn("UpstreamHostPool '{}': max_connections={} < {} workers, "
                             "effective cap inflated to {} (1 per partition minimum)",
                             service_name_, config.max_connections, num_dispatchers,
                             effective_total);
    }

    logging::Get()->info("UpstreamHostPool '{}' created for {}:{} with {} "
                         "partitions (max_conn={}, max_idle={})",
                         service_name_, host_, port_, num_dispatchers,
                         config.max_connections, config.max_idle_connections);
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
