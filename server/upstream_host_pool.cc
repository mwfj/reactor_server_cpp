#include "upstream/upstream_host_pool.h"
#include "tls/tls_client_context.h"
#include "log/logger.h"

UpstreamHostPool::UpstreamHostPool(
    const std::string& service_name,
    const std::string& host, int port,
    const std::string& sni_hostname,
    std::shared_ptr<const NET_DNS_NAMESPACE::ResolvedEndpoint> resolved_endpoint,
    const UpstreamPoolConfig& config,
    const std::vector<std::shared_ptr<Dispatcher>>& dispatchers,
    std::shared_ptr<TlsClientContext> tls_ctx,
    std::atomic<int64_t>& outstanding_conns,
    std::atomic<bool>& manager_shutting_down,
    std::mutex& drain_mtx,
    std::condition_variable& drain_cv)
    : service_name_(service_name)
    , host_(host)
    , port_(port)
    , config_(config)
    , dispatchers_(dispatchers)
{
    if (!resolved_endpoint) {
        throw std::invalid_argument(
            "UpstreamHostPool '" + service_name +
            "': resolved_endpoint must not be null (see §5.5 step 9)");
    }
    // Create one partition per dispatcher
    size_t num_dispatchers = dispatchers.size();
    partitions_.reserve(num_dispatchers);

    // Guard against negative limits from direct API callers that bypass
    // ConfigLoader::Validate. The static_cast<size_t> below would wrap
    // -1 to SIZE_MAX, silently disabling pool bounds.
    if (config.max_connections < 0) {
        throw std::invalid_argument(
            "upstream '" + service_name + "': pool.max_connections (" +
            std::to_string(config.max_connections) + ") must not be negative");
    }
    if (config.max_idle_connections < 0) {
        throw std::invalid_argument(
            "upstream '" + service_name + "': pool.max_idle_connections (" +
            std::to_string(config.max_idle_connections) + ") must not be negative");
    }

    // Distribute limits across partitions using floor division + remainder.
    // The first R partitions get floor+1, the rest get floor. This ensures
    // the aggregate never exceeds the configured global cap.
    // Example: max_connections=5 over 4 dispatchers → [2, 1, 1, 1] (sum=5).
    //
    // When max_connections < num_dispatchers (e.g. default 64 on a 96-core
    // host), some partitions get 0 capacity. Requests dispatched to those
    // partitions queue and time out — a degraded but correct behavior that
    // respects the operator's configured backpressure limit. Silently
    // inflating the cap would defeat that limit and risk overloading the
    // upstream backend. A warning surfaces the mismatch so operators can
    // increase pool.max_connections if needed.
    size_t total_conn = static_cast<size_t>(config.max_connections);
    size_t total_idle = static_cast<size_t>(config.max_idle_connections);

    if (num_dispatchers > 0 && total_conn < num_dispatchers) {
        logging::Get()->warn(
            "upstream '{}': pool.max_connections ({}) < worker_threads ({}); "
            "{} dispatcher partition(s) will have zero capacity — increase "
            "pool.max_connections to at least {} for full coverage",
            service_name, total_conn, num_dispatchers,
            num_dispatchers - total_conn, num_dispatchers);
    }

    size_t conn_floor = (num_dispatchers > 0) ? total_conn / num_dispatchers : total_conn;
    size_t conn_remainder = (num_dispatchers > 0) ? total_conn % num_dispatchers : 0;
    size_t idle_floor = (num_dispatchers > 0) ? total_idle / num_dispatchers : total_idle;
    size_t idle_remainder = (num_dispatchers > 0) ? total_idle % num_dispatchers : 0;

    for (size_t i = 0; i < num_dispatchers; ++i) {
        UpstreamPoolConfig partition_config = config;
        size_t per_partition = conn_floor + (i < conn_remainder ? 1 : 0);
        partition_config.max_connections = static_cast<int>(per_partition);

        size_t per_partition_idle = idle_floor + (i < idle_remainder ? 1 : 0);
        partition_config.max_idle_connections = static_cast<int>(per_partition_idle);

        // All partitions share the same `resolved_endpoint` shared_ptr
        // at construction. Step 11's reload swap replaces each partition's
        // own copy independently — not the host-pool's. By-value capture
        // here hands each partition an already-refcount-held pointer so
        // destruction order within the pool doesn't matter.
        partitions_.push_back(std::make_unique<PoolPartition>(
            dispatchers[i], host, port, sni_hostname, resolved_endpoint,
            partition_config, tls_ctx,
            outstanding_conns, manager_shutting_down, drain_mtx, drain_cv));
    }


    logging::Get()->info("UpstreamHostPool '{}' created for {}:{} "
                         "(resolved={}:{}) with {} partitions "
                         "(max_conn={}, max_idle={})",
                         service_name_, host_, port_,
                         resolved_endpoint->addr.Ip(),
                         resolved_endpoint->addr.Port(),
                         num_dispatchers,
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
    // Route through PoolPartition::ScheduleInitiateShutdown so the enqueue
    // is tracked by the partition's inflight_tasks_ counter. The partition
    // destructor blocks on that counter before freeing containers, which
    // eliminates the standalone-teardown race where a queued InitiateShutdown
    // lambda could run after the partition had been freed.
    for (auto& partition : partitions_) {
        partition->ScheduleInitiateShutdown();
    }
}
