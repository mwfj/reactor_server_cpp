#include "upstream/upstream_manager.h"
#include "tls/tls_client_context.h"
#include "log/logger.h"

#include <openssl/ssl.h>

UpstreamManager::UpstreamManager(
    const std::vector<UpstreamConfig>& upstreams,
    const std::vector<std::shared_ptr<Dispatcher>>& dispatchers)
    : dispatchers_(dispatchers)
{
    for (const auto& upstream : upstreams) {
        // Create TLS context if enabled
        std::shared_ptr<TlsClientContext> tls_ctx;
        if (upstream.tls.enabled) {
            try {
                tls_ctx = std::make_shared<TlsClientContext>(
                    upstream.tls.ca_file, upstream.tls.verify_peer);

                // Set minimum TLS version
                if (upstream.tls.min_version == "1.3") {
                    tls_ctx->SetMinProtocolVersion(TLS1_3_VERSION);
                }
                // Default 1.2 is already set in TlsClientContext constructor

                // Set ALPN for HTTP/1.1 (HTTP/2 upstream deferred)
                tls_ctx->SetAlpnProtocols({"http/1.1"});

                tls_contexts_[upstream.name] = tls_ctx;
                logging::Get()->info("TLS client context created for upstream '{}'",
                                     upstream.name);
            } catch (const std::exception& e) {
                logging::Get()->error("Failed to create TLS context for "
                                      "upstream '{}': {}", upstream.name,
                                      e.what());
                throw;
            }
        }

        // Create the host pool
        pools_[upstream.name] = std::make_unique<UpstreamHostPool>(
            upstream.name, upstream.host, upstream.port,
            upstream.pool, dispatchers, tls_ctx,
            outstanding_conns_, drain_cv_);
    }

    logging::Get()->info("UpstreamManager initialized with {} upstream(s)",
                         pools_.size());
}

UpstreamManager::~UpstreamManager() {
    logging::Get()->debug("UpstreamManager destroyed");
}

void UpstreamManager::CheckoutAsync(
    const std::string& service_name,
    size_t dispatcher_index,
    PoolPartition::ReadyCallback ready_cb,
    PoolPartition::ErrorCallback error_cb) {

    auto it = pools_.find(service_name);
    if (it == pools_.end()) {
        logging::Get()->error("Unknown upstream service: '{}'", service_name);
        error_cb(PoolPartition::CHECKOUT_CONNECT_FAILED);
        return;
    }

    auto* partition = it->second->GetPartition(dispatcher_index);
    if (!partition) {
        error_cb(PoolPartition::CHECKOUT_CONNECT_FAILED);
        return;
    }

    partition->CheckoutAsync(std::move(ready_cb), std::move(error_cb));
}

void UpstreamManager::EvictExpired(size_t dispatcher_index) {
    for (auto& [name, pool] : pools_) {
        auto* partition = pool->GetPartition(dispatcher_index);
        if (partition) {
            partition->EvictExpired();
        }
    }
}

void UpstreamManager::InitiateShutdown() {
    logging::Get()->info("UpstreamManager initiating shutdown");
    for (auto& [name, pool] : pools_) {
        pool->InitiateShutdown();
    }
}

void UpstreamManager::WaitForDrain(std::chrono::seconds timeout) {
    auto deadline = std::chrono::steady_clock::now() + timeout;
    std::unique_lock<std::mutex> lck(drain_mtx_);
    drain_cv_.wait_until(lck, deadline, [this]() {
        return outstanding_conns_.load(std::memory_order_acquire) <= 0;
    });

    if (!AllDrained()) {
        logging::Get()->warn("Upstream drain timeout, {} connections remaining",
                             outstanding_conns_.load(std::memory_order_relaxed));
        lck.unlock();
        ForceCloseRemaining();
    }
}

bool UpstreamManager::AllDrained() const {
    return outstanding_conns_.load(std::memory_order_acquire) <= 0;
}

void UpstreamManager::ForceCloseRemaining() {
    logging::Get()->warn("Force-closing remaining upstream connections");
    // Each pool's partitions need to be shut down on their dispatcher thread.
    // InitiateShutdown() already enqueued — remaining are active connections
    // that haven't been returned yet. Force their transport close.
    for (auto& [name, pool] : pools_) {
        for (size_t i = 0; i < pool->partition_count(); ++i) {
            auto* partition = pool->GetPartition(i);
            if (partition && !partition->IsShuttingDown()) {
                dispatchers_[i]->EnQueue([partition]() {
                    partition->InitiateShutdown();
                });
            }
        }
    }
}

bool UpstreamManager::HasUpstream(const std::string& service_name) const {
    return pools_.find(service_name) != pools_.end();
}
