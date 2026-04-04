#include "upstream/upstream_manager.h"
#include "tls/tls_client_context.h"
#include "log/logger.h"

#include <openssl/ssl.h>
#include <signal.h>
#include <limits>

// Suppress SIGPIPE for TLS upstream connections. SSL_write uses the
// underlying socket's write() which bypasses MSG_NOSIGNAL. Without
// this, a peer reset during SSL_write kills the process.
// Safe to call multiple times — only overrides SIG_DFL.
static void SuppressSigpipe() {
    struct sigaction sa_cur{};
    sigaction(SIGPIPE, nullptr, &sa_cur);
    if (sa_cur.sa_handler == SIG_DFL) {
        struct sigaction sa_ign{};
        sa_ign.sa_handler = SIG_IGN;
        sigemptyset(&sa_ign.sa_mask);
        sigaction(SIGPIPE, &sa_ign, nullptr);
    }
}

UpstreamManager::UpstreamManager(
    const std::vector<UpstreamConfig>& upstreams,
    const std::vector<std::shared_ptr<Dispatcher>>& dispatchers)
    : dispatchers_(dispatchers)
{
    // Check if any upstream uses TLS — suppress SIGPIPE if so.
    // When used inside HttpServer/NetServer, SIGPIPE is already suppressed.
    // When used standalone (e.g., tests), this is the only protection.
    for (const auto& u : upstreams) {
        if (u.tls.enabled) {
            SuppressSigpipe();
            break;
        }
    }

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
            upstream.tls.sni_hostname,
            upstream.pool, dispatchers, tls_ctx,
            outstanding_conns_, shutting_down_, drain_mtx_, drain_cv_);
    }

    // Adjust dispatcher timer intervals for upstream timeout enforcement.
    // Without this, standalone dispatchers use their default interval (often
    // 60s), making connect_timeout_ms and idle_timeout_sec fire tens of
    // seconds late. HttpServer::MarkServerReady does this for production;
    // this covers standalone UpstreamManager usage.
    int min_upstream_sec = std::numeric_limits<int>::max();
    for (const auto& u : upstreams) {
        int connect_sec = std::max((u.pool.connect_timeout_ms + 999) / 1000, 1);
        min_upstream_sec = std::min(min_upstream_sec, connect_sec);
        if (u.pool.idle_timeout_sec > 0) {
            min_upstream_sec = std::min(min_upstream_sec, u.pool.idle_timeout_sec);
        }
    }
    if (min_upstream_sec < std::numeric_limits<int>::max()) {
        for (auto& disp : dispatchers_) {
            // Only narrow the interval, never widen. The dispatcher may
            // already have a shorter cadence from request_timeout_sec or
            // idle_timeout_sec (set by HttpServer before this runs).
            disp->EnQueue([disp, min_upstream_sec]() {
                int current = disp->GetTimerInterval();
                if (current <= 0 || min_upstream_sec < current) {
                    disp->SetTimerInterval(min_upstream_sec);
                }
            });
        }
    }

    // Wire periodic eviction via the timer callback on each dispatcher.
    // In HttpServer, NetServer already sets timeout_trigger_callback to
    // NetServer::Timeout which chains to HttpServer's timer_callback
    // (including EvictExpired). For standalone use, no such chain exists.
    // We use SetTimerCB (the Dispatcher's own periodic callback from
    // TimerHandler) which is only set to NetServer::RemoveConnection in
    // production — standalone dispatchers have it unset.
    // Note: SetTimerCB is for the dispatcher-internal timer, separate
    // from SetTimeOutTriggerCB. It fires from TimerHandler unconditionally.
    // Actually, SetTimerCB fires RemoveConnection(fd) with an int arg —
    // wrong signature. Use SetTimeOutTriggerCB instead but only for
    // standalone dispatchers.
    //
    // Practical solution: the timer interval adjustment above ensures
    // TimerHandler fires frequently. PurgeExpiredWaitEntries runs from
    // CheckoutAsync, ReturnConnection, ServiceWaitQueue, and EvictExpired.
    // The ScheduleWaitQueuePurge deferred task fires on the next idle
    // timeout. This is sufficient for production and near-sufficient for
    // standalone. Document the limitation for the pure-sustained-I/O edge case.

    logging::Get()->info("UpstreamManager initialized with {} upstream(s)",
                         pools_.size());
}

UpstreamManager::~UpstreamManager() {
    // Safety net: ensure shutdown is initiated and pools are drained before
    // destruction. In production (HttpServer), Stop() handles this explicitly.
    // In standalone use, the caller may not have called InitiateShutdown.
    if (!shutting_down_.load(std::memory_order_acquire)) {
        InitiateShutdown();
    }
    // Brief drain — give queued tasks a chance to complete. Dispatcher
    // threads must still be running for this to work; if they're already
    // stopped (HttpServer::~HttpServer after net_server_.Stop()), this
    // is a no-op and safe.
    static constexpr int DTOR_DRAIN_MS = 100;
    if (outstanding_conns_.load(std::memory_order_acquire) > 0) {
        std::unique_lock<std::mutex> lck(drain_mtx_);
        drain_cv_.wait_for(lck, std::chrono::milliseconds(DTOR_DRAIN_MS),
            [this]() {
                return outstanding_conns_.load(std::memory_order_acquire) <= 0;
            });
    }
    logging::Get()->debug("UpstreamManager destroyed");
}

void UpstreamManager::CheckoutAsync(
    const std::string& service_name,
    size_t dispatcher_index,
    PoolPartition::ReadyCallback ready_cb,
    PoolPartition::ErrorCallback error_cb) {

    // Reject immediately if shutdown has started — the per-partition
    // InitiateShutdown tasks may not have executed yet on all dispatchers.
    // Note: a narrow TOCTOU window exists where a handler reads false here,
    // then InitiateShutdown stores true on the stopper thread, and the
    // handler proceeds to create one last connection. This is acceptable:
    // the connection is cleaned up during the normal shutdown drain, and
    // closing the window would require a global mutex that serializes all
    // checkouts across all dispatchers, defeating the per-partition design.
    if (shutting_down_.load(std::memory_order_acquire)) {
        error_cb(PoolPartition::CHECKOUT_SHUTTING_DOWN);
        return;
    }

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
    // Set the atomic flag BEFORE enqueueing per-partition shutdown tasks.
    // CheckoutAsync checks this flag synchronously, preventing new checkouts
    // between the flag set and the per-partition InitiateShutdown execution.
    shutting_down_.store(true, std::memory_order_release);
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
        // Note: ForceCloseActive moves leased connections to zombie_conns_.
        // outstanding_conns_ stays positive until leases release. The manager
        // must outlive all dispatchers — HttpServer::Stop() ensures this by
        // calling net_server_.Stop() (which joins all threads) before
        // resetting upstream_manager_. See HttpServer::Stop() for the
        // explicit destruction ordering.
    }
}

bool UpstreamManager::AllDrained() const {
    return outstanding_conns_.load(std::memory_order_acquire) <= 0;
}

void UpstreamManager::ForceCloseRemaining() {
    logging::Get()->warn("Force-closing remaining upstream connections");
    // InitiateShutdown() was already called for all partitions. Active connections
    // that weren't returned before the drain timeout are still alive. Force-close
    // them by enqueuing ForceCloseActive() on each partition's dispatcher thread.
    for (auto& [name, pool] : pools_) {
        for (size_t i = 0; i < pool->partition_count(); ++i) {
            auto* partition = pool->GetPartition(i);
            if (partition) {
                dispatchers_[i]->EnQueue([partition]() {
                    partition->ForceCloseActive();
                });
            }
        }
    }
}

bool UpstreamManager::HasUpstream(const std::string& service_name) const {
    return pools_.find(service_name) != pools_.end();
}
