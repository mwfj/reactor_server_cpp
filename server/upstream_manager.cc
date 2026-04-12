#include "upstream/upstream_manager.h"
#include "tls/tls_client_context.h"
#include "log/logger.h"

#include <openssl/ssl.h>
#include <signal.h>
#include <limits>

// Convert a timeout in milliseconds to a DISPATCHER TIMER CADENCE in
// whole seconds. Sub-2s timeouts clamp to 1s (instead of rounding up
// to 2s) so that ms-based upstream timeouts get 1s resolution as
// documented — a 1100ms deadline rounded to 2s cadence would be
// checked only every 2s, firing up to ~0.9s late. Promotes to int64_t
// to avoid signed overflow on INT_MAX-range operator typos. Saturates
// to INT_MAX and returns at least 1. Mirrors the helper in
// http_server.cc — keep them in sync.
static int CadenceSecFromMs(int ms) {
    if (ms <= 0) return 1;
    if (ms < 2000) return 1;
    int64_t sec64 = (static_cast<int64_t>(ms) + 999) / 1000;
    if (sec64 > std::numeric_limits<int>::max()) {
        return std::numeric_limits<int>::max();
    }
    return static_cast<int>(sec64);
}

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
    // 60s), making connect_timeout_ms / idle_timeout_sec / proxy
    // response_timeout_ms fire tens of seconds late.
    // HttpServer::MarkServerReady does this for production; this covers
    // standalone UpstreamManager usage (see HttpServer::MarkServerReady
    // for the mirrored logic).
    int min_upstream_sec = std::numeric_limits<int>::max();
    for (const auto& u : upstreams) {
        int connect_sec = CadenceSecFromMs(u.pool.connect_timeout_ms);
        min_upstream_sec = std::min(min_upstream_sec, connect_sec);
        if (u.pool.idle_timeout_sec > 0) {
            min_upstream_sec = std::min(min_upstream_sec, u.pool.idle_timeout_sec);
        }
        // Proxy response timeout: also drives timer scan cadence when
        // ProxyTransaction::ArmResponseTimeout sets a deadline on the
        // transport. Without folding this in, a configured
        // proxy.response_timeout_ms can still fire at the default ~60s
        // cadence instead of its configured budget.
        if (u.proxy.response_timeout_ms > 0) {
            int response_sec = CadenceSecFromMs(u.proxy.response_timeout_ms);
            min_upstream_sec = std::min(min_upstream_sec, response_sec);
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

    // Periodic eviction: In production, HttpServer wires EvictExpired via
    // the NetServer timer callback chain. For standalone use, the caller
    // must call EvictExpired periodically (or rely on inline purges from
    // CheckoutAsync/ReturnConnection/ServiceWaitQueue). The timer interval
    // adjustment above ensures deadline-based timeouts fire promptly.
    // Queue timeouts are handled by ScheduleWaitQueuePurge (deferred task).

    logging::Get()->info("UpstreamManager initialized with {} upstream(s)",
                         pools_.size());
}

UpstreamManager::~UpstreamManager() {
    // Safety net: ensure shutdown is initiated before destruction.
    if (!shutting_down_.load(std::memory_order_acquire)) {
        InitiateShutdown();
    }

    // The old 500ms best-effort barrier here has been removed: PoolPartition
    // now schedules its own InitiateShutdown via inflight_tasks_-tracked
    // enqueue, and ~PoolPartition blocks on inflight_tasks_ unconditionally.
    // That gives us a hard guarantee that every queued shutdown lambda has
    // either executed or been dropped (RAII guard decrement) before pools_
    // is destroyed, eliminating the standalone UAF/hang race.

    // Block until every outstanding connection (including checked-out leases
    // and zombies held by leases) has been released. UpstreamLease stores a
    // raw PoolPartition* and a raw UpstreamConnection*; destroying the pools
    // while a lease is still live leaves those pointers dangling. Even the
    // alive_ guard in UpstreamLease::Release only covers the partition —
    // reads like lease->fd() still dereference the freed connection.
    //
    // In production (HttpServer::Stop) this wait is a no-op: the graceful
    // drain + WaitForDrain + ForceCloseRemaining sequence has already pushed
    // outstanding_conns_ to 0 (or moved active connections to zombies that
    // are then cleaned up when leases release). In standalone tests/helpers
    // the caller MUST release all leases before destroying the manager;
    // otherwise we block indefinitely (a fatal programming error at this
    // point — returning would cause UAF on later lease access). A periodic
    // warning log surfaces the leak without silently hanging.
    {
        std::unique_lock<std::mutex> lck(drain_mtx_);
        while (outstanding_conns_.load(std::memory_order_acquire) > 0) {
            if (drain_cv_.wait_for(lck, std::chrono::seconds(5),
                    [this]() {
                        return outstanding_conns_.load(std::memory_order_acquire) <= 0;
                    })) {
                break;
            }
            logging::Get()->warn(
                "~UpstreamManager blocked on {} outstanding lease(s); "
                "destructor cannot safely return until all leases are released",
                outstanding_conns_.load(std::memory_order_relaxed));
        }
    }
    logging::Get()->debug("UpstreamManager destroyed");
}

void UpstreamManager::CheckoutAsync(
    const std::string& service_name,
    size_t dispatcher_index,
    PoolPartition::ReadyCallback ready_cb,
    PoolPartition::ErrorCallback error_cb,
    std::shared_ptr<std::atomic<bool>> cancel_token) {

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

    partition->CheckoutAsync(std::move(ready_cb), std::move(error_cb),
                               std::move(cancel_token));
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
    // Route through ScheduleForceCloseActive so the enqueue is tracked by
    // the partition's inflight_tasks_ counter. Without this, the raw
    // partition* capture can outlive ~UpstreamManager in standalone usage
    // and dereference freed memory — the same race ScheduleInitiateShutdown
    // was introduced to close.
    for (auto& [name, pool] : pools_) {
        for (size_t i = 0; i < pool->partition_count(); ++i) {
            auto* partition = pool->GetPartition(i);
            if (partition) {
                partition->ScheduleForceCloseActive();
            }
        }
    }
}

Dispatcher* UpstreamManager::GetDispatcherForIndex(size_t index) const {
    if (index >= dispatchers_.size()) {
        logging::Get()->warn("GetDispatcherForIndex out of range: {} >= {}",
                             index, dispatchers_.size());
        return nullptr;
    }
    return dispatchers_[index].get();
}

bool UpstreamManager::HasUpstream(const std::string& service_name) const {
    return pools_.find(service_name) != pools_.end();
}
