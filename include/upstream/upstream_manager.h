#pragma once

#include "common.h"
#include "upstream/upstream_host_pool.h"
#include "upstream/pool_partition.h"
#include "config/server_config.h"
#include "net/dns_resolver.h"
// <memory>, <unordered_map>, <atomic>, <mutex>, <optional>, <condition_variable> provided by common.h

class TlsClientContext;

namespace CIRCUIT_BREAKER_NAMESPACE {
class CircuitBreakerManager;
}

namespace OBSERVABILITY_NAMESPACE {
class ObservabilityManager;
}

class UpstreamManager {
public:
    // PRODUCTION ctor: resolved endpoints are provided by
    // the caller — `HttpServer::MarkServerReady` passes
    // `HttpServer::upstream_resolved_`, which `HttpServer::Start`
    // populated via the DNS batch. The partitions use the resolved IP
    // for connect; hostnames stay in upstream.host for logging /
    // effective-SNI derivation
    UpstreamManager(const std::vector<UpstreamConfig>& upstreams,
                    const std::vector<std::shared_ptr<Dispatcher>>& dispatchers,
                    NET_DNS_NAMESPACE::ResolvedMap resolved);

    // LEGACY ctor: for unit tests and embedders that
    // don't route through DnsResolver. Auto-fills the resolved map by
    // parsing each `config.host` as a bare IP literal (after
    // Normalize-style bracket stripping). Throws invalid_argument on
    // the FIRST non-literal host — callers with hostnames must use the
    // 3-arg ctor with a map produced by `DnsResolver::ResolveMany`.
    //
    // Delegates to the 3-arg ctor so both paths share the same
    // partition-construction code.
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
    // milliseconds resolution so HttpServer::Stop's single-deadline
    // budget can pass sub-second residuals without rounding-up to the
    // next full second (which would defeat the hard-cap contract).
    // Callers passing chrono::seconds get implicit conversion (no API
    // break for the test suites).
    void WaitForDrain(std::chrono::milliseconds timeout);

    // Non-blocking check: true if outstanding_conns_ == 0.
    bool AllDrained() const;

    // ---- Counters consumed by the shutdown drain predicate ----
    //
    // active_leases — UpstreamConnection leases currently held by
    //   callers (not yet returned). Tracked separately from
    //   outstanding_conns_ so the drain predicate doesn't wait on
    //   IDLE keep-alive sockets sitting in the pool — those have no
    //   in-flight request behind them and would block the
    //   observability shutdown drain until the idle timeout fires.
    //   Bumped by PoolPartition right before handing out a lease;
    //   decremented by ReturnConnection when the lease is released.
    //
    // inflight_transactions — ProxyTransactions that entered Start()
    //   but haven't reached terminal completion. Independent of
    //   active_leases (a transaction can be queued or awaiting a
    //   circuit-breaker decision before holding a lease) and bumped
    //   by ProxyTransaction directly.
    int64_t active_leases() const noexcept {
        return inflight_leases_.load(std::memory_order_acquire);
    }
    int64_t donated_h2_leases() const noexcept {
        return donated_h2_leases_.load(std::memory_order_acquire);
    }
    // Count of `UpstreamLease::Release()` calls that observed an
    // off-dispatcher invocation and skipped the partition mutation.
    // Each increment represents a leaked inflight/donated counter
    // bump that the drain predicate will never observe — operator
    // signal that shutdown drain risks wedging until timeout. Should
    // remain zero in healthy production; bumps surface via /stats.
    //
    // The counter is heap-owned (shared_ptr<atomic>) so it outlives
    // the partition: an off-dispatcher Release reaching for the
    // counter via the lease's captured shared_ptr is safe even when
    // the partition is concurrently destructing. See UpstreamLease.
    int64_t off_dispatcher_release_drops() const noexcept {
        return off_dispatcher_release_drops_ptr_->load(
            std::memory_order_acquire);
    }

#ifdef REACTOR_BUILDING_TESTS
    // Test-only: adjust the lease counters by signed deltas. Tests that
    // exercise the swap helper in isolation use this to restore a clean
    // baseline before the manager destructor checks invariants.
    // Compile-only-in-test-builds (Makefile -DREACTOR_BUILDING_TESTS on
    // the test_runner target); production code cannot reference this
    // symbol because it isn't declared in the production build.
    void RebalanceCountersForTesting_DO_NOT_USE_IN_PRODUCTION(
        int64_t inflight_delta, int64_t donated_delta) noexcept {
        inflight_leases_.fetch_add(inflight_delta,
                                   std::memory_order_acq_rel);
        donated_h2_leases_.fetch_add(donated_delta,
                                     std::memory_order_acq_rel);
    }
#endif
    int64_t inflight_transactions() const noexcept {
        return inflight_transactions_.load(std::memory_order_acquire);
    }
    // Drain mutex/cv accessors for HttpServer::WaitForAllAsyncDrain.
    // NOTE: drain_cv_ is signaled by PoolPartition::MaybeSignalDrain
    // ONLY when shutting_down_ is set AND outstanding_conns_ has
    // dropped to zero (the final transition). DecInflightTransactions
    // is a silent atomic with no notify. Callers waiting on this cv
    // MUST pair it with a periodic re-check timer; the cv alone is
    // an opportunistic short-circuit for the final zero-crossing,
    // not a per-event wake.
    std::mutex& drain_mtx() noexcept { return drain_mtx_; }
    std::condition_variable& drain_cv() noexcept { return drain_cv_; }
    void IncInflightTransactions() noexcept {
        inflight_transactions_.fetch_add(1, std::memory_order_acq_rel);
    }
    void DecInflightTransactions() noexcept {
        inflight_transactions_.fetch_sub(1, std::memory_order_acq_rel);
    }

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

    // Reload-time endpoint refresh. Synchronous on the caller's thread.
    // Iterates every entry in `merged` and, for the matching pool's
    // partitions, performs a release-store on resolved_endpoint_. Returns
    // ONLY after every partition for every matching service has been
    // published. Entries in `merged` with no matching pool are ignored.
    // Called by HttpServer::Reload while holding reload_mtx_.
    void UpdateResolvedEndpoints(
        const NET_DNS_NAMESPACE::ResolvedMap& merged);

    // Reload-time enumerator: pairs every live PoolPartition with its
    // upstream service name. Pointers stay valid until UpstreamManager
    // destruction (pools_ is built once at ctor and never modified).
    struct LivePartitionRef {
        std::string upstream_name;
        PoolPartition* partition;
    };
    std::vector<LivePartitionRef> LivePartitions() const;

    // Smallest cadence-relevant upstream timeout across all entries, or
    // INT_MAX when no upstream contributes. Folds connect_timeout_ms,
    // pool.idle_timeout_sec, proxy.response_timeout_ms, and the per-
    // upstream H2 timer block (see Http2UpstreamConfig::MinCadenceSec).
    // Used at the three dispatcher-cadence narrow sites (Initialize,
    // HttpServer::MarkServerReady, HttpServer::Reload) — narrow only,
    // never widen.
    static int ComputeMinUpstreamCadenceSec(
        const std::vector<UpstreamConfig>& upstreams);

    // Per-upstream H2 snapshot commit pipeline. For each live partition,
    // resolve the matching staged Http2UpstreamConfig and release-store
    // it via PoolPartition::ApplyHttp2ConfigCommit. Live partitions
    // missing from the staged set keep their existing snapshot
    // (conservative narrow). Build the staged map once, then look up
    // each partition by name in O(1). Safe to call from any thread —
    // each partition's commit is an atomic_store on shared_ptr, and
    // pools_ is build-once at ctor. Used by HttpServer::MarkServerReady
    // for initial bootstrap and HttpServer::Reload for live propagation.
    void CommitHttp2Snapshots(
        const std::vector<UpstreamConfig>& upstreams);

    // Read access to the per-upstream TLS client context. Returns null
    // when the upstream is plaintext (no TLS) or when the name is
    // unknown. Exposed for tests / diagnostics — production code uses
    // PoolPartition's stored shared_ptr directly. Safe from any thread:
    // tls_contexts_ is populated at construction and never mutated.
    std::shared_ptr<TlsClientContext> GetTlsContextForUpstream(
        const std::string& upstream_name) const {
        auto it = tls_contexts_.find(upstream_name);
        return it == tls_contexts_.end() ? nullptr : it->second;
    }

    // Install a non-owning pointer to the server's ObservabilityManager.
    // Called once from HttpServer::MarkServerReady after both managers are
    // constructed. Forwards into every existing PoolPartition so pool
    // gauge / histogram emits can begin. Pre-call, partitions skip emits
    // (obs_manager_ stays null). Lifetime: in HttpServer's declaration
    // order, observability_manager_ is declared AFTER upstream_manager_
    // (~line 600 vs ~line 551 in include/http/http_server.h), so
    // reverse-destruction destroys observability_manager_ FIRST. The
    // production path is safe because ~HttpServer calls Stop() first;
    // Stop() drives InitiateShutdown while obs is still alive. In abnormal
    // teardown paths (mid-startup exception, test fixtures that drop the
    // server without Stop()), PoolPartition's safety-net dtor nulls
    // obs_manager_ before any emit — see PoolPartition::~PoolPartition.
    void SetObservabilityManager(
        OBSERVABILITY_NAMESPACE::ObservabilityManager* obs_manager) noexcept;

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

    // Non-owning pointer to the observability manager, installed by
    // HttpServer::MarkServerReady. Forwarded into every PoolPartition.
    // No atomic — set once on dispatcher-aware initialization before any
    // partition-side gauge emit runs. Default null — observability is
    // an opt-in layer.
    OBSERVABILITY_NAMESPACE::ObservabilityManager* obs_manager_ = nullptr;

    // Non-owning pointer to the circuit-breaker manager, installed by
    // HttpServer::MarkServerReady after both managers exist. Atomic so
    // late-arriving hot-path reads in ProxyTransaction see either a
    // coherent pointer or nullptr (never torn). Owned by HttpServer;
    // lifetime outlives UpstreamManager (breaker destructs first —
    // §3.1 ownership). Default nullptr — breaker is an opt-in layer.
    std::atomic<CIRCUIT_BREAKER_NAMESPACE::CircuitBreakerManager*> breaker_manager_{nullptr};

    // Manager-owned atomic counter: total outstanding connections
    // (active + idle keep-alive). Used by ~UpstreamManager's
    // teardown wait — observability shutdown reads inflight_leases_
    // instead so an idle pool doesn't stall the drain.
    std::atomic<int64_t> outstanding_conns_{0};

    // Leases currently checked out by callers. Bumped by
    // PoolPartition before invoking ready_cb with a fresh lease;
    // decremented in PoolPartition::ReturnConnection when the
    // lease's destructor returns the connection. Distinct from
    // outstanding_conns_ which counts all live connections (idle
    // keep-alive sockets included).
    //
    // Per-request only — H2 donated leases are tracked separately in
    // donated_h2_leases_. UpstreamH2Connection::AdoptLease converts
    // the +1 from inflight_leases_ to donated_h2_leases_; the drain
    // predicate in HttpServer::WaitForAllAsyncDrain consults only
    // inflight_leases_ so idle H2 sessions do not stall observability
    // flush.
    std::atomic<int64_t> inflight_leases_{0};

    // Long-lived H2 session ownership of donated transports. Each
    // multiplexed H2 session holds one donated lease for its entire
    // lifetime; this counter rises on AdoptLease (in
    // AcquireH2Connection construct branch and
    // OnH2ConnectHandshakeComplete) and falls when the lease destructor
    // routes ReturnConnection with the donated flag set. Excluded from
    // the shutdown drain predicate — otherwise an idle H2 session keeps
    // the active_leases counter positive and observability flush burns
    // its full budget waiting for the lease that only releases when
    // InitiateShutdown explicitly retires the session.
    std::atomic<int64_t> donated_h2_leases_{0};

    // Off-dispatcher Release safety counter. Each increment indicates a
    // single leaked inflight/donated bump (Release skipped the partition
    // mutation to avoid container races). Operators monitor via /stats;
    // a non-zero value means shutdown drain may wedge until timeout
    // OR /stats active_leases reports stale.
    //
    // Heap-owned via shared_ptr so every UpstreamLease can capture it at
    // construction. The lease's captured shared_ptr keeps the atomic
    // alive even if the partition is destroyed mid-Release, which
    // eliminates the partition-deref race that a reference-typed
    // counter would have. The manager keeps the only strong reference
    // here for the manager-level accessor; partitions and leases each
    // hold their own copies and contribute to the refcount.
    std::shared_ptr<std::atomic<int64_t>> off_dispatcher_release_drops_ptr_ =
        std::make_shared<std::atomic<int64_t>>(0);

    // Bumped from ProxyTransaction::Start, decremented at terminal
    // completion. Read by HttpServer::WaitForAllAsyncDrain alongside
    // active_leases.
    std::atomic<int64_t> inflight_transactions_{0};

    std::mutex drain_mtx_;
    std::condition_variable drain_cv_;
};
