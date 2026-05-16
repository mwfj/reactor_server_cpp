#include "upstream/pool_partition.h"
#include "upstream/upstream_lease.h"
#include "upstream/upstream_connection.h"
#include "upstream/upstream_h2_connection.h"
#include "upstream/proxy_transaction.h"   // for RESULT_UPSTREAM_DISCONNECT
#include "socket_handler.h"
#include "tls/tls_client_context.h"
#include "tls/tls_connection.h"
#include "log/logger.h"
#include "log/log_utils.h"
#include "observability/counter.h"
#include "observability/histogram.h"
#include "observability/metrics_catalog.h"
#include "observability/observability_manager.h"
#include <cassert>
#include <future>

// ── Shutdown-strand invariant ─────────────────────────────────────────
// ~PoolPartition's on_dispatcher lambda clears wait_queue_ WITHOUT
// firing error_callback on remaining entries. Any code path that
// observes shutting_down_ mid-loop must fan out CHECKOUT_SHUTTING_DOWN
// to its snapshotted entries INLINE rather than requeue-and-bail —
// otherwise the owning ProxyTransaction strands until its response
// timeout. The Drain* helpers below repeat this guard at 3 points
// (entry, mid-loop, post-requeue) to cover every observation window;
// see UPSTREAM_PROXY.md for the original failure mode.

// ── UpstreamLease out-of-line definitions ──────────────────────────────
// These live here because the destructor/Release need the complete
// PoolPartition type (forward-declared in upstream_lease.h).

UpstreamLease::~UpstreamLease() {
    Release();
}

UpstreamH2Stream* UpstreamLease::GetH2Stream() const {
    UpstreamH2Connection* c = GetH2Connection();
    if (!c) return nullptr;
    return c->GetStream(h2_stream_id_);
}

void UpstreamLease::Release() {
    // Partition-alive guard: ~PoolPartition stores false to alive_ BEFORE
    // freeing any member. A lease that outlives its partition (standalone
    // UpstreamManager teardown with an outstanding lease) would otherwise
    // dereference freed memory.
    const bool partition_live = partition_ && partition_alive_ &&
        partition_alive_->load(std::memory_order_acquire);

    // Dispatcher-thread-only invariant. Release calls into
    // partition_->ReturnConnection / ReturnH2Stream which mutate
    // idle_conns_ / active_conns_ / h2_table_ — all dispatcher-locked-
    // by-convention with no internal mutex. A cross-thread Release
    // would race those containers AND corrupt inflight_leases_ /
    // donated_h2_leases_ accounting. Hard-reject in BOTH debug and
    // release builds: debug-assert + warn-log + skip the partition
    // mutations (counter corruption avoided, lease still resets local
    // fields so the destructor stays well-defined). The H2 lease shape
    // in this PR adds more lease holders → social discipline alone is
    // weaker insurance than before.
    // Use the lease's captured dispatcher_ shared_ptr, NOT
    // partition_->dispatcher(). The partition may be racing destruction:
    // ~PoolPartition stores `alive=false` first but then waits for
    // inflight_tasks_==0 — UpstreamLease::Release does NOT bump that
    // counter, so an off-dispatcher Release that already observed
    // `alive=true` can race the destructor's return. After the
    // destructor returns, partition_ storage is freed.
    // The captured dispatcher_ shared_ptr keeps the Dispatcher alive
    // independently of the partition.
    bool off_dispatcher = false;
    if (partition_live && dispatcher_ &&
        !dispatcher_->is_on_loop_thread()) {
        off_dispatcher = true;
        logging::Get()->error(
            "UpstreamLease::Release: called off the partition dispatcher "
            "thread (kind={}) — skipping partition return to avoid "
            "container/counter race",
            kind_ == Kind::H1 ? "H1"
                              : kind_ == Kind::H2 ? "H2" : "EMPTY");
        // The debug-assert is a developer aid for catching cross-thread
        // misuse during development. Test builds (REACTOR_BUILDING_TESTS)
        // deliberately exercise this path to lock the warn-log + counter-
        // bump + skip-mutation contract, so the assert is suppressed
        // there — the release-build behavior IS the production contract.
#if !defined(NDEBUG) && !defined(REACTOR_BUILDING_TESTS)
        assert(false &&
               "UpstreamLease::Release must run on partition dispatcher");
#endif
    }

    if (off_dispatcher) {
        // Skip partition mutation entirely. Counter corruption is the
        // worse failure mode; a lost return is bounded (single lease).
        // Bump the heap-owned counter (captured at lease construction)
        // so /stats surfaces the leak and operators can correlate
        // shutdown-drain delays. Critically: the counter is reached
        // via shared_ptr — NOT via partition_->... — so the bump is
        // safe even if the partition is mid-destruction. Bumping
        // through partition_ here would race the destructor between
        // the partition_alive observation above and this line.
        if (off_dispatcher_release_drops_) {
            off_dispatcher_release_drops_->fetch_add(
                1, std::memory_order_acq_rel);
        }
    } else if (kind_ == Kind::H1 && partition_live && conn_) {
        partition_->ReturnConnection(conn_, donated_to_h2_);
    } else if (kind_ == Kind::H2 && partition_live && h2_conn_ &&
               conn_alive_ &&
               conn_alive_->load(std::memory_order_acquire)) {
        partition_->ReturnH2Stream(h2_conn_, h2_stream_id_,
                                   partition_alive_, conn_alive_);
    } else if (!partition_live && (kind_ != Kind::EMPTY)) {
        // Non-empty lease whose partition died before we could return.
        // Indicates a shutdown-ordering bug upstream of this lease — the
        // owning subsystem should have drained leases before partition
        // teardown. Warn so the latency / metric ghost is correlatable.
        logging::Get()->warn(
            "UpstreamLease::Release: partition died before lease return "
            "(kind={}, donated_to_h2={}) — possible shutdown-ordering bug",
            kind_ == Kind::H1 ? "H1" : "H2", donated_to_h2_ ? 1 : 0);
    }
    kind_ = Kind::EMPTY;
    conn_ = nullptr;
    h2_conn_ = nullptr;
    h2_stream_id_ = -1;
    partition_ = nullptr;
    partition_alive_.reset();
    conn_alive_.reset();
    off_dispatcher_release_drops_.reset();
    dispatcher_.reset();
    donated_to_h2_ = false;
}

// ── PoolPartition ──────────────────────────────────────────────────────

PoolPartition::PoolPartition(
    std::shared_ptr<Dispatcher> dispatcher,
    const std::string& service_name,
    const std::string& upstream_host, int upstream_port,
    const std::string& sni_hostname,
    std::shared_ptr<const NET_DNS_NAMESPACE::ResolvedEndpoint> resolved_endpoint,
    const UpstreamPoolConfig& config,
    std::shared_ptr<TlsClientContext> tls_ctx,
    std::atomic<int64_t>& outstanding_conns,
    std::atomic<int64_t>& inflight_leases,
    std::atomic<int64_t>& donated_h2_leases,
    std::shared_ptr<std::atomic<int64_t>> off_dispatcher_release_drops,
    std::atomic<bool>& manager_shutting_down,
    std::mutex& drain_mtx,
    std::condition_variable& drain_cv)
    : dispatcher_(std::move(dispatcher))
    , service_name_(service_name)
    , upstream_host_(upstream_host)
    , upstream_port_(upstream_port)
    , sni_hostname_(sni_hostname)
    , config_(config)
    , tls_ctx_(std::move(tls_ctx))
    , resolved_endpoint_(std::move(resolved_endpoint))
    , outstanding_conns_(outstanding_conns)
    , inflight_leases_(inflight_leases)
    , donated_h2_leases_(donated_h2_leases)
    , off_dispatcher_release_drops_(std::move(off_dispatcher_release_drops))
    , manager_shutting_down_(manager_shutting_down)
    , drain_mtx_(drain_mtx)
    , drain_cv_(drain_cv)
    , partition_max_connections_(static_cast<size_t>(config.max_connections))
{
    // Programmer error guard: partition needs a resolved endpoint to
    // connect. Production builds get one from HttpServer::Start's DNS
    // batch; legacy-literal builds get one from
    // UpstreamManager::BuildResolvedFromLiterals. A null here means a
    // caller is constructing PoolPartition directly with the old
    // no-endpoint signature — fail fast with a clear message.
    if (!resolved_endpoint_) {
        throw std::invalid_argument(
            "PoolPartition: resolved_endpoint must not be null "
            "(use UpstreamManager's 2-arg legacy ctor for literal-only "
            "setups; direct PoolPartition construction requires a "
            "ResolvedEndpoint).");
    }
    logging::Get()->debug(
        "PoolPartition created for {}:{} (resolved={}:{}) on dispatcher {}",
        upstream_host_, upstream_port_,
        resolved_endpoint_->addr.Ip(),
        resolved_endpoint_->addr.Port(),
        dispatcher_->dispatcher_index());
}

// Null out all callbacks on a connection's transport to prevent
// dangling-this use-after-free if the ConnectionHandler outlives
// the PoolPartition (still in dispatcher's connections_ map).
// Nulls completion/write-progress too so an H2 borrower's wire-up
// can't survive an Init failure into the next pool reuse.
static void ClearTransportCallbacks(UpstreamConnection* conn) {
    if (conn && conn->GetTransport()) {
        auto t = conn->GetTransport();
        t->SetConnectCompleteCallback(nullptr);
        t->SetCloseCb(nullptr);
        t->SetOnMessageCb(nullptr);
        t->SetErrorCb(nullptr);
        t->SetCompletionCb(nullptr);
        t->SetWriteProgressCb(nullptr);
    }
}

// Saturation ratio in percent. Caller guarantees max_streams_pref > 0.
static int ComputeStreamUtilizationPct(uint32_t streams,
                                       uint32_t max_streams_pref) {
    return static_cast<int>(
        (static_cast<uint64_t>(streams) * 100u) / max_streams_pref);
}

PoolPartition::~PoolPartition() {
    // Atomic write — stops new purge chains from being scheduled.
    alive_->store(false, std::memory_order_release);

    // All destruction-sensitive work runs on the dispatcher (close
    // callbacks fired by channel events can mutate the same containers
    // off-thread). RAII inflight-guard fires the decrement even if
    // EnQueue is dropped by a stopped dispatcher.

    auto on_dispatcher = [this]() {
        // On dispatcher thread — single-threaded, no concurrent mutation.
        // Safe to walk containers and touch connection transports.
        //
        // Null obs_manager_ FIRST. In HttpServer's declaration order,
        // observability_manager_ is destroyed BEFORE upstream_manager_
        // (declared later, destructs first). The production path is safe
        // (Stop() runs while obs is alive), but this safety-net path fires
        // after ~ObservabilityManager may have already run. Zeroing the
        // pointer here ensures every emit helper's null-guard on obs_manager_
        // fires and no calls reach a destroyed ObservabilityManager.
        obs_manager_.store(nullptr, std::memory_order_release);
        //
        // H2 sessions destruct FIRST so their nghttp2 + transport-callback
        // teardown lands here, before the underlying transports (in
        // connecting_conns_ / active_conns_) get their callbacks nulled
        // below. h2_connecting_conns_, pending_destroy_h2_conns_, and
        // pending_h2_replacement_targets_ are cleared on the dispatcher
        // for the same reason. ~UpstreamH2Connection nulls its transport
        // callbacks BEFORE running terminate_session + FlushSend, so a
        // stray incoming-bytes event during the destruction window cannot
        // reenter HandleBytes on a session about to be torn down. See
        // UPSTREAM_H2.md / UPSTREAM_PROXY.md for the full ordering
        // invariant.
        h2_table_.Clear();
        h2_connecting_conns_.clear();
        pending_destroy_h2_conns_.clear();
        pending_h2_replacement_targets_.clear();
        auto clear = [](auto& container) {
            for (auto& c : container) {
                if (!c) continue;
                auto t = c->GetTransport();  // GetTransport returns by value
                if (t) {
                    t->SetConnectCompleteCallback(nullptr);
                    t->SetCloseCb(nullptr);
                    t->SetErrorCb(nullptr);
                    t->SetOnMessageCb(nullptr);
                    t->SetCompletionCb(nullptr);
                    t->SetWriteProgressCb(nullptr);
                }
            }
        };
        clear(idle_conns_);
        clear(active_conns_);
        clear(connecting_conns_);
        clear(zombie_conns_);
    };

    if (dispatcher_ && !dispatcher_->was_stopped() &&
        !dispatcher_->is_on_loop_thread()) {
        // RAII guard — see MakeInflightGuard for semantics. Captured by the
        // lambda so the decrement fires whether the lambda runs or is
        // dropped by a stopped dispatcher.
        auto guard = MakeInflightGuard();
        dispatcher_->EnQueue([on_dispatcher, guard]() {
            on_dispatcher();
        });
    } else {
        // On-thread OR dispatcher stopped: no concurrent access possible.
        // Run inline (safe).
        on_dispatcher();
    }

    // Unbounded wait: a stale task firing post-destructor would UAF
    // freed members. inflight_tasks_ is shared_ptr<atomic>, outlives
    // the partition. ProcessPendingTasks inline-drains when this dtor
    // runs on the dispatcher itself (self-teardown from a pool cb).
    int iteration = 0;
    while (inflight_tasks_->load(std::memory_order_acquire) > 0) {
        if (dispatcher_ && dispatcher_->is_on_loop_thread()) {
            dispatcher_->ProcessPendingTasks();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        if (++iteration == 500) {  // ~5 second warning threshold
            logging::Get()->warn("PoolPartition destructor waiting on {} "
                                 "in-flight dispatcher tasks",
                                 inflight_tasks_->load(std::memory_order_relaxed));
            iteration = 0;
        }
    }

    // Do NOT call ForceClose() here — destructor may run on the main thread
    // and ForceClose() does cross-thread epoll operations (UB).
    // SocketHandler::~SocketHandler() will close the fd naturally.
}

void PoolPartition::CheckoutAsync(ReadyCallback ready_cb, ErrorCallback error_cb,
                                    std::shared_ptr<std::atomic<bool>> cancel_token) {
    // All pool operations must run on the owning dispatcher thread.
    // Off-thread access would data-race on the containers.
    if (dispatcher_ && !dispatcher_->is_dispatcher_thread()) {
        logging::Get()->error("BUG: CheckoutAsync called off dispatcher thread");
        error_cb(CHECKOUT_CONNECT_FAILED);
        return;
    }

    // Hoist alive_ — PurgeExpiredWaitEntries may fire a waiter's error_cb
    // that tears down the pool/manager, destroying this partition.
    auto alive = alive_;

    // Purge expired wait queue entries inline — ensures queue timeouts
    // fire even without external EvictExpired calls (standalone usage).
    PurgeExpiredWaitEntries();
    if (!alive->load(std::memory_order_acquire)) return;

    if (shutting_down_.load(std::memory_order_acquire)) {
        error_cb(CHECKOUT_SHUTTING_DOWN);
        return;
    }

    // If the caller has already cancelled (rare — typically cancel
    // fires after CheckoutAsync), short-circuit immediately so we don't
    // waste a slot or fire ready_cb on a dead transaction.
    if (cancel_token &&
        cancel_token->load(std::memory_order_acquire)) {
        return;
    }

    // 1. Try to find a valid idle connection (MRU = front).
    // Defense-in-depth against the reload-cleanup task race: a connection
    // idle at reload time should be reaped by EnqueueIdleCleanupOnEndpointChange,
    // but if a checkout lands BEFORE that cleanup task runs, the popped idle
    // entry may still carry the old captured_endpoint(). Skip + destroy in
    // that case so a stale-IP connection is never handed to a borrower.
    auto current_ep_for_pop = LoadResolvedEndpoint();
    while (!idle_conns_.empty()) {
        auto conn = std::move(idle_conns_.front());
        idle_conns_.pop_front();

        // Endpoint match check: a keepalive captured against an old
        // resolved IP must not be handed out after the partition adopts
        // a new endpoint. ConnectionEndpointMatches atomic-loads the
        // current resolved_endpoint_ and compares with the connection's
        // captured pointer; idle connections from a superseded endpoint
        // get destroyed here.
        (void)current_ep_for_pop;  // helper does its own atomic_load
        if (!ConnectionEndpointMatches(*conn)) {
            // This conn previously emitted +1 on the idle gauge in
            // ReturnConnection. Emit the matching -1 BEFORE Destroy so a
            // hostname/DNS endpoint reload doesn't leave
            // reactor.upstream.pool.connections.idle permanently high.
            EmitIdleGaugeDelta(-1.0);
            DestroyConnection(std::move(conn));
            continue;
        }

        if (!ValidateConnection(conn.get())) {
            // Same idle-gauge balance as the endpoint-mismatch branch
            // above — the popped conn previously bumped +1 in
            // ReturnConnection; destroying it without a matching -1
            // leaks the gauge.
            EmitIdleGaugeDelta(-1.0);
            DestroyConnection(std::move(conn));
            continue;
        }

        // Valid idle connection found — activate and deliver synchronously.
        // Set far-future deadline to suppress server-wide idle timeout.
        static constexpr auto FAR_FUTURE_CHECKOUT = std::chrono::hours(24 * 365);
        conn->MarkInUse();
        conn->GetTransport()->SetDeadline(
            std::chrono::steady_clock::now() + FAR_FUTURE_CHECKOUT);
        UpstreamConnection* raw = conn.get();
        active_conns_.push_back(std::move(conn));
        // idle->active transition: pair both emits before the user callback
        // so a callback that tears the partition down still leaves the
        // gauges consistent. Histogram fires with ~0 duration (immediate).
        EmitIdleGaugeDelta(-1.0);
        EmitActiveGaugeDelta(+1.0);
        EmitCheckoutWaitDuration(0.0, "immediate");
        // Bump inflight_leases_ BEFORE handing the lease to the caller.
        // ReturnConnection (called from ~UpstreamLease) decrements.
        inflight_leases_.fetch_add(1, std::memory_order_acq_rel);
        ready_cb(UpstreamLease(raw, this, alive_, off_dispatcher_release_drops_, dispatcher_));
        return;
    }

    // 2. No idle — create new if under limit
    if (TotalCount() < partition_max_connections_) {
        CreateNewConnection(std::move(ready_cb), std::move(error_cb));
        return;
    }

    // 3. At capacity — queue if room. Before rejecting on a full
    // queue, sweep for cancelled waiters. A burst of disconnected
    // clients (e.g., client-side aborts against a slow upstream)
    // can otherwise fill the bounded queue with dead entries whose
    // transactions have already been cancelled, leaving no room for
    // new live requests until each dead entry expires on its own
    // queue timeout. Purging on demand keeps the queue slot budget
    // effective under cancel bursts.
    if (wait_queue_.size() >= MAX_WAIT_QUEUE_SIZE) {
        size_t purged = PurgeCancelledWaitEntries();
        if (purged > 0) {
            logging::Get()->debug(
                "PoolPartition dropped {} cancelled waiters before new "
                "checkout (host={}:{})",
                purged, upstream_host_, upstream_port_);
        }
    }
    if (wait_queue_.size() < MAX_WAIT_QUEUE_SIZE) {
        WaitEntry entry;
        entry.ready_callback = std::move(ready_cb);
        entry.error_callback = std::move(error_cb);
        entry.queued_at = std::chrono::steady_clock::now();
        entry.cancel_token = std::move(cancel_token);
        wait_queue_.push_back(std::move(entry));
        // Ensure queued checkouts eventually get CHECKOUT_QUEUE_TIMEOUT.
        // In production (HttpServer), the timer callback calls EvictExpired
        // periodically. In standalone mode, we schedule a self-rescheduling
        // purge task that checks timestamps each iteration.
        if (dispatcher_ && !shutting_down_.load(std::memory_order_acquire)) {
            ScheduleWaitQueuePurge();
        }
        return;
    }

    // 4. Queue full — reject
    EmitCheckoutWaitDuration(0.0, "rejected");
    error_cb(CHECKOUT_POOL_EXHAUSTED);
}

size_t PoolPartition::PurgeCancelledWaitEntries() {
    size_t before = wait_queue_.size();
    auto now = std::chrono::steady_clock::now();
    // std::deque supports erase via iterators; walk forward and erase
    // cancelled entries in place. Callbacks are NOT fired — a cancelled
    // checkout's owning transaction has already been torn down via the
    // framework abort hook and does not expect any completion.
    for (auto it = wait_queue_.begin(); it != wait_queue_.end(); ) {
        if (IsEntryCancelled(*it)) {
            auto cancelled_dur = std::chrono::duration_cast<
                std::chrono::duration<double>>(now - it->queued_at);
            EmitCheckoutWaitDuration(cancelled_dur.count(), "cancelled");
            it = wait_queue_.erase(it);
        } else {
            ++it;
        }
    }
    return before - wait_queue_.size();
}

void PoolPartition::EnqueueH2StreamSlotWaiter(
    const std::string& upstream_name, int port,
    ReadyCallback ready_cb, ErrorCallback error_cb,
    std::shared_ptr<std::atomic<bool>> cancel_token) {
    if (shutting_down_.load(std::memory_order_acquire) ||
        manager_shutting_down_.load(std::memory_order_acquire)) {
        if (error_cb) error_cb(CHECKOUT_SHUTTING_DOWN);
        return;
    }
    if (wait_queue_.size() >= MAX_WAIT_QUEUE_SIZE) {
        PurgeCancelledWaitEntries();
        if (wait_queue_.size() >= MAX_WAIT_QUEUE_SIZE) {
            logging::Get()->warn(
                "PoolPartition::EnqueueH2StreamSlotWaiter: queue full "
                "({}/{}) upstream={}:{}",
                wait_queue_.size(), MAX_WAIT_QUEUE_SIZE, upstream_name, port);
            if (error_cb) error_cb(CHECKOUT_QUEUE_FULL);
            return;
        }
    }
    WaitEntry e;
    e.ready_callback = std::move(ready_cb);
    e.error_callback = std::move(error_cb);
    e.queued_at = std::chrono::steady_clock::now();
    e.cancel_token = std::move(cancel_token);
    e.kind = WaiterKind::H2_STREAM_SLOT;
    e.upstream_name = upstream_name;
    e.port = port;
    wait_queue_.push_back(std::move(e));
    ScheduleWaitQueuePurge();
}

void PoolPartition::DrainH2StreamWaitersForHost(
    const std::string& upstream_name, int port) {
    // Hot path: RunDeferredEraseWalk calls this on every H2 stream-close.
    // No production caller enqueues H2_STREAM_SLOT waiters today, so the
    // wait_queue_ holds ANY-kind entries only — skip the scan + atomic
    // loads when nothing could possibly match.
    if (wait_queue_.empty()) return;
    if (shutting_down_.load(std::memory_order_acquire) ||
        manager_shutting_down_.load(std::memory_order_acquire)) {
        return;
    }
    auto alive = alive_;

    // Snapshot the matching entries out of wait_queue_ first so an
    // entry's ready_callback firing synchronously cannot invalidate the
    // deque iteration. Matches the H1 ServiceWaitQueue pattern of
    // hoisting `alive` and re-checking after every callback.
    std::vector<WaitEntry> matched;
    for (auto it = wait_queue_.begin(); it != wait_queue_.end(); ) {
        if (it->kind == WaiterKind::H2_STREAM_SLOT &&
            it->upstream_name == upstream_name && it->port == port) {
            if (IsEntryCancelled(*it)) {
                it = wait_queue_.erase(it);
                continue;
            }
            matched.push_back(std::move(*it));
            it = wait_queue_.erase(it);
        } else {
            ++it;
        }
    }

    // Walk matched entries. The vending path for H2_STREAM_SLOT is not
    // wired yet (no production EnqueueH2StreamSlotWaiter caller), so the
    // body is currently a defer-and-requeue: each entry returns to the
    // queue head until a future caller fires the actual lease handoff.
    // Reverse iteration on requeue preserves FIFO ordering in the deque.
    std::deque<WaitEntry> requeue;
    bool stopped_early = false;
    for (size_t i = 0; i < matched.size(); ++i) {
        WaitEntry& e = matched[i];
        if (stopped_early) {
            requeue.push_back(std::move(e));
            continue;
        }
        if (!alive->load(std::memory_order_acquire)) {
            // Partition destroyed mid-drain — current entry plus every
            // remaining matched entry is unreachable. Mirrors
            // DrainAnyWaitersForFastH2's warn so operators can correlate
            // a future enqueuer's hung waiters with this destruction
            // window (today no production enqueuer exists).
            size_t abandoned = matched.size() - i;
            logging::Get()->warn(
                "DrainH2StreamWaitersForHost abandoned {} matched "
                "H2_STREAM_SLOT waiter(s) for {}:{} — partition destroyed "
                "mid-drain", abandoned, upstream_name, port);
            return;
        }
        if (shutting_down_.load(std::memory_order_acquire) ||
            manager_shutting_down_.load(std::memory_order_acquire)) {
            // Fire CHECKOUT_SHUTTING_DOWN inline rather than requeueing.
            // ~PoolPartition's on_dispatcher lambda clears wait_queue_
            // WITHOUT fan-out, so any requeued entry would strand the
            // owning ProxyTransaction. Drain all remaining matched
            // entries with the same fate so we don't half-strand them.
            if (e.error_callback) e.error_callback(CHECKOUT_SHUTTING_DOWN);
            for (size_t j = i + 1; j < matched.size(); ++j) {
                if (matched[j].error_callback) {
                    matched[j].error_callback(CHECKOUT_SHUTTING_DOWN);
                }
            }
            // Don't restore the requeue deque — every entry has been
            // notified inline. Return early.
            return;
        }
        // Use endpoint-aware lookup so a DNS-swapped stale session
        // does not wake the waiter only for SubmitRequest's freshness
        // check to fail. FindUsableH2Connection marks stale candidates
        // dead inline so subsequent CollectUsableForUpstream skips them.
        UpstreamH2Connection* h2 = FindUsableH2Connection(upstream_name);
        if (!h2 || !h2->IsUsable()) {
            // No usable session right now — requeue everything we still
            // have. The next slot-free (RunDeferredEraseWalk) or fresh
            // H2 connect will re-enter this path.
            requeue.push_back(std::move(e));
            stopped_early = true;
            continue;
        }
        // TODO: wire UpstreamLease H2-kind ctor once ProxyTransaction
        // migrates to UpstreamLease h2_lease_. No production caller of
        // EnqueueH2StreamSlotWaiter today; requeue so a future enqueuer
        // (or unit-test fixture) does not see spurious connect failures
        // before the vending path lands. Cold-start dedup for ANY-kind
        // waiters is covered by DrainAnyWaitersForFastH2.
        requeue.push_back(std::move(e));
        stopped_early = true;
    }
    // Shutdown observation between requeue-push and the FIFO restore
    // below: any requeued entry would strand because ~PoolPartition's
    // lambda clears wait_queue_ without firing error_callback.
    // Fan-out CHECKOUT_SHUTTING_DOWN inline instead of restoring.
    if (shutting_down_.load(std::memory_order_acquire) ||
        manager_shutting_down_.load(std::memory_order_acquire)) {
        for (auto& e : requeue) {
            if (e.error_callback) e.error_callback(CHECKOUT_SHUTTING_DOWN);
        }
        return;
    }
    // Restore FIFO order at front of queue.
    for (auto it = requeue.rbegin(); it != requeue.rend(); ++it) {
        wait_queue_.push_front(std::move(*it));
    }
}

void PoolPartition::DrainAnyWaitersForFastH2() {
    if (wait_queue_.empty()) return;
    if (shutting_down_.load(std::memory_order_acquire) ||
        manager_shutting_down_.load(std::memory_order_acquire)) {
        return;
    }
    auto alive = alive_;

    // Snapshot ANY-kind entries so a synchronous ready_callback (which
    // re-enters TryDispatchExistingH2Session → DispatchH2 → possibly
    // mem_recv2 → sink chain) cannot invalidate the iterator.
    std::vector<WaitEntry> matched;
    for (auto it = wait_queue_.begin(); it != wait_queue_.end(); ) {
        if (it->kind == WaiterKind::ANY) {
            if (IsEntryCancelled(*it)) {
                it = wait_queue_.erase(it);
                continue;
            }
            matched.push_back(std::move(*it));
            it = wait_queue_.erase(it);
        } else {
            ++it;
        }
    }

    // Capacity-aware fan-out — re-check FindUsable each iteration so we
    // never over-fire past max_concurrent_streams (siblings would lose
    // SubmitRequest's IsUsable gate). continue (not break) preserves
    // the shutdown-flip branch's requeue contract.
    std::deque<WaitEntry> requeue;
    for (size_t i = 0; i < matched.size(); ++i) {
        WaitEntry& e = matched[i];
        if (!alive->load(std::memory_order_acquire)) {
            // Partition destroyed mid-drain — current entry plus every
            // remaining matched entry is unreachable: their
            // ready/error_callbacks may close over freed partition
            // state. Warn so operators see how many ProxyTransactions
            // hung until response timeout.
            size_t abandoned = matched.size() - i;
            logging::Get()->warn(
                "DrainAnyWaitersForFastH2 abandoned {} matched ANY "
                "waiter(s) — partition destroyed mid-drain; affected "
                "ProxyTransactions will hang until response timeout",
                abandoned);
            return;
        }
        if (shutting_down_.load(std::memory_order_acquire) ||
            manager_shutting_down_.load(std::memory_order_acquire)) {
            // Fire CHECKOUT_SHUTTING_DOWN inline rather than requeueing:
            // ~PoolPartition's on_dispatcher lambda clears wait_queue_
            // WITHOUT firing error_callback, so a requeued entry would
            // strand the owning ProxyTransaction until response timeout.
            // InitiateShutdown's single-pass rejection may already have
            // completed by the time we observed the flag.
            if (e.error_callback) e.error_callback(CHECKOUT_SHUTTING_DOWN);
            continue;
        }
        // Endpoint-aware lookup — see DrainH2StreamWaitersForHost above
        // for rationale. A DNS-swapped stale candidate must not be
        // surfaced as usable to ANY-kind waiters.
        UpstreamH2Connection* h2 = FindUsableH2Connection(service_name_);
        if (!h2) {
            // No usable session right now (no session, all dead, or
            // cap reached by a sibling already served this drain).
            // Re-queue and wait for the next slot-free / cold-start
            // signal to re-enter this path.
            requeue.push_back(std::move(e));
            continue;
        }
        if (e.ready_callback) e.ready_callback(UpstreamLease());
    }

    // Shutdown observation between requeue-push and FIFO restore: a
    // requeued entry would strand because ~PoolPartition's lambda
    // clears wait_queue_ without firing error_callback. Fan-out
    // CHECKOUT_SHUTTING_DOWN inline.
    if (shutting_down_.load(std::memory_order_acquire) ||
        manager_shutting_down_.load(std::memory_order_acquire)) {
        for (auto& e : requeue) {
            if (e.error_callback) e.error_callback(CHECKOUT_SHUTTING_DOWN);
        }
        return;
    }
    // Restore FIFO: push_front in reverse so first requeued ends up
    // at wait_queue_.front().
    for (auto it = requeue.rbegin(); it != requeue.rend(); ++it) {
        wait_queue_.push_front(std::move(*it));
    }
}

void PoolPartition::MoveConnToPendingDestroy(UpstreamH2Connection* conn) {
    // Precondition: one service per partition (see `service_name_`).
    // The replacement target below keys on service_name_; broadening
    // to multi-name routing requires passing the key explicitly.
    if (!conn) return;
    auto owned = h2_table_.Extract(conn);
    if (!owned) {
        logging::Get()->debug(
            "PoolPartition::MoveConnToPendingDestroy: conn not tracked");
        return;
    }
    // Capture the replacement target BEFORE the destroy path runs —
    // the transport still has its port at this moment, and the H2
    // session lives under service_name_ in h2_table_. The reap below
    // frees the active_conns_ slot; only then can a fresh probe pass
    // the TotalCount cap.
    if (auto t = conn->transport()) {
        pending_h2_replacement_targets_.push_back(
            HostPortKey{service_name_, t->upstream_port()});
    } else {
        // The H2 session lost its transport pointer before reaching
        // pending-destroy (transport already destroyed, or the session
        // was constructed with null transport for testing). No port
        // available → cannot start a replacement probe even after the
        // slot frees. Queued H2_STREAM_SLOT waiters for this upstream
        // will time out at MAX_QUEUE_AGE unless a fresh CheckoutAsync
        // re-triggers OpenNewH2Connection.
        logging::Get()->warn(
            "MoveConnToPendingDestroy: transport already gone for "
            "upstream={} — replacement target NOT captured; queued "
            "waiters may time out",
            service_name_);
    }
    pending_destroy_h2_conns_.push_back(std::move(owned));
}

void PoolPartition::ReapPendingDestroyH2Conns() {
    if (pending_destroy_h2_conns_.empty() &&
        pending_h2_replacement_targets_.empty()) {
        return;
    }
    // Snapshot BOTH containers together — MoveConnToPendingDestroy
    // appends to both; a destroy-chain reentrant call must leave them
    // paired for the NEXT reap (else cap-gate rejects the probe and
    // the target is silently lost under tight caps). See UPSTREAM_PROXY.md.
    auto victims = std::move(pending_destroy_h2_conns_);
    pending_destroy_h2_conns_.clear();
    auto targets = std::move(pending_h2_replacement_targets_);
    pending_h2_replacement_targets_.clear();

    for (auto& c : victims) {
        if (!c) continue;
        c->DestroyOnDispatcher();
        // Unique_ptr lapses at scope end — dtor sees
        // destroyed_on_dispatcher_=true and short-circuits.
    }

    // Slot is now free (DestroyOnDispatcher → lease_.reset →
    // ReturnConnection → ExtractFromActive). Re-issue the
    // replacement-connect that OnGoawayReceived short-circuited on
    // the TotalCount cap. StartH2ReplacementConnect is idempotent
    // (gates on h2_connecting_conns_ and h2_table_) so a duplicate
    // call is a no-op.
    for (const auto& key : targets) {
        StartH2ReplacementConnect(key.host, key.port);
    }
}

#ifdef REACTOR_BUILDING_TESTS
void PoolPartition::InsertH2ConnectionForTesting(
    const std::string& upstream_name,
    std::unique_ptr<UpstreamH2Connection> conn) {
    if (!conn) return;
    conn->SetPartition(this);
    h2_table_.Insert(upstream_name, std::move(conn));
}

void PoolPartition::SeedPendingReplacementTargetForTesting(int port) {
    pending_h2_replacement_targets_.push_back(
        HostPortKey{service_name_, port});
}
#endif  // REACTOR_BUILDING_TESTS

void PoolPartition::FailH2StreamSlotWaiters(
    const std::string& upstream_name, int port, int connect_outcome,
    const std::string& reason) {
    auto alive = alive_;
    std::vector<WaitEntry> matched;
    for (auto it = wait_queue_.begin(); it != wait_queue_.end(); ) {
        if (it->kind == WaiterKind::H2_STREAM_SLOT &&
            it->upstream_name == upstream_name && it->port == port) {
            if (IsEntryCancelled(*it)) {
                it = wait_queue_.erase(it);
                continue;
            }
            matched.push_back(std::move(*it));
            it = wait_queue_.erase(it);
        } else {
            ++it;
        }
    }
    if (!matched.empty()) {
        logging::Get()->warn(
            "PoolPartition::FailH2StreamSlotWaiters: failing {} waiter(s) "
            "upstream={}:{} outcome={} reason={}",
            matched.size(), upstream_name, port, connect_outcome, reason);
    }
    for (auto& e : matched) {
        if (!alive->load(std::memory_order_acquire)) return;
        if (e.error_callback) e.error_callback(connect_outcome);
    }
}

void PoolPartition::ReturnConnection(UpstreamConnection* conn,
                                     bool was_donated_to_h2) {
    if (!conn) return;

    // The lease that owned `conn` is being released. Per-request leases
    // decrement inflight_leases_ (matches every ready_cb(UpstreamLease)
    // bump site). Donated H2 leases decrement the separate
    // donated_h2_leases_ counter — the drain predicate consults only
    // the per-request counter, so long-lived multiplexed sessions do
    // not stall observability flush. AdoptLease performs the +1 swap
    // (inflight_leases_-- and donated_h2_leases_++) so the totals stay
    // balanced.
    if (was_donated_to_h2) {
        donated_h2_leases_.fetch_sub(1, std::memory_order_acq_rel);
    } else {
        inflight_leases_.fetch_sub(1, std::memory_order_acq_rel);
    }

    // Hoist alive_ onto the stack — the waiter retry loops below call
    // CreateNewConnection, which can synchronously invoke a user error_cb
    // on inline connect failures. A user callback that tears down the
    // pool/manager would free `this` mid-loop.
    auto alive = alive_;

    // Find in active_conns_ and extract
    auto owned = ExtractFromActive(conn);
    if (!owned) {
        // Check zombie list — connection was force-closed after drain timeout
        // but the lease just released it. Clean up now.
        for (auto it = zombie_conns_.begin(); it != zombie_conns_.end(); ++it) {
            if (it->get() == conn) {
                zombie_conns_.erase(it);
                // Decrement here — zombie producers (OnConnectionClosed for
                // active connections, ForceCloseActive) intentionally defer
                // the decrement until the lease releases, so WaitForDrain
                // doesn't see 0 while leases are still alive.
                outstanding_conns_.fetch_sub(1, std::memory_order_release);
                MaybeSignalDrain();
                return;
            }
        }
        logging::Get()->warn("ReturnConnection: connection not found in active set "
                             "(already closed or double-return)");
        return;
    }

    // If shutting down (partition-local or manager-wide), destroy instead of
    // pooling. Without the manager check, a lease returned between the manager
    // flag and the partition's enqueued InitiateShutdown can re-enter the pool
    // and start new upstream work after Stop() has begun.
    if (shutting_down_ || manager_shutting_down_.load(std::memory_order_acquire)) {
        // active -> destroy (connection leaves active; never enters idle)
        EmitActiveGaugeDelta(-1.0);
        DestroyConnection(std::move(owned));
        return;
    }

    // Early-response poison: if the borrower marked this connection as closing
    // (e.g., upstream sent a response before the request write completed, leaving
    // stale request bytes in the transport's output buffer), destroy it instead
    // of returning to idle.
    if (owned->IsClosing()) {
        EmitActiveGaugeDelta(-1.0);
        DestroyConnection(std::move(owned));
        CreateForWaiters();
        return;
    }

    // Endpoint generation check on return. Two synchronous reuse paths
    // below (over-idle-cap direct handoff + trailing ServiceWaitQueue
    // grabbing this conn off the front of idle_conns_) bypass the
    // CheckoutAsync endpoint gate, so a post-reload-swap conn could
    // serve a queued waiter on a stale IP. Fail closed at entry.
    if (!ConnectionEndpointMatches(*owned)) {
        EmitActiveGaugeDelta(-1.0);
        DestroyConnection(std::move(owned));
        CreateForWaiters();
        return;
    }

    owned->IncrementRequestCount();
    owned->MarkIdle();

    // Re-wire pool-owned callbacks — borrowers may have overwritten them
    // with request-specific handlers during checkout.
    WirePoolCallbacks(owned.get());

    // Check if expired
    if (owned->IsExpired(config_.max_lifetime_sec, config_.max_requests_per_conn)) {
        EmitActiveGaugeDelta(-1.0);
        DestroyConnection(std::move(owned));
        CreateForWaiters();
        return;
    }

    // Check if over idle cap. If waiters are queued, hand the connection
    // directly to the next waiter instead of destroying it — otherwise
    // max_idle_connections=0 starves queued checkouts even though capacity
    // just freed.
    if (idle_conns_.size() >= static_cast<size_t>(config_.max_idle_connections)) {
        PurgeExpiredWaitEntries();
        if (!alive->load(std::memory_order_acquire)) return;
        // Drop cancelled waiters at the front before attempting handoff
        // — otherwise a cancelled front-of-queue entry would "consume"
        // the returning connection by being silently dropped while
        // still blocking any live waiter behind it.
        {
            auto now = std::chrono::steady_clock::now();
            while (!wait_queue_.empty() &&
                   IsEntryCancelled(wait_queue_.front())) {
                auto cancelled_dur =
                    std::chrono::duration_cast<std::chrono::duration<double>>(
                        now - wait_queue_.front().queued_at);
                EmitCheckoutWaitDuration(cancelled_dur.count(), "cancelled");
                wait_queue_.pop_front();
            }
        }
        if (!wait_queue_.empty() && ValidateConnection(owned.get())) {
            // Hand directly to the next waiter (validated — not dead/expired)
            static constexpr auto FAR_FUTURE_HANDOFF = std::chrono::hours(24 * 365);
            owned->MarkInUse();
            owned->GetTransport()->SetDeadline(
                std::chrono::steady_clock::now() + FAR_FUTURE_HANDOFF);
            UpstreamConnection* raw = owned.get();
            // Direct handoff: active gauge stays unchanged (same conn in
            // active container, just transferred to a new lease). Record
            // wait-time histogram for the queued waiter — outcome=queued_satisfied.
            auto wait_dur = std::chrono::duration_cast<std::chrono::duration<double>>(
                std::chrono::steady_clock::now() - wait_queue_.front().queued_at);
            active_conns_.push_back(std::move(owned));
            auto entry = std::move(wait_queue_.front());
            wait_queue_.pop_front();
            EmitCheckoutWaitDuration(wait_dur.count(), "queued_satisfied");
            // Bump inflight_leases_ BEFORE the handoff. The fetch_sub
            // at the top of ReturnConnection paired with the released
            // lease; this is a brand-new lease handed to a waiter and
            // needs its own increment so the waiter's eventual return
            // brings the counter back to balance. Without this the
            // counter goes negative on every queued-reuse handoff and
            // the observability shutdown drain never observes
            // active_leases() == 0.
            inflight_leases_.fetch_add(1, std::memory_order_acq_rel);
            entry.ready_callback(UpstreamLease(raw, this, alive_, off_dispatcher_release_drops_, dispatcher_));
            // No member access follows (function returns), but keep the
            // check for defense-in-depth against future refactors.
            if (!alive->load(std::memory_order_acquire)) return;
        } else {
            // No waiters, or connection is dead/expired — destroy it.
            // If waiters exist but connection is invalid, create a replacement.
            EmitActiveGaugeDelta(-1.0);
            DestroyConnection(std::move(owned));
            CreateForWaiters();
        }
        return;
    }

    // Set idle deadline for timeout scanning
    auto idle_deadline = std::chrono::steady_clock::now() +
                         std::chrono::seconds(config_.idle_timeout_sec);
    owned->GetTransport()->SetDeadline(idle_deadline);

    // Push to front (MRU). active -> idle: pair emits before potential
    // ServiceWaitQueue, which itself may pop this very entry back to active.
    idle_conns_.push_front(std::move(owned));
    EmitActiveGaugeDelta(-1.0);
    EmitIdleGaugeDelta(+1.0);

    // Service any waiting requests
    ServiceWaitQueue();
}

void PoolPartition::ReturnH2Stream(
    UpstreamH2Connection* h2_conn, int32_t stream_id,
    std::shared_ptr<std::atomic<bool>> /*partition_alive*/,
    std::shared_ptr<std::atomic<bool>> /*conn_alive*/) {
    // Structural no-op for SUBMITTED H2 streams. The slot-release
    // admission path lives in `UpstreamH2Connection::RunDeferredEraseWalk`
    // — the SOLE site of `--active_streams_` for submitted streams. That
    // walker ALSO invokes `DrainH2StreamWaitersForHost` +
    // `DrainAnyWaitersForFastH2` immediately after the decrement.
    //
    // By the time a non-donated `UpstreamLease::Kind::H2` lease
    // destructor reaches this method, one of two things has
    // happened: (a) the stream completed via peer close-stream and
    // the walker already drained, OR (b) `ProxyTransaction::Cleanup`
    // called `ResetStream` (via lease accessors) and the eventual
    // walker pass will drain. In NEITHER case does this method
    // have remaining work — adding a drain here would either
    // double-fire (case a) or fire against stale capacity (case b
    // before walker runs).
    //
    // Donated H2 leases (the H2 session's permanent transport
    // lease) skip this path via the `donated_to_h2_` check in the
    // `UpstreamLease` destructor (`upstream_lease.cc`).
    logging::Get()->debug(
        "PoolPartition::ReturnH2Stream: lease destruction "
        "(h2_conn={}, stream_id={}) — slot-release admission "
        "handled by RunDeferredEraseWalk; no-op",
        static_cast<const void*>(h2_conn), stream_id);
}

void PoolPartition::EvictExpired() {
    // Hoist alive_ — PurgeExpiredWaitEntries/ServiceWaitQueue can fire user
    // callbacks that tear down the pool/manager.
    auto alive_local = alive_;

    // Evict expired idle connections from back (LRU)
    auto now = std::chrono::steady_clock::now();

    auto it = idle_conns_.begin();
    while (it != idle_conns_.end()) {
        auto& conn = *it;
        bool expired = conn->IsExpired(config_.max_lifetime_sec,
                                        config_.max_requests_per_conn);
        bool idle_timeout = false;
        auto idle_duration = std::chrono::duration_cast<std::chrono::seconds>(
            now - conn->last_used_at());
        if (idle_duration.count() >= config_.idle_timeout_sec) {
            idle_timeout = true;
        }

        bool alive = conn->IsAlive();
        if (expired || idle_timeout || !alive) {
            logging::Get()->debug("Evicting idle upstream connection fd={} "
                                  "{}:{} (expired={} idle_timeout={} alive={})",
                                  conn->fd(), upstream_host_, upstream_port_,
                                  expired, idle_timeout, alive);
            auto owned = std::move(*it);
            it = idle_conns_.erase(it);
            // idle -> destroyed
            EmitIdleGaugeDelta(-1.0);
            DestroyConnection(std::move(owned));
        } else {
            ++it;
        }
    }

    PurgeExpiredWaitEntries();
    if (!alive_local->load(std::memory_order_acquire)) return;

    // Periodic H2 liveness sweep — drives PING idle/timeout per
    // session and reaps drained or PING-timed-out connections.
    h2_table_.TickAll(now);

    // Eviction freed capacity — retry queued checkouts.
    ServiceWaitQueue();
}

std::shared_ptr<void> PoolPartition::MakeInflightGuard() {
    inflight_tasks_->fetch_add(1, std::memory_order_relaxed);
    auto inflight = inflight_tasks_;
    return std::shared_ptr<void>(nullptr, [inflight](void*) {
        inflight->fetch_sub(1, std::memory_order_release);
    });
}

bool PoolPartition::ShouldOpenAdditionalH2Conn(
    const std::string& upstream_name)
{
    auto cfg = LoadHttp2ConfigSnapshot();
    if (!cfg || cfg->saturation_open_pct == 0) return false;
    if (TotalCount() >= partition_max_connections_) return false;
    if (cfg->max_concurrent_streams_pref == 0) return false;
    // CollectUsableForUpstream reaps expired entries inline, which
    // mutates h2_table_. Dispatcher-thread-only, idempotent: dead
    // entries don't count toward saturation either way.
    auto candidates = h2_table_.CollectUsableForUpstream(upstream_name);
    if (candidates.empty()) return false;  // cold-start handles first
    const int threshold = cfg->saturation_open_pct;
    for (auto* c : candidates) {
        // EffectiveMaxStreams clamps to peer SETTINGS — a session that
        // hit its peer-imposed limit BELOW our local pref is saturated
        // at the peer cap; using local pref alone hides that pressure.
        const uint32_t eff_cap = c->EffectiveMaxStreams();
        if (eff_cap == 0) continue;  // session not usable — skip
        const int ratio_pct = ComputeStreamUtilizationPct(
            c->active_stream_count(), eff_cap);
        if (ratio_pct < threshold) return false;  // one still has slack
    }
    return true;
}

UpstreamH2Connection* PoolPartition::FindUsableH2ConnectionSaturation(
    const std::string& upstream_name)
{
    auto cfg = LoadHttp2ConfigSnapshot();
    // Disabled fast path — saturation_open_pct=0 collapses to the
    // existing first-usable semantic.
    if (!cfg || cfg->saturation_open_pct == 0) {
        return FindUsableH2Connection(upstream_name);
    }
    const int threshold = cfg->saturation_open_pct;
    auto candidates = h2_table_.CollectUsableForUpstream(upstream_name);
    for (auto* candidate : candidates) {
        UpstreamConnection* t = candidate->transport();
        if (!t || !ConnectionEndpointMatches(*t)) {
            // Endpoint stale (post-reload IP swap). Mark dead — the
            // table walker reaps on next CollectUsable.
            candidate->MarkDead();
            continue;
        }
        const uint32_t eff_cap = candidate->EffectiveMaxStreams();
        if (eff_cap == 0) continue;  // session not usable — skip
        const int ratio_pct = ComputeStreamUtilizationPct(
            candidate->active_stream_count(), eff_cap);
        if (ratio_pct < threshold) return candidate;
        // Over threshold — skip; caller may use fallback path or
        // trigger a capacity probe.
    }
    return nullptr;
}

void PoolPartition::MaybePreconnectH2(
    const std::string& upstream_name, int port,
    const UpstreamH2Connection& picked_session)
{
    auto cfg = LoadHttp2ConfigSnapshot();
    if (!cfg) return;
    if (cfg->preconnect_watermark_pct == 0) return;  // disabled fast path
    // Validator already rejects (preconnect > 0 && saturation == 0)
    // at both Validate and ValidateHotReloadable, but check the SIGHUP
    // race window here too: the snapshot we just loaded may have
    // saturation flipped to 0 between when the operator submitted the
    // reload AND our read. Defensive: skip the probe in that case
    // (the firing condition is undefined when saturation is off).
    if (cfg->saturation_open_pct == 0) return;
    if (cfg->max_concurrent_streams_pref == 0) return;  // infinite capacity
    // Use the picked session's EFFECTIVE cap (peer SETTINGS-clamped) so
    // utilization tracks the wire-level cap, not the configured one.
    const uint32_t picked_cap = picked_session.EffectiveMaxStreams();
    if (picked_cap == 0) return;  // picked session not usable
    const int ratio_pct = ComputeStreamUtilizationPct(
        picked_session.active_stream_count(), picked_cap);
    // Firing condition: in the (watermark, saturation) window. AT/below
    // watermark → no preconnect (operator says we're not stressed yet).
    // AT/above saturation → saturation routing already opens a fresh
    // probe; preconnect would duplicate.
    if (ratio_pct < cfg->preconnect_watermark_pct) return;
    if (ratio_pct >= cfg->saturation_open_pct) return;

    // Fleet-wide spare check: do not open another warm spare if one
    // already exists. Without this, A at 60% (in window) + B at 0%
    // (spare) → each request picks A and fires another preconnect
    // until pool.max_connections fills with idle warm spares.
    // Spare = any OTHER usable session whose utilization is below the
    // watermark (operator's "this session has slack" signal).
    //
    // Endpoint-aware: a stale-endpoint candidate (DNS swapped, session
    // about to be retired) must NOT count as a spare — otherwise
    // preconnect is suppressed on a session that won't survive the
    // next dispatch. Mark stale candidates dead inline so the next
    // FindUsable / CollectUsable skips them (mirrors
    // FindUsableH2Connection's defensive eviction).
    auto candidates = h2_table_.CollectUsableForUpstream(upstream_name);
    for (auto* c : candidates) {
        if (c == &picked_session) continue;  // not a spare; this is the picked one
        UpstreamConnection* t = c->transport();
        if (!t || !ConnectionEndpointMatches(*t)) {
            c->MarkDead();
            continue;
        }
        const uint32_t cap = c->EffectiveMaxStreams();
        if (cap == 0) continue;  // not usable — skip
        const int cand_pct = ComputeStreamUtilizationPct(
            c->active_stream_count(), cap);
        if (cand_pct < cfg->preconnect_watermark_pct) {
            // Spare already available — skip preconnect.
            return;
        }
    }
    // Delegate the actual probe to StartH2CapacityProbe so the
    // capacity-probe semantics (shutdown / in-flight-probe / cap
    // gates) are applied uniformly. Note: StartH2CapacityProbe
    // itself consults ShouldOpenAdditionalH2Conn which returns false
    // when ANY conn is under-saturation. The picked session is
    // currently under-saturation (firing condition above) — so
    // ShouldOpenAdditionalH2Conn returns false, and the preconnect
    // would be skipped. That's the wrong policy for preconnect:
    // saturation-routing wants ALL conns saturated; preconnect wants
    // ANY conn at/above watermark. We therefore bypass the
    // ShouldOpenAdditionalH2Conn gate by inlining the remaining
    // (cap + in-flight-probe) checks.
    if (shutting_down_.load(std::memory_order_acquire) ||
        manager_shutting_down_.load(std::memory_order_acquire)) {
        return;
    }
    HostPortKey key{upstream_name, port};
    if (h2_connecting_conns_.count(key) > 0) return;  // probe in flight
    if (TotalCount() >= partition_max_connections_) {
        preconnect_skipped_cap_count_.fetch_add(1, std::memory_order_relaxed);
        logging::Get()->warn(
            "MaybePreconnectH2 skipped (TotalCount {} >= cap {}) "
            "upstream={}:{} — slot starvation prevention",
            TotalCount(), partition_max_connections_, upstream_name, port);
        return;
    }
    logging::Get()->debug(
        "MaybePreconnectH2: firing preconnect probe upstream={}:{} "
        "(ratio_pct={}, watermark={}, saturation={})",
        upstream_name, port, ratio_pct,
        cfg->preconnect_watermark_pct, cfg->saturation_open_pct);
    // Only count successful dispatches (OpenNewH2Connection returns
    // false for missing TLS context / shutdown / construct errors;
    // a pre-bump would lie about probe activity in those failure paths).
    if (OpenNewH2Connection(upstream_name, port)) {
        preconnect_fired_count_.fetch_add(1, std::memory_order_relaxed);
    }
}

void PoolPartition::StartH2CapacityProbe(
    const std::string& upstream_name, int port)
{
    if (shutting_down_.load(std::memory_order_acquire) ||
        manager_shutting_down_.load(std::memory_order_acquire)) {
        logging::Get()->debug(
            "StartH2CapacityProbe skipped (shutdown) upstream={}:{}",
            upstream_name, port);
        return;
    }
    HostPortKey key{upstream_name, port};
    if (h2_connecting_conns_.count(key) > 0) {
        logging::Get()->debug(
            "StartH2CapacityProbe skipped (in-flight probe exists) "
            "upstream={}:{}",
            upstream_name, port);
        return;
    }
    // Policy gate: the WHOLE point of capacity probe is admitting
    // alongside existing usable sessions when saturation/preconnect
    // says we need more capacity. Unlike StartH2ReplacementConnect
    // (which refuses on `FindUsable != nullptr`), this helper OMITS
    // the "any usable session exists" check — but it still defers
    // to the policy gate so we don't probe unnecessarily.
    if (!ShouldOpenAdditionalH2Conn(upstream_name)) {
        logging::Get()->debug(
            "StartH2CapacityProbe skipped (policy says no more probes) "
            "upstream={}:{}",
            upstream_name, port);
        return;
    }
    if (TotalCount() >= partition_max_connections_) {
        // Cap-saturated — defensive duplicate of the gate inside
        // ShouldOpenAdditionalH2Conn (which already covers this);
        // warn-level so operators see the cap pressure correlated
        // with capacity-probe attempts.
        logging::Get()->warn(
            "StartH2CapacityProbe skipped (TotalCount {} >= cap {}) "
            "upstream={}:{} — capacity probe deferred",
            TotalCount(), partition_max_connections_, upstream_name, port);
        return;
    }
    OpenNewH2Connection(upstream_name, port);
}

UpstreamH2Connection* PoolPartition::FindUsableH2Connection(
    const std::string& upstream_name)
{
    // Multi-conn-per-host walk (B2.2). Iterate every usable candidate
    // for the upstream; for each, check endpoint freshness against
    // the partition's current resolved_endpoint_. The first
    // endpoint-fresh candidate wins; stale candidates are marked
    // dead inline so a subsequent FindUsable / CollectUsable skips
    // them (existing pre-B2 semantic preserved). Returns null when
    // no endpoint-fresh usable session exists for the upstream — the
    // caller decides whether to admit a new probe (cold-start /
    // saturation / preconnect) or fall back.
    auto candidates = h2_table_.CollectUsableForUpstream(upstream_name);
    for (auto* candidate : candidates) {
        UpstreamConnection* t = candidate->transport();
        if (t && ConnectionEndpointMatches(*t)) {
            return candidate;
        }
        candidate->MarkDead();
    }
    return nullptr;
}

void PoolPartition::WireH2SessionTransportCallbacks(
    UpstreamConnection* up, UpstreamH2Connection* raw)
{
    if (!up || !raw) return;
    auto transport = up->GetTransport();
    if (!transport) return;
    auto alive = raw->alive_token();

    // Drop any one-shot connect/handshake closures inherited from the
    // cold-start probe path. They are consumed-on-fire in
    // connection_handler.cc so a stale residual is harmless today, but
    // the H2 session's alive-token discipline assumes no closures from
    // earlier owners survive across the promotion boundary.
    transport->SetConnectCompleteCallback(nullptr);
    transport->SetHandshakeCompleteCallback(nullptr);

    // Callbacks wired BEFORE Init() because Init's preface flush can
    // fire complete_callback synchronously on a writable transport
    // (DoSendRaw direct-write path) — our drain attribution must be
    // active for that bootstrap traffic. The H2 connection
    // multiplexes the transport for its lifetime; pool accounting
    // follows the lease destructor when the H2 connection retires.
    // Dual-token capture: alive-flag-then-raw. The dtor flips alive
    // before nulling these callbacks, so an in-flight invocation sees
    // a false load and short-circuits before dereferencing `raw`.
    transport->SetOnMessageCb(
        [raw, alive](std::shared_ptr<ConnectionHandler>, std::string& data) {
            if (!alive->load(std::memory_order_acquire)) return;
            ssize_t rv = raw->HandleBytes(data.data(), data.size());
            if (rv < 0) {
                // MarkDead BEFORE the fail-fan-out so a concurrent
                // FindUsable can't pick this conn between the in-flight
                // streams being failed and the table eviction. See the
                // UPSTREAM_PROXY.md pitfall on dead_ vs goaway_seen_.
                raw->MarkDead();
                raw->FailAllStreams(
                    ProxyTransaction::RESULT_UPSTREAM_DISCONNECT,
                    "h2 session fatal error");
                data.clear();
                return;
            }
            // nghttp2_session_mem_recv2 contracts to consume the entire
            // input on success — UpstreamH2Connection::HandleBytes returns
            // either rv<0 or rv==len. Be defensive against future contract
            // drift: erase only the consumed prefix and log loudly so a
            // partial-consume regression surfaces in tests / staging.
            const size_t consumed = static_cast<size_t>(rv);
            if (consumed < data.size()) {
                logging::Get()->error(
                    "H2 HandleBytes partial consume: rv={} of {} bytes — "
                    "preserving remainder; nghttp2 contract drift?",
                    consumed, data.size());
                data.erase(0, consumed);
            } else {
                data.clear();
            }
        });
    transport->SetCloseCb(
        [raw, alive](std::shared_ptr<ConnectionHandler>) {
            if (!alive->load(std::memory_order_acquire)) return;
            // MarkDead BEFORE FailAllStreams (mirrors PING-timeout and
            // session-fatal-error sites). A FindUsable racing the
            // fan-out would otherwise see streams_.empty() with
            // dead_=false and return this conn, whose transport is
            // already gone.
            raw->MarkDead();
            raw->FailAllStreams(
                ProxyTransaction::RESULT_UPSTREAM_DISCONNECT,
                "transport closed");
        });
    // EPOLLERR / EVENT_ERR is routed through SetErrorCb only — the
    // close callback is deliberately suppressed on the error path
    // (`connection_handler.cc` comments "NOT close handler — avoid
    // duplicate callbacks"). Without an error hook here, a pure
    // EPOLLERR on an H2 transport would tear down the channel
    // without notifying nghttp2: queued streams would hang until
    // their per-transaction response timeout instead of failing
    // immediately. Mirror SetCloseCb's MarkDead + FailAllStreams.
    transport->SetErrorCb(
        [raw, alive](std::shared_ptr<ConnectionHandler>) {
            if (!alive->load(std::memory_order_acquire)) return;
            raw->MarkDead();
            raw->FailAllStreams(
                ProxyTransaction::RESULT_UPSTREAM_DISCONNECT,
                "transport error");
        });
    // Drive request-side sink virtuals from REAL transport drain (not
    // from nghttp2 frame serialization). The H2 session enqueues every
    // outbound HEADERS/DATA frame into its drain_queue_ inside
    // on_frame_send_callback; these two hooks pop the queue as bytes
    // actually leave the transport buffer, then dispatch
    // OnRequestBodyProgress / OnRequestSubmitted on the corresponding
    // stream's sink. Matches H1's transport-callback-driven semantic.
    transport->SetWriteProgressCb(
        [raw, alive](std::shared_ptr<ConnectionHandler>, size_t remaining) {
            if (!alive->load(std::memory_order_acquire)) return;
            raw->OnTransportWriteProgress(remaining);
        });
    transport->SetCompletionCb(
        [raw, alive](std::shared_ptr<ConnectionHandler>) {
            if (!alive->load(std::memory_order_acquire)) return;
            raw->OnTransportWriteComplete();
        });
}

UpstreamH2Connection* PoolPartition::AcquireH2Connection(
    const std::string& upstream_name, UpstreamLease& lease)
{
    // Saturation-aware reuse: try an under-threshold endpoint-fresh
    // session first; if one exists, multiplex onto it (caller's lease
    // is untouched). If every usable session is over-threshold, decide
    // whether to admit a new H2 conn (via the fresh-construct branch
    // below) OR fall back to an over-threshold session for THIS
    // request (saturated session is still better than blocking).
    if (auto* existing = FindUsableH2ConnectionSaturation(upstream_name)) {
        return existing;
    }
    // Fall back to first-usable when (a) saturation policy does not
    // warrant a new conn, OR (b) the caller passed an empty lease.
    // The empty-lease case fires when TryDispatchExistingH2Session has
    // already picked an over-threshold-but-usable session and re-enters
    // through DispatchH2 → AcquireH2Connection: fresh-construct is
    // impossible without a transport handle in the lease, so the only
    // viable answer is to return that same session via FindUsable.
    if (!ShouldOpenAdditionalH2Conn(upstream_name) || !lease.Get()) {
        if (auto* existing = FindUsableH2Connection(upstream_name)) {
            return existing;
        }
    }
    // Saturation says open a new one. Fall through to fresh-construct.

    auto cfg = LoadHttp2ConfigSnapshot();
    if (!cfg || !cfg->enabled) return nullptr;

    auto* up = lease.Get();
    if (!up) return nullptr;
    auto transport = up->GetTransport();
    if (!transport) return nullptr;

    auto h2 = std::make_unique<UpstreamH2Connection>(up, cfg);
    UpstreamH2Connection* raw = h2.get();

    WireH2SessionTransportCallbacks(up, raw);

    if (!h2->Init()) {
        logging::Get()->warn(
            "PoolPartition::AcquireH2Connection: Init failed upstream={} "
            "host={}:{}",
            upstream_name, upstream_host_, upstream_port_);
        // Unwire before transport returns — dtor's alive-flip handles
        // the race, but null'ing now closes it inline.
        ClearTransportCallbacks(up);
        return nullptr;
    }

    // SetPartition BEFORE AdoptLease so the lease-to-donation counter
    // swap inside AdoptLease can find the manager-level atomic refs.
    h2->SetPartition(this);
    h2->AdoptLease(std::move(lease));
    h2_table_.Insert(upstream_name, std::move(h2));
    // Drain happens at ProxyTransaction::DispatchH2 AFTER SubmitRequest,
    // not here — firing other ANY-kind waiters before the creator
    // submits would let them race through TryDispatchExistingH2Session
    // and consume the only stream slot under max_concurrent_streams=1.
    return raw;
}

void PoolPartition::ScheduleInitiateShutdown(int server_drain_timeout_sec) {
    // Direct call if no dispatcher (degenerate/test path).
    if (!dispatcher_) {
        InitiateShutdown(server_drain_timeout_sec);
        return;
    }
    // Already on the dispatcher thread — run inline.
    if (dispatcher_->is_dispatcher_thread()) {
        InitiateShutdown(server_drain_timeout_sec);
        return;
    }
    // Dispatcher already stopped (threads joined) — EnQueue would silently
    // drop the lambda, leaving idle/connecting connections alive and the
    // outstanding_conns_ counter stuck above zero, which would hang
    // ~UpstreamManager's drain wait forever. Run inline: no dispatcher
    // thread exists to race with container mutations, so touching
    // idle_conns_/connecting_conns_ from the stopper thread is safe.
    if (dispatcher_->was_stopped()) {
        InitiateShutdown(server_drain_timeout_sec);
        return;
    }
    // Off-thread: enqueue and track via MakeInflightGuard so ~PoolPartition
    // blocks until the lambda has executed (or been dropped by a stopped
    // dispatcher). Guarded by alive_weak so a task that somehow races past
    // the destructor is a no-op instead of a UAF on freed containers.
    auto guard = MakeInflightGuard();
    std::weak_ptr<std::atomic<bool>> alive_weak = alive_;
    dispatcher_->EnQueue(
        [this, alive_weak, guard, server_drain_timeout_sec]() {
            auto alive = alive_weak.lock();
            if (!alive || !alive->load(std::memory_order_acquire)) return;
            InitiateShutdown(server_drain_timeout_sec);
        });
}

void PoolPartition::ScheduleForceCloseActive() {
    if (!dispatcher_) {
        ForceCloseActive();
        return;
    }
    if (dispatcher_->is_dispatcher_thread()) {
        ForceCloseActive();
        return;
    }
    if (dispatcher_->was_stopped()) {
        ForceCloseActive();
        return;
    }
    auto guard = MakeInflightGuard();
    std::weak_ptr<std::atomic<bool>> alive_weak = alive_;
    dispatcher_->EnQueue([this, alive_weak, guard]() {
        auto alive = alive_weak.lock();
        if (!alive || !alive->load(std::memory_order_acquire)) return;
        ForceCloseActive();
    });
}

// Compute the H2 graceful-drain budget in milliseconds.
// server_drain_timeout_sec=0 means "shut down immediately with no
// graceful H2 drain" (safety-net destructor call passes 0; an
// operator setting `server.shutdown_drain_timeout_sec=0` opts out).
// Per-conn `http2.goaway_drain_timeout_sec=0` likewise opts out at
// the connection level. Either zero → 0 (immediate-destroy path);
// both non-zero → min(server, per_conn) * 1000 so the per-conn drain
// is bounded by the whole-server SLA. Operators wanting a non-zero
// per-conn drain must set BOTH fields to positive values.
static int ComputeShutdownDrainBudgetMs(int per_conn_sec,
                                        int server_sec) {
    if (per_conn_sec <= 0 || server_sec <= 0) return 0;
    int min_sec = std::min(per_conn_sec, server_sec);
    return min_sec * 1000;
}

void PoolPartition::InitiateShutdown(int server_drain_timeout_sec) {
    // Hoist alive_ onto the stack — ForceClose on connecting sockets fires
    // the close callback which invokes the waiter's user error_callback,
    // and the wait-queue rejection loop below invokes error_callback directly.
    // Either may synchronously tear down the pool/manager.
    auto alive = alive_;

    shutting_down_.store(true, std::memory_order_release);

    // Close all idle connections (no user callbacks — pool-owned)
    while (!idle_conns_.empty()) {
        auto conn = std::move(idle_conns_.front());
        idle_conns_.pop_front();
        EmitIdleGaugeDelta(-1.0);
        DestroyConnection(std::move(conn));
    }

    // Force-close all connecting connections. Use ForceClose() instead of
    // DestroyConnection() so the close callback fires and delivers
    // CHECKOUT_CONNECT_FAILED to the caller's error_cb. DestroyConnection
    // would clear callbacks first, leaving callers' promises unresolved.
    // ForceClose → CallCloseCb → close callback → error_cb + OnConnectionClosed
    // which extracts from connecting_conns_ and decrements outstanding_conns_.
    // Iterate while non-empty: each ForceClose removes the front entry via
    // OnConnectionClosed, so the loop converges.
    while (!connecting_conns_.empty()) {
        auto& conn = connecting_conns_.front();
        if (conn && conn->GetTransport() && !conn->GetTransport()->IsClosing()) {
            conn->GetTransport()->ForceClose();
            if (!alive->load(std::memory_order_acquire)) return;
        } else {
            // Transport already closing or null — extract and destroy manually
            auto orphan = std::move(connecting_conns_.front());
            connecting_conns_.erase(connecting_conns_.begin());
            if (orphan) {
                ClearTransportCallbacks(orphan.get());
                outstanding_conns_.fetch_sub(1, std::memory_order_release);
            }
        }
    }

    // Reject all waiters
    while (!wait_queue_.empty()) {
        auto entry = std::move(wait_queue_.front());
        wait_queue_.pop_front();
        // Cancelled waiters have no callback to fire — the transaction
        // already tore its side down via the framework abort hook.
        if (IsEntryCancelled(entry)) {
            continue;
        }
        entry.error_callback(CHECKOUT_SHUTTING_DOWN);
        if (!alive->load(std::memory_order_acquire)) return;
    }

    // Retire H2 sessions. Two paths: graceful drain (drain_budget_ms > 0)
    // OR immediate kill (drain_budget_ms == 0). The graceful path emits
    // GOAWAY on each session via BeginShutdownDrain (which also sets
    // goaway_seen_ so IsUsable rejects new submissions immediately),
    // then schedules PollShutdownDrain to reap sessions as they complete
    // OR force-close them at the deadline. The immediate path uses
    // ExtractAll + DestroyOnDispatcher (mirrors the pre-Phase-4
    // behavior — used by the destructor safety-net call where any
    // wait would block destruction).
    auto h2_cfg_for_drain = LoadHttp2ConfigSnapshot();
    const int per_conn_drain_sec = h2_cfg_for_drain
        ? h2_cfg_for_drain->goaway_drain_timeout_sec : 0;
    const int drain_budget_ms = ComputeShutdownDrainBudgetMs(
        per_conn_drain_sec, server_drain_timeout_sec);
    if (drain_budget_ms <= 0) {
        // Immediate kill (legacy path / destructor safety-net).
        auto h2_to_destroy = h2_table_.ExtractAll();
        for (auto& conn : h2_to_destroy) {
            if (conn) conn->DestroyOnDispatcher();
            if (!alive->load(std::memory_order_acquire)) return;
        }
    } else {
        // Graceful drain. BeginShutdownDrain emits GOAWAY + sets
        // goaway_seen_ + records the deadline; the session stays in
        // h2_table_ while in-flight streams complete. PollShutdownDrain
        // (kicked off below) reaps each session as IsShutdownDrainComplete
        // becomes true (streams empty / transport dead / deadline elapsed).
        //
        // Reentrant-delete UAF guard: BeginShutdownDrain → FlushSend can
        // fail synchronously, fire transport close-cb → FailAllStreams →
        // sink->OnError → ProxyTransaction::MaybeRetry → AcquireH2Connection
        // → h2_table_.CollectUsableForUpstream (which reaps IsExpired
        // entries inline). After BeginShutdownDrain runs, the session is
        // (goaway_seen=true, streams=empty) → IsExpired=true. A raw
        // snapshot would dangle when the synchronous chain reaps the
        // unique_ptr the loop is currently working through (or any
        // later snapshot entry that became expired via a sibling close-
        // cb's FailAllStreams). Take owning unique_ptrs out of h2_table_
        // BEFORE the BeginShutdownDrain loop; reentrant FindUsable then
        // sees an empty table (shutting_down_ is already set so no fresh
        // admissions). Re-insert under the preserved upstream-name key
        // after the loop completes so PollShutdownDrain can walk them
        // via the canonical reap path.
        auto owned = h2_table_.ExtractAllWithKeys();
        for (auto& [_, conn] : owned) {
            if (!conn) continue;
            conn->BeginShutdownDrain(drain_budget_ms);
            if (!alive->load(std::memory_order_acquire)) return;
        }
        for (auto& [name, conn] : owned) {
            if (conn) h2_table_.Insert(name, std::move(conn));
        }
        // Kick off the poll loop. PollShutdownDrain re-arms itself while
        // any session is still draining; idempotent if the table is
        // already empty (it's a no-op).
        if (dispatcher_ && !dispatcher_->was_stopped()) {
            auto guard = MakeInflightGuard();
            std::weak_ptr<std::atomic<bool>> alive_weak = alive_;
            dispatcher_->EnQueueDelayed(
                [this, alive_weak, guard]() {
                    auto local = alive_weak.lock();
                    if (!local || !local->load(std::memory_order_acquire)) return;
                    PollShutdownDrain();
                },
                std::chrono::milliseconds(50));
        } else {
            // No dispatcher to schedule on — fall back to immediate
            // kill so we don't leave sessions stranded.
            auto h2_to_destroy = h2_table_.ExtractAll();
            for (auto& conn : h2_to_destroy) {
                if (conn) conn->DestroyOnDispatcher();
                if (!alive->load(std::memory_order_acquire)) return;
            }
        }
    }

    // Connecting H2 probes: extract first, then destroy. Mirrors the
    // h2_table_.ExtractAll() pattern above — DestroyOnDispatcher can
    // reentrantly mutate h2_connecting_conns_ via lease-return
    // chains, so iterating-by-reference on the live map would invalidate
    // iterators.
    std::vector<std::unique_ptr<UpstreamH2Connection>> probes_to_destroy;
    probes_to_destroy.reserve(h2_connecting_conns_.size());
    for (auto& kv : h2_connecting_conns_) {
        if (kv.second) probes_to_destroy.push_back(std::move(kv.second));
    }
    h2_connecting_conns_.clear();
    for (auto& probe : probes_to_destroy) {
        if (probe) probe->DestroyOnDispatcher();
        if (!alive->load(std::memory_order_acquire)) return;
    }

    // Drain any GOAWAY victims sitting in the pending-destroy stash so
    // their leases also release before the drain wait below. Also
    // empties pending_h2_replacement_targets_ — no point starting
    // replacement probes during shutdown.
    pending_h2_replacement_targets_.clear();
    ReapPendingDestroyH2Conns();

    // Active connections will be destroyed when returned via ReturnConnection
    MaybeSignalDrain();
}

void PoolPartition::DrainWaitQueueOnTrip() {
    // Hoist alive_ — a waiter's error_callback may synchronously trigger
    // a request completion path that tears down the partition (e.g. the
    // test harness). Same pattern used by InitiateShutdown.
    auto alive = alive_;

    if (shutting_down_.load(std::memory_order_acquire)) {
        // Already draining via InitiateShutdown — that path will send
        // CHECKOUT_SHUTTING_DOWN to every waiter. Don't double-fire.
        return;
    }

    if (wait_queue_.empty()) return;

    logging::Get()->info(
        "PoolPartition draining wait queue on breaker trip: {}:{} "
        "queue_size={}",
        upstream_host_, upstream_port_, wait_queue_.size());

    while (!wait_queue_.empty()) {
        auto entry = std::move(wait_queue_.front());
        wait_queue_.pop_front();
        // Cancelled waiters have no callback to fire — the transaction
        // already tore its side down via the framework abort hook.
        if (IsEntryCancelled(entry)) {
            continue;
        }
        // CHECKOUT_CIRCUIT_OPEN — ProxyTransaction::OnCheckoutError maps
        // to RESULT_CIRCUIT_OPEN and delivers MakeCircuitOpenResponse()
        // without touching the breaker (our own reject, don't feed back).
        entry.error_callback(CHECKOUT_CIRCUIT_OPEN);
        if (!alive->load(std::memory_order_acquire)) return;
    }
}

void PoolPartition::StoreResolvedEndpoint(
    std::shared_ptr<const NET_DNS_NAMESPACE::ResolvedEndpoint> new_ep)
{
    std::atomic_store_explicit(&resolved_endpoint_,
                                std::move(new_ep),
                                std::memory_order_release);
}

void PoolPartition::ApplyHttp2ConfigCommit(
    std::shared_ptr<const Http2UpstreamConfig> snapshot)
{
    std::atomic_store_explicit(&http2_config_snapshot_,
                                std::move(snapshot),
                                std::memory_order_release);
}

void PoolPartition::EnqueueIdleCleanupOnEndpointChange(
    std::shared_ptr<const NET_DNS_NAMESPACE::ResolvedEndpoint> old_ep)
{
    if (!old_ep) return;
    if (shutting_down_.load(std::memory_order_acquire)) return;
    if (!dispatcher_) return;
    if (dispatcher_->was_stopped()) return;

    auto guard = MakeInflightGuard();
    std::weak_ptr<std::atomic<bool>> alive_weak = alive_;
    dispatcher_->EnQueue(
        [this, alive_weak, guard, old_ep = std::move(old_ep)]() mutable {
            auto alive = alive_weak.lock();
            if (!alive || !alive->load(std::memory_order_acquire)) return;
            CloseIdleMatchingEndpointOnDispatcher(old_ep);
        });
}

void PoolPartition::CloseIdleMatchingEndpointOnDispatcher(
    const std::shared_ptr<const NET_DNS_NAMESPACE::ResolvedEndpoint>& old_ep)
{
    auto it = idle_conns_.begin();
    while (it != idle_conns_.end()) {
        if ((*it)->captured_endpoint() == old_ep) {
            auto owned = std::move(*it);
            it = idle_conns_.erase(it);
            // Balance the +1 idle gauge emitted in ReturnConnection. Without
            // this, every reload that adopts a new endpoint leaks one tick
            // on reactor.upstream.pool.connections.idle per evicted conn.
            EmitIdleGaugeDelta(-1.0);
            DestroyConnection(std::move(owned));
        } else {
            ++it;
        }
    }
    // Drop cached H2 negotiation outcomes that referenced the old
    // endpoint. The endpoint-match check in ShouldSkipH2ProbeForEndpoint
    // is the primary gate (stale entries would harmlessly miss); this
    // sweep keeps the cache lean so it doesn't accumulate unreachable
    // entries across reload churn.
    InvalidateH2NegotiationCacheForEndpoint(old_ep);
}

void PoolPartition::PollShutdownDrain() {
    if (!alive_->load(std::memory_order_acquire)) return;
    const auto now = std::chrono::steady_clock::now();
    // Two-phase walk to defuse a reentrant-erase UAF: `DestroyOnDispatcher`
    // synchronously fires `FailAllStreams` → `sink->OnError(...)` for every
    // surviving stream; a sink callback can reenter partition code that
    // calls `FindUsableH2Connection` / `CollectUsableForUpstream`, which
    // reaps `IsExpired` entries from `h2_table_` mid-walk. If a still-to-
    // be-processed raw pointer in our snapshot is the one reaped, the next
    // iteration's `IsShutdownDrainComplete` reads freed memory.
    //
    // Phase 1: walk the snapshot, Extract every drain-complete session
    // into a local owning vector. The unique_ptrs keep the H2 conns
    // alive across any reentrant `h2_table_` mutations.
    // Phase 2: destroy from the local vector — reentrant lookups find
    // an empty h2_table_ (post-Extract) and cannot dangling-pointer us.
    auto snap = h2_table_.CollectAll();
    std::vector<std::unique_ptr<UpstreamH2Connection>> to_destroy;
    to_destroy.reserve(snap.size());
    for (auto* conn : snap) {
        if (!conn->IsShutdownDrainComplete(now)) continue;
        if (auto owned = h2_table_.Extract(conn)) {
            to_destroy.push_back(std::move(owned));
        }
    }
    for (auto& owned : to_destroy) {
        // Canonical 6-step teardown (alive flip → null callbacks →
        // remove timer → teardown session → fail streams → mark
        // closing). The dtor's safety-net path short-circuits on
        // `destroyed_on_dispatcher_=true` when `owned` lapses at the
        // end of the local vector's iteration.
        owned->DestroyOnDispatcher();
        if (!alive_->load(std::memory_order_acquire)) return;
    }
    // Also drain pending-destroy stash so its donated leases release
    // and outstanding_conns_ decrements toward zero. This is the same
    // helper the normal recv-flush chain calls — calling it here
    // catches any victims that arrived during shutdown (e.g. peer
    // GOAWAYs while we were draining).
    ReapPendingDestroyH2Conns();

    // Re-arm while any session is still draining OR any pending-destroy
    // victim awaits its post-flush reap. Loop exits naturally when both
    // are empty — every IsShutdownDrainComplete predicate eventually
    // fires on the deadline branch even if streams never complete.
    if ((h2_table_.TotalConnections() == 0 &&
         pending_destroy_h2_conns_.empty()) ||
        !dispatcher_ || dispatcher_->was_stopped()) {
        // Drain complete (or dispatcher gone — bail). Signal any
        // manager-level WaitForDrain waiters.
        MaybeSignalDrain();
        return;
    }
    auto guard = MakeInflightGuard();
    std::weak_ptr<std::atomic<bool>> alive_weak = alive_;
    dispatcher_->EnQueueDelayed(
        [this, alive_weak, guard]() {
            auto local = alive_weak.lock();
            if (!local || !local->load(std::memory_order_acquire)) return;
            PollShutdownDrain();
        },
        std::chrono::milliseconds(50));
}

void PoolPartition::RecordH2NegotiationOutcome(
    const std::string& upstream_name, int port,
    H2NegotiationOutcome outcome,
    std::shared_ptr<const NET_DNS_NAMESPACE::ResolvedEndpoint> endpoint)
{
    if (!endpoint) return;  // No endpoint to key the cache on.
    HostPortKey key{upstream_name, port};
    auto it = h2_negotiation_outcome_.find(key);
    if (it == h2_negotiation_outcome_.end()) {
        // Cap enforcement before inserting a new key.
        if (h2_negotiation_outcome_.size() >= kH2NegotiationCacheCap &&
            !h2_negotiation_outcome_order_.empty()) {
            HostPortKey evict = h2_negotiation_outcome_order_.front();
            h2_negotiation_outcome_order_.pop_front();
            h2_negotiation_outcome_.erase(evict);
            logging::Get()->warn(
                "PoolPartition: h2_negotiation_outcome cache cap reached "
                "({}); evicting LRU entry {}:{}",
                kH2NegotiationCacheCap, evict.host, evict.port);
        }
        h2_negotiation_outcome_[key] = {outcome, std::move(endpoint)};
        h2_negotiation_outcome_order_.push_back(key);
    } else {
        // Update outcome + endpoint; refresh insertion order to back.
        it->second.outcome = outcome;
        it->second.endpoint = std::move(endpoint);
        auto order_it = std::find(h2_negotiation_outcome_order_.begin(),
                                  h2_negotiation_outcome_order_.end(), key);
        if (order_it != h2_negotiation_outcome_order_.end()) {
            h2_negotiation_outcome_order_.erase(order_it);
        }
        h2_negotiation_outcome_order_.push_back(key);
    }
}

bool PoolPartition::ShouldSkipH2ProbeForEndpoint(
    const std::string& upstream_name, int port,
    const std::shared_ptr<const NET_DNS_NAMESPACE::ResolvedEndpoint>&
        current_endpoint) const
{
    if (!current_endpoint) return false;
    auto it = h2_negotiation_outcome_.find(HostPortKey{upstream_name, port});
    if (it == h2_negotiation_outcome_.end()) return false;
    if (it->second.outcome != H2NegotiationOutcome::H1Only) return false;
    // Endpoint identity comparison (shared_ptr equality): a DNS swap
    // produces a fresh ResolvedEndpoint object even if the address
    // happens to be the same, so this correctly invalidates after
    // re-resolution.
    return it->second.endpoint == current_endpoint;
}

void PoolPartition::InvalidateH2NegotiationCacheForEndpoint(
    const std::shared_ptr<const NET_DNS_NAMESPACE::ResolvedEndpoint>& old_ep)
{
    if (!old_ep) return;
    for (auto it = h2_negotiation_outcome_.begin();
         it != h2_negotiation_outcome_.end();) {
        if (it->second.endpoint == old_ep) {
            HostPortKey k = it->first;
            it = h2_negotiation_outcome_.erase(it);
            auto order_it = std::find(h2_negotiation_outcome_order_.begin(),
                                       h2_negotiation_outcome_order_.end(), k);
            if (order_it != h2_negotiation_outcome_order_.end()) {
                h2_negotiation_outcome_order_.erase(order_it);
            }
        } else {
            ++it;
        }
    }
}

void PoolPartition::ForceCloseActive() {
    // Collect transports + borrower callbacks, then move to zombie, then
    // close transports, then notify borrowers. This ordering ensures:
    // 1. Connections are in zombie_conns_ before notifications (so
    //    ReturnConnection finds them if the borrower releases the lease)
    // 2. Callbacks are copied before ClearTransportCallbacks nulls them
    // 3. No iteration over active_conns_ during mutation
    struct CloseWork {
        std::shared_ptr<ConnectionHandler> transport;
        CALLBACKS_NAMESPACE::ConnOnMsgCallback on_msg;
        int fd;
    };
    std::vector<CloseWork> work;
    work.reserve(active_conns_.size());

    for (auto& conn : active_conns_) {
        CloseWork w;
        w.transport = conn->GetTransport();
        w.fd = conn->fd();
        if (w.transport && conn->IsInUse()) {
            w.on_msg = w.transport->GetOnMessageCb();
        }
        ClearTransportCallbacks(conn.get());
        if (w.transport) {
            w.transport->ClearDeadline();
            if (w.fd >= 0) {
                dispatcher_->RemoveTimerConnectionIfMatch(w.fd, w.transport);
            }
            if (!w.transport->IsClosing()) {
                w.transport->ForceClose();
            }
        }
        conn->MarkClosing();
        work.push_back(std::move(w));
    }

    // Active -> zombie: gauge emits -N before the move. The conns no
    // longer count as active even though they're held alive for lease
    // safety; zombies aren't tracked by either gauge.
    const double active_drained = static_cast<double>(active_conns_.size());
    if (active_drained > 0.0) {
        EmitActiveGaugeDelta(-active_drained);
    }

    // Move to zombie list — kept alive until leases release them.
    for (auto& conn : active_conns_) {
        zombie_conns_.push_back(std::move(conn));
    }
    active_conns_.clear();

    // Notify borrowers AFTER zombification. If the notification triggers
    // lease release → ReturnConnection, it finds the connection in
    // zombie_conns_ and cleans up safely.
    for (auto& w : work) {
        if (w.on_msg && w.transport) {
            std::string empty;
            try { w.on_msg(w.transport, empty); } catch (...) {}
        }
    }
}

bool PoolPartition::ConnectionEndpointMatches(
        const UpstreamConnection& c) const {
    // atomic_load matches the publisher contract documented at the
    // resolved_endpoint_ declaration: step-11 will swap with
    // atomic_store; today, the load returns the same pointer for the
    // partition's lifetime so this compare is always true.
    auto current = std::atomic_load_explicit(
        &resolved_endpoint_, std::memory_order_acquire);
    return c.captured_endpoint() == current;
}

void PoolPartition::CreateNewConnection(ReadyCallback ready_cb,
                                         ErrorCallback error_cb) {

    auto endpoint = std::atomic_load_explicit(
        &resolved_endpoint_, std::memory_order_acquire);
    if (!endpoint) {
        // Should be impossible after the ctor guard, but defensive: a
        // null pointer during the swap window would otherwise crash.
        logging::Get()->error(
            "PoolPartition::CreateNewConnection: resolved_endpoint_ is "
            "null for {}:{}", upstream_host_, upstream_port_);
        error_cb(CHECKOUT_CONNECT_FAILED);
        return;
    }
    const InetAddr& upstream_addr = endpoint->addr;
    if (!upstream_addr.is_valid()) {
        logging::Get()->error(
            "PoolPartition::CreateNewConnection: resolved endpoint for "
            "'{}' is invalid (family={}, port={})", upstream_host_,
            static_cast<int>(upstream_addr.family()), upstream_addr.Port());
        error_cb(CHECKOUT_CONNECT_FAILED);
        return;
    }

    const sa_family_t family =
        (upstream_addr.family() == InetAddr::Family::kIPv6) ? AF_INET6 : AF_INET;

    // Create outbound socket AFTER parsing — matches the parsed family so
    // connect() does not immediately fail with EAFNOSUPPORT on an IPv6
    // upstream. Order also means we never allocate an fd we might have
    // to close on parse failure.
    int fd = SocketHandler::CreateClientSocket(family);
    if (fd < 0) {
        logging::Get()->error("Failed to create client socket for {}:{} (family={})",
                              upstream_host_, upstream_port_, (int)family);
        error_cb(CHECKOUT_CONNECT_FAILED);
        return;
    }

    // Initiate non-blocking connect on the raw fd BEFORE wrapping in
    // ConnectionHandler. This avoids creating a temporary SocketHandler
    // that would close the fd in its destructor.
    int connect_result = ::connect(fd, upstream_addr.Addr(), upstream_addr.Len());
    if (connect_result < 0 && errno != EINPROGRESS && errno != EINTR) {
        int saved_errno = errno;
        logging::Get()->warn("connect() failed for {}:{}: {} (errno={})",
                             upstream_host_, upstream_port_,
                             logging::SafeStrerror(saved_errno), saved_errno);
        ::close(fd);
        error_cb(CHECKOUT_CONNECT_FAILED);
        return;
    }

    // Build socket handler and connection handler. Thread the resolved
    // family into SocketHandler so later observability / debug paths
    // (e.g. GetBoundPort's getsockname) branch on ss_family correctly.
    auto sock = std::make_unique<SocketHandler>(fd, family);
    auto conn_handler = std::make_shared<ConnectionHandler>(
        dispatcher_, std::move(sock));

    // Register in dispatcher's timer map for timeout scanning
    dispatcher_->AddConnection(conn_handler);

    // Set connect timeout deadline
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(config_.connect_timeout_ms);
    conn_handler->SetDeadline(deadline);

    // Wire deadline timeout callback to distinguish timeout from refusal.
    // Returns false so the default close behavior proceeds (CloseAfterWrite).
    // The close callback below will be overridden by the timeout flag.
    auto timed_out = std::make_shared<bool>(false);
    conn_handler->SetDeadlineTimeoutCb([timed_out]() {
        *timed_out = true;
        return false;  // proceed with default close behavior
    });

    // Create the upstream connection wrapper. Pass the endpoint that was
    // current when this connect was initiated so the idle-cleanup task
    // can identify connections associated with a superseded IP.
    auto upstream_conn = std::make_unique<UpstreamConnection>(
        conn_handler, upstream_host_, upstream_port_, endpoint);
    UpstreamConnection* raw_conn = upstream_conn.get();

    // Safety invariant for `this` captures: PoolPartition destruction only happens
    // after dispatchers stop (HttpServer::Stop → UpstreamManager destroyed after
    // NetServer::Stop). ClearTransportCallbacks in ~PoolPartition and DestroyConnection
    // nulls all callbacks before the partition is freed. Single-threaded dispatcher
    // execution means callbacks can't race with destruction.

    // Shared callbacks — connect is async, so callbacks outlive this scope
    auto ready_cb_copy = std::make_shared<ReadyCallback>(std::move(ready_cb));
    auto error_cb_copy = std::make_shared<ErrorCallback>(std::move(error_cb));

    // Wire the connect-complete callback
    conn_handler->SetConnectCompleteCallback(
        [this, raw_conn, ready_cb_copy, error_cb_copy]
        (std::shared_ptr<ConnectionHandler> handler) {
            // TLS? Start handshake
            if (tls_ctx_) {
                try {
                    // Use configured sni_hostname for SNI + hostname verification.
                    // When empty, pass empty string — TlsConnection skips SNI and
                    // SSL_set1_host when sni_hostname is empty. Sending an IPv4
                    // address as SNI would fail against name-based certificates.
                    auto tls = std::make_unique<TlsConnection>(
                        *tls_ctx_, handler->fd(), sni_hostname_);
                    handler->SetTlsConnection(std::move(tls));
                    // The fall-through in CallWriteCb kicks off DoHandshake
                    // inline on the same EPOLLOUT. OnMessage fires when done.
                } catch (const std::exception& e) {
                    logging::Get()->error("TLS setup failed for {}:{}: {}",
                                          upstream_host_, upstream_port_,
                                          e.what());
                    // Clean up partition state BEFORE invoking user callback.
                    // An embedder may tear down the pool/manager from error_cb
                    // (e.g. reacting to repeated checkout failures), which
                    // would free this PoolPartition. Any dispatcher_ or
                    // raw_conn access after the callback would be UAF.
                    //
                    // Hoist the shared_ptr onto the stack FIRST: DestroyConnection
                    // calls ClearTransportCallbacks which nulls the
                    // SetConnectCompleteCallback holding this very lambda,
                    // destroying its captures while it's still executing. Any
                    // capture access post-cleanup must go through a stack copy.
                    auto error_cb_local = error_cb_copy;
                    auto owned = ExtractFromConnecting(raw_conn);
                    if (owned) {
                        DestroyConnection(std::move(owned));
                    }
                    (*error_cb_local)(CHECKOUT_CONNECT_FAILED);
                    return;
                }
                // Don't deliver ready — TLS handshake still in progress.
                // OnMessage callback fires when handshake completes.
                return;
            }

            // No TLS — connection is ready
            OnConnectComplete(raw_conn, *ready_cb_copy, *error_cb_copy);
        });

    // Wire close callback for connect failure / timeout / shutdown.
    conn_handler->SetCloseCb(
        [this, raw_conn, error_cb_copy, timed_out]
        (std::shared_ptr<ConnectionHandler>) {
            // Snapshot notification decision BEFORE cleanup. OnConnectionClosed
            // will destroy raw_conn for the connecting case (unique_ptr drops
            // out of scope). Check both partition-local and manager-wide
            // shutdown flags — if UpstreamManager::InitiateShutdown() set the
            // global flag before this partition's queued InitiateShutdown()
            // ran, we still report CHECKOUT_SHUTTING_DOWN deterministically
            // instead of CHECKOUT_CONNECT_FAILED/TIMEOUT (matches the
            // error-callback path).
            int code = 0;
            bool should_notify = raw_conn->IsConnecting();
            if (should_notify) {
                if (shutting_down_.load(std::memory_order_acquire) ||
                    manager_shutting_down_.load(std::memory_order_acquire)) {
                    code = CHECKOUT_SHUTTING_DOWN;
                } else if (*timed_out) {
                    code = CHECKOUT_CONNECT_TIMEOUT;
                } else {
                    code = CHECKOUT_CONNECT_FAILED;
                }
            }
            // Clean up partition state BEFORE invoking the user callback.
            // An embedder may tear down the pool/manager from error_cb,
            // freeing this PoolPartition. Dispatcher/state access after the
            // callback would then be UAF.
            //
            // Hoist error_cb_copy onto the stack FIRST: OnConnectionClosed
            // calls ClearTransportCallbacks which nulls the SetCloseCb
            // std::function holding this very lambda, destroying its
            // captures while still executing. The stack copy keeps the
            // target alive across the cleanup.
            auto error_cb_local = should_notify
                ? error_cb_copy
                : std::shared_ptr<ErrorCallback>{};
            OnConnectionClosed(raw_conn);
            if (error_cb_local) {
                (*error_cb_local)(code);
            }
        });

    // Wire error callback for EPOLLERR events (async reset, local error).
    // Use the same timeout/shutdown distinction as the close callback.
    conn_handler->SetErrorCb(
        [this, raw_conn, error_cb_copy, timed_out]
        (std::shared_ptr<ConnectionHandler>) {
            // Same safe-ordering rationale as SetCloseCb above: snapshot
            // notification state, hoist captures, clean up, invoke callback.
            int code = 0;
            bool should_notify = raw_conn->IsConnecting();
            if (should_notify) {
                if (shutting_down_.load(std::memory_order_acquire) ||
                    manager_shutting_down_.load(std::memory_order_acquire)) {
                    code = CHECKOUT_SHUTTING_DOWN;
                } else if (*timed_out) {
                    code = CHECKOUT_CONNECT_TIMEOUT;
                } else {
                    code = CHECKOUT_CONNECT_FAILED;
                }
            }
            auto error_cb_local = should_notify
                ? error_cb_copy
                : std::shared_ptr<ErrorCallback>{};
            OnConnectionClosed(raw_conn);
            if (error_cb_local) {
                (*error_cb_local)(code);
            }
        });

    // Wire message callback for TLS handshake completion
    if (tls_ctx_) {
        conn_handler->SetOnMessageCb(
            [this, raw_conn, ready_cb_copy, error_cb_copy]
            (std::shared_ptr<ConnectionHandler> handler, std::string&) {
                if (raw_conn->IsConnecting()) {
                    handler->ClearDeadline();
                    OnConnectComplete(raw_conn, *ready_cb_copy, *error_cb_copy);
                }
            });
    }

    // Increment outstanding counter
    outstanding_conns_.fetch_add(1, std::memory_order_relaxed);

    // Store in connecting set
    connecting_conns_.push_back(std::move(upstream_conn));

    // Register outbound callbacks (enables write-only for connect detection)
    try {
        conn_handler->RegisterOutboundCallbacks();
    } catch (const std::exception& e) {
        logging::Get()->error("epoll registration failed for outbound fd {}: {}",
                              conn_handler->fd(), e.what());
        auto owned = ExtractFromConnecting(raw_conn);
        if (owned) {
            DestroyConnection(std::move(owned));
        }
        (*error_cb_copy)(CHECKOUT_CONNECT_FAILED);
        return;
    }
}

void PoolPartition::OnConnectComplete(UpstreamConnection* conn,
                                       ReadyCallback ready_cb,
                                       ErrorCallback error_cb) {
    // Find in connecting_conns_ and move to active
    auto owned = ExtractFromConnecting(conn);
    if (!owned) {
        logging::Get()->warn("OnConnectComplete: connection not found in "
                             "connecting set");
        return;
    }

    // Capture connect duration for the histogram emit below.
    // created_at_ is set at UpstreamConnection construction, immediately
    // before the non-blocking ::connect, so this is a tight upper bound
    // on the wire-level connect time.
    auto connect_dur_sec = std::chrono::duration_cast<std::chrono::duration<double>>(
        std::chrono::steady_clock::now() - owned->created_at()).count();
    if (connect_dur_sec < 0.0) connect_dur_sec = 0.0;

    // Check both partition-local flag AND manager-wide flag. The manager flag
    // is set immediately by InitiateShutdown(); the partition flag is set later
    // by the enqueued task. Without checking both, a connect that completes
    // between the two can deliver a lease after Stop() has begun.
    if (shutting_down_ || manager_shutting_down_.load(std::memory_order_acquire)) {
        DestroyConnection(std::move(owned));
        error_cb(CHECKOUT_SHUTTING_DOWN);
        return;
    }

    // Set a far-future deadline instead of clearing. ClearDeadline would
    // expose the transport to the server-wide idle timeout (since the fd is
    // still in the dispatcher's connections_ map). A far-future deadline
    // keeps has_deadline_=true, which suppresses the idle timeout check in
    // ConnectionHandler::IsTimeOut(). The borrower can set their own deadline.
    static constexpr auto FAR_FUTURE = std::chrono::hours(24 * 365);
    owned->GetTransport()->SetDeadline(
        std::chrono::steady_clock::now() + FAR_FUTURE);
    owned->MarkInUse();

    // Wire pool-owned close/error callbacks BEFORE handing to the borrower.
    // Without this, a fresh connection from CreateNewConnection still has
    // the connect-phase callbacks that don't forward EOF to the borrower's
    // on_message_callback, so a disconnect on the very first request hangs.
    WirePoolCallbacks(owned.get());

    UpstreamConnection* raw = owned.get();
    active_conns_.push_back(std::move(owned));

    logging::Get()->debug("Upstream connection ready fd={} {}:{}",
                          raw->fd(), upstream_host_, upstream_port_);

    // Fresh connect succeeded — enters active directly (no prior gauge to
    // decrement). Histogram records connect time under outcome=created.
    EmitActiveGaugeDelta(+1.0);
    EmitCheckoutWaitDuration(connect_dur_sec, "created");

    // See the matching site above — bump before handing the lease out.
    inflight_leases_.fetch_add(1, std::memory_order_acq_rel);
    ready_cb(UpstreamLease(raw, this, alive_, off_dispatcher_release_drops_, dispatcher_));
}

void PoolPartition::OnConnectionClosed(UpstreamConnection* conn) {
    // Hoist alive_ — the retry loop below calls CreateNewConnection which
    // can synchronously fire a waiter's error_cb on inline failures
    // (socket(), inet_addr, immediate connect, epoll registration).
    // A user callback may tear down the pool/manager, after which touching
    // wait_queue_/TotalCount()/MaybeSignalDrain would be UAF.
    auto alive = alive_;

    // Safe from double-decrement with DestroyConnection because both paths
    // run on the dispatcher thread (single-threaded). OnConnectionClosed
    // extracts from containers; DestroyConnection clears callbacks before
    // ForceClose, so the close callback can't re-fire.
    auto owned = ExtractFromConnecting(conn);
    bool was_active = false;
    bool was_idle = false;
    if (!owned) {
        owned = ExtractFromActive(conn);
        if (owned) was_active = true;
    }
    if (!owned) {
        owned = ExtractFromIdle(conn);
        if (owned) was_idle = true;
    }

    if (owned) {
        // Emit gauge -1 for whichever container the conn left.
        // Connecting->closed has NO gauge (never observable until OnConnectComplete).
        if (was_active) EmitActiveGaugeDelta(-1.0);
        else if (was_idle) EmitIdleGaugeDelta(-1.0);
        ClearTransportCallbacks(owned.get());
        auto transport = owned->GetTransport();
        if (transport) {
            transport->ClearDeadline();
            int conn_fd = owned->fd();
            if (conn_fd >= 0) {
                dispatcher_->RemoveTimerConnectionIfMatch(conn_fd, transport);
            }
        }
        owned->MarkClosing();

        if (was_active) {
            // An UpstreamLease may still hold a raw pointer to this connection.
            // Move to zombie list — the lease destructor's ReturnConnection
            // will clean it up and decrement outstanding_conns_ at that point.
            // Do NOT decrement here: WaitForDrain must not see 0 until all
            // leases are released, otherwise the manager can be destroyed
            // while a lease is still alive (use-after-free on partition_).
            zombie_conns_.push_back(std::move(owned));
        } else {
            // For connecting/idle connections, no lease exists — safe to
            // decrement and destroy immediately.
            outstanding_conns_.fetch_sub(1, std::memory_order_release);
        }

        // A slot just freed — retry queued checkouts
        CreateForWaiters();
        if (!alive->load(std::memory_order_acquire)) return;

        MaybeSignalDrain();
    }
}

bool PoolPartition::OpenNewH2Connection(const std::string& upstream_name,
                                         int port) {
    if (shutting_down_.load(std::memory_order_acquire) ||
        manager_shutting_down_.load(std::memory_order_acquire)) {
        return false;
    }
    // Defensive cap-gate. The documented contract is that callers gate
    // on TotalCount() before invoking, but this is a public method;
    // future call sites that forget the gate would otherwise overflow
    // the partition's connection budget. The two existing call sites
    // (StartH2ReplacementConnect and the ALPN probe path) already gate
    // — this check is harmless there and prevents the regression class.
    if (TotalCount() >= partition_max_connections_) {
        logging::Get()->warn(
            "OpenNewH2Connection: TotalCount {} >= cap {} for {}:{} — "
            "caller forgot the pre-gate; refusing to overflow pool",
            TotalCount(), partition_max_connections_, upstream_name, port);
        return false;
    }
    if (!tls_ctx_) {
        logging::Get()->warn(
            "OpenNewH2Connection: TLS context required for ALPN probe "
            "upstream={}:{}", upstream_name, port);
        return false;
    }
    auto endpoint = std::atomic_load_explicit(
        &resolved_endpoint_, std::memory_order_acquire);
    if (!endpoint || !endpoint->addr.is_valid()) {
        logging::Get()->error(
            "OpenNewH2Connection: invalid resolved endpoint for {}:{}",
            upstream_name, port);
        return false;
    }
    auto cfg = LoadHttp2ConfigSnapshot();
    if (!cfg || !cfg->enabled || cfg->prefer == "never") return false;

    // Skip probe when prefer="auto" and the cache says H1Only for the
    // current endpoint. prefer="always" deliberately re-attempts so the
    // operator-config rejection surfaces every request. prefer="never"
    // already short-circuited above.
    if (cfg->prefer == "auto" &&
        ShouldSkipH2ProbeForEndpoint(upstream_name, port, endpoint)) {
        logging::Get()->debug(
            "OpenNewH2Connection: skipping probe (cache says H1Only) "
            "upstream={}:{}", upstream_name, port);
        return false;
    }

    const InetAddr& addr = endpoint->addr;
    const sa_family_t family =
        (addr.family() == InetAddr::Family::kIPv6) ? AF_INET6 : AF_INET;
    int fd = SocketHandler::CreateClientSocket(family);
    if (fd < 0) {
        logging::Get()->error(
            "OpenNewH2Connection: socket() failed for {}:{} (family={})",
            upstream_name, port, static_cast<int>(family));
        return false;
    }
    int connect_result = ::connect(fd, addr.Addr(), addr.Len());
    if (connect_result < 0 && errno != EINPROGRESS && errno != EINTR) {
        int saved_errno = errno;
        logging::Get()->warn("OpenNewH2Connection: connect() failed {}:{}: "
                             "{} (errno={})", upstream_name, port,
                             logging::SafeStrerror(saved_errno), saved_errno);
        ::close(fd);
        return false;
    }

    auto sock = std::make_unique<SocketHandler>(fd, family);
    auto conn_handler = std::make_shared<ConnectionHandler>(
        dispatcher_, std::move(sock));
    dispatcher_->AddConnection(conn_handler);

    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(config_.connect_timeout_ms);
    conn_handler->SetDeadline(deadline);

    // UpstreamConnection records the operator host string (logging /
    // captured_endpoint), not the service name. Pass `upstream_host_`
    // here — `upstream_name` is the h2_table_ / wait-queue key, used
    // separately in the callback closures below.
    auto upstream_conn = std::make_unique<UpstreamConnection>(
        conn_handler, upstream_host_, port, endpoint);
    auto h2 = std::make_unique<UpstreamH2Connection>(upstream_conn.get(), cfg);
    h2->SetPartition(this);
    auto alive = h2->alive_token();

    // The H2 shell's lease stays EMPTY during the probe. ALPN-h2
    // success in OnH2ConnectHandshakeComplete moves the upstream_conn
    // from connecting_conns_ into active_conns_ and only then calls
    // AdoptLease — so the eventual DestroyOnDispatcher's lease.reset()
    // routes ReturnConnection through the active-conn path.
    outstanding_conns_.fetch_add(1, std::memory_order_relaxed);
    UpstreamConnection* raw_uc = upstream_conn.get();
    // push_back is the move's commit point. unique_ptr's noexcept
    // move-constructor pairs with vector's strong-exception guarantee
    // for reallocation, but the catch below still rolls back
    // outstanding_conns_ in case bad_alloc somehow escapes (cheap
    // defense; the main throw path is the Set*Cb block below).
    try {
        connecting_conns_.push_back(std::move(upstream_conn));
    } catch (...) {
        outstanding_conns_.fetch_sub(1, std::memory_order_release);
        throw;
    }

    // Each Set*Cb below moves a std::function whose closure captures
    // alive / timed_out / raw_uc — at sizes large enough that SBO does
    // not apply, so the move triggers a heap allocation that can throw
    // bad_alloc. The try covers every such call (plus
    // RegisterOutboundCallbacks below) so a throw anywhere routes
    // through the rollback rather than stranding partial wiring on the
    // transport with `outstanding_conns_` bumped.
    //
    // Shared rollback used by both catch blocks. The pitfall rule
    // "bump + push + wire must be one transaction" needs BOTH std and
    // non-std catches so rollback fires regardless of throw type. Drop
    // `h2` BEFORE DestroyConnection so its safety-net dtor nulls H2
    // transport callbacks first; ForceClose's close-cb chain then
    // no-ops. outstanding_conns_ is decremented inline by
    // DestroyConnection. No H2_STREAM_SLOT waiters can exist yet (this
    // runs before any enqueue could land).
    auto rollback = [&]() {
        h2.reset();
        if (auto owned = ExtractFromConnecting(raw_uc)) {
            DestroyConnection(std::move(owned));
            return;
        }
        // Transport vanished from connecting_conns_ between setup and
        // rollback — almost certainly a synchronous close-cb chain
        // already extracted it. outstanding_conns_ was bumped at
        // CreateNewConnection but never decremented if DestroyConnection
        // didn't run; surface the leak.
        logging::Get()->error(
            "OpenNewH2Connection rollback: ExtractFromConnecting "
            "returned null for {}:{} — outstanding_conns_ may have "
            "leaked unless the close-callback chain decremented it",
            upstream_name, port);
    };
    try {
        auto timed_out = std::make_shared<bool>(false);
        conn_handler->SetDeadlineTimeoutCb([timed_out]() {
            *timed_out = true;
            return false;
        });

        // Forward terminal connect-failure outcomes through
        // OnH2ConnectHandshakeComplete so the ALPN-resolve state machine
        // owns every disposition. Capture upstream_name + port by value so
        // the disposition keys match h2_connecting_conns_ regardless of
        // how `raw_uc->upstream_host()` relates to the service name.
        conn_handler->SetConnectCompleteCallback(
            [alive, upstream_name, port, this]
            (std::shared_ptr<ConnectionHandler> handler) {
                if (!alive->load(std::memory_order_acquire)) return;
                // Start TLS handshake. ALPN list set on tls_ctx_ at ctor.
                try {
                    auto tls = std::make_unique<TlsConnection>(
                        *tls_ctx_, handler->fd(), sni_hostname_);
                    handler->SetTlsConnection(std::move(tls));
                } catch (const std::exception& e) {
                    logging::Get()->error(
                        "OpenNewH2Connection: TLS setup failed {}:{}: {}",
                        upstream_name, port, e.what());
                    OnH2ConnectHandshakeComplete(
                        upstream_name, port, CHECKOUT_CONNECT_FAILED, "");
                }
                // On success, handshake-complete fires once TLS settles.
            });

        conn_handler->SetHandshakeCompleteCallback(
            [alive, raw_uc, upstream_name, port, this]() {
                if (!alive->load(std::memory_order_acquire)) return;
                std::string alpn;
                auto t = raw_uc ? raw_uc->GetTransport() : nullptr;
                if (t) alpn = t->GetAlpnProtocol();
                OnH2ConnectHandshakeComplete(
                    upstream_name, port, CHECKOUT_OK, alpn);
            });

        // SetCloseCb and SetErrorCb share the same outcome classifier —
        // factor into a callback that both wire identically.
        auto classify_and_dispatch =
            [alive, upstream_name, port, timed_out, this]
            (std::shared_ptr<ConnectionHandler>) {
                if (!alive->load(std::memory_order_acquire)) return;
                int code = CHECKOUT_CONNECT_FAILED;
                if (shutting_down_.load(std::memory_order_acquire) ||
                    manager_shutting_down_.load(std::memory_order_acquire)) {
                    code = CHECKOUT_SHUTTING_DOWN;
                } else if (*timed_out) {
                    code = CHECKOUT_CONNECT_TIMEOUT;
                }
                OnH2ConnectHandshakeComplete(upstream_name, port, code, "");
            };
        conn_handler->SetCloseCb(classify_and_dispatch);
        conn_handler->SetErrorCb(std::move(classify_and_dispatch));

        conn_handler->RegisterOutboundCallbacks();

        // Final commit: stash the H2 shell into the connecting map. This
        // can throw bad_alloc on key allocation BEFORE consuming h2 (the
        // unique_ptr move-assign is noexcept, so a thrown insert leaves
        // h2 intact and us in a partial-state where outstanding_conns_
        // is bumped, transport sits in connecting_conns_, and callbacks
        // are wired pointing at the about-to-destruct h2. Putting the
        // commit inside the try ensures the shared rollback fires and
        // tears everything down atomically — pitfall rule "bump + push
        // + wire is one transaction" extended to "bump + push + wire +
        // stash".
        h2_connecting_conns_[HostPortKey{upstream_name, port}] = std::move(h2);
    } catch (const std::exception& e) {
        logging::Get()->error(
            "OpenNewH2Connection: setup failed for {}:{}: {}",
            upstream_name, port, e.what());
        rollback();
        return false;
    } catch (...) {
        logging::Get()->error(
            "OpenNewH2Connection: setup failed for {}:{} (non-std exception)",
            upstream_name, port);
        rollback();
        return false;
    }
    return true;
}

void PoolPartition::OnH2ConnectHandshakeComplete(
    const std::string& upstream_name, int port, int outcome,
    const std::string& alpn)
{
    HostPortKey key{upstream_name, port};

    auto cfg = LoadHttp2ConfigSnapshot();
    if (!cfg) {
        // The H2 config snapshot was cleared between OpenNewH2Connection
        // and the handshake completing — typically a config-reload window
        // that disabled H2 or removed the upstream. Fall back to "auto"
        // for the prefer semantics; an operator who configured
        // prefer=always loses the strict-h2 gate for THIS probe. Warn
        // so an operator can correlate any unexpected H1 adoptions to
        // a recent reload.
        logging::Get()->warn(
            "OnH2ConnectHandshakeComplete: H2 config snapshot is null "
            "for upstream={}:{} — defaulting prefer to 'auto' (config "
            "reload window may have cleared the snapshot)",
            upstream_name, port);
    }
    const std::string prefer = cfg ? cfg->prefer : std::string("auto");

    // Extract the shell out of the stash so we own it locally.
    std::unique_ptr<UpstreamH2Connection> shell;
    auto it = h2_connecting_conns_.find(key);
    if (it != h2_connecting_conns_.end()) {
        shell = std::move(it->second);
        h2_connecting_conns_.erase(it);
    }
    // The underlying transport lives in connecting_conns_; retrieve
    // its raw pointer through the shell BEFORE running cleanup.
    UpstreamConnection* uc_raw =
        shell ? shell->transport() : nullptr;

    auto fail = [&](int code, const char* reason) {
        if (shell) shell->DestroyOnDispatcher();
        // Extract + destroy the underlying transport. ExtractFromConnecting
        // is a no-op if `uc_raw` already left the container (e.g. the
        // close/error callback chain raced us — defensive only).
        if (uc_raw) {
            auto owned = ExtractFromConnecting(uc_raw);
            if (owned) DestroyConnection(std::move(owned));
        }
        FailH2StreamSlotWaiters(upstream_name, port, code, reason);
    };

    if (outcome == CHECKOUT_SHUTTING_DOWN) {
        fail(CHECKOUT_SHUTTING_DOWN, "shutdown during h2 probe");
        return;
    }
    if (outcome != CHECKOUT_OK) {
        fail(outcome, "h2 probe connect-fail");
        return;
    }

    const bool got_h2 = (alpn == "h2");
    if (!got_h2) {
        if (prefer == "always") {
            // TODO: when EnqueueH2StreamSlotWaiter wires up the explicit
            // H2-stream-slot vending path, replace this generic checkout
            // failure with a terminal RESULT_H2_ALPN_NOT_NEGOTIATED so
            // the deterministic operator-config reject does not burn
            // retry budget. See UPSTREAM_H2_DISPATCH.md pitfall "Async
            // strict-h2 gate uses generic RESULT_CHECKOUT_FAILED".
            fail(CHECKOUT_CONNECT_FAILED,
                 "alpn_not_h2_under_prefer_always");
            return;
        }
        // DNS swap mid-probe detection: the probe's captured endpoint
        // (in `uc_raw->captured_endpoint()`) is compared to the
        // partition's current `resolved_endpoint_` via
        // `ConnectionEndpointMatches`; on mismatch a reload published
        // a new endpoint while the probe was in flight. The negotiated
        // h1 transport is keyed against the stale endpoint → must not
        // be adopted into idle_conns_. Roll back, drop the (now-stale)
        // cache entry, and trigger a replacement probe so queued
        // waiters get serviced against the fresh endpoint.
        if (uc_raw && !ConnectionEndpointMatches(*uc_raw)) {
            logging::Get()->info(
                "OnH2ConnectHandshakeComplete: DNS swap mid-probe "
                "detected on alpn-h1 fallback for {}:{}; rolling back "
                "and scheduling replacement probe",
                upstream_name, port);
            InvalidateH2NegotiationCacheForEndpoint(uc_raw->captured_endpoint());
            if (shell) shell->DestroyOnDispatcher();
            if (auto owned = ExtractFromConnecting(uc_raw)) {
                DestroyConnection(std::move(owned));
            }
            FailH2StreamSlotWaiters(upstream_name, port,
                                    CHECKOUT_CONNECT_FAILED,
                                    "dns_swap_mid_h2_probe (alpn-h1)");
            StartH2ReplacementConnect(upstream_name, port);
            return;
        }

        // prefer=auto: hand the negotiated h1 transport to the H1 idle
        // pool so a subsequent H1 dispatch can borrow it without a
        // second TCP/TLS handshake. Queued H2_STREAM_SLOT waiters for
        // this upstream are reclassified to ANY-kind so ServiceWaitQueue
        // can match them against the freshly-adopted idle conn.
        auto owned_uc = uc_raw ? ExtractFromConnecting(uc_raw) : nullptr;
        if (!owned_uc) {
            // Transport vanished from connecting_conns_ between
            // OnH2ConnectHandshakeComplete entry and the extract here
            // (concurrent close-cb chain). Symmetric to the ALPN-h2
            // success branch's vanish path: fail H2_STREAM_SLOT
            // waiters AND re-dispatch ANY-kind cold-start waiters via
            // ServiceWaitQueue so they pick up fresh capacity rather
            // than stranding until MAX_QUEUE_AGE.
            logging::Get()->warn(
                "OnH2ConnectHandshakeComplete: ALPN-h1 transport "
                "vanished from connecting_conns_ for {}:{} — failing "
                "H2 slot waiters and triggering wait-queue service",
                upstream_name, port);
            if (shell) shell->DestroyOnDispatcher();
            FailH2StreamSlotWaiters(upstream_name, port,
                                    CHECKOUT_CONNECT_FAILED,
                                    "transport vanished pre-h1-adoption");
            ServiceWaitQueue();
            return;
        }
        // Commit-at-end adoption: AdoptAsH1Connection is by-ref and
        // commits via push_back. On throw, owned_uc still owns the
        // transport; rollback nulls shell->transport_ + destroys.
        // MarkTransferred fires post-commit so the shell's safety-net
        // dtor stays armed until adoption is durable.
        try {
            AdoptAsH1Connection(owned_uc);  // by ref; commits at end
        } catch (...) {
            // Adoption failed pre-commit. owned_uc still owns the
            // transport. Null the shell's dangling pointer, destroy
            // the transport, tear down the shell. Rethrow.
            if (shell) shell->ClearTransportForRollback();
            if (owned_uc) DestroyConnection(std::move(owned_uc));
            if (shell) shell->DestroyOnDispatcher();
            throw;
        }
        // Adoption committed. Signal "shell no longer owns the
        // transport" so the safety-net dtor's ClearH2TransportCallbacks
        // does not wipe the callbacks WirePoolCallbacks just installed
        // on the idle conn.
        if (shell) shell->MarkTransferred();
        // Record the H1Only outcome for prefer="auto" (the only prefer
        // mode that reaches this branch — prefer="always" routes
        // through the alpn_not_h2_under_prefer_always fail path above;
        // prefer="never" doesn't probe). Use the transport's captured
        // endpoint (the one the probe targeted) rather than
        // LoadResolvedEndpoint(): a reload may have published a new
        // endpoint after the DNS-swap check above passed, and keying
        // this stale H1Only result against the new endpoint would
        // wrongly suppress H2 probing to the freshly-rotated backend.
        RecordH2NegotiationOutcome(
            upstream_name, port, H2NegotiationOutcome::H1Only,
            uc_raw ? uc_raw->captured_endpoint() : nullptr);
        ReclassifyH2WaitersToAny(upstream_name, port);
        // Asymmetry note: no inflight_leases_ bump here (unlike the
        // ALPN-h2 success branch at line ~2063). AdoptAsH1Connection
        // hands the transport to idle_conns_, not to a borrower — the
        // matching bump fires later when the H1 idle conn is checked
        // out via ServiceWaitQueue / CheckoutAsync.
        ServiceWaitQueue();
        return;
    }

    if (!shell) {
        // Shell-only-missing: extract + destroy uc_raw inline.
        // Dual-null (concurrent shutdown reaped both): debug-log only —
        // nothing to free, FailH2StreamSlotWaiters is a no-op today.
        if (!uc_raw) {
            logging::Get()->debug(
                "OnH2ConnectHandshakeComplete: shell AND transport both "
                "vanished concurrently for {}:{} (likely shutdown race) "
                "— no resources to free", upstream_name, port);
        } else {
            logging::Get()->error(
                "OnH2ConnectHandshakeComplete: no shell in stash for "
                "{}:{} on ALPN-h2 success — failing queued waiters",
                upstream_name, port);
            auto owned = ExtractFromConnecting(uc_raw);
            if (owned) DestroyConnection(std::move(owned));
        }
        FailH2StreamSlotWaiters(upstream_name, port, CHECKOUT_CONNECT_FAILED,
                                "h2 shell missing on alpn-h2 success");
        return;
    }

    // DNS swap mid-probe detection: the probe targeted
    // `uc_raw->captured_endpoint()`; if the partition's
    // `resolved_endpoint_` was swapped during the probe window,
    // installing this transport as an H2 session would route every
    // future stream to the stale IP. Tear down, drop the (now-stale)
    // cache entry, and trigger a replacement probe against the current
    // endpoint so queued H2_STREAM_SLOT waiters resume. Mirrors the
    // alpn-h1 fallback's gate above byte-for-byte; the recheck is the
    // same, only the cleanup branches differ (h2 success has not yet
    // wired anything, so no MarkTransferred / AdoptAsH1Connection
    // rollback is needed).
    if (uc_raw && !ConnectionEndpointMatches(*uc_raw)) {
        logging::Get()->info(
            "OnH2ConnectHandshakeComplete: DNS swap mid-probe "
            "detected on alpn-h2 success path for {}:{}; tearing "
            "down and scheduling replacement probe",
            upstream_name, port);
        InvalidateH2NegotiationCacheForEndpoint(uc_raw->captured_endpoint());
        if (shell) shell->DestroyOnDispatcher();
        if (auto owned = ExtractFromConnecting(uc_raw)) {
            DestroyConnection(std::move(owned));
        }
        FailH2StreamSlotWaiters(upstream_name, port,
                                CHECKOUT_CONNECT_FAILED,
                                "dns_swap_mid_h2_probe (alpn-h2)");
        StartH2ReplacementConnect(upstream_name, port);
        return;
    }

    // Wire callbacks BEFORE Init() — its preface flush can fire
    // complete_callback synchronously on a writable transport.
    // try/catch covers std::function moves that can heap-allocate;
    // see UPSTREAM_H2.md "Set*Cb between fetch_add and try-block".
    // Shared cleanup for both catch blocks below. ClearTransportCallbacks
    // alone is not sufficient: SetOnMessageCb is wired first, so a
    // mid-wire throw can leave an OnMessage closure live on the
    // transport that captured `shell.get()`. fail() routes through
    // `shell->DestroyOnDispatcher()` which flips conn_alive_->false
    // BEFORE freeing the shell; any surviving callback's alive-token
    // guard short-circuits before dereferencing the destroyed shell.
    auto wire_cleanup = [&]() {
        if (uc_raw) ClearTransportCallbacks(uc_raw);
        fail(CHECKOUT_CONNECT_FAILED, "h2 wire-callbacks threw");
    };
    try {
        WireH2SessionTransportCallbacks(uc_raw, shell.get());
    } catch (const std::exception& e) {
        logging::Get()->error(
            "OnH2ConnectHandshakeComplete: WireH2SessionTransportCallbacks "
            "threw for {}:{}: {}",
            upstream_name, port, e.what());
        wire_cleanup();
        return;
    } catch (...) {
        logging::Get()->error(
            "OnH2ConnectHandshakeComplete: WireH2SessionTransportCallbacks "
            "threw non-std exception for {}:{}",
            upstream_name, port);
        wire_cleanup();
        return;
    }

    if (!shell->Init()) {
        logging::Get()->error(
            "OnH2ConnectHandshakeComplete: Init failed for {}:{}",
            upstream_name, port);
        // ClearTransportCallbacks before the fail path: we just installed
        // OnMessage/Close/Error/WriteProgress/Completion above and Init
        // failure means the H2 session is going away — its dtor would
        // null these, but doing it inline closes the race-window where
        // a synchronous close-callback chain from DestroyConnection could
        // re-enter the just-installed routed callbacks.
        if (uc_raw) ClearTransportCallbacks(uc_raw);
        fail(CHECKOUT_CONNECT_FAILED, "h2 session init failed");
        return;
    }

    // Promote the transport from connecting_conns_ to active_conns_ so
    // the eventual DestroyOnDispatcher's lease.reset routes through
    // ReturnConnection's active-conn path. AdoptLease binds the lease
    // to the freshly-moved conn; the H2 session holds the transport
    // for its lifetime.
    auto owned_uc = ExtractFromConnecting(uc_raw);
    if (!owned_uc) {
        logging::Get()->error(
            "OnH2ConnectHandshakeComplete: transport vanished from "
            "connecting_conns_ for {}:{} mid-resolve", upstream_name, port);
        // Unreachable today (dispatcher-thread-only extract/destroy);
        // kept as defense-in-depth against a future async-extract
        // refactor where the alive-token gate would matter. Roll back
        // the just-installed transport callbacks so a stray close-
        // callback chain from DestroyOnDispatcher cannot re-enter
        // routed closures pointing at the dying session.
        if (uc_raw) ClearTransportCallbacks(uc_raw);
        shell->DestroyOnDispatcher();
        FailH2StreamSlotWaiters(upstream_name, port, CHECKOUT_CONNECT_FAILED,
                                "transport vanished mid-h2-resolve");
        return;
    }
    owned_uc->MarkInUse();
    // Clear connect-timeout state before promotion. The probe-phase
    // dispatcher timer still references this fd; without overwriting
    // SetDeadline + nulling SetDeadlineTimeoutCb the timer's
    // configured connect_timeout_ms eventually fires, sets *timed_out,
    // and tears down a healthy multiplexed session.
    if (auto t = uc_raw->GetTransport()) {
        static constexpr auto FAR_FUTURE_H2 = std::chrono::hours(24 * 365);
        t->SetDeadline(std::chrono::steady_clock::now() + FAR_FUTURE_H2);
        t->SetDeadlineTimeoutCb(nullptr);
    }
    active_conns_.push_back(std::move(owned_uc));
    // Bump inflight_leases_ as a "synthetic" per-request handoff —
    // AdoptLease immediately swaps it into donated_h2_leases_ so the
    // drain predicate (consults inflight_leases_ only) does not
    // observe this long-lived session. The matching decrement
    // happens at lease destruction via ReturnConnection with
    // was_donated_to_h2=true.
    inflight_leases_.fetch_add(1, std::memory_order_acq_rel);
    shell->AdoptLease(UpstreamLease(uc_raw, this, alive_,
                                    off_dispatcher_release_drops_,
                                    dispatcher_));

    h2_table_.Insert(upstream_name, std::move(shell));
    // Record the H2Negotiated outcome against the endpoint the probe
    // ran on (transport-captured) rather than LoadResolvedEndpoint() —
    // see the ALPN-h1 branch comment for the reload-race rationale.
    // H2Negotiated entries never short-circuit ShouldSkipH2ProbeForEndpoint
    // (which gates only on H1Only), but keying consistently against the
    // probe's endpoint keeps eviction logic uniform across branches.
    RecordH2NegotiationOutcome(
        upstream_name, port, H2NegotiationOutcome::H2Negotiated,
        uc_raw ? uc_raw->captured_endpoint() : nullptr);
    DrainAnyWaitersForFastH2();
    DrainH2StreamWaitersForHost(upstream_name, port);
}

void PoolPartition::StartH2ReplacementConnect(
    const std::string& upstream_name, int port)
{
    if (shutting_down_.load(std::memory_order_acquire) ||
        manager_shutting_down_.load(std::memory_order_acquire)) {
        logging::Get()->debug(
            "StartH2ReplacementConnect skipped (shutdown) upstream={}:{}",
            upstream_name, port);
        return;
    }
    HostPortKey key{upstream_name, port};
    if (h2_connecting_conns_.count(key) > 0) {
        logging::Get()->debug(
            "StartH2ReplacementConnect skipped (in-flight probe exists) "
            "upstream={}:{}",
            upstream_name, port);
        return;
    }
    // Endpoint-aware: a stale-endpoint candidate (DNS swapped between
    // GOAWAY and now) must NOT suppress the replacement probe — the
    // queued waiters need a fresh session. FindUsableH2Connection
    // marks stale candidates dead inline so they're removed from the
    // table before the gate decides.
    if (FindUsableH2Connection(upstream_name) != nullptr) {
        logging::Get()->debug(
            "StartH2ReplacementConnect skipped (usable session exists) "
            "upstream={}:{}",
            upstream_name, port);
        return;
    }
    if (TotalCount() >= partition_max_connections_) {
        // Cap-saturated. Under pool.max_connections=1 the OnGoawayReceived
        // call site is the EXPECTED no-op (dying session still occupies
        // the slot; post-recv reap retries successfully) — debug-log
        // when the target is already queued. Otherwise warn because
        // queued waiters will time out at MAX_QUEUE_AGE.
        const bool already_pending = std::find(
            pending_h2_replacement_targets_.begin(),
            pending_h2_replacement_targets_.end(),
            key) != pending_h2_replacement_targets_.end();
        if (already_pending) {
            logging::Get()->debug(
                "StartH2ReplacementConnect deferred (TotalCount {} >= cap "
                "{}, target queued for post-reap retry) upstream={}:{}",
                TotalCount(), partition_max_connections_,
                upstream_name, port);
        } else {
            logging::Get()->warn(
                "StartH2ReplacementConnect skipped (TotalCount {} >= cap "
                "{}) upstream={}:{} — queued waiters may time out",
                TotalCount(), partition_max_connections_,
                upstream_name, port);
        }
        return;
    }

    OpenNewH2Connection(upstream_name, port);
}

void PoolPartition::AdoptAsH1Connection(
    std::unique_ptr<UpstreamConnection>& conn) {
    if (!conn) return;
    // Pre-commit work. A mid-wire throw leaves `conn` STILL OWNING
    // the transport (the unique_ptr is untouched until push_back) —
    // the transport's callbacks may be partially mutated, but the
    // caller's catch routes through DestroyConnection which calls
    // ClearTransportCallbacks to null all 5 cleanly. Realistic throw
    // sites: WirePoolCallbacks's std::function moves and SetDeadline.
    WirePoolCallbacks(conn.get());

    static constexpr auto FAR_FUTURE_ADOPT = std::chrono::hours(24 * 365);
    if (auto t = conn->GetTransport()) {
        t->SetDeadline(
            std::chrono::steady_clock::now() + FAR_FUTURE_ADOPT);
    }
    conn->MarkIdle();

    // Commit point. push_back's strong throw guarantee + unique_ptr's
    // noexcept move-constructor mean either push_back's allocation
    // succeeds (conn becomes empty, idle_conns_ grew by one) or
    // throws bad_alloc (conn unchanged, idle_conns_ unchanged). No
    // partial-state outcome possible.
    idle_conns_.push_back(std::move(conn));
}

void PoolPartition::ReclassifyH2WaitersToAny(
    const std::string& upstream_name, int port) {
    for (auto& entry : wait_queue_) {
        if (entry.kind == WaiterKind::H2_STREAM_SLOT &&
            entry.upstream_name == upstream_name && entry.port == port) {
            entry.kind = WaiterKind::ANY;
        }
    }
}

bool PoolPartition::ValidateConnection(UpstreamConnection* conn) {
    auto transport = conn ? conn->GetTransport() : nullptr;
    if (transport && transport->IsOnDispatcherThread() &&
        transport->InputBufferSize() > 0) {
        logging::Get()->debug("UpstreamConnection fd={} has buffered input, "
                              "marking non-reusable", conn->fd());
        return false;
    }
    if (!conn->IsAlive()) return false;
    if (conn->IsExpired(config_.max_lifetime_sec,
                         config_.max_requests_per_conn)) return false;
    return true;
}

void PoolPartition::ServiceWaitQueue() {
    // If shutdown has started (partition-local or manager-wide), don't hand
    // out or create connections. Pending waiters will be drained with
    // CHECKOUT_SHUTTING_DOWN by the partition's InitiateShutdown(). Without
    // this, a connection return between the manager flag flip and the
    // enqueued InitiateShutdown task can still service waiters, creating new
    // upstream work after Stop() has begun and extending shutdown.
    if (shutting_down_ || manager_shutting_down_.load(std::memory_order_acquire)) {
        return;
    }

    // Hoist alive_ onto the stack: a waiter's ready_callback / error_callback
    // may synchronously tear down the pool/manager (e.g., reacting to a first
    // checkout failure by calling HttpServer::Stop()), which frees this
    // PoolPartition. After that, touching any member (wait_queue_, idle_conns_,
    // TotalCount()) is UAF. The hoisted copy keeps the atomic<bool> alive
    // independently of the partition; we check it after each callback and
    // return immediately if the partition has been destroyed.
    auto alive = alive_;

    PurgeExpiredWaitEntries();
    if (!alive->load(std::memory_order_acquire)) return;

    // Helper: drop any cancelled entries at the front so we match them
    // against idle connections / capacity rather than "consuming" a
    // slot with a dead entry. Cancelled entries have no callbacks to
    // fire — the owning transaction's framework abort hook already
    // handled that side. Emit outcome=cancelled histogram for each
    // so operators have visibility on cancel volume during normal operation.
    auto drop_cancelled_front = [this]() {
        auto now = std::chrono::steady_clock::now();
        while (!wait_queue_.empty() &&
               IsEntryCancelled(wait_queue_.front())) {
            auto cancelled_dur =
                std::chrono::duration_cast<std::chrono::duration<double>>(
                    now - wait_queue_.front().queued_at);
            EmitCheckoutWaitDuration(cancelled_dur.count(), "cancelled");
            wait_queue_.pop_front();
        }
    };

    drop_cancelled_front();
    // H2_STREAM_SLOT entries cannot be served from idle H1 connections.
    // FIFO means anything queued behind the front waits too — break out
    // of the idle-pop branch and let DrainH2StreamWaitersForHost handle
    // admission when an H2 slot frees.
    while (!wait_queue_.empty() && !idle_conns_.empty()) {
        if (wait_queue_.front().kind == WaiterKind::H2_STREAM_SLOT) break;
        // Validate the idle connection
        auto conn = std::move(idle_conns_.front());
        idle_conns_.pop_front();

        // Endpoint generation check — mirrors CheckoutAsync. Without
        // this, a queued waiter could receive an idle keepalive
        // captured to a stale resolved IP if a hostname-aware reload
        // (step 11) atomic-stored a new resolved_endpoint_ between the
        // connection's return-to-idle and ServiceWaitQueue running.
        // The check is a same-pointer compare today; once step 11 lands
        // it actually fences stale handoffs.
        if (!ConnectionEndpointMatches(*conn)) {
            // Drained from idle without re-entering active.
            EmitIdleGaugeDelta(-1.0);
            DestroyConnection(std::move(conn));
            continue;
        }

        if (!ValidateConnection(conn.get())) {
            EmitIdleGaugeDelta(-1.0);
            DestroyConnection(std::move(conn));
            continue;
        }

        // Set far-future deadline to suppress server-wide idle timeout
        static constexpr auto FAR_FUTURE_SWQ = std::chrono::hours(24 * 365);
        conn->MarkInUse();
        conn->GetTransport()->SetDeadline(
            std::chrono::steady_clock::now() + FAR_FUTURE_SWQ);

        UpstreamConnection* raw = conn.get();
        // idle -> active transition matches CheckoutAsync idle-reuse.
        // Record wait time for the front waiter under outcome=queued_satisfied.
        auto wait_dur = std::chrono::duration_cast<std::chrono::duration<double>>(
            std::chrono::steady_clock::now() - wait_queue_.front().queued_at);
        active_conns_.push_back(std::move(conn));
        EmitIdleGaugeDelta(-1.0);
        EmitActiveGaugeDelta(+1.0);
        EmitCheckoutWaitDuration(wait_dur.count(), "queued_satisfied");

        auto entry = std::move(wait_queue_.front());
        wait_queue_.pop_front();
        // Bump inflight_leases_ before the ready_callback runs — see
        // the matching site in ReturnConnection's direct-handoff
        // branch. Idle-pool handoffs must increment too; otherwise
        // the eventual lease release drives active_leases() negative
        // and stalls graceful shutdown's drain wait.
        inflight_leases_.fetch_add(1, std::memory_order_acq_rel);
        entry.ready_callback(UpstreamLease(raw, this, alive_, off_dispatcher_release_drops_, dispatcher_));
        if (!alive->load(std::memory_order_acquire)) return;
        // ready_callback can synchronously start server shutdown
        // (e.g. a first-request callback that calls HttpServer::Stop
        // on a checkout-failure policy). After that, continuing to
        // service queued waiters would create fresh upstream work
        // after manager_shutting_down_ is already true, making the
        // shutdown nondeterministic. Re-check shutdown flags after
        // every waiter callback and bail out if they flipped.
        if (shutting_down_.load(std::memory_order_acquire) ||
            manager_shutting_down_.load(std::memory_order_acquire)) {
            return;
        }
        drop_cancelled_front();
    }

    // If idle connections ran out (all stale) but waiters remain and capacity
    // is available, create new connections for them instead of letting them
    // sit until CHECKOUT_QUEUE_TIMEOUT.
    drop_cancelled_front();
    while (!wait_queue_.empty() && TotalCount() < partition_max_connections_) {
        // H2_STREAM_SLOT at the front gates the create-new branch
        // entirely — replacement-connect for H2 cold-start lives on the
        // wait-queue admission path (StartH2ReplacementConnect now
        // exists; H2_STREAM_SLOT vending stays forward-work until
        // ProxyTransaction migrates to UpstreamLease h2_lease_).
        // Breaking preserves FIFO for any ANY entries queued behind it.
        if (wait_queue_.front().kind == WaiterKind::H2_STREAM_SLOT) break;
        auto entry = std::move(wait_queue_.front());
        wait_queue_.pop_front();
        // CreateNewConnection may synchronously invoke error_cb on inline
        // failures (inet_addr, socket(), ::connect non-EINPROGRESS), which
        // also counts as a callback that may tear the partition down.
        CreateNewConnection(std::move(entry.ready_callback),
                            std::move(entry.error_callback));
        if (!alive->load(std::memory_order_acquire)) return;
        // Re-check shutdown after the synchronous callback path —
        // an inline connect failure's error_cb can trigger server
        // shutdown just like ready_callback above. Without this the
        // next loop iteration could still create a new connection
        // after manager_shutting_down_ is true.
        if (shutting_down_.load(std::memory_order_acquire) ||
            manager_shutting_down_.load(std::memory_order_acquire)) {
            return;
        }
        drop_cancelled_front();
    }
}

void PoolPartition::ScheduleWaitQueuePurge() {
    if (!dispatcher_ || shutting_down_.load(std::memory_order_acquire)) return;
    // Dedup: one chain is enough. Without this, every queued waiter would
    // spawn its own chain, burning CPU under back-pressure.
    if (purge_chain_active_) return;
    purge_chain_active_ = true;

    // RAII guard — see MakeInflightGuard for semantics.
    auto guard = MakeInflightGuard();

    std::weak_ptr<std::atomic<bool>> alive_weak = alive_;
    dispatcher_->EnQueue([this, alive_weak, guard]() {
        auto alive = alive_weak.lock();
        if (!alive || !alive->load(std::memory_order_acquire)) {
            // Partition destroyed — do not touch `this`.
            return;
        }
        // alive==true and destructor waits for inflight=0 (guard not yet
        // destroyed) before freeing members, so touching `this` is safe.
        if (shutting_down_.load(std::memory_order_acquire)) {
            purge_chain_active_ = false;
            return;
        }
        PurgeExpiredWaitEntries();
        if (!alive->load(std::memory_order_acquire)) return;
        if (wait_queue_.empty() || shutting_down_.load(std::memory_order_acquire) || !dispatcher_) {
            purge_chain_active_ = false;
            return;
        }
        // Reschedule via EnQueueDeferred (no wake). This prevents hot-
        // spinning the dispatcher when entries haven't expired yet. The
        // deferred task fires on the next wake (any EnQueue from any
        // source) or the ~1s idle timeout. Accepted limitation: under
        // pure dispatcher isolation with no activity, queue timeouts
        // may be delayed by up to 1s, which is within connect_timeout_ms
        // (minimum 1000ms per config validation).
        auto inner_guard = MakeInflightGuard();
        std::weak_ptr<std::atomic<bool>> inner_alive = alive_;
        dispatcher_->EnQueueDeferred([this, inner_alive, inner_guard]() {
            auto alive2 = inner_alive.lock();
            if (!alive2 || !alive2->load(std::memory_order_acquire)) {
                return;
            }
            if (shutting_down_.load(std::memory_order_acquire)) {
                purge_chain_active_ = false;
                return;
            }
            PurgeExpiredWaitEntries();
            if (!alive2->load(std::memory_order_acquire)) return;
            if (wait_queue_.empty() || shutting_down_.load(std::memory_order_acquire)) {
                purge_chain_active_ = false;
                return;
            }
            // Clear the dedup flag and re-enter — ScheduleWaitQueuePurge
            // will set it again and start a fresh EnQueue→EnQueueDeferred
            // cycle. One logical chain, bounded CPU cost.
            purge_chain_active_ = false;
            ScheduleWaitQueuePurge();
        });
    });
}

void PoolPartition::PurgeExpiredWaitEntries() {
    // Hoist alive_ onto the stack — see ServiceWaitQueue for rationale.
    // A waiter's error_callback may synchronously tear down the partition.
    auto alive = alive_;
    auto now = std::chrono::steady_clock::now();
    while (!wait_queue_.empty()) {
        auto& entry = wait_queue_.front();
        // Cancelled entries at the front can be dropped unconditionally —
        // their owning transaction is already gone and expects no callback.
        if (IsEntryCancelled(entry)) {
            // Record outcome=cancelled with the wait duration; no callback
            // is fired but the histogram tracks the time spent queued.
            auto cancelled_dur = std::chrono::duration_cast<
                std::chrono::duration<double>>(now - entry.queued_at);
            EmitCheckoutWaitDuration(cancelled_dur.count(), "cancelled");
            wait_queue_.pop_front();
            continue;
        }
        auto waited = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - entry.queued_at);
        if (waited.count() >= config_.connect_timeout_ms) {
            // Emit the wait-duration histogram BEFORE the callback so a
            // partition teardown triggered by error_cb (the callback can
            // synchronously call manager_->InitiateShutdown via the
            // transaction's abort hook) doesn't drop the observation.
            // outcome=queue_timeout distinguishes "waited past
            // connect_timeout_ms" from outcome=rejected (queue cap hit
            // at submit time) and outcome=cancelled (waiter's transaction
            // dropped before service).
            auto waited_sec = std::chrono::duration_cast<
                std::chrono::duration<double>>(now - entry.queued_at);
            EmitCheckoutWaitDuration(waited_sec.count(), "queue_timeout");
            auto error_cb = std::move(entry.error_callback);
            logging::Get()->warn(
                "PoolPartition wait queue: aged-out waiter for {} "
                "(waited_ms={}, queue_size={}, timeout_ms={})",
                service_name_, waited.count(),
                wait_queue_.size(), config_.connect_timeout_ms);
            wait_queue_.pop_front();
            error_cb(CHECKOUT_QUEUE_TIMEOUT);
            if (!alive->load(std::memory_order_acquire)) return;
            // error_cb can trigger shutdown — bail so no further
            // waiter is handed a new connect or a queue timeout
            // after the manager has begun tearing down.
            if (shutting_down_.load(std::memory_order_acquire) ||
                manager_shutting_down_.load(std::memory_order_acquire)) {
                return;
            }
        } else {
            break;  // Queue is ordered by time — stop at first non-expired
        }
    }
}

void PoolPartition::CreateForWaiters() {
    // Hoist alive_ — CreateNewConnection may synchronously invoke error_cb
    // (e.g., inet_addr / socket() / ::connect non-EINPROGRESS failures),
    // which could tear down the partition.
    auto alive = alive_;

    PurgeExpiredWaitEntries();
    if (!alive->load(std::memory_order_acquire)) return;

    while (!shutting_down_.load(std::memory_order_acquire) &&
           !manager_shutting_down_.load(std::memory_order_acquire) &&
           !wait_queue_.empty() &&
           TotalCount() < partition_max_connections_) {
        // Drop cancelled entries before spending a new connect on them.
        // Emit outcome=cancelled so operators have visibility on cancel
        // volume during normal operation (not just tear-down paths).
        if (IsEntryCancelled(wait_queue_.front())) {
            auto cancelled_dur =
                std::chrono::duration_cast<std::chrono::duration<double>>(
                    std::chrono::steady_clock::now() -
                    wait_queue_.front().queued_at);
            EmitCheckoutWaitDuration(cancelled_dur.count(), "cancelled");
            wait_queue_.pop_front();
            continue;
        }
        auto entry = std::move(wait_queue_.front());
        wait_queue_.pop_front();
        size_t count_before = TotalCount();
        CreateNewConnection(std::move(entry.ready_callback),
                            std::move(entry.error_callback));
        if (!alive->load(std::memory_order_acquire)) return;
        // If CreateNewConnection succeeded (async connect started), stop —
        // the next waiter will be serviced when this connection completes.
        // On synchronous failure (count didn't increase), try the next
        // waiter — transient errors (e.g., fd exhaustion) may clear.
        if (TotalCount() > count_before) break;
    }
}

void PoolPartition::DestroyConnection(
    std::unique_ptr<UpstreamConnection> conn) {
    if (!conn) return;

    int conn_fd = conn->fd();
    logging::Get()->debug("Destroying upstream connection fd={} {}:{}",
                          conn_fd, upstream_host_, upstream_port_);

    // Remove from dispatcher timer (use IfMatch to guard against fd reuse)
    auto transport = conn->GetTransport();
    if (conn_fd >= 0) {
        dispatcher_->RemoveTimerConnectionIfMatch(conn_fd, transport);
    }
    ClearTransportCallbacks(conn.get());

    if (transport && !transport->IsClosing()) {
        transport->ForceClose();
    }

    // Decrement outstanding counter (release so WaitForDrain acquire-sees it)
    outstanding_conns_.fetch_sub(1, std::memory_order_release);

    // unique_ptr destructor handles the UpstreamConnection cleanup
    conn.reset();

    MaybeSignalDrain();
}

void PoolPartition::EmitIdleGaugeDelta(double delta) {
    auto* obs = obs_manager_.load(std::memory_order_acquire);
    if (!obs || service_name_.empty() || delta == 0.0) return;
    const auto& cat = obs->catalog();
    if (cat.reactor_upstream_pool_connections_idle == nullptr) return;
    cat.reactor_upstream_pool_connections_idle->Add(
        delta, {{"reactor.upstream.service", service_name_}});
}

void PoolPartition::EmitActiveGaugeDelta(double delta) {
    auto* obs = obs_manager_.load(std::memory_order_acquire);
    if (!obs || service_name_.empty() || delta == 0.0) return;
    const auto& cat = obs->catalog();
    if (cat.reactor_upstream_pool_connections_active == nullptr) return;
    cat.reactor_upstream_pool_connections_active->Add(
        delta, {{"reactor.upstream.service", service_name_}});
}

void PoolPartition::EmitCheckoutWaitDuration(double duration_sec,
                                              const char* outcome) {
    auto* obs = obs_manager_.load(std::memory_order_acquire);
    if (!obs || service_name_.empty() || outcome == nullptr) return;
    const auto& cat = obs->catalog();
    if (cat.reactor_upstream_pool_checkout_wait_duration == nullptr) return;
    if (duration_sec < 0.0) duration_sec = 0.0;
    cat.reactor_upstream_pool_checkout_wait_duration->Record(
        duration_sec,
        {{"reactor.upstream.service", service_name_},
         {"outcome", outcome}});
}

void PoolPartition::MaybeSignalDrain() {
    // Check both partition-local and manager-wide shutdown flags.
    // Without the manager check, a lease returned between manager shutdown
    // and partition shutdown won't signal the drain CV, leaving WaitForDrain
    // blocked until timeout.
    if ((shutting_down_.load(std::memory_order_acquire) || manager_shutting_down_.load(std::memory_order_acquire)) &&
        outstanding_conns_.load(std::memory_order_acquire) <= 0) {
        // Lock drain_mtx_ before notify to prevent lost wakeups.
        // Without this, the waiter can check the predicate (sees non-zero),
        // we decrement + notify, then the waiter enters wait_until and
        // misses the notification. The lock serializes the notify with
        // the waiter's predicate check + wait transition.
        {
            std::lock_guard<std::mutex> lck(drain_mtx_);
        }
        drain_cv_.notify_all();
    }
}

void PoolPartition::WirePoolCallbacks(UpstreamConnection* conn) {
    auto transport = conn->GetTransport();
    if (!transport) return;

    // Reset borrower-installed request-level callbacks.
    transport->SetCompletionCb(nullptr);
    transport->SetWriteProgressCb(nullptr);
    transport->SetConnectCompleteCallback(nullptr);
    transport->SetDeadlineTimeoutCb(nullptr);
    // OnCheckoutReady's defer_for_handshake path installs a one-shot
    // handshake callback when ALPN inspection is needed. Consume-on-fire
    // (connection_handler.cc) and weak_self short-circuit on cancel make
    // a stale residual callback safe today, but the safety relies on
    // those subtle invariants. Clearing here makes pool-returned
    // connections structurally clean — defense-in-depth against a future
    // refactor that removes consume-on-fire.
    transport->SetHandshakeCompleteCallback(nullptr);
    // Reset transport-level flags that track an in-flight borrower's
    // backpressure / cap-stop state. ForceClose clears these too; resetting
    // here guarantees they can never survive the borrower-return boundary
    // and poison the next checkout with a stale defer. See
    // DEVELOPMENT_RULES.md ("kqueue EV_EOF coalescing").
    transport->ResetForPoolReuse();
    // Idle pooled transports must never sit with an unbounded read cap.
    // Unexpected bytes are treated as poison below, but ConnectionHandler
    // reads into input_bf_ before the callback runs.
    transport->SetMaxInputSize(MAX_BUFFER_SIZE);

    // Install pool-owned idle read handler: any data received on an idle
    // pooled connection is suspicious (late response chunk, protocol
    // garbage, half-close preamble). Force-close instead of letting
    // ConnectionHandler silently buffer the bytes — otherwise the next
    // checkout would see stale data prepended to its own response.
    std::weak_ptr<std::atomic<bool>> alive_weak_idle = alive_;
    transport->SetOnMessageCb(
        [alive_weak_idle]
        (std::shared_ptr<ConnectionHandler> handler, std::string&) {
            auto alive = alive_weak_idle.lock();
            if (!alive || !alive->load(std::memory_order_acquire)) return;
            // Only poison if still idle (not mid-checkout — borrower's
            // on_message_callback is installed during checkout).
            // Any data arriving on this callback means no borrower
            // has overridden it — treat as poison.
            logging::Get()->debug("Idle upstream connection received "
                                  "unexpected data fd={}, force-closing",
                                  handler ? handler->fd() : -1);
            if (handler && !handler->IsClosing()) {
                handler->ForceClose();
            }
        });

    // Re-wire pool-owned close + error callbacks. These handle pool
    // bookkeeping AND notify the borrower (if checked out) by firing
    // on_message_callback with an empty string to signal EOF. Without
    // this, a borrower waiting on SetOnMessageCb hangs indefinitely
    // when the upstream disconnects mid-request.
    UpstreamConnection* raw_conn = conn;
    transport->SetCloseCb(
        [this, raw_conn](std::shared_ptr<ConnectionHandler> handler) {
            // Hoist captures to stack locals BEFORE OnConnectionClosed.
            // That helper calls ClearTransportCallbacks which null-assigns
            // this very SetCloseCb std::function, destroying the closure
            // while operator() is still executing. Post-cleanup access
            // must go through locals, not the now-freed captures.
            PoolPartition* self = this;
            UpstreamConnection* conn = raw_conn;
            // Save the borrower's on_message_callback BEFORE pool cleanup —
            // the notification below may trigger ReturnConnection which
            // could destroy the connection.
            CALLBACKS_NAMESPACE::ConnOnMsgCallback borrower_cb;
            if (conn->IsInUse() && handler) {
                borrower_cb = handler->GetOnMessageCb();
            }
            self->OnConnectionClosed(conn);
            // Notify borrower of upstream disconnect. Empty data = EOF.
            if (borrower_cb && handler) {
                std::string empty;
                try { borrower_cb(handler, empty); } catch (...) {}
            }
        });
    transport->SetErrorCb(
        [this, raw_conn](std::shared_ptr<ConnectionHandler> handler) {
            // Same capture-hoist rationale as SetCloseCb above.
            PoolPartition* self = this;
            UpstreamConnection* conn = raw_conn;
            CALLBACKS_NAMESPACE::ConnOnMsgCallback borrower_cb;
            if (conn->IsInUse() && handler) {
                borrower_cb = handler->GetOnMessageCb();
            }
            self->OnConnectionClosed(conn);
            if (borrower_cb && handler) {
                std::string empty;
                try { borrower_cb(handler, empty); } catch (...) {}
            }
        });
}


// ── Extract helpers ────────────────────────────────────────────────────

// Shared implementation: find conn by raw pointer, erase, return owned.
template<typename Container>
static std::unique_ptr<UpstreamConnection> ExtractFromContainer(
    Container& c, UpstreamConnection* conn) {
    for (auto it = c.begin(); it != c.end(); ++it) {
        if (it->get() == conn) {
            auto owned = std::move(*it);
            c.erase(it);
            return owned;
        }
    }
    return nullptr;
}

std::unique_ptr<UpstreamConnection> PoolPartition::ExtractFromIdle(
    UpstreamConnection* conn) {
    return ExtractFromContainer(idle_conns_, conn);
}

std::unique_ptr<UpstreamConnection> PoolPartition::ExtractFromActive(
    UpstreamConnection* conn) {
    return ExtractFromContainer(active_conns_, conn);
}

std::unique_ptr<UpstreamConnection> PoolPartition::ExtractFromConnecting(
    UpstreamConnection* conn) {
    return ExtractFromContainer(connecting_conns_, conn);
}
