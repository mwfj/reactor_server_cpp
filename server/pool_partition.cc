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
#include <cassert>
#include <future>

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

#ifndef NDEBUG
    // Dispatcher-thread-only invariant. Release calls into
    // partition_->ReturnConnection / ReturnH2Stream which mutate
    // idle_conns_ / active_conns_ / h2_table_ — all dispatcher-locked-
    // by-convention with no internal mutex. A cross-thread Release would
    // race those containers. Assert in debug builds only because the
    // invariant is enforced socially today; if a future async drop site
    // violates it, this fires loudly.
    if (partition_live && partition_->dispatcher() &&
        !partition_->dispatcher()->is_on_loop_thread()) {
        logging::Get()->error(
            "UpstreamLease::Release: called off the partition dispatcher "
            "thread — container mutation race");
        assert(false &&
               "UpstreamLease::Release must run on partition dispatcher");
    }
#endif

    if (kind_ == Kind::H1 && partition_live && conn_) {
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

PoolPartition::~PoolPartition() {
    // Atomic write — stops new purge chains from being scheduled.
    alive_->store(false, std::memory_order_release);

    // The destructor cannot safely walk containers off-thread (close
    // callbacks fired by dispatcher channel events can mutate them
    // concurrently). Instead, enqueue a task that runs on the dispatcher
    // thread and does ALL the work: walk containers, collect transports,
    // clear callbacks. Then wait for the task to complete via inflight_tasks_.
    //
    // The inflight counter uses an RAII guard so the decrement fires even
    // if EnQueue drops the task (dispatcher stopped mid-shutdown). Without
    // this, a lossy EnQueue would leak the counter and the destructor
    // would hang forever.

    auto on_dispatcher = [this]() {
        // On dispatcher thread — single-threaded, no concurrent mutation.
        // Safe to walk containers and touch connection transports.
        // Drop H2 sessions FIRST so their nghttp2_session destructors
        // run before the underlying transports get their callbacks
        // nulled (the H2 connection's lease destructor returns the
        // transport to the pool and the pool walk below frees them).
        // ~UpstreamH2Connection nulls its transport callbacks BEFORE
        // running terminate_session + FlushSend, so a stray incoming-
        // bytes event during the destruction window cannot reenter
        // HandleBytes on a session about to be torn down. This is
        // independent of SendRaw's was_stopped() drop — closes the
        // door on a future SendRaw refactor that removes that check.
        h2_table_.Clear();
        // Drop H2 cold-start probe shells and pending-destroy stash on
        // the dispatcher thread so each shell's ~UpstreamH2Connection
        // safety-net path (transport callback unwire + MarkClosing +
        // FlushSend of any terminate_session GOAWAY) runs here rather
        // than spilling to whatever thread happens to call ~PoolPartition.
        // The underlying transports live in connecting_conns_ /
        // active_conns_ (cleared right below) so transport_->MarkClosing
        // inside the H2 dtors does not UAF.
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

    // Wait for all in-flight dispatcher tasks to complete. Every lambda
    // that touches `this` increments inflight_tasks_ before enqueue and
    // decrements via RAII guard, so this counter is accurate even under
    // lossy EnQueue (dispatcher stopped mid-shutdown).
    //
    // No timeout — we MUST wait. A stale task firing after the destructor
    // returns would dereference freed members. inflight_tasks_ is a
    // shared_ptr<atomic>, so it outlives the partition safely.
    //
    // If this destructor is running ON the dispatcher thread (standalone
    // teardown from a pool callback), the queued tasks cannot drain by
    // themselves — the loop thread is us, blocked here. Drain them
    // inline via ProcessPendingTasks. Without this, the destructor
    // deadlocks under load whenever a purge/shutdown task is still queued.
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
            DestroyConnection(std::move(conn));
            continue;
        }

        if (!ValidateConnection(conn.get())) {
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
        // Bump inflight_leases_ BEFORE handing the lease to the caller.
        // ReturnConnection (called from ~UpstreamLease) decrements.
        inflight_leases_.fetch_add(1, std::memory_order_acq_rel);
        ready_cb(UpstreamLease(raw, this, alive_));
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
    error_cb(CHECKOUT_POOL_EXHAUSTED);
}

size_t PoolPartition::PurgeCancelledWaitEntries() {
    size_t before = wait_queue_.size();
    // std::deque supports erase via iterators; walk forward and erase
    // cancelled entries in place. Callbacks are NOT fired — a cancelled
    // checkout's owning transaction has already been torn down via the
    // framework abort hook and does not expect any completion.
    for (auto it = wait_queue_.begin(); it != wait_queue_.end(); ) {
        if (IsEntryCancelled(*it)) {
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
            // Push back what we've already moved out so shutdown drain
            // sees them and fires CHECKOUT_SHUTTING_DOWN uniformly.
            requeue.push_back(std::move(e));
            stopped_early = true;
            continue;
        }
        UpstreamH2Connection* h2 = h2_table_.FindUsable(upstream_name);
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

    // Capacity-aware fan-out. Each fired waiter synchronously dispatches
    // through TryDispatchExistingH2Session → SubmitRequest which bumps
    // active_streams_. Over-firing under a tight max_concurrent_streams
    // cap would fail siblings inside SubmitRequest's IsUsable() gate
    // (returns -1), even though they won the dequeue race. Refuse to
    // admit unless FindUsable still reports a slot is available.
    //
    // continue vs break on FindUsable=null: FindUsable is deterministic
    // across iterations of THIS drain — ready_callback creates no new
    // sessions and the live h2_table_ entry only sheds capacity, never
    // gains it. So once FindUsable returns null it stays null; continue
    // and break are observationally equivalent on the !h2 branch.
    // continue is chosen for symmetry with the shutdown-flip branch
    // which DOES need to drain remaining entries into the requeue
    // deque.
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
            requeue.push_back(std::move(e));
            continue;
        }
        UpstreamH2Connection* h2 = h2_table_.FindUsable(service_name_);
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

    // Restore FIFO: push_front in reverse so first requeued ends up
    // at wait_queue_.front().
    for (auto it = requeue.rbegin(); it != requeue.rend(); ++it) {
        wait_queue_.push_front(std::move(*it));
    }
}

void PoolPartition::MoveConnToPendingDestroy(UpstreamH2Connection* conn) {
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
    // Snapshot BOTH containers together BEFORE running destroy. A
    // destroy step's callback chain (sink OnError →
    // ProxyTransaction::Cleanup → ResetStream → late GOAWAY handling)
    // could re-enter MoveConnToPendingDestroy, which appends to BOTH
    // pending_destroy_h2_conns_ and pending_h2_replacement_targets_.
    // If we snapshot targets AFTER destroy, the newly-appended target
    // is picked up here while its newly-appended victim sits unmoved
    // in pending_destroy_h2_conns_ — StartH2ReplacementConnect runs
    // BEFORE that victim's slot is freed, and under
    // pool.max_connections=1 the cap-gate rejects the probe and the
    // target is silently lost.
    // Both snapshots taken together. Reentrant additions stay in the
    // members for the NEXT reap, where they get paired correctly
    // (victim destroyed → slot freed → target drained).
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
        DestroyConnection(std::move(owned));
        return;
    }

    // Early-response poison: if the borrower marked this connection as closing
    // (e.g., upstream sent a response before the request write completed, leaving
    // stale request bytes in the transport's output buffer), destroy it instead
    // of returning to idle.
    if (owned->IsClosing()) {
        DestroyConnection(std::move(owned));
        CreateForWaiters();
        return;
    }

    // Endpoint generation check on return. A reload that atomic-stored a
    // new resolved_endpoint_ between this connection's checkout and its
    // return leaves the connection bound to the OLD IP. The downstream
    // CheckoutAsync / ServiceWaitQueue idle-pop sites already reject
    // mismatched endpoints, but two paths in this function bypass that
    // gate by reusing `owned` synchronously without going through
    // idle_conns_:
    //   (1) the over-idle-cap direct waiter handoff below pops a waiter
    //       and hands it `owned` after only ValidateConnection — never
    //       consulting ConnectionEndpointMatches.
    //   (2) the trailing ServiceWaitQueue() fires while `owned` is still
    //       at the front of idle_conns_ (just pushed); the queued waiter
    //       could grab a stale-IP keepalive that was returned post-swap.
    // Failing closed at the entry guarantees a returning post-swap
    // connection is destroyed + a fresh-endpoint replacement is created
    // for any queued waiter via CreateForWaiters.
    if (!ConnectionEndpointMatches(*owned)) {
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
        while (!wait_queue_.empty() && IsEntryCancelled(wait_queue_.front())) {
            wait_queue_.pop_front();
        }
        if (!wait_queue_.empty() && ValidateConnection(owned.get())) {
            // Hand directly to the next waiter (validated — not dead/expired)
            static constexpr auto FAR_FUTURE_HANDOFF = std::chrono::hours(24 * 365);
            owned->MarkInUse();
            owned->GetTransport()->SetDeadline(
                std::chrono::steady_clock::now() + FAR_FUTURE_HANDOFF);
            UpstreamConnection* raw = owned.get();
            active_conns_.push_back(std::move(owned));
            auto entry = std::move(wait_queue_.front());
            wait_queue_.pop_front();
            // Bump inflight_leases_ BEFORE the handoff. The fetch_sub
            // at the top of ReturnConnection paired with the released
            // lease; this is a brand-new lease handed to a waiter and
            // needs its own increment so the waiter's eventual return
            // brings the counter back to balance. Without this the
            // counter goes negative on every queued-reuse handoff and
            // the observability shutdown drain never observes
            // active_leases() == 0.
            inflight_leases_.fetch_add(1, std::memory_order_acq_rel);
            entry.ready_callback(UpstreamLease(raw, this, alive_));
            // No member access follows (function returns), but keep the
            // check for defense-in-depth against future refactors.
            if (!alive->load(std::memory_order_acquire)) return;
        } else {
            // No waiters, or connection is dead/expired — destroy it.
            // If waiters exist but connection is invalid, create a replacement.
            DestroyConnection(std::move(owned));
            CreateForWaiters();
        }
        return;
    }

    // Set idle deadline for timeout scanning
    auto idle_deadline = std::chrono::steady_clock::now() +
                         std::chrono::seconds(config_.idle_timeout_sec);
    owned->GetTransport()->SetDeadline(idle_deadline);

    // Push to front (MRU)
    idle_conns_.push_front(std::move(owned));

    // Service any waiting requests
    ServiceWaitQueue();
}

void PoolPartition::ReturnH2Stream(
    UpstreamH2Connection* h2_conn, int32_t stream_id,
    std::shared_ptr<std::atomic<bool>> /*partition_alive*/,
    std::shared_ptr<std::atomic<bool>> /*conn_alive*/) {
    // Reaching this entry means an UpstreamLease::Kind::H2 destructor
    // ran without a wired H2-lease vending path. Stream teardown today
    // is driven by OnStreamClose / ResetStream / RunDeferredEraseWalk
    // — silent no-op here would mask a future caller that DOES vend
    // H2 leases via this API but forgot to drain the waiter queue.
    // FIXME: implement DrainH2StreamWaitersForHost dispatch once the
    // h2_lease_ migration on ProxyTransaction lands.
    logging::Get()->error(
        "BUG: PoolPartition::ReturnH2Stream called without a wired "
        "H2-lease vending path (h2_conn={}, stream_id={}) — H2 stream "
        "slot release dropped; queued H2_STREAM_SLOT waiters will not "
        "be admitted.",
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

UpstreamH2Connection* PoolPartition::FindUsableH2Connection(
    const std::string& upstream_name)
{
    // After a hostname re-resolution, an existing session pinned to the
    // old IP must NOT serve fresh requests; mark it dead so future
    // FindUsable() skips it. In-flight streams on that connection are
    // deliberately NOT failed here — mirrors the H1 keepalive reuse
    // contract that lets requests already on the wire complete
    // naturally. Three paths reap the dead connection afterwards:
    // (a) normal stream completion drains active_stream_count to 0 and
    //     TickAll's `IsDead() && empty` branch erases the entry;
    // (b) transport close/error fires SetCloseCb / SetErrorCb (wired
    //     in AcquireH2Connection's construct branch) which run
    //     FailAllStreams + the table walker erases on the next Tick;
    // (c) endpoint loss times out via ping_timeout_sec /
    //     goaway_drain_timeout_sec, Tick returns false, FailAllStreams
    //     fires, table walker erases.
    if (auto* existing = h2_table_.FindUsable(upstream_name)) {
        UpstreamConnection* t = existing->transport();
        if (t && ConnectionEndpointMatches(*t)) {
            return existing;
        }
        existing->MarkDead();
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
    // Reuse a multiplexed session if one is still healthy AND its
    // transport matches the partition's currently-published endpoint.
    // Same FindUsableH2Connection helper that ProxyTransaction's
    // pre-checkout fast path uses — caller's lease (if any) is
    // untouched on the reuse branch. See FindUsableH2Connection's
    // doc comment for the H1-keepalive-parity / dead-conn reap chain.
    if (auto* existing = FindUsableH2Connection(upstream_name)) {
        return existing;
    }

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

void PoolPartition::ScheduleInitiateShutdown() {
    // Direct call if no dispatcher (degenerate/test path).
    if (!dispatcher_) {
        InitiateShutdown();
        return;
    }
    // Already on the dispatcher thread — run inline.
    if (dispatcher_->is_dispatcher_thread()) {
        InitiateShutdown();
        return;
    }
    // Dispatcher already stopped (threads joined) — EnQueue would silently
    // drop the lambda, leaving idle/connecting connections alive and the
    // outstanding_conns_ counter stuck above zero, which would hang
    // ~UpstreamManager's drain wait forever. Run inline: no dispatcher
    // thread exists to race with container mutations, so touching
    // idle_conns_/connecting_conns_ from the stopper thread is safe.
    if (dispatcher_->was_stopped()) {
        InitiateShutdown();
        return;
    }
    // Off-thread: enqueue and track via MakeInflightGuard so ~PoolPartition
    // blocks until the lambda has executed (or been dropped by a stopped
    // dispatcher). Guarded by alive_weak so a task that somehow races past
    // the destructor is a no-op instead of a UAF on freed containers.
    auto guard = MakeInflightGuard();
    std::weak_ptr<std::atomic<bool>> alive_weak = alive_;
    dispatcher_->EnQueue([this, alive_weak, guard]() {
        auto alive = alive_weak.lock();
        if (!alive || !alive->load(std::memory_order_acquire)) return;
        InitiateShutdown();
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

void PoolPartition::InitiateShutdown() {
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

    // Retire H2 sessions explicitly. Each session holds a donated
    // UpstreamLease whose destructor decrements outstanding_conns_ via
    // ReturnConnection → DestroyConnection (shutting_down_ branch).
    // Without this, an idle H2 session would keep its lease alive
    // until ~PoolPartition's dispatcher lambda calls h2_table_.Clear()
    // — but that runs AFTER WaitForDrain blocks on outstanding_conns_,
    // so the manager destructor deadlocks until WAIT_FOR_DRAIN_TIMEOUT.
    //
    // Mid-loop bailout safety: if `alive` flips between iterations,
    // `h2_to_destroy` is a local vector whose unique_ptr dtors run on
    // this thread at scope exit. Each safety-net dtor performs
    // memory-only ops (MarkDead, FailAllStreams, terminate_session,
    // FlushSend, MarkClosing); the only sink-emitter (FlushSend) routes
    // SendRaw through ConnectionHandler which handles cross-thread via
    // EnQueue. Safe to bail out — the dtors complete the teardown.
    auto h2_to_destroy = h2_table_.ExtractAll();
    for (auto& conn : h2_to_destroy) {
        if (conn) conn->DestroyOnDispatcher();
        if (!alive->load(std::memory_order_acquire)) return;
        // unique_ptr lapses at scope end → dtor's destroyed_on_dispatcher_
        // short-circuit fires; lease was released by step 5 above.
    }

    // Connecting H2 probes: same shape. The probe shell's transport is
    // in connecting_conns_ above (already drained by the connecting
    // loop). What remains is the H2 session wrapper — destroy it on
    // dispatcher to flip its alive token before the dtor runs.
    for (auto& kv : h2_connecting_conns_) {
        if (kv.second) kv.second->DestroyOnDispatcher();
        if (!alive->load(std::memory_order_acquire)) return;
    }
    h2_connecting_conns_.clear();

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
            DestroyConnection(std::move(owned));
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

    // See the matching site above — bump before handing the lease out.
    inflight_leases_.fetch_add(1, std::memory_order_acq_rel);
    ready_cb(UpstreamLease(raw, this, alive_));
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
    if (!owned) {
        owned = ExtractFromActive(conn);
        if (owned) was_active = true;
    }
    if (!owned) owned = ExtractFromIdle(conn);

    if (owned) {
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
    connecting_conns_.push_back(std::move(upstream_conn));

    // Each Set*Cb below moves a std::function whose closure captures
    // alive / timed_out / raw_uc — at sizes large enough that SBO does
    // not apply, so the move triggers a heap allocation that can throw
    // bad_alloc. The try covers every such call (plus
    // RegisterOutboundCallbacks below) so a throw anywhere routes
    // through the single catch-handler rollback rather than stranding
    // partial wiring on the transport with `outstanding_conns_` bumped.
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
    } catch (const std::exception& e) {
        logging::Get()->error(
            "OpenNewH2Connection: setup failed for {}:{}: {}",
            upstream_name, port, e.what());
        // The shell `h2` has not been inserted into h2_connecting_conns_
        // yet — drop it before the rollback so its dtor's safety-net
        // (which nulls SetCloseCb / SetErrorCb on the transport) runs
        // BEFORE DestroyConnection's ForceClose. After h2.reset() the
        // transport has no H2 close-cb installed, so the ForceClose
        // close-callback chain is a no-op for H2 purposes; the
        // outstanding_conns_ decrement is handled inline by
        // DestroyConnection. No queued H2_STREAM_SLOT waiters exist
        // for this key at this point (OpenNewH2Connection runs before
        // any waiter could enqueue), so no fan-out is needed.
        h2.reset();
        if (auto owned = ExtractFromConnecting(raw_uc)) {
            DestroyConnection(std::move(owned));
        } else {
            // Transport vanished from connecting_conns_ between this
            // function's setup and the rollback path — almost certainly
            // a synchronous close-cb chain that already extracted it.
            // outstanding_conns_ was bumped at CreateNewConnection but
            // never decremented if DestroyConnection didn't run; surface
            // the leak so future refactors that widen this race don't
            // hide it.
            logging::Get()->error(
                "OpenNewH2Connection rollback: ExtractFromConnecting "
                "returned null for {}:{} — outstanding_conns_ may have "
                "leaked unless the close-callback chain decremented it",
                upstream_name, port);
        }
        return false;
    }

    h2_connecting_conns_[HostPortKey{upstream_name, port}] = std::move(h2);
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
        // prefer=auto: hand the negotiated h1 transport to the H1 idle
        // pool so a subsequent H1 dispatch can borrow it without a
        // second TCP/TLS handshake. Queued H2_STREAM_SLOT waiters for
        // this upstream are reclassified to ANY-kind so ServiceWaitQueue
        // can match them against the freshly-adopted idle conn.
        auto owned_uc = uc_raw ? ExtractFromConnecting(uc_raw) : nullptr;
        if (!owned_uc) {
            if (shell) shell->DestroyOnDispatcher();
            FailH2StreamSlotWaiters(upstream_name, port,
                                    CHECKOUT_CONNECT_FAILED,
                                    "transport vanished pre-h1-adoption");
            return;
        }
        // Exception-safe adoption sequence:
        //  1. AdoptAsH1Connection takes `owned_uc` by REFERENCE and
        //     commits via push_back at the end. If it throws (e.g.
        //     push_back bad_alloc, callback wiring fails), owned_uc
        //     still owns the transport — the caller must destroy it
        //     AND null shell->transport_ to prevent the shell's
        //     safety-net dtor from dereferencing a freed transport.
        //  2. MarkTransferred fires ONLY after the commit succeeds.
        //     A late ReclassifyH2WaitersToAny throw after MarkTransferred
        //     is harmless: the H2 shell's dtor short-circuits via
        //     transferred_, the transport is alive in idle_conns_.
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
        // Distinguish the two shapes for shutdown-ordering forensics:
        // - shell-only-missing (uc_raw still present): a concurrent
        //   teardown reached the shell map first; uc_raw needs explicit
        //   destruction here.
        // - dual-null (uc_raw also vanished): a concurrent shutdown
        //   reaped both the shell AND the transport from connecting_conns_
        //   before this disposition path ran; nothing left to free, and
        //   FailH2StreamSlotWaiters is a no-op today (no production
        //   enqueuer) — so this branch returns silently otherwise. Log
        //   at debug so a future shutdown-ordering regression has a
        //   diagnostic trail.
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

    // Wire the multiplexed-H2-session transport callbacks BEFORE Init().
    // Init()'s preface flush can fire complete_callback synchronously on
    // a writable transport (DoSendRaw direct-write path) — the same
    // contract AcquireH2Connection's in-place promotion path observes.
    // Without this, the freshly-promoted session would have no path for
    // response bytes (no OnMessage → no HandleBytes) and the probe-phase
    // SetCloseCb / SetErrorCb would still point at the failure-disposition
    // closures (semantically wrong after h2_table_ insertion). Wrapped
    // in try/catch because each Set*Cb assignment moves a std::function
    // whose closure can trigger heap allocation that throws bad_alloc;
    // a mid-wire throw would otherwise orphan uc_raw in connecting_conns_
    // with outstanding_conns_ leaked.
    try {
        WireH2SessionTransportCallbacks(uc_raw, shell.get());
    } catch (const std::exception& e) {
        logging::Get()->error(
            "OnH2ConnectHandshakeComplete: WireH2SessionTransportCallbacks "
            "threw for {}:{}: {}",
            upstream_name, port, e.what());
        if (uc_raw) ClearTransportCallbacks(uc_raw);
        // ClearTransportCallbacks alone is not sufficient: SetOnMessageCb
        // is wired first, so a mid-wire throw can leave an OnMessage
        // closure live on the transport that captured `shell.get()`.
        // fail() routes through `shell->DestroyOnDispatcher()` which
        // flips conn_alive_->false BEFORE freeing the shell; any
        // surviving callback's alive-token guard short-circuits before
        // dereferencing the destroyed shell.
        fail(CHECKOUT_CONNECT_FAILED, "h2 wire-callbacks threw");
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
    shell->AdoptLease(UpstreamLease(uc_raw, this, alive_));

    h2_table_.Insert(upstream_name, std::move(shell));
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
    if (h2_table_.FindUsable(upstream_name) != nullptr) {
        logging::Get()->debug(
            "StartH2ReplacementConnect skipped (usable session exists) "
            "upstream={}:{}",
            upstream_name, port);
        return;
    }
    if (TotalCount() >= partition_max_connections_) {
        // Cap-saturated probe rejection is the failure mode that
        // motivated the pending_h2_replacement_targets_ deque. The
        // OnGoawayReceived call site queues a target via
        // MoveConnToPendingDestroy BEFORE this inline call — under
        // pool.max_connections=1 the dying session still occupies the
        // slot, so this branch is the EXPECTED no-op; the post-recv
        // ReapPendingDestroyH2Conns retries successfully. Suppress to
        // debug when the target is already pending (design-target
        // case). Steady-state cap pressure with no pending target is
        // worth a warn because queued waiters will time out at
        // MAX_QUEUE_AGE otherwise.
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
    // Pre-commit work first. Any throw here leaves `conn` unchanged
    // (caller still owns it) so the H2 shell's transport_ raw pointer
    // does not dangle while the caller's catch routes the transport
    // through DestroyConnection. WirePoolCallbacks's std::function
    // assignments and SetDeadline are the realistic throw sites
    // (std::bad_alloc on SBO→heap promotion is unlikely but
    // possible).
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
    // handled that side.
    auto drop_cancelled_front = [this]() {
        while (!wait_queue_.empty() && IsEntryCancelled(wait_queue_.front())) {
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
            DestroyConnection(std::move(conn));
            continue;
        }

        if (!ValidateConnection(conn.get())) {
            DestroyConnection(std::move(conn));
            continue;
        }

        // Set far-future deadline to suppress server-wide idle timeout
        static constexpr auto FAR_FUTURE_SWQ = std::chrono::hours(24 * 365);
        conn->MarkInUse();
        conn->GetTransport()->SetDeadline(
            std::chrono::steady_clock::now() + FAR_FUTURE_SWQ);

        UpstreamConnection* raw = conn.get();
        active_conns_.push_back(std::move(conn));

        auto entry = std::move(wait_queue_.front());
        wait_queue_.pop_front();
        // Bump inflight_leases_ before the ready_callback runs — see
        // the matching site in ReturnConnection's direct-handoff
        // branch. Idle-pool handoffs must increment too; otherwise
        // the eventual lease release drives active_leases() negative
        // and stalls graceful shutdown's drain wait.
        inflight_leases_.fetch_add(1, std::memory_order_acq_rel);
        entry.ready_callback(UpstreamLease(raw, this, alive_));
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
            wait_queue_.pop_front();
            continue;
        }
        auto waited = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - entry.queued_at);
        if (waited.count() >= config_.connect_timeout_ms) {
            auto error_cb = std::move(entry.error_callback);
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
        if (IsEntryCancelled(wait_queue_.front())) {
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
