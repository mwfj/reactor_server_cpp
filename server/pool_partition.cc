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
#include <future>

// ── UpstreamLease out-of-line definitions ──────────────────────────────
// These live here because the destructor/Release need the complete
// PoolPartition type (forward-declared in upstream_lease.h).

UpstreamLease::~UpstreamLease() {
    Release();
}

void UpstreamLease::Release() {
    // Skip the return if the partition was already destroyed — ~PoolPartition
    // stores false to alive_ BEFORE freeing any member, and the partition's
    // own destructor walk already nulls transport callbacks for the connections
    // it owns (including zombies). Without this guard, a lease that outlives
    // its partition (standalone UpstreamManager teardown with an outstanding
    // lease) would dereference freed memory via partition_->ReturnConnection.
    if (conn_ && partition_ && alive_ &&
        alive_->load(std::memory_order_acquire)) {
        partition_->ReturnConnection(conn_);
    }
    conn_ = nullptr;
    partition_ = nullptr;
    alive_.reset();
}

// ── PoolPartition ──────────────────────────────────────────────────────

PoolPartition::PoolPartition(
    std::shared_ptr<Dispatcher> dispatcher,
    const std::string& upstream_host, int upstream_port,
    const std::string& sni_hostname,
    std::shared_ptr<const NET_DNS_NAMESPACE::ResolvedEndpoint> resolved_endpoint,
    const UpstreamPoolConfig& config,
    std::shared_ptr<TlsClientContext> tls_ctx,
    std::atomic<int64_t>& outstanding_conns,
    std::atomic<int64_t>& inflight_leases,
    std::atomic<bool>& manager_shutting_down,
    std::mutex& drain_mtx,
    std::condition_variable& drain_cv,
    const std::string& service_name)
    : dispatcher_(std::move(dispatcher))
    , upstream_host_(upstream_host)
    , upstream_port_(upstream_port)
    , sni_hostname_(sni_hostname)
    , config_(config)
    , tls_ctx_(std::move(tls_ctx))
    , service_name_(service_name)
    , resolved_endpoint_(std::move(resolved_endpoint))
    , outstanding_conns_(outstanding_conns)
    , inflight_leases_(inflight_leases)
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

void PoolPartition::ReturnConnection(UpstreamConnection* conn) {
    if (!conn) return;

    // The lease that owned `conn` is being released — decrement
    // inflight_leases_ once per call regardless of where the connection
    // ends up (idle pool / destroyed / zombie cleanup). Pairs with the
    // increment at every ready_cb(UpstreamLease(...)) site above.
    inflight_leases_.fetch_sub(1, std::memory_order_acq_rel);

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
            entry.ready_callback(UpstreamLease(raw, this, alive_));
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

std::shared_ptr<UpstreamH2Connection> PoolPartition::FindUsableH2Connection(
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
    if (auto existing = h2_table_.FindUsable(upstream_name)) {
        UpstreamConnection* t = existing->transport();
        if (t && ConnectionEndpointMatches(*t)) {
            return existing;
        }
        existing->MarkDead();
    }
    return nullptr;
}

std::shared_ptr<UpstreamH2Connection> PoolPartition::AcquireH2Connection(
    const std::string& upstream_name, UpstreamLease& lease)
{
    // Reuse a multiplexed session if one is still healthy AND its
    // transport matches the partition's currently-published endpoint.
    // Same FindUsableH2Connection helper that ProxyTransaction's
    // pre-checkout fast path uses — caller's lease (if any) is
    // untouched on the reuse branch. See FindUsableH2Connection's
    // doc comment for the H1-keepalive-parity / dead-conn reap chain.
    if (auto existing = FindUsableH2Connection(upstream_name)) {
        return existing;
    }

    auto cfg = LoadHttp2ConfigSnapshot();
    if (!cfg || !cfg->enabled) return nullptr;

    auto* up = lease.Get();
    if (!up) return nullptr;
    auto transport = up->GetTransport();
    if (!transport) return nullptr;

    auto h2 = std::make_shared<UpstreamH2Connection>(up, cfg);

    // Callbacks wired BEFORE Init() because Init's preface flush can
    // fire complete_callback synchronously on a writable transport
    // (DoSendRaw direct-write path) — our drain attribution must be
    // active for that bootstrap traffic. The H2 connection
    // multiplexes the transport for its lifetime; pool accounting
    // follows the lease destructor when the H2 connection retires.
    std::weak_ptr<UpstreamH2Connection> wk = h2;
    transport->SetOnMessageCb(
        [wk](std::shared_ptr<ConnectionHandler>, std::string& data) {
            auto h = wk.lock();
            if (!h) return;
            ssize_t rv = h->HandleBytes(data.data(), data.size());
            if (rv < 0) {
                // MarkDead BEFORE the fail-fan-out so a concurrent
                // FindUsable can't pick this conn between the in-flight
                // streams being failed and the table eviction. See the
                // UPSTREAM_PROXY.md pitfall on dead_ vs goaway_seen_.
                h->MarkDead();
                h->FailAllStreams(
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
        [wk](std::shared_ptr<ConnectionHandler>) {
            auto h = wk.lock();
            if (!h) return;
            // MarkDead BEFORE FailAllStreams (mirrors PING-timeout and
            // session-fatal-error sites). A FindUsable racing the
            // fan-out would otherwise see streams_.empty() with
            // dead_=false and return this conn, whose transport is
            // already gone.
            h->MarkDead();
            h->FailAllStreams(
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
        [wk](std::shared_ptr<ConnectionHandler>) {
            auto h = wk.lock();
            if (!h) return;
            h->MarkDead();
            h->FailAllStreams(
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
        [wk](std::shared_ptr<ConnectionHandler>, size_t remaining) {
            auto h = wk.lock();
            if (!h) return;
            h->OnTransportWriteProgress(remaining);
        });
    transport->SetCompletionCb(
        [wk](std::shared_ptr<ConnectionHandler>) {
            auto h = wk.lock();
            if (!h) return;
            h->OnTransportWriteComplete();
        });

    if (!h2->Init()) {
        logging::Get()->warn(
            "PoolPartition::AcquireH2Connection: Init failed upstream={} "
            "host={}:{}",
            upstream_name, upstream_host_, upstream_port_);
        // Unwire our weak_ptr closures before the transport returns to
        // the pool — WirePoolCallbacks doesn't overwrite completion /
        // write-progress on reuse.
        ClearTransportCallbacks(up);
        return nullptr;
    }

    h2->AdoptLease(std::move(lease));
    h2_table_.Insert(upstream_name, h2);
    return h2;
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
    while (!wait_queue_.empty() && !idle_conns_.empty()) {
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
