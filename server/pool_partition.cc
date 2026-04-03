#include "upstream/pool_partition.h"
#include "upstream/upstream_lease.h"
#include "upstream/upstream_connection.h"
#include "socket_handler.h"
#include "tls/tls_client_context.h"
#include "tls/tls_connection.h"
#include "log/logger.h"
#include "log/log_utils.h"

// ── UpstreamLease out-of-line definitions ──────────────────────────────
// These live here because the destructor/Release need the complete
// PoolPartition type (forward-declared in upstream_lease.h).

UpstreamLease::~UpstreamLease() {
    Release();
}

void UpstreamLease::Release() {
    if (conn_ && partition_) {
        partition_->ReturnConnection(conn_);
    }
    conn_ = nullptr;
    partition_ = nullptr;
}

// ── PoolPartition ──────────────────────────────────────────────────────

PoolPartition::PoolPartition(
    std::shared_ptr<Dispatcher> dispatcher,
    const std::string& upstream_host, int upstream_port,
    const std::string& sni_hostname,
    const UpstreamPoolConfig& config,
    std::shared_ptr<TlsClientContext> tls_ctx,
    std::atomic<int64_t>& outstanding_conns,
    std::condition_variable& drain_cv)
    : dispatcher_(std::move(dispatcher))
    , upstream_host_(upstream_host)
    , upstream_port_(upstream_port)
    , sni_hostname_(sni_hostname)
    , config_(config)
    , tls_ctx_(std::move(tls_ctx))
    , outstanding_conns_(outstanding_conns)
    , drain_cv_(drain_cv)
    , partition_max_connections_(static_cast<size_t>(config.max_connections))
{
    logging::Get()->debug("PoolPartition created for {}:{} on dispatcher {}",
                          upstream_host_, upstream_port_,
                          dispatcher_->dispatcher_index());
}

// Null out all callbacks on a connection's transport to prevent
// dangling-this use-after-free if the ConnectionHandler outlives
// the PoolPartition (still in dispatcher's connections_ map).
static void ClearTransportCallbacks(UpstreamConnection* conn) {
    if (conn && conn->GetTransport()) {
        auto t = conn->GetTransport();
        t->SetConnectCompleteCallback(nullptr);
        t->SetCloseCb(nullptr);
        t->SetOnMessageCb(nullptr);
        t->SetErrorCb(nullptr);
    }
}

PoolPartition::~PoolPartition() {
    // Do NOT call ForceClose() here — destructor may run on the main thread
    // and ForceClose() does cross-thread epoll operations (UB).
    // SocketHandler::~SocketHandler() will close the fd naturally.
    for (auto& c : idle_conns_)       ClearTransportCallbacks(c.get());
    for (auto& c : active_conns_)     ClearTransportCallbacks(c.get());
    for (auto& c : connecting_conns_) ClearTransportCallbacks(c.get());
}

void PoolPartition::CheckoutAsync(ReadyCallback ready_cb, ErrorCallback error_cb) {
    // All pool operations must run on the owning dispatcher thread.
    // Off-thread access would data-race on the containers.
    if (dispatcher_ && !dispatcher_->is_dispatcher_thread()) {
        logging::Get()->error("BUG: CheckoutAsync called off dispatcher thread");
        error_cb(CHECKOUT_CONNECT_FAILED);
        return;
    }

    if (shutting_down_) {
        error_cb(CHECKOUT_SHUTTING_DOWN);
        return;
    }

    // 1. Try to find a valid idle connection (MRU = front)
    while (!idle_conns_.empty()) {
        auto conn = std::move(idle_conns_.front());
        idle_conns_.pop_front();

        if (!ValidateConnection(conn.get())) {
            DestroyConnection(std::move(conn));
            continue;
        }

        // Valid idle connection found — activate and deliver synchronously
        conn->MarkInUse();
        conn->GetTransport()->ClearDeadline();
        UpstreamConnection* raw = conn.get();
        active_conns_.push_back(std::move(conn));
        ready_cb(UpstreamLease(raw, this));
        return;
    }

    // 2. No idle — create new if under limit
    if (TotalCount() < partition_max_connections_) {
        CreateNewConnection(std::move(ready_cb), std::move(error_cb));
        return;
    }

    // 3. At capacity — queue if room
    if (wait_queue_.size() < MAX_WAIT_QUEUE_SIZE) {
        wait_queue_.push_back({
            std::move(ready_cb),
            std::move(error_cb),
            std::chrono::steady_clock::now()
        });
        return;
    }

    // 4. Queue full — reject
    error_cb(CHECKOUT_POOL_EXHAUSTED);
}

void PoolPartition::ReturnConnection(UpstreamConnection* conn) {
    if (!conn) return;

    // Find in active_conns_ and extract
    auto owned = ExtractFromActive(conn);
    if (!owned) {
        // Not in active — might be a double-return or already cleaned up
        logging::Get()->warn("ReturnConnection: connection not found in active set "
                             "(already closed or double-return)");
        return;
    }

    // If shutting down, destroy instead of pooling
    if (shutting_down_) {
        DestroyConnection(std::move(owned));
        return;
    }

    owned->IncrementRequestCount();
    owned->MarkIdle();

    // Check if expired
    if (owned->IsExpired(config_.max_lifetime_sec, config_.max_requests_per_conn)) {
        DestroyConnection(std::move(owned));
        // If waiters are queued, create a replacement
        if (!wait_queue_.empty() && TotalCount() < partition_max_connections_) {
            auto entry = std::move(wait_queue_.front());
            wait_queue_.pop_front();
            CreateNewConnection(std::move(entry.ready_callback),
                                std::move(entry.error_callback));
        }
        return;
    }

    // Check if over idle cap. If waiters are queued, hand the connection
    // directly to the next waiter instead of destroying it — otherwise
    // max_idle_connections=0 starves queued checkouts even though capacity
    // just freed.
    if (idle_conns_.size() >= static_cast<size_t>(config_.max_idle_connections)) {
        if (!wait_queue_.empty() && ValidateConnection(owned.get())) {
            // Hand directly to the next waiter (validated — not dead/expired)
            owned->MarkInUse();
            owned->GetTransport()->ClearDeadline();
            UpstreamConnection* raw = owned.get();
            active_conns_.push_back(std::move(owned));
            auto entry = std::move(wait_queue_.front());
            wait_queue_.pop_front();
            entry.ready_callback(UpstreamLease(raw, this));
        } else {
            // No waiters, or connection is dead/expired — destroy it.
            // If waiters exist but connection is invalid, create a replacement.
            bool has_waiters = !wait_queue_.empty();
            DestroyConnection(std::move(owned));
            if (has_waiters && TotalCount() < partition_max_connections_) {
                auto entry = std::move(wait_queue_.front());
                wait_queue_.pop_front();
                CreateNewConnection(std::move(entry.ready_callback),
                                    std::move(entry.error_callback));
            }
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

void PoolPartition::EvictExpired() {
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

    // Evict timed-out wait queue entries
    while (!wait_queue_.empty()) {
        auto& entry = wait_queue_.front();
        auto waited = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - entry.queued_at);
        if (waited.count() >= config_.connect_timeout_ms) {
            auto error_cb = std::move(entry.error_callback);
            wait_queue_.pop_front();
            error_cb(CHECKOUT_QUEUE_TIMEOUT);
        } else {
            break;  // Queue is ordered by time — stop at first non-expired
        }
    }
}

void PoolPartition::InitiateShutdown() {
    shutting_down_ = true;

    // Close all idle connections
    while (!idle_conns_.empty()) {
        auto conn = std::move(idle_conns_.front());
        idle_conns_.pop_front();
        DestroyConnection(std::move(conn));
    }

    // Force-close all connecting — move to local first to avoid O(N²) erase-from-front
    {
        auto conns_to_destroy = std::move(connecting_conns_);
        for (auto& conn : conns_to_destroy) {
            DestroyConnection(std::move(conn));
        }
    }

    // Reject all waiters
    while (!wait_queue_.empty()) {
        auto entry = std::move(wait_queue_.front());
        wait_queue_.pop_front();
        entry.error_callback(CHECKOUT_SHUTTING_DOWN);
    }

    // Active connections will be destroyed when returned via ReturnConnection
    MaybeSignalDrain();
}

void PoolPartition::ForceCloseActive() {
    // Known limitation: outstanding UpstreamLease objects held by request
    // handlers become dangling after this call. The lease destructor's
    // ReturnConnection will find nothing in active_conns_ and log a warning.
    // This is acceptable because ForceCloseActive only runs after the drain
    // timeout expires, meaning the handler is stuck/unresponsive.
    // Move active connections to a local vector to iterate safely while
    // destroying — DestroyConnection modifies active_conns_ indirectly.
    auto active = std::move(active_conns_);
    for (auto& conn : active) {
        DestroyConnection(std::move(conn));
    }
}

void PoolPartition::CreateNewConnection(ReadyCallback ready_cb,
                                         ErrorCallback error_cb) {
    // Create outbound socket
    int fd = SocketHandler::CreateClientSocket();
    if (fd < 0) {
        logging::Get()->error("Failed to create client socket for {}:{}",
                              upstream_host_, upstream_port_);
        error_cb(CHECKOUT_CONNECT_FAILED);
        return;
    }

    // Initiate non-blocking connect on the raw fd BEFORE wrapping in
    // ConnectionHandler. This avoids creating a temporary SocketHandler
    // that would close the fd in its destructor.
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(upstream_port_);
    sa.sin_addr.s_addr = inet_addr(upstream_host_.c_str());
    if (sa.sin_addr.s_addr == INADDR_NONE) {
        logging::Get()->error("Invalid upstream host '{}': must be an IPv4 address",
                              upstream_host_);
        ::close(fd);
        error_cb(CHECKOUT_CONNECT_FAILED);
        return;
    }

    int connect_result = ::connect(fd, reinterpret_cast<struct sockaddr*>(&sa),
                                    sizeof(sa));
    if (connect_result < 0 && errno != EINPROGRESS && errno != EINTR) {
        int saved_errno = errno;
        logging::Get()->warn("connect() failed for {}:{}: {} (errno={})",
                             upstream_host_, upstream_port_,
                             logging::SafeStrerror(saved_errno), saved_errno);
        ::close(fd);
        error_cb(CHECKOUT_CONNECT_FAILED);
        return;
    }

    // Build socket handler and connection handler
    auto sock = std::make_unique<SocketHandler>(fd);
    auto conn_handler = std::make_shared<ConnectionHandler>(
        dispatcher_, std::move(sock));

    // Register in dispatcher's timer map for timeout scanning
    dispatcher_->AddConnection(conn_handler);

    // Set connect timeout deadline
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(config_.connect_timeout_ms);
    conn_handler->SetDeadline(deadline);

    // Create the upstream connection wrapper
    auto upstream_conn = std::make_unique<UpstreamConnection>(
        conn_handler, upstream_host_, upstream_port_);
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
                    std::string sni = sni_hostname_.empty() ? upstream_host_ : sni_hostname_;
                    auto tls = std::make_unique<TlsConnection>(
                        *tls_ctx_, handler->fd(), sni);
                    handler->SetTlsConnection(std::move(tls));
                    // The fall-through in CallWriteCb kicks off DoHandshake
                    // inline on the same EPOLLOUT. OnMessage fires when done.
                } catch (const std::exception& e) {
                    logging::Get()->error("TLS setup failed for {}:{}: {}",
                                          upstream_host_, upstream_port_,
                                          e.what());
                    (*error_cb_copy)(CHECKOUT_CONNECT_FAILED);
                    OnConnectionClosed(raw_conn);  // clean up the leaked pool slot
                    return;
                }
                // Don't deliver ready — TLS handshake still in progress.
                // OnMessage callback fires when handshake completes.
                return;
            }

            // No TLS — connection is ready
            OnConnectComplete(raw_conn, *ready_cb_copy, *error_cb_copy);
        });

    // Wire close callback for connect failure / timeout
    conn_handler->SetCloseCb(
        [this, raw_conn, error_cb_copy]
        (std::shared_ptr<ConnectionHandler>) {
            if (raw_conn->IsConnecting()) {
                (*error_cb_copy)(CHECKOUT_CONNECT_FAILED);
            }
            OnConnectionClosed(raw_conn);
        });

    // Wire error callback for EPOLLERR events (async reset, local error).
    // CallErroCb does NOT invoke the close callback, so without this,
    // EPOLLERR events would silently leak pool slots.
    conn_handler->SetErrorCb(
        [this, raw_conn, error_cb_copy]
        (std::shared_ptr<ConnectionHandler>) {
            if (raw_conn->IsConnecting()) {
                (*error_cb_copy)(CHECKOUT_CONNECT_FAILED);
            }
            OnConnectionClosed(raw_conn);
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

    if (shutting_down_) {
        DestroyConnection(std::move(owned));
        error_cb(CHECKOUT_SHUTTING_DOWN);
        return;
    }

    // Clear connect deadline
    owned->GetTransport()->ClearDeadline();
    owned->MarkInUse();

    UpstreamConnection* raw = owned.get();
    active_conns_.push_back(std::move(owned));

    logging::Get()->debug("Upstream connection ready fd={} {}:{}",
                          raw->fd(), upstream_host_, upstream_port_);

    ready_cb(UpstreamLease(raw, this));
}

void PoolPartition::OnConnectionClosed(UpstreamConnection* conn) {
    // Safe from double-decrement with DestroyConnection because both paths
    // run on the dispatcher thread (single-threaded). OnConnectionClosed
    // extracts from containers; DestroyConnection clears callbacks before
    // ForceClose, so the close callback can't re-fire.
    auto owned = ExtractFromConnecting(conn);
    if (!owned) owned = ExtractFromActive(conn);
    if (!owned) owned = ExtractFromIdle(conn);

    if (owned) {
        // Clear callbacks and deadline BEFORE destruction — the transport
        // (ConnectionHandler) survives in the dispatcher's connections_ map.
        // Without this, a pending deadline or error event would fire callbacks
        // that capture the now-freed raw_conn pointer (use-after-free).
        ClearTransportCallbacks(owned.get());
        auto transport = owned->GetTransport();
        if (transport) {
            transport->ClearDeadline();
            // Remove from dispatcher timer map to prevent memory leak.
            // Without this, the shared_ptr in connections_ keeps the
            // ConnectionHandler alive indefinitely after close.
            int conn_fd = owned->fd();
            if (conn_fd >= 0) {
                dispatcher_->RemoveTimerConnectionIfMatch(conn_fd, transport);
            }
        }
        outstanding_conns_.fetch_sub(1, std::memory_order_release);
        MaybeSignalDrain();
    }
}

bool PoolPartition::ValidateConnection(UpstreamConnection* conn) {
    if (!conn->IsAlive()) return false;
    if (conn->IsExpired(config_.max_lifetime_sec,
                         config_.max_requests_per_conn)) return false;
    return true;
}

void PoolPartition::ServiceWaitQueue() {
    while (!wait_queue_.empty() && !idle_conns_.empty()) {
        // Validate the idle connection
        auto conn = std::move(idle_conns_.front());
        idle_conns_.pop_front();

        if (!ValidateConnection(conn.get())) {
            DestroyConnection(std::move(conn));
            continue;
        }

        conn->MarkInUse();
        conn->GetTransport()->ClearDeadline();

        UpstreamConnection* raw = conn.get();
        active_conns_.push_back(std::move(conn));

        auto entry = std::move(wait_queue_.front());
        wait_queue_.pop_front();
        entry.ready_callback(UpstreamLease(raw, this));
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
    if (shutting_down_ &&
        outstanding_conns_.load(std::memory_order_acquire) <= 0) {
        drain_cv_.notify_all();
    }
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
