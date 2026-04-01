#include "net_server.h"
#include "tls/tls_context.h"
#include "tls/tls_connection.h"
#include "log/logger.h"

#include <csignal>
#include <future>

// Process-global SIGPIPE suppression. Checked on every NetServer construction
// (not call_once) so it works correctly after Cleanup(RESTORE) restores the
// original disposition.
static void SigpipeGuardAcquire() {
    struct sigaction sa_cur{};
    sigaction(SIGPIPE, nullptr, &sa_cur);
    if (sa_cur.sa_handler == SIG_DFL) {
        struct sigaction sa_ign{};
        sa_ign.sa_handler = SIG_IGN;
        sigemptyset(&sa_ign.sa_mask);
        sigaction(SIGPIPE, &sa_ign, nullptr);
    }
}

NetServer::NetServer(const std::string& _ip, const size_t _port,
                     int timer_interval,
                     std::chrono::seconds connection_timeout,
                     int worker_threads)
    : conn_dispatcher_(std::make_shared<Dispatcher>()),
      acceptor_(nullptr),
      timer_interval_(timer_interval),
      connection_timeout_sec_(static_cast<int>(connection_timeout.count()))
{
    // Suppress SIGPIPE if the current handler is the default (which kills
    // the process). OpenSSL's SSL_write/SSL_shutdown use the underlying
    // socket's write() which bypasses MSG_NOSIGNAL. Without suppression,
    // a single peer reset on a TLS connection kills the entire process.
    // Only override SIG_DFL — if the embedder has installed their own
    // handler, leave it alone to avoid breaking their signal handling.
    SigpipeGuardAcquire();
    conn_dispatcher_->Init();
    conn_dispatcher_->SetTimeOutTriggerCB(std::bind(&NetServer::Timeout, this, std::placeholders::_1));
    acceptor_ = std::unique_ptr<Acceptor>(new Acceptor(conn_dispatcher_, _ip, _port));
    acceptor_->SetNewConnCb(std::bind(&NetServer::HandleNewConnection, this, std::placeholders::_1));
    // Route thread pool errors through spdlog so they reach the log file
    // in daemon mode (where stderr is /dev/null).
    sock_workers_.SetErrorLogger([](const std::string& msg) {
        logging::Get()->error("{}", msg);
    });
    if (worker_threads > 0) {
        sock_workers_.Init(worker_threads);
    } else {
        sock_workers_.Init();
    }
    sock_workers_.Start();
}

NetServer::~NetServer(){
    Stop();
    socket_dispatchers_.clear();
    connections_.clear();
}

// start event loop
void NetServer::Start(){
    socket_dispatchers_.reserve(sock_workers_.GetThreadWorkerNum());
    for(int idx = 0; idx < sock_workers_.GetThreadWorkerNum(); idx ++){
        // Use configurable timer parameters
        std::shared_ptr<Dispatcher> task = std::make_shared<Dispatcher>(
            true, timer_interval_,
            std::chrono::seconds(connection_timeout_sec_.load(std::memory_order_relaxed)));
        // Initialize each socket dispatcher (required for eventfd setup)
        task->Init();
        socket_dispatchers_.emplace_back(task);
        task->SetTimeOutTriggerCB(std::bind(&NetServer::Timeout, this, std::placeholders::_1)); 
        task->SetTimerCB(std::bind(&NetServer::RemoveConnection, this, std::placeholders::_1));

        // Use lambda with COPY-BY-VALUE capture for thread safety
        // Why copy? The lambda will execute in a different thread later.
        // Capturing 'task' by value ensures the Dispatcher shared_ptr is safely
        // shared across threads without dangling references.
        std::shared_ptr<SocketWorker> work_task = std::shared_ptr<SocketWorker>(
            new SocketWorker([task]() {
                task->RunEventLoop();
            }));
        sock_workers_.AddTask(work_task);
    }
    // Init complete — fire ready callback before entering the blocking loop.
    // Daemon mode uses this to signal the parent process that startup succeeded.
    if (ready_callback_) {
        ready_callback_();
        ready_callback_ = nullptr;  // one-shot
    }

    conn_dispatcher_->RunEventLoop();
}

// stop event loop
void NetServer::StopAccepting() {
    if (conn_dispatcher_->was_stopped()) return;  // already stopped

    if (conn_dispatcher_->is_running()) {
        // Event loop is active: enqueue close + barrier to ensure any
        // in-flight accept callback has finished before we return.
        conn_dispatcher_->EnQueue([this]() {
            if (acceptor_) acceptor_->CloseListenSocket();
        });
        if (!conn_dispatcher_->is_on_loop_thread()) {
            auto barrier = std::make_shared<std::promise<void>>();
            auto future = barrier->get_future();
            conn_dispatcher_->EnQueue([barrier]() { barrier->set_value(); });
            future.wait();
        }
    } else {
        // Event loop not started (Stop before Start, ready_callback shutdown):
        // close synchronously — no concurrent accept callbacks possible.
        if (acceptor_) acceptor_->CloseListenSocket();
    }
    conn_dispatcher_->StopEventLoop();
}

void NetServer::Stop(){
    // First: stop accepting (may already be done by HttpServer::Stop())
    StopAccepting();

    // Second (deferred): ClearConnections is done AFTER the drain wait so that
    // dispatcher TimerHandler continues enforcing per-connection deadlines during
    // HTTP/2 graceful drain. The clear is enqueued later, before StopEventLoop.

    // Third: Gracefully close all active connections — CloseAfterWrite lets pending
    // output (including WS close frames) drain via the still-running event loops.
    // Connections with empty output buffers close immediately (ForceClose path).
    std::vector<std::shared_ptr<ConnectionHandler>> conns_to_close;
    {
        std::lock_guard<std::mutex> lck(conn_mtx_);
        for (auto& pair : connections_) {
            if (pair.second) {
                conns_to_close.push_back(pair.second);
            }
        }
        connections_.clear();
    }
    for (auto& conn : conns_to_close) {
        // Skip connections already marked by a higher layer (e.g., HttpServer
        // sent a WS close frame and called CloseAfterWrite on them).
        if (conn->IsCloseDeferred()) continue;
        // Skip connections in the H2 graceful drain set — they close
        // themselves after all active streams complete.
        if (draining_conns_.count(conn.get())) continue;
        conn->CloseAfterWrite();
    }
    // Do NOT clear conns_to_close here. The shared_ptrs must keep
    // ConnectionHandlers alive until the deferred CloseAfterWrite lambdas
    // (which capture weak_ptr) have executed. Without this, ClearConnections
    // + clear() can drop the last strong ref before the drain/close lambda
    // runs, causing weak_ptr::lock() to fail and skipping graceful close.

    // Fourth: Wait for each dispatcher to process enqueued CloseAfterWrite tasks.
    // Without this barrier, StopEventLoop would exit the event loop before
    // EnableWriteMode (from CloseAfterWrite) triggers a write event, truncating
    // buffered output (WS close frames, in-flight HTTP responses) under backpressure.
    // The barrier ensures write mode is registered; StopEventLoop's WakeUp then
    // triggers one final WaitForEvent that includes the write-ready channels.
    // Wait for each socket dispatcher to process enqueued work.
    // Skips self-dispatcher to avoid deadlock when Stop() is called from a handler.
    auto wait_for_dispatcher_barrier = [this]() {
        for (auto& disp : socket_dispatchers_) {
            if (disp->was_stopped()) continue;
            if (disp->is_on_loop_thread()) {
                // Self-dispatcher: process pending tasks inline instead of
                // skipping. Without this, CloseAfterWrite tasks queued onto
                // this dispatcher never run (the thread is blocked in Stop()),
                // and buffered output gets truncated.
                disp->HandleEventId();
                continue;
            }
            auto barrier = std::make_shared<std::promise<void>>();
            auto future = barrier->get_future();
            disp->EnQueue([barrier]() { barrier->set_value(); });
            future.wait();
        }
    };

    wait_for_dispatcher_barrier();

    // Fourth-B: If H2 connections are draining, wait for them while event loops
    // are still running. The pre_stop_drain_cb blocks until drain completes or timeout.
    if (pre_stop_drain_cb_) {
        pre_stop_drain_cb_();
        pre_stop_drain_cb_ = nullptr;  // one-shot

        // Second barrier: covers CloseAfterWrite tasks enqueued by H2 handlers
        // during the drain wait above.
        wait_for_dispatcher_barrier();
    }
    draining_conns_.clear();  // one-shot cleanup

    // Fourth-C: Now safe to release dispatcher-held connection references.
    // Deferred from earlier so TimerHandler continues enforcing deadlines during drain.
    for (auto& disp : socket_dispatchers_) {
        disp->EnQueue([d = disp]() {
            d->ClearConnections();
        });
    }
    wait_for_dispatcher_barrier();

    // Fifth: Stop socket dispatcher event loops (conn_dispatcher already stopped above).
    // StopEventLoop's WakeUp triggers one final loop iteration that processes any
    // write-ready channels (from EnableWriteMode set above), draining buffered output.
    for(auto task : socket_dispatchers_)
        task -> StopEventLoop();

    // Sixth: Now safe to join worker threads
    sock_workers_.Stop();

    // Seventh: Release shutdown connection references. All deferred work has
    // completed — the event loops are stopped and workers are joined.
    conns_to_close.clear();
}

void NetServer::HandleNewConnection(std::unique_ptr<SocketHandler> cilent_sock){
    // Enforce max_connections limit
    int max_conns = max_connections_.load(std::memory_order_relaxed);
    if (max_conns > 0) {
        std::lock_guard<std::mutex> lck(conn_mtx_);
        if (static_cast<int>(connections_.size()) >= max_conns) {
            logging::Get()->warn("Max connections ({}) reached, rejecting fd {}",
                                max_conns, cilent_sock->fd());
            return;  // SocketHandler destructor closes the fd
        }
    }

    int idx = cilent_sock -> fd() % sock_workers_.GetThreadWorkerNum();
    std::shared_ptr<ConnectionHandler> conn = std::shared_ptr<ConnectionHandler>(new ConnectionHandler(socket_dispatchers_[idx], std::move(cilent_sock)));

    // Inject TLS BEFORE RegisterCallbacks to avoid race:
    // RegisterCallbacks() enables epoll read, so data could arrive immediately.
    // OnMessage() must know about TLS before the first read event.
    if (tls_ctx_) {
        try {
            auto tls = std::make_unique<TlsConnection>(*tls_ctx_, conn->fd());
            conn->SetTlsConnection(std::move(tls));
        } catch (const std::exception& e) {
            logging::Get()->error("TLS setup failed for fd {}: {}", conn->fd(), e.what());
            // Close properly to avoid double-close: both Channel and SocketHandler
            // hold the same fd. CallCloseCb closes the channel fd and releases from SocketHandler.
            conn->CallCloseCb();
            return;
        }
    }

    // Set application callbacks and per-connection limits BEFORE RegisterCallbacks().
    // RegisterCallbacks() enables epoll (EPOLL_CTL_ADD), after which data can arrive
    // on the socket dispatcher thread. All connection state must be configured before
    // this point — the epoll_ctl syscall provides the memory barrier ensuring writes
    // here are visible to reads on the socket dispatcher thread.
    conn -> SetCloseCb(std::bind(&NetServer::HandleCloseConnection, this, std::placeholders::_1));
    conn -> SetErrorCb(std::bind(&NetServer::HandleErrorConnection, this, std::placeholders::_1));
    conn -> SetOnMessageCb(std::bind(&NetServer::OnMessage, this, std::placeholders::_1, std::placeholders::_2));
    conn -> SetCompletionCb(std::bind(&NetServer::HandleSendComplete, this, std::placeholders::_1));
    conn -> SetWriteProgressCb(std::bind(&NetServer::HandleWriteProgress, this, std::placeholders::_1, std::placeholders::_2));

    // Set input buffer cap BEFORE epoll registration to eliminate the race where
    // the first read arrives uncapped before HttpServer::HandleNewConnection runs.
    size_t max_input = max_input_size_.load(std::memory_order_relaxed);
    if (max_input > 0) {
        conn->SetMaxInputSize(max_input);
    }

    AddConnection(conn);

    // Two-phase initialization: register channel callbacks and enable epoll.
    // Uses weak_ptr captures so callbacks are safe if ConnectionHandler is destroyed.
    // If epoll_ctl fails (ENOMEM/ENOSPC), clean up the half-initialized connection
    // to prevent leaking a connection slot and fd.
    try {
        conn -> RegisterCallbacks();
    } catch (const std::exception& e) {
        logging::Get()->error("epoll registration failed for fd {}: {}", conn->fd(), e.what());
        // CallCloseCb handles: close channel, fire close callback (removes from
        // connections_ map), release fd from SocketHandler (prevents double-close).
        conn->CallCloseCb();
        return;
    }

    // Register with socket dispatcher's timer for idle timeout scanning.
    // Must go through EnQueue so AddConnection runs on the dispatcher thread,
    // avoiding lock inversion between timer_mtx_ and conn_mtx_.
    {
        std::weak_ptr<ConnectionHandler> weak_conn = conn;
        auto dispatcher = socket_dispatchers_[idx];
        dispatcher->EnQueue([weak_conn, dispatcher]() {
            if (auto c = weak_conn.lock()) {
                dispatcher->AddConnection(c);
            }
        });
    }

    logging::Get()->debug("New connection fd={} from {}:{}", conn->fd(), conn->ip_addr(), conn->port());

    if(callbacks_.new_conn_callback)
        callbacks_.new_conn_callback(conn);
}

void NetServer::HandleCloseConnection(std::shared_ptr<ConnectionHandler> conn){
    // Capture fd BEFORE any cleanup that might invalidate it (CallCloseCb → ReleaseFd)
    // Note: HandleCloseConnection is called FROM CallCloseCb, so fd() should still be
    // valid at this point (ReleaseFd runs after the callback). But under fd-reuse the
    // number could belong to a new connection, so we verify identity.
    int close_fd = conn->fd();

    if(callbacks_.close_conn_callback)
        callbacks_.close_conn_callback(conn);

    logging::Get()->debug("Client fd={} disconnected", close_fd);

    // Remove from dispatcher's timer map with identity check to avoid fd-reuse race
    int idx = close_fd % sock_workers_.GetThreadWorkerNum();
    auto dispatcher = socket_dispatchers_[idx];
    std::weak_ptr<ConnectionHandler> weak_conn = conn;
    dispatcher->EnQueue([close_fd, weak_conn, dispatcher]() {
        dispatcher->RemoveTimerConnectionIfMatch(close_fd, weak_conn.lock());
    });

    // Remove from connections_ map with identity check to avoid removing a reused fd
    {
        std::lock_guard<std::mutex> lck(conn_mtx_);
        auto it = connections_.find(close_fd);
        if (it != connections_.end() && it->second == conn) {
            connections_.erase(it);
        }
    }
    conn.reset();
}

void NetServer::HandleErrorConnection(std::shared_ptr<ConnectionHandler> conn){
    int close_fd = conn->fd();

    if(callbacks_.error_callback)
        callbacks_.error_callback(conn);

    logging::Get()->debug("Client fd={} error occurred, disconnect", close_fd);

    // Remove from dispatcher's timer map with identity check to avoid fd-reuse race
    int idx = close_fd % sock_workers_.GetThreadWorkerNum();
    auto dispatcher = socket_dispatchers_[idx];
    std::weak_ptr<ConnectionHandler> weak_conn = conn;
    dispatcher->EnQueue([close_fd, weak_conn, dispatcher]() {
        dispatcher->RemoveTimerConnectionIfMatch(close_fd, weak_conn.lock());
    });

    // Remove from connections_ map with identity check
    {
        std::lock_guard<std::mutex> lck(conn_mtx_);
        auto it = connections_.find(close_fd);
        if (it != connections_.end() && it->second == conn) {
            connections_.erase(it);
        }
    }
    conn.reset();
}

void NetServer::OnMessage(std::shared_ptr<ConnectionHandler> conn, std::string& message){
    if(callbacks_.on_message_callback)
        callbacks_.on_message_callback(conn, message);
}

void NetServer::AddConnection(std::shared_ptr<ConnectionHandler> conn){
    std::lock_guard<std::mutex> lck(conn_mtx_);
    connections_[conn -> fd()] = conn;
}

void NetServer::RemoveConnection(int fd){
    std::lock_guard<std::mutex> lck(conn_mtx_);
    connections_.erase(fd);
}

void NetServer::HandleSendComplete(std::shared_ptr<ConnectionHandler> conn){
    if(callbacks_.send_complete_callback)
        callbacks_.send_complete_callback(conn);
}

void NetServer::HandleWriteProgress(std::shared_ptr<ConnectionHandler> conn, size_t remaining){
    if(callbacks_.write_progress_callback)
        callbacks_.write_progress_callback(conn, remaining);
}

void NetServer::Timeout(std::shared_ptr<Dispatcher> sock_dispatcher){
    if(callbacks_.timer_callback)
        callbacks_.timer_callback(sock_dispatcher);
}

void NetServer::SetNewConnectionCb(CALLBACKS_NAMESPACE::NetSrvConnCallback fn){
    if(fn)
        callbacks_.new_conn_callback = std::move(fn);
}

void NetServer::SetCloseConnectionCb(CALLBACKS_NAMESPACE::NetSrvCloseConnCallback fn){
    if(fn)
        callbacks_.close_conn_callback = std::move(fn);
}

void NetServer::SetErrorCb(CALLBACKS_NAMESPACE::NetSrvErrorCallback fn){
    if(fn)
        callbacks_.error_callback = std::move(fn);
}

void NetServer::SetOnMessageCb(CALLBACKS_NAMESPACE::NetSrvOnMsgCallback fn){
    if(fn)
        callbacks_.on_message_callback = std::move(fn);
}

void NetServer::SetSendCompletionCb(CALLBACKS_NAMESPACE::NetSrvSendCompleteCallback fn){
    if(fn)
        callbacks_.send_complete_callback = std::move(fn);
}

void NetServer::SetWriteProgressCb(CALLBACKS_NAMESPACE::NetSrvWriteProgressCallback fn){
    if(fn)
        callbacks_.write_progress_callback = std::move(fn);
}

void NetServer::SetTimerCb(CALLBACKS_NAMESPACE::NetSrvTimerCallback fn){
    if(fn)
        callbacks_.timer_callback = std::move(fn);
}

bool NetServer::IsOnDispatcherThread() const {
    for (const auto& disp : socket_dispatchers_) {
        if (disp->is_on_loop_thread()) return true;
    }
    return false;
}

void NetServer::SetConnectionTimeout(std::chrono::seconds timeout) {
    connection_timeout_sec_.store(static_cast<int>(timeout.count()),
                                 std::memory_order_relaxed);
    for (auto& disp : socket_dispatchers_) {
        disp->EnQueue([d = disp, timeout]() {
            d->SetTimeout(timeout);
        });
    }
}

void NetServer::SetTimerInterval(int seconds) {
    timer_interval_ = seconds;
    for (auto& disp : socket_dispatchers_) {
        disp->EnQueue([d = disp, seconds]() {
            d->SetTimerInterval(seconds);
        });
    }
}
