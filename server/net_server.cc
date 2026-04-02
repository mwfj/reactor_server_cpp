#include "net_server.h"
#include "tls/tls_context.h"
#include "tls/tls_connection.h"
#include "log/logger.h"

#include <csignal>
#include <future>

static constexpr int STOP_BARRIER_TIMEOUT_SEC = 5;

NetServer::NetServer(const std::string& _ip, const size_t _port,
                     int timer_interval,
                     std::chrono::seconds connection_timeout,
                     int worker_threads)
    : conn_dispatcher_(std::make_shared<Dispatcher>()),
      acceptor_(nullptr),
      timer_interval_(timer_interval),
      connection_timeout_(connection_timeout)
{
    // Suppress SIGPIPE if the current handler is the default (which kills
    // the process). OpenSSL's SSL_write/SSL_shutdown use the underlying
    // socket's write() which bypasses MSG_NOSIGNAL. Without suppression,
    // a single peer reset on a TLS connection kills the entire process.
    // Only override SIG_DFL — if the embedder has installed their own
    // handler, leave it alone to avoid breaking their signal handling.
    {
        struct sigaction sa_cur;
        sigaction(SIGPIPE, nullptr, &sa_cur);
        if (sa_cur.sa_handler == SIG_DFL) {
            signal(SIGPIPE, SIG_IGN);
        }
    }
    // Initialize conn_dispatcher_ after shared_ptr is constructed (required for eventfd setup)
    conn_dispatcher_->Init();
    conn_dispatcher_->SetTimeOutTriggerCB(std::bind(&NetServer::Timeout, this, std::placeholders::_1));

    // Now create acceptor with initialized dispatcher
    acceptor_ = std::unique_ptr<Acceptor>(new Acceptor(conn_dispatcher_, _ip, _port));
    acceptor_->SetNewConnCb(std::bind(&NetServer::HandleNewConnection, this, std::placeholders::_1));
    if (worker_threads > 0) {
        sock_workers_.Init(worker_threads);
    } else {
        sock_workers_.Init();
    }
    sock_workers_.Start();
}

NetServer::~NetServer(){
    Stop();
    // Ensure worker threads are stopped even if Stop() took the early-return
    // path (dispatchers_ready_ == false). Covers the case where Start() was
    // never called but the constructor already started sock_workers_.
    // ThreadPool::Stop() is idempotent.
    sock_workers_.Stop();
    socket_dispatchers_.clear();
    connections_.clear();
}

// start event loop
void NetServer::Start(){
    start_called_.store(true, std::memory_order_release);

    // Helper: clean up any partially-built dispatchers and stop workers.
    // Used on concurrent shutdown detection and on exceptions. Sets
    // dispatchers_ready_ so Stop() won't skip worker cleanup.
    auto cleanup_partial_startup = [this]() {
        for (auto& d : socket_dispatchers_)
            d->StopEventLoop();
        sock_workers_.Stop();
        dispatchers_ready_.store(true, std::memory_order_release);
    };

    try {
        socket_dispatchers_.reserve(sock_workers_.GetThreadWorkerNum());
        for(int idx = 0; idx < sock_workers_.GetThreadWorkerNum(); idx ++){
            // Check for concurrent shutdown before each iteration.
            if (conn_dispatcher_->was_stopped()) break;

            // Use configurable timer parameters
            std::shared_ptr<Dispatcher> task = std::make_shared<Dispatcher>(true, timer_interval_, connection_timeout_);
            task->Init();
            socket_dispatchers_.emplace_back(task);
            task->SetTimeOutTriggerCB(std::bind(&NetServer::Timeout, this, std::placeholders::_1));
            task->SetTimerCB(std::bind(&NetServer::RemoveConnection, this, std::placeholders::_1));

            std::shared_ptr<SocketWorker> work_task = std::shared_ptr<SocketWorker>(
                new SocketWorker([task]() {
                    task->RunEventLoop();
                }));
            sock_workers_.AddTask(work_task);
        }

        // If Stop() was called while we were building dispatchers, clean up.
        if (conn_dispatcher_->was_stopped()) {
            cleanup_partial_startup();
            return;
        }

        // Barrier: wait for all socket dispatchers to enter their event loops.
        {
            static constexpr int DISPATCHER_START_TIMEOUT_SEC = 5;
            for (auto& disp : socket_dispatchers_) {
                auto deadline = std::chrono::steady_clock::now()
                              + std::chrono::seconds(DISPATCHER_START_TIMEOUT_SEC);
                while (!disp->is_running() && !disp->was_stopped()) {
                    if (std::chrono::steady_clock::now() > deadline) {
                        logging::Get()->error(
                            "Socket dispatcher failed to start within {} seconds",
                            DISPATCHER_START_TIMEOUT_SEC);
                        cleanup_partial_startup();
                        throw std::runtime_error(
                            "Socket dispatcher failed to start within timeout");
                    }
                    std::this_thread::yield();
                }
            }
        }

        // Re-check: Stop() may have arrived while we were in the barrier.
        if (conn_dispatcher_->was_stopped()) {
            cleanup_partial_startup();
            return;
        }

    } catch (...) {
        // Dispatcher construction, Init(), or AddTask() failed under
        // resource pressure. Clean up whatever was built so Stop() doesn't
        // have to guess whether Start() finished. Without this,
        // start_called_==true + dispatchers_ready_==false leaves Stop()
        // unable to stop workers or dispatchers.
        cleanup_partial_startup();
        throw;
    }

    // All socket dispatchers are running. Mark ready so Stop() knows
    // it's safe to iterate socket_dispatchers_. Placed AFTER the barrier
    // (not before) so that a racing Stop() takes the early-return path
    // instead of enqueueing barrier tasks to dispatchers that haven't
    // entered their event loops yet (which would stall 5s × N workers).
    dispatchers_ready_.store(true, std::memory_order_release);

    // Enqueue the ready callback into the conn_dispatcher's task queue so it
    // fires from within the first event loop iteration — after the accept loop
    // is running and processing events. This eliminates the startup race where
    // the old inline callback fired before RunEventLoop(), leaving a window
    // where the listen socket was live but the accept loop wasn't draining it.
    //
    // EnQueue works here because conn_dispatcher_->Init() (called in constructor)
    // registered the wake channel. The enqueued task + WakeUp() causes the first
    // WaitForEvent() to return immediately, executing the callback.
    if (ready_callback_) {
        // Capture by value and guard with was_stopped() so the callback
        // is a no-op if Stop() races in before the first event loop drain.
        // Without this, daemon mode could send NotifyReady() after shutdown
        // started, and TestServerRunner could observe a false-ready server.
        auto cb = std::move(ready_callback_);
        ready_callback_ = nullptr;
        conn_dispatcher_->EnQueue([cb = std::move(cb), this]() {
            if (!conn_dispatcher_->was_stopped()) {
                cb();
            }
        });
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
            if (future.wait_for(std::chrono::seconds(STOP_BARRIER_TIMEOUT_SEC))
                    == std::future_status::timeout) {
                logging::Get()->error(
                    "conn_dispatcher barrier timed out during StopAccepting");
            }
        }
    } else {
        // Event loop not started (Stop before Start, ready_callback shutdown).
        // Set was_stopped BEFORE closing so that CloseChannel's off-loop
        // check sees was_stopped_ == true and takes the inline path.
        // Without this, CloseChannel enqueues the fd close to a dispatcher
        // that will never run, leaving the listen socket bound.
        conn_dispatcher_->StopEventLoop();
        if (acceptor_) acceptor_->CloseListenSocket();
        return;  // StopEventLoop already called
    }
    conn_dispatcher_->StopEventLoop();
}

void NetServer::Stop(){
    // First: stop accepting (may already be done by HttpServer::Stop())
    StopAccepting();

    // If Start() hasn't finished building socket_dispatchers_, skip
    // dispatcher iteration to avoid racing with the vector build.
    if (!dispatchers_ready_.load(std::memory_order_acquire)) {
        if (!start_called_.load(std::memory_order_acquire)) {
            // Start() was never called — workers are idle in GetTask(),
            // not in RunEventLoop(), so stopping the pool won't hang.
            sock_workers_.Stop();
        }
        // If Start() IS running, it checks was_stopped() in its build
        // loop and after the barrier, and handles dispatcher + worker
        // cleanup itself.
        return;
    }

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
            if (future.wait_for(std::chrono::seconds(STOP_BARRIER_TIMEOUT_SEC))
                    == std::future_status::timeout) {
                logging::Get()->error(
                    "Socket dispatcher barrier timed out during Stop(), "
                    "forcing StopEventLoop");
                disp->StopEventLoop();
            }
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
    for(auto& task : socket_dispatchers_) {
        if (task->is_on_loop_thread()) {
            // Self-dispatcher (Stop called from a handler on this thread):
            // enqueue StopEventLoop so the loop does one more WaitForEvent
            // iteration before exiting. This lets write-ready channels
            // (armed by CloseAfterWrite/EnableWriteMode in the barrier)
            // fire and flush buffered output. A direct StopEventLoop would
            // set is_running_=false immediately, and the loop would exit
            // as soon as the current handler returns — truncating output.
            task->EnQueue([t = task]() { t->StopEventLoop(); });
        } else {
            task->StopEventLoop();
        }
    }

    // Sixth: Now safe to join worker threads
    sock_workers_.Stop();

    // Seventh: Release shutdown connection references. All deferred work has
    // completed — the event loops are stopped and workers are joined.
    conns_to_close.clear();
}

void NetServer::HandleNewConnection(std::unique_ptr<SocketHandler> cilent_sock){
    // Enforce max_connections limit
    if (max_connections_ > 0) {
        std::lock_guard<std::mutex> lck(conn_mtx_);
        if (static_cast<int>(connections_.size()) >= max_connections_) {
            logging::Get()->warn("Max connections ({}) reached, rejecting fd {}",
                                max_connections_, cilent_sock->fd());
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
    if (max_input_size_ > 0) {
        conn->SetMaxInputSize(max_input_size_);
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
