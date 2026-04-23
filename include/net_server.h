#pragma once
#include "common.h"
#include "socket_handler.h"
#include "inet_addr.h"
#include "epoll_handler.h"
#include "channel.h"
#include "dispatcher.h"
#include "connection_handler.h"
#include "acceptor.h"
#include "callbacks.h"
#include "log/logger.h"

#include "threadtask.h"
#include "threadpool.h"
#include <mutex>
#include <set>

class TlsContext;

// For socket connection related task, use this type of worker
// SocketWorker: Handles I/O event loops for client connections in thread pool
class SocketWorker : public ThreadTaskInterface{
public:
    explicit SocketWorker(std::function<void()> _func) : func_(std::move(_func)){}
protected:
    int RunTask() override {
        try{
            func_();
            return 0;  // Success
        }catch (const std::exception& e){
            logging::Get()->error("SocketWorker error: {}", e.what());
            return -1;
        }
    }
private:
    std::function<void()> func_;
};

class NetServer {
private:
    // Owner (shared with components for coordination)
    // The main event loop for build socket and connection
    std::shared_ptr<Dispatcher> conn_dispatcher_;
    // Sub-events looks for
    std::vector<std::shared_ptr<Dispatcher>> socket_dispatchers_;
    std::map<int, std::shared_ptr<ConnectionHandler>> connections_;
    std::mutex conn_mtx_;  // Protects connections_ map from concurrent access
    std::unique_ptr<Acceptor> acceptor_;  // Sole owner of Acceptor

    CALLBACKS_NAMESPACE::NetSrvCallbacks callbacks_;

    ThreadPool sock_workers_;

    // Timer configuration
    int timer_interval_;  // How often to check for timeouts (seconds)
    // Atomic: written by SetConnectionTimeout (main thread via Reload),
    // read by GetConnectionTimeout (dispatcher threads via /stats).
    std::atomic<int> connection_timeout_sec_;  // Connection idle timeout (seconds)

    std::shared_ptr<TlsContext> tls_ctx_;  // Shared with HttpServer for safe lifetime
    std::atomic<int> max_connections_{0};       // 0 = unlimited
    std::atomic<size_t> max_input_size_{0};    // 0 = unlimited, set before RegisterCallbacks
    std::function<void()> ready_callback_ = nullptr;  // Fires after init, before event loop
    std::set<ConnectionHandler*> draining_conns_;       // H2 connections exempt from force-close
    std::mutex draining_conns_mtx_;                     // Protects draining_conns_ for late additions
    std::function<void()> pre_stop_drain_cb_;           // H2 drain wait callback
    std::atomic<bool> dispatchers_ready_{false};        // True after socket_dispatchers_ is fully built
    std::atomic<bool> start_called_{false};             // True once Start() begins executing
    std::atomic<bool> stop_requested_{false};           // True once Stop() begins — suppresses ready callback

public:
    NetServer() = delete;

    // PHASE 1 — construct + Init the conn_dispatcher_ member + install
    // the timeout-trigger callback. Does NOT construct Acceptor, does
    // NOT build or start socket dispatchers, does NOT start the worker
    // pool. `conn_dispatcher_` MUST be Init()-complete here because
    // `Acceptor::Acceptor()` (called in Phase 2) synchronously invokes
    // `event_dispatcher_->UpdateChannelInLoop()` to register the listen
    // channel; without an initialised dispatcher that call would fail.
    //
    // Callers then:
    //   1. Configure TLS / max-connections / callbacks as needed.
    //   2. Call `StartListening(InetAddr)` to open the listen socket.
    //   3. Call `Start()` to spin up dispatchers + workers + run the
    //      event loop.
    //
    // `Stop()` / `~NetServer` tolerate three partial-construction
    // states — ctor-only (no Acceptor, no dispatchers), StartListening-
    // but-not-Start (Acceptor bound, dispatchers not yet built), and
    // full startup. §5.4a of HOSTNAME_RESOLUTION_AND_IPV6_DESIGN.md.
    NetServer(int timer_interval,
              std::chrono::seconds connection_timeout,
              int worker_threads = 0);   // 0 = hardware_concurrency
    ~NetServer();

    // PHASE 2 — open the listen socket on a resolved address. Uses the
    // Phase-1 conn_dispatcher_ to construct `Acceptor` (which binds +
    // listens + registers its read channel via `UpdateChannelInLoop`).
    // Throws `std::runtime_error` on bind / listen / IPV6_V6ONLY
    // setsockopt failure (fail-closed per §5.4). Must be called exactly
    // once, before `Start()`. After `StartListening` returns the listen
    // fd is open but no dispatchers or workers are running yet.
    void StartListening(const InetAddr& resolved);

    // PHASE 3 — unchanged behaviour: build + start socket dispatchers,
    // start the worker pool, wait for dispatchers to become running,
    // fire the ready_callback, then `RunEventLoop()` on conn_dispatcher_.
    void Start();

    // Tolerant stop. Safe in all three partial-construction states:
    //   (1) ctor-only — no listener, no dispatchers. Effectively a
    //       no-op except for setting stop_requested_.
    //   (2) StartListening-but-not-Start — closes the listen socket,
    //       skips dispatcher iteration.
    //   (3) Full startup — normal drain path.
    void Stop();

    // Close the listening socket and stop accepting new connections.
    // Called by HttpServer before building the H2 drain snapshot to prevent
    // new connections from bypassing the graceful shutdown path.
    void StopAccepting();

    void HandleNewConnection(std::unique_ptr<SocketHandler>);
    void HandleCloseConnection(std::shared_ptr<ConnectionHandler>);
    void HandleErrorConnection(std::shared_ptr<ConnectionHandler>);
    void HandleSendComplete(std::shared_ptr<ConnectionHandler>);
    void HandleWriteProgress(std::shared_ptr<ConnectionHandler>, size_t);

    void OnMessage(std::shared_ptr<ConnectionHandler>, std::string&);
    void AddConnection(std::shared_ptr<ConnectionHandler>);
    void RemoveConnection(int);
    void Timeout(std::shared_ptr<Dispatcher>);
    
    void SetNewConnectionCb(CALLBACKS_NAMESPACE::NetSrvConnCallback);
    void SetCloseConnectionCb(CALLBACKS_NAMESPACE::NetSrvCloseConnCallback);
    void SetErrorCb(CALLBACKS_NAMESPACE::NetSrvErrorCallback);
    void SetOnMessageCb(CALLBACKS_NAMESPACE::NetSrvOnMsgCallback);
    void SetSendCompletionCb(CALLBACKS_NAMESPACE::NetSrvSendCompleteCallback);
    void SetWriteProgressCb(CALLBACKS_NAMESPACE::NetSrvWriteProgressCallback);
    void SetTimerCb(CALLBACKS_NAMESPACE::NetSrvTimerCallback);

    void SetTlsContext(std::shared_ptr<TlsContext> ctx) { tls_ctx_ = std::move(ctx); }
    void SetMaxConnections(int max) { max_connections_.store(max, std::memory_order_relaxed); }
    int GetMaxConnections() const { return max_connections_.load(std::memory_order_relaxed); }
    void SetMaxInputSize(size_t max) { max_input_size_.store(max, std::memory_order_relaxed); }
    std::chrono::seconds GetConnectionTimeout() const {
        return std::chrono::seconds(connection_timeout_sec_.load(std::memory_order_relaxed));
    }

    // Update idle timeout on all socket dispatchers at runtime.
    // EnQueues the update to each dispatcher thread to avoid racing with TimerHandler.
    void SetConnectionTimeout(std::chrono::seconds timeout);

    // Update timer scan interval on all socket dispatchers at runtime.
    // EnQueues the update to each dispatcher thread.
    void SetTimerInterval(int seconds);

    // Get the current timer scan interval (seconds).
    int GetTimerInterval() const { return timer_interval_; }

    // Get the actual worker thread count (resolved from auto mode).
    int GetWorkerCount() { return sock_workers_.GetThreadWorkerNum(); }

    // Access the socket dispatchers (one per worker thread).
    // Used by upstream connection pooling to pin outbound connections
    // to the same dispatcher as the inbound request.
    const std::vector<std::shared_ptr<Dispatcher>>& GetSocketDispatchers() const {
        return socket_dispatchers_;
    }

    // Connections exempt from CloseAfterWrite during Stop().
    // Set by HttpServer before Stop() for HTTP/2 graceful drain.
    void SetDrainingConns(std::set<ConnectionHandler*> conns) {
        std::lock_guard<std::mutex> lck(draining_conns_mtx_);
        draining_conns_ = std::move(conns);
    }
    // Add a single connection to the drain-exempt set. Thread-safe for
    // late additions during shutdown (e.g., H2 detected after snapshot).
    void AddDrainingConn(ConnectionHandler* conn) {
        std::lock_guard<std::mutex> lck(draining_conns_mtx_);
        draining_conns_.insert(conn);
    }

    // Callback invoked after the first drain barrier, while event loops are
    // still running. Used by HttpServer to wait for HTTP/2 stream drain.
    void SetPreStopDrainCallback(std::function<void()> cb) {
        pre_stop_drain_cb_ = std::move(cb);
    }

    // Process pending tasks on the calling thread's dispatcher.
    // Used during stop-from-handler drain to keep enqueued tasks
    // (GOAWAY, CloseAfterWrite) progressing while the event loop is blocked.
    void ProcessSelfDispatcherTasks();

    // Check if the calling thread is a socket dispatcher thread.
    // Used to detect Stop-from-handler scenarios that would deadlock drain wait.
    bool IsOnDispatcherThread() const;

    // Called after init completes but before the blocking event loop.
    // Used by daemon mode to signal readiness to the parent process.
    void SetReadyCallback(std::function<void()> cb) { ready_callback_ = std::move(cb); }

    // Returns the actual port the server is listening on.
    // Resolves ephemeral port 0. Available after `StartListening()` has
    // succeeded; returns 0 in the ctor-only state.
    int GetBoundPort() const { return acceptor_ ? acceptor_->GetBoundPort() : 0; }

    // True once `StartListening()` has opened the listen socket.
    // False in the ctor-only partial state. Used by Stop() and by
    // `HttpServer::Start()` to gate Phase C on Phase B.
    bool IsListening() const { return acceptor_ != nullptr; }
};
