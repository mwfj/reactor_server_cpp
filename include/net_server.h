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
    NetServer(const std::string& _ip, const size_t _port,
              int timer_interval = 60,
              std::chrono::seconds connection_timeout = std::chrono::seconds(300),
              int worker_threads = 0);  // 0 = use hardware_concurrency default
    ~NetServer(); 

    void Start();
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
    // Resolves ephemeral port 0. Available after the constructor completes
    // (bind happens during construction). IPv4 only.
    int GetBoundPort() const { return acceptor_ ? acceptor_->GetBoundPort() : 0; }
};
