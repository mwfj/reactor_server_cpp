#include "net_server.h"
#include "tls/tls_context.h"
#include "tls/tls_connection.h"


NetServer::NetServer(const std::string& _ip, const size_t _port,
                     int timer_interval,
                     std::chrono::seconds connection_timeout,
                     int worker_threads)
    : conn_dispatcher_(std::make_shared<Dispatcher>()),
      acceptor_(nullptr),
      timer_interval_(timer_interval),
      connection_timeout_(connection_timeout)
{
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
    socket_dispatchers_.clear();
    connections_.clear();
}

// start event loop
void NetServer::Start(){
    socket_dispatchers_.reserve(sock_workers_.GetThreadWorkerNum());
    for(int idx = 0; idx < sock_workers_.GetThreadWorkerNum(); idx ++){
        // Use configurable timer parameters
        std::shared_ptr<Dispatcher> task = std::make_shared<Dispatcher>(true, timer_interval_, connection_timeout_);
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
    conn_dispatcher_->RunEventLoop();
}

// stop event loop
void NetServer::Stop(){
    // First: Stop the connection dispatcher so no more accept events fire,
    // then destroy the acceptor to release the listening port immediately.
    // StopEventLoop sets is_running_=false; RunEventLoop exits on next check.
    // Acceptor::~Acceptor closes the channel (atomic guard) and releases the fd.
    conn_dispatcher_->StopEventLoop();
    acceptor_.reset();

    // Second: Release dispatcher-held connection references via EnQueue
    // (ClearConnections must run on the dispatcher thread to avoid racing TimerHandler)
    for (auto& disp : socket_dispatchers_) {
        disp->EnQueue([d = disp]() {
            d->ClearConnections();
        });
    }

    // Third: Close all active connections — collect under lock, close after releasing.
    // CallCloseCb triggers HandleCloseConnection which takes conn_mtx_, so we must
    // NOT hold the lock while calling it to avoid deadlock.
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
        conn->CallCloseCb();
    }
    conns_to_close.clear();

    // Fourth: Stop socket dispatcher event loops (conn_dispatcher already stopped above)
    for(auto task : socket_dispatchers_)
        task -> StopEventLoop();

    // Fifth: Now safe to join worker threads
    sock_workers_.Stop();
}

void NetServer::HandleNewConnection(std::unique_ptr<SocketHandler> cilent_sock){
    // Enforce max_connections limit
    if (max_connections_ > 0) {
        std::lock_guard<std::mutex> lck(conn_mtx_);
        if (static_cast<int>(connections_.size()) >= max_connections_) {
            std::cerr << "[NetServer] Max connections (" << max_connections_
                      << ") reached, rejecting fd " << cilent_sock->fd() << std::endl;
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
            std::cerr << "[NetServer] TLS setup failed for fd " << conn->fd() << ": " << e.what() << std::endl;
            // Close properly to avoid double-close: both Channel and SocketHandler
            // hold the same fd. CallCloseCb closes the channel fd and releases from SocketHandler.
            conn->CallCloseCb();
            return;
        }
    }

    // Set application callbacks BEFORE RegisterCallbacks().
    // RegisterCallbacks() queues epoll registration via EnQueue, so in practice
    // the socket dispatcher processes it after these are set. But ordering them
    // first eliminates any theoretical race window.
    conn -> SetCloseCb(std::bind(&NetServer::HandleCloseConnection, this, std::placeholders::_1));
    conn -> SetErrorCb(std::bind(&NetServer::HandleErrorConnection, this, std::placeholders::_1));
    conn -> SetOnMessageCb(std::bind(&NetServer::OnMessage, this, std::placeholders::_1, std::placeholders::_2));
    conn -> SetCompletionCb(std::bind(&NetServer::HandleSendComplete, this, std::placeholders::_1));
    AddConnection(conn);

    // Two-phase initialization: register channel callbacks and enable epoll.
    // Uses weak_ptr captures so callbacks are safe if ConnectionHandler is destroyed.
    conn -> RegisterCallbacks();

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

    std::cout << "[Reactor Server] new connection(fd: "
        << conn -> fd() << ", ip: " << conn -> ip_addr() << ", port: " << conn -> port() << ").\n"
        << "ok" << std::endl;

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

    std::cout << "[NetServer] client fd: " << close_fd << " disconnected." << std::endl;

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

    std::cout << "[NetServer] client fd: " << close_fd << " error occurred, disconnect." << std::endl;

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

void NetServer::SetTimerCb(CALLBACKS_NAMESPACE::NetSrvTimerCallback fn){
    if(fn)
        callbacks_.timer_callback = std::move(fn);
}