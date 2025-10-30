#include "net_server.h"


NetServer::NetServer(const std::string& _ip, const size_t _port,
                     int timer_interval,
                     std::chrono::seconds connection_timeout)
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
    // Should we replace std::bind with lambda here?
    acceptor_->SetNewConnCb(std::bind(&NetServer::HandleNewConnection, this, std::placeholders::_1));
    sock_workers_.Init();
    sock_workers_.Start();
}

NetServer::~NetServer(){
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
    // First: Close all active connections to ensure clean shutdown
    // This prevents connections from holding references to dispatchers during shutdown
    {
        std::lock_guard<std::mutex> lck(conn_mtx_);
        connections_.clear();  // This will trigger ConnectionHandler destructors
    }

    // Second: Stop all event loops (now with no active connections)
    for(auto task : socket_dispatchers_)
        task -> StopEventLoop();
    conn_dispatcher_->StopEventLoop();

    // Third: Now safe to join worker threads
    sock_workers_.Stop();
}

void NetServer::HandleNewConnection(std::unique_ptr<SocketHandler> cilent_sock){
    int idx = cilent_sock -> fd() % sock_workers_.GetThreadWorkerNum();
    std::shared_ptr<ConnectionHandler> conn = std::shared_ptr<ConnectionHandler>(new ConnectionHandler(socket_dispatchers_[idx], std::move(cilent_sock)));

    // Two-phase initialization: register callbacks after shared_ptr is created
    // This allows callbacks to safely capture weak_ptr instead of raw 'this'
    conn -> RegisterCallbacks();

    conn -> SetCloseCb(std::bind(&NetServer::HandleCloseConnection, this, std::placeholders::_1));
    conn -> SetErrorCb(std::bind(&NetServer::HandleErrorConnection, this, std::placeholders::_1));
    conn -> SetOnMessageCb(std::bind(&NetServer::OnMessage, this, std::placeholders::_1, std::placeholders::_2));
    conn -> SetCompletionCb(std::bind(&NetServer::HandleSendComplete, this, std::placeholders::_1));
    AddConnection(conn);

    std::cout << "[Reactor Server] new connection(fd: "
        << conn -> fd() << ", ip: " << conn -> ip_addr() << ", port: " << conn -> port() << ").\n"
        << "ok" << std::endl;

    if(new_conn_callback_)
        new_conn_callback_(conn);
}

void NetServer::HandleCloseConnection(std::shared_ptr<ConnectionHandler> conn){
    if(close_conn_callback_)
        close_conn_callback_(conn);

    std::cout << "[NetServer] client fd: " << conn -> fd() << " disconnected." << std::endl;
    RemoveConnection(conn -> fd());
    // close this connection
    conn.reset();
}

void NetServer::HandleErrorConnection(std::shared_ptr<ConnectionHandler> conn){
    if(error_callback_)
        error_callback_(conn);

    std::cout << "[NetServer] client fd: " << conn -> fd() << "error occurred, disconnect." << std::endl;
    RemoveConnection(conn -> fd());
    conn.reset();
}

void NetServer::OnMessage(std::shared_ptr<ConnectionHandler> conn, std::string& message){
    if(on_message_callback_)
        on_message_callback_(conn, message);
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
    if(send_complete_callback_)
        send_complete_callback_(conn);
}

void NetServer::SetNewConnectionCb(std::function<void(std::shared_ptr<ConnectionHandler>)> fn){
    if(fn)
        new_conn_callback_ = fn;
}

void NetServer::SetCloseConnectionCb(std::function<void(std::shared_ptr<ConnectionHandler>)> fn){
    if(fn)
        close_conn_callback_ = fn;
}

void NetServer::SetErrorCb(std::function<void(std::shared_ptr<ConnectionHandler>)> fn){
    if(fn)
        error_callback_ = fn;
}

void NetServer::SetOnMessageCb(std::function<void(std::shared_ptr<ConnectionHandler>, std::string&)> fn){
    if(fn)
        on_message_callback_ = fn;
}

void NetServer::SetSendCompletionCb(std::function<void(std::shared_ptr<ConnectionHandler>)> fn){
    if(fn)
        send_complete_callback_ = fn;
}

void NetServer::SetTimerCb(std::function<void(std::shared_ptr<Dispatcher>)> fn){
    timer_callback = fn;
}

void NetServer::Timeout(std::shared_ptr<Dispatcher> sock_dispatcher){
    if(timer_callback)
        timer_callback(sock_dispatcher);
}