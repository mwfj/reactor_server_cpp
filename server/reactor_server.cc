#include "reactor_server.h"
#include "log/logger.h"


ReactorServer::ReactorServer(const std::string& _ip, const size_t _port,
                             int timer_interval,
                             std::chrono::seconds connection_timeout)
    : net_server_(_ip, _port, timer_interval, connection_timeout)
{   
    // Should we replace std::bind with lambda here?
    net_server_.SetNewConnectionCb(std::bind(&ReactorServer::NewConnection, this, std::placeholders::_1));
    net_server_.SetCloseConnectionCb(std::bind(&ReactorServer::CloseConnecition, this, std::placeholders::_1));
    net_server_.SetErrorCb(std::bind(&ReactorServer::Error, this, std::placeholders::_1));
    net_server_.SetOnMessageCb(std::bind(&ReactorServer::ProcessMessage, this, std::placeholders::_1, std::placeholders::_2));
    net_server_.SetSendCompletionCb(std::bind(&ReactorServer::SendComplete, this, std::placeholders::_1));
}

void ReactorServer::Start(){
    task_workers_.Init(3);
    task_workers_.Start();

    net_server_.Start();
}

void ReactorServer::Stop(){
    // Stop task_workers_ FIRST — waits for in-flight tasks to complete their
    // SendData() calls while dispatchers are still running. Stopping
    // net_server_ first would drop sends from in-flight tasks (dispatchers
    // stopped → EnQueue drops). New tasks may still be enqueued by
    // ProcessMessage during this window, but task_workers_.Stop() rejects
    // them with exceptions via SetException after setting is_running=false.
    task_workers_.Stop();
    net_server_.Stop();
}

void ReactorServer::NewConnection(std::shared_ptr<ConnectionHandler> conn){
    logging::Get()->debug("New Connection Comes In");
    // Can add some extra features related code below
}

void ReactorServer::CloseConnecition(std::shared_ptr<ConnectionHandler> conn){
    logging::Get()->debug("Connection Closed");
    // Can add some extra features related code below
}

void ReactorServer::Error(std::shared_ptr<ConnectionHandler> conn){
    logging::Get()->warn("Error Function Called");
    // Can add some extra features related code below
}

// NOTE: This legacy TCP echo server treats each callback invocation as one
// logical message. This is stream-unsafe: TCP fragmentation/coalescing can
// split or merge application messages across callbacks. For proper message
// framing, use HttpServer (HTTP framing) or WebSocket (frame-based protocol).
void ReactorServer::ProcessMessage(std::shared_ptr<ConnectionHandler> conn, std::string& message){
    logging::Get()->debug("Process Message: {}", message);

    if(task_workers_.is_running() && (task_workers_.GetThreadWorkerNum() > 0)){
        // Use lambda with COPY-BY-VALUE capture for thread safety
        // Why copy 'message'?
        // 1. 'message' is a reference parameter owned by the caller (NetServer)
        // 2. The lambda will execute asynchronously in a worker thread LATER
        // 3. By the time the task executes, the original 'message' reference is INVALID (out of scope)
        // 4. We MUST copy the data to avoid dangling reference bugs
        //
        // Capture semantics:
        // - [this]: raw pointer (ReactorServer lifetime guaranteed by design)
        // - [conn]: shared_ptr by value (increments ref count, safe across threads)
        // - [msg]: string copy captured by value (C++11 compatible)
        std::string msg = message;  // Explicit copy for C++11 compatibility
        std::shared_ptr<TaskWorker> task = std::shared_ptr<TaskWorker>(
            new TaskWorker([this, conn, msg]() {
                // OnMessage expects std::string&, so create mutable local copy
                std::string mutable_msg = msg;
                this->OnMessage(conn, mutable_msg);
            }));
        task_workers_.AddTask(task);
    } else {
        OnMessage(conn, message);
    }
}

void ReactorServer::OnMessage(std::shared_ptr<ConnectionHandler> conn, std::string& message){
    // Can add some extra features related code below
    // Here we are just simple echo that message
    message = "[Server Reply]: " + message;
    conn -> SendData(message.data(), message.size());
}

void ReactorServer::SendComplete(std::shared_ptr<ConnectionHandler> conn){
    logging::Get()->debug("Message Send Completed");
    // Can add some feature related code below
}
