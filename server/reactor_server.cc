#include "reactor_server.h"
#include <iostream>


ReactorServer::ReactorServer(const std::string& _ip, const size_t _port,
                             int timer_interval,
                             std::chrono::seconds connection_timeout)
    : net_server_(_ip, _port, timer_interval, connection_timeout)
{   
    // Should we replace std::bind with lambda here?
    net_server_.SetNewConnectionCb(std::bind(&ReactorServer::NewConnection, this, std::placeholders::_1));
    net_server_.SetCloseConnectionCb(std::bind(&ReactorServer::CloseConnecition, this, std::placeholders::_1));
    net_server_.SetErrorCb(std::bind(&ReactorServer::CloseConnecition, this, std::placeholders::_1));
    net_server_.SetOnMessageCb(std::bind(&ReactorServer::ProcessMessage, this, std::placeholders::_1, std::placeholders::_2));
    net_server_.SetSendCompletionCb(std::bind(&ReactorServer::SendComplete, this, std::placeholders::_1));
}

void ReactorServer::Start(){
    task_workers_.Init(3);
    task_workers_.Start();

    net_server_.Start();
}

void ReactorServer::Stop(){
    task_workers_.Stop();
    net_server_.Stop();
}

void ReactorServer::NewConnection(std::shared_ptr<ConnectionHandler> conn){
    std::cout << "New Connection Comes In" << std::endl;
    // Can add some extra features related code below
}

void ReactorServer::CloseConnecition(std::shared_ptr<ConnectionHandler> conn){
    std::cout << "Connection Closed" << std::endl;
    // Can add some extra features related code below
}

void ReactorServer::Error(std::shared_ptr<ConnectionHandler> conn){
    std::cout << "Error Function Called" << std::endl;
    // Can add some extra features related code below
}

void ReactorServer::ProcessMessage(std::shared_ptr<ConnectionHandler> conn, std::string& message){
    std::cout << "Thread Id: " << std::this_thread::get_id() << " Process Message: " << message << std::endl;

    if(task_workers_.is_running() || (task_workers_.GetThreadWorkerNum() == 0)){
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
    std::cout << "Message Send Completed" << std::endl;
    // Can add some feature related code below
}
