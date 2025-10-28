#pragma once
#include "common.h"
#include "socket_handler.h"
#include "inet_addr.h"
#include "epoll_handler.h"
#include "channel.h"
#include "dispatcher.h"
#include "connection_handler.h"
#include "acceptor.h"

#include "threadtask.h"
#include "threadpool.h"
#include <mutex>

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
            std::cerr << "[NetServer] SocketWorker: Error handling event: " << e.what() << std::endl;
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

    // Callbacks
    std::function<void(std::shared_ptr<ConnectionHandler>)>  new_conn_callback_ = nullptr;
    std::function<void(std::shared_ptr<ConnectionHandler>)>  close_conn_callback_ = nullptr;
    std::function<void(std::shared_ptr<ConnectionHandler>)>  error_callback_ = nullptr;

    std::function<void(std::shared_ptr<ConnectionHandler>, std::string&)>  on_message_callback_ = nullptr;
    std::function<void(std::shared_ptr<ConnectionHandler>)>  send_complete_callback_ = nullptr;
    std::function<void(std::shared_ptr<Dispatcher>)> timer_callback = nullptr;

    ThreadPool sock_workers_;

    // Timer configuration
    int timer_interval_;  // How often to check for timeouts (seconds)
    std::chrono::seconds connection_timeout_;  // Connection idle timeout duration

public:
    NetServer() = delete;
    NetServer(const std::string& _ip, const size_t _port,
              int timer_interval = 60,
              std::chrono::seconds connection_timeout = std::chrono::seconds(300));
    ~NetServer(); 

    void Start();
    void Stop();

    void HandleNewConnection(std::unique_ptr<SocketHandler>);
    void HandleCloseConnection(std::shared_ptr<ConnectionHandler>);
    void HandleErrorConnection(std::shared_ptr<ConnectionHandler>);
    void HandleSendComplete(std::shared_ptr<ConnectionHandler>);

    void OnMessage(std::shared_ptr<ConnectionHandler>, std::string&);
    void AddConnection(std::shared_ptr<ConnectionHandler>);
    void RemoveConnection(int);
    void Timeout(std::shared_ptr<Dispatcher>);
    
    void SetNewConnectionCb(std::function<void(std::shared_ptr<ConnectionHandler>)>);
    void SetCloseConnectionCb(std::function<void(std::shared_ptr<ConnectionHandler>)>);
    void SetErrorCb(std::function<void(std::shared_ptr<ConnectionHandler>)>);
    void SetOnMessageCb(std::function<void(std::shared_ptr<ConnectionHandler>, std::string&)>);
    void SetSendCompletionCb(std::function<void(std::shared_ptr<ConnectionHandler>)>);
    void SetTimerCb(std::function<void(std::shared_ptr<Dispatcher>)>);
};