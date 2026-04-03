#pragma once
#include "common.h"
#include "threadpool.h"
#include "net_server.h"

// For feature related task, use this type of worker
// TaskWorker: Handles application-level message processing tasks in thread pool
class TaskWorker : public ThreadTaskInterface {
public:
    explicit TaskWorker(std::function<void()> _func) : func_(std::move(_func)){}
protected:
    int RunTask() override {
        try{
            func_();
            return 0;  // Success
        }catch (const std::exception& e){
            std::cerr << "[Reactor] TaskWorker: Error handling event: " << e.what() << std::endl;
            return -1;
        }
    }
private:
    std::function<void()> func_;
};


/**
 * Legacy TCP echo server used ONLY by reactor-core test suites
 * (basic, stress, race condition, timeout tests).
 *
 * WARNING: This class is TCP-stream-unsafe — it treats each callback
 * invocation as one logical message. TCP fragmentation/coalescing can
 * split or merge messages across callbacks. For proper message framing,
 * use HttpServer (HTTP framing) or WebSocket (frame-based protocol).
 *
 * NOT for production use. Kept solely as test infrastructure for
 * verifying the reactor core (epoll, connection lifecycle, timeouts).
 */

class ReactorServer
{
private:
    NetServer net_server_;
    ThreadPool task_workers_;
public:
    ReactorServer(const std::string&, const size_t,
                  int timer_interval = 60,
                  std::chrono::seconds connection_timeout = std::chrono::seconds(300));
    ~ReactorServer() = default;

    void Start();
    void Stop();

    // Called after init completes but before the blocking event loop.
    void SetReadyCallback(std::function<void()> cb);

    // Returns the actual port the server is listening on.
    int GetBoundPort() const;

    void NewConnection(std::shared_ptr<ConnectionHandler>);
    void CloseConnecition(std::shared_ptr<ConnectionHandler>);
    void Error(std::shared_ptr<ConnectionHandler>);
    void ProcessMessage(std::shared_ptr<ConnectionHandler>, std::string&);
    void OnMessage(std::shared_ptr<ConnectionHandler>, std::string&);
    void SendComplete(std::shared_ptr<ConnectionHandler>);
};