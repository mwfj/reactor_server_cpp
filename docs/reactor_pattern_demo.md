# Building a TCP Echo Server with the Reactor Pattern

This guide demonstrates how to build a TCP echo server on top of the reactor core using the patterns established in this codebase. It is based on the original `ReactorServer` demo class that was used during early development to validate the reactor core before the HTTP/WebSocket/TLS layers were built.

> **Note:** For production use, prefer `HttpServer` (HTTP framing) or WebSocket (frame-based protocol) over raw TCP. Raw TCP is stream-oriented — message boundaries are not preserved, so application-level framing is required for correctness.

---

## Architecture Overview

The reactor core provides non-blocking, event-driven I/O through these components:

```
Application Layer (your code)
        │
        ▼
   NetServer           ← Server orchestrator: manages acceptor, dispatchers, connections
        │
   ┌────┼────┐
   ▼    ▼    ▼
Dispatcher(s)          ← Event loop coordinators (one per worker thread)
   │
   ▼
Channel + EventHandler ← fd + event callbacks, backed by epoll (Linux) or kqueue (macOS)
   │
   ▼
ConnectionHandler      ← Per-connection state: read/write buffers, lifecycle, optional TLS
```

Your application code sits above `NetServer` and receives callbacks for connection lifecycle events and incoming data.

---

## Step 1: Define Your Server Class

The server class wraps `NetServer` and optionally a `ThreadPool` for offloading message processing:

```cpp
#include "net_server.h"
#include "threadpool.h"

// Task wrapper for thread pool integration
class TaskWorker : public ThreadTaskInterface {
public:
    explicit TaskWorker(std::function<void()> func) : func_(std::move(func)) {}
protected:
    int RunTask() override {
        try {
            func_();
            return 0;
        } catch (const std::exception& e) {
            std::cerr << "TaskWorker error: " << e.what() << std::endl;
            return -1;
        }
    }
private:
    std::function<void()> func_;
};

class EchoServer {
private:
    NetServer net_server_;
    ThreadPool task_workers_;
public:
    EchoServer(const std::string& ip, size_t port,
               int timer_interval = 60,
               std::chrono::seconds connection_timeout = std::chrono::seconds(300));
    ~EchoServer() = default;

    void Start();
    void Stop();
    void SetReadyCallback(std::function<void()> cb);
    int GetBoundPort() const;

    // Callback handlers
    void NewConnection(std::shared_ptr<ConnectionHandler> conn);
    void CloseConnection(std::shared_ptr<ConnectionHandler> conn);
    void Error(std::shared_ptr<ConnectionHandler> conn);
    void ProcessMessage(std::shared_ptr<ConnectionHandler> conn, std::string& message);
    void OnMessage(std::shared_ptr<ConnectionHandler> conn, std::string& message);
    void SendComplete(std::shared_ptr<ConnectionHandler> conn);
};
```

---

## Step 2: Wire Callbacks in the Constructor

`NetServer` exposes five callback hooks. Register them in the constructor using lambdas or `std::bind`:

```cpp
EchoServer::EchoServer(const std::string& ip, size_t port,
                       int timer_interval,
                       std::chrono::seconds connection_timeout)
    : net_server_(ip, port, timer_interval, connection_timeout)
{
    using namespace std::placeholders;
    net_server_.SetNewConnectionCb(
        std::bind(&EchoServer::NewConnection, this, _1));
    net_server_.SetCloseConnectionCb(
        std::bind(&EchoServer::CloseConnection, this, _1));
    net_server_.SetErrorCb(
        std::bind(&EchoServer::Error, this, _1));
    net_server_.SetOnMessageCb(
        std::bind(&EchoServer::ProcessMessage, this, _1, _2));
    net_server_.SetSendCompletionCb(
        std::bind(&EchoServer::SendComplete, this, _1));
}
```

### NetServer Callback Reference

| Callback | Signature | When Fired |
|----------|-----------|------------|
| `SetNewConnectionCb` | `void(shared_ptr<ConnectionHandler>)` | New TCP connection accepted |
| `SetCloseConnectionCb` | `void(shared_ptr<ConnectionHandler>)` | Connection closed (peer or server) |
| `SetErrorCb` | `void(shared_ptr<ConnectionHandler>)` | Error on connection |
| `SetOnMessageCb` | `void(shared_ptr<ConnectionHandler>, string&)` | Data received from client |
| `SetSendCompletionCb` | `void(shared_ptr<ConnectionHandler>)` | Output buffer fully drained |

---

## Step 3: Implement Lifecycle Methods

### Start and Stop

```cpp
void EchoServer::Start() {
    task_workers_.Init(3);    // 3 worker threads
    task_workers_.Start();
    net_server_.Start();      // Blocks in event loop
}

void EchoServer::Stop() {
    // Order matters for clean shutdown:
    // 1. Stop accepting — prevents new connections during teardown
    net_server_.StopAccepting();
    // 2. Stop task workers — waits for in-flight tasks to finish their
    //    SendData() calls while dispatchers are still running
    task_workers_.Stop();
    // 3. Stop the rest — close connections, stop event loops
    net_server_.Stop();
}
```

### Ready Callback and Port Discovery

```cpp
void EchoServer::SetReadyCallback(std::function<void()> cb) {
    net_server_.SetReadyCallback(std::move(cb));
}

int EchoServer::GetBoundPort() const {
    return net_server_.GetBoundPort();
}
```

The ready callback fires after `bind()` + `listen()` but before the blocking event loop. Pass port `0` to get an OS-assigned ephemeral port, then call `GetBoundPort()` in the ready callback to discover it.

---

## Step 4: Handle Messages

### Thread Pool Offloading

The `ProcessMessage` callback runs on the dispatcher (event loop) thread. For CPU-intensive work, offload to the thread pool:

```cpp
void EchoServer::ProcessMessage(std::shared_ptr<ConnectionHandler> conn,
                                std::string& message)
{
    if (task_workers_.is_running() && task_workers_.GetThreadWorkerNum() > 0) {
        // IMPORTANT: Copy message by value — the reference is only valid
        // during this callback. The lambda executes later on a worker thread,
        // by which time the original reference is invalid.
        std::string msg = message;
        auto task = std::make_shared<TaskWorker>([this, conn, msg]() {
            std::string mutable_msg = msg;
            this->OnMessage(conn, mutable_msg);
        });
        try {
            task_workers_.AddTask(task);
        } catch (const std::runtime_error&) {
            // Pool stopped concurrently (shutdown race) — drop gracefully
            return;
        }
    } else {
        // No thread pool — handle inline on the dispatcher thread
        OnMessage(conn, message);
    }
}
```

### Echo Logic

```cpp
void EchoServer::OnMessage(std::shared_ptr<ConnectionHandler> conn,
                           std::string& message)
{
    message = "[Server Reply]: " + message;
    conn->SendData(message.data(), message.size());
}
```

`SendData()` writes to the connection's output buffer. The reactor core handles flushing the buffer to the socket via write-ready events.

> **Warning:** `SendData()` uses the connection's internal `Buffer` which prepends a 4-byte length header (network byte order). This is a length-prefix framing protocol — the client must read the 4-byte header first, then read exactly that many bytes. This is NOT HTTP and is NOT wire-compatible with standard tools like `curl`.

---

## Step 5: Build a Matching Client

Since the server uses length-prefix framing, the client must match:

```cpp
class EchoClient {
    int sockfd_ = -1;
    struct sockaddr_in servaddr_;

    // Read exactly n bytes (handles partial reads)
    bool RecvN(void* buffer, size_t n) {
        size_t total = 0;
        char* ptr = static_cast<char*>(buffer);
        while (total < n) {
            ssize_t received = recv(sockfd_, ptr + total, n - total, 0);
            if (received <= 0) {
                if (received == 0) return false;           // Connection closed
                if (errno == EINTR) continue;              // Interrupted, retry
                if (errno == EAGAIN) throw std::runtime_error("Timeout");
                throw std::runtime_error("Receive failed");
            }
            total += received;
        }
        return true;
    }

    // Send exactly n bytes (handles partial writes)
    bool SendN(const void* buffer, size_t n) {
        size_t total = 0;
        const char* ptr = static_cast<const char*>(buffer);
        while (total < n) {
            int flags = 0;
#ifdef MSG_NOSIGNAL
            flags |= MSG_NOSIGNAL;  // Prevent SIGPIPE on Linux
#endif
            ssize_t sent = send(sockfd_, ptr + total, n - total, flags);
            if (sent <= 0) {
                if (errno == EINTR || errno == ECONNRESET) return false;
                throw std::runtime_error("Send failed");
            }
            total += sent;
        }
        return true;
    }

public:
    void Connect(const char* ip, int port) {
        sockfd_ = socket(AF_INET, SOCK_STREAM, 0);
#ifdef SO_NOSIGPIPE
        int set = 1;
        setsockopt(sockfd_, SOL_SOCKET, SO_NOSIGPIPE, &set, sizeof(set));
#endif
        memset(&servaddr_, 0, sizeof(servaddr_));
        servaddr_.sin_family = AF_INET;
        servaddr_.sin_addr.s_addr = inet_addr(ip);
        servaddr_.sin_port = htons(port);

        if (connect(sockfd_, (struct sockaddr*)&servaddr_, sizeof(servaddr_)) < 0) {
            throw std::runtime_error("Connection failed");
        }
    }

    void Send(const std::string& message) {
        SendN(message.data(), message.size());
    }

    std::string Receive() {
        // Read 4-byte length header (network byte order)
        uint32_t msg_length = 0;
        if (!RecvN(&msg_length, 4)) {
            throw std::runtime_error("Receive header failed");
        }
        msg_length = ntohl(msg_length);

        // Read the message body
        std::vector<char> buf(msg_length);
        if (!RecvN(buf.data(), msg_length)) {
            throw std::runtime_error("Receive body failed");
        }
        return std::string(buf.data(), msg_length);
    }

    void Close() {
        if (sockfd_ >= 0) {
            close(sockfd_);
            sockfd_ = -1;
        }
    }

    ~EchoClient() { Close(); }
};
```

---

## Key Patterns and Lessons

### 1. TCP Stream Safety

TCP is a byte stream — `recv()` does not preserve message boundaries. A single `send("Hello")` might arrive as two `recv()` calls returning `"Hel"` and `"lo"`, or two sends might coalesce into one `recv()`. Always use application-level framing:

- **Length-prefix:** 4-byte header + body (used by `Buffer::AppendWithHead`)
- **HTTP framing:** Content-Length or Transfer-Encoding (used by `HttpServer`)
- **WebSocket frames:** opcode + length + payload (used by `WebSocketConnection`)

### 2. Callback Thread Safety

- The `OnMessage` callback runs on the **dispatcher thread**. Long-running work blocks the event loop for all connections on that dispatcher.
- Offload CPU-intensive work to a `ThreadPool`, but **copy** all data by value — references are only valid during the callback.
- When capturing `ConnectionHandler` in lambdas, use `shared_ptr` (not raw pointers) to ensure the connection survives until the task executes.

### 3. Shutdown Ordering

The shutdown sequence must respect dependencies:
1. **Stop accepting** — prevents new connections from racing with teardown
2. **Stop task workers** — waits for in-flight tasks that may call `SendData()` (dispatchers must still be running to flush output)
3. **Stop event loops** — closes connections, joins dispatcher threads

Reversing steps 2 and 3 can cause `SendData()` to fail because dispatchers are already stopped.

### 4. Ephemeral Ports for Testing

Always use port `0` in tests to get an OS-assigned ephemeral port:

```cpp
EchoServer server("127.0.0.1", 0);  // Ephemeral port
server.SetReadyCallback([&server]() {
    int port = server.GetBoundPort();  // Discover assigned port
    // ... start test clients ...
});
server.Start();
```

This eliminates port conflicts between test suites running in parallel.

### 5. The TestServerRunner Pattern

The `TestServerRunner<T>` RAII wrapper starts any server type in a background thread and blocks until the ready callback fires:

```cpp
EchoServer server("127.0.0.1", 0);
TestServerRunner<EchoServer> runner(server);
int port = runner.GetPort();
// ... test with port ...
// ~TestServerRunner calls Stop() + join
```

This pattern works with any server type that exposes `SetReadyCallback()`, `GetBoundPort()`, `Start()`, and `Stop()`.

---

## Migration Path

If you built a raw TCP server following this pattern and want to migrate to HTTP:

1. Replace `NetServer` callbacks with `HttpServer` route handlers:
   ```cpp
   HttpServer server("127.0.0.1", 8080);
   server.Post("/echo", [](const HttpRequest& req, HttpResponse& resp) {
       resp.Status(200).Body(req.body);
   });
   server.Start();
   ```

2. HTTP framing handles message boundaries automatically — no length-prefix protocol needed.

3. Clients can use `curl`, browsers, or any HTTP library instead of custom socket code.

4. Thread pool integration is handled internally by `HttpServer` — no manual `TaskWorker` offloading needed.

See [docs/http.md](http.md) for the full HTTP API reference.
