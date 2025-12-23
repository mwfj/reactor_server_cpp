# Reactor Server

This is a C++11 implementation of a high-performance network server using the Reactor pattern with epoll-based/kqueue-based I/O multiplexing. The server is designed to handle thousands of concurrent connections efficiently using edge-triggered epoll mode.

This server now support MacOS and Linux

## Build Commands

```bash
# Main project (reactor server)
make                     # Build the executable (default target)
make help               # Show detailed help about Makefile targets
make clean              # Remove build artifacts
make test               # Build and run all tests (basic + stress + race + timeout)
./run                   # Run all tests directly (after building)

# Run specific test suites
make test_basic         # Run only basic functional tests
make test_stress        # Run only stress tests (100 concurrent clients)
make test_race          # Run only race condition tests
./run basic             # Run basic tests (or: ./run -b)
./run stress            # Run stress tests (or: ./run -s)
./run race              # Run race condition tests (or: ./run -r)
./run timeout           # Run timeout tests (or: ./run -t)
./run help              # Show test runner help

# Thread pool subproject (independent)
cd thread_pool
make                    # Build thread pool executable
make clean              # Clean thread pool artifacts
./run                   # Run thread pool tests
```

## Architecture

### Reactor Pattern Implementation

The codebase implements a modular Reactor pattern with clear separation of concerns:

**Dispatcher** ([include/dispatcher.h](include/dispatcher.h), [server/dispatcher.cc](server/dispatcher.cc))
- Central event loop coordinator that wraps EventHandler (cross-platform I/O multiplexing)
- `RunEventLoop()`: Main reactor loop that calls platform-specific wait with 1000ms timeout and dispatches events
- `StopEventLoop()`: Sets running state to false to exit the loop gracefully (atomic for thread safety)
- `UpdateChannel()` / `RemoveChannel()`: Delegates channel registration to EventHandler
- `WakeUp()` / `EnQueue()`: Cross-thread task queueing using eventfd (Linux) or pipe (macOS)
- `AddConnection()` / `SetTimerCB()`: Connection timeout management using timerfd
- Owns the EventHandler instance as `std::unique_ptr<EventHandler>` (sole ownership)
- **Two-phase initialization**: Must call `Init()` after construction to set up wake_channel_ (cannot use shared_from_this() in constructor)

**EventHandler** ([include/event_handler.h](include/event_handler.h), [server/event_handler.cc](server/event_handler.cc))
- Cross-platform abstraction layer that wraps platform-specific I/O multiplexing
- Linux: Uses EpollHandler (epoll API)
- macOS: Uses KqueueHandler (kqueue API)
- Windows: Prepared for IOCP (not yet implemented)
- Provides uniform interface: `UpdateEvent()`, `RemoveChannel()`, `WaitForEvent()`
- Automatically selects implementation at compile time via preprocessor directives

**EpollHandler** ([include/epoll_handler.h](include/epoll_handler.h), [server/epoll_handler.cc](server/epoll_handler.cc))
- Linux-specific wrapper around epoll API
- Manages the epoll file descriptor and event array (up to 1000 events per call)
- `UpdateEvent()`: Registers/modifies channels in the epoll interest list (EPOLL_CTL_ADD/MOD)
- `WaitForEvent()`: Blocks waiting for I/O events and returns vector of active channels
- Stores all channels in `channel_map_` (map<int, shared_ptr<Channel>>)

**KqueueHandler** ([include/kqueue_handler.h](include/kqueue_handler.h), [server/kqueue_handler.cpp](server/kqueue_handler.cpp))
- macOS/BSD-specific wrapper around kqueue API
- Manages the kqueue file descriptor and kevent array (up to 1000 events per call)
- `UpdateEvent()`: Registers/modifies channels using EV_SET with EVFILT_READ/EVFILT_WRITE filters
- `WaitForEvent()`: Blocks on kevent() and returns vector of active channels
- Stores all channels in `channel_map_` with mutex protection for thread safety

**Channel** ([include/channel.h](include/channel.h), [server/channel.cc](server/channel.cc))
- Represents a file descriptor and its associated event handlers
- Maintains fd, Dispatcher reference (weak_ptr), and event state (requested vs delivered events)
- `HandleEvent()`: Dispatches events (EPOLLIN, EPOLLOUT, EPOLLRDHUP, EPOLLERR) to callbacks
- `OnMessage()`: Default read callback implementing echo protocol (reads until EAGAIN, echoes back)
- `NewConnection()`: Legacy method for accepting connections (now delegated to Acceptor)
- `CloseChannel()`: Closes fd and resets epoll state, prevents double-close with `is_channel_closed_` flag
- Uses std::function callbacks for flexible event handling

**Acceptor** ([include/acceptor.h](include/acceptor.h), [server/acceptor.cc](server/acceptor.cc))
- Handles listening socket setup and new connection acceptance
- Constructor initializes listening socket with optimal TCP options (SO_REUSEADDR, SO_REUSEPORT, TCP_NODELAY, SO_KEEPALIVE)
- `NewConnection()`: Accepts new client connections and invokes callback with new SocketHandler
- Creates and manages acceptor_channel_ for listening socket
- Delegates connection handling to NetServer via callback

**ConnectionHandler** ([include/connection_handler.h](include/connection_handler.h), [server/connection_handler.cc](server/connection_handler.cc))
- Represents a single client connection with its Channel and SocketHandler
- Constructor creates client Channel, sets up callbacks, enables edge-triggered mode
- Provides accessor methods: `fd()`, `ip_addr()`, `port()`
- Manages input/output buffers (`input_bf_`, `output_bf_`) for buffered I/O
- `OnMessage()`: Reads data into input buffer until EAGAIN
- `SendData()`: Appends data to output buffer with size header and enables write mode
- `CallWriteCb()`: Sends buffered data, disables write mode when complete
- Callback setters: `SetOnMessageCb()`, `SetCompletionCb()`, `SetCloseCb()`, `SetErrorCb()`
- Uses callback types from [include/callbacks.h](include/callbacks.h) (`CALLBACKS_NAMESPACE` namespace)

**SocketHandler** ([include/socket_handler.h](include/socket_handler.h), [server/socket_handler.cc](server/socket_handler.cc))
- RAII wrapper for socket file descriptors with move semantics (no copy allowed)
- Handles socket lifecycle: creation, configuration, binding, listening, accepting, closing
- Automatically sets all sockets to non-blocking mode
- Provides socket option setters: TCP_NODELAY, SO_REUSEADDR, SO_REUSEPORT, SO_KEEPALIVE
- Uses `accept4()` with SOCK_NONBLOCK flag for atomic non-blocking accept

**NetServer** ([include/net_server.h](include/net_server.h), [server/net_server.cc](server/net_server.cc))
- High-level server orchestrator that ties all components together
- Constructor creates Acceptor and sets new connection callback
- `Start()`: Starts the Dispatcher event loop
- `Stop()`: Stops the Dispatcher event loop
- `HandleNewConnection()`: Creates ConnectionHandler for new clients, stores in connections_ map
- `HandleCloseConnection()` / `HandleErrorConnection()`: Removes connections from map and releases resources
- Maintains `std::map<int, std::shared_ptr<ConnectionHandler>>` for all active connections
- Provides callback setters for application-level event handling: `SetNewConnectionCb()`, `SetCloseConnectionCb()`, `SetErrorCb()`, `SetOnMessageCb()`, `SetSendCompletionCb()`

**Buffer** ([include/buffer.h](include/buffer.h), [server/buffer.cc](server/buffer.cc))
- Manages read and write buffers for each connection
- `Append()`: Appends data without metadata
- `AppendWithHead()`: Appends data with size metadata (4-byte header)
- `Erase()`, `Clear()`: Buffer management operations
- `Size()`, `Data()`: Buffer access methods
- Each ConnectionHandler maintains separate `input_bf_` and `output_bf_` instances

**ReactorServer** ([include/reactor_server.h](include/reactor_server.h), [server/reactor_server.cc](server/reactor_server.cc))
- Application-level wrapper around NetServer for easier usage
- Demonstrates callback-based protocol implementation pattern
- Sets up all NetServer callbacks in constructor using `std::bind`
- Virtual methods for application logic: `NewConnection()`, `CloseConnection()`, `Error()`, `ProcessMessage()`, `SendComplete()`
- Example implementation shows echo protocol with message prefix: `"[Server Reply]: "`

**Callbacks** ([include/callbacks.h](include/callbacks.h))
- Centralized callback type definitions in `CALLBACKS_NAMESPACE` namespace
- Organizes callbacks by component: ConnectionHandler, Channel, NetServer, Dispatcher
- Provides structured callback groups: `ConnCallbacks`, `ChannelCallbacks`, `NetSrvCallbacks`, `DispatcherCallbacks`
- Improves type safety and code organization
- All callback types use `std::function` for flexibility

### Data Flow

1. **Server Initialization**:
   - NetServer creates Dispatcher (which creates EpollHandler)
   - NetServer creates Acceptor with listening socket
   - Acceptor creates Channel for listening socket, registers with Dispatcher/EpollHandler

2. **Event Loop**:
   - `Start()` calls `Dispatcher::RunEventLoop()`
   - Loop calls `epoll_wait()` via `EpollHandler::WaitForEvent()` with 1000ms timeout
   - Returns vector of active channels

3. **New Connection Flow**:
   - EPOLLIN on listening socket triggers Acceptor's Channel callback
   - `Acceptor::NewConnection()` accepts client, creates SocketHandler
   - Callback invokes `NetServer::HandleNewConnection()` with SocketHandler
   - NetServer creates ConnectionHandler (which creates client Channel)
   - NetServer sets callbacks on ConnectionHandler, stores in connections_ map
   - ConnectionHandler registers client Channel with Dispatcher for EPOLLIN events in edge-triggered mode
   - NetServer calls application-level `new_conn_callback_` if set

4. **Client Data Flow (Read)**:
   - EPOLLIN on client socket triggers `Channel::HandleEvent()`
   - HandleEvent() calls `ConnectionHandler::OnMessage()`
   - `OnMessage()` reads data into `input_bf_` until EAGAIN
   - NetServer calls application-level `on_message_callback_` with connection and buffered data
   - Application processes message and calls `conn->SendData()` to send response

5. **Client Data Flow (Write)**:
   - `SendData()` appends data to `output_bf_` and enables EPOLLOUT
   - EPOLLOUT event triggers `ConnectionHandler::CallWriteCb()`
   - `CallWriteCb()` sends buffered data, removes sent bytes from buffer
   - When buffer empty: disables EPOLLOUT, calls `send_complete_callback_`

6. **Client Disconnection**:
   - On read==0 or EPOLLRDHUP/EPOLLHUP: calls `CallCloseCb()`
   - `NetServer::HandleCloseConnection()` calls application callback, removes from map
   - ConnectionHandler shared_ptr reset, triggering cleanup

### Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          REACTOR SERVER DATA FLOW                           │
│                    (Component Interaction & Data Movement)                  │
└─────────────────────────────────────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════════════
 STEP 1: SERVER INITIALIZATION
═══════════════════════════════════════════════════════════════════════════════

                            ┌───────────────────┐
                            │   NetServer       │
                            │   Constructor     │
                            └─────────┬─────────┘
                                      │
                    ┌─────────────────┼─────────────────┐
                    │                 │                 │
                    ▼                 ▼                 ▼
          ┌─────────────────┐  ┌────────────┐  ┌────────────────┐
          │   Dispatcher    │  │  Acceptor  │  │  Application   │
          │                 │  │            │  │  Callbacks     │
          └────────┬────────┘  └─────┬──────┘  └────────────────┘
                   │                 │
                   │ creates         │ creates
                   ▼                 ▼
          ┌─────────────────┐  ┌────────────────┐
          │  EventHandler   │  │ SocketHandler  │
          │  (Epoll/Kqueue) │  │ (listen socket)│
          └─────────────────┘  └─────┬──────────┘
                   │                 │
                   │                 │ creates
                   │                 ▼
                   │           ┌────────────────┐
                   │           │  Channel       │
                   │           │  (listen fd)   │
                   │           └────────┬───────┘
                   │                    │
                   │◀───────────────────┘
                   │  register with epoll/kqueue
                   │  (EPOLLIN events)
                   ▼
          ┌─────────────────────────────┐
          │  channel_map_[listen_fd]    │
          │  stores shared_ptr<Channel> │
          └─────────────────────────────┘

═══════════════════════════════════════════════════════════════════════════════
 STEP 2: EVENT LOOP (Dispatcher::RunEventLoop)
═══════════════════════════════════════════════════════════════════════════════

    ┌──────────────────────────────────────────────────────────────┐
    │                    MAIN EVENT LOOP                           │
    │                                                              │
    │   while (is_running_) {                                      │
    │                                                              │
    │     ┌───────────────────────────────────────────┐            │
    │     │ EventHandler::WaitForEvent(1000ms)        │            │
    │     │ ↓                                         │            │
    │     │ epoll_wait()/kevent() - BLOCKS            │            │
    │     └─────────────────┬─────────────────────────┘            │
    │                       │                                      │
    │                       ▼                                      │
    │     ┌────────────────────────────────────────────┐           │
    │     │ Returns: vector<shared_ptr<Channel>>       │           │
    │     │          (active channels with events)     │           │
    │     └─────────────────┬──────────────────────────┘           │
    │                       │                                      │
    │                       ▼                                      │
    │     ┌────────────────────────────────────────────┐           │
    │     │ For each active channel:                   │           │
    │     │   channel->HandleEvent()                   │           │
    │     │     ↓                                      │           │
    │     │   Dispatches to registered callbacks       │           │
    │     └────────────────────────────────────────────┘           │
    │   }                                                          │
    └──────────────────────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════════════
 STEP 3: NEW CONNECTION ACCEPTANCE
═══════════════════════════════════════════════════════════════════════════════

    Client connects
         │
         ▼
    [TCP SYN/ACK Handshake]
         │
         ▼
    ┌──────────────────────┐
    │ EPOLLIN on listen_fd │
    └──────────┬───────────┘
               │
               ▼
    ┌────────────────────────────┐
    │ Acceptor::NewConnection()  │
    │   accept4(SOCK_NONBLOCK)   │
    └──────────┬─────────────────┘
               │
               ├─ Creates: SocketHandler (client_fd)
               │
               ▼
    ┌─────────────────────────────────────┐
    │ NetServer::HandleNewConnection()    │
    └──────────┬──────────────────────────┘
               │
               ├─ Creates: ConnectionHandler
               │              │
               │              ├─ Creates: Channel (client_fd)
               │              ├─ Creates: input_bf_, output_bf_
               │              └─ RegisterCallbacks() [weak_ptr]
               │
               ├─ Stores in: connections_[client_fd]
               │
               ▼
    ┌─────────────────────────────────────┐
    │ Channel registered with Dispatcher  │
    │ Mode: EPOLLIN | EPOLLET             │
    └─────────────────────────────────────┘
               │
               ▼
    ┌─────────────────────────────────────┐
    │ Application: new_conn_callback_     │
    └─────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════════════
 STEP 4: CLIENT DATA READ (Client → Server)
═══════════════════════════════════════════════════════════════════════════════

    Client sends data
         │
         ▼
    ┌──────────────────────┐
    │ EPOLLIN on client_fd │
    └──────────┬───────────┘
               │
               ▼
    ┌──────────────────────────┐
    │ Channel::HandleEvent()   │
    │   (EPOLLIN detected)     │
    └──────────┬───────────────┘
               │
               ▼
    ┌───────────────────────────────────────┐
    │ ConnectionHandler::OnMessage()        │
    │                                       │
    │   while (true) {                      │
    │     n = read(fd, buf, MAX_BUFFER)     │
    │     if (n > 0)                        │
    │       input_bf_.Append(buf, n)        │◀─── Edge-triggered:
    │     else if (errno == EAGAIN)         │     Read until EAGAIN
    │       break                           │
    │   }                                   │
    └───────────────┬───────────────────────┘
                    │
                    ▼
    ┌─────────────────────────────────────────┐
    │ NetServer::OnMessage()                  │
    │   Extracts data from input_bf_          │
    └───────────────┬─────────────────────────┘
                    │
                    ▼
    ┌─────────────────────────────────────────┐
    │ Application: on_message_callback_       │
    │   - Parse protocol                      │
    │   - Process business logic              │
    │   - Generate response                   │
    │   - Call conn->SendData()               │
    └─────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════════════
 STEP 5: SERVER DATA WRITE (Server → Client)
═══════════════════════════════════════════════════════════════════════════════

    Application calls conn->SendData(data, len)
         │
         ▼
    ┌────────────────────────────────────────┐
    │ ConnectionHandler::SendData()          │
    │   output_bf_.AppendWithHead(data, len) │ ◀── 4-byte length header
    │   channel_->EnableWriting()            │     prepended
    │   channel_->EnableETMode()             │
    └─────────────┬──────────────────────────┘
                  │
                  ├─ Modifies epoll: EPOLLIN | EPOLLOUT | EPOLLET
                  │
                  ▼
    ┌──────────────────────────┐
    │ EPOLLOUT on client_fd    │ ◀── Socket writable
    └──────────┬─────────────────┘
               │
               ▼
    ┌──────────────────────────┐
    │ Channel::HandleEvent()   │
    │   (EPOLLOUT detected)    │
    └──────────┬───────────────┘
               │
               ▼
    ┌────────────────────────────────────────┐
    │ ConnectionHandler::CallWriteCb()       │
    │                                        │
    │   while (output_bf_.Size() > 0) {      │
    │     n = write(fd, output_bf_.Data())   │
    │     if (n > 0)                         │
    │       output_bf_.Erase(n)              │◀─── Edge-triggered:
    │     else if (errno == EAGAIN)          │     Write until EAGAIN
    │       break                            │
    │   }                                    │
    │                                        │
    │   if (output_bf_.Size() == 0) {        │
    │     channel_->DisableWriting()         │
    │     completion_callback_()             │
    │   }                                    │
    └────────────────┬───────────────────────┘
                     │
                     ▼
    ┌──────────────────────────────────────────┐
    │ NetServer::HandleSendComplete()          │
    └────────────────┬─────────────────────────┘
                     │
                     ▼
    ┌──────────────────────────────────────────┐
    │ Application: send_complete_callback_     │
    └──────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════════════
 STEP 6: CONNECTION CLOSE
═══════════════════════════════════════════════════════════════════════════════

    Client closes connection / read() returns 0 / EPOLLRDHUP
         │
         ▼
    ┌──────────────────────────────────┐
    │ Channel::HandleEvent()           │
    │   (EPOLLRDHUP | EPOLLHUP)        │
    └──────────┬───────────────────────┘
               │
               ▼
    ┌──────────────────────────────────┐
    │ ConnectionHandler::CallCloseCb() │
    └──────────┬───────────────────────┘
               │
               ▼
    ┌─────────────────────────────────────────┐
    │ NetServer::HandleCloseConnection()      │
    │   - Remove from connections_[fd]        │
    │   - Call close_conn_callback_           │
    └─────────────┬───────────────────────────┘
                  │
                  ▼
    ┌─────────────────────────────────────────┐
    │ Application: close_conn_callback_       │
    └─────────────┬───────────────────────────┘
                  │
                  ▼
    ┌─────────────────────────────────────────┐
    │ ConnectionHandler destroyed             │
    │   (shared_ptr refcount → 0)             │
    └─────────────┬───────────────────────────┘
                  │
                  ▼
    ┌─────────────────────────────────────────┐
    │ Channel::CloseChannel()                 │
    │   1. dispatcher->RemoveChannel(fd)      │
    │      → epoll_ctl(EPOLL_CTL_DEL)         │
    │   2. close(fd)                          │
    └─────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════════════
                           MEMORY MANAGEMENT
═══════════════════════════════════════════════════════════════════════════════

┌─────────────────────────────────────────────────────────────────────────────┐
│ Ownership Model (C++11 Smart Pointers)                                      │
│                                                                             │
│  NetServer                                                                  │
│    ├─ unique_ptr<Dispatcher>          (sole ownership)                      │
│    │    └─ unique_ptr<EventHandler>   (sole ownership)                      │
│    │                                                                        │
│    ├─ unique_ptr<Acceptor>             (sole ownership)                     │
│    │    └─ unique_ptr<SocketHandler>   (listen socket)                      │
│    │                                                                        │
│    └─ map<fd, shared_ptr<ConnectionHandler>>  (shared ownership)            │
│              │                                                              │
│              ├─ unique_ptr<SocketHandler>     (client socket)               │
│              ├─ shared_ptr<Channel>           (shared with EventHandler)    │
│              │    └─ weak_ptr<Dispatcher>     (avoids circular ref)         │
│              ├─ Buffer input_bf_                                            │
│              └─ Buffer output_bf_                                           │
│                                                                             │
│  EventHandler (EpollHandler/KqueueHandler)                                  │
│    └─ map<fd, shared_ptr<Channel>>    (shared with ConnectionHandler)       │
│                                                                             │
│  Callbacks use weak_ptr<ConnectionHandler>:                                 │
│    - Prevents circular reference: Handler → Channel → Callback → Handler    │
│    - Safe destruction: callbacks check weak_ptr.lock() before invoking      │
└─────────────────────────────────────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════════════
                        CROSS-THREAD COMMUNICATION
═══════════════════════════════════════════════════════════════════════════════

  Other Thread                    I/O Thread (Dispatcher Event Loop)
       │                                     │
       │ EnQueue(task)                       │
       ├──────────────────────────────┐      │
       │                              │      │
       │  ┌───────────────────────┐   │      │
       │  │ Lock task_que_ mutex  │   │      │
       │  │ task_que_.push(task)  │   │      │
       │  │ Unlock mutex          │   │      │
       │  └───────────────────────┘   │      │
       │                              │      │
       │ WakeUp()                     │      │
       │  write(wake_fd_, "1")  ──────┼──────▶ EPOLLIN on wake_fd_
       │                              │      │
       │                              │      ▼
       │                              │  HandleEventId()
       │                              │      │
       │                              │      ├─ read(wake_fd_)
       │                              │      │
       │                              │      ├─ Lock mutex
       │                              │      ├─ Copy task_que_ → local_tasks
       │                              │      ├─ Clear task_que_
       │                              │      ├─ Unlock mutex
       │                              │      │
       │                              │      └─ Execute local_tasks
       │                              │            (outside mutex)
       │                              │
       ▼                              ▼
```

## Cross-Platform Support

**[include/common.h](include/common.h)** provides platform detection and common constants:
- **Linux**: Uses epoll API via EpollHandler (fully implemented and tested)
- **macOS**: Uses kqueue API via KqueueHandler (implemented, ready for testing)
- **Windows**: Header prepared for IOCP (not yet implemented)

**EventHandler abstraction** ([include/event_handler.h](include/event_handler.h)):
- Wraps platform-specific handlers (EpollHandler for Linux, KqueueHandler for macOS)
- Uses preprocessor directives (`#ifdef __linux__`, `#ifdef __APPLE__`) to select implementation
- Provides uniform interface across platforms
- Dispatcher and Channel interact only with EventHandler, not platform-specific handlers

**Platform-specific features**:
- **Linux**: eventfd for cross-thread wakeup, timerfd for connection timeouts
- **macOS**: kqueue handles both I/O events and timers (implementation in progress)

**Current Status**: Linux fully tested. macOS kqueue implementation added but requires testing. Windows IOCP planned.

## Callback Architecture

The server uses a layered callback system for separation of concerns. All callback types are centralized in [include/callbacks.h](include/callbacks.h) under the `CALLBACKS_NAMESPACE` namespace for improved type safety and organization.

**Layer 1: Channel-level callbacks** (internal, set by ConnectionHandler)
- Read callback → `ConnectionHandler::OnMessage()`
- Write callback → `ConnectionHandler::CallWriteCb()`
- Close callback → `ConnectionHandler::CallCloseCb()`
- Error callback → `ConnectionHandler::CallErroCb()`

**Layer 2: NetServer-level callbacks** (internal, handle connection management)
- `HandleNewConnection()`: Creates ConnectionHandler, adds to map
- `HandleCloseConnection()`: Removes from map, calls app callback
- `HandleErrorConnection()`: Removes from map on error
- `HandleSendComplete()`: Delegates to app callback
- `OnMessage()`: Delegates to app callback with buffered data

**Layer 3: Application-level callbacks** (set by user via ReactorServer or custom code)
- `new_conn_callback_`: Called when new connection established
- `close_conn_callback_`: Called before connection cleanup
- `error_callback_`: Called on connection error
- `on_message_callback_`: Process incoming messages from `input_bf_`
- `send_complete_callback_`: Called after output buffer fully sent

### Callback Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CALLBACK ARCHITECTURE                               │
│                    (3-Layer Callback Chain Pattern)                         │
└─────────────────────────────────────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════════════
 1. NEW CONNECTION FLOW
═══════════════════════════════════════════════════════════════════════════════

  ┌─────────────┐        ┌──────────────┐        ┌────────────────────┐
  │  Acceptor   │───────▶│  NetServer   │───────▶│  Application       │
  │  Channel    │        │              │        │  (ReactorServer)   │
  └─────────────┘        └──────────────┘        └────────────────────┘
       │                      │                         │
       │ EPOLLIN on           │                         │
       │ listen socket        │                         │
       │                      │                         │
       ▼                      ▼                         ▼
  NewConnection()     HandleNewConnection()      new_conn_callback_
       │                      │                         │
       │                      ├─ Create ConnectionHandler
       │                      ├─ Store in connections_
       │                      └─ Call app callback ────▶

═══════════════════════════════════════════════════════════════════════════════
 2. DATA READ FLOW (Client → Server)
═══════════════════════════════════════════════════════════════════════════════

  ┌─────────────┐        ┌──────────────┐        ┌────────────────────┐
  │   Channel   │───────▶│ Connection   │───────▶│  NetServer         │
  │             │        │  Handler     │        │                    │
  └─────────────┘        └──────────────┘        └────────────────────┘
       │                      │                         │
       │ EPOLLIN              │                         │
       │                      │                         │
       ▼                      ▼                         ▼
  HandleEvent()          OnMessage()             OnMessage()
       │                      │                         │
       │                      ├─ Read into input_bf_    │
       │                      │   until EAGAIN          │
       │                      │                         │
       │                      └─────────────────────────┼──▶ on_message_callback_
       │                                                │         │
       │                                                │         ▼
       │                                                │   Application
       │                                                │   processes data

═══════════════════════════════════════════════════════════════════════════════
 3. DATA WRITE FLOW (Server → Client)
═══════════════════════════════════════════════════════════════════════════════

  Application calls conn->SendData()
       │
       ▼
  ┌──────────────┐        ┌─────────────┐        ┌────────────────────┐
  │ Connection   │───────▶│   Channel   │───────▶│  ConnectionHandler │
  │  Handler     │        │             │        │                    │
  └──────────────┘        └─────────────┘        └────────────────────┘
       │                       │                        │
       │ SendData()            │                        │
       ├─ Append to            │                        │
       │  output_bf_           │                        │
       ├─ Enable EPOLLOUT      │                        │
       │                       │                        │
       │                       │ EPOLLOUT               │
       │                       ▼                        │
       │                 HandleEvent()                  │
       │                      │                         │
       │                      └─────────────────────────▶ CallWriteCb()
       │                                                       │
       │                                                       ├─ Send buffered data
       │                                                       ├─ Erase sent bytes
       │                                                       └─ When buffer empty:
       │                                                                │
  ┌────┴────────────┐                                                   │
  │   NetServer     │◀──────────────────────────────────────────────────┘
  │                 │
  └─────────────────┘
       │
       ▼
  HandleSendComplete()
       │
       └──────────▶ send_complete_callback_ (Application)

═══════════════════════════════════════════════════════════════════════════════
 4. CONNECTION CLOSE FLOW
═══════════════════════════════════════════════════════════════════════════════

  ┌─────────────┐        ┌──────────────┐        ┌────────────────────┐
  │   Channel   │───────▶│ Connection   │───────▶│  NetServer         │
  │             │        │  Handler     │        │                    │
  └─────────────┘        └──────────────┘        └────────────────────┘
       │                      │                         │
       │ EPOLLRDHUP/          │                         │
       │ EPOLLHUP/            │                         │
       │ read() == 0          │                         │
       │                      │                         │
       ▼                      ▼                         ▼
  HandleEvent()          CallCloseCb()           HandleCloseConnection()
       │                      │                         │
       │                      │                         ├─ Remove from connections_
       │                      │                         ├─ Call app callback
       │                      │                         │
       │                      │                         └──▶ close_conn_callback_
       │                      │                                   │
       │                      └─ CloseChannel()                   ▼
       │                         │                          Application
       │                         ├─ RemoveChannel()        cleanup
       │                         └─ close(fd)

═══════════════════════════════════════════════════════════════════════════════
 5. ERROR HANDLING FLOW
═══════════════════════════════════════════════════════════════════════════════

  ┌─────────────┐        ┌──────────────┐        ┌────────────────────┐
  │   Channel   │───────▶│ Connection   │───────▶│  NetServer         │
  │             │        │  Handler     │        │                    │
  └─────────────┘        └──────────────┘        └────────────────────┘
       │                      │                         │
       │ EPOLLERR             │                         │
       │                      │                         │
       ▼                      ▼                         ▼
  HandleEvent()          CallErrorCb()            HandleErrorConnection()
       │                      │                         │
       │                      │                         ├─ Remove from connections_
       │                      │                         ├─ Call app callback
       │                      │                         │
       │                      │                         └──▶ error_callback_
       │                      │                                   │
       │                      └─ CloseChannel()                  ▼
       │                                                    Application
       │                                                    error handling

```

### Key Design Pattern in Callback

1. Weak Pointer Callbacks (Two-Phase Initialization)                     
   - ConnectionHandler callbacks use `weak_ptr<ConnectionHandler>` capture 
   - Prevents circular references: Handler → Channel → Callback → Handler
   - `RegisterCallbacks()` called after shared_ptr wrapping                
   - Callbacks check `weak_ptr.lock()` before invoking (safe destruction)  
                                                                
2. Separation of Concerns                                                
   - Layer 1 (Channel): Low-level fd event dispatch                      
   - Layer 2 (NetServer): Connection lifecycle management                
   - Layer 3 (Application): Business logic and protocol implementation   
                                                                
3. Non-Blocking + Edge-Triggered
   - All callbacks must handle partial reads/writes (EAGAIN/EWOULDBLOCK)
   - Read loops continue until EAGAIN
   - Write buffers accumulate data until socket writable

### Callback Type Definitions

The [include/callbacks.h](include/callbacks.h) file provides organized callback types for each component:

**ConnectionHandler Callbacks**:
- `ConnOnMsgCallback` - Message received from client
- `ConnCompleteCallback` - Send operation completed
- `ConnCloseCallback` - Connection closed
- `ConnErrorCallback` - Error occurred on connection
- `ConnCallbacks` struct groups all ConnectionHandler callbacks

**NetServer Callbacks**:
- `NetSrvConnCallback` - New connection established
- `NetSrvCloseConnCallback` - Connection closed notification
- `NetSrvErrorCallback` - Connection error notification
- `NetSrvOnMsgCallback` - Process incoming messages
- `NetSrvSendCompleteCallback` - Send completion notification
- `NetSrvTimerCallback` - Timer event notification
- `NetSrvCallbacks` struct groups all NetServer callbacks

**Dispatcher Callbacks**:
- `DispatcherTOTriggerCallback` - Timeout trigger callback
- `DispatcherTimerCallback` - Timer handler callback
- `DispatcherCallbacks` struct groups all Dispatcher callbacks

**Channel Callbacks**:
- `ChannelReadCallback` - Read event occurred
- `ChannelWriteCallback` - Write ready
- `ChannelCloseCallback` - Channel closed
- `ChannelErrorCallback` - Channel error
- `ChannelCallbacks` struct groups all Channel callbacks                 

## Application Development

### Using ReactorServer (Recommended)

The `ReactorServer` class ([include/reactor_server.h](include/reactor_server.h), [server/reactor_server.cc](server/reactor_server.cc)) provides a template for building applications:

```cpp
class ReactorServer {
private:
    NetServer net_server_;
public:
    ReactorServer(const std::string& ip, const size_t port);

    void Start();  // Start event loop
    void Stop();   // Stop event loop

    // Override these methods to implement your protocol:
    void NewConnection(std::shared_ptr<ConnectionHandler> conn);
    void CloseConnection(std::shared_ptr<ConnectionHandler> conn);
    void Error(std::shared_ptr<ConnectionHandler> conn);
    void ProcessMessage(std::shared_ptr<ConnectionHandler> conn, std::string& message);
    void SendComplete(std::shared_ptr<ConnectionHandler> conn);
};
```

**Key points**:
- Constructor binds all callbacks to NetServer using `std::bind`
- Override virtual methods to implement custom protocol logic
- `ProcessMessage()` receives data from input buffer, call `conn->SendData()` to respond
- Data sent via `SendData()` is automatically buffered with 4-byte size header (length prefix protocol)
- Write operations are buffered and sent asynchronously when socket is writable

### Using NetServer Directly

For more control, instantiate NetServer and set callbacks manually:

```cpp
NetServer server("127.0.0.1", 8888);
server.SetOnMessageCb([](std::shared_ptr<ConnectionHandler> conn, std::string& msg) {
    // Process message and send response
    std::string response = process(msg);
    conn->SendData(response.data(), response.size());
});
server.Start();  // Blocks in event loop
```