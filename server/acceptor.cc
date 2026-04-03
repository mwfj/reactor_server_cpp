#include "acceptor.h"
#include "channel.h"
#include "log/logger.h"
#include "log/log_utils.h"

#include <fcntl.h>

// init server socket
Acceptor::Acceptor(std::shared_ptr<Dispatcher> _dispatcher, const std::string& _ip, const size_t _port):
    event_dispatcher_(_dispatcher),
    servsock_(new SocketHandler())
{
    InetAddr addr(_ip, _port);
    servsock_->SetReuseAddr(true);
    servsock_->SetTcpNoDelay(true);
    servsock_->SetReusePort(true);
    servsock_->SetKeepAlive(true);

    servsock_->Bind(addr);
    servsock_->Listen(MAX_CONNECTIONS);

    // Reserve one fd for the idle fd trick (EMFILE recovery).
    idle_fd_ = ::open("/dev/null", O_RDONLY | O_CLOEXEC);

    acceptor_channel_ = std::shared_ptr<Channel>(new Channel(event_dispatcher_, servsock_ -> fd()));
    acceptor_channel_ -> SetReadCallBackFn(std::bind(&Acceptor::NewConnection, this));
    // Register the acceptor channel synchronously — MUST NOT go through
    // EnableReadMode() → UpdateChannel() → EnQueue(). The constructor runs
    // before any event loop starts, so enqueued registration would only
    // execute later. If it fails silently, the ready callback fires but the
    // server can't accept connections. Direct registration surfaces any
    // kqueue/epoll error immediately (as a thrown exception from Bind/Listen
    // or a failed epoll_ctl), and the Acceptor constructor propagates it.
    acceptor_channel_->SetEvent(acceptor_channel_->Event() | EVENT_READ | EVENT_RDHUP);
    try {
        event_dispatcher_->UpdateChannelInLoop(acceptor_channel_);
    } catch (...) {
        // Constructor is aborting — destructor won't run, so clean up
        // the idle fd manually. Without this, repeated startup retries
        // under resource pressure leak one fd per attempt.
        if (idle_fd_ >= 0) { ::close(idle_fd_); idle_fd_ = -1; }
        throw;
    }
}

Acceptor::~Acceptor() {
    CloseListenSocket();
}

void Acceptor::CloseListenSocket() {
    int listen_fd = servsock_ ? servsock_->fd() : -1;
    logging::Get()->debug("Closing listen socket fd={}", listen_fd);
    if (acceptor_channel_ && !acceptor_channel_->is_channel_closed()) {
        acceptor_channel_->CloseChannel();
    }
    if (servsock_) {
        servsock_->ReleaseFd();
    }
    if (idle_fd_ >= 0) {
        ::close(idle_fd_);
        idle_fd_ = -1;
    }
}

void Acceptor::SetNewConnCb(std::function<void(std::unique_ptr<SocketHandler>)> fn){
    new_conn_cb_ = fn;
}

// processing new connection from client
void Acceptor::NewConnection(){
    // Accept ALL pending connections in a loop (continued below).

    // Accept ALL pending connections in a loop.
    // Edge-triggered epoll only notifies ONCE, so we must drain the entire
    // queue to EAGAIN. Returning before EAGAIN means no future EPOLLIN edge
    // fires even after resources recover — permanent accept starvation.
    // Guard: if the channel was closed by CloseListenSocket (shutdown),
    // don't accept. This prevents accepting new connections after Stop()
    // has started, even if the accept event and the close task are in the
    // same epoll batch and the accept fires first.
    if (!acceptor_channel_ || acceptor_channel_->is_channel_closed()
        || closing_.load(std::memory_order_acquire)) {
        logging::Get()->debug("Accept: listen socket closed/closing, skipping");
        return;
    }

    // Timed retry backoff: if an earlier ENOMEM set a retry deadline,
    // sleep for the remaining backoff then proceed. The sleep blocks the
    // conn_dispatcher briefly (~100ms max), which is acceptable:
    //   - The conn_dispatcher only handles accepts (no socket I/O)
    //   - ENOMEM is rare and transient
    //   - This avoids both busy-spin (EnQueue loop) and starvation
    //     (EnQueueDeferred under sustained traffic)
    // Shutdown tasks enqueued during the sleep run on the next HandleEventId.
    if (retry_due_at_ != std::chrono::steady_clock::time_point{}) {
        auto now = std::chrono::steady_clock::now();
        if (now < retry_due_at_) {
            std::this_thread::sleep_for(retry_due_at_ - now);
        }
        retry_due_at_ = {};
        // Re-check shutdown after sleep
        if (closing_.load(std::memory_order_acquire) ||
            event_dispatcher_->was_stopped()) {
            return;
        }
    }

    while(true){
        InetAddr client_addr;
        int client_fd = servsock_ -> Accept(client_addr);
        if(client_fd == SocketHandler::ACCEPT_QUEUE_DRAINED){
            return;
        }
        if(client_fd == SocketHandler::ACCEPT_CONN_ABORTED){
            continue;
        }
        if(client_fd == SocketHandler::ACCEPT_FD_EXHAUSTION){
            // FD exhaustion (EMFILE/ENFILE).
            // Use the "idle fd trick": close a reserved fd to make room for
            // one accept, immediately close the accepted connection (we can't
            // serve it), then re-open the reserved fd. This drains one pending
            // connection from the listen queue, preventing ET mode starvation
            // where the server permanently stops accepting after a transient
            // fd exhaustion event.
            logging::Get()->warn("Accept: fd exhaustion detected, using idle-fd trick");
            if (idle_fd_ >= 0) {
                ::close(idle_fd_);
                idle_fd_ = -1;
            }
            // Try to drain one connection with the freed fd slot
            InetAddr discard_addr;
            int discard_fd = servsock_->Accept(discard_addr);
            if (discard_fd >= 0) {
                ::close(discard_fd);  // Can't serve it — just drain the queue
            }
            // Re-reserve the fd for next time
            idle_fd_ = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
            // Continue loop to drain more or reach EAGAIN
            continue;
        }
        if(client_fd == SocketHandler::ACCEPT_MEMORY_PRESSURE){
            // Memory/buffer pressure (ENOBUFS/ENOMEM).
            // Set a timed retry with sleep-based backoff. On epoll ET mode,
            // EPOLL_CTL_MOD doesn't create a new edge when the socket is
            // already readable, so we can't just return and rely on
            // re-notification. Kqueue level-triggered would retry naturally,
            // but this approach works on both platforms.
            int saved_errno = errno;
            logging::Get()->warn("Accept: memory pressure ({}), retry in ~100ms",
                                 logging::SafeStrerror(saved_errno));
            static constexpr int ACCEPT_RETRY_MS = 100;
            retry_due_at_ = std::chrono::steady_clock::now() +
                            std::chrono::milliseconds(ACCEPT_RETRY_MS);
            event_dispatcher_->EnQueue([this]() {
                NewConnection();
            });
            return;
        }
        // Re-check shutdown inside the loop: under a queued backlog, the
        // pre-loop closing_ check passes but StopAccepting sets closing_=true
        // while we're draining. Without this, a burst of post-stop connections
        // is admitted until EAGAIN.
        if (closing_.load(std::memory_order_acquire)) {
            ::close(client_fd);
            return;
        }
        std::unique_ptr<SocketHandler> client_sock(new SocketHandler(client_fd, client_addr.Ip(), client_addr.Port()));
        new_conn_cb_(std::move(client_sock));
    }
}
