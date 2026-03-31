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
    acceptor_channel_ -> EnableReadMode(); // let epoll_wait monitorting reading event
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
    // Accept ALL pending connections in a loop.
    // Edge-triggered epoll only notifies ONCE, so we must drain the entire
    // queue to EAGAIN. Returning before EAGAIN means no future EPOLLIN edge
    // fires even after resources recover — permanent accept starvation.
    // Guard: if the channel was closed by CloseListenSocket (shutdown),
    // don't accept. This prevents accepting new connections after Stop()
    // has started, even if the accept event and the close task are in the
    // same epoll batch and the accept fires first.
    if (!acceptor_channel_ || acceptor_channel_->is_channel_closed()) {
        logging::Get()->debug("Accept: listen socket closed, skipping");
        return;
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
            // Memory/buffer pressure (ENOBUFS/ENOMEM). Schedule a deferred
            // retry via EnQueue — returning without draining the backlog in
            // ET mode would leave accept stuck (no new edge to wake epoll).
            // EnQueue lets the event loop process pending closes/frees first,
            // then retries accept. No sleep — non-blocking event loop.
            int saved_errno = errno;
            logging::Get()->warn("Accept: memory pressure ({}), scheduling retry",
                                 logging::SafeStrerror(saved_errno));
            event_dispatcher_->EnQueue([this]() {
                NewConnection();
            });
            return;
        }
        std::unique_ptr<SocketHandler> client_sock(new SocketHandler(client_fd, client_addr.Ip(), client_addr.Port()));
        new_conn_cb_(std::move(client_sock));
    }
}
