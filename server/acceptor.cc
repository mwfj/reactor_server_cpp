#include "acceptor.h"
#include "channel.h"

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
    // Close the channel first (removes from epoll + closes fd),
    // then release fd from SocketHandler to prevent double-close.
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

void Acceptor::CloseListenSocket() {
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
    if (!acceptor_channel_ || acceptor_channel_->is_channel_closed()) return;

    while(true){
        InetAddr client_addr;
        int client_fd = servsock_ -> Accept(client_addr);
        if(client_fd == -1){
            // Queue drained (EAGAIN) — exit loop
            return;
        }
        if(client_fd == -2){
            // ECONNABORTED — one connection failed, keep draining queue
            continue;
        }
        if(client_fd == -3){
            // FD exhaustion (EMFILE/ENFILE).
            // Use the "idle fd trick": close a reserved fd to make room for
            // one accept, immediately close the accepted connection (we can't
            // serve it), then re-open the reserved fd. This drains one pending
            // connection from the listen queue, preventing ET mode starvation
            // where the server permanently stops accepting after a transient
            // fd exhaustion event.
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
        if(client_fd == -4){
            // Memory/buffer pressure (ENOBUFS/ENOMEM).
            // The idle fd trick doesn't help — closing fds frees fd slots, not memory.
            // Can't drain the queue (accept keeps failing), can't spin (starvation).
            // Re-arm the channel via EPOLL_CTL_MOD — on Linux this re-triggers the
            // edge if the fd is still ready, so the next epoll_wait cycle retries.
            // Without this, the listen socket stays readable but ET mode never
            // delivers another edge (no transition occurred).
            if (acceptor_channel_ && !acceptor_channel_->is_channel_closed()) {
                acceptor_channel_->EnableReadMode();
            }
            return;
        }
        std::unique_ptr<SocketHandler> client_sock(new SocketHandler(client_fd, client_addr.Ip(), client_addr.Port()));
        new_conn_cb_(std::move(client_sock));
    }
}
