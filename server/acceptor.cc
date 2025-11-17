#include "acceptor.h"
#include "channel.h"

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

    acceptor_channel_ = std::shared_ptr<Channel>(new Channel(event_dispatcher_, servsock_ -> fd()));
    acceptor_channel_ -> SetReadCallBackFn(std::bind(&Acceptor::NewConnection, this));
    acceptor_channel_ -> EnableReadMode(); // let epoll_wait monitorting reading event
}

void Acceptor::SetNewConnCb(std::function<void(std::unique_ptr<SocketHandler>)> fn){
    new_conn_cb_ = fn;
}

// processing new connection from client
void Acceptor::NewConnection(){
    // CRITICAL FIX: Accept ALL pending connections in a loop
    // When multiple clients connect simultaneously, they queue in the listen socket's backlog.
    // Edge-triggered epoll only notifies ONCE, so we must drain the entire queue.
    // Without this loop, only the first connection is accepted, and the rest timeout.
    //
    // Why this bug occurred:
    // - 10 concurrent clients connect nearly simultaneously
    // - All get queued in the listen socket
    // - epoll triggers EPOLLIN once (edge-triggered)
    // - Old code accepted only 1 connection and returned
    // - Remaining 9 connections stayed in queue, never processed
    // - Those clients timeout waiting for server response
    //
    // The fix: Loop until Accept() returns -1 (EAGAIN/EWOULDBLOCK)
    while(true){
        InetAddr client_addr;
        int client_fd = servsock_ -> Accept(client_addr);
        if(client_fd == -1){
            // No more connections available (EAGAIN in non-blocking mode)
            return;
        }
        std::unique_ptr<SocketHandler> client_sock(new SocketHandler(client_fd, client_addr.Ip(), client_addr.Port()));
        new_conn_cb_(std::move(client_sock));
    }
}