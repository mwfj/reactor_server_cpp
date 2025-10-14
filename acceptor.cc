#include "acceptor.h"
#include "channel.h"

// init server socket
Acceptor::Acceptor(std::shared_ptr<Dispatcher> _dispatcher, const std::string& _ip, const uint16_t _port):
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
    acceptor_channel_ -> EnableReadMode(acceptor_channel_); // let epoll_wait monitorting reading event
}

void Acceptor::SetNewConnCb(std::function<void(std::unique_ptr<SocketHandler>)> fn){
    new_conn_cb_ = fn;
}

// processing new connection from client
void Acceptor::NewConnection(){
    InetAddr client_addr;
    std::unique_ptr<SocketHandler> client_sock(new SocketHandler(servsock_ -> Accept(client_addr)));
    new_conn_cb_(std::move(client_sock));
}