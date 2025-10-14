#include "server.h"


ReactorServer::ReactorServer(const std::string& _ip, const uint16_t _port)
    : event_dispatcher_(std::shared_ptr<Dispatcher>(new Dispatcher())),
      acceptor_(new Acceptor(event_dispatcher_, _ip, _port))
{
    acceptor_->SetNewConnCb(std::bind(&ReactorServer::NewConnction, this, std::placeholders::_1));
}

ReactorServer::~ReactorServer(){
    connections_.clear();
}

// start event loop
void ReactorServer::Start(){
    event_dispatcher_->RunEventLoop();
}

// stop event loop
void ReactorServer::Stop(){
    event_dispatcher_->StopEventLoop();
}

void ReactorServer::NewConnction(std::unique_ptr<SocketHandler> cilent_sock){
    std::shared_ptr<ConnectionHandler> conn = std::shared_ptr<ConnectionHandler>(new ConnectionHandler(event_dispatcher_, std::move(cilent_sock)));
    conn ->SetCloseCb(std::bind(&ReactorServer::CloseConnection, this, std::placeholders::_1));
    conn ->SetErrorCb(std::bind(&ReactorServer::ErrorConnection, this, std::placeholders::_1));

    std::cout << "[Reactor Server] new connection(fd: " 
        << conn -> fd() << ", ip: " << conn->ip_addr() << ", port: " << conn -> port() << ").\n"
        << "ok" << std::endl;
    connections_[conn -> fd()] = conn;
}

void ReactorServer::CloseConnection(std::shared_ptr<ConnectionHandler> conn){
    std::cout << "client fd: " << conn -> fd() << "disconnected." << std::endl;
    connections_.erase(conn -> fd());
    // close this connection
    conn.reset();
}

void ReactorServer::ErrorConnection(std::shared_ptr<ConnectionHandler> conn){
    std::cout << "client fd: " << conn -> fd() << "error occurred, disconnect." << std::endl;
    connections_.erase(conn -> fd());
    conn.reset();
}