#include "net_server.h"


NetServer::NetServer(const std::string& _ip, const size_t _port)
    : event_dispatcher_(std::shared_ptr<Dispatcher>(new Dispatcher())),
      acceptor_(new Acceptor(event_dispatcher_, _ip, _port))
{
    acceptor_->SetNewConnCb(std::bind(&NetServer::HandleNewConnection, this, std::placeholders::_1));
}

NetServer::~NetServer(){
    connections_.clear();
}

// start event loop
void NetServer::Start(){
    event_dispatcher_->RunEventLoop();
}

// stop event loop
void NetServer::Stop(){
    event_dispatcher_->StopEventLoop();
}

void NetServer::HandleNewConnection(std::unique_ptr<SocketHandler> cilent_sock){
    std::shared_ptr<ConnectionHandler> conn = std::shared_ptr<ConnectionHandler>(new ConnectionHandler(event_dispatcher_, std::move(cilent_sock)));
    conn -> SetCloseCb(std::bind(&NetServer::HandleCloseConnection, this, std::placeholders::_1));
    conn -> SetErrorCb(std::bind(&NetServer::HandleErrorConnection, this, std::placeholders::_1));
    conn -> SetOnMessageCb(std::bind(&NetServer::OnMessage, this, std::placeholders::_1, std::placeholders::_2));
    conn -> SetCompletionCb(std::bind(&NetServer::HandleSendComplete, this, std::placeholders::_1));

    connections_[conn -> fd()] = conn;

    std::cout << "[Reactor Server] new connection(fd: " 
        << conn -> fd() << ", ip: " << conn -> ip_addr() << ", port: " << conn -> port() << ").\n"
        << "ok" << std::endl;

    if(new_conn_callback_)
        new_conn_callback_(conn);
}

void NetServer::HandleCloseConnection(std::shared_ptr<ConnectionHandler> conn){
    if(close_conn_callback_)
        close_conn_callback_(conn);

    std::cout << "[NetServer] client fd: " << conn -> fd() << " disconnected." << std::endl;
    connections_.erase(conn -> fd());
    // close this connection
    conn.reset();
}

void NetServer::HandleErrorConnection(std::shared_ptr<ConnectionHandler> conn){
    if(error_callback_)
        error_callback_(conn);
        
    std::cout << "[NetServer] client fd: " << conn -> fd() << "error occurred, disconnect." << std::endl;
    connections_.erase(conn -> fd());
    conn.reset();
}

void NetServer::OnMessage(std::shared_ptr<ConnectionHandler> conn, std::string& message){
    if(on_message_callback_)
        on_message_callback_(conn, message);
}

void NetServer::HandleSendComplete(std::shared_ptr<ConnectionHandler> conn){
    if(send_complete_callback_)
        send_complete_callback_(conn);
}

void NetServer::SetNewConnectionCb(std::function<void(std::shared_ptr<ConnectionHandler>)> fn){
    if(fn)
        new_conn_callback_ = fn;
}

void NetServer::SetCloseConnectionCb(std::function<void(std::shared_ptr<ConnectionHandler>)> fn){
    if(fn)
        close_conn_callback_ = fn;
}

void NetServer::SetErrorCb(std::function<void(std::shared_ptr<ConnectionHandler>)> fn){
    if(fn)
        error_callback_ = fn;
}

void NetServer::SetOnMessageCb(std::function<void(std::shared_ptr<ConnectionHandler>, std::string&)> fn){
    if(fn)
        on_message_callback_ = fn;
}

void NetServer::SetSendCompletionCb(std::function<void(std::shared_ptr<ConnectionHandler>)> fn){
    if(fn)
        send_complete_callback_ = fn;
}