#include "connection_handler.h"


void ConnectionHandler::SetNonBlocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        throw std::runtime_error("Failed to get socket flags");
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        throw std::runtime_error("Failed to set non-blocking mode");
    }
}



void ConnectionHandler::Close() {
    if (fd_ != -1) {
        ::close(fd_);
        fd_ = -1;
    }
}

bool ConnectionHandler::SetTcpNoDelay(bool _flag){
    int optVal = _flag ? 1 : 0;
    return ::setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, &optVal, sizeof(optVal)) == 0;
}
bool ConnectionHandler::SetReuseAddr(bool _flag){
    int optVal = _flag ? 1 : 0;
    return ::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &optVal, sizeof(optVal)) == 0;
}
bool ConnectionHandler::SetReusePort(bool _flag){
    int optVal = _flag ? 1 : 0;
    return ::setsockopt(fd_, SOL_SOCKET, SO_REUSEPORT, &optVal, sizeof(optVal)) == 0;
}
bool ConnectionHandler::SetKeepAlive(bool _flag){
    int optVal = _flag ? 1 : 0;
    return ::setsockopt(fd_, SOL_SOCKET, SO_KEEPALIVE, &optVal, sizeof(optVal)) == 0;
}

int ConnectionHandler::CreateSocket() {
    int listenfd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenfd == -1) {
        throw std::runtime_error("Invalid socket...");
    }
    SetNonBlocking(listenfd);
    return listenfd;
}

void ConnectionHandler::Bind(const InetAddr& _servAddr){
    if(::bind(fd_, _servAddr.Addr(), sizeof(_servAddr)) < 0){
        Close();
        throw std::runtime_error("Error occurred when binding port ...");
    }
}

void ConnectionHandler::Listen(int _maxLen){
    if(::listen(fd_, _maxLen) != 0){
        Close();
        throw std::runtime_error("Error occurred when listening ...");
    }
}
int ConnectionHandler::Accept(InetAddr& _clientAddr){
    sockaddr_in acceptAddr;
    socklen_t len = sizeof(acceptAddr);
    int clientfd = accept4(fd_, reinterpret_cast<sockaddr*>(&acceptAddr), &len, SOCK_NONBLOCK);
    if(clientfd == -1){
        Close();
        throw std::runtime_error("Error occurred when accepting port ...");
        return -1;
    }else{
        _clientAddr.SetAddr(acceptAddr);
        return clientfd;
    }
}

void ConnectionHandler::Close(){
    if(fd_ != -1)
        ::close(fd_);
}

int ConnectionHandler::fd() const { return fd_; }