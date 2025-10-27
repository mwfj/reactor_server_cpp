#include "socket_handler.h"


SocketHandler::SocketHandler() : fd_(CreateSocket()), port_(0) {}
SocketHandler::SocketHandler(int fd) : fd_(fd), port_(0) {}
SocketHandler::SocketHandler(int fd, const std::string& ip, int port) : fd_(fd), ip_addr_(ip), port_(port) {}
SocketHandler::~SocketHandler() { Close(); }

bool SocketHandler::SetTcpNoDelay(bool _flag){
    int optVal = _flag ? 1 : 0;
    return ::setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, &optVal, sizeof(optVal)) == 0;
}
bool SocketHandler::SetReuseAddr(bool _flag){
    int optVal = _flag ? 1 : 0;
    return ::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &optVal, sizeof(optVal)) == 0;
}
bool SocketHandler::SetReusePort(bool _flag){
    int optVal = _flag ? 1 : 0;
    return ::setsockopt(fd_, SOL_SOCKET, SO_REUSEPORT, &optVal, sizeof(optVal)) == 0;
}
bool SocketHandler::SetKeepAlive(bool _flag){
    int optVal = _flag ? 1 : 0;
    return ::setsockopt(fd_, SOL_SOCKET, SO_KEEPALIVE, &optVal, sizeof(optVal)) == 0;
}

int SocketHandler::CreateSocket() {
    int listenfd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenfd == -1) {
        std::cout << "[Socket Handler] Invalid socket..." << std::endl;
        throw std::runtime_error("Invalid socket...");
    }
    SetNonBlocking(listenfd);
    return listenfd;
}

void SocketHandler::Bind(const InetAddr& _servAddr){
    if(::bind(fd_, _servAddr.Addr(), sizeof(sockaddr_in)) < 0){
        int saved_errno = errno;  // Save errno before any other calls
        Close();
        std::cout << "[Socket Handler] Error occurred when binding port: "
                  << strerror(saved_errno) << " (errno=" << saved_errno << ")" << std::endl;
        throw std::runtime_error(std::string("Error binding port: ") + strerror(saved_errno));
    }
}

void SocketHandler::Listen(int _maxLen){
    if(::listen(fd_, _maxLen) != 0){
        Close();
        std::cout << "[Socket Handler] Error occurred when listening ..." << std::endl;
        throw std::runtime_error("Error occurred when listening ...");
    }
}
int SocketHandler::Accept(InetAddr& _clientAddr){
    sockaddr_in acceptAddr;
    socklen_t len = sizeof(acceptAddr);
    int clientfd = accept4(fd_, reinterpret_cast<sockaddr*>(&acceptAddr), &len, SOCK_NONBLOCK);
    if(clientfd == -1){
        // Don't close listening socket on accept error
        if(errno == EAGAIN || errno == EWOULDBLOCK) {
            // No connections available right now - not an error
            return -1;
        }
        std::cout << "[Socket Handler] Error occurred when accepting connection" << std::endl;
        throw std::runtime_error("Error occurred when accepting connection");
    }
    _clientAddr.SetAddr(acceptAddr);
    return clientfd;
}

void SocketHandler::Close() {
    if (fd_ != -1) {
        ::close(fd_);
        fd_ = -1;
    }
}

void SocketHandler::SetNonBlocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        std::cout << "[Socket Handler] Failed to get socket flags" << std::endl;
        throw std::runtime_error("Failed to get socket flags");
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        std::cout << "[Socket Handler] Failed to set non-blocking mode" << std::endl;
        throw std::runtime_error("Failed to set non-blocking mode");
    }
}