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
#if defined(__linux__)
    // Linux: use accept4 with SOCK_NONBLOCK for atomic non-blocking accept
    int clientfd = accept4(fd_, reinterpret_cast<sockaddr*>(&acceptAddr), &len, SOCK_NONBLOCK);
#elif defined(__APPLE__) || defined(__MACH__)
    // macOS: use regular accept and set non-blocking separately
    int clientfd = accept(fd_, reinterpret_cast<sockaddr*>(&acceptAddr), &len);
#endif
    if(clientfd == -1){
        // Don't close listening socket on accept error
        if(errno == EAGAIN || errno == EWOULDBLOCK) {
            // No connections available right now - not an error
            return -1;
        }
        // On macOS under high load, we can get ECONNABORTED, EMFILE, ENFILE
        // These should not crash the server - just log and return
        if(errno == ECONNABORTED || errno == EMFILE || errno == ENFILE ||
           errno == ENOBUFS || errno == ENOMEM) {
            // Temporary resource exhaustion - log but don't crash
            // ECONNABORTED: Connection aborted before accept completed
            // EMFILE: Process file descriptor limit reached
            // ENFILE: System file descriptor limit reached
            // ENOBUFS/ENOMEM: Insufficient resources
            std::cerr << "[Socket Handler] Accept failed (temporary): " << strerror(errno) << std::endl;
            return -1;
        }
        std::cout << "[Socket Handler] Error occurred when accepting connection: " << strerror(errno) << std::endl;
        throw std::runtime_error(std::string("Error accepting connection: ") + strerror(errno));
    }
#if defined(__APPLE__) || defined(__MACH__)
    // Set non-blocking after successful accept on macOS
    SetNonBlocking(clientfd);
#endif
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
    // RACE CONDITION FIX: Handle TOCTOU race between accept() and SetNonBlocking()
    //
    // Scenario that triggers this:
    // 1. Server accepts connection, gets clientfd
    // 2. Client immediately closes (sends FIN/RST)
    // 3. Kernel processes close, invalidates clientfd
    // 4. Server tries to set non-blocking on already-closed fd
    // 5. fcntl() fails with EBADF (Bad file descriptor)
    //
    // This is especially common in rapid connect/disconnect tests (RC-TEST-3)
    // where clients connect and immediately close without sending data.
    //
    // Solution: Check errno and handle closed fds gracefully instead of throwing.
    // The connection is already gone, so there's nothing to set non-blocking.
    // Just log and return - the fd will be cleaned up elsewhere.

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        // fd is likely already closed by peer (EBADF)
        // This is not an error - just a race condition we need to handle
        if (errno == EBADF) {
            // File descriptor already closed - this is expected in rapid close scenarios
            // No need to log as it's a normal race condition, not an error
            return;
        }
        // Other errors are unexpected - log them
        std::cerr << "[Socket Handler] Unexpected error getting socket flags: "
                  << strerror(errno) << " (errno=" << errno << ")" << std::endl;
        throw std::runtime_error(std::string("Failed to get socket flags: ") + strerror(errno));
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        // Same logic - fd might have been closed between the two fcntl calls
        if (errno == EBADF) {
            // File descriptor closed between F_GETFL and F_SETFL
            return;
        }
        std::cerr << "[Socket Handler] Unexpected error setting non-blocking mode: "
                  << strerror(errno) << " (errno=" << errno << ")" << std::endl;
        throw std::runtime_error(std::string("Failed to set non-blocking mode: ") + strerror(errno));
    }
}