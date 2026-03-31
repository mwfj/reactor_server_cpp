#include "socket_handler.h"
#include "log/logger.h"
#include "log/log_utils.h"


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
        logging::Get()->error("Failed to create socket");
        throw std::runtime_error("Invalid socket...");
    }
    SetNonBlocking(listenfd);
    return listenfd;
}

void SocketHandler::Bind(const InetAddr& _servAddr){
    if(::bind(fd_, _servAddr.Addr(), sizeof(sockaddr_in)) < 0){
        int saved_errno = errno;  // Save errno before any other calls
        Close();
        logging::Get()->error("Bind failed: {} (errno={})", logging::SafeStrerror(saved_errno), saved_errno);
        throw std::runtime_error(std::string("Error binding port: ") + logging::SafeStrerror(saved_errno));
    }
}

void SocketHandler::Listen(int _maxLen){
    if(::listen(fd_, _maxLen) != 0){
        Close();
        logging::Get()->error("Listen failed");
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
        int saved_errno = errno;
        // Don't close listening socket on accept error
        if(saved_errno == EAGAIN || saved_errno == EWOULDBLOCK) {
            return ACCEPT_QUEUE_DRAINED;
        }
        if(saved_errno == ECONNABORTED) {
            return ACCEPT_CONN_ABORTED;
        }
        if(saved_errno == EMFILE || saved_errno == ENFILE) {
            logging::Get()->error("Accept failed (fd exhaustion): {}", logging::SafeStrerror(saved_errno));
            return ACCEPT_FD_EXHAUSTION;
        }
        if(saved_errno == ENOBUFS || saved_errno == ENOMEM) {
            logging::Get()->error("Accept failed (memory pressure): {}", logging::SafeStrerror(saved_errno));
            return ACCEPT_MEMORY_PRESSURE;
        }
        logging::Get()->error("Accept failed: {}", logging::SafeStrerror(saved_errno));
        throw std::runtime_error(std::string("Error accepting connection: ") + logging::SafeStrerror(saved_errno));
    }
#if defined(__APPLE__) || defined(__MACH__)
    // Set non-blocking after successful accept on macOS.
    // On Linux, accept4(SOCK_NONBLOCK) handles this atomically.
    // Check fd validity after SetNonBlocking: if it silently returned
    // on EBADF (fd-reuse race), the fd is dead and must not be handed
    // to the reactor — later epoll/kqueue registration would operate
    // on an fd that may already belong to another connection.
    SetNonBlocking(clientfd);
    if (fcntl(clientfd, F_GETFL) == -1) {
        // fd is dead — treat as aborted connection, continue draining
        return ACCEPT_CONN_ABORTED;
    }
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
        int saved_errno = errno;
        // fd is likely already closed by peer (EBADF)
        // This is not an error - just a race condition we need to handle
        if (saved_errno == EBADF) {
            // File descriptor already closed - this is expected in rapid close scenarios
            // No need to log as it's a normal race condition, not an error
            return;
        }
        // Other errors are unexpected - log them
        logging::Get()->error("Unexpected error getting socket flags: {} (errno={})",
                              logging::SafeStrerror(saved_errno), saved_errno);
        throw std::runtime_error(std::string("Failed to get socket flags: ") + logging::SafeStrerror(saved_errno));
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        int saved_errno = errno;
        // Same logic - fd might have been closed between the two fcntl calls
        if (saved_errno == EBADF) {
            // File descriptor closed between F_GETFL and F_SETFL
            return;
        }
        logging::Get()->error("Unexpected error setting non-blocking mode: {} (errno={})",
                              logging::SafeStrerror(saved_errno), saved_errno);
        throw std::runtime_error(std::string("Failed to set non-blocking mode: ") + logging::SafeStrerror(saved_errno));
    }

    // macOS: suppress SIGPIPE per-socket since MSG_NOSIGNAL is not available
#ifdef SO_NOSIGPIPE
    int set = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &set, sizeof(set)) < 0) {
        int saved_errno = errno;
        logging::Get()->warn("Failed to set SO_NOSIGPIPE: {}", logging::SafeStrerror(saved_errno));
    }
#endif
}
