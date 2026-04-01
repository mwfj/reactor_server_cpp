#pragma once
#include "common.h"
#include "inet_addr.h"

class SocketHandler {
public:
    // Accept() return codes for non-fd results
    static constexpr int ACCEPT_QUEUE_DRAINED   = -1;  // EAGAIN/EWOULDBLOCK
    static constexpr int ACCEPT_CONN_ABORTED    = -2;  // ECONNABORTED
    static constexpr int ACCEPT_FD_EXHAUSTION   = -3;  // EMFILE/ENFILE (recoverable via idle fd trick)
    static constexpr int ACCEPT_MEMORY_PRESSURE = -4;  // ENOBUFS/ENOMEM

private:
    int fd_;
    std::string ip_addr_;
    int port_;
    void SetNonBlocking(int fd);

public:
    SocketHandler();
    explicit SocketHandler(int);
    SocketHandler(int fd, const std::string& ip, int port);
    ~SocketHandler();
    
    // Delete copy operations
    SocketHandler(const SocketHandler&) = delete;
    SocketHandler& operator=(const SocketHandler&) = delete;
    
    // Move operations
    SocketHandler(SocketHandler&& other) noexcept
        : fd_(other.fd_), ip_addr_(std::move(other.ip_addr_)), port_(other.port_) {
        other.fd_ = -1;
        other.port_ = 0;
    }
    SocketHandler& operator=(SocketHandler&& other) noexcept {
        if (this != &other) {
            Close();
            fd_ = other.fd_;
            ip_addr_ = std::move(other.ip_addr_);
            port_ = other.port_;
            other.fd_ = -1;
            other.port_ = 0;
        }
        return *this;
    }

    int fd() const { return fd_; }
    const std::string& ip_addr() const {return ip_addr_;}
    int port() const {return port_;}
    

    // Release ownership of the fd without closing it (used when Channel takes over)
    void ReleaseFd() { fd_ = -1; }
    
    bool SetTcpNoDelay(bool);
    bool SetReuseAddr(bool);
    bool SetReusePort(bool);
    bool SetKeepAlive(bool);
    
    int CreateSocket();
    void Bind(const InetAddr& servAddr);
    void Listen(int maxLen);
    int Accept(InetAddr& clientAddr);
    void Close();

    // Query the actual port bound by the OS (resolves ephemeral port 0).
    // Must be called after Bind(). Returns 0 if getsockname() fails.
    int GetBoundPort() const;
};
