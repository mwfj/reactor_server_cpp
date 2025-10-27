#pragma once
#include "common.h"
#include "inet_addr.h"

class SocketHandler {
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

    bool SetTcpNoDelay(bool);
    bool SetReuseAddr(bool);
    bool SetReusePort(bool);
    bool SetKeepAlive(bool);
    
    int CreateSocket();
    void Bind(const InetAddr& servAddr);
    void Listen(int maxLen);
    int Accept(InetAddr& clientAddr);
    void Close();
};