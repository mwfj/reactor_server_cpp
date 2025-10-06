// connection_handler.h
#pragma once
#include "common.h"
#include "inet_addr.h"

class ConnectionHandler {
private:
    int fd_;
    void SetNonBlocking(int fd);
    
public:
    ConnectionHandler::ConnectionHandler() : fd_(CreateSocket()) {}
    explicit ConnectionHandler::ConnectionHandler(int fd) : fd_(fd) {}
    ConnectionHandler::~ConnectionHandler() { Close(); }
    
    // Delete copy operations
    ConnectionHandler(const ConnectionHandler&) = delete;
    ConnectionHandler& operator=(const ConnectionHandler&) = delete;
    
    // Move operations
    ConnectionHandler::ConnectionHandler(ConnectionHandler&& other) noexcept 
        : fd_(other.fd_) {
        other.fd_ = -1;
    }
    ConnectionHandler& ConnectionHandler::operator=(ConnectionHandler&& other) noexcept {
        if (this != &other) {
            Close();
            fd_ = other.fd_;
            other.fd_ = -1;
        }
        return *this;
    }
    
    int fd() const { return fd_; }
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