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

    // Outbound connect result codes (used by ConnectionHandler::FinishConnect)
    static constexpr int CONNECT_SUCCESS     =  0;  // SO_ERROR == 0
    static constexpr int CONNECT_ERROR       = -1;  // SO_ERROR != 0 or getsockopt failure

private:
    int fd_;
    std::string ip_addr_;
    int port_;
    sa_family_t family_ = AF_UNSPEC;   // §5.3 dual-family — set by CreateSocket / accept-ctor
    static void SetNonBlocking(int fd);   // static per v0.45 step 4 — CreateSocket is static

public:
    SocketHandler();
    explicit SocketHandler(int);
    // v0.45 step 4: adopt an existing listen/client fd AND record the
    // address family the fd was created with. Used by Acceptor when it
    // creates the fd via CreateSocket(family) explicitly (so IPV6_V6ONLY
    // can be applied before Bind per §5.4).
    SocketHandler(int fd, sa_family_t family);
    SocketHandler(int fd, const std::string& ip, int port);
    ~SocketHandler();
    
    // Delete copy operations
    SocketHandler(const SocketHandler&) = delete;
    SocketHandler& operator=(const SocketHandler&) = delete;
    
    // Move operations
    SocketHandler(SocketHandler&& other) noexcept
        : fd_(other.fd_), ip_addr_(std::move(other.ip_addr_)),
          port_(other.port_), family_(other.family_) {
        other.fd_ = -1;
        other.port_ = 0;
        other.family_ = AF_UNSPEC;
    }
    SocketHandler& operator=(SocketHandler&& other) noexcept {
        if (this != &other) {
            Close();
            fd_ = other.fd_;
            ip_addr_ = std::move(other.ip_addr_);
            port_ = other.port_;
            family_ = other.family_;
            other.fd_ = -1;
            other.port_ = 0;
            other.family_ = AF_UNSPEC;
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
    
    // Dual-family per §5.3. `family` selects AF_INET or AF_INET6. The
    // AF_INET default preserves source compatibility for every existing
    // call site — IPv6 callers opt in explicitly.
    //
    // v0.45 step 4: STATIC. Returns a new fd; caller decides what to do
    // with it (wrap in SocketHandler(fd, family), or keep raw). Making
    // this static lets Acceptor create the fd before constructing a
    // SocketHandler, so IPV6_V6ONLY can be applied before Bind (§5.4).
    static int CreateSocket(sa_family_t family = AF_INET);
    static int CreateClientSocket(sa_family_t family = AF_INET);
    void Bind(const InetAddr& servAddr);
    void Listen(int maxLen);
    int Accept(InetAddr& clientAddr);
    void Close();

    // Address family the underlying socket was created with. AF_UNSPEC
    // if the fd was never set (moved-from, closed). Used by Acceptor to
    // know whether to apply IPV6_V6ONLY before Bind.
    sa_family_t family() const { return family_; }

    // Query the actual port bound by the OS (resolves ephemeral port 0).
    // Must be called after Bind(). Returns 0 if getsockname() fails.
    int GetBoundPort() const;
};
