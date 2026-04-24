#pragma once
#include "common.h"

// InetAddr — dual-family (IPv4 + IPv6) socket-address wrapper built on
// sockaddr_storage so a single object can flow through accept(),
// getsockname(), getpeername(), connect() without buffer truncation.
//
// Refactored from the original sockaddr_in-only shape per
// HOSTNAME_RESOLUTION_AND_IPV6_DESIGN.md §5.1. Per-connection memory
// grows by ~112 bytes (112 → 128 for sockaddr_storage), acceptable at
// 10k concurrent connections.
class InetAddr {
public:
    enum class Family { kUnknown, kIPv4, kIPv6 };

    InetAddr() = default;
    ~InetAddr() = default;

    // Literal constructor. Auto-detects family (tries inet_pton(AF_INET)
    // then inet_pton(AF_INET6)). Does NOT perform DNS — callers pass a
    // bare IP literal (no brackets for IPv6; the CLI and ConfigLoader
    // strip brackets before calling this ctor — see §5.5.1).
    //
    // On parse failure family_ == kUnknown and is_valid() returns false.
    // Callers must check is_valid() before passing the address to
    // bind()/connect().
    InetAddr(const std::string& ip_literal, int port);

    // Copy-in from a raw sockaddr (e.g., from accept(), getsockname(),
    // getaddrinfo()). Accepts AF_INET or AF_INET6; any other family
    // leaves the InetAddr in the kUnknown state.
    InetAddr(const sockaddr* sa, socklen_t sa_len);

    // Build from a single getaddrinfo result with an explicit port
    // override (getaddrinfo fills in `port` from the service/hint, but
    // callers typically resolve host-only and supply port separately).
    static InetAddr FromAddrInfo(const struct addrinfo* ai, int port);

    Family family() const { return family_; }
    bool is_valid() const { return family_ != Family::kUnknown; }

    // Returns the address in bare numeric form via inet_ntop. IPv4:
    // "127.0.0.1". IPv6: "2001:db8::1" (no brackets — callers that need
    // RFC 3986 authority form should route through
    // DnsResolver::FormatAuthority). Empty string on kUnknown.
    std::string Ip() const;

    // Host-byte-order port. Returns 0 on kUnknown.
    int Port() const;

    // Raw sockaddr pointer + length pair for passing to bind()/connect()/
    // accept()/getsockname(). Len() returns sizeof(sockaddr_in) for IPv4,
    // sizeof(sockaddr_in6) for IPv6, 0 for kUnknown — NEVER sizeof the
    // storage buffer, which would overflow the kernel's sa_len check on
    // BSD.
    const sockaddr* Addr() const;
    socklen_t Len() const { return len_; }

    // Copy-in from raw sockaddr after construction (e.g., overwriting an
    // Accept-receiver after accept() returns). Replaces the legacy
    // SetAddr(sockaddr_in) signature that the v0.1 design removed.
    void SetAddr(const sockaddr* sa, socklen_t sa_len);

    // In-place port mutator — writes sin_port on AF_INET, sin6_port on
    // AF_INET6. No-op on kUnknown (defensive: Start() never calls this
    // on an uninitialised InetAddr). `port` is in host byte order;
    // internal conversion via htons().
    //
    // Used by HttpServer::Start() after NetServer::StartListening()
    // succeeds to refresh bind_resolved_ with the kernel-assigned
    // ephemeral port — see §5.4a.
    void SetPort(uint16_t port);

    // Debug formatting. Returns "ip:port" for IPv4, "[ip]:port" for
    // IPv6, "<invalid>" for kUnknown. Matches the authority form per
    // RFC 3986 §3.2.2 so it is safe to embed in logs.
    std::string ToString() const;

private:
    sockaddr_storage addr_{};
    socklen_t        len_    = 0;
    Family           family_ = Family::kUnknown;
};
