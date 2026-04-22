#include "inet_addr.h"
#include <cstring>
#include <netdb.h>   // struct addrinfo — forward-declared in the header

// InetAddr — sockaddr_storage-backed implementation.
// Per HOSTNAME_RESOLUTION_AND_IPV6_DESIGN.md §5.1. Moved out of header
// to keep the public include lightweight and centralise the
// family-branching logic (inet_pton / inet_ntop / port field access) in
// one translation unit.

namespace {

// Overlay helpers — sockaddr_storage is large enough to hold either
// sockaddr_in or sockaddr_in6; use reinterpret_cast to access the
// family-specific field layout. Strict-aliasing is allowed here because
// sockaddr_storage is explicitly designed for this purpose (POSIX
// sys/socket.h documents the layout compatibility).
sockaddr_in* AsV4(sockaddr_storage* ss) {
    return reinterpret_cast<sockaddr_in*>(ss);
}
const sockaddr_in* AsV4(const sockaddr_storage* ss) {
    return reinterpret_cast<const sockaddr_in*>(ss);
}
sockaddr_in6* AsV6(sockaddr_storage* ss) {
    return reinterpret_cast<sockaddr_in6*>(ss);
}
const sockaddr_in6* AsV6(const sockaddr_storage* ss) {
    return reinterpret_cast<const sockaddr_in6*>(ss);
}

}  // namespace

InetAddr::InetAddr(const std::string& ip_literal, int port) {
    // Try IPv4 first — the common case and cheaper.
    sockaddr_in v4{};
    if (::inet_pton(AF_INET, ip_literal.c_str(), &v4.sin_addr) == 1) {
        v4.sin_family = AF_INET;
        v4.sin_port = htons(static_cast<uint16_t>(port));
        std::memcpy(&addr_, &v4, sizeof(v4));
        len_ = sizeof(v4);
        family_ = Family::kIPv4;
        return;
    }

    // Fall back to IPv6. Reject bracketed forms ("[::1]") — callers
    // (CLI / ConfigLoader::Normalize) must strip brackets before us.
    sockaddr_in6 v6{};
    if (::inet_pton(AF_INET6, ip_literal.c_str(), &v6.sin6_addr) == 1) {
        v6.sin6_family = AF_INET6;
        v6.sin6_port = htons(static_cast<uint16_t>(port));
        std::memcpy(&addr_, &v6, sizeof(v6));
        len_ = sizeof(v6);
        family_ = Family::kIPv6;
        return;
    }

    // Neither parse succeeded — leave the InetAddr in kUnknown state.
    // Callers detect via is_valid() and reject.
}

InetAddr::InetAddr(const sockaddr* sa, socklen_t sa_len) {
    SetAddr(sa, sa_len);
}

InetAddr InetAddr::FromAddrInfo(const struct addrinfo* ai, int port) {
    InetAddr out;
    if (ai == nullptr) return out;
    out.SetAddr(ai->ai_addr, ai->ai_addrlen);
    // getaddrinfo results often carry a port from the `service` hint,
    // but the project resolves host-only and applies port separately —
    // override whatever ai encodes with the caller-supplied value so
    // call sites do not need to know whether ai had a port.
    if (out.is_valid()) {
        out.SetPort(static_cast<uint16_t>(port));
    }
    return out;
}

std::string InetAddr::Ip() const {
    // Produce a HEADER-SAFE bare IP token — no RFC 4007 zone-id suffix
    // appended here. `Ip()` is read transitively by HeaderRewriter into
    // `X-Forwarded-For`; zone-qualified literals like `fe80::1%5` are
    // widely rejected by downstream XFF parsers, ACL engines, and log
    // pipelines. An earlier review-round fix tried to append `%scope_id`
    // to preserve link-local peer identity across interfaces, but that
    // regressed header correctness on exactly the traffic the fix
    // targeted (reviewer P2). The proper fix — separate peer-identity
    // API + `InetAddr`-carrying `SocketHandler` — is deferred out of
    // step-1 scope; link-local peer identity collapse on multi-interface
    // hosts is an acknowledged P3 gap that will be addressed in a later
    // phase alongside the observability work (§10 / §14).
    char buf[INET6_ADDRSTRLEN] = {0};
    if (family_ == Family::kIPv4) {
        if (::inet_ntop(AF_INET, &AsV4(&addr_)->sin_addr, buf,
                        sizeof(buf)) != nullptr) {
            return buf;
        }
    } else if (family_ == Family::kIPv6) {
        if (::inet_ntop(AF_INET6, &AsV6(&addr_)->sin6_addr, buf,
                        sizeof(buf)) != nullptr) {
            return buf;
        }
    }
    return {};
}

int InetAddr::Port() const {
    if (family_ == Family::kIPv4) return ntohs(AsV4(&addr_)->sin_port);
    if (family_ == Family::kIPv6) return ntohs(AsV6(&addr_)->sin6_port);
    return 0;
}

const sockaddr* InetAddr::Addr() const {
    return reinterpret_cast<const sockaddr*>(&addr_);
}

void InetAddr::SetAddr(const sockaddr* sa, socklen_t sa_len) {
    if (sa == nullptr || sa_len == 0) {
        addr_ = {};
        len_ = 0;
        family_ = Family::kUnknown;
        return;
    }
    if (sa->sa_family == AF_INET && sa_len >= socklen_t(sizeof(sockaddr_in))) {
        std::memcpy(&addr_, sa, sizeof(sockaddr_in));
        len_ = sizeof(sockaddr_in);
        family_ = Family::kIPv4;
    } else if (sa->sa_family == AF_INET6 &&
               sa_len >= socklen_t(sizeof(sockaddr_in6))) {
        std::memcpy(&addr_, sa, sizeof(sockaddr_in6));
        len_ = sizeof(sockaddr_in6);
        family_ = Family::kIPv6;
    } else {
        // Unknown family or truncated length — reject.
        addr_ = {};
        len_ = 0;
        family_ = Family::kUnknown;
    }
}

void InetAddr::SetPort(uint16_t port) {
    const uint16_t net_port = htons(port);
    if (family_ == Family::kIPv4) {
        AsV4(&addr_)->sin_port = net_port;
    } else if (family_ == Family::kIPv6) {
        AsV6(&addr_)->sin6_port = net_port;
    }
    // kUnknown: no-op (defensive — callers never reach here on a valid
    // flow; see §5.1 comment on SetPort).
}

std::string InetAddr::ToString() const {
    if (family_ == Family::kUnknown) return "<invalid>";
    const std::string ip = Ip();
    const std::string port_str = std::to_string(Port());
    if (family_ == Family::kIPv6) {
        return "[" + ip + "]:" + port_str;
    }
    return ip + ":" + port_str;
}
