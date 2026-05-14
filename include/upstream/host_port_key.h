#pragma once

#include <cstddef>
#include <functional>
#include <string>

// User-defined key for the H2 connecting-conns stash and replacement-
// connect dedup set. A struct (not a `std::pair` alias) is required so
// that specializing `std::hash<HostPortKey>` below depends on a user-
// defined type — specializing `std::hash` for library types like
// `std::pair` would be undefined behavior per [namespace.std].
struct HostPortKey {
    std::string host;
    int port;

    bool operator==(const HostPortKey& other) const noexcept {
        return port == other.port && host == other.host;
    }
    bool operator!=(const HostPortKey& other) const noexcept {
        return !(*this == other);
    }
};

namespace std {
template <>
struct hash<HostPortKey> {
    size_t operator()(const HostPortKey& k) const noexcept {
        size_t h1 = std::hash<std::string>{}(k.host);
        size_t h2 = std::hash<int>{}(k.port);
        // boost::hash_combine mixing pattern, widened to 64 bits via
        // the floor(2^64 / phi) constant — same shape as
        // boost::hash_combine_impl<64>, just inlined here so we don't
        // pull boost in.
        return h1 ^ (h2 + 0x9e3779b97f4a7c15ULL + (h1 << 6) + (h1 >> 2));
    }
};
}  // namespace std
