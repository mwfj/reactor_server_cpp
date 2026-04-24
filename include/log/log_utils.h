#pragma once

#include <string>
#include <system_error>

namespace logging {

// Thread-safe errno-to-string. Uses std::system_category().message()
// which is guaranteed thread-safe by the C++ standard (since C++11)
// and works on all platforms (Linux glibc/musl, macOS, BSD).
inline std::string SafeStrerror(int errnum) {
    return std::system_category().message(errnum);
}

// Sanitize a URL path for logging: strip query string and fragment.
// "/api/users?token=abc123&page=1" -> "/api/users"
// "/api/users#section" -> "/api/users"
// "/api/users" -> "/api/users" (no change)
inline std::string SanitizePath(const std::string& path) {
    auto pos = path.find_first_of("?#");
    if (pos != std::string::npos) return path.substr(0, pos);
    return path;
}

// Sanitize a claim value or identity string for logging: strip CR, LF, and
// other ASCII control characters that could enable log injection attacks.
// Applies defense-in-depth to sub, issuer, kid, and policy_name fields that
// originate from JWT claims or operator config (both are attacker-reachable).
inline std::string SanitizeLogValue(const std::string& value) {
    std::string out;
    out.reserve(value.size());
    for (unsigned char c : value) {
        if (c < 0x20 || c == 0x7f) {
            // Replace control characters with a visible marker.
            out.push_back('?');
        } else {
            out.push_back(static_cast<char>(c));
        }
    }
    return out;
}

// Extract the directory component from a file path.
// "logs/reactor.log" -> "logs"
// "reactor.log" -> "" (empty = current directory)
// "/var/log/server.log" -> "/var/log"
// "/reactor.log" -> "/"
inline std::string ExtractDir(const std::string& path) {
    auto pos = path.rfind('/');
    if (pos == 0) return "/";
    if (pos != std::string::npos) return path.substr(0, pos);
    return "";
}

} // namespace logging
