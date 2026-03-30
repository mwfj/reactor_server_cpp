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
