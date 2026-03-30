#pragma once

#include <string>

namespace logging {

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
inline std::string ExtractDir(const std::string& path) {
    auto pos = path.rfind('/');
    if (pos != std::string::npos) return path.substr(0, pos);
    return "";
}

} // namespace logging
