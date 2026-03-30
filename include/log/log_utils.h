#pragma once

#include <string>
#include <cstring>

namespace logging {

// Thread-safe errno-to-string using the XSI-compliant strerror_r.
// Returns the error message for the given errno value without
// sharing a static buffer across threads.
inline std::string SafeStrerror(int errnum) {
    char buf[256];
#if (_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && !_GNU_SOURCE
    // XSI-compliant: returns int, writes to buf
    if (strerror_r(errnum, buf, sizeof(buf)) == 0) return std::string(buf);
    return "errno " + std::to_string(errnum);
#elif defined(__APPLE__) || defined(__FreeBSD__)
    // macOS/BSD: XSI-compliant strerror_r
    if (strerror_r(errnum, buf, sizeof(buf)) == 0) return std::string(buf);
    return "errno " + std::to_string(errnum);
#else
    // GNU strerror_r: returns char* (may or may not use buf)
    const char* msg = strerror_r(errnum, buf, sizeof(buf));
    return std::string(msg ? msg : buf);
#endif
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
