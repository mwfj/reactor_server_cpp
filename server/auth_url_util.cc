#include "auth/auth_url_util.h"
#include <cctype>

namespace AUTH_NAMESPACE {

namespace {
// Case-insensitive "starts with prefix" check. Only ASCII semantics —
// URI schemes are ASCII per RFC 3986 §3.1.
bool StartsWithCaseInsensitive(const std::string& s, const char* prefix) {
    size_t i = 0;
    while (prefix[i] != '\0') {
        if (i >= s.size()) return false;
        char a = static_cast<char>(std::tolower(
            static_cast<unsigned char>(s[i])));
        char b = static_cast<char>(std::tolower(
            static_cast<unsigned char>(prefix[i])));
        if (a != b) return false;
        ++i;
    }
    return true;
}
}  // namespace

bool HasHttpsScheme(const std::string& url) noexcept {
    return StartsWithCaseInsensitive(url, "https://");
}

ParsedHttpsUri ParseHttpsUri(const std::string& url) {
    ParsedHttpsUri out;
    std::string rest = url;

    if (StartsWithCaseInsensitive(rest, "https://")) {
        rest = rest.substr(8);
    } else if (StartsWithCaseInsensitive(rest, "http://")) {
        rest = rest.substr(7);
    } else if (!rest.empty() && rest.front() == '/') {
        // Already a bare path — return as-is.
        out.path_with_query = rest;
        return out;
    }

    // Split on first '/': everything before is host[:port]; from '/' onward
    // is the path (including query string).
    auto slash = rest.find('/');
    if (slash == std::string::npos) {
        out.host = rest;
        out.path_with_query = "/";
    } else {
        out.host = rest.substr(0, slash);
        out.path_with_query = rest.substr(slash);
        if (out.path_with_query.empty()) out.path_with_query = "/";
    }
    return out;
}

}  // namespace AUTH_NAMESPACE
