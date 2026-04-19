#include "auth/auth_url_util.h"

namespace AUTH_NAMESPACE {

ParsedHttpsUri ParseHttpsUri(const std::string& url) {
    ParsedHttpsUri out;
    std::string rest = url;

    if (rest.rfind("https://", 0) == 0) {
        rest = rest.substr(8);
    } else if (rest.rfind("http://", 0) == 0) {
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
