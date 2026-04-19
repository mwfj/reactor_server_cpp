#include "auth/auth_error_responses.h"

#include "http/http_status.h"
#include "log/logger.h"

namespace AUTH_NAMESPACE {

namespace {

// Replace characters that would break the quoted-string form of
// WWW-Authenticate. Operators rarely trigger this (our error_description
// strings are compile-time constants or log labels), but the escape is
// cheap and defense-in-depth against future authored descriptions.
std::string EscapeQuotedString(const std::string& in) {
    std::string out;
    out.reserve(in.size() + 2);
    for (char c : in) {
        if (c == '"' || c == '\\') out.push_back('\\');
        // Strip control chars defensively.
        if (static_cast<unsigned char>(c) < 0x20) continue;
        out.push_back(c);
    }
    return out;
}

}  // namespace

std::string BuildWwwAuthenticate(const std::string& realm,
                                  const std::string& error_code,
                                  const std::string& error_description,
                                  const std::string& scope) {
    std::string out = "Bearer realm=\"";
    out += EscapeQuotedString(realm.empty() ? std::string("api") : realm);
    out += '"';
    if (!error_code.empty()) {
        out += ", error=\"";
        out += EscapeQuotedString(error_code);
        out += '"';
    }
    if (!error_description.empty()) {
        out += ", error_description=\"";
        out += EscapeQuotedString(error_description);
        out += '"';
    }
    if (!scope.empty()) {
        out += ", scope=\"";
        out += EscapeQuotedString(scope);
        out += '"';
    }
    return out;
}

HttpResponse MakeUnauthorized(const std::string& realm,
                               AuthErrorCode error_code,
                               const std::string& error_description) {
    HttpResponse r;
    r.Status(HttpStatus::UNAUTHORIZED)
     .Header("WWW-Authenticate",
             BuildWwwAuthenticate(realm,
                                   AuthErrorCodeAsString(error_code),
                                   error_description, /*scope=*/""))
     .Header("Cache-Control", "no-store")
     .Header("Pragma", "no-cache")
     .Text("Unauthorized");
    return r;
}

HttpResponse MakeForbidden(const std::string& realm,
                            const std::string& error_description,
                            const std::vector<std::string>& required_scopes) {
    std::string scope_joined;
    for (const auto& s : required_scopes) {
        if (!scope_joined.empty()) scope_joined.push_back(' ');
        scope_joined += s;
    }
    HttpResponse r;
    r.Status(HttpStatus::FORBIDDEN)
     .Header("WWW-Authenticate",
             BuildWwwAuthenticate(realm,
                                   AuthErrorCodeAsString(
                                       AuthErrorCode::InsufficientScope),
                                   error_description, scope_joined))
     .Header("Cache-Control", "no-store")
     .Header("Pragma", "no-cache")
     .Text("Forbidden");
    return r;
}

HttpResponse MakeServiceUnavailable(const std::string& /*realm*/,
                                     int retry_after_sec,
                                     const std::string& /*error_description*/) {
    // RFC 6750 recommends Retry-After floor 1s; upper bound prevents misconfig.
    if (retry_after_sec < 1) retry_after_sec = 1;
    if (retry_after_sec > 300) retry_after_sec = 300;
    // RFC 7235 §3.1 mandates WWW-Authenticate only on 401 responses.
    // A 503 signals a temporary infrastructure problem, not an auth challenge;
    // emitting WWW-Authenticate on 503 is non-standard and can confuse clients
    // that treat its presence as a hard 401-class error. Retry-After is
    // sufficient to communicate the transient nature of the failure.
    HttpResponse r;
    r.Status(HttpStatus::SERVICE_UNAVAILABLE)
     .Header("Retry-After", std::to_string(retry_after_sec))
     .Header("Cache-Control", "no-store")
     .Header("Pragma", "no-cache")
     .Text("Service Unavailable");
    return r;
}

}  // namespace AUTH_NAMESPACE
