#include "upstream/http_request_serializer.h"

std::string HttpRequestSerializer::Serialize(
    const std::string& method,
    const std::string& path,
    const std::string& query,
    const std::map<std::string, std::string>& headers,
    const std::string& body) {

    std::string result;
    result.reserve(INITIAL_BUFFER_RESERVE + body.size());

    result += method;
    result += ' ';
    result += path.empty() ? "/" : path;
    if (!query.empty()) {
        result += '?';
        result += query;
    }
    result += " HTTP/1.1\r\n";

    for (const auto& pair : headers) {
        if (pair.first == "content-length") {
            continue;
        }
        result += pair.first;
        result += ": ";
        result += pair.second;
        result += "\r\n";
    }

    // Content-Length framing (RFC 7230 §3.3.2):
    //
    //  1. When the body is NON-EMPTY, emit Content-Length regardless of
    //     method. Without it, a keep-alive upstream has no framing for
    //     the body and will either wait for EOF or misparse the body as
    //     the next request. This is critical for forwarded DELETE,
    //     OPTIONS, TRACE, or backend-specific GET-with-body requests.
    //
    //  2. When the body is EMPTY and the method has "enclosed payload"
    //     semantics (POST/PUT/PATCH), emit Content-Length: 0. Some
    //     strict upstream servers reject or hang on bodyless
    //     POST/PUT/PATCH requests without an explicit CL: 0.
    //
    //  3. Otherwise (empty body on GET/HEAD/DELETE/OPTIONS/TRACE), omit
    //     Content-Length entirely — some strict servers and WAFs reject
    //     CL: 0 on methods that don't expect a body.
    const bool has_body = !body.empty();
    const bool method_expects_body = (method == "POST" ||
                                       method == "PUT"  ||
                                       method == "PATCH");
    if (has_body || method_expects_body) {
        result += "Content-Length: ";
        result += std::to_string(body.size());
        result += "\r\n";
    }

    result += "\r\n";

    if (!body.empty()) {
        result += body;
    }

    return result;
}
