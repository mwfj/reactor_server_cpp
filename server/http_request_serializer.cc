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

    if (!body.empty()) {
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
