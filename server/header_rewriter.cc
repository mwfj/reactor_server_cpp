#include "upstream/header_rewriter.h"
#include "log/logger.h"
#include <unordered_set>

HeaderRewriter::HeaderRewriter(const Config& config)
    : config_(config)
{
}

bool HeaderRewriter::IsHopByHopHeader(const std::string& name) {
    // RFC 7230 Section 6.1: hop-by-hop headers.
    // "proxy-connection" is non-standard (legacy from old proxy implementations)
    // but included defensively — it should never be forwarded end-to-end.
    return name == "connection"
        || name == "keep-alive"
        || name == "proxy-connection"
        || name == "transfer-encoding"
        || name == "te"
        || name == "trailer"
        || name == "upgrade";
}

std::vector<std::string> HeaderRewriter::ParseConnectionHeader(
    const std::string& value) {
    std::vector<std::string> tokens;
    size_t start = 0;
    while (start < value.size()) {
        // Skip leading whitespace
        while (start < value.size() && value[start] == ' ') {
            ++start;
        }
        if (start >= value.size()) {
            break;
        }

        // Find next comma
        size_t comma = value.find(',', start);
        size_t end = (comma != std::string::npos) ? comma : value.size();

        // Trim trailing whitespace
        size_t token_end = end;
        while (token_end > start && value[token_end - 1] == ' ') {
            --token_end;
        }

        if (token_end > start) {
            std::string token = value.substr(start, token_end - start);
            // Lowercase the token
            std::transform(token.begin(), token.end(), token.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            tokens.push_back(std::move(token));
        }

        start = (comma != std::string::npos) ? comma + 1 : value.size();
    }
    return tokens;
}

std::map<std::string, std::string> HeaderRewriter::RewriteRequest(
    const std::map<std::string, std::string>& client_headers,
    const std::string& client_ip,
    bool client_tls,
    const std::string& upstream_host,
    int upstream_port) const {

    // Collect additional hop-by-hop headers from Connection header value
    std::unordered_set<std::string> connection_listed;
    auto conn_it = client_headers.find("connection");
    if (conn_it != client_headers.end()) {
        auto parsed = ParseConnectionHeader(conn_it->second);
        connection_listed.insert(parsed.begin(), parsed.end());
    }

    // Build output map: copy all headers except hop-by-hop and connection-listed
    std::map<std::string, std::string> output;
    for (const auto& [name, value] : client_headers) {
        if (IsHopByHopHeader(name) || connection_listed.count(name)) {
            continue;
        }
        output[name] = value;
    }

    // X-Forwarded-For: append client IP
    if (config_.set_x_forwarded_for) {
        auto it = output.find("x-forwarded-for");
        if (it != output.end()) {
            it->second += ", " + client_ip;
        } else {
            output["x-forwarded-for"] = client_ip;
        }
    }

    // X-Forwarded-Proto: set based on downstream TLS
    if (config_.set_x_forwarded_proto) {
        output["x-forwarded-proto"] = client_tls ? "https" : "http";
    }

    // Via: append gateway identifier
    if (config_.set_via_header) {
        static const std::string VIA_ENTRY = "1.1 reactor-gateway";
        auto it = output.find("via");
        if (it != output.end()) {
            it->second += ", " + VIA_ENTRY;
        } else {
            output["via"] = VIA_ENTRY;
        }
    }

    // Host: rewrite to upstream address
    if (config_.rewrite_host) {
        // Omit port for default ports (80 and 443)
        if (upstream_port == 80 || upstream_port == 443) {
            output["host"] = upstream_host;
        } else {
            output["host"] = upstream_host + ":"
                           + std::to_string(upstream_port);
        }
    }

    logging::Get()->debug("HeaderRewriter::RewriteRequest: "
                          "input={} output={} headers",
                          client_headers.size(), output.size());

    return output;
}

std::vector<std::pair<std::string, std::string>> HeaderRewriter::RewriteResponse(
    const std::vector<std::pair<std::string, std::string>>& upstream_headers) const {

    // Collect additional hop-by-hop headers from Connection header value
    std::unordered_set<std::string> connection_listed;
    for (const auto& [name, value] : upstream_headers) {
        if (name == "connection") {
            auto parsed = ParseConnectionHeader(value);
            connection_listed.insert(parsed.begin(), parsed.end());
        }
    }

    // Filter: remove hop-by-hop headers and connection-listed headers
    std::vector<std::pair<std::string, std::string>> output;
    for (const auto& [name, value] : upstream_headers) {
        if (IsHopByHopHeader(name) || connection_listed.count(name)) {
            continue;
        }
        output.emplace_back(name, value);
    }

    // Via: append gateway identifier
    if (config_.set_via_header) {
        static const std::string VIA_ENTRY = "1.1 reactor-gateway";
        // Look for existing Via header to append
        bool found_via = false;
        for (auto& [name, value] : output) {
            if (name == "via") {
                value += ", " + VIA_ENTRY;
                found_via = true;
                break;
            }
        }
        if (!found_via) {
            output.emplace_back("via", VIA_ENTRY);
        }
    }

    logging::Get()->debug("HeaderRewriter::RewriteResponse: "
                          "input={} output={} headers",
                          upstream_headers.size(), output.size());

    return output;
}
