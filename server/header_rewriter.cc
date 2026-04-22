#include "upstream/header_rewriter.h"
#include "log/logger.h"
#include "net/dns_resolver.h"   // DnsResolver::FormatAuthority (§5.5.1)
#include <unordered_set>

HeaderRewriter::HeaderRewriter(const Config& config)
    : config_(config)
{
}

bool HeaderRewriter::IsHopByHopHeader(const std::string& name) {
    // RFC 7230 Section 6.1: hop-by-hop headers.
    // "proxy-connection" is non-standard (legacy from old proxy implementations)
    // but included defensively — it should never be forwarded end-to-end.
    // Proxy-Authorization / Proxy-Authenticate are scoped to the next proxy
    // hop, not the origin server / final client, so strip them as well.
    return name == "connection"
        || name == "keep-alive"
        || name == "proxy-connection"
        || name == "proxy-authenticate"
        || name == "proxy-authorization"
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
        while (start < value.size() &&
               (value[start] == ' ' || value[start] == '\t')) {
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
        while (token_end > start &&
               (value[token_end - 1] == ' ' || value[token_end - 1] == '\t')) {
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
    bool upstream_tls,
    const std::string& upstream_host,
    int upstream_port,
    const std::string& sni_hostname) const {

    // Collect additional hop-by-hop headers from Connection header value
    std::unordered_set<std::string> connection_listed;
    auto conn_it = client_headers.find("connection");
    if (conn_it != client_headers.end()) {
        auto parsed = ParseConnectionHeader(conn_it->second);
        connection_listed.insert(parsed.begin(), parsed.end());
    }

    // Build output map: copy all headers except hop-by-hop and connection-listed.
    // Also strip Expect — the proxy has already handled 100-continue locally
    // and buffered the full body, so forwarding it would cause the upstream to
    // reply 417 or emit a spurious 100 Continue alongside the body.
    std::map<std::string, std::string> output;
    for (const auto& [name, value] : client_headers) {
        if (IsHopByHopHeader(name) || connection_listed.count(name)
            || name == "expect") {
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
        auto it = output.find("via");
        if (it != output.end()) {
            it->second += ", ";
            it->second += VIA_ENTRY;
        } else {
            output["via"] = VIA_ENTRY;
        }
    }

    // Host: rewrite to upstream address (or SNI hostname when configured).
    // When an HTTPS upstream is reached by IP with tls.sni_hostname set,
    // the backend expects Host to match the SNI name for virtual-host
    // routing, not the raw IP address. SNI is a TLS-layer concept and
    // has no meaning for plain HTTP upstreams; config validation doesn't
    // reject tls.sni_hostname on non-TLS upstreams, so guard here to
    // avoid rewriting Host to an unintended name that would misroute
    // the request on the backend.
    // Rewrite Host, or ensure it's present for HTTP/1.1 compliance.
    // When rewrite_host is false (passthrough), we still must add Host if
    // the client omitted it (HTTP/1.0) — an HTTP/1.1 request without Host
    // is invalid and many backends reject it with 400.
    if (config_.rewrite_host || output.find("host") == output.end()) {
        const std::string& host_value =
            (upstream_tls && !sni_hostname.empty())
                ? sni_hostname
                : upstream_host;
        const bool omit_port = (!upstream_tls && upstream_port == 80) ||
                               (upstream_tls && upstream_port == 443);
        // Review-round fix (§5.5.1 step-7 preview): emit the Host header
        // via DnsResolver::FormatAuthority so IPv6 literals get RFC 3986
        // §3.2.2 bracketing. Previous path built `host_value + ":" + port`
        // verbatim, producing `::1:8080` for IPv6 upstreams — invalid
        // authority that many backends reject or misroute. FormatAuthority
        // produces identical output for hostnames / IPv4 literals (byte-
        // for-byte) and `[::1]:8080` / `[::1]` for IPv6. Handles the same
        // omit_port well-known-port rule the previous code had.
        output["host"] = NET_DNS_NAMESPACE::DnsResolver::FormatAuthority(
            host_value, upstream_port, omit_port);
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
        // Look for existing Via header to append
        bool found_via = false;
        for (auto& [name, value] : output) {
            if (name == "via") {
                value += ", ";
                value += VIA_ENTRY;
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
