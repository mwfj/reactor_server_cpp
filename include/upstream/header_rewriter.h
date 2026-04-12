#pragma once

#include "common.h"
// <string>, <map>, <vector>, <utility> provided by common.h

class HeaderRewriter {
public:
    // Configuration for header rewriting behavior
    struct Config {
        bool set_x_forwarded_for = true;      // Append client IP to X-Forwarded-For
        bool set_x_forwarded_proto = true;     // Set X-Forwarded-Proto
        bool set_via_header = true;            // Add Via header
        bool rewrite_host = true;             // Rewrite Host to upstream address
        // When false, pass through client's original Host header
    };

    explicit HeaderRewriter(const Config& config);

    // Rewrite request headers for upstream forwarding.
    // Input: client request headers (lowercase keys from HttpRequest::headers).
    // Output: new header map suitable for HttpRequestSerializer.
    // client_ip: peer address from ConnectionHandler::ip_addr()
    // client_tls: true if downstream connection has TLS
    // upstream_host: upstream address for Host header rewrite
    // upstream_port: upstream port for Host header rewrite
    // sni_hostname: if non-empty, used as Host instead of upstream_host
    //   (for TLS backends reached by IP with virtual-host routing)
    std::map<std::string, std::string> RewriteRequest(
        const std::map<std::string, std::string>& client_headers,
        const std::string& client_ip,
        bool client_tls,
        bool upstream_tls,
        const std::string& upstream_host,
        int upstream_port,
        const std::string& sni_hostname = "") const;

    // Rewrite response headers from upstream before relaying to client.
    // Strips hop-by-hop headers from the upstream response.
    // Uses vector<pair> to preserve repeated headers (Set-Cookie, etc.).
    std::vector<std::pair<std::string, std::string>> RewriteResponse(
        const std::vector<std::pair<std::string, std::string>>& upstream_headers) const;

    // Via header value appended by the proxy (RFC 7230 §5.7.1).
    static constexpr const char* VIA_ENTRY = "1.1 reactor-gateway";

private:
    Config config_;

    // Hop-by-hop headers to strip (RFC 7230 section 6.1):
    // connection, keep-alive, proxy-connection, transfer-encoding, te, trailer, upgrade
    static bool IsHopByHopHeader(const std::string& name);

    // Parse comma-separated Connection header to find additional hop-by-hop headers
    static std::vector<std::string> ParseConnectionHeader(const std::string& value);
};
