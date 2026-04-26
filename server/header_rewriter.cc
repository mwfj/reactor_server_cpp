#include "upstream/header_rewriter.h"

#include "auth/auth_config.h"
#include "auth/auth_claims.h"
#include "auth/auth_context.h"
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

namespace {

// Lowercase an ASCII header name in-place — mirrors the inbound parser's
// HttpRequest::headers storage contract (lowercase keys).
std::string LowercaseHeaderName(std::string name) {
    std::transform(name.begin(), name.end(), name.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return name;
}

// Protective list of names the overlay MUST NOT touch — the config
// validator (ConfigLoader::Validate) already rejects these at load, but
// checking at runtime keeps the overlay safe if a future config path
// bypasses validation. Defense-in-depth per DEVELOPMENT_RULES.md.
bool IsReservedOverlayHeader(const std::string& lower) {
    return lower == "authorization" ||
           lower == "host" ||
           lower == "connection" ||
           lower == "keep-alive" ||
           lower == "transfer-encoding" ||
           lower == "te" ||
           lower == "trailer" ||
           lower == "upgrade" ||
           lower == "proxy-connection" ||
           lower == "proxy-authenticate" ||
           lower == "proxy-authorization" ||
           lower == "via" ||
           lower == "x-forwarded-for" ||
           lower == "x-forwarded-proto" ||
           lower == "x-auth-undetermined" ||  // manager-owned
           (!lower.empty() && lower.front() == ':');  // HTTP/2 pseudo-headers
}

// Strip headers matching the auth-forward configuration's identity
// header names. Skips `authorization` (managed separately by
// preserve_authorization) and skips any name the config-validator
// should have rejected (defense-in-depth).
void ApplyInboundIdentityStrip(
        const AUTH_NAMESPACE::AuthForwardConfig& fwd,
        std::map<std::string, std::string>& out) {
    auto try_erase = [&](const std::string& header_name) {
        if (header_name.empty()) return;
        std::string lower = LowercaseHeaderName(header_name);
        if (IsReservedOverlayHeader(lower)) return;
        out.erase(lower);
    };
    try_erase(fwd.subject_header);
    try_erase(fwd.issuer_header);
    try_erase(fwd.scopes_header);
    try_erase(fwd.raw_jwt_header);
    for (const auto& [claim_name, header_name] : fwd.claims_to_headers) {
        try_erase(header_name);
    }
}

// Inject validated identity claims. Only runs on a populated AuthContext
// that is NOT marked `undetermined`. Undetermined handling follows the
// design's §6.4 step 5a.
// RFC 7230 §3.2.6 field-value = *(VCHAR | HTAB | SP); CR/LF/other CTLs
// are forbidden. Rejecting here prevents header injection / request
// splitting from a malicious (but signed) JWT claim — the issuer may be
// trusted, but a compromised or naive IdP can still sign whatever
// payload bytes it is handed, including `\r\nHost: attacker\r\n`.
static bool AuthOverlayValueIsSafe(const std::string& value) {
    for (unsigned char c : value) {
        // Reject all CTLs (0x00-0x1F, 0x7F) EXCEPT horizontal tab (0x09).
        // CR (0x0D) and LF (0x0A) are the explicit injection vectors;
        // other CTLs can also confuse intermediaries or upstream parsers.
        if (c == '\t') continue;
        if (c < 0x20 || c == 0x7F) return false;
    }
    return true;
}

void ApplyIdentityInject(
        const AUTH_NAMESPACE::AuthForwardConfig& fwd,
        const AUTH_NAMESPACE::AuthContext& ctx,
        std::map<std::string, std::string>& out) {
    auto try_set = [&](const std::string& header_name,
                        const std::string& value) {
        if (header_name.empty() || value.empty()) return;
        if (!AuthOverlayValueIsSafe(value)) {
            // Silently dropping a safe-looking claim would mask attacks
            // from operators; log loudly but still drop — emitting the
            // value verbatim would let the attacker inject extra
            // headers or split the backend request.
            logging::Get()->warn(
                "HeaderRewriter: dropping auth-overlay header '{}' — "
                "value contains CR/LF/CTL (RFC 7230 §3.2.6 violation; "
                "possible header-injection attempt)",
                header_name);
            return;
        }
        std::string lower = LowercaseHeaderName(header_name);
        if (IsReservedOverlayHeader(lower)) return;
        out[lower] = value;
    };

    if (!ctx.subject.empty()) {
        try_set(fwd.subject_header, ctx.subject);
    }
    if (!ctx.issuer.empty()) {
        try_set(fwd.issuer_header, ctx.issuer);
    }
    if (!ctx.scopes.empty() && !fwd.scopes_header.empty()) {
        std::string joined;
        for (const auto& s : ctx.scopes) {
            if (!joined.empty()) joined += ' ';
            joined += s;
        }
        try_set(fwd.scopes_header, joined);
    }
    for (const auto& [claim_name, header_name] : fwd.claims_to_headers) {
        auto it = ctx.claims.find(claim_name);
        if (it == ctx.claims.end()) continue;
        // Skip the presence sentinel — PopulateFromPayload writes it for
        // non-scalar (array/object) claims so required_claims presence
        // checks match JWT-mode semantics. Emitting "<present>" verbatim
        // to upstreams would be a regression vs the prior behavior of
        // dropping non-scalar claims. Operators who need the actual
        // value must wait for native array→header flattening in a future
        // HeaderRewriter feature.
        if (it->second == AUTH_NAMESPACE::kNonScalarClaimSentinel) continue;
        try_set(header_name, it->second);
    }
    // Only emit the raw token header when the operator asked for it AND
    // the middleware stashed the token (forward.raw_jwt_header was
    // non-empty at verification time). The context's raw_token is kept
    // empty otherwise (§9 item 9).
    if (!fwd.raw_jwt_header.empty() && !ctx.raw_token.empty()) {
        try_set(fwd.raw_jwt_header, ctx.raw_token);
    }
}

void ApplyUndeterminedInject(
        const AUTH_NAMESPACE::AuthForwardConfig& /*fwd*/,
        std::map<std::string, std::string>& out) {
    // The X-Auth-Undetermined flag is owned by the gateway itself, not by
    // forward config — operators don't reconfigure this name. Matches
    // §6.4's explicit guidance.
    out["x-auth-undetermined"] = "true";
}

}  // namespace

std::map<std::string, std::string> HeaderRewriter::RewriteRequest(
    const std::map<std::string, std::string>& client_headers,
    const std::string& client_ip,
    bool client_tls,
    bool upstream_tls,
    const std::string& upstream_host,
    int upstream_port,
    const std::string& sni_hostname,
    const AUTH_NAMESPACE::AuthForwardConfig* auth_forward,
    const std::optional<AUTH_NAMESPACE::AuthContext>* auth_ctx) const {

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

    // Auth overlay step 2: strip inbound identity headers BEFORE any
    // operator-XFF / Via / Host rewrite. Prevents a client from spoofing
    // X-Auth-Subject / X-Auth-Issuer / claim headers on a route that
    // doesn't require auth on the inbound path but injects identity on
    // the outbound. Order rule per §6.4: strip before inject.
    if (auth_forward != nullptr &&
        auth_forward->strip_inbound_identity_headers) {
        ApplyInboundIdentityStrip(*auth_forward, output);
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
        const std::string& host_src =
            (upstream_tls && !sni_hostname.empty())
                ? sni_hostname
                : upstream_host;

        const std::string host_value =
            NET_DNS_NAMESPACE::DnsResolver::StripTrailingDot(host_src);
        const bool omit_port = (!upstream_tls && upstream_port == 80) ||
                               (upstream_tls && upstream_port == 443);

        output["host"] = NET_DNS_NAMESPACE::DnsResolver::FormatAuthority(
            host_value, upstream_port, omit_port);
    }

    // Auth overlay step 5: inject validated identity. Only runs when
    // BOTH a forward config AND an AuthContext are supplied. §6.4 step 5a:
    // undetermined contexts emit X-Auth-Undetermined only (no
    // subject/issuer/scopes/claims). Step 5b: normal ALLOW flows emit the
    // configured header names.
    //
    // Security invariant: always strip the inbound x-auth-undetermined header
    // before inject to prevent client spoofing. IsReservedOverlayHeader blocks
    // the strip inside ApplyInboundIdentityStrip, so we must do it here
    // unconditionally when auth is active (regardless of strip_inbound setting).
    if (auth_forward != nullptr) {
        output.erase("x-auth-undetermined");
    }
    if (auth_forward != nullptr &&
        auth_ctx != nullptr && auth_ctx->has_value()) {
        const auto& ctx = **auth_ctx;
        if (ctx.undetermined) {
            ApplyUndeterminedInject(*auth_forward, output);
        } else {
            ApplyIdentityInject(*auth_forward, ctx, output);
        }
    }

    // Auth overlay step 6: Authorization preservation. When the operator
    // sets preserve_authorization=false, strip Authorization so the
    // upstream never sees the bearer token. Default true matches
    // current behavior (token is forwarded alongside injected headers).
    if (auth_forward != nullptr && !auth_forward->preserve_authorization) {
        output.erase("authorization");
    }

    logging::Get()->debug("HeaderRewriter::RewriteRequest: "
                          "input={} output={} headers auth_overlay={}",
                          client_headers.size(), output.size(),
                          auth_forward != nullptr ? "on" : "off");

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
