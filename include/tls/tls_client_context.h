#pragma once

#include "common.h"
#include <openssl/ssl.h>

class TlsClientContext {
public:
    // Create client TLS context with optional CA verification.
    // If verify_peer is true and ca_file is empty, uses system CA store.
    // If verify_peer is true and ca_file is non-empty, uses the specified CA file.
    // If verify_peer is false, peer certificate is not verified (use for testing only).
    TlsClientContext(const std::string& ca_file = "",
                     bool verify_peer = true);
    ~TlsClientContext();

    // Non-copyable and non-movable (SSL_CTX* ownership must not be transferred)
    TlsClientContext(const TlsClientContext&) = delete;
    TlsClientContext& operator=(const TlsClientContext&) = delete;
    TlsClientContext(TlsClientContext&&) = delete;
    TlsClientContext& operator=(TlsClientContext&&) = delete;

    SSL_CTX* GetCtx() const { return ctx_; }

    void SetMinProtocolVersion(int version);

    // ALPN negotiation: set the list of protocols to advertise to the server.
    // Protocol strings: "h2", "http/1.1". For client context, uses
    // SSL_CTX_set_alpn_protos() (not the server selection callback).
    void SetAlpnProtocols(const std::vector<std::string>& protocols);

private:
    SSL_CTX* ctx_;

    // Stored ALPN protocol list (wire-format: length-prefixed concatenation)
    std::vector<unsigned char> alpn_wire_;
};
