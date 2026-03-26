#pragma once

#include "common.h"
#include <openssl/ssl.h>

class TlsContext {
public:
    // Create server TLS context with certificate and private key
    TlsContext(const std::string& cert_file, const std::string& key_file);
    ~TlsContext();

    // Non-copyable and non-movable (SSL_CTX* ownership must not be transferred)
    TlsContext(const TlsContext&) = delete;
    TlsContext& operator=(const TlsContext&) = delete;
    TlsContext(TlsContext&&) = delete;
    TlsContext& operator=(TlsContext&&) = delete;

    SSL_CTX* GetCtx() const { return ctx_; }

    void SetMinProtocolVersion(int version);
    void SetCipherList(const std::string& ciphers);

    // ALPN negotiation: set the list of supported protocols in preference order.
    // Protocol strings: "h2", "http/1.1". The server selects the first match.
    void SetAlpnProtocols(const std::vector<std::string>& protocols);

private:
    SSL_CTX* ctx_;

    // Stored ALPN protocol list (wire-format: length-prefixed concatenation)
    std::vector<unsigned char> alpn_wire_;

    // Static ALPN selection callback for OpenSSL
    static int AlpnSelectCallback(
        SSL* ssl,
        const unsigned char** out,
        unsigned char* outlen,
        const unsigned char* in,
        unsigned int inlen,
        void* arg);
};
