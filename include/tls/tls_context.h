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

private:
    SSL_CTX* ctx_;
};
