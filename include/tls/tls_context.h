#pragma once

#include <openssl/ssl.h>
#include <string>

class TlsContext {
public:
    // Create server TLS context with certificate and private key
    TlsContext(const std::string& cert_file, const std::string& key_file);
    ~TlsContext();

    // Non-copyable
    TlsContext(const TlsContext&) = delete;
    TlsContext& operator=(const TlsContext&) = delete;

    SSL_CTX* GetCtx() const { return ctx_; }

    void SetMinProtocolVersion(int version);
    void SetCipherList(const std::string& ciphers);

private:
    SSL_CTX* ctx_;
};
