#include "tls/tls_context.h"
#include <openssl/err.h>
#include <stdexcept>

TlsContext::TlsContext(const std::string& cert_file, const std::string& key_file) {
    // Create TLS server context
    ctx_ = SSL_CTX_new(TLS_server_method());
    if (!ctx_) {
        throw std::runtime_error("Failed to create SSL_CTX");
    }

    // Set minimum TLS 1.2
    SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION);

    // Load certificate
    if (SSL_CTX_use_certificate_file(ctx_, cert_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
        SSL_CTX_free(ctx_);
        throw std::runtime_error("Failed to load certificate: " + cert_file);
    }

    // Load private key
    if (SSL_CTX_use_PrivateKey_file(ctx_, key_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
        SSL_CTX_free(ctx_);
        throw std::runtime_error("Failed to load private key: " + key_file);
    }

    // Verify private key matches certificate
    if (!SSL_CTX_check_private_key(ctx_)) {
        SSL_CTX_free(ctx_);
        throw std::runtime_error("Private key does not match certificate");
    }
}

TlsContext::~TlsContext() {
    if (ctx_) {
        SSL_CTX_free(ctx_);
    }
}

void TlsContext::SetMinProtocolVersion(int version) {
    SSL_CTX_set_min_proto_version(ctx_, version);
}

void TlsContext::SetCipherList(const std::string& ciphers) {
    SSL_CTX_set_cipher_list(ctx_, ciphers.c_str());
}
