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
    if (!SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION)) {
        SSL_CTX_free(ctx_);
        throw std::runtime_error("Failed to set minimum TLS version to 1.2");
    }

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
    if (!SSL_CTX_set_min_proto_version(ctx_, version)) {
        throw std::runtime_error("Failed to set minimum TLS protocol version");
    }
}

void TlsContext::SetCipherList(const std::string& ciphers) {
    if (SSL_CTX_set_cipher_list(ctx_, ciphers.c_str()) != 1) {
        throw std::runtime_error("Failed to set cipher list: " + ciphers);
    }
}

void TlsContext::SetAlpnProtocols(const std::vector<std::string>& protocols) {
    // Build wire-format ALPN list: each protocol prefixed by its length byte
    alpn_wire_.clear();
    for (const auto& proto : protocols) {
        if (proto.size() > 255) {
            throw std::runtime_error("ALPN protocol too long: " + proto);
        }
        alpn_wire_.push_back(static_cast<unsigned char>(proto.size()));
        alpn_wire_.insert(alpn_wire_.end(), proto.begin(), proto.end());
    }

    // Register ALPN selection callback
    SSL_CTX_set_alpn_select_cb(ctx_, AlpnSelectCallback, this);
}

int TlsContext::AlpnSelectCallback(
    SSL* /*ssl*/,
    const unsigned char** out,
    unsigned char* outlen,
    const unsigned char* in,
    unsigned int inlen,
    void* arg) {

    auto* self = static_cast<TlsContext*>(arg);
    if (self->alpn_wire_.empty()) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    // Use OpenSSL's helper to select the preferred protocol.
    // SSL_select_next_proto picks the first server protocol found in the
    // client list, giving server-preference ordering.
    if (SSL_select_next_proto(
            const_cast<unsigned char**>(out), outlen,
            self->alpn_wire_.data(),
            static_cast<unsigned int>(self->alpn_wire_.size()),
            in, inlen) != OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    return SSL_TLSEXT_ERR_OK;
}
