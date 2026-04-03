#include "tls/tls_client_context.h"
#include "log/logger.h"
#include <openssl/err.h>
#include <stdexcept>

TlsClientContext::TlsClientContext(const std::string& ca_file, bool verify_peer) {
    // Create TLS client context
    ctx_ = SSL_CTX_new(TLS_client_method());
    if (!ctx_) {
        throw std::runtime_error("Failed to create client SSL_CTX");
    }

    // Set minimum TLS 1.2 — never fail open
    if (!SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION)) {
        SSL_CTX_free(ctx_);
        throw std::runtime_error("Failed to set minimum TLS version to 1.2");
    }

    if (verify_peer) {
        SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER, nullptr);

        if (!ca_file.empty()) {
            // Load specific CA file
            if (SSL_CTX_load_verify_locations(ctx_, ca_file.c_str(), nullptr) != 1) {
                SSL_CTX_free(ctx_);
                throw std::runtime_error("Failed to load CA file: " + ca_file);
            }
            logging::Get()->debug("TlsClientContext: loaded CA file={}", ca_file);
        } else {
            // Use system default CA store
            if (SSL_CTX_set_default_verify_paths(ctx_) != 1) {
                SSL_CTX_free(ctx_);
                throw std::runtime_error("Failed to set default verify paths (system CA store)");
            }
            logging::Get()->debug("TlsClientContext: using system CA store");
        }
    } else {
        SSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, nullptr);
        logging::Get()->warn("TlsClientContext: peer verification disabled — use for testing only");
    }

    logging::Get()->debug("TlsClientContext: created (verify_peer={})", verify_peer);
}

TlsClientContext::~TlsClientContext() {
    if (ctx_) {
        SSL_CTX_free(ctx_);
    }
}

void TlsClientContext::SetMinProtocolVersion(int version) {
    if (!SSL_CTX_set_min_proto_version(ctx_, version)) {
        throw std::runtime_error("Failed to set minimum TLS protocol version");
    }
}

void TlsClientContext::SetAlpnProtocols(const std::vector<std::string>& protocols) {
    // Build wire-format ALPN list: each protocol prefixed by its length byte
    alpn_wire_.clear();
    for (const auto& proto : protocols) {
        if (proto.size() > 255) {
            throw std::runtime_error("ALPN protocol too long: " + proto);
        }
        alpn_wire_.push_back(static_cast<unsigned char>(proto.size()));
        alpn_wire_.insert(alpn_wire_.end(), proto.begin(), proto.end());
    }

    // For client context, SSL_CTX_set_alpn_protos advertises protocols to the server.
    // Return value: 0 on success, non-zero on failure.
    if (SSL_CTX_set_alpn_protos(ctx_, alpn_wire_.data(),
                                static_cast<unsigned int>(alpn_wire_.size())) != 0) {
        throw std::runtime_error("Failed to set ALPN protocols on client context");
    }

    logging::Get()->debug("TlsClientContext: ALPN protocols set (count={})", protocols.size());
}
