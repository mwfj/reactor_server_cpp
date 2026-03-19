#include "tls/tls_connection.h"
#include <openssl/err.h>

TlsConnection::TlsConnection(TlsContext& ctx, int fd) {
    ssl_ = SSL_new(ctx.GetCtx());
    if (!ssl_) {
        throw std::runtime_error("Failed to create SSL object");
    }
    SSL_set_fd(ssl_, fd);
    SSL_set_accept_state(ssl_);  // Server-side
}

TlsConnection::~TlsConnection() {
    if (ssl_) {
        SSL_free(ssl_);
    }
}

int TlsConnection::DoHandshake() {
    int ret = SSL_do_handshake(ssl_);
    if (ret == 1) {
        handshake_complete_ = true;
        return 0;  // Complete
    }

    int err = SSL_get_error(ssl_, ret);
    switch (err) {
        case SSL_ERROR_WANT_READ:  return 1;
        case SSL_ERROR_WANT_WRITE: return 2;
        default:                   return -1;
    }
}

int TlsConnection::Read(char* buf, size_t len) {
    int ret = SSL_read(ssl_, buf, static_cast<int>(len));
    if (ret > 0) return ret;

    int err = SSL_get_error(ssl_, ret);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        return 0;  // Would block
    }
    return -1;  // Error or closed
}

int TlsConnection::Write(const char* buf, size_t len) {
    int ret = SSL_write(ssl_, buf, static_cast<int>(len));
    if (ret > 0) return ret;

    int err = SSL_get_error(ssl_, ret);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        return 0;  // Would block
    }
    return -1;  // Error
}

int TlsConnection::Shutdown() {
    return SSL_shutdown(ssl_);
}

std::string TlsConnection::GetCipherName() const {
    const char* cipher = SSL_get_cipher(ssl_);
    return cipher ? cipher : "unknown";
}

std::string TlsConnection::GetProtocolVersion() const {
    const char* version = SSL_get_version(ssl_);
    return version ? version : "unknown";
}
