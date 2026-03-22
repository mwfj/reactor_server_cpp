#include "tls/tls_connection.h"
#include <openssl/err.h>

TlsConnection::TlsConnection(TlsContext& ctx, int fd) {
    ssl_ = SSL_new(ctx.GetCtx());
    if (!ssl_) {
        throw std::runtime_error("Failed to create SSL object");
    }
    if (SSL_set_fd(ssl_, fd) != 1) {
        SSL_free(ssl_);
        ssl_ = nullptr;
        throw std::runtime_error("Failed to set SSL file descriptor");
    }
    SSL_set_accept_state(ssl_);  // Server-side

    // Allow retrying SSL_write with a different buffer address.
    // Our output_bf_ can reallocate between the original write and the retry.
    SSL_set_mode(ssl_, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE);
}

TlsConnection::~TlsConnection() {
    if (ssl_) {
        // Note: SSL_shutdown() is NOT called here because by the time
        // TlsConnection is destroyed, Channel::CloseChannel() has already
        // closed the fd. Use the explicit Shutdown() method before socket
        // close if a clean close_notify is needed.
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

// Returns: >0 bytes read, 0=want_read, -3=want_write, -2=peer close, -1=error
int TlsConnection::Read(char* buf, size_t len) {
    int ret = SSL_read(ssl_, buf, static_cast<int>(len));
    if (ret > 0) return ret;

    int err = SSL_get_error(ssl_, ret);
    if (err == SSL_ERROR_WANT_READ) return 0;    // Need more read data
    if (err == SSL_ERROR_WANT_WRITE) return -3;   // Need write readiness (renegotiation)
    if (err == SSL_ERROR_ZERO_RETURN) return -2;   // Peer closed cleanly
    return -1;  // Error
}

// Returns: >0 bytes written, 0=want_write, -3=want_read, -1=error
int TlsConnection::Write(const char* buf, size_t len) {
    int ret = SSL_write(ssl_, buf, static_cast<int>(len));
    if (ret > 0) return ret;

    int err = SSL_get_error(ssl_, ret);
    if (err == SSL_ERROR_WANT_WRITE) return 0;    // Need write readiness
    if (err == SSL_ERROR_WANT_READ) return -3;     // Need read readiness (renegotiation)
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
