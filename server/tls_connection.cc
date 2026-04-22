#include "tls/tls_connection.h"
#include "tls/tls_client_context.h"
#include "net/dns_resolver.h"  // StripTrailingDot (§5.10 SNI/verify-name strip)
#include "log/logger.h"
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

TlsConnection::TlsConnection(TlsClientContext& ctx, int fd, const std::string& sni_hostname) {
    ssl_ = SSL_new(ctx.GetCtx());
    if (!ssl_) {
        throw std::runtime_error("Failed to create client SSL object");
    }
    if (SSL_set_fd(ssl_, fd) != 1) {
        SSL_free(ssl_);
        ssl_ = nullptr;
        throw std::runtime_error("Failed to set client SSL file descriptor");
    }
    SSL_set_connect_state(ssl_);  // Client-side

    // Set SNI hostname for virtual hosting — server uses this to select certificate
    if (!sni_hostname.empty()) {
        // Review-round fix (§5.10 / §5.5.1 symmetric trailing-dot strip).
        // Operators commonly add a trailing dot to `tls.sni_hostname` for
        // absolute-FQDN semantics at the DNS layer. But RFC 6066 §3 SNI
        // and X.509 SAN `dNSName` entries are dotless — passing
        // `api.example.com.` into `SSL_set_tlsext_host_name` makes the
        // server either miss the correct SNI vhost (many implementations
        // do byte-level match on the ServerName) or return a cert whose
        // SAN is `api.example.com`, which `SSL_set1_host` then rejects
        // as a hostname-verification failure. The Host-header path in
        // HeaderRewriter already strips in v0.46; applying the same
        // strip here keeps the three consumers (Host, SNI, verify-name)
        // in lockstep. `StripTrailingDot` is idempotent for dotless
        // inputs — safe to call unconditionally. Design v0.37 moves
        // this strip into `ConfigLoader::Normalize` (step 6, not landed
        // yet); until then, per-consumer strips at the point of use are
        // the parallel-safe approach.
        const std::string effective_sni =
            NET_DNS_NAMESPACE::DnsResolver::StripTrailingDot(sni_hostname);
        if (SSL_set_tlsext_host_name(ssl_, effective_sni.c_str()) != 1) {
            SSL_free(ssl_);
            ssl_ = nullptr;
            throw std::runtime_error("Failed to set SNI hostname: " + effective_sni);
        }
        // Enable hostname verification — SSL_VERIFY_PEER (set on the CTX) validates
        // chain trust, but SSL_set1_host() is required to verify the certificate's
        // CN/SAN matches the expected hostname, preventing MITM attacks.
        if (SSL_set1_host(ssl_, effective_sni.c_str()) != 1) {
            SSL_free(ssl_);
            ssl_ = nullptr;
            throw std::runtime_error(
                "Failed to enable hostname verification for: " + effective_sni);
        }
        logging::Get()->debug("TlsConnection client: SNI + hostname verification set to {}", effective_sni);
    }

    // Allow retrying SSL_write with a different buffer address (same as server mode)
    SSL_set_mode(ssl_, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE);

    logging::Get()->debug("TlsConnection client: created fd={}", fd);
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
        return TLS_COMPLETE;
    }

    int err = SSL_get_error(ssl_, ret);
    switch (err) {
        case SSL_ERROR_WANT_READ:  return TLS_WANT_READ;
        case SSL_ERROR_WANT_WRITE: return TLS_WANT_WRITE;
        default:                   return TLS_ERROR;
    }
}

int TlsConnection::Read(char* buf, size_t len) {
    int ret = SSL_read(ssl_, buf, static_cast<int>(len));
    if (ret > 0) return ret;

    int err = SSL_get_error(ssl_, ret);
    if (err == SSL_ERROR_WANT_READ) return TLS_COMPLETE;      // Need more read data
    if (err == SSL_ERROR_WANT_WRITE) return TLS_CROSS_RW;     // Need write readiness (renegotiation)
    if (err == SSL_ERROR_ZERO_RETURN) return TLS_PEER_CLOSED;  // Peer closed cleanly
    return TLS_ERROR;
}

int TlsConnection::Peek(char* buf, size_t len) {
    int ret = SSL_peek(ssl_, buf, static_cast<int>(len));
    if (ret > 0) return ret;  // Application data is buffered

    int err = SSL_get_error(ssl_, ret);
    if (err == SSL_ERROR_WANT_READ) return TLS_COMPLETE;       // No app data (benign record consumed)
    if (err == SSL_ERROR_WANT_WRITE) return TLS_COMPLETE;      // Benign: TLS needs to send (e.g., KeyUpdate ack)
    if (err == SSL_ERROR_ZERO_RETURN) return TLS_PEER_CLOSED;  // close_notify received
    return TLS_ERROR;
}

int TlsConnection::Write(const char* buf, size_t len) {
    int ret = SSL_write(ssl_, buf, static_cast<int>(len));
    if (ret > 0) return ret;

    int err = SSL_get_error(ssl_, ret);
    if (err == SSL_ERROR_WANT_WRITE) return TLS_COMPLETE;    // Need write readiness
    if (err == SSL_ERROR_WANT_READ) return TLS_CROSS_RW;     // Need read readiness (renegotiation)
    return TLS_ERROR;
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

std::string TlsConnection::GetAlpnProtocol() const {
    const unsigned char* data = nullptr;
    unsigned int len = 0;
    SSL_get0_alpn_selected(ssl_, &data, &len);
    if (data && len > 0) {
        return std::string(reinterpret_cast<const char*>(data), len);
    }
    return "";
}
