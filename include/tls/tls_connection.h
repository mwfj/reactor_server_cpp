#pragma once

#include "tls/tls_context.h"
// <string>, <stdexcept> provided by common.h (via tls_context.h)

// Forward declaration — avoids pulling tls_client_context.h into every includer
class TlsClientContext;

class TlsConnection {
public:
    // TLS operation return codes
    static constexpr int TLS_COMPLETE    =  0;  // Handshake complete / would_block (read/write)
    static constexpr int TLS_WANT_READ   =  1;  // DoHandshake needs read readiness
    static constexpr int TLS_WANT_WRITE  =  2;  // DoHandshake needs write readiness
    static constexpr int TLS_ERROR       = -1;  // Fatal error
    static constexpr int TLS_PEER_CLOSED = -2;  // Peer sent close_notify (Read only)
    static constexpr int TLS_CROSS_RW    = -3;  // Read needs write / Write needs read (renegotiation)

    // Server-mode constructor (existing)
    TlsConnection(TlsContext& ctx, int fd);

    // Client-mode constructor — uses TLS_client_method context.
    // If sni_hostname is non-empty, sets SNI (Server Name Indication) for virtual hosting.
    TlsConnection(TlsClientContext& ctx, int fd, const std::string& sni_hostname = "");
    ~TlsConnection();

    // Non-copyable and non-movable (SSL* ownership must not be transferred)
    TlsConnection(const TlsConnection&) = delete;
    TlsConnection& operator=(const TlsConnection&) = delete;
    TlsConnection(TlsConnection&&) = delete;
    TlsConnection& operator=(TlsConnection&&) = delete;

    // Returns: TLS_COMPLETE, TLS_WANT_READ, TLS_WANT_WRITE, or TLS_ERROR
    int DoHandshake();

    // Returns: >0 bytes read, TLS_COMPLETE (would_block), TLS_CROSS_RW, TLS_PEER_CLOSED, or TLS_ERROR
    int Read(char* buf, size_t len);

    // Non-destructive peek: returns >0 if application data is buffered,
    // TLS_COMPLETE if no app data (benign TLS record consumed internally),
    // TLS_PEER_CLOSED if close_notify, or TLS_ERROR.
    int Peek(char* buf, size_t len);

    // Returns: >0 bytes written, TLS_COMPLETE (would_block), TLS_CROSS_RW, or TLS_ERROR
    int Write(const char* buf, size_t len);

    int Shutdown();

    bool IsHandshakeComplete() const { return handshake_complete_; }
    std::string GetCipherName() const;
    std::string GetProtocolVersion() const;

    // Test-only accessor — returns the underlying OpenSSL SSL*. Used by
    // DualStack tests to introspect SNI / verify-name post-ctor without
    // running a handshake. Production code must not rely on this; the
    // ownership model (non-copyable / non-movable) is deliberate.
    SSL* GetSslForTesting() const { return ssl_; }

    // Get the ALPN-negotiated protocol (e.g., "h2", "http/1.1").
    // Returns empty string if no ALPN was negotiated or handshake not complete.
    std::string GetAlpnProtocol() const;

private:
    SSL* ssl_;
    bool handshake_complete_ = false;
};
