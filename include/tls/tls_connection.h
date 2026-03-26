#pragma once

#include "tls/tls_context.h"
// <string>, <stdexcept> provided by common.h (via tls_context.h)

class TlsConnection {
public:
    // TLS operation return codes
    static constexpr int TLS_COMPLETE    =  0;  // Handshake complete / would_block (read/write)
    static constexpr int TLS_WANT_READ   =  1;  // DoHandshake needs read readiness
    static constexpr int TLS_WANT_WRITE  =  2;  // DoHandshake needs write readiness
    static constexpr int TLS_ERROR       = -1;  // Fatal error
    static constexpr int TLS_PEER_CLOSED = -2;  // Peer sent close_notify (Read only)
    static constexpr int TLS_CROSS_RW    = -3;  // Read needs write / Write needs read (renegotiation)

    TlsConnection(TlsContext& ctx, int fd);
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

    // Returns: >0 bytes written, TLS_COMPLETE (would_block), TLS_CROSS_RW, or TLS_ERROR
    int Write(const char* buf, size_t len);

    int Shutdown();

    bool IsHandshakeComplete() const { return handshake_complete_; }
    std::string GetCipherName() const;
    std::string GetProtocolVersion() const;

    // Get the ALPN-negotiated protocol (e.g., "h2", "http/1.1").
    // Returns empty string if no ALPN was negotiated or handshake not complete.
    std::string GetAlpnProtocol() const;

private:
    SSL* ssl_;
    bool handshake_complete_ = false;
};
