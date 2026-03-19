#pragma once

#include "tls/tls_context.h"
#include <string>
#include <stdexcept>

class TlsConnection {
public:
    TlsConnection(TlsContext& ctx, int fd);
    ~TlsConnection();

    // Non-copyable
    TlsConnection(const TlsConnection&) = delete;
    TlsConnection& operator=(const TlsConnection&) = delete;

    // Returns: 0=complete, 1=want_read, 2=want_write, -1=error
    int DoHandshake();

    // Returns: >0 bytes read, 0=would_block, -1=error/closed
    int Read(char* buf, size_t len);

    // Returns: >0 bytes written, 0=would_block, -1=error
    int Write(const char* buf, size_t len);

    int Shutdown();

    bool IsHandshakeComplete() const { return handshake_complete_; }
    std::string GetCipherName() const;
    std::string GetProtocolVersion() const;

private:
    SSL* ssl_;
    bool handshake_complete_ = false;
};
