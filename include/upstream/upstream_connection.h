#pragma once

#include "common.h"
#include "connection_handler.h"
// <memory>, <functional>, <chrono>, <string> provided by common.h (via connection_handler.h)

// Forward declarations
class TlsClientContext;
class PoolPartition;
struct UpstreamPoolConfig;

class UpstreamConnection {
public:
    // Connection lifecycle states
    enum class State {
        CONNECTING,      // Non-blocking connect() in progress
        TLS_HANDSHAKE,   // TLS handshake in progress
        READY,           // Connected and available for checkout
        IN_USE,          // Checked out, request in flight
        CLOSING          // Draining / shutting down
    };

    UpstreamConnection(std::shared_ptr<ConnectionHandler> conn,
                       const std::string& host, int port);
    ~UpstreamConnection();

    // Non-copyable, non-movable (pool owns via unique_ptr)
    UpstreamConnection(const UpstreamConnection&) = delete;
    UpstreamConnection& operator=(const UpstreamConnection&) = delete;
    UpstreamConnection(UpstreamConnection&&) = delete;
    UpstreamConnection& operator=(UpstreamConnection&&) = delete;

    // Pool lifecycle transitions (dispatcher-thread-only)
    void MarkInUse();
    void MarkIdle();
    void MarkClosing();

    // State queries
    bool IsIdle() const { return state_ == State::READY; }
    bool IsInUse() const { return state_ == State::IN_USE; }
    bool IsConnecting() const {
        return state_ == State::CONNECTING || state_ == State::TLS_HANDSHAKE;
    }
    bool IsClosing() const { return state_ == State::CLOSING; }
    State state() const { return state_; }

    // Validation before reuse
    bool IsAlive() const;
    bool IsExpired(int max_lifetime_sec, int max_requests_per_conn) const;

    // Lifecycle metadata
    int fd() const;
    const std::string& upstream_host() const { return upstream_host_; }
    int upstream_port() const { return upstream_port_; }
    std::chrono::steady_clock::time_point created_at() const { return created_at_; }
    std::chrono::steady_clock::time_point last_used_at() const { return last_used_at_; }
    uint64_t request_count() const { return request_count_; }
    void IncrementRequestCount();

    // Access to underlying transport.
    // IMPORTANT: Borrowers MUST NOT overwrite SetCloseCb or SetErrorCb
    // on the transport — these are owned by the pool for lifecycle tracking.
    // Use SetOnMessageCb, SetCompletionCb, and SetWriteProgressCb for
    // request-level I/O. Overwriting close/error callbacks causes the pool
    // to lose track of upstream disconnections until the lease is returned.
    std::shared_ptr<ConnectionHandler> GetTransport() const { return conn_; }

private:
    std::shared_ptr<ConnectionHandler> conn_;
    State state_ = State::CONNECTING;

    std::string upstream_host_;
    int upstream_port_;

    std::chrono::steady_clock::time_point created_at_;
    std::chrono::steady_clock::time_point last_used_at_;
    uint64_t request_count_ = 0;
};
