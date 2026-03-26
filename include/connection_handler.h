#pragma once
#include "common.h"
#include "dispatcher.h"
#include "socket_handler.h"
#include "buffer.h"
#include "timestamp.h"
#include "callbacks.h"

#include <memory>

// Forward declaration (no need to include full TLS headers)
class TlsConnection;

class ConnectionHandler : public std::enable_shared_from_this<ConnectionHandler>
{
private:
    std::shared_ptr<Dispatcher> event_dispatcher_;
    std::unique_ptr<SocketHandler> sock_;  // Sole owner of client socket
    std::shared_ptr<Channel> client_channel_;

    CALLBACKS_NAMESPACE::ConnCallbacks callbacks_;

    Buffer input_bf_;
    Buffer output_bf_;

    std::atomic<bool> is_closing_{false};
    std::atomic<bool> close_after_write_{false};

    TimeStamp ts_; // Each connection owns a timestamp to manage
    bool has_deadline_ = false;
    std::chrono::steady_clock::time_point deadline_;
    std::function<void()> deadline_timeout_cb_;
    // Monotonic counter incremented on every on-thread deadline write/clear.
    // Off-thread SetDeadline captures the generation at queue time and only
    // applies the deadline if the generation hasn't changed, preventing stale
    // queued deadlines from being resurrected after ClearDeadline.
    // Atomic because the off-thread path reads it (to capture a snapshot)
    // while the on-thread path writes it — plain unsigned would be UB.
    std::atomic<unsigned> deadline_generation_{0};

    // TLS support
    enum class TlsState { NONE, HANDSHAKE, READY };
    TlsState tls_state_ = TlsState::NONE;
    std::unique_ptr<TlsConnection> tls_;
    // TLS renegotiation/key-update retry flags:
    bool tls_read_wants_write_ = false;
    bool tls_write_wants_read_ = false;
    size_t tls_pending_write_size_ = 0;  // Size of pending SSL_write for retry

    // Cap on input buffer accumulation during the ET read loop.
    // Prevents allocating far beyond configured limits (max_body_size, etc.)
    // before the parser has a chance to reject. The read loop still drains
    // to EAGAIN (required for ET mode) but discards bytes past this limit.
    // 0 = unlimited (default, for backward compatibility with ReactorServer).
    size_t max_input_size_ = 0;
public:
    ConnectionHandler() = delete;
    ConnectionHandler(std::shared_ptr<Dispatcher>, std::unique_ptr<SocketHandler>);
    // Out-of-line: unique_ptr<TlsConnection> needs complete type for destruction.
    // TlsConnection is forward-declared here; the full definition is in connection_handler.cc.
    ~ConnectionHandler();

    // Two-phase initialization: must be called after object is wrapped in shared_ptr
    void RegisterCallbacks();

    int fd() const{ return sock_ ? sock_ -> fd() : -1; }
    bool IsClosing() const { return is_closing_.load(std::memory_order_acquire); }
    bool IsCloseDeferred() const { return close_after_write_.load(std::memory_order_acquire); }
    const std::string& ip_addr() const { return sock_ -> ip_addr(); }
    int port() const { return sock_ -> port(); }

    void OnMessage();

    void SendData(const char*, size_t);
    void DoSend(const char*, size_t);  // Internal: appends to buffer and enables write (in socket thread)

    void SendRaw(const char*, size_t);
    void DoSendRaw(const char*, size_t);  // Internal: appends without length header (in socket thread)

    void CallCloseCb();
    void ForceClose();  // Bypass close_after_write defer — for stalled flush recovery
    void CloseAfterWrite();
    void CallErroCb();
    void CallWriteCb();

    void SetOnMessageCb(CALLBACKS_NAMESPACE::ConnOnMsgCallback);
    void SetCompletionCb(CALLBACKS_NAMESPACE::ConnCompleteCallback);
    void SetCloseCb(CALLBACKS_NAMESPACE::ConnCloseCallback);
    void SetErrorCb(CALLBACKS_NAMESPACE::ConnErrorCallback);

    void SetTlsConnection(std::unique_ptr<TlsConnection> tls);
    void SetMaxInputSize(size_t max) { max_input_size_ = max; }

    // Get the ALPN-negotiated protocol from the TLS connection.
    // Returns empty string if no TLS or ALPN not negotiated.
    std::string GetAlpnProtocol() const;

    // Deadline: if set, IsTimeOut returns true when deadline is exceeded
    void SetDeadline(std::chrono::steady_clock::time_point deadline);
    void ClearDeadline();

    // Pre-close callback for deadline timeouts — allows upper layers (HttpConnectionHandler)
    // to send a 408 response before the connection is closed by the timer.
    using DeadlineTimeoutCb = std::function<void()>;
    void SetDeadlineTimeoutCb(DeadlineTimeoutCb cb);
    void CallDeadlineTimeoutCb();

    bool IsTimeOut(std::chrono::seconds) const;
};
