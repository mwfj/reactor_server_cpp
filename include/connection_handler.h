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
    std::function<bool()> deadline_timeout_cb_;
    // Monotonic counter incremented on every on-thread deadline write/clear.
    // Off-thread SetDeadline captures the generation at queue time and only
    // applies the deadline if the generation hasn't changed, preventing stale
    // queued deadlines from being resurrected after ClearDeadline.
    // Atomic because the off-thread path reads it (to capture a snapshot)
    // while the on-thread path writes it — plain unsigned would be UB.
    std::atomic<unsigned> deadline_generation_{0};

    // Outbound connect support (for upstream/proxy connections)
    enum class ConnectState { NONE, CONNECTING, CONNECTED };
    ConnectState connect_state_ = ConnectState::NONE;
    using ConnectCompleteCallback = std::function<void(std::shared_ptr<ConnectionHandler>)>;
    ConnectCompleteCallback connect_complete_callback_ = nullptr;

    // TLS support
    bool tls_ready_from_write_ = false;  // TLS handshake completed via CallWriteCb
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
    // 0 = unlimited (default). HttpServer sets this via ComputeInputCap().
    size_t max_input_size_ = 0;
public:
    ConnectionHandler() = delete;
    ConnectionHandler(std::shared_ptr<Dispatcher>, std::unique_ptr<SocketHandler>);
    // Out-of-line: unique_ptr<TlsConnection> needs complete type for destruction.
    // TlsConnection is forward-declared here; the full definition is in connection_handler.cc.
    ~ConnectionHandler();

    // Two-phase initialization: must be called after object is wrapped in shared_ptr
    void RegisterCallbacks();
    // Outbound variant: registers callbacks for connect-in-progress sockets.
    // Enables ET + write-only mode (EPOLLOUT detects connect completion).
    void RegisterOutboundCallbacks();
    void SetConnectCompleteCallback(ConnectCompleteCallback cb);
    int FinishConnect();  // Check SO_ERROR via getsockopt; returns CONNECT_SUCCESS or CONNECT_ERROR
    int dispatcher_index() const;

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
    // Get the current on-message callback (for upstream pool disconnect notification).
    const CALLBACKS_NAMESPACE::ConnOnMsgCallback& GetOnMessageCb() const {
        return callbacks_.on_message_callback;
    }
    void SetCompletionCb(CALLBACKS_NAMESPACE::ConnCompleteCallback);
    void SetWriteProgressCb(CALLBACKS_NAMESPACE::ConnWriteProgressCallback);
    void SetCloseCb(CALLBACKS_NAMESPACE::ConnCloseCallback);
    void SetErrorCb(CALLBACKS_NAMESPACE::ConnErrorCallback);

    void SetTlsConnection(std::unique_ptr<TlsConnection> tls);
    void SetMaxInputSize(size_t max) { max_input_size_ = max; }
    size_t OutputBufferSize() const { return output_bf_.Size(); }

    // Returns true if this connection has TLS (any state: handshake or ready).
    bool HasTls() const { return tls_state_ != TlsState::NONE; }
    // Returns true if TLS is fully established (handshake complete).
    bool IsTlsReady() const { return tls_state_ == TlsState::READY; }

    // Non-destructive TLS peek for idle connection validation.
    // Returns: >0 (app data buffered — stale), TLS_COMPLETE (clean — benign
    // record consumed), TLS_PEER_CLOSED, TLS_ERROR. Only valid when IsTlsReady().
    int TlsPeek(char* buf, size_t len);

    // Enqueue a task to run on this connection's dispatcher thread.
    // Thread-safe. Used by protocol layers that need dispatcher-thread
    // execution from other threads (e.g., HTTP/2 graceful shutdown).
    void RunOnDispatcher(std::function<void()> task);

    // Get the ALPN-negotiated protocol from the TLS connection.
    // Returns empty string if no TLS or ALPN not negotiated.
    std::string GetAlpnProtocol() const;

    // Deadline: if set, IsTimeOut returns true when deadline is exceeded
    void SetDeadline(std::chrono::steady_clock::time_point deadline);
    void ClearDeadline();

    // Deadline timeout callback. Returns true if the timeout was handled
    // (e.g., HTTP/2 RST'd expired streams and re-armed) — connection stays alive.
    // Returns false to proceed with the default close behavior.
    using DeadlineTimeoutCb = std::function<bool()>;
    void SetDeadlineTimeoutCb(DeadlineTimeoutCb cb);
    bool CallDeadlineTimeoutCb();  // returns true if handled (keep alive)

    bool IsTimeOut(std::chrono::seconds) const;
};
