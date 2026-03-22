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

    // TLS support
    enum class TlsState { NONE, HANDSHAKE, READY };
    TlsState tls_state_ = TlsState::NONE;
    std::unique_ptr<TlsConnection> tls_;
    // TLS renegotiation/key-update retry flags:
    // When SSL_read returns WANT_WRITE, we must retry the read on the next writable event.
    // When SSL_write returns WANT_READ, we must retry the write on the next readable event.
    bool tls_read_wants_write_ = false;
    bool tls_write_wants_read_ = false;
public:
    ConnectionHandler() = delete;
    ConnectionHandler(std::shared_ptr<Dispatcher>, std::unique_ptr<SocketHandler>);
    ~ConnectionHandler() = default; // no need the release resource for smart pointer

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
    void CloseAfterWrite();
    void CallErroCb();
    void CallWriteCb();

    void SetOnMessageCb(CALLBACKS_NAMESPACE::ConnOnMsgCallback);
    void SetCompletionCb(CALLBACKS_NAMESPACE::ConnCompleteCallback);
    void SetCloseCb(CALLBACKS_NAMESPACE::ConnCloseCallback);
    void SetErrorCb(CALLBACKS_NAMESPACE::ConnErrorCallback);

    void SetTlsConnection(std::unique_ptr<TlsConnection> tls);

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
