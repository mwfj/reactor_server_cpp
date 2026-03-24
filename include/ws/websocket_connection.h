#pragma once

#include "ws/websocket_parser.h"
#include "ws/websocket_frame.h"
#include "connection_handler.h"

// <memory>, <functional>, <string> provided by common.h (via connection_handler.h)

class WebSocketConnection {
public:
    explicit WebSocketConnection(std::shared_ptr<ConnectionHandler> conn);

    // Message-level callbacks
    using MessageCallback = std::function<void(WebSocketConnection& ws, const std::string& message, bool is_binary)>;
    using CloseCallback = std::function<void(WebSocketConnection& ws, uint16_t code, const std::string& reason)>;
    using PingCallback = std::function<void(WebSocketConnection& ws, const std::string& payload)>;
    using ErrorCallback = std::function<void(WebSocketConnection& ws, const std::string& error)>;

    void OnMessage(MessageCallback callback);
    void OnClose(CloseCallback callback);
    void OnPing(PingCallback callback);
    void OnError(ErrorCallback callback);

    // Send operations
    void SendText(const std::string& message);
    void SendBinary(const std::string& data);
    void SendClose(uint16_t code = 1000, const std::string& reason = "");
    void SendPing(const std::string& payload = "");
    void SendPong(const std::string& payload = "");

    // Connection info
    int fd() const;
    bool IsOpen() const { return is_open_ && !close_sent_; }

    // Access parser (for setting max payload size)
    WebSocketParser& GetParser() { return parser_; }

    // Set maximum reassembled message size (0 = unlimited)
    void SetMaxMessageSize(size_t max) { max_message_size_ = max; }

    // Feed raw data from the reactor
    void OnRawData(const std::string& data);

    // Called when the transport (TCP/TLS) disconnects without a WebSocket Close frame.
    // Fires the close handler so applications can clean up session state.
    void NotifyTransportClose();

private:
    std::shared_ptr<ConnectionHandler> conn_;
    WebSocketParser parser_;
    std::atomic<bool> is_open_{true};
    std::atomic<bool> close_sent_{false};  // We sent a close frame, waiting for peer's reply
    uint16_t sent_close_code_ = 0;     // Close code we sent (for NotifyTransportClose)
    std::string sent_close_reason_;    // Close reason we sent

    MessageCallback message_callback_;
    CloseCallback close_callback_;
    PingCallback ping_callback_;
    ErrorCallback error_callback_;

    // Fragmentation reassembly
    std::string fragment_buffer_;
    WebSocketOpcode fragment_opcode_ = WebSocketOpcode::Text;
    bool in_fragment_ = false;
    size_t max_message_size_ = 0;  // 0 = unlimited

    void ProcessFrame(const WebSocketFrame& frame);
    void SendFrame(const WebSocketFrame& frame);
};
