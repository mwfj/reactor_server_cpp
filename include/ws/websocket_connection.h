#pragma once

#include "ws/websocket_parser.h"
#include "ws/websocket_frame.h"
#include "connection_handler.h"

#include <memory>
#include <functional>
#include <string>

class WebSocketConnection {
public:
    explicit WebSocketConnection(std::shared_ptr<ConnectionHandler> conn);

    // Message-level callbacks
    using MessageHandler = std::function<void(WebSocketConnection& ws, const std::string& message, bool is_binary)>;
    using CloseHandler = std::function<void(WebSocketConnection& ws, uint16_t code, const std::string& reason)>;
    using PingHandler = std::function<void(WebSocketConnection& ws, const std::string& payload)>;
    using ErrorHandler = std::function<void(WebSocketConnection& ws, const std::string& error)>;

    void OnMessage(MessageHandler handler);
    void OnClose(CloseHandler handler);
    void OnPing(PingHandler handler);
    void OnError(ErrorHandler handler);

    // Send operations
    void SendText(const std::string& message);
    void SendBinary(const std::string& data);
    void SendClose(uint16_t code = 1000, const std::string& reason = "");
    void SendPing(const std::string& payload = "");
    void SendPong(const std::string& payload = "");

    // Connection info
    int fd() const;
    bool IsOpen() const { return is_open_; }

    // Access parser (for setting max payload size)
    WebSocketParser& GetParser() { return parser_; }

    // Set maximum reassembled message size (0 = unlimited)
    void SetMaxMessageSize(size_t max) { max_message_size_ = max; }

    // Feed raw data from the reactor
    void OnRawData(const std::string& data);

private:
    std::shared_ptr<ConnectionHandler> conn_;
    WebSocketParser parser_;
    bool is_open_ = true;
    bool close_sent_ = false;  // We sent a close frame, waiting for peer's reply

    MessageHandler message_handler_;
    CloseHandler close_handler_;
    PingHandler ping_handler_;
    ErrorHandler error_handler_;

    // Fragmentation reassembly
    std::string fragment_buffer_;
    WebSocketOpcode fragment_opcode_ = WebSocketOpcode::Text;
    bool in_fragment_ = false;
    size_t max_message_size_ = 0;  // 0 = unlimited

    void ProcessFrame(const WebSocketFrame& frame);
    void SendFrame(const WebSocketFrame& frame);
};
