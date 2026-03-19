#pragma once

#include <string>
#include <cstdint>

enum class WebSocketOpcode : uint8_t {
    Continuation = 0x0,
    Text         = 0x1,
    Binary       = 0x2,
    Close        = 0x8,
    Ping         = 0x9,
    Pong         = 0xA,
};

struct WebSocketFrame {
    bool fin = true;
    WebSocketOpcode opcode = WebSocketOpcode::Text;
    bool masked = false;
    uint64_t payload_length = 0;
    uint8_t masking_key[4] = {0};
    std::string payload;

    // Serialize frame for sending (server->client: NOT masked per RFC 6455)
    std::string Serialize() const;

    // Factory methods
    static WebSocketFrame TextFrame(const std::string& payload);
    static WebSocketFrame BinaryFrame(const std::string& data);
    static WebSocketFrame CloseFrame(uint16_t code = 1000, const std::string& reason = "");
    static WebSocketFrame PingFrame(const std::string& payload = "");
    static WebSocketFrame PongFrame(const std::string& payload = "");
};
