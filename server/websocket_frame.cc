#include "ws/websocket_frame.h"

std::string WebSocketFrame::Serialize() const {
    std::string result;

    // Byte 1: FIN + opcode
    uint8_t byte1 = static_cast<uint8_t>(opcode);
    if (fin) byte1 |= 0x80;
    result += static_cast<char>(byte1);

    // Byte 2: MASK + payload length
    // Server-to-client frames are NOT masked
    uint64_t len = payload.size();
    if (len <= 125) {
        result += static_cast<char>(len & 0x7F);
    } else if (len <= 65535) {
        result += static_cast<char>(126);
        result += static_cast<char>((len >> 8) & 0xFF);
        result += static_cast<char>(len & 0xFF);
    } else {
        result += static_cast<char>(127);
        for (int i = 7; i >= 0; i--) {
            result += static_cast<char>((len >> (8 * i)) & 0xFF);
        }
    }

    // Payload (no masking for server-sent frames)
    result += payload;

    return result;
}

WebSocketFrame WebSocketFrame::TextFrame(const std::string& payload) {
    WebSocketFrame f;
    f.opcode = WebSocketOpcode::Text;
    f.payload = payload;
    f.payload_length = payload.size();
    return f;
}

WebSocketFrame WebSocketFrame::BinaryFrame(const std::string& data) {
    WebSocketFrame f;
    f.opcode = WebSocketOpcode::Binary;
    f.payload = data;
    f.payload_length = data.size();
    return f;
}

WebSocketFrame WebSocketFrame::CloseFrame(uint16_t code, const std::string& reason) {
    WebSocketFrame f;
    f.opcode = WebSocketOpcode::Close;
    // Close frame payload: 2-byte status code + optional reason
    f.payload += static_cast<char>((code >> 8) & 0xFF);
    f.payload += static_cast<char>(code & 0xFF);
    f.payload += reason;
    f.payload_length = f.payload.size();
    return f;
}

WebSocketFrame WebSocketFrame::PingFrame(const std::string& payload) {
    WebSocketFrame f;
    f.opcode = WebSocketOpcode::Ping;
    f.payload = payload;
    f.payload_length = payload.size();
    return f;
}

WebSocketFrame WebSocketFrame::PongFrame(const std::string& payload) {
    WebSocketFrame f;
    f.opcode = WebSocketOpcode::Pong;
    f.payload = payload;
    f.payload_length = payload.size();
    return f;
}
