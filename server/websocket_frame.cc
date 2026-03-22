#include "ws/websocket_frame.h"
#include "ws/utf8_validate.h"

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

    // RFC 6455 §7.4: only specific codes may appear on the wire.
    // Valid: 1000-1003, 1007-1014 (IANA), 3000-4999 (private use).
    // Invalid: 1004-1006, 1015, 1016-2999, >4999 — replace with 1000.
    bool valid_code = (code >= 1000 && code <= 1003) ||
                      (code >= 1007 && code <= 1014) ||
                      (code >= 3000 && code <= 4999);
    if (!valid_code) {
        code = 1000;
    }

    // Close frame payload: 2-byte status code + optional reason
    // RFC 6455 §5.5: control frame payload max 125 bytes (2 for code + up to 123 for reason)
    f.payload += static_cast<char>((code >> 8) & 0xFF);
    f.payload += static_cast<char>(code & 0xFF);

    // Truncate reason to fit 123-byte limit, respecting UTF-8 boundaries.
    // If byte at the cut point is a continuation byte (10xxxxxx), back up to
    // the lead byte to avoid splitting a multi-byte codepoint.
    std::string trimmed_reason = reason;
    if (trimmed_reason.size() > 123) {
        size_t cut = 123;
        // Back up if we'd split a multi-byte character
        while (cut > 0 && (static_cast<uint8_t>(trimmed_reason[cut]) & 0xC0) == 0x80) {
            --cut;
        }
        // 'cut' now points to a lead byte — exclude it if it starts a multi-byte
        // sequence that extends past byte 122
        if (cut > 0) {
            uint8_t lead = static_cast<uint8_t>(trimmed_reason[cut]);
            size_t codepoint_len = 1;
            if ((lead & 0xE0) == 0xC0) codepoint_len = 2;
            else if ((lead & 0xF0) == 0xE0) codepoint_len = 3;
            else if ((lead & 0xF8) == 0xF0) codepoint_len = 4;
            if (cut + codepoint_len > 123) {
                // This codepoint would be incomplete — exclude it
                trimmed_reason = trimmed_reason.substr(0, cut);
            } else {
                trimmed_reason = trimmed_reason.substr(0, cut + codepoint_len);
            }
        } else {
            trimmed_reason.clear();
        }
    }
    // RFC 6455 §7.4.1: close reason must be valid UTF-8.
    // Validate after truncation to prevent emitting protocol-invalid frames.
    if (!trimmed_reason.empty() && !IsValidUtf8(trimmed_reason)) {
        trimmed_reason.clear();  // Drop invalid reason, keep the close code
    }
    f.payload += trimmed_reason;

    f.payload_length = f.payload.size();
    return f;
}

WebSocketFrame WebSocketFrame::PingFrame(const std::string& payload) {
    WebSocketFrame f;
    f.opcode = WebSocketOpcode::Ping;
    // RFC 6455 §5.5: control frame payload max 125 bytes
    f.payload = payload.size() > 125 ? payload.substr(0, 125) : payload;
    f.payload_length = f.payload.size();
    return f;
}

WebSocketFrame WebSocketFrame::PongFrame(const std::string& payload) {
    WebSocketFrame f;
    f.opcode = WebSocketOpcode::Pong;
    // RFC 6455 §5.5: control frame payload max 125 bytes
    f.payload = payload.size() > 125 ? payload.substr(0, 125) : payload;
    f.payload_length = f.payload.size();
    return f;
}
