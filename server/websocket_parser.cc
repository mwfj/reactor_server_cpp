#include "ws/websocket_parser.h"
#include <algorithm>

WebSocketParser::WebSocketParser() {}

size_t WebSocketParser::Parse(const char* data, size_t len) {
    buffer_.append(data, len);
    size_t total_consumed = 0;
    size_t offset = 0;  // track position within buffer_ to avoid O(N^2) erase

    auto buf_remaining = [&]() -> size_t { return buffer_.size() - offset; };

    while (buf_remaining() > 0 && !has_error_) {
        switch (state_) {
            case State::ReadHeader: {
                if (buf_remaining() < 2) goto done;

                uint8_t byte1 = static_cast<uint8_t>(buffer_[offset]);
                uint8_t byte2 = static_cast<uint8_t>(buffer_[offset + 1]);

                current_ = WebSocketFrame{};
                current_.fin = (byte1 & 0x80) != 0;
                current_.opcode = static_cast<WebSocketOpcode>(byte1 & 0x0F);
                current_.masked = (byte2 & 0x80) != 0;

                uint8_t len7 = byte2 & 0x7F;
                offset += 2;
                total_consumed += 2;

                // RFC 6455 §5.2: RSV bits must be 0 unless extension negotiated
                if ((byte1 & 0x70) != 0) {
                    has_error_ = true;
                    error_message_ = "RSV bits set without extension negotiation";
                    goto done;
                }

                // RFC 6455 §5.1: server MUST close on unmasked client frames
                if (!current_.masked) {
                    has_error_ = true;
                    error_message_ = "Client frame not masked";
                    goto done;
                }

                // RFC 6455 §5.2: reject reserved opcodes (0x3-0x7 data, 0xB-0xF control)
                uint8_t op = static_cast<uint8_t>(current_.opcode);
                bool is_valid_opcode = (op <= 0x2) || (op >= 0x8 && op <= 0xA);
                if (!is_valid_opcode) {
                    has_error_ = true;
                    error_message_ = "Reserved opcode";
                    goto done;
                }

                // Validate: control frames must not be fragmented and <= 125 bytes
                if (op >= 0x8) {
                    if (!current_.fin) {
                        has_error_ = true;
                        error_message_ = "Fragmented control frame";
                        goto done;
                    }
                    if (len7 > 125) {
                        has_error_ = true;
                        error_message_ = "Control frame payload > 125 bytes";
                        goto done;
                    }
                }

                if (len7 <= 125) {
                    current_.payload_length = len7;
                    if (max_payload_size_ > 0 && current_.payload_length > max_payload_size_) {
                        has_error_ = true;
                        error_message_ = "Frame payload exceeds maximum size";
                        goto done;
                    }
                    state_ = current_.masked ? State::ReadMaskingKey : State::ReadPayload;
                } else if (len7 == 126) {
                    state_ = State::ReadExtendedLen16;
                } else {
                    state_ = State::ReadExtendedLen64;
                }
                break;
            }

            case State::ReadExtendedLen16: {
                if (buf_remaining() < 2) goto done;
                uint16_t len16 = (static_cast<uint8_t>(buffer_[offset]) << 8) |
                                  static_cast<uint8_t>(buffer_[offset + 1]);
                current_.payload_length = len16;
                offset += 2;
                total_consumed += 2;
                if (max_payload_size_ > 0 && current_.payload_length > max_payload_size_) {
                    has_error_ = true;
                    error_message_ = "Frame payload exceeds maximum size";
                    goto done;
                }
                state_ = current_.masked ? State::ReadMaskingKey : State::ReadPayload;
                break;
            }

            case State::ReadExtendedLen64: {
                if (buf_remaining() < 8) goto done;
                // RFC 6455 §5.2: most significant bit must be 0
                if (static_cast<uint8_t>(buffer_[offset]) & 0x80) {
                    has_error_ = true;
                    error_message_ = "64-bit payload length has MSB set";
                    goto done;
                }
                uint64_t len64 = 0;
                for (int i = 0; i < 8; i++) {
                    len64 = (len64 << 8) | static_cast<uint8_t>(buffer_[offset + i]);
                }
                current_.payload_length = len64;
                offset += 8;
                total_consumed += 8;
                if (max_payload_size_ > 0 && current_.payload_length > max_payload_size_) {
                    has_error_ = true;
                    error_message_ = "Frame payload exceeds maximum size";
                    goto done;
                }
                state_ = current_.masked ? State::ReadMaskingKey : State::ReadPayload;
                break;
            }

            case State::ReadMaskingKey: {
                if (buf_remaining() < 4) goto done;
                std::memcpy(current_.masking_key, buffer_.data() + offset, 4);
                offset += 4;
                total_consumed += 4;
                state_ = State::ReadPayload;
                payload_read_ = 0;
                break;
            }

            case State::ReadPayload: {
                size_t remaining = current_.payload_length - payload_read_;
                if (remaining == 0) {
                    // Zero-length payload (e.g., empty ping/pong) — no unmasking needed
                    completed_.push_back(std::move(current_));
                    state_ = State::ReadHeader;
                    payload_read_ = 0;
                    break;
                }

                size_t available = std::min(remaining, buf_remaining());
                if (available == 0) goto done;

                current_.payload.append(buffer_.data() + offset, available);
                offset += available;
                total_consumed += available;
                payload_read_ += available;

                if (payload_read_ == current_.payload_length) {
                    // Unmask once, only at completion
                    if (current_.masked) {
                        Unmask(current_.payload, current_.masking_key);
                    }
                    completed_.push_back(std::move(current_));
                    state_ = State::ReadHeader;
                    payload_read_ = 0;
                }
                break;
            }
        }
    }

done:
    // Single erase of all consumed bytes — O(N) total instead of O(N^2)
    if (offset > 0) {
        buffer_.erase(0, offset);
    }

    return total_consumed;
}

WebSocketFrame WebSocketParser::NextFrame() {
    WebSocketFrame frame = std::move(completed_.front());
    completed_.pop_front();
    return frame;
}

void WebSocketParser::Unmask(std::string& data, const uint8_t key[4], size_t offset) {
    for (size_t i = offset; i < data.size(); i++) {
        data[i] ^= key[(i - offset) % 4];
    }
}
