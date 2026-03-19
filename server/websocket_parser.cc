#include "ws/websocket_parser.h"
#include <algorithm>

WebSocketParser::WebSocketParser() {}

size_t WebSocketParser::Parse(const char* data, size_t len) {
    buffer_.append(data, len);
    size_t total_consumed = 0;

    while (!buffer_.empty() && !has_error_) {
        switch (state_) {
            case State::ReadHeader: {
                if (buffer_.size() < 2) return total_consumed;

                uint8_t byte1 = static_cast<uint8_t>(buffer_[0]);
                uint8_t byte2 = static_cast<uint8_t>(buffer_[1]);

                current_ = WebSocketFrame{};
                current_.fin = (byte1 & 0x80) != 0;
                current_.opcode = static_cast<WebSocketOpcode>(byte1 & 0x0F);
                current_.masked = (byte2 & 0x80) != 0;

                uint8_t len7 = byte2 & 0x7F;
                buffer_.erase(0, 2);
                total_consumed += 2;

                // RFC 6455 §5.2: RSV bits must be 0 unless extension negotiated
                if ((byte1 & 0x70) != 0) {
                    has_error_ = true;
                    error_message_ = "RSV bits set without extension negotiation";
                    return total_consumed;
                }

                // RFC 6455 §5.1: server MUST close on unmasked client frames
                if (!current_.masked) {
                    has_error_ = true;
                    error_message_ = "Client frame not masked";
                    return total_consumed;
                }

                // Validate: control frames must not be fragmented and <= 125 bytes
                if (static_cast<uint8_t>(current_.opcode) >= 0x8) {
                    if (!current_.fin) {
                        has_error_ = true;
                        error_message_ = "Fragmented control frame";
                        return total_consumed;
                    }
                    if (len7 > 125) {
                        has_error_ = true;
                        error_message_ = "Control frame payload > 125 bytes";
                        return total_consumed;
                    }
                }

                if (len7 <= 125) {
                    current_.payload_length = len7;
                    state_ = current_.masked ? State::ReadMaskingKey : State::ReadPayload;
                } else if (len7 == 126) {
                    state_ = State::ReadExtendedLen16;
                } else {
                    state_ = State::ReadExtendedLen64;
                }
                break;
            }

            case State::ReadExtendedLen16: {
                if (buffer_.size() < 2) return total_consumed;
                uint16_t len16 = (static_cast<uint8_t>(buffer_[0]) << 8) |
                                  static_cast<uint8_t>(buffer_[1]);
                current_.payload_length = len16;
                buffer_.erase(0, 2);
                total_consumed += 2;
                state_ = current_.masked ? State::ReadMaskingKey : State::ReadPayload;
                break;
            }

            case State::ReadExtendedLen64: {
                if (buffer_.size() < 8) return total_consumed;
                uint64_t len64 = 0;
                for (int i = 0; i < 8; i++) {
                    len64 = (len64 << 8) | static_cast<uint8_t>(buffer_[i]);
                }
                current_.payload_length = len64;
                buffer_.erase(0, 8);
                total_consumed += 8;
                state_ = current_.masked ? State::ReadMaskingKey : State::ReadPayload;
                break;
            }

            case State::ReadMaskingKey: {
                if (buffer_.size() < 4) return total_consumed;
                std::memcpy(current_.masking_key, buffer_.data(), 4);
                buffer_.erase(0, 4);
                total_consumed += 4;
                state_ = State::ReadPayload;
                payload_read_ = 0;
                break;
            }

            case State::ReadPayload: {
                size_t remaining = current_.payload_length - payload_read_;
                if (remaining == 0) {
                    // Unmask if needed
                    if (current_.masked) {
                        Unmask(current_.payload, current_.masking_key);
                    }
                    completed_.push_back(std::move(current_));
                    state_ = State::ReadHeader;
                    payload_read_ = 0;
                    break;
                }

                size_t available = std::min(remaining, buffer_.size());
                if (available == 0) return total_consumed;

                current_.payload.append(buffer_.data(), available);
                buffer_.erase(0, available);
                total_consumed += available;
                payload_read_ += available;

                if (payload_read_ == current_.payload_length) {
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
