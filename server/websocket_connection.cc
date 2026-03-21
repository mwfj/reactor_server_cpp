#include "ws/websocket_connection.h"

// RFC 3629 UTF-8 validation
// RFC 3629 UTF-8 validation with full codepoint range checks:
// - Rejects overlong encodings (e.g., 0xC0 0x80 for U+0000)
// - Rejects surrogates U+D800-U+DFFF
// - Rejects codepoints > U+10FFFF
static bool IsValidUtf8(const std::string& data) {
    size_t i = 0;
    while (i < data.size()) {
        uint8_t c = static_cast<uint8_t>(data[i]);
        uint32_t codepoint;
        size_t len;

        if (c <= 0x7F) {
            i++; continue;
        } else if ((c & 0xE0) == 0xC0) {
            len = 2;
            if (c < 0xC2) return false;  // overlong
            codepoint = c & 0x1F;
        } else if ((c & 0xF0) == 0xE0) {
            len = 3;
            codepoint = c & 0x0F;
        } else if ((c & 0xF8) == 0xF0) {
            len = 4;
            codepoint = c & 0x07;
        } else {
            return false;  // invalid lead byte
        }

        if (i + len > data.size()) return false;

        for (size_t j = 1; j < len; j++) {
            uint8_t cb = static_cast<uint8_t>(data[i + j]);
            if ((cb & 0xC0) != 0x80) return false;
            codepoint = (codepoint << 6) | (cb & 0x3F);
        }

        // Reject surrogates (U+D800-U+DFFF) and codepoints > U+10FFFF
        if (codepoint >= 0xD800 && codepoint <= 0xDFFF) return false;
        if (codepoint > 0x10FFFF) return false;

        // Reject overlong encodings
        if (len == 3 && codepoint < 0x0800) return false;
        if (len == 4 && codepoint < 0x10000) return false;

        i += len;
    }
    return true;
}

WebSocketConnection::WebSocketConnection(std::shared_ptr<ConnectionHandler> conn)
    : conn_(std::move(conn)) {}

void WebSocketConnection::OnMessage(MessageHandler handler) { message_handler_ = std::move(handler); }
void WebSocketConnection::OnClose(CloseHandler handler) { close_handler_ = std::move(handler); }
void WebSocketConnection::OnPing(PingHandler handler) { ping_handler_ = std::move(handler); }
void WebSocketConnection::OnError(ErrorHandler handler) { error_handler_ = std::move(handler); }

void WebSocketConnection::SendText(const std::string& message) {
    if (close_sent_ || !is_open_) return;  // No data frames after close
    SendFrame(WebSocketFrame::TextFrame(message));
}

void WebSocketConnection::SendBinary(const std::string& data) {
    if (close_sent_ || !is_open_) return;  // No data frames after close
    SendFrame(WebSocketFrame::BinaryFrame(data));
}

void WebSocketConnection::SendClose(uint16_t code, const std::string& reason) {
    if (close_sent_) return;  // Already sent a close frame
    SendFrame(WebSocketFrame::CloseFrame(code, reason));
    close_sent_ = true;
    // Keep is_open_ true so OnRawData can still receive the peer's close reply.
    // The connection will be closed when we receive the peer's close frame in
    // ProcessFrame, or by the idle timeout if the peer never responds.
}

void WebSocketConnection::SendPing(const std::string& payload) {
    SendFrame(WebSocketFrame::PingFrame(payload));
}

void WebSocketConnection::SendPong(const std::string& payload) {
    SendFrame(WebSocketFrame::PongFrame(payload));
}

int WebSocketConnection::fd() const {
    return conn_->fd();
}

void WebSocketConnection::OnRawData(const std::string& data) {
    if (!is_open_) return;

    parser_.Parse(data.data(), data.size());

    // Drain any valid frames that were parsed BEFORE the error.
    // The parser may have pushed complete frames before encountering a malformed one.
    while (parser_.HasFrame() && is_open_) {
        ProcessFrame(parser_.NextFrame());
    }

    if (parser_.HasError() && is_open_) {
        if (error_handler_) {
            error_handler_(*this, parser_.GetError());
        }
        // Use the correct close code based on the error type
        std::string err_msg = parser_.GetError();
        uint16_t close_code = 1002;  // Default: protocol error
        if (err_msg.find("exceeds maximum size") != std::string::npos) {
            close_code = 1009;  // Message Too Big
        }
        SendClose(close_code, err_msg.substr(0, 123));
        if (conn_) conn_->CloseAfterWrite();
        return;
    }
}

void WebSocketConnection::ProcessFrame(const WebSocketFrame& frame) {
    // If we've sent a close frame, only accept the peer's Close reply — discard data/continuation
    if (close_sent_ && frame.opcode != WebSocketOpcode::Close) {
        return;  // Discard non-close frames during close handshake
    }

    switch (frame.opcode) {
        case WebSocketOpcode::Text:
        case WebSocketOpcode::Binary: {
            // IMPORTANT: Receiving a new Text/Binary frame while in_fragment_ is true
            // is a protocol error per RFC 6455 -- send Close(1002) and return
            if (in_fragment_) {
                if (error_handler_) {
                    error_handler_(*this, "New data frame received during fragmented message");
                }
                SendClose(1002, "Protocol error: interleaved data frames");
                if (conn_) conn_->CloseAfterWrite();
                return;
            }

            if (frame.fin) {
                // Complete single-frame message
                // RFC 6455 §5.6: text frames must contain valid UTF-8
                if (frame.opcode == WebSocketOpcode::Text && !IsValidUtf8(frame.payload)) {
                    if (error_handler_) error_handler_(*this, "Invalid UTF-8 in text message");
                    SendClose(1007, "Invalid UTF-8");
                    if (conn_) conn_->CloseAfterWrite();
                    return;
                }
                if (message_handler_) {
                    message_handler_(*this, frame.payload,
                                     frame.opcode == WebSocketOpcode::Binary);
                }
            } else {
                // First fragment
                if (max_message_size_ > 0 && frame.payload.size() > max_message_size_) {
                    if (error_handler_) error_handler_(*this, "Message exceeds maximum size");
                    SendClose(1009, "Message too big");
                    if (conn_) conn_->CloseAfterWrite();
                    in_fragment_ = false;
                    fragment_buffer_.clear();
                    return;
                }
                in_fragment_ = true;
                fragment_opcode_ = frame.opcode;
                fragment_buffer_ = frame.payload;
            }
            break;
        }

        case WebSocketOpcode::Continuation: {
            if (!in_fragment_) {
                if (error_handler_) error_handler_(*this, "Unexpected continuation frame");
                SendClose(1002, "Protocol error: unexpected continuation");
                if (conn_) conn_->CloseAfterWrite();
                return;
            }
            if (max_message_size_ > 0 &&
                (fragment_buffer_.size() >= max_message_size_ ||
                 frame.payload.size() > max_message_size_ - fragment_buffer_.size())) {
                if (error_handler_) error_handler_(*this, "Message exceeds maximum size");
                SendClose(1009, "Message too big");
                if (conn_) conn_->CloseAfterWrite();
                in_fragment_ = false;
                fragment_buffer_.clear();
                return;
            }
            fragment_buffer_ += frame.payload;
            if (frame.fin) {
                // RFC 6455 §5.6: validate reassembled text messages
                if (fragment_opcode_ == WebSocketOpcode::Text && !IsValidUtf8(fragment_buffer_)) {
                    if (error_handler_) error_handler_(*this, "Invalid UTF-8 in text message");
                    SendClose(1007, "Invalid UTF-8");
                    if (conn_) conn_->CloseAfterWrite();
                    in_fragment_ = false;
                    fragment_buffer_.clear();
                    return;
                }
                if (message_handler_) {
                    message_handler_(*this, fragment_buffer_,
                                     fragment_opcode_ == WebSocketOpcode::Binary);
                }
                in_fragment_ = false;
                fragment_buffer_.clear();
            }
            break;
        }

        case WebSocketOpcode::Close: {
            // RFC 6455 §7.1.5: close body must be 0 bytes or >= 2 bytes
            if (frame.payload.size() == 1) {
                if (error_handler_) error_handler_(*this, "Invalid close frame: 1-byte payload");
                SendClose(1002, "Protocol error");
                if (conn_) conn_->CloseAfterWrite();
                return;
            }
            // If payload is empty, echo an empty close frame (no code/reason)
            if (frame.payload.empty()) {
                if (!close_sent_) {
                    // Send empty close frame to match
                    WebSocketFrame empty_close;
                    empty_close.opcode = WebSocketOpcode::Close;
                    empty_close.fin = true;
                    SendFrame(empty_close);
                    close_sent_ = true;
                }
                is_open_ = false;
                if (conn_) conn_->CloseAfterWrite();
                if (close_handler_) close_handler_(*this, 1005, "");  // 1005 = no status received
                break;
            }

            uint16_t code = 1000;
            std::string reason;
            if (frame.payload.size() >= 2) {
                code = (static_cast<uint8_t>(frame.payload[0]) << 8) |
                        static_cast<uint8_t>(frame.payload[1]);
                if (frame.payload.size() > 2) {
                    reason = frame.payload.substr(2);
                }
            }
            // RFC 6455 §7.1.6: close reason must be valid UTF-8
            if (!reason.empty() && !IsValidUtf8(reason)) {
                if (error_handler_) error_handler_(*this, "Close reason is not valid UTF-8");
                SendClose(1007, "Invalid UTF-8 in close reason");
                if (conn_) conn_->CloseAfterWrite();
                return;
            }
            // Validate close code per RFC 6455 Section 7.4 + IANA registry.
            // Valid ranges: 1000-1003, 1007-1014 (IANA registered), 3000-4999 (private use).
            // Codes 1004-1006, 1015 are reserved and must not appear on the wire.
            // Unknown codes in valid ranges are echoed as-is per RFC 6455 §7.4.
            bool valid_code = (code >= 1000 && code <= 1003) ||
                              (code >= 1007 && code <= 1014) ||
                              (code >= 3000 && code <= 4999);
            if (!valid_code && frame.payload.size() >= 2) {
                // Invalid code on wire — protocol error, close with 1002
                code = 1002;
                reason = "Invalid close code";
            }
            // Echo close frame back if we haven't sent one yet (peer-initiated close).
            // If close_sent_ is already true, this is the peer's reply to our close.
            if (!close_sent_) {
                SendClose(code, reason);
            }
            is_open_ = false;
            // Close the TCP transport — handshake is complete (both sides sent close).
            // This runs on the reactor thread (via OnRawData callback chain),
            // so CloseAfterWrite is safe to call inline.
            if (conn_) {
                conn_->CloseAfterWrite();
            }
            if (close_handler_) {
                close_handler_(*this, code, reason);
            }
            break;
        }

        case WebSocketOpcode::Ping: {
            // Auto-respond with pong
            SendPong(frame.payload);
            if (ping_handler_) {
                ping_handler_(*this, frame.payload);
            }
            break;
        }

        case WebSocketOpcode::Pong: {
            // Pong received -- no action needed (keepalive ack)
            break;
        }

        default: {
            if (error_handler_) {
                error_handler_(*this, "Unknown opcode");
            }
            break;
        }
    }
}

void WebSocketConnection::SendFrame(const WebSocketFrame& frame) {
    if (!conn_) return;
    std::string wire = frame.Serialize();
    conn_->SendRaw(wire.data(), wire.size());
}
