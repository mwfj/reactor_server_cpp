#include "ws/websocket_connection.h"
#include "ws/utf8_validate.h"

WebSocketConnection::WebSocketConnection(std::shared_ptr<ConnectionHandler> conn)
    : conn_(std::move(conn)) {}

void WebSocketConnection::OnMessage(MessageCallback callback) { message_callback_ = std::move(callback); }
void WebSocketConnection::OnClose(CloseCallback callback) { close_callback_ = std::move(callback); }
void WebSocketConnection::OnPing(PingCallback callback) { ping_callback_ = std::move(callback); }
void WebSocketConnection::OnError(ErrorCallback callback) { error_callback_ = std::move(callback); }

void WebSocketConnection::SendText(const std::string& message) {
    if (close_sent_ || !is_open_) return;  // No data frames after close
    // RFC 6455 §5.6: text frames must contain valid UTF-8.
    // Validate outbound text to prevent emitting protocol-invalid frames
    // that would cause compliant clients to close with 1007.
    if (!IsValidUtf8(message)) {
        if (error_callback_) error_callback_(*this, "Outbound text message is not valid UTF-8");
        return;
    }
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
    sent_close_code_ = code;
    sent_close_reason_ = reason;
    // Keep is_open_ true so OnRawData can receive the peer's Close reply.
    // Arm a deadline — if the peer doesn't reply within this window, the
    // timer scanner will force-close. Do NOT call CloseAfterWrite here:
    // that would ForceClose as soon as the Close frame drains, before the
    // peer has a chance to send their Close reply (resulting in 1006).
    // The Close frame drains naturally via the write path. close_sent_
    // prevents new data frames (SendText/SendBinary check it).
    if (conn_) {
        conn_->SetDeadline(std::chrono::steady_clock::now() + std::chrono::seconds(5));
    }
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

void WebSocketConnection::NotifyTransportClose() {
    if (!is_open_) return;
    is_open_ = false;
    // Always report 1006 (Abnormal Closure) for transport-level disconnects.
    // Even if we sent a Close frame, the peer never completed the handshake
    // (no Close reply received), so RFC 6455 classifies this as abnormal.
    if (close_callback_) {
        close_callback_(*this, 1006, "Transport closed");
    }
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
        if (!close_sent_) {
            if (error_callback_) {
                error_callback_(*this, parser_.GetError());
            }
            // Use the correct close code based on the error type
            std::string err_msg = parser_.GetError();
            uint16_t close_code = 1002;  // Default: protocol error
            if (err_msg.find("exceeds maximum size") != std::string::npos) {
                close_code = 1009;  // Message Too Big
            }
            SendClose(close_code, err_msg.substr(0, 123));
        }
        // Reset the parser to prevent unbounded buffer growth.
        // Parse() appends to buffer_ before checking has_error_, so without
        // a reset, every subsequent call accumulates data in memory until
        // the transport times out. Also allows receiving the peer's Close reply.
        parser_.ResetAfterError();
        return;
    }
}

void WebSocketConnection::ProcessFrame(const WebSocketFrame& frame) {
    // If we've sent a close frame, only accept Close replies and Ping/Pong control frames.
    // RFC 6455 §5.5.2: endpoint MUST respond to Ping until Close is received.
    // Discard data/continuation frames during the close handshake.
    if (close_sent_ && frame.opcode != WebSocketOpcode::Close
        && frame.opcode != WebSocketOpcode::Ping
        && frame.opcode != WebSocketOpcode::Pong) {
        return;
    }

    switch (frame.opcode) {
        // Text and Binary share the same processing logic: both are data frames
        // subject to the same fragmentation, reassembly, and delivery rules.
        // The only difference is the is_binary flag passed to the message callback.
        case WebSocketOpcode::Text:
        case WebSocketOpcode::Binary: {
            // IMPORTANT: Receiving a new Text/Binary frame while in_fragment_ is true
            // is a protocol error per RFC 6455 -- send Close(1002) and return
            if (in_fragment_) {
                if (error_callback_) {
                    error_callback_(*this, "New data frame received during fragmented message");
                }
                SendClose(1002, "Protocol error: interleaved data frames");
                return;
            }

            if (frame.fin) {
                // Complete single-frame message
                // RFC 6455 §5.6: text frames must contain valid UTF-8
                if (frame.opcode == WebSocketOpcode::Text && !IsValidUtf8(frame.payload)) {
                    if (error_callback_) error_callback_(*this, "Invalid UTF-8 in text message");
                    SendClose(1007, "Invalid UTF-8");
                    return;
                }
                if (message_callback_) {
                    message_callback_(*this, frame.payload,
                                     frame.opcode == WebSocketOpcode::Binary);
                }
            } else {
                // First fragment
                if (max_message_size_ > 0 && frame.payload.size() > max_message_size_) {
                    if (error_callback_) error_callback_(*this, "Message exceeds maximum size");
                    SendClose(1009, "Message too big");
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
                if (error_callback_) error_callback_(*this, "Unexpected continuation frame");
                SendClose(1002, "Protocol error: unexpected continuation");
                return;
            }
            if (max_message_size_ > 0 &&
                (fragment_buffer_.size() >= max_message_size_ ||
                 frame.payload.size() > max_message_size_ - fragment_buffer_.size())) {
                if (error_callback_) error_callback_(*this, "Message exceeds maximum size");
                SendClose(1009, "Message too big");
                in_fragment_ = false;
                fragment_buffer_.clear();
                return;
            }
            fragment_buffer_ += frame.payload;
            if (frame.fin) {
                // RFC 6455 §5.6: validate reassembled text messages
                if (fragment_opcode_ == WebSocketOpcode::Text && !IsValidUtf8(fragment_buffer_)) {
                    if (error_callback_) error_callback_(*this, "Invalid UTF-8 in text message");
                    SendClose(1007, "Invalid UTF-8");
                    in_fragment_ = false;
                    fragment_buffer_.clear();
                    return;
                }
                if (message_callback_) {
                    message_callback_(*this, fragment_buffer_,
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
                if (error_callback_) error_callback_(*this, "Invalid close frame: 1-byte payload");
                // Set is_open_ = false BEFORE SendClose so that if the send
                // fails synchronously (→ CallCloseCb → NotifyTransportClose),
                // the transport-close path sees is_open_ == false and skips,
                // preventing a duplicate close callback.
                is_open_ = false;
                SendClose(1002, "Protocol error");
                // The peer already sent their Close frame — the handshake is
                // complete once we send ours. Close the transport immediately
                // instead of waiting 5s for a reply that won't come.
                if (conn_) conn_->CloseAfterWrite();
                if (close_callback_) close_callback_(*this, 1002, "Protocol error");
                return;
            }
            // If payload is empty, echo an empty close frame (no code/reason)
            if (frame.payload.empty()) {
                is_open_ = false;
                if (!close_sent_) {
                    // Send empty close frame to match
                    WebSocketFrame empty_close;
                    empty_close.opcode = WebSocketOpcode::Close;
                    empty_close.fin = true;
                    SendFrame(empty_close);
                    close_sent_ = true;
                }
                if (conn_) conn_->CloseAfterWrite();
                if (close_callback_) close_callback_(*this, 1005, "");  // 1005 = no status received
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
                if (error_callback_) error_callback_(*this, "Close reason is not valid UTF-8");
                is_open_ = false;
                SendClose(1007, "Invalid UTF-8 in close reason");
                // The peer already sent their Close frame — handshake complete.
                // Close transport immediately instead of waiting 5s.
                if (conn_) conn_->CloseAfterWrite();
                if (close_callback_) close_callback_(*this, 1007, "Invalid UTF-8 in close reason");
                return;
            }
            if (!WebSocketFrame::IsValidCloseCode(code) && frame.payload.size() >= 2) {
                // Invalid code on wire — protocol error, close with 1002
                code = 1002;
                reason = "Invalid close code";
            }
            // Set is_open_ = false BEFORE sending the reply so that a
            // synchronous send failure (→ NotifyTransportClose) is a no-op,
            // preventing duplicate close callbacks.
            is_open_ = false;
            // Echo close frame back if we haven't sent one yet (peer-initiated close).
            // If close_sent_ is already true, this is the peer's reply to our close.
            if (!close_sent_) {
                // 1010 ("Missing Extension") is client-only per RFC 6455 §7.4.1.
                // Valid to receive from a client, but the server must not echo it.
                // Acknowledge with 1000 (Normal Closure) instead.
                uint16_t echo_code = (code == 1010) ? 1000 : code;
                SendClose(echo_code, reason);
            }
            // Close the TCP transport — handshake is complete (both sides sent close).
            // This runs on the reactor thread (via OnRawData callback chain),
            // so CloseAfterWrite is safe to call inline.
            if (conn_) {
                conn_->CloseAfterWrite();
            }
            if (close_callback_) {
                close_callback_(*this, code, reason);
            }
            break;
        }

        case WebSocketOpcode::Ping: {
            // Auto-respond with pong
            SendPong(frame.payload);
            if (ping_callback_) {
                ping_callback_(*this, frame.payload);
            }
            break;
        }

        case WebSocketOpcode::Pong: {
            // Pong received -- no action needed (keepalive ack)
            break;
        }

        default: {
            if (error_callback_) {
                error_callback_(*this, "Unknown opcode");
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
