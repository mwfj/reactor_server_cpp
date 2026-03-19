#include "ws/websocket_connection.h"

WebSocketConnection::WebSocketConnection(std::shared_ptr<ConnectionHandler> conn)
    : conn_(std::move(conn)) {}

void WebSocketConnection::OnMessage(MessageHandler handler) { message_handler_ = std::move(handler); }
void WebSocketConnection::OnClose(CloseHandler handler) { close_handler_ = std::move(handler); }
void WebSocketConnection::OnPing(PingHandler handler) { ping_handler_ = std::move(handler); }
void WebSocketConnection::OnError(ErrorHandler handler) { error_handler_ = std::move(handler); }

void WebSocketConnection::SendText(const std::string& message) {
    SendFrame(WebSocketFrame::TextFrame(message));
}

void WebSocketConnection::SendBinary(const std::string& data) {
    SendFrame(WebSocketFrame::BinaryFrame(data));
}

void WebSocketConnection::SendClose(uint16_t code, const std::string& reason) {
    SendFrame(WebSocketFrame::CloseFrame(code, reason));
    is_open_ = false;
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

    if (parser_.HasError()) {
        if (error_handler_) {
            error_handler_(*this, parser_.GetError());
        }
        SendClose(1002, "Protocol error");
        return;
    }

    while (parser_.HasFrame()) {
        ProcessFrame(parser_.NextFrame());
    }
}

void WebSocketConnection::ProcessFrame(const WebSocketFrame& frame) {
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
                return;
            }

            if (frame.fin) {
                // Complete single-frame message
                if (message_handler_) {
                    message_handler_(*this, frame.payload,
                                     frame.opcode == WebSocketOpcode::Binary);
                }
            } else {
                // First fragment
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
                return;
            }
            fragment_buffer_ += frame.payload;
            if (frame.fin) {
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
            uint16_t code = 1000;
            std::string reason;
            if (frame.payload.size() >= 2) {
                code = (static_cast<uint8_t>(frame.payload[0]) << 8) |
                        static_cast<uint8_t>(frame.payload[1]);
                if (frame.payload.size() > 2) {
                    reason = frame.payload.substr(2);
                }
            }
            // Echo close frame back (close handshake)
            if (is_open_) {
                SendClose(code, reason);
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
