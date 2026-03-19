#pragma once

#include "ws/websocket_frame.h"
#include <deque>
#include <string>
#include <cstring>

class WebSocketParser {
public:
    WebSocketParser();

    // Feed raw bytes. Returns number of bytes consumed.
    size_t Parse(const char* data, size_t len);

    // Check if complete frames are available
    bool HasFrame() const { return !completed_.empty(); }

    // Dequeue next complete frame
    WebSocketFrame NextFrame();

    // Error state
    bool HasError() const { return has_error_; }
    std::string GetError() const { return error_message_; }

private:
    enum class State {
        ReadHeader,
        ReadExtendedLen16,
        ReadExtendedLen64,
        ReadMaskingKey,
        ReadPayload,
    };

    State state_ = State::ReadHeader;
    WebSocketFrame current_;
    std::deque<WebSocketFrame> completed_;
    std::string buffer_;
    size_t payload_read_ = 0;
    bool has_error_ = false;
    std::string error_message_;

    // Unmask payload in-place
    static void Unmask(std::string& data, const uint8_t key[4], size_t offset = 0);
};
