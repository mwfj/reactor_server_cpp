#pragma once

#include <cstdint>
#include <cstddef>

namespace HTTP2_CONSTANTS {

// Connection preface (RFC 9113 Section 3.4)
static constexpr const char* CLIENT_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
static constexpr size_t CLIENT_PREFACE_LEN = 24;

// Default SETTINGS values (RFC 9113 Section 6.5.2)
static constexpr uint32_t DEFAULT_HEADER_TABLE_SIZE       = 4096;
static constexpr uint32_t DEFAULT_MAX_CONCURRENT_STREAMS  = 100;
static constexpr uint32_t DEFAULT_INITIAL_WINDOW_SIZE     = 65535;
static constexpr uint32_t DEFAULT_MAX_FRAME_SIZE          = 16384;
static constexpr uint32_t DEFAULT_MAX_HEADER_LIST_SIZE    = 65536;  // 64 KB

// Limits (RFC 9113 constraints)
static constexpr uint32_t MIN_MAX_FRAME_SIZE              = 16384;
static constexpr uint32_t MAX_MAX_FRAME_SIZE              = 16777215;
static constexpr uint32_t MAX_WINDOW_SIZE                 = 2147483647;  // 2^31 - 1

// Flood protection thresholds (per sliding window interval)
static constexpr int MAX_SETTINGS_PER_INTERVAL            = 100;
static constexpr int MAX_PING_PER_INTERVAL                = 50;
static constexpr int MAX_RST_STREAM_PER_INTERVAL          = 100;
static constexpr int MAX_EMPTY_FRAMES_PER_INTERVAL        = 200;
static constexpr int FLOOD_CHECK_INTERVAL_SEC             = 10;

// ALPN protocol identifiers
static constexpr const char ALPN_H2[]     = "h2";
static constexpr const char ALPN_HTTP11[] = "http/1.1";

} // namespace HTTP2_CONSTANTS
