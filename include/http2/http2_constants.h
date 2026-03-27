#pragma once

#include <cstdint>
#include <cstddef>

namespace HTTP2_CONSTANTS {

// Connection preface (RFC 9113 Section 3.4)
inline constexpr const char* CLIENT_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
inline constexpr size_t CLIENT_PREFACE_LEN = 24;

// Default SETTINGS values (RFC 9113 Section 6.5.2)
inline constexpr uint32_t DEFAULT_HEADER_TABLE_SIZE       = 4096;
inline constexpr uint32_t DEFAULT_MAX_CONCURRENT_STREAMS  = 100;
inline constexpr uint32_t DEFAULT_INITIAL_WINDOW_SIZE     = 65535;
inline constexpr uint32_t DEFAULT_MAX_FRAME_SIZE          = 16384;
inline constexpr uint32_t DEFAULT_MAX_HEADER_LIST_SIZE    = 65536;  // 64 KB

// Limits (RFC 9113 constraints)
inline constexpr uint32_t MIN_MAX_FRAME_SIZE              = 16384;
inline constexpr uint32_t MAX_MAX_FRAME_SIZE              = 16777215;
inline constexpr uint32_t MAX_WINDOW_SIZE                 = 2147483647;  // 2^31 - 1

// Flood protection thresholds (per sliding window interval)
inline constexpr int MAX_SETTINGS_PER_INTERVAL            = 100;
inline constexpr int MAX_PING_PER_INTERVAL                = 50;
inline constexpr int MAX_RST_STREAM_PER_INTERVAL          = 100;
inline constexpr int FLOOD_CHECK_INTERVAL_SEC             = 10;

// ALPN protocol identifiers
inline constexpr const char ALPN_H2[]     = "h2";
inline constexpr const char ALPN_HTTP11[] = "http/1.1";

// Error Codes (RFC 9113 Section 7) — subset used in project code.
// Avoids including nghttp2.h in files that only need error code values.
inline constexpr uint32_t ERROR_NO_ERROR          = 0x0;
inline constexpr uint32_t ERROR_PROTOCOL_ERROR    = 0x1;
inline constexpr uint32_t ERROR_INTERNAL_ERROR    = 0x2;
inline constexpr uint32_t ERROR_ENHANCE_YOUR_CALM = 0xB;

} // namespace HTTP2_CONSTANTS
