#pragma once

#include "common.h"
#include "config/server_config.h"
#include <nghttp2/nghttp2.h>
// <vector>, <cstdint> provided by common.h (via server_config.h)

// HTTP/2 SETTINGS frame helpers for the OUTBOUND H2 client. The server-side
// H2 stack uses its own constants table in include/http2/http2_constants.h;
// this header is the upstream-side counterpart that converts a per-upstream
// `Http2UpstreamConfig` snapshot into the nghttp2 settings array sent in
// the client preface.
namespace UPSTREAM_H2_SETTINGS {

inline std::vector<nghttp2_settings_entry> BuildSettingsArray(
    const Http2UpstreamConfig& cfg)
{
    std::vector<nghttp2_settings_entry> out;
    out.reserve(5);
    out.push_back({NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,
                    cfg.initial_window_size});
    out.push_back({NGHTTP2_SETTINGS_MAX_FRAME_SIZE,
                    cfg.max_frame_size});
    out.push_back({NGHTTP2_SETTINGS_HEADER_TABLE_SIZE,
                    cfg.header_table_size});
    // nghttp2 defaults this to UINT32_MAX (unbounded). Explicit cap
    // bounds peer header blocks (RFC 9113 §6.5.2).
    out.push_back({NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE,
                    cfg.max_header_list_size});
    out.push_back({NGHTTP2_SETTINGS_ENABLE_PUSH, 0});
    return out;
}

}  // namespace UPSTREAM_H2_SETTINGS
