#pragma once

#include "http/streaming_response_sender.h"

inline const char* StreamingAbortReasonToString(
    HTTP_STREAMING_NAMESPACE::StreamingResponseSender::AbortReason reason) {
    using AbortReason =
        HTTP_STREAMING_NAMESPACE::StreamingResponseSender::AbortReason;
    switch (reason) {
        case AbortReason::UPSTREAM_TRUNCATED: return "upstream_truncated";
        case AbortReason::UPSTREAM_TIMEOUT: return "upstream_timeout";
        case AbortReason::UPSTREAM_ERROR: return "upstream_error";
        case AbortReason::CLIENT_DISCONNECT: return "client_disconnect";
        case AbortReason::TIMER_EXPIRED: return "timer_expired";
        case AbortReason::SERVER_SHUTDOWN: return "server_shutdown";
    }
    return "unknown";
}
