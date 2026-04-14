#pragma once

// Named HTTP status code constants used across the server.
//
// llhttp provides a full enum (enum llhttp_status in llhttp.h), but
// including that header pulls in the entire parser API. This header
// defines the subset actually referenced by server code, using the
// same HTTP_STATUS_* naming convention for familiarity.

struct HttpStatus {
    // 1xx Informational
    static constexpr int CONTINUE            = 100;
    static constexpr int SWITCHING_PROTOCOLS = 101;
    // RFC 2518 §10.1 (WebDAV) — the lowest valid non-final 1xx that
    // can be emitted via InterimResponseSender. Codes 100 and 101 are
    // framework-managed (internal Continue / protocol upgrade).
    static constexpr int PROCESSING          = 102;
    // RFC 8297 — 103 Early Hints. Canonical user-facing 1xx for
    // pre-announcing preload resources.
    static constexpr int EARLY_HINTS         = 103;

    // 2xx Success
    static constexpr int OK                  = 200;
    static constexpr int NO_CONTENT          = 204;
    static constexpr int RESET_CONTENT       = 205;

    // 3xx Redirection
    static constexpr int NOT_MODIFIED        = 304;

    // 4xx Client Error
    static constexpr int BAD_REQUEST                  = 400;
    static constexpr int UNAUTHORIZED                 = 401;
    static constexpr int FORBIDDEN                    = 403;
    static constexpr int NOT_FOUND                    = 404;
    static constexpr int METHOD_NOT_ALLOWED           = 405;
    static constexpr int REQUEST_TIMEOUT              = 408;
    static constexpr int PAYLOAD_TOO_LARGE            = 413;
    static constexpr int EXPECTATION_FAILED           = 417;
    static constexpr int TOO_MANY_REQUESTS            = 429;
    static constexpr int REQUEST_HEADER_FIELDS_TOO_LARGE = 431;

    // 5xx Server Error
    static constexpr int INTERNAL_SERVER_ERROR        = 500;
    static constexpr int BAD_GATEWAY                  = 502;
    static constexpr int SERVICE_UNAVAILABLE          = 503;
    static constexpr int GATEWAY_TIMEOUT              = 504;
    static constexpr int HTTP_VERSION_NOT_SUPPORTED   = 505;

    HttpStatus() = delete;
};
