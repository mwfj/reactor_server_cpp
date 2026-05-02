#pragma once

// SpanStatusCode per OTel SDK spec.
//
// Per §6.6 of OPENTELEMETRY_DESIGN.md:
//   - Server 4xx → UNSET (not the gateway's error; client misuse).
//   - Server 5xx → ERROR.
//   - Client 4xx + 5xx → ERROR (the gateway's outbound failed).
//   - Successful operations → leave UNSET unless the application has
//     a domain-specific reason to mark OK.
//
// `OK` is reserved for explicit assertion of success by the
// instrumentation; do NOT default to OK for 2xx responses.

#include <cstdint>

namespace OBSERVABILITY_NAMESPACE {

enum class SpanStatusCode : uint8_t {
    UNSET = 0,
    OK    = 1,
    ERROR = 2,
};

}  // namespace OBSERVABILITY_NAMESPACE
