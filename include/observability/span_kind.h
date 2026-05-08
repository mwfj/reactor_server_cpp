#pragma once

// SpanKind per OTel SDK spec — used to label spans in the export
// pipeline so backends can distinguish server-side, client-side,
// internal, and messaging spans without inspecting attributes.

#include <cstdint>

namespace OBSERVABILITY_NAMESPACE {

enum class SpanKind : uint8_t {
    INTERNAL = 1,  // In-process work (e.g. auth.idp_check intermediate node).
    SERVER   = 2,  // Inbound request handling (the gateway's per-request span).
    CLIENT   = 3,  // Outbound HTTP / RPC (proxy attempts, JWKS, OIDC, OTLP).
    PRODUCER = 4,  // Async messaging produce.
    CONSUMER = 5,  // Async messaging consume.
};

}  // namespace OBSERVABILITY_NAMESPACE
