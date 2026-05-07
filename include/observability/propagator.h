#pragma once

// W3C Trace Context propagator per W3C Trace Context Level 1 §3.
//
//   traceparent = version "-" trace-id "-" parent-id "-" trace-flags
//                 (currently always version="00", total 55 chars)
//   tracestate  = comma-separated list of vendor-specific list-members
//                 (parsed/serialized via TraceState; this propagator
//                 just hands the header value through.)
//
// W3CPropagator is stateless — no instance state, no synchronization;
// all methods are static. The split-context model means `Extract`
// returns the REMOTE PARENT (immutable snapshot of the inbound
// traceparent), and `Inject` writes a LOCAL SpanContext (e.g.
// AttemptTraceContext.attempt_local). Outbound callers MUST NOT inject
// `RequestTraceContext.current_local` directly — that would make
// downstream services attach to the SERVER hop instead of the gateway-
// internal CLIENT span.

#include "observability/span_context.h"
#include "observability/trace_state.h"

#include "../common.h"

namespace OBSERVABILITY_NAMESPACE {

class W3CPropagator {
public:
    // Wire format constants per W3C Trace Context §3.2.
    static constexpr size_t kTraceparentLen = 55;  // "00-32hex-16hex-2hex"
    static constexpr const char* kVersion00 = "00";

    // Parse a `traceparent` header value. Returns the extracted SpanContext
    // when the value is well-formed AND identifies a valid (non-zero)
    // trace_id + parent_id (W3C §3.2.2.5 invalid forms are rejected).
    // Returns nullopt on:
    //   - Wrong length (anything but 55 chars).
    //   - Bad version (anything but "00").
    //   - Non-hex characters in any field.
    //   - All-zero trace_id or parent_id.
    //
    // The returned SpanContext has `is_remote = true` and an empty
    // TraceState — pass the `tracestate` header separately to ParseTraceState.
    static std::optional<SpanContext> ParseTraceparent(
        std::string_view header_value) noexcept;

    // Parse a `tracestate` header value. Returns the parsed TraceState
    // on success (including empty header → empty TraceState); nullopt
    // when the header violates W3C list-member caps (>32 members or
    // any member >256 chars).
    static std::optional<TraceState> ParseTracestate(
        std::string_view header_value);

    // High-level helper: extract a complete SpanContext from a request's
    // headers map. Applies both ParseTraceparent + ParseTracestate; the
    // tracestate parse failure DOES NOT invalidate the parent — per
    // W3C §3.3.5, an invalid tracestate is dropped silently while the
    // traceparent is preserved.
    //
    // Header lookup is case-insensitive (HTTP/1.1 stores header names
    // lower-cased per the project's HttpRequest convention; HTTP/2 also
    // emits lowercase per RFC 9113 §8.1.2.1, so a single lower-case
    // lookup covers both).
    //
    // Returns:
    //   - SpanContext with is_remote=true + populated trace_state on success.
    //   - SpanContext with is_remote=true + empty trace_state when the
    //     traceparent is valid but tracestate is missing / invalid.
    //   - nullopt when traceparent is missing or invalid.
    static std::optional<SpanContext> Extract(
        const std::map<std::string, std::string>& headers);

    // Serialize a SpanContext into a `traceparent` header value.
    // Returns nullopt when the context is not valid (zero trace_id or
    // span_id) — callers MUST NOT inject an invalid context.
    static std::optional<std::string> SerializeTraceparent(
        const SpanContext& ctx);

    // Inject `ctx`'s SpanContext into the outbound headers map. Writes
    // `traceparent` (always when ctx.IsValid()) and `tracestate` (when
    // ctx.state() is non-empty). Caller MUST strip any pre-existing
    // `traceparent`/`tracestate` headers BEFORE calling Inject —
    // there is no implicit replace.
    //
    // Returns false when ctx is invalid (no header written).
    static bool Inject(const SpanContext& ctx,
                        std::map<std::string, std::string>& headers);

    // Vector overload for callers that work with header pair vectors
    // (e.g. UpstreamHttpClient::Request.headers). Same semantics.
    static bool Inject(const SpanContext& ctx,
                        std::vector<std::pair<std::string, std::string>>& headers);
};

}  // namespace OBSERVABILITY_NAMESPACE
