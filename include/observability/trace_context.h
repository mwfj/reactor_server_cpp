#pragma once

// Trace-context value types per OPENTELEMETRY_DESIGN.md §4.5.1 / §6.1 / §6.3.
//
// Three contexts are tracked per inbound request:
//
//   RequestTraceContext (§4.5.1)
//     Captured at request entry. `remote_parent` is the W3C parent we
//     extracted from the inbound `traceparent` header (or default-
//     constructed when absent). `current_local` is the gateway's INBOUND
//     server-hop identity — the trace_id continues from `remote_parent`
//     when present, else a freshly-generated one; the span_id is always
//     freshly generated. `is_recording` captures the sampler decision so
//     mid-flight `traces.enabled` flips don't tear down spans on already-
//     started requests (§14).
//
//   AttemptTraceContext (§5.3)
//     Per-`ProxyTransaction`-attempt context. Each retry gets a fresh
//     `attempt_local.span_id`; `trace_id` and `state` are inherited from
//     `RequestTraceContext.current_local`. `upstream_span` is the CLIENT
//     span we allocated for this attempt (null on DROP / observability-
//     disabled).
//
//   IssueTraceContext (§6.3)
//     Per-`UpstreamHttpClient::Issue`-call context for non-proxy outbound
//     (JWKS / OIDC / introspection / OTLP exporter). Same per-call shape
//     as AttemptTraceContext but for the auth-path / exporter-path
//     UpstreamHttpClient hops. `tracer` is the Tracer instance that
//     should StartSpan with `precomputed_context = local`.
//
// Header is intentionally minimal — `<cstdint>`, `<memory>`, `<optional>`,
// `<string>`, `span_context.h`, AND forward declarations of `class Span;`
// AND `class Tracer;` in OBSERVABILITY_NAMESPACE. Pulling `span.h` /
// `tracer.h` would create a cycle through the wider observability tree
// (span.h transitively pulls attribute machinery + span_kind + span_status;
// tracer.h pulls span.h + sampler.h + provider fwds). The forward
// declarations are sufficient because `shared_ptr<Span>` and `Tracer*`
// only need the pointee's complete type at construction / destruction /
// reset / member-access call sites — those live in `.cc` files that
// include `span.h` / `tracer.h` directly.

#include "observability/span_context.h"

#include <memory>  // std::shared_ptr<Span>
// Note: <cstdint> / <optional> / <string> are NOT needed here — they're
// pulled in by consumers like http_request.h (which declares
// `std::optional<RequestTraceContext>`) and by .cc files that use the
// types via Tracer::StartSpan etc. This header itself only declares
// POD value types holding SpanContext + shared_ptr + Tracer*.

namespace OBSERVABILITY_NAMESPACE {

// Forward declarations — defined in span.h / tracer.h respectively.
// shared_ptr<Span> AND Tracer* only need the pointee's complete type at
// `.cc` call sites; the header declaration point is satisfied by the
// forward declaration alone.
class Span;
class Tracer;

// Per-request inbound trace context (§4.5.1).
//
// Two SpanContexts are tracked because they have DIFFERENT roles:
//   - `remote_parent` is the inbound W3C parent. It is the PARENT of
//     our inbound SERVER span, and is used for parent-based sampling
//     decisions. It is NEVER injected as outbound `traceparent`
//     (doing so would skip our gateway-internal spans in the trace tree).
//   - `current_local` is OUR inbound SERVER hop's identity. Its trace_id
//     continues from `remote_parent.trace_id()` when valid (else fresh);
//     its span_id is always freshly-generated. The exported SERVER span
//     carries `current_local.span_id()` so downstream Z-Pages / Tempo
//     queries by span_id resolve to this hop.
//
// Outbound `traceparent` is NEVER `current_local` directly — outbound
// hops use per-call AttemptTraceContext / IssueTraceContext (one fresh
// span_id per outbound hop) so child spans on the receiving end attach
// under our gateway-internal CLIENT span, not directly under the inbound
// SERVER hop.
struct RequestTraceContext {
    SpanContext remote_parent;
    SpanContext current_local;
    bool is_recording = false;
};

// Per-`ProxyTransaction`-attempt outbound context (§5.3).
//
// `attempt_local` is the CLIENT-side child span identity for THIS attempt.
// trace_id is inherited from `RequestTraceContext.current_local.trace_id`;
// span_id is freshly generated per attempt (retries get a fresh span_id
// so the trace tree shows one CLIENT span per upstream hop). flags +
// state are inherited from `RequestTraceContext.current_local`.
//
// `upstream_span` is the actual Span object we allocated for this
// attempt via `Tracer::StartSpan(opts{ kind=CLIENT,
// parent=inbound_span->Context(), precomputed_context=attempt_local })`.
// Null when observability is disabled OR the inbound was DROP-sampled
// (we still synthesize the SpanContext so outbound `traceparent` is
// emitted with `sampled=0`, but we don't allocate a Span object).
struct AttemptTraceContext {
    SpanContext attempt_local;
    std::shared_ptr<Span> upstream_span;
};

// Per-`UpstreamHttpClient::Issue`-call outbound context (§6.3).
//
// Used by the auth-path HTTP clients (JWKS fetch, OIDC discovery,
// introspection POST) and the OTLP exporter. Same shape as
// AttemptTraceContext but with the additional `tracer` and `parent`
// fields:
//   - `tracer` is the Tracer instance the caller should
//     StartSpan against. Each subsystem uses its own Tracer (e.g.
//     "reactor.auth.jwks", "reactor.otel.exporter").
//   - `parent` is the SpanContext to use as the StartSpanOptions
//     parent. For auth-path callers with `auth_idp_check_span` enabled,
//     this is the auth.idp_check INTERNAL span; with that span
//     disabled, this falls back to the inbound SERVER span's context.
struct IssueTraceContext {
    SpanContext local;
    SpanContext parent;
    Tracer*     tracer = nullptr;
};

}  // namespace OBSERVABILITY_NAMESPACE
