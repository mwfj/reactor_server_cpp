#pragma once

// Common observability namespace + forward declarations.
//
// `OBSERVABILITY_NAMESPACE` is a literal namespace name (not a macro),
// matching the convention used by `AUTH_NAMESPACE`, `CIRCUIT_BREAKER_NAMESPACE`,
// etc. — UPPER_SNAKE_CASE identifiers used directly as namespace names per
// `.claude/rules/CODE_CONVENTIONS.md`.
//
// Forward declarations live here so headers that only need pointer / reference
// to observability types (e.g. `include/http/http_request.h`'s
// `std::shared_ptr<Span>` field) can include this single header without
// pulling in the full observability tree.

namespace OBSERVABILITY_NAMESPACE {

// Trace identity (declared in trace_id.h).
struct TraceId;
struct SpanId;
struct TraceFlags;

// Per-context value types.
class TraceState;
class SpanContext;

// Span object model (declared in span.h / tracer.h).
class Span;
class Tracer;
class TracerProvider;
class Sampler;
class SpanProcessor;
class SpanExporter;

// Metrics object model (declared in counter.h / histogram.h / meter.h).
class Counter;
class UpDownCounter;
class Histogram;
class Meter;
class MeterProvider;
class MetricReader;
class MetricExporter;

// Attribute / label primitives.
struct AttrValue;
struct Attribute;
struct Label;
struct LabelSet;

// Resource / scope.
class Resource;
class InstrumentationScope;

// Snapshot types (POD; carried into export pipeline).
struct SpanData;
struct MetricsSnapshot;

// OTLP push pipeline.
class OtlpHttpExporter;
class BatchSpanProcessor;
class PeriodicMetricReader;

// Per-request observability bookkeeping.
struct ObservabilitySnapshot;
class ObservabilityManager;

// Trace context value types (declared in trace_context.h).
struct RequestTraceContext;
struct AttemptTraceContext;
struct IssueTraceContext;

}  // namespace OBSERVABILITY_NAMESPACE
