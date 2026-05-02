#pragma once

// SpanContext per W3C / OTel — the immutable identity of a span on
// the wire. Combines TraceId + SpanId + TraceFlags + TraceState +
// is_remote (true when the context was extracted from an inbound
// header, false when locally generated).
//
// SpanContext is a value type; copying is cheap. The `state` field
// owns its TraceState (which itself owns its strings) so a SpanContext
// can be passed by value across thread boundaries safely.

#include "observability/trace_id.h"
#include "observability/trace_state.h"

namespace OBSERVABILITY_NAMESPACE {

class SpanContext {
public:
    SpanContext() = default;

    SpanContext(TraceId trace_id,
                SpanId span_id,
                TraceFlags flags,
                TraceState state,
                bool is_remote)
        : trace_id_(trace_id),
          span_id_(span_id),
          flags_(flags),
          state_(std::move(state)),
          is_remote_(is_remote) {}

    const TraceId&    trace_id()  const noexcept { return trace_id_; }
    const SpanId&     span_id()   const noexcept { return span_id_; }
    TraceFlags        flags()     const noexcept { return flags_; }
    const TraceState& state()     const noexcept { return state_; }
    bool              is_remote() const noexcept { return is_remote_; }

    // Mutable accessors for builder-style construction at extract /
    // sample-decision time. SpanContext is logically immutable once
    // attached to a Span, but propagator code populates it in stages.
    TraceState& mutable_state() noexcept { return state_; }
    void SetFlags(TraceFlags f) noexcept { flags_ = f; }
    void SetSpanId(SpanId id) noexcept { span_id_ = id; }
    void SetTraceId(TraceId id) noexcept { trace_id_ = id; }

    // A SpanContext is "valid" when both trace_id and span_id are
    // non-zero (W3C requirement). An invalid context is treated as
    // "no propagation" — the upstream Inject path emits no traceparent.
    bool IsValid() const noexcept {
        return trace_id_.IsValid() && span_id_.IsValid();
    }

private:
    TraceId    trace_id_{};
    SpanId     span_id_{};
    TraceFlags flags_{};
    TraceState state_{};
    bool       is_remote_ = false;
};

}  // namespace OBSERVABILITY_NAMESPACE
