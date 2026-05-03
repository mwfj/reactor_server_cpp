#pragma once

// Span — the recording handle for a single in-flight span.
//
// Lifecycle: allocated via `Tracer::StartSpan`, mutated by application
// + framework code on the OWNING DISPATCHER ONLY (no synchronization
// inside the Span itself), finished via `End()` which moves the
// SpanData into the SpanProcessor and marks the Span as
// no-longer-recording.
//
// Span mutation is dispatcher-thread-only. Cross-thread access from a
// worker thread (e.g. a BatchSpanProcessor flushing the queue) is
// forbidden — the processor receives a fully-detached SpanData snapshot
// and never touches the Span object. The shutdown kill loop respects
// this contract via the synchronized link/kill protocol on
// ObservabilitySnapshot plus DropWithoutEnd(), which mutates Span
// members on the OWNING DISPATCHER (inline when the kill loop is on-
// thread, or marshaled via EnQueue otherwise).
//
// Idempotent guarantees:
//   - End() may be called at most once. Repeat calls are silently
//     dropped (logged in debug builds).
//   - DropWithoutEnd() is safe to call BEFORE End() — it cancels the
//     OnEnd dispatch so SpanProcessor::OnEnd never fires for this
//     span. Used by the shutdown kill path on processor teardown.

#include "observability/instrumentation_scope.h"
#include "observability/resource.h"
#include "observability/span_context.h"
#include "observability/span_data.h"
#include "observability/span_kind.h"
#include "observability/span_status.h"

#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <vector>

namespace OBSERVABILITY_NAMESPACE {

class SpanProcessor;  // forward — full type in span_processor.h

// Per-span caps — match opentelemetry-cpp defaults. These can be
// overridden by configuration in a future revision; for now they're
// fixed constants so the disabled fast path needs no config lookup.
inline constexpr size_t kMaxAttributesPerSpan = 128;
inline constexpr size_t kMaxEventsPerSpan     = 128;
inline constexpr size_t kMaxLinksPerSpan      = 32;

class Span {
public:
    Span(SpanContext context,
         SpanContext parent,
         bool        has_parent,
         std::string name,
         SpanKind    kind,
         std::chrono::system_clock::time_point start_system,
         std::shared_ptr<const Resource>             resource,
         std::shared_ptr<const InstrumentationScope> scope,
         std::shared_ptr<SpanProcessor>              processor);

    // Non-copyable, non-movable — Spans are pinned to their owning
    // dispatcher and tracked via shared_ptr. The shared_ptr handle is
    // what gets passed around; the Span object itself stays put.
    Span(const Span&) = delete;
    Span& operator=(const Span&) = delete;
    Span(Span&&) = delete;
    Span& operator=(Span&&) = delete;

    ~Span();

    // The exported SpanContext. Never changes post-construction.
    const SpanContext& Context() const noexcept { return context_; }

    // Mutation API — dispatcher-thread-only. Idempotent + bounded:
    // attributes / events / links past the per-span cap are silently
    // dropped, with the corresponding `*_truncated` flag set on the
    // exported SpanData so backends can surface the loss.
    void UpdateName(std::string name);
    void SetAttribute(std::string key, AttrValue value);
    void AddEvent(std::string name,
                  std::chrono::system_clock::time_point ts = std::chrono::system_clock::now());
    void AddEvent(std::string name,
                  std::vector<Attribute> attrs,
                  std::chrono::system_clock::time_point ts = std::chrono::system_clock::now());
    void AddLink(SpanLink link);
    void SetStatus(SpanStatusCode code, std::string description = {});

    // Convenience — records a span event named "exception" with
    // attributes mirroring OTel exception semconv.
    void RecordException(const std::exception& e);

    // True iff the Span will be exported (RECORD_AND_SAMPLE) — used by
    // hot-path call sites to skip building expensive attributes when
    // the span isn't going to be exported.
    //
    // DROP-sampled spans receive a null `processor_` at construction
    // (Tracer::StartSpan branches on the sampler decision); the null
    // processor is the load-bearing signal for "this span won't be
    // recorded". `processor_` is set once at construction and never
    // mutated post-construction (Tracer::SwapProcessor only affects
    // FUTURE StartSpan calls), so a plain pointer compare is safe.
    bool IsRecording() const noexcept {
        return processor_ != nullptr &&
               !ended_.load(std::memory_order_acquire) &&
               !dropped_.load(std::memory_order_acquire);
    }

    // Mark the span finished. Idempotent — repeat calls are dropped.
    // Hands the populated SpanData to the SpanProcessor (move).
    void End(std::chrono::system_clock::time_point end_system =
                 std::chrono::system_clock::now());

    // Drop without firing OnEnd. Used by the shutdown kill path to
    // release Span members WITHOUT enqueueing to the processor (which
    // may already be torn down). Idempotent. After DropWithoutEnd,
    // subsequent End() / mutator calls are no-ops.
    //
    // Must be called on the owning dispatcher per the dispatcher-
    // thread-only mutation contract. Inline kills run it directly;
    // cross-dispatcher kills marshal via EnQueue.
    void DropWithoutEnd();

private:
    // Move-out helper — packs the current Span state into a SpanData
    // snapshot. Called by End().
    SpanData MakeSnapshot(std::chrono::system_clock::time_point end_system);

    SpanContext context_;
    SpanContext parent_context_;
    bool        has_parent_;

    std::string                name_;
    SpanKind                   kind_;
    SpanStatusCode             status_code_       = SpanStatusCode::UNSET;
    std::string                status_description_;
    std::chrono::system_clock::time_point start_system_;

    std::vector<Attribute>     attributes_;
    std::vector<SpanEvent>     events_;
    std::vector<SpanLink>      links_;
    bool                       attributes_truncated_ = false;
    bool                       events_truncated_     = false;
    bool                       links_truncated_      = false;

    std::shared_ptr<const Resource>             resource_;
    std::shared_ptr<const InstrumentationScope> scope_;

    // Held by shared_ptr so the processor stays alive as long as ANY
    // Span references it. The TracerProvider holds the canonical
    // shared_ptr; per-span ownership is a weak reference upgraded to
    // strong at construction. When the manager is torn down before
    // End(), the kill-marshal closure captures `weak_from_this()` on
    // the manager (NOT raw `this`) so the closure no-ops cleanly.
    std::shared_ptr<SpanProcessor> processor_;

    // Atomic flags so IsRecording() can be queried from any thread
    // (read-only) for early-out optimization. Mutation still happens
    // on the owning dispatcher; the atomics just publish the End/Drop
    // decisions.
    std::atomic<bool> ended_{false};
    std::atomic<bool> dropped_{false};
};

}  // namespace OBSERVABILITY_NAMESPACE
