#include "observability/tracer.h"

#include "observability/instrumentation_scope.h"
#include "observability/resource.h"
#include "observability/span_processor.h"

#include <atomic>

namespace OBSERVABILITY_NAMESPACE {

namespace {

// std::atomic<std::shared_ptr<T>> isn't universally available across all
// supported compilers (libstdc++ shipped it in GCC 12+), so we use the
// non-template std::atomic_load / std::atomic_store helpers — those are
// the C++11 originals and are guaranteed available. They're deprecated
// in C++20 but not removed; we'll migrate when the toolchain floor moves.
template <typename T>
std::shared_ptr<T> AtomicLoad(const std::shared_ptr<T>& p) noexcept {
    return std::atomic_load_explicit(&p, std::memory_order_acquire);
}

template <typename T>
void AtomicStore(std::shared_ptr<T>& dst, std::shared_ptr<T> src) noexcept {
    std::atomic_store_explicit(&dst, std::move(src), std::memory_order_release);
}

}  // namespace

Tracer::Tracer(std::shared_ptr<const InstrumentationScope> scope,
               std::shared_ptr<const Resource>             resource,
               std::shared_ptr<SpanProcessor>              processor,
               std::shared_ptr<const Sampler>              sampler,
               std::shared_ptr<RandomSource>               random)
    : scope_(std::move(scope)),
      resource_(std::move(resource)),
      processor_(std::move(processor)),
      sampler_(std::move(sampler)),
      random_(std::move(random)) {}

void Tracer::SwapSampler(std::shared_ptr<const Sampler> sampler) noexcept {
    AtomicStore(sampler_, std::move(sampler));
}

void Tracer::SwapProcessor(std::shared_ptr<SpanProcessor> processor) noexcept {
    AtomicStore(processor_, std::move(processor));
}

std::shared_ptr<Span> Tracer::StartSpan(std::string name,
                                          const StartSpanOptions& opts) {
    // Snapshot the sampler + processor BEFORE building the span so
    // mid-flight Reload swaps don't tear down the processor under us.
    auto sampler   = AtomicLoad(sampler_);
    auto processor = AtomicLoad(processor_);

    // Build the SpanContext for the new span. Three sources, in order:
    //   1. precomputed_context (proxy / auth callers wanting wire-format
    //      span_id alignment per §6.1).
    //   2. Inherited from parent — same trace_id, freshly-generated span_id.
    //   3. Root span — freshly-generated trace_id AND span_id.
    SpanContext own_context;
    if (opts.has_precomputed_context) {
        own_context = opts.precomputed_context;
    } else if (opts.has_parent && opts.parent.IsValid()) {
        own_context.SetTraceId(opts.parent.trace_id());
        own_context.SetSpanId(random_->NewSpanId());
        own_context.SetFlags(opts.parent.flags());
        own_context.mutable_state() = opts.parent.state();
    } else {
        own_context.SetTraceId(random_->NewTraceId());
        own_context.SetSpanId(random_->NewSpanId());
        own_context.SetFlags(TraceFlags{});
    }

    // Sampler decision — uses the freshly-generated trace_id.
    SamplingDecision decision = SamplingDecision::DROP;
    if (sampler) {
        SamplingResult result = sampler->ShouldSample(
            opts.has_parent ? opts.parent : SpanContext{},
            own_context.trace_id(),
            name,
            opts.kind);
        decision = result.decision;
        if (result.has_trace_state_override) {
            // Inject the sampler's trace_state mutation. We round-trip
            // through Parse() to validate the W3C list-member shape;
            // an invalid override is silently dropped per §3.3.
            auto parsed = TraceState::Parse(result.trace_state_override);
            if (parsed.has_value()) {
                own_context.mutable_state() = std::move(*parsed);
            }
        }
    }
    // Mirror the decision onto the trace flags so outbound traceparent
    // injection (which reads `flags().IsSampled()`) reflects the
    // sampler's call.
    auto flags = own_context.flags();
    flags.SetSampled(decision == SamplingDecision::RECORD_AND_SAMPLE);
    own_context.SetFlags(flags);

    const auto start_time = opts.has_explicit_start_time
        ? opts.start_time
        : std::chrono::system_clock::now();

    auto span = std::make_shared<Span>(
        std::move(own_context),
        opts.parent,
        opts.has_parent,
        std::move(name),
        opts.kind,
        start_time,
        resource_,
        scope_,
        // DROP / RECORD_ONLY spans receive a null processor — End()
        // therefore no-ops and the SpanData snapshot is never built.
        // RECORD_ONLY is treated identically to DROP for export
        // purposes here; if a future use case wants to record-but-not-
        // export, it would attach a separate in-process metrics
        // processor.
        decision == SamplingDecision::RECORD_AND_SAMPLE ? processor : nullptr);

    // Seed initial attributes.
    for (const auto& a : opts.attributes) {
        span->SetAttribute(a.key, a.value);
    }

    // Pre-end notification — only when we're actually recording.
    if (processor && decision == SamplingDecision::RECORD_AND_SAMPLE) {
        processor->OnStart(opts.has_parent ? opts.parent : SpanContext{},
                            span->Context());
    }

    return span;
}

}  // namespace OBSERVABILITY_NAMESPACE
