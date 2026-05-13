#pragma once

// Tracer — span factory bound to a single InstrumentationScope.
// Owned by TracerProvider; callers obtain via `provider->GetTracer(name,
// version)`. Tracer is reference-only — copying / moving is forbidden,
// callers hold a `Tracer*` returned by the provider for the provider's
// lifetime.
//
// `StartSpan` is the single entry point. `StartSpanOptions` carries:
//   - `kind`              — SpanKind (SERVER / CLIENT / INTERNAL / etc).
//   - `parent`            — parent SpanContext (default-constructed for
//                            root spans).
//   - `precomputed_context` — when set, the new Span uses this context
//                              verbatim instead of generating a fresh
//                              span_id. Proxy / auth callers want the
//                              exported CLIENT span's `Context().span_id` 
//                              to match the wire-format span_id they already injected via
//                              `AttemptTraceContext.attempt_local` /
//                              `IssueTraceContext.local`. Without this,
//                              outbound traceparent (which uses the
//                              per-call context) and the exported
//                              CLIENT span (which would otherwise use
//                              a freshly-generated span_id) would
//                              diverge.
//   - `start_time`        — explicit start time; defaults to now().
//   - `attributes`        — initial attribute set (saves `SetAttribute`
//                            calls from the hot path).

#include "observability/sampler.h"
#include "observability/span.h"
#include "observability/span_context.h"
#include "observability/span_kind.h"
#include "observability/trace_id.h"

#include "../common.h"
// <chrono>, <memory>, <string>, <vector> via common.h

namespace OBSERVABILITY_NAMESPACE {

class InstrumentationScope;
class ObservabilityManager;
class Resource;
class SpanProcessor;

struct StartSpanOptions {
    SpanKind                              kind = SpanKind::INTERNAL;
    SpanContext                           parent{};            // default-constructed = no parent
    bool                                  has_parent = false;
    SpanContext                           precomputed_context{}; // optional — see header docstring
    bool                                  has_precomputed_context = false;
    std::chrono::system_clock::time_point start_time{};
    bool                                  has_explicit_start_time = false;
    std::vector<Attribute>                attributes;
    // Per-call sampler override. Used by route-aware sampling so the
    // server-span middleware can apply `traces.sampler.routes` overrides
    // without rebuilding the global Tracer/MeterProvider chain. When
    // null, Tracer falls back to the provider-installed sampler.
    std::shared_ptr<const Sampler>        sampler_override;
};

class Tracer {
public:
    Tracer(std::shared_ptr<const InstrumentationScope> scope,
           std::shared_ptr<const Resource>             resource,
           std::shared_ptr<SpanProcessor>              processor,
           std::shared_ptr<const Sampler>              sampler,
           std::shared_ptr<RandomSource>               random,
           ObservabilityManager*                       manager);

    Tracer(const Tracer&) = delete;
    Tracer& operator=(const Tracer&) = delete;

    // Self-metric escape hatch — returns the ObservabilityManager pointer
    // installed at construction time, or null when constructed without
    // one (test fixtures). See batch_span_processor.h::manager() docstring
    // for the SHUTDOWN CAVEAT that applies to any code path consuming
    // manager_-> sub-members (catalog, meter_provider, metric_reader) —
    // those may already be destroyed by the time worker drains run.
    ObservabilityManager* manager() const noexcept { return manager_; }

    // StartSpan — the only span constructor. Returns a non-null
    // shared_ptr<Span> on every call: even DROP-sampled spans get a
    // (non-recording) Span so callers don't need to null-check before
    // mutating. The Span's `IsRecording()` reports the actual decision.
    std::shared_ptr<Span> StartSpan(std::string name,
                                     const StartSpanOptions& opts = {});

    const InstrumentationScope& scope() const { return *scope_; }

    // Used by ObservabilityManager::Reload to atomic-swap the sampler /
    // processor under shared_ptr semantics. No locks — readers see the
    // old or new shared_ptr atomically; in-flight spans keep their
    // original processor reference (captured at StartSpan time) so
    // mid-flight reload can't tear down the processor under their feet.
    void SwapSampler(std::shared_ptr<const Sampler> sampler) noexcept;
    void SwapProcessor(std::shared_ptr<SpanProcessor> processor) noexcept;

private:
    std::shared_ptr<const InstrumentationScope> scope_;
    std::shared_ptr<const Resource>             resource_;
    // Both processor_ and sampler_ are atomic_load / atomic_store via
    // std::atomic<shared_ptr<>> for lock-free hot-path reads.
    std::shared_ptr<SpanProcessor>              processor_;
    std::shared_ptr<const Sampler>              sampler_;
    std::shared_ptr<RandomSource>               random_;

    // Raw pointer; manager storage outlives every Tracer (TracerProvider
    // destructs as part of ~ObservabilityManager's body). See
    // batch_span_processor.h::manager() docstring for the SHUTDOWN CAVEAT
    // that applies to any code path consuming manager_-> sub-members
    // (catalog, meter_provider, metric_reader) — those may already be
    // destroyed by the time ~TracerProvider's drain runs.
    ObservabilityManager*                       manager_ = nullptr;
};

}  // namespace OBSERVABILITY_NAMESPACE
