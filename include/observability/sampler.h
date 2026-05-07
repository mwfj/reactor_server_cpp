#pragma once

// Sampler interface + four built-in implementations per OTel SDK spec.
//
//   AlwaysOn        — every span sampled.
//   AlwaysOff       — every span dropped (still recordable for in-process
//                     metrics if explicitly enabled, but not exported).
//   TraceIdRatio    — deterministic sampling by trace_id hash; same trace
//                     always lands the same way, so the trace tree stays
//                     consistent across services.
//   ParentBased     — defer to the parent's sampled bit; root spans fall
//                     back to a configurable inner sampler.
//
// All Sampler instances are immutable post-construction. TracerProvider
// holds the active sampler as `shared_ptr<const Sampler>` and swaps it
// atomically on Reload.

#include "observability/span_context.h"
#include "observability/span_kind.h"

#include "../common.h"
// <cstdint>, <memory>, <string> via common.h

namespace OBSERVABILITY_NAMESPACE {

// Sampling decision returned by Sampler::ShouldSample.
enum class SamplingDecision {
    DROP                = 0,  // Don't record, don't export.
    RECORD_ONLY         = 1,  // Record locally, don't export (rare; mostly for debugging).
    RECORD_AND_SAMPLE   = 2,  // Record locally AND export.
};

struct SamplingResult {
    SamplingDecision decision = SamplingDecision::DROP;

    // The sampler MAY mutate trace_state (e.g. record its own decision
    // marker per W3C tracestate spec). Empty when no mutation.
    std::string trace_state_override;
    bool        has_trace_state_override = false;
};

class Sampler {
public:
    virtual ~Sampler() = default;

    // Decision is made BEFORE the Span object is allocated. `parent` is
    // the parent SpanContext (default-constructed when this is a root span;
    // `parent.IsValid()` is false in that case). `trace_id` is the
    // freshly-generated or inherited trace_id for the new span.
    //
    // `name` and `kind` are passed in case future samplers want to
    // route by route name / span kind. The current built-ins ignore them.
    virtual SamplingResult ShouldSample(
        const SpanContext& parent,
        const TraceId&     trace_id,
        const std::string& name,
        SpanKind           kind) const = 0;

    // Stable name for diagnostics (e.g. "always_on", "trace_id_ratio:0.1").
    virtual std::string Description() const = 0;
};

// ---- Built-in samplers ----

class AlwaysOnSampler final : public Sampler {
public:
    SamplingResult ShouldSample(const SpanContext&, const TraceId&,
                                 const std::string&, SpanKind) const override {
        return SamplingResult{SamplingDecision::RECORD_AND_SAMPLE};
    }
    std::string Description() const override { return "always_on"; }
};

class AlwaysOffSampler final : public Sampler {
public:
    SamplingResult ShouldSample(const SpanContext&, const TraceId&,
                                 const std::string&, SpanKind) const override {
        return SamplingResult{SamplingDecision::DROP};
    }
    std::string Description() const override { return "always_off"; }
};

// Deterministic ratio sampler — uses the upper 64 bits of the trace_id
// as a uniform-distribution sampling key. ratio=0 is AlwaysOff;
// ratio=1 is AlwaysOn; intermediate values sample ~ratio fraction of
// trace_ids.
class TraceIdRatioSampler final : public Sampler {
public:
    explicit TraceIdRatioSampler(double ratio);
    SamplingResult ShouldSample(const SpanContext&, const TraceId&,
                                 const std::string&, SpanKind) const override;
    std::string Description() const override;
    double ratio() const noexcept { return ratio_; }

private:
    double   ratio_;
    uint64_t threshold_;  // ratio * UINT64_MAX, precomputed.
};

// ParentBased sampler — defers to the parent's sampled bit when the
// parent SpanContext is valid. Root spans fall back to the configured
// inner samplers (one for sampled-parent absent, one for parents that
// are remote-and-not-sampled, etc.). For our use we keep just two:
// the root sampler (`root_`) and a remote-not-sampled override
// (`remote_not_sampled_`). When `remote_not_sampled_` is null, a
// remote-not-sampled parent is treated as DROP (matches OTel default).
class ParentBasedSampler final : public Sampler {
public:
    explicit ParentBasedSampler(std::shared_ptr<const Sampler> root,
                                 std::shared_ptr<const Sampler> remote_not_sampled = nullptr);
    SamplingResult ShouldSample(const SpanContext&, const TraceId&,
                                 const std::string&, SpanKind) const override;
    std::string Description() const override;

private:
    std::shared_ptr<const Sampler> root_;
    std::shared_ptr<const Sampler> remote_not_sampled_;
};

}  // namespace OBSERVABILITY_NAMESPACE
