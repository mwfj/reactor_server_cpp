#include "observability/sampler.h"

#include <sstream>

namespace OBSERVABILITY_NAMESPACE {

namespace {

// Read the upper 64 bits of a trace_id as a host-byte-order uint64.
// The sampling key only needs determinism per trace_id, not a fixed
// endianness. "Treat the first 8 bytes as a big-endian u64" matches
// the W3C wire format and gives identical sampling decisions for the
// same trace_id across different hosts.
uint64_t TraceIdUpper64(const TraceId& id) noexcept {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v = (v << 8) | static_cast<uint64_t>(id.bytes[i]);
    }
    return v;
}

}  // namespace

TraceIdRatioSampler::TraceIdRatioSampler(double ratio) {
    if (!(ratio >= 0.0)) ratio_ = 0.0;
    else if (ratio >= 1.0) ratio_ = 1.0;
    else ratio_ = ratio;
    // ratio * 2^64. We compute via long-double to avoid the subtle
    // double-precision rounding error that would otherwise let
    // `ratio == 1.0` produce `threshold_ < UINT64_MAX` (causing one
    // trace per ~2^64 to be dropped under "always sample" config).
    if (ratio_ >= 1.0) {
        threshold_ = ~uint64_t{0};
    } else if (ratio_ <= 0.0) {
        threshold_ = 0;
    } else {
        long double scaled =
            static_cast<long double>(ratio_) *
            static_cast<long double>(static_cast<uint64_t>(1) << 63) * 2.0L;
        if (scaled >= static_cast<long double>(~uint64_t{0})) {
            threshold_ = ~uint64_t{0};
        } else {
            threshold_ = static_cast<uint64_t>(scaled);
        }
    }
}

SamplingResult TraceIdRatioSampler::ShouldSample(
    const SpanContext& /*parent*/,
    const TraceId&     trace_id,
    const std::string& /*name*/,
    SpanKind           /*kind*/) const {
    if (threshold_ == 0) return SamplingResult{SamplingDecision::DROP};
    if (threshold_ == ~uint64_t{0}) {
        return SamplingResult{SamplingDecision::RECORD_AND_SAMPLE};
    }
    const uint64_t key = TraceIdUpper64(trace_id);
    if (key < threshold_) {
        return SamplingResult{SamplingDecision::RECORD_AND_SAMPLE};
    }
    return SamplingResult{SamplingDecision::DROP};
}

std::string TraceIdRatioSampler::Description() const {
    std::ostringstream oss;
    oss << "trace_id_ratio:" << ratio_;
    return oss.str();
}

ParentBasedSampler::ParentBasedSampler(
    std::shared_ptr<const Sampler> root,
    std::shared_ptr<const Sampler> remote_not_sampled)
    : root_(std::move(root)),
      remote_not_sampled_(std::move(remote_not_sampled)) {
    if (!root_) {
        // Defensive default — if a caller forgets the root sampler, drop
        // every root span rather than crash. The TracerProvider's
        // construction path validates this and rejects null roots, but
        // the sampler itself stays robust.
        root_ = std::make_shared<AlwaysOffSampler>();
    }
}

SamplingResult ParentBasedSampler::ShouldSample(
    const SpanContext& parent,
    const TraceId&     trace_id,
    const std::string& name,
    SpanKind           kind) const {
    if (!parent.IsValid()) {
        // Root span — defer to root sampler.
        return root_->ShouldSample(parent, trace_id, name, kind);
    }
    if (parent.flags().IsSampled()) {
        // Parent says sampled — record and export.
        return SamplingResult{SamplingDecision::RECORD_AND_SAMPLE};
    }
    // Parent NOT sampled.
    if (parent.is_remote() && remote_not_sampled_) {
        return remote_not_sampled_->ShouldSample(parent, trace_id, name, kind);
    }
    return SamplingResult{SamplingDecision::DROP};
}

std::string ParentBasedSampler::Description() const {
    std::string out = "parent_based(root=";
    out += root_->Description();
    if (remote_not_sampled_) {
        out += ",remote_not_sampled=";
        out += remote_not_sampled_->Description();
    }
    out += ")";
    return out;
}

}  // namespace OBSERVABILITY_NAMESPACE
