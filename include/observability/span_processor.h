#pragma once

// SpanProcessor interface per OTel SDK spec §5.
//
// Tracer and Span call into the processor at OnStart / OnEnd; the
// processor decides whether to enqueue for export, drop, or both.
// Concrete implementations:
//   - NoopSpanProcessor — discards everything (used when traces are
//     disabled but the manager still exists for metric/structured-log
//     correlation purposes).
//   - InMemorySpanProcessor — retains finished SpanData for in-process
//     tests (no worker thread, no export). Used by the §16 unit-test
//     suite to assert span shapes WITHOUT spinning up the OTLP pipeline.
//   - BatchSpanProcessor — production export path; lands in task #70.

#include "observability/span_data.h"

#include <chrono>
#include <mutex>
#include <vector>

namespace OBSERVABILITY_NAMESPACE {

class SpanProcessor {
public:
    virtual ~SpanProcessor() = default;

    // Called by Tracer::StartSpan when the sampler decides to record.
    // Pre-end notification — most processors no-op here; subclasses that
    // care (e.g. live-stream processors) override.
    virtual void OnStart(const SpanContext& /*parent*/,
                         const SpanContext& /*own*/) {}

    // Called by Span::End when the span finishes. Receives the fully-
    // populated SpanData snapshot. The processor takes ownership of the
    // SpanData (move semantics — caller passes by value).
    virtual void OnEnd(SpanData data) = 0;

    // Called by SpanExporter / TracerProvider shutdown. r84 contract:
    // the exporter owns the trio (SignalShutdown / CancelAllActiveExports
    // / RebindDispatcher). Processors expose their own lifecycle:
    //   - SignalShutdown: stop accepting new OnEnd; begin draining.
    //   - JoinWorkers(deadline): block until the drain completes or the
    //     deadline expires.
    // The default no-op processors don't have workers; only
    // BatchSpanProcessor (task #70) overrides these.
    virtual void SignalShutdown() {}
    virtual void JoinWorkers(std::chrono::milliseconds /*deadline*/) {}
};

// In-memory processor that retains SpanData for inspection. Test-only;
// production deployments use BatchSpanProcessor.
class InMemorySpanProcessor final : public SpanProcessor {
public:
    void OnEnd(SpanData data) override {
        std::lock_guard<std::mutex> g(mtx_);
        spans_.push_back(std::move(data));
    }

    std::vector<SpanData> Drain() {
        std::lock_guard<std::mutex> g(mtx_);
        std::vector<SpanData> out;
        out.swap(spans_);
        return out;
    }

    size_t Size() const {
        std::lock_guard<std::mutex> g(mtx_);
        return spans_.size();
    }

private:
    mutable std::mutex     mtx_;
    std::vector<SpanData>  spans_;
};

// Drop-everything processor — used when traces are disabled but the
// manager still exists.
class NoopSpanProcessor final : public SpanProcessor {
public:
    void OnEnd(SpanData /*data*/) override {}
};

}  // namespace OBSERVABILITY_NAMESPACE
