#pragma once

// TracerProvider — factory for Tracers + owner of the active sampler /
// processor. Constructed by ObservabilityManager (one per pipeline);
// holds a shared_ptr<Resource> + a shared_ptr<RandomSource> shared
// across all spawned Tracers.
//
// Reload contract (§11.1 r79): `tracer_provider_->Reload(...)` accepts
// a new sampler shared_ptr + new processor options (which are passed
// THROUGH to the underlying BatchSpanProcessor; the provider itself
// doesn't own batch knobs). The Reload is atomic: in-flight spans
// keep their original processor (captured at StartSpan time), new
// spans see the new sampler / processor.

#include "observability/resource.h"
#include "observability/sampler.h"
#include "observability/span_processor.h"
#include "observability/trace_id.h"
#include "observability/tracer.h"

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace OBSERVABILITY_NAMESPACE {

// Subset of BatchSpanProcessor knobs passed through Reload. Future
// processor implementations may extend this struct; the provider just
// shuttles it onward.
struct ProcessorOptions {
    size_t max_export_batch_size = 512;
    std::chrono::milliseconds schedule_delay = std::chrono::milliseconds{5000};
};

class TracerProvider {
public:
    TracerProvider(std::shared_ptr<const Resource> resource,
                    std::shared_ptr<SpanProcessor>  processor,
                    std::shared_ptr<const Sampler>  sampler,
                    std::shared_ptr<RandomSource>   random);

    TracerProvider(const TracerProvider&) = delete;
    TracerProvider& operator=(const TracerProvider&) = delete;

    // Get-or-create a Tracer for the given (name, version). Tracers are
    // cached; repeat calls with the same (name, version) pair return
    // the same Tracer*. The provider OWNS the Tracer; callers hold a
    // raw pointer for the provider's lifetime.
    Tracer* GetTracer(const std::string& name,
                       const std::string& version = {});

    // Live-reloadable knobs. Passes the new sampler down to every
    // cached Tracer atomically; processor swap likewise. ProcessorOptions
    // is passed onward to BatchSpanProcessor::Reload (when wired).
    void Reload(std::shared_ptr<const Sampler> new_sampler,
                ProcessorOptions               new_processor_options);

    const Resource& resource() const { return *resource_; }

private:
    std::shared_ptr<const Resource> resource_;
    // Processor + sampler are atomic_load / atomic_store via the
    // std::shared_ptr<> non-template atomic API. Hot-path reads in
    // StartSpan grab a snapshot of both at the call boundary so
    // in-flight spans aren't disturbed by a concurrent Reload.
    std::shared_ptr<SpanProcessor> processor_;
    std::shared_ptr<const Sampler> sampler_;
    std::shared_ptr<RandomSource>  random_;
    ProcessorOptions               processor_options_;

    // (name, version) → Tracer cache. Tracer instances are owned by
    // the provider via unique_ptr stored in `tracer_storage_`; the map
    // returns raw pointers.
    std::mutex                                       tracer_mtx_;
    std::unordered_map<std::string, std::unique_ptr<Tracer>> tracers_;
};

}  // namespace OBSERVABILITY_NAMESPACE
