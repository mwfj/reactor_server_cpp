#include "observability/tracer_provider.h"

#include "observability/instrumentation_scope.h"

namespace OBSERVABILITY_NAMESPACE {

TracerProvider::TracerProvider(std::shared_ptr<const Resource> resource,
                                std::shared_ptr<SpanProcessor>  processor,
                                std::shared_ptr<const Sampler>  sampler,
                                std::shared_ptr<RandomSource>   random)
    : resource_(std::move(resource)),
      processor_(std::move(processor)),
      sampler_(std::move(sampler)),
      random_(std::move(random)) {}

Tracer* TracerProvider::GetTracer(const std::string& name,
                                    const std::string& version) {
    // Cache key combines name + version so an upgrade of the underlying
    // library produces a distinct InstrumentationScope (matches OTel
    // semantics — backends often dedupe by scope).
    std::string key = name;
    key.push_back('\0');  // separator that can't appear in either field
    key.append(version);

    std::lock_guard<std::mutex> g(tracer_mtx_);
    auto it = tracers_.find(key);
    if (it != tracers_.end()) return it->second.get();

    auto scope    = std::make_shared<InstrumentationScope>(name, version);
    auto tracer   = std::make_unique<Tracer>(
        std::move(scope), resource_, processor_, sampler_, random_);
    Tracer* raw = tracer.get();
    tracers_.emplace(std::move(key), std::move(tracer));
    return raw;
}

void TracerProvider::Reload(std::shared_ptr<const Sampler> new_sampler,
                              ProcessorOptions               new_processor_options) {
    {
        std::lock_guard<std::mutex> g(tracer_mtx_);
        // Capture new live values for any future GetTracer() calls.
        if (new_sampler) sampler_ = new_sampler;
        processor_options_ = new_processor_options;
    }
    // Atomic-swap the sampler on every cached Tracer. processor_
    // itself stays put — it's owned by ObservabilityManager and gets
    // its reload-knob updates via its own Reload(). Trace-side knobs
    // (schedule_delay, max_export_batch_size) live on
    // BatchSpanProcessor.
    if (new_sampler) {
        std::lock_guard<std::mutex> g(tracer_mtx_);
        for (auto& [_, tracer] : tracers_) {
            tracer->SwapSampler(new_sampler);
        }
    }
}

}  // namespace OBSERVABILITY_NAMESPACE
