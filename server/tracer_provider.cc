#include "observability/tracer_provider.h"

#include "common.h"
#include "observability/batch_span_processor.h"
#include "observability/instrumentation_scope.h"

namespace OBSERVABILITY_NAMESPACE {

TracerProvider::TracerProvider(std::shared_ptr<const Resource> resource,
                                std::shared_ptr<SpanProcessor>  processor,
                                std::shared_ptr<const Sampler>  sampler,
                                std::shared_ptr<RandomSource>   random,
                                ObservabilityManager*           manager)
    : resource_(std::move(resource)),
      processor_(std::move(processor)),
      sampler_(std::move(sampler)),
      random_(std::move(random)),
      manager_(manager) {}

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
        std::move(scope), resource_, processor_, sampler_, random_, manager_);
    Tracer* raw = tracer.get();
    tracers_.emplace(std::move(key), std::move(tracer));
    return raw;
}

void TracerProvider::SwapProcessorAcrossTracers(
        std::shared_ptr<SpanProcessor> new_processor) {
    if (!new_processor) return;
    std::lock_guard<std::mutex> g(tracer_mtx_);
    processor_ = new_processor;   // future GetTracer() picks this up
    for (auto& [_, tracer] : tracers_) {
        tracer->SwapProcessor(new_processor);
    }
}

void TracerProvider::Reload(std::shared_ptr<const Sampler> new_sampler,
                              ProcessorOptions               new_processor_options) {
    std::shared_ptr<SpanProcessor> processor_for_reload;
    {
        std::lock_guard<std::mutex> g(tracer_mtx_);
        // Capture new live values for any future GetTracer() calls.
        if (new_sampler) sampler_ = new_sampler;
        processor_options_ = new_processor_options;
        // Snapshot the processor under the lock so a concurrent
        // SwapProcessor doesn't tear it down between this read and
        // the Reload call below.
        processor_for_reload = processor_;
    }
    // Atomic-swap the sampler on every cached Tracer.
    if (new_sampler) {
        std::lock_guard<std::mutex> g(tracer_mtx_);
        for (auto& [_, tracer] : tracers_) {
            tracer->SwapSampler(new_sampler);
        }
    }
    // Forward the batch-shape reload to the concrete processor. The
    // base SpanProcessor interface is intentionally narrow; the
    // dynamic_cast is the smallest API change that still routes
    // ProcessorOptions to BatchSpanProcessor's atomics. NoopSpanProcessor
    // and other processors that don't take these knobs simply skip
    // the cast and stay unchanged.
    if (processor_for_reload) {
        if (auto* bsp = dynamic_cast<BatchSpanProcessor*>(
                processor_for_reload.get())) {
            // export_timeout=0 is the "preserve construction-time
            // timeout" sentinel — fall back to the 2-arg overload.
            // Any positive value pushes the new deadline into the
            // BSP's atomic so the next attempt observes the change.
            if (new_processor_options.export_timeout
                    > std::chrono::milliseconds{0}) {
                bsp->Reload(new_processor_options.max_export_batch_size,
                            new_processor_options.schedule_delay,
                            new_processor_options.export_timeout);
            } else {
                bsp->Reload(new_processor_options.max_export_batch_size,
                            new_processor_options.schedule_delay);
            }
            bsp->ReloadRetries(
                new_processor_options.retries_max_attempts,
                new_processor_options.retries_initial_backoff,
                new_processor_options.retries_max_backoff);
        }
    }
}

}  // namespace OBSERVABILITY_NAMESPACE
