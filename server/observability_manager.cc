#include "observability/observability_manager.h"

#include "observability/sampler.h"
#include "observability/semantic_conventions.h"
#include "observability/span.h"
#include "observability/span_status.h"

#include "log/logger.h"

namespace OBSERVABILITY_NAMESPACE {

std::shared_ptr<ObservabilityManager> ObservabilityManager::Create(
    ObservabilityConfig config,
    std::shared_ptr<const Resource> resource,
    std::shared_ptr<SpanProcessor>  span_processor,
    std::shared_ptr<RandomSource>   random) {
    // Use new + shared_ptr constructor explicitly because the
    // ObservabilityManager constructor is private (factory pattern).
    // shared_ptr's deleter will call ~ObservabilityManager normally.
    auto mgr = std::shared_ptr<ObservabilityManager>(
        new ObservabilityManager(std::move(config),
                                  std::move(resource),
                                  std::move(span_processor),
                                  std::move(random)));
    mgr->Init();
    return mgr;
}

ObservabilityManager::ObservabilityManager(
    ObservabilityConfig config,
    std::shared_ptr<const Resource> resource,
    std::shared_ptr<SpanProcessor>  span_processor,
    std::shared_ptr<RandomSource>   random)
    : config_(std::move(config)),
      resource_(std::move(resource)),
      random_(std::move(random)),
      span_processor_(std::move(span_processor)) {
    traces_enabled_.store(config_.traces.enabled,
                            std::memory_order_release);
    metrics_enabled_.store(config_.metrics.enabled,
                            std::memory_order_release);
    include_target_info_.store(config_.metrics.prometheus.include_target_info,
                                 std::memory_order_release);
}

ObservabilityManager::~ObservabilityManager() {
    // Defensive: BeginShutdown is idempotent; if HttpServer::Stop
    // never called it (e.g. test teardown without explicit shutdown),
    // run it here so the processor / reader workers join cleanly.
    BeginShutdown(std::chrono::milliseconds{1000});
}

void ObservabilityManager::Init() {
    // Build the sampler from config now that shared_from_this is seeded.
    auto sampler = BuildSamplerFromConfig();

    tracer_provider_ = std::make_unique<TracerProvider>(
        resource_, span_processor_, std::move(sampler), random_);
    meter_provider_ = std::make_unique<MeterProvider>(
        resource_, kDefaultMetricShards);

    MeterReaderOptions ro;
    ro.export_interval = config_.metrics.reader.export_interval;
    ro.export_timeout  = config_.metrics.reader.export_timeout;
    meter_provider_->Reload(ro);
}

std::shared_ptr<const Sampler>
ObservabilityManager::BuildSamplerFromConfig() const {
    switch (config_.traces.sampler.type) {
        case SamplerType::AlwaysOn:
            return std::make_shared<AlwaysOnSampler>();
        case SamplerType::AlwaysOff:
            return std::make_shared<AlwaysOffSampler>();
        case SamplerType::TraceIdRatio:
            return std::make_shared<TraceIdRatioSampler>(
                config_.traces.sampler.ratio);
        case SamplerType::ParentBased:
        default: {
            auto root = std::make_shared<TraceIdRatioSampler>(
                config_.traces.sampler.ratio);
            return std::make_shared<ParentBasedSampler>(std::move(root));
        }
    }
}

void ObservabilityManager::RegisterLiveSnapshot(
    const std::shared_ptr<ObservabilitySnapshot>& snap) {
    if (!snap) return;
    // Atomic register-and-count (r45): both the registry insert AND
    // the counter increment happen under the SAME mutex acquisition,
    // so the Phase 1c kill loop can never observe a registered-but-
    // uncounted OR counted-but-unregistered snapshot.
    std::lock_guard<std::mutex> g(live_snapshots_mtx_);
    live_snapshots_[snap.get()] = snap;
    inflight_finalizations_.fetch_add(1, std::memory_order_acq_rel);
}

void ObservabilityManager::DeregisterAndDecrement(
    ObservabilitySnapshot& snap) {
    bool decremented = false;
    {
        std::lock_guard<std::mutex> g(live_snapshots_mtx_);
        auto it = live_snapshots_.find(&snap);
        if (it != live_snapshots_.end()) {
            live_snapshots_.erase(it);
            inflight_finalizations_.fetch_sub(1, std::memory_order_acq_rel);
            decremented = true;
        }
    }
    if (decremented) {
        std::lock_guard<std::mutex> g(finalizers_done_mtx_);
        finalizers_done_cv_.notify_all();
    }
}

bool ObservabilityManager::FinalizeFromSnapshot(
    ObservabilitySnapshot& snap,
    int      status_code,
    uint64_t wire_body_size,
    std::string error_type) {
    // Idempotent CAS gate — exactly one caller wins.
    bool expected = false;
    if (!snap.finalized.compare_exchange_strong(expected, true,
            std::memory_order_acq_rel)) {
        return false;
    }

    // Bookkeeping: bump finalizers_in_progress so Phase 1c's
    // wait predicate observes the in-progress finalize as load-bearing.
    finalizers_in_progress_.fetch_add(1, std::memory_order_acq_rel);

    try {
        OnFinalizeWinner(snap, status_code, wire_body_size, error_type);
    } catch (const std::exception& e) {
        logging::Get()->error(
            "FinalizeFromSnapshot threw on snapshot finalize: {}", e.what());
    } catch (...) {
        logging::Get()->error(
            "FinalizeFromSnapshot threw an unknown exception");
    }

    // Decrement-and-deregister BEFORE the cv-notify so the wait
    // predicate sees a consistent counter when it wakes.
    DeregisterAndDecrement(snap);

    finalizers_in_progress_.fetch_sub(1, std::memory_order_acq_rel);
    {
        std::lock_guard<std::mutex> g(finalizers_done_mtx_);
        finalizers_done_cv_.notify_all();
    }
    return true;
}

void ObservabilityManager::OnFinalizeWinner(
    ObservabilitySnapshot& snap,
    int      status_code,
    uint64_t wire_body_size,
    const std::string& error_type) {
    snap.status_code.store(status_code, std::memory_order_release);
    snap.wire_body_size.store(wire_body_size, std::memory_order_release);
    snap.error_type = error_type;

    // Attach response-side attributes to the inbound SERVER span before
    // ending it (per OPENTELEMETRY_DESIGN.md §6.6 + §7.1):
    //   - http.response.status_code (always when status > 0)
    //   - http.server.response.body.size (wire-bytes; 0 for HEAD/1xx/204/304)
    //   - error.type (when set; categorical string per OTel error semconv)
    //   - SpanStatusCode: server 5xx → ERROR; 4xx → UNSET (client misuse,
    //     not the gateway's fault); successful operations stay UNSET.
    if (snap.inbound_span) {
        if (status_code > 0) {
            snap.inbound_span->SetAttribute(
                std::string(sem::kHttpResponseStatusCode),
                AttrValue(static_cast<int64_t>(status_code)));
        }
        snap.inbound_span->SetAttribute(
            std::string(sem::kHttpServerResponseBodySize),
            AttrValue(static_cast<int64_t>(wire_body_size)));
        if (!error_type.empty()) {
            snap.inbound_span->SetAttribute(
                std::string(sem::kErrorType),
                AttrValue(error_type));
            snap.inbound_span->SetStatus(SpanStatusCode::ERROR, error_type);
        } else if (status_code >= 500 && status_code < 600) {
            snap.inbound_span->SetStatus(SpanStatusCode::ERROR);
        }
        // End is idempotent + dispatcher-thread-only — we're on the
        // dispatcher thread because finalize is called from the response-
        // completion path (sync handler / async-completion / streaming
        // End/Abort / middleware-rejection). The Phase 1c kill path uses
        // CASE A/B semantics in KillOutstandingSnapshots.
        snap.inbound_span->End();
    }
}

void ObservabilityManager::BeginShutdown(
    std::chrono::milliseconds timeout) {
    bool expected = false;
    if (!shutdown_started_.compare_exchange_strong(expected, true,
            std::memory_order_acq_rel)) {
        return;  // idempotent
    }
    if (span_processor_) {
        span_processor_->SignalShutdown();
        span_processor_->JoinWorkers(timeout);
    }
    // PeriodicMetricReader shutdown lands in task #70.
}

void ObservabilityManager::KillOutstandingSnapshots(
    std::chrono::milliseconds /*grace*/) {
    // Snapshot the registry under the mutex, then run the per-snapshot
    // kill outside it (each snapshot's CAS gate is independent).
    std::vector<std::shared_ptr<ObservabilitySnapshot>> to_kill;
    {
        std::lock_guard<std::mutex> g(live_snapshots_mtx_);
        to_kill.reserve(live_snapshots_.size());
        for (const auto& [raw, weak] : live_snapshots_) {
            (void)raw;
            if (auto sp = weak.lock()) to_kill.push_back(std::move(sp));
        }
    }

    for (auto& snap_sp : to_kill) {
        ObservabilitySnapshot& snap = *snap_sp;

        // Step 1 (r48): publish kill flag on linked transaction
        // INLINE on the shutdown thread, BEFORE any marshal. Phase-3
        // terminal callbacks acquire-load the flag BEFORE Span::End
        // and skip End when set.
        std::shared_ptr<UpstreamTransactionLink> tx;
        {
            std::lock_guard<std::mutex> g(snap.link_mtx);
            tx = snap.tx_weak.lock();
        }
        if (tx) tx->MarkKilledForShutdown();

        // Step 2: idempotent CAS-from-false-to-true. Ties FinalizeFromSnapshot
        // and the kill loop together — only one wins. If the user-side
        // finalize already won, kill no-ops and we just deregister
        // (deregister is idempotent — DeregisterAndDecrement no-ops
        // when the entry is already gone).
        bool expected = false;
        if (!snap.finalized.compare_exchange_strong(expected, true,
                std::memory_order_acq_rel)) {
            continue;
        }

        // Drop the inbound SERVER span. Per r80: when the kill loop is
        // running on the snapshot's owning dispatcher (CASE B),
        // DropWithoutEnd is safe inline — it mutates Span members on
        // the dispatcher thread. When OFF the owning dispatcher
        // (CASE A), the design uses EnQueue with weak_from_this()
        // capture; for now we INLINE both cases because the per-
        // dispatcher kill marshal infrastructure is part of task #73
        // (HttpServer::Stop wiring). The race window is bounded by
        // BeginShutdown(t) above, which already drained the
        // BatchSpanProcessor; DropWithoutEnd is safe because it's
        // marked atomic-CAS-idempotent at the Span level and only
        // mutates Span-local state.
        if (snap.inbound_span) {
            snap.inbound_span->DropWithoutEnd();
        }

        DeregisterAndDecrement(snap);
        snapshots_killed_on_timeout_.fetch_add(1, std::memory_order_relaxed);
    }
}

void ObservabilityManager::Reload(const ObservabilityConfig& new_config) {
    // Master flag (`enabled`) and Resource fields are restart-required
    // — caller (HttpServer::Reload) emits the WARN log. We ignore
    // them here.
    traces_enabled_.store(new_config.traces.enabled, std::memory_order_release);
    metrics_enabled_.store(new_config.metrics.enabled, std::memory_order_release);
    include_target_info_.store(
        new_config.metrics.prometheus.include_target_info,
        std::memory_order_release);

    // Capture the new sampler config for any FUTURE GetTracer() calls.
    config_.traces.sampler  = new_config.traces.sampler;
    config_.traces.enabled  = new_config.traces.enabled;
    config_.metrics         = new_config.metrics;

    // Build new sampler + push to TracerProvider.
    auto new_sampler = BuildSamplerFromConfig();
    if (tracer_provider_) {
        ProcessorOptions po;  // r79: processor knobs not in obs config yet.
        tracer_provider_->Reload(new_sampler, po);
    }

    if (meter_provider_) {
        MeterReaderOptions ro;
        ro.export_interval = new_config.metrics.reader.export_interval;
        ro.export_timeout  = new_config.metrics.reader.export_timeout;
        meter_provider_->Reload(ro);
    }
}

}  // namespace OBSERVABILITY_NAMESPACE
