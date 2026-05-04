#include "observability/observability_manager.h"

#include "observability/sampler.h"
#include "observability/semantic_conventions.h"
#include "observability/span.h"
#include "observability/span_status.h"

#include "common.h"
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
    PublishLiveFlags(config_);
}

ObservabilityManager::~ObservabilityManager() {
    // Idempotent safety net for tests / abnormal teardown paths.
    BeginShutdown(std::chrono::milliseconds{1000});
}

void ObservabilityManager::PublishLiveFlags(const ObservabilityConfig& c) {
    traces_enabled_.store(c.traces.enabled, std::memory_order_release);
    metrics_enabled_.store(c.metrics.enabled, std::memory_order_release);
    include_target_info_.store(
        c.metrics.prometheus.include_target_info,
        std::memory_order_release);
}

void ObservabilityManager::Init() {
    // Build the sampler from config now that shared_from_this is seeded.
    auto sampler = BuildSamplerFromConfig();
    route_overrides_snapshot_ = BuildRouteOverridesFromConfig();

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

std::shared_ptr<const std::vector<ObservabilityManager::RouteOverride>>
ObservabilityManager::BuildRouteOverridesFromConfig() const {
    auto out = std::make_shared<std::vector<RouteOverride>>();
    out->reserve(config_.traces.sampler.routes.size());
    for (const auto& r : config_.traces.sampler.routes) {
        if (r.path.empty()) continue;
        RouteOverride ov;
        ov.path_prefix = r.path;
        switch (r.sampler) {
            case SamplerType::AlwaysOn:
                ov.sampler = std::make_shared<AlwaysOnSampler>();
                break;
            case SamplerType::AlwaysOff:
                ov.sampler = std::make_shared<AlwaysOffSampler>();
                break;
            case SamplerType::TraceIdRatio:
                ov.sampler = std::make_shared<TraceIdRatioSampler>(r.ratio);
                break;
            case SamplerType::ParentBased:
            default: {
                auto root = std::make_shared<TraceIdRatioSampler>(r.ratio);
                ov.sampler = std::make_shared<ParentBasedSampler>(std::move(root));
                break;
            }
        }
        out->push_back(std::move(ov));
    }
    return out;
}

std::shared_ptr<const Sampler>
ObservabilityManager::EffectiveSamplerForPath(
        const std::string& path) const noexcept {
    auto snap = std::atomic_load_explicit(&route_overrides_snapshot_,
                                            std::memory_order_acquire);
    if (!snap || snap->empty() || path.empty()) return nullptr;
    for (const auto& r : *snap) {
        if (r.path_prefix.empty()) continue;
        // Literal byte-prefix match against the request path.
        if (path.size() < r.path_prefix.size()) continue;
        if (std::memcmp(path.data(), r.path_prefix.data(),
                         r.path_prefix.size()) == 0) {
            return r.sampler;
        }
    }
    return nullptr;
}

void ObservabilityManager::RegisterLiveSnapshot(
    const std::shared_ptr<ObservabilitySnapshot>& snap) {
    if (!snap) return;
    // Insert AND counter-bump under the SAME mutex so the kill loop
    // can never observe a registered-but-uncounted snapshot (or vice versa).
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

    // Make the in-progress finalize visible to the shutdown wait predicate.
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

    // Attach response-side attributes before ending:
    //   http.response.status_code, http.server.response.body.size,
    //   error.type. 5xx maps to SpanStatusCode::ERROR; 4xx stays UNSET
    //   (client misuse is not a server-side error).
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
        // Idempotent + dispatcher-thread-only. The shutdown kill path
        // takes a different code route via KillOutstandingSnapshots.
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

        // Publish kill flag on the linked transaction first so its
        // terminal callbacks observe the marker before they emit
        // Span::End and skip the emit when set.
        std::shared_ptr<UpstreamTransactionLink> tx;
        {
            std::lock_guard<std::mutex> g(snap.link_mtx);
            tx = snap.tx_weak.lock();
        }
        if (tx) tx->MarkKilledForShutdown();

        // CAS arbitrates against any concurrent FinalizeFromSnapshot —
        // exactly one path commits the terminal event.
        bool expected = false;
        if (!snap.finalized.compare_exchange_strong(expected, true,
                std::memory_order_acq_rel)) {
            continue;
        }

        // DropWithoutEnd only flips the dropped_ atomic; it never
        // touches the Span's non-atomic state. Safe to invoke from
        // the stopper thread even if the owning dispatcher is mid-
        // SetAttribute. The processor was already drained by
        // BeginShutdown above, and the destructor will reclaim
        // memory naturally on the last shared_ptr release.
        if (snap.inbound_span) {
            snap.inbound_span->DropWithoutEnd();
        }

        DeregisterAndDecrement(snap);
        snapshots_killed_on_timeout_.fetch_add(1, std::memory_order_relaxed);
    }
}

void ObservabilityManager::Reload(const ObservabilityConfig& new_config) {
    // Master `enabled` and Resource are restart-required; HttpServer::Reload
    // emits the warn for those. Ignore them here.
    PublishLiveFlags(new_config);

    // Capture the new sampler config for any future GetTracer() calls.
    config_.traces.sampler  = new_config.traces.sampler;
    config_.traces.enabled  = new_config.traces.enabled;
    config_.metrics         = new_config.metrics;

    // Build new sampler + push to TracerProvider.
    auto new_sampler = BuildSamplerFromConfig();
    if (tracer_provider_) {
        ProcessorOptions po;
        tracer_provider_->Reload(new_sampler, po);
    }

    // Republish per-route overrides. Atomic-store so the middleware's
    // EffectiveSamplerForPath load picks up the new vector without a
    // mutex; in-flight requests that already captured the old snapshot
    // continue with the previous policy until they complete.
    auto new_routes = BuildRouteOverridesFromConfig();
    std::atomic_store_explicit(&route_overrides_snapshot_,
                                std::move(new_routes),
                                std::memory_order_release);

    if (meter_provider_) {
        MeterReaderOptions ro;
        ro.export_interval = new_config.metrics.reader.export_interval;
        ro.export_timeout  = new_config.metrics.reader.export_timeout;
        meter_provider_->Reload(ro);
    }
}

}  // namespace OBSERVABILITY_NAMESPACE
