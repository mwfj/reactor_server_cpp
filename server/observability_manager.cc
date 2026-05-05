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

    // Register the OTel HTTP-semconv server-request duration histogram
    // up front so OnFinalizeWinner can Record() without any per-request
    // get-or-create cost. Buckets: configured `metrics.histogram_buckets`
    // for "http.server.request.duration" if present, otherwise the
    // OTel-recommended default exponential-ish ladder (seconds).
    Meter* http_server_meter =
        meter_provider_->GetMeter("reactor.http.server");
    std::vector<double> duration_buckets;
    auto bucket_it = config_.metrics.histogram_buckets.find(
        "http.server.request.duration");
    if (bucket_it != config_.metrics.histogram_buckets.end()
        && !bucket_it->second.empty()) {
        duration_buckets = bucket_it->second;
    } else {
        duration_buckets = {0.005, 0.01, 0.025, 0.05, 0.075, 0.1,
                             0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0};
    }
    MetricLabelRegistry::Catalog duration_catalog;
    duration_catalog.allowed_keys = {
        "http.request.method",
        "http.response.status_code",
        "http.route",
        "network.protocol.version",
        "error.type",
    };
    http_server_request_duration_ = http_server_meter->GetHistogram(
        "http.server.request.duration",
        "Duration of HTTP server requests",
        "s",
        std::move(duration_buckets),
        std::move(duration_catalog));
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
    out->reserve(config_.traces.sampler.routes.size() + 1);
    bool metrics_path_overridden = false;
    const std::string& metrics_path =
        config_.metrics.prometheus.path;
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
        if (!metrics_path.empty() && ov.path_prefix == metrics_path) {
            metrics_path_overridden = true;
        }
        out->push_back(std::move(ov));
    }
    // Auto-suppress trace sampling for the live Prometheus scrape
    // path. Without this, every /metrics scrape (typically once per
    // 15s per Prometheus) emits a SERVER span, polluting the trace
    // export with self-noise. The override is appended ONLY when the
    // operator hasn't already provided one for the same path so an
    // explicit always_on / trace_id_ratio override still wins.
    // Route registration is restart-only — we use the live path so a
    // reload that stages a different prometheus.path doesn't move
    // the auto-suppress to a path that isn't actually scraped.
    if (!metrics_path.empty() && !metrics_path_overridden
        && config_.metrics.exporter == "prometheus_pull") {
        RouteOverride auto_off;
        auto_off.path_prefix = metrics_path;
        auto_off.sampler = std::make_shared<AlwaysOffSampler>();
        out->push_back(std::move(auto_off));
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

    // Record the OTel HTTP server request duration metric.
    // Always record when the instrument exists — `metrics.enabled`
    // gates the EXPORT surface (Prometheus 404, OTLP push skip), not
    // in-memory writes. Stopping writes during a temporary toggle
    // would silently lose history from cumulative histograms; flipping
    // export back on must resume the full series with the in-flight
    // counts intact. The instrument pointer is null only when Init()
    // didn't run (master `enabled=false`).
    if (http_server_request_duration_ != nullptr) {
        const auto duration_ns =
            std::chrono::steady_clock::now() - snap.start_steady;
        const double duration_s =
            std::chrono::duration<double>(duration_ns).count();
        std::vector<std::pair<std::string, std::string>> labels;
        labels.reserve(5);
        if (!snap.method.empty()) {
            labels.emplace_back("http.request.method", snap.method);
        }
        if (status_code > 0) {
            labels.emplace_back("http.response.status_code",
                                std::to_string(status_code));
        }
        if (!snap.route_pattern.empty()) {
            labels.emplace_back("http.route", snap.route_pattern);
        }
        if (!snap.network_protocol_version.empty()) {
            labels.emplace_back("network.protocol.version",
                                snap.network_protocol_version);
        }
        // OTel HTTP semconv: error.type is required for 5xx and
        // optional for everything else. The finalizer's error_type
        // covers transport aborts and middleware rejections; for
        // bare 5xx the reviewer's prior round derived a stringified
        // status — match that here so span↔histogram correlation is
        // consistent.
        std::string effective_error = error_type;
        if (effective_error.empty() && status_code >= 500
            && status_code < 600) {
            effective_error = std::to_string(status_code);
        }
        if (!effective_error.empty()) {
            labels.emplace_back("error.type", std::move(effective_error));
        }
        http_server_request_duration_->Record(duration_s, labels);
    }

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
    // Preserve restart-only fields explicitly: max_queue_size (queue
    // allocated at ctor), traces.exporter / metrics.exporter,
    // otlp.upstream pair, prometheus.path (route registered once at
    // ctor), and histogram_buckets (instruments built at ctor). The
    // BuildRouteOverridesFromConfig() call below uses prometheus.path
    // to auto-suppress scrape sampling — pinning it to the live path
    // keeps the auto-suppress on the actually-registered route after
    // a SIGHUP that stages a different path.
    auto saved_traces_exporter   = config_.traces.exporter;
    auto saved_traces_otlp_up    = config_.traces.otlp.upstream;
    auto saved_traces_max_queue  = config_.traces.batch.max_queue_size;
    auto saved_metrics_exporter  = config_.metrics.exporter;
    auto saved_metrics_otlp_up   = config_.metrics.otlp.upstream;
    auto saved_metrics_prom_path = config_.metrics.prometheus.path;
    auto saved_metrics_buckets   = config_.metrics.histogram_buckets;

    config_.traces.sampler  = new_config.traces.sampler;
    config_.traces.enabled  = new_config.traces.enabled;
    config_.traces.batch    = new_config.traces.batch;
    config_.metrics         = new_config.metrics;

    config_.traces.exporter         = std::move(saved_traces_exporter);
    config_.traces.otlp.upstream    = std::move(saved_traces_otlp_up);
    config_.traces.batch.max_queue_size = saved_traces_max_queue;
    config_.metrics.exporter        = std::move(saved_metrics_exporter);
    config_.metrics.otlp.upstream   = std::move(saved_metrics_otlp_up);
    config_.metrics.prometheus.path = std::move(saved_metrics_prom_path);
    config_.metrics.histogram_buckets = std::move(saved_metrics_buckets);

    // Build new sampler + push to TracerProvider, including the
    // updated batch-shape knobs so a SIGHUP that edits
    // traces.batch.{max_export_batch_size,schedule_delay} actually
    // takes effect on the running BatchSpanProcessor (the previous
    // default-constructed ProcessorOptions made the reload a silent
    // no-op).
    auto new_sampler = BuildSamplerFromConfig();
    if (tracer_provider_) {
        ProcessorOptions po;
        po.max_export_batch_size =
            static_cast<size_t>(new_config.traces.batch.max_export_batch_size);
        po.schedule_delay = new_config.traces.batch.schedule_delay;
        po.retries_max_attempts =
            new_config.traces.batch.retries.max_attempts;
        po.retries_initial_backoff =
            new_config.traces.batch.retries.initial_backoff;
        po.retries_max_backoff =
            new_config.traces.batch.retries.max_backoff;
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
