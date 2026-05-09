#include "observability/observability_manager.h"

#include "observability/batch_span_processor.h"
#include "observability/periodic_metric_reader.h"
#include "observability/sampler.h"
#include "observability/semantic_conventions.h"
#include "observability/span.h"
#include "observability/span_status.h"

#include "common.h"
#include "log/logger.h"

namespace OBSERVABILITY_NAMESPACE {

std::shared_ptr<ObservabilityManager> ObservabilityManager::Create(
    ObservabilityConfig             config,
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
    ObservabilityConfig             config,
    std::shared_ptr<const Resource> resource,
    std::shared_ptr<SpanProcessor>  span_processor,
    std::shared_ptr<RandomSource>   random)
    : config_(std::move(config)),
      resource_(std::move(resource)),
      random_(std::move(random)),
      span_processor_(std::move(span_processor)) {
    PublishLiveFlags(config_);
}

// Bounded budget for the dtor's safety-net BeginShutdown. Production
// shuts down through HttpServer::Stop with the operator-configured
// shutdown_drain_timeout_sec and never reaches this branch with live
// work. The dtor budget covers tests / abnormal teardown only — long
// enough to drain a typical processor flush, short enough that an
// unwinding test doesn't hang.
static constexpr auto kDtorShutdownBudget = std::chrono::milliseconds{1000};

ObservabilityManager::~ObservabilityManager() {
    // Idempotent safety net for tests / abnormal teardown paths.
    // Production goes through HttpServer::Stop's coordinated kill +
    // shutdown sequence and never reaches the dtor with live
    // snapshots. Tests and abnormal teardown (panic, exception during
    // construction-then-drop) skip that sequence — kill outstanding
    // snapshots first so survivors' weak manager refs don't outlive
    // the registry. Without this, FinalizeIfSnapshot becomes a
    // manager.lock()==nullptr no-op once the dtor begins and inbound
    // SERVER spans silently leak (never End()-ed).
    KillOutstandingSnapshots(std::chrono::milliseconds{0});
    BeginShutdown(kDtorShutdownBudget);
}

void ObservabilityManager::PublishLiveFlags(const ObservabilityConfig& c) {
    // Gate the live "traces enabled" flag on whether a real span
    // pipeline exists. main.cc installs a null SpanProcessor when
    // traces.exporter is empty (Prometheus-only / metrics-only
    // deployments), and a null processor produces non-recording
    // spans regardless of c.traces.enabled. Publishing
    // traces_enabled_=true in that mode would have the inbound
    // middleware allocate a SpanContext + ObservabilitySnapshot per
    // request and the proxy strip transparent W3C propagation —
    // pure overhead with no telemetry to show for it.
    //
    // PRECONDITION: span_processor_ is set once at Init() and never
    // hot-swapped. A future caller that swaps the processor at
    // runtime (e.g. exporter pipeline rebuild on SIGHUP) MUST call
    // PublishLiveFlags(config_) explicitly post-swap — otherwise
    // traces_enabled_ stays cached against the stale processor and
    // either overcommits work to a now-null pipeline or silently
    // disables tracing on a pipeline that just came online.
    const bool traces_pipeline_present = c.traces.enabled && span_processor_ != nullptr;
    traces_enabled_.store(traces_pipeline_present,
                            std::memory_order_release);
    metrics_enabled_.store(c.metrics.enabled, std::memory_order_release);
    include_target_info_.store(
        c.metrics.prometheus.include_target_info,
        std::memory_order_release);
    // Operator visibility — traces.enabled is documented as live-
    // reloadable, but with no SpanProcessor attached (e.g. boot-time
    // exporter empty) the flip is silently no-op. Warn the
    // operator instead of failing closed; metrics-only deployments are
    // valid and shouldn't fail to reload, but the operator should know
    // their staged change didn't take effect. Restart is required to
    // attach a processor. Warn ONCE per process so SIGHUP reloads of a
    // stable misconfig don't spam the log.
    if (c.traces.enabled && span_processor_ == nullptr
        && !traces_processor_misconfig_warned_) {
        logging::Get()->warn(
            "observability.traces.enabled=true but no SpanProcessor "
            "is attached (traces.exporter was empty at boot). "
            "Restart with traces.exporter set to enable tracing.");
        traces_processor_misconfig_warned_ = true;
    }
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
    Meter* http_server_meter = meter_provider_->GetMeter("reactor.http.server");
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
    const std::string& metrics_path = config_.metrics.prometheus.path;

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
        if (path.size() < r.path_prefix.size()) continue;

        // FIXME: Is this has the potential memory leak or performance issue? 
        // We are doing memcmp for every request, and the path_prefix can be of arbitrary length. 
        // We should consider using a more efficient data structure for route overrides, 
        // such as a trie or prefix tree, to optimize the lookup process?
        if (std::memcmp(path.data(), r.path_prefix.data(),
                         r.path_prefix.size()) != 0) {
            continue;
        }
        // Path-or-subtree match: configured `path` matches request
        // path exactly, OR the request path's next byte is `/`
        // (subtree), OR the configured path itself ends with `/`
        // (operator-encoded subtree, including bare `/` for root).
        // Rejects partial-segment matches like `/api` vs `/apifoo`.
        if (path.size() == r.path_prefix.size()) return r.sampler;
        if (path[r.path_prefix.size()] == '/') return r.sampler;
        if (r.path_prefix.back() == '/') return r.sampler;
    }
    return nullptr;
}

// Backstop for missed FinalizeIfSnapshot at any production call site.
// Defined here (not in the header) so the dtor body sees the full
// ObservabilityManager type for FinalizeFromSnapshot. The CAS gate
// inside FinalizeFromSnapshot makes this idempotent against a late
// finalizer that wins the race; manager.lock() failure means the
// kill path already finalized us through the registry.
ObservabilitySnapshot::~ObservabilitySnapshot() {
    if (finalized.load(std::memory_order_acquire)) return;
    auto mgr = manager.lock();
    if (!mgr) return;  // manager torn down — kill loop ran or test path.

    // Exception-safe: FinalizeFromSnapshot wraps OnFinalizeWinner in
    // try/catch and never throws. The mgr shared_ptr keeps the
    // manager alive for the duration of the call. The counter bump
    // is precise (not best-effort): the registry holds only a
    // weak_ptr, so the dtor running implies the last shared_ptr
    // dropped — meaning no concurrent thread can be inside
    // FinalizeFromSnapshot for this snapshot. The CAS below is
    // therefore guaranteed to win, so every counter increment
    // corresponds to a real backstop fire.
    mgr->snapshots_finalized_via_dtor_.fetch_add(1, std::memory_order_relaxed);

    mgr->FinalizeFromSnapshot(*this, /*status=*/0, /*wire_body=*/0,
                                /*error_type=*/"unfinalized_drop");
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
    // Reserve the in-progress slot BEFORE the CAS. A winner preempted
    // before incrementing would let HttpServer::Stop's drain
    // (FlushObservabilityForShutdown + KillAndShutdownObservability)
    // observe finalizers_in_progress_ == 0, call BeginShutdown, and
    // drop the still-pending Span::End. Decrement on CAS failure so
    // the loser path doesn't leak the reservation.
    finalizers_in_progress_.fetch_add(1, std::memory_order_acq_rel);

    // Idempotent CAS gate — exactly one caller wins.
    bool expected = false;
    if (!snap.finalized.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        finalizers_in_progress_.fetch_sub(1, std::memory_order_acq_rel);
        // Surface losers that carried an abnormal observation. The
        // winner's payload — whatever it is — is what gets exported,
        // so a non-empty loser error_type means a real terminal-event
        // signal was discarded (e.g. client_disconnect lost to a
        // success finalize). Empty-error_type losers are routine race
        // outcomes (a success record losing to a shutdown/abort
        // record where the recorded outcome is the more important
        // one) — silent. The trace_id + snap address let operators
        // correlate with the exported span.
        if (!error_type.empty()) {
            logging::Get()->warn(
                "FinalizeFromSnapshot CAS lost: trace_id={} snap=0x{:x} "
                "discarded_error_type={} discarded_status={} "
                "discarded_wire_body_size={}",
                snap.trace_context.trace_id().ToHex(),
                reinterpret_cast<uintptr_t>(&snap),
                error_type, status_code, wire_body_size);
        }
        // Notify so a drain wait that latched on this loser-bump
        // wakes once the counter returns to its real value.
        std::lock_guard<std::mutex> g(finalizers_done_mtx_);
        finalizers_done_cv_.notify_all();
        return false;
    }

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

    // Derive the effective error.type ONCE so the span attribute,
    // span status description, and histogram label all carry the
    // same value — span/metric correlations break otherwise. OTel
    // HTTP semconv requires error.type on 5xx; the finalizer's
    // error_type carries transport aborts / middleware rejections,
    // and for bare 5xx with no caller-supplied reason we stringify
    // the status code (e.g. "500", "502").
    std::string effective_error = error_type;
    if (effective_error.empty() && status_code >= 500
        && status_code < 600) {
        effective_error = std::to_string(status_code);
    }

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
        if (!effective_error.empty()) {
            labels.emplace_back("error.type", effective_error);
        }
        http_server_request_duration_->Record(duration_s, labels);
    }

    // Attach response-side attributes before ending:
    //   http.response.status_code, http.server.response.body.size,
    //   error.type. 5xx maps to SpanStatusCode::ERROR; 4xx stays UNSET
    //   (client misuse is not a server-side error). The same
    //   effective_error is applied as the span attribute and the
    //   ERROR status description so span ↔ histogram correlations
    //   carry the identical value.
    if (snap.inbound_span) {
        if (status_code > 0) {
            snap.inbound_span->SetAttribute(
                std::string(SEMCONV_NAMESPACE::kHttpResponseStatusCode),
                AttrValue(static_cast<int64_t>(status_code)));
        }
        snap.inbound_span->SetAttribute(
            std::string(SEMCONV_NAMESPACE::kHttpServerResponseBodySize),
            AttrValue(static_cast<int64_t>(wire_body_size)));
        if (!effective_error.empty()) {
            snap.inbound_span->SetAttribute(
                std::string(SEMCONV_NAMESPACE::kErrorType),
                AttrValue(effective_error));
            // OTel HTTP semconv: server-side 4xx maps to Status=UNSET
            // (client misuse, not a server fault). ERROR is reserved
            // for 5xx and transport-level aborts (status_code <= 0
            // means the response never reached the wire — covers
            // client_disconnect / server_timeout / handler_threw /
            // ws_upgrade_handler_threw / async_route_warmup_unavailable
            // / rejected_by_*_middleware-on-disconnect). Without this
            // gate, 4xx auth/validation rejections would inflate
            // server-error span telemetry even though the metric
            // already correctly carries error.type=…
            const bool is_server_error =
                (status_code >= 500 && status_code < 600) ||
                status_code <= 0;
            if (is_server_error) {
                snap.inbound_span->SetStatus(SpanStatusCode::ERROR,
                                              effective_error);
            }
        }
        // Idempotent + dispatcher-thread-only. The shutdown kill path
        // takes a different code route via KillOutstandingSnapshots.
        snap.inbound_span->End();
    }
}

void ObservabilityManager::RegisterMetricReader(
    std::shared_ptr<PeriodicMetricReader> reader) {
    if (!reader) return;
    if (metric_reader_) {
        logging::Get()->warn(
            "ObservabilityManager::RegisterMetricReader: reader already set; ignoring");
        return;
    }
    metric_reader_ = std::move(reader);
}

void ObservabilityManager::SwapToBatchSpanProcessor(
    std::shared_ptr<SpanProcessor> new_processor) {
    if (!new_processor) return;
    // Idempotent: only swap when we're still on the boot-time Noop. A
    // second swap (e.g. SIGHUP-driven exporter rebuild) is a future-phase
    // concern — today the OTLP wiring runs once at MarkServerReady.
    if (dynamic_cast<NoopSpanProcessor*>(span_processor_.get()) == nullptr) {
        logging::Get()->warn(
            "SwapToBatchSpanProcessor: processor already swapped; ignoring");
        return;
    }
    span_processor_ = new_processor;
    if (tracer_provider_) {
        tracer_provider_->SwapProcessorAcrossTracers(new_processor);
    }
}

bool ObservabilityManager::span_processor_is_batch_for_test() const noexcept {
    return dynamic_cast<BatchSpanProcessor*>(span_processor_.get()) != nullptr;
}

bool ObservabilityManager::exporter_is_shared_for_test() const noexcept {
    auto bsp = std::dynamic_pointer_cast<BatchSpanProcessor>(span_processor_);
    if (!bsp || !metric_reader_) return false;
    auto span_exp   = bsp->exporter();
    auto metric_exp = metric_reader_->exporter();
    if (!span_exp || !metric_exp) return false;
    return dynamic_cast<void*>(span_exp.get())
        == dynamic_cast<void*>(metric_exp.get());
}

void ObservabilityManager::BeginShutdown(
    std::chrono::milliseconds timeout) {
    // The shutdown_started_ latch is one-shot — never reset. Production
    // callers shut the manager down once; tests construct a fresh
    // manager per cycle (see obs_stress's per-iteration MakeManager).
    // A future "restart in place" would need the latch to reset
    // before re-arming the worker drain.
    bool expected = false;
    if (!shutdown_started_.compare_exchange_strong(expected, true,
            std::memory_order_acq_rel)) {
        return;  // idempotent
    }

    const auto deadline = std::chrono::steady_clock::now() + timeout;
    auto remaining = [deadline]() {
        const auto now = std::chrono::steady_clock::now();
        return now >= deadline ? std::chrono::milliseconds{0}
            : std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
    };

    // Detect a single exporter wired into BOTH BSP and PMR (e.g.
    // OtlpHttpExporter inherits both interfaces). Per-worker self-signal
    // would race: the first to finish would shut the exporter down before
    // the other could flush. dynamic_cast<void*> yields the most-derived
    // address, so the two interface sub-object pointers (different vtable
    // offsets) reduce to the same pointer when they point to the same
    // object.
    auto bsp = std::dynamic_pointer_cast<BatchSpanProcessor>(span_processor_);
    std::shared_ptr<SpanExporter>   shared_span_exporter;
    std::shared_ptr<MetricExporter> shared_metric_exporter;
    if (bsp && metric_reader_) {
        shared_span_exporter   = bsp->exporter();
        shared_metric_exporter = metric_reader_->exporter();
    }
    const bool exporter_shared =
        shared_span_exporter && shared_metric_exporter
        && dynamic_cast<void*>(shared_span_exporter.get())
            == dynamic_cast<void*>(shared_metric_exporter.get());

    if (exporter_shared) {
        bsp->DisableExporterShutdownOnDrain();
        metric_reader_->DisableExporterShutdownOnDrain();
    }

    if (span_processor_) {
        span_processor_->SignalShutdown();
        span_processor_->JoinWorkers(remaining());
    }
    if (metric_reader_) {
        metric_reader_->SignalShutdown();
        metric_reader_->JoinWorkers(remaining());
    }

    if (exporter_shared && shared_span_exporter) {
        shared_span_exporter->SignalShutdown();
    }
}

void ObservabilityManager::KillOutstandingSnapshots(
    [[maybe_unused]] std::chrono::milliseconds grace) {
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

        // The link/kill protocol must be atomic against
        // ProxyTransaction::Start. Without holding link_mtx across
        // the finalized CAS:
        //   1. Kill takes link_mtx, sees tx_weak empty, releases.
        //   2. Start (under link_mtx) sees finalized=false, publishes
        //      tx_weak, releases.
        //   3. Kill CAS-flips finalized=true.
        //   4. Nobody ever calls MarkKilledForShutdown — the proxy
        //      runs against a snapshot already removed from
        //      drain counters.
        // Holding link_mtx across the CAS makes Start's locked check
        // either observe finalized=true (and self-mark) OR run
        // entirely before/after kill's whole locked region.
        std::shared_ptr<UpstreamTransactionLink> tx;
        bool finalize_won = false;
        {
            std::lock_guard<std::mutex> g(snap.link_mtx);
            tx = snap.tx_weak.lock();
            bool expected = false;
            finalize_won = snap.finalized.compare_exchange_strong(
                expected, true, std::memory_order_acq_rel);
        }
        if (!finalize_won) {
            continue;  // a finalizer already won; let it run.
        }
        // Only mark survivors as killed for shutdown — transactions
        // that finalized normally (CAS lost above) are already past
        // their terminal callback and don't need a redundant
        // EnQueue + Cancel.
        if (tx) tx->MarkKilledForShutdown();

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
    // PRECONDITION: callers serialise Reload via HttpServer::reload_mtx_.
    // The field-by-field mutation of config_ below is single-writer
    // safe ONLY under that lock; concurrent Reload calls would race
    // on the non-atomic config_ assignments. Reads of the live
    // atomic flags (TracesEnabled / MetricsEnabled / IncludeTargetInfo)
    // are unaffected — they go through PublishLiveFlags's release
    // stores and stay coherent across the writer's mutation window.
    //
    // Master `enabled` and Resource are restart-required; HttpServer::Reload
    // emits the warn for those. Ignore them here.
    PublishLiveFlags(new_config);

    // Live-reloadable fields ONLY — copy field-by-field rather than
    // wholesale-assign-then-restore. Adding a new field to
    // ObservabilityConfig MUST classify it here: omit and it stays
    // restart-only (live behaviour pinned at ctor); add and it picks
    // up the staged value. The save/overwrite/restore pattern made
    // it possible for a field added to MetricsConfig to silently
    // take the staged value while restart-only fields kept restoring;
    // explicit assignment makes the classification visible at the
    // call site. The field-by-field grouping below mirrors the
    // restart-vs-live header in observability_config.h.
    //
    // Restart-only fields NOT touched here:
    //   traces.exporter, traces.otlp.upstream, traces.batch.max_queue_size,
    //   metrics.exporter, metrics.otlp.upstream, metrics.prometheus.path,
    //   metrics.histogram_buckets.
    config_.traces.enabled               = new_config.traces.enabled;
    config_.traces.sampler               = new_config.traces.sampler;
    config_.traces.otlp.headers          = new_config.traces.otlp.headers;
    config_.traces.otlp.timeout_ms       = new_config.traces.otlp.timeout_ms;
    config_.traces.batch.max_export_batch_size =
        new_config.traces.batch.max_export_batch_size;
    config_.traces.batch.schedule_delay  = new_config.traces.batch.schedule_delay;
    config_.traces.batch.retries         = new_config.traces.batch.retries;

    config_.metrics.enabled              = new_config.metrics.enabled;
    config_.metrics.otlp.headers         = new_config.metrics.otlp.headers;
    config_.metrics.otlp.timeout_ms      = new_config.metrics.otlp.timeout_ms;
    config_.metrics.reader               = new_config.metrics.reader;
    config_.metrics.prometheus.include_target_info =
        new_config.metrics.prometheus.include_target_info;

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
