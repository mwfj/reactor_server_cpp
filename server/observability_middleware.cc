#include "observability/observability_middleware.h"

#include "http/http_request.h"
#include "http/http_response.h"
#include "observability/observability_manager.h"
#include "observability/observability_snapshot.h"
#include "observability/propagator.h"
#include "observability/semantic_conventions.h"
#include "observability/span.h"
#include "observability/span_context.h"
#include "observability/tracer.h"
#include "observability/trace_context.h"

#include <chrono>
#include <utility>

namespace OBSERVABILITY_NAMESPACE {

namespace {

// Backends group spans by (Resource, InstrumentationScope); a stable
// scope name lets operators filter "all gateway-emitted server spans".
constexpr const char* kInboundTracerName = "reactor.http.server";

// Extract the inbound trace context. Missing or malformed → invalid
// remote_parent (the SERVER span becomes a root). current_local is
// filled by the caller after StartSpan returns. The propagator is the
// manager-provided composite, so any wire format the operator
// configured (W3C, Jaeger) is honoured.
RequestTraceContext BuildRequestTraceContext(
    const HttpRequest& request,
    const Propagator* propagator) {
    RequestTraceContext rtx;
    if (!propagator) return rtx;
    auto parent = propagator->Extract(request.headers);
    if (parent.has_value()) {
        rtx.remote_parent = std::move(*parent);
    }
    return rtx;
}

}  // namespace

HttpRouter::Middleware MakeObservabilityMiddleware(
    std::shared_ptr<ObservabilityManager> manager) {
    if (!manager) {
        return [](HttpRequest& /*request*/, HttpResponse& /*response*/) {
            return true;
        };
    }

    // The shared_ptr keeps the manager alive for the lifetime of the
    // closure, which the router holds for the server's lifetime.
    auto mgr_sp = std::move(manager);

    return [mgr_sp](HttpRequest& request, HttpResponse& /*response*/) -> bool {
        // PopulateRouteParams runs before the middleware chain so
        // request.route_match is already set.

        const bool traces_enabled = mgr_sp->TracesEnabled();
        Tracer* tracer = mgr_sp->GetTracer(kInboundTracerName);

        // Skip parent extraction entirely when traces are off — the
        // snapshot is still built so metrics + middleware-rejection
        // paths can finalize, but no header lookup or context copy
        // needs to happen.
        RequestTraceContext rtx;
        std::shared_ptr<const Propagator> live_propagator;
        if (traces_enabled) {
            live_propagator = mgr_sp->propagator();
            rtx = BuildRequestTraceContext(request, live_propagator.get());
        }

        std::shared_ptr<Span> server_span;
        if (traces_enabled) {
            StartSpanOptions opts;
            opts.kind                    = SpanKind::SERVER;
            opts.has_parent              = rtx.remote_parent.IsValid();
            opts.parent                  = rtx.remote_parent;
            opts.has_explicit_start_time = false;
            // Resolve the per-route sampler override (if any) using the
            // raw request path BEFORE pattern resolution, per the
            // documented `traces.sampler.routes.path` semantic. The
            // override flows through to Tracer::StartSpan via opts;
            // null means "use the global sampler".
            opts.sampler_override =
                mgr_sp->EffectiveSamplerForPath(request.path);

            // OTel HTTP semconv initial server-span attributes.
            // status_code is filled at FinalizeFromSnapshot.
            opts.attributes.reserve(4);
            if (!request.method.empty()) {
                opts.attributes.emplace_back(
                    std::string(SEMCONV_NAMESPACE::kHttpRequestMethod),
                    AttrValue(request.method));
            }
            if (!request.route_match.pattern.empty()) {
                opts.attributes.emplace_back(
                    std::string(SEMCONV_NAMESPACE::kHttpRoute),
                    AttrValue(request.route_match.pattern));
            }
            if (!request.url_scheme.empty()) {
                opts.attributes.emplace_back(
                    std::string(SEMCONV_NAMESPACE::kUrlScheme),
                    AttrValue(request.url_scheme));
            }
            if (!request.network_protocol_version.empty()) {
                opts.attributes.emplace_back(
                    std::string(SEMCONV_NAMESPACE::kNetworkProtocolVersion),
                    AttrValue(request.network_protocol_version));
            }

            const std::string& span_name =
                !request.route_match.pattern.empty()
                    ? request.route_match.pattern
                    : (request.method.empty() ? std::string("HTTP")
                                                : request.method);
            server_span = tracer->StartSpan(span_name, opts);
            // Outbound propagation reads current_local; mirror the
            // freshly-created SpanContext back into rtx.
            rtx.current_local = server_span->Context();
            rtx.is_recording = server_span->IsRecording();
        }

        auto snap = std::make_shared<ObservabilitySnapshot>();
        snap->trace_context             = rtx.current_local;
        snap->route_pattern             = request.route_match.pattern;
        snap->method                    = request.method;
        snap->url_scheme                = request.url_scheme;
        snap->network_protocol_version  = request.network_protocol_version;
        snap->start_steady              = std::chrono::steady_clock::now();
        snap->start_system              = std::chrono::system_clock::now();
        snap->inbound_span              = server_span;
        snap->manager                   = mgr_sp;
        snap->owning_dispatcher         = request.owning_dispatcher;

        mgr_sp->RegisterLiveSnapshot(snap);

        // Republish to the request so downstream code (proxy, auth
        // outbound, finalize wiring) can read trace ctx + span + snap.
        request.trace_ctx = rtx;
        request.observability_span = server_span;
        request.obs_snapshot = std::move(snap);

        return true;
    };
}

}  // namespace OBSERVABILITY_NAMESPACE
