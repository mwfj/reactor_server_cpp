#include "observability/observability_middleware.h"

#include "http/http_request.h"
#include "http/http_response.h"
#include "observability/observability_manager.h"
#include "observability/observability_snapshot.h"
#include "observability/semantic_conventions.h"
#include "observability/span.h"
#include "observability/span_context.h"
#include "observability/tracer.h"
#include "observability/trace_context.h"

#include <chrono>
#include <utility>

namespace OBSERVABILITY_NAMESPACE {

namespace {

// Tracer name used by the observability middleware for inbound
// SERVER spans. Backends group spans by (Resource,
// InstrumentationScope); using a stable name lets operators filter
// "all gateway-emitted server spans" by scope name.
constexpr const char* kInboundTracerName = "reactor.http.server";

// Capture inbound trace context from the request. Task #69 will
// implement full W3C Propagator extraction; for now we treat the
// inbound `traceparent` header as ABSENT (RequestTraceContext gets a
// freshly-generated current_local trace+span id) because the
// Propagator hasn't landed yet. This is correct behavior for the
// "no inbound context" case; the propagator slice extends the helper
// without changing the middleware shape.
RequestTraceContext BuildRequestTraceContext(
    const HttpRequest& /*request*/,
    Tracer* tracer) {
    RequestTraceContext rtx;
    // Empty remote_parent → root span.
    // current_local is built by the tracer when StartSpan generates
    // ids; the middleware reads it back from the resulting Span's
    // Context() and copies into rtx so outbound propagation has a
    // stable identity.
    (void)tracer;  // unused until Propagator lands.
    return rtx;
}

}  // namespace

HttpRouter::Middleware MakeObservabilityMiddleware(
    std::shared_ptr<ObservabilityManager> manager) {
    if (!manager) {
        // Defensive: caller (HttpServer::MarkServerReady) should NOT
        // install this middleware when observability is disabled.
        // If it does, fall through every request as a true no-op.
        return [](HttpRequest& /*request*/, HttpResponse& /*response*/) {
            return true;
        };
    }

    // Capture by value: the middleware closure outlives the call site
    // (HttpRouter holds it in `middlewares_`). The shared_ptr keeps
    // the manager alive at least as long as the router, which is the
    // contract HttpServer enforces (manager is constructed before
    // MarkServerReady installs this middleware, and is owned by
    // HttpServer for the server's lifetime).
    auto mgr_sp = std::move(manager);

    return [mgr_sp](HttpRequest& request, HttpResponse& /*response*/) -> bool {
        // 1. Ensure route_match is populated. The router's
        //    ResolveRouteMatch is idempotent (short-circuits when
        //    kind != None) so calling it both from middleware AND
        //    from the dispatch site is safe. We can't call it directly
        //    here because the middleware doesn't hold a router pointer;
        //    instead, the dispatch site calls PopulateRouteParams
        //    BEFORE running the middleware chain, so by the time we
        //    arrive route_match.kind is already set. (See
        //    HttpRouter::DispatchHandler in server/http_router.cc.)

        // 2. Snapshot the live trace flags. Disabled traces → still
        //    build the snapshot (metrics + middleware-rejection paths
        //    rely on it) but skip Span allocation.
        const bool traces_enabled = mgr_sp->TracesEnabled();

        // 3. Build trace context.
        Tracer* tracer = mgr_sp->GetTracer(kInboundTracerName);
        RequestTraceContext rtx = BuildRequestTraceContext(request, tracer);

        // 4. Allocate the SERVER Span (only when traces are enabled).
        std::shared_ptr<Span> server_span;
        if (traces_enabled) {
            StartSpanOptions opts;
            opts.kind                    = SpanKind::SERVER;
            opts.has_parent              = rtx.remote_parent.IsValid();
            opts.parent                  = rtx.remote_parent;
            opts.has_explicit_start_time = false;

            // Initial server-span attributes per OTel HTTP semconv.
            // Only http.request.method + http.route + url.scheme +
            // network.protocol.version; status_code lands at
            // FinalizeFromSnapshot.
            if (!request.method.empty()) {
                opts.attributes.emplace_back(
                    std::string(sem::kHttpRequestMethod),
                    AttrValue(request.method));
            }
            if (!request.route_match.pattern.empty()) {
                opts.attributes.emplace_back(
                    std::string(sem::kHttpRoute),
                    AttrValue(request.route_match.pattern));
            }
            if (!request.url_scheme.empty()) {
                opts.attributes.emplace_back(
                    std::string(sem::kUrlScheme),
                    AttrValue(request.url_scheme));
            }
            if (!request.network_protocol_version.empty()) {
                opts.attributes.emplace_back(
                    std::string(sem::kNetworkProtocolVersion),
                    AttrValue(request.network_protocol_version));
            }

            const std::string& span_name =
                !request.route_match.pattern.empty()
                    ? request.route_match.pattern
                    : (request.method.empty() ? std::string("HTTP")
                                                : request.method);
            server_span = tracer->StartSpan(span_name, opts);
            // Mirror the freshly-created SpanContext back into rtx so
            // downstream outbound-propagation paths read a populated
            // current_local.
            rtx.current_local = server_span->Context();
            rtx.is_recording = server_span->IsRecording();
        }

        // 5. Build the snapshot + register-and-count under
        //    live_snapshots_mtx_. PopulateSnapshot is the field-fill;
        //    RegisterLiveSnapshot is the SINGLE atomic register-and-
        //    count site (r45).
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

        // 6. Hand back to the request. Trace ctx + span are also
        //    written so downstream code (proxy, auth-path outbound
        //    HTTP, finalize wiring) can read them off the request.
        request.trace_ctx = rtx;
        request.observability_span = server_span;
        request.obs_snapshot = std::move(snap);

        // Always-pass — observability is non-blocking.
        return true;
    };
}

}  // namespace OBSERVABILITY_NAMESPACE
