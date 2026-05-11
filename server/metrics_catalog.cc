#include "observability/metrics_catalog.h"

#include "observability/counter.h"
#include "observability/histogram.h"
#include "observability/meter.h"
#include "observability/meter_provider.h"
#include "observability/metric_label_registry.h"
#include "observability/observability_manager.h"

#include <utility>

namespace OBSERVABILITY_NAMESPACE {

namespace {

MetricLabelRegistry::Catalog MakeCatalog(
        std::vector<std::string> keys,
        std::unordered_map<std::string, size_t> caps = {}) {
    MetricLabelRegistry::Catalog c;
    c.allowed_keys = std::move(keys);
    c.value_cardinality_caps = std::move(caps);
    return c;
}

constexpr double kBytesBuckets[] = {
    0, 256, 1024, 4 * 1024, 16 * 1024, 64 * 1024,
    256 * 1024, 1024 * 1024, 4 * 1024 * 1024,
};

constexpr double kLatencyBuckets[] = {
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
};

constexpr double kTokensBuckets[] = {0, 1, 10, 100, 1000, 10000};

template <size_t N>
std::vector<double> ToVec(const double (&arr)[N]) {
    return std::vector<double>(arr, arr + N);
}

}  // namespace

void MetricsCatalog::Build(ObservabilityManager& manager, MetricsCatalog& out) {
    Meter* meter = manager.meter_provider()->GetMeter("reactor.gateway", "1");

    // §7.1 server ----------------------------------------------------
    out.http_server_active_requests = meter->GetUpDownCounter(
        "http.server.active_requests",
        "Active inbound requests",
        "{requests}",
        MakeCatalog({"http.request.method", "http.route"},
                     {{"http.route", kDefaultRouteCap}}));

    out.http_server_request_body_size = meter->GetHistogram(
        "http.server.request.body.size",
        "Inbound request body size in bytes",
        "By",
        ToVec(kBytesBuckets),
        MakeCatalog({"http.request.method", "http.route"},
                     {{"http.route", kDefaultRouteCap}}));

    out.http_server_response_body_size = meter->GetHistogram(
        "http.server.response.body.size",
        "Outbound response body size in bytes",
        "By",
        ToVec(kBytesBuckets),
        MakeCatalog({"http.request.method", "http.route",
                       "http.response.status_code"},
                     {{"http.route", kDefaultRouteCap}}));

    out.reactor_http_connections_active = meter->GetUpDownCounter(
        "reactor.http.connections.active",
        "Active HTTP connections",
        "{connections}",
        MakeCatalog({"protocol"}));

    out.reactor_http_connections_accepted = meter->GetCounter(
        "reactor.http.connections.accepted",
        "Accepted HTTP connections",
        "{connections}",
        MakeCatalog({"protocol"}));

    // §7.2 client / upstream pool -----------------------------------
    // Defense-in-depth: keys whose values come from operator config
    // (`server.address`, `reactor.upstream.service`) or include
    // formatted free-text components (`error.type` includes
    // std::to_string(status_code)) get explicit caps to make the
    // closed-enum contract visible. Default would already be
    // kDefaultGenericCap (256), but explicit declaration documents
    // intent and protects against a future caller forgetting the
    // discipline.
    out.http_client_request_duration = meter->GetHistogram(
        "http.client.request.duration",
        "Upstream request latency in seconds",
        "s",
        ToVec(kLatencyBuckets),
        MakeCatalog({"http.request.method", "server.address", "server.port",
                       "http.response.status_code", "error.type",
                       "reactor.upstream.service"},
                     {{"server.address",          kDefaultGenericCap},
                      {"error.type",              kDefaultGenericCap},
                      {"reactor.upstream.service", kDefaultGenericCap}}));

    out.http_client_active_requests = meter->GetUpDownCounter(
        "http.client.active_requests",
        "In-flight upstream requests",
        "{requests}",
        MakeCatalog({"reactor.upstream.service"},
                     {{"reactor.upstream.service", kDefaultGenericCap}}));

    out.reactor_upstream_retries = meter->GetCounter(
        "reactor.upstream.retries",
        "Upstream request retries",
        "{retries}",
        MakeCatalog({"reactor.upstream.service", "reason"},
                     {{"reactor.upstream.service", kDefaultGenericCap}}));

    out.reactor_upstream_pool_connections_idle = meter->GetUpDownCounter(
        "reactor.upstream.pool.connections.idle",
        "Idle pool connections",
        "{connections}",
        MakeCatalog({"reactor.upstream.service"},
                     {{"reactor.upstream.service", kDefaultGenericCap}}));

    out.reactor_upstream_pool_connections_active = meter->GetUpDownCounter(
        "reactor.upstream.pool.connections.active",
        "Active pool connections",
        "{connections}",
        MakeCatalog({"reactor.upstream.service"},
                     {{"reactor.upstream.service", kDefaultGenericCap}}));

    out.reactor_upstream_pool_checkout_wait_duration = meter->GetHistogram(
        "reactor.upstream.pool.checkout.wait.duration",
        "Pool checkout wait time in seconds",
        "s",
        ToVec(kLatencyBuckets),
        MakeCatalog({"reactor.upstream.service", "outcome"},
                     {{"reactor.upstream.service", kDefaultGenericCap}}));

    // §7.3 middleware ------------------------------------------------
    // `issuer` values are operator-config-bounded (issuer names from
    // auth config); explicit caps document the bound.
    out.reactor_auth_requests = meter->GetCounter(
        "reactor.auth.requests",
        "Auth admission decisions",
        "{requests}",
        MakeCatalog({"outcome", "issuer", "reason"},
                     {{"issuer", kDefaultGenericCap}}));

    out.reactor_auth_cache_lookups = meter->GetCounter(
        "reactor.auth.cache.lookups",
        "Auth introspection cache lookups",
        "{lookups}",
        MakeCatalog({"outcome", "issuer"},
                     {{"issuer", kDefaultGenericCap}}));

    out.reactor_auth_jwks_refreshes = meter->GetCounter(
        "reactor.auth.jwks.refreshes",
        "JWKS cache refreshes",
        "{refreshes}",
        MakeCatalog({"issuer", "outcome"},
                     {{"issuer", kDefaultGenericCap}}));

    // `zone` and `service` values come from operator config (zone
    // names, upstream names). Explicit caps document the bound.
    out.reactor_rate_limit_decisions = meter->GetCounter(
        "reactor.rate_limit.decisions",
        "Rate-limit admission decisions",
        "{requests}",
        MakeCatalog({"zone", "decision"},
                     {{"zone", kDefaultGenericCap}}));

    out.reactor_rate_limit_tokens = meter->GetHistogram(
        "reactor.rate_limit.tokens",
        "Bucket level on each check",
        "{tokens}",
        ToVec(kTokensBuckets),
        MakeCatalog({"zone"},
                     {{"zone", kDefaultGenericCap}}));

    out.reactor_circuit_breaker_state = meter->GetUpDownCounter(
        "reactor.circuit_breaker.state",
        "Circuit-breaker membership (1 if in state, else 0)",
        "{}",
        MakeCatalog({"service", "state"},
                     {{"service", kDefaultGenericCap}}));

    out.reactor_circuit_breaker_rejected = meter->GetCounter(
        "reactor.circuit_breaker.rejected",
        "Requests rejected by the circuit breaker",
        "{requests}",
        MakeCatalog({"service", "reason"},
                     {{"service", kDefaultGenericCap}}));

    out.reactor_circuit_breaker_transitions = meter->GetCounter(
        "reactor.circuit_breaker.transitions",
        "Circuit-breaker state transitions",
        "{transitions}",
        MakeCatalog({"service", "from", "to", "trigger"},
                     {{"service", kDefaultGenericCap}}));

    out.reactor_dns_resolves = meter->GetCounter(
        "reactor.dns.resolves",
        "DNS resolution outcomes",
        "{resolves}",
        MakeCatalog({"outcome"}));

    out.reactor_websocket_active_connections = meter->GetUpDownCounter(
        "reactor.websocket.active_connections",
        "Active WebSocket connections",
        "{connections}",
        MakeCatalog({}));

    out.reactor_websocket_frames = meter->GetCounter(
        "reactor.websocket.frames",
        "WebSocket frames",
        "{frames}",
        MakeCatalog({"op", "direction"}));

    // §7.4 self-metrics ---------------------------------------------
    out.reactor_otel_spans_created = meter->GetCounter(
        "reactor.otel.spans.created",
        "Spans started by the tracer",
        "{spans}",
        MakeCatalog({}));

    out.reactor_otel_spans_dropped_unsampled = meter->GetCounter(
        "reactor.otel.spans.dropped_unsampled",
        "Spans dropped by the sampler",
        "{spans}",
        MakeCatalog({}));

    out.reactor_otel_spans_dropped_queue_full = meter->GetCounter(
        "reactor.otel.spans.dropped_queue_full",
        "BatchSpanProcessor queue overflow drops",
        "{spans}",
        MakeCatalog({}));

    out.reactor_otel_spans_exported = meter->GetCounter(
        "reactor.otel.spans.exported",
        "Span export outcomes",
        "{spans}",
        MakeCatalog({"outcome"}));

    out.reactor_otel_export_duration = meter->GetHistogram(
        "reactor.otel.export.duration",
        "Exporter end-to-end duration in seconds",
        "s",
        ToVec(kLatencyBuckets),
        MakeCatalog({}));

    out.reactor_otel_propagation_invalid = meter->GetCounter(
        "reactor.otel.propagation.invalid",
        "Trace-context parse failures",
        "{invalidations}",
        MakeCatalog({"format", "reason"}));

    out.reactor_otel_metrics_export_skipped = meter->GetCounter(
        "reactor.otel.metrics_export_skipped",
        "Metric exports skipped (metrics.enabled=false)",
        "{exports}",
        MakeCatalog({}));

    out.reactor_otel_snapshots_killed_on_timeout = meter->GetCounter(
        "reactor.otel.snapshots_killed_on_timeout",
        "ObservabilitySnapshots finalized by the kill loop",
        "{snapshots}",
        MakeCatalog({}));

    out.reactor_otel_cardinality_overflow = meter->GetCounter(
        "reactor.otel.cardinality_overflow",
        "Label values rewritten to __overflow__",
        "{rewrites}",
        MakeCatalog({"label_key"}));
}

}  // namespace OBSERVABILITY_NAMESPACE
