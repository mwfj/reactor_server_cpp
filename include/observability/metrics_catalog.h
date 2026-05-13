#pragma once

// MetricsCatalog — single owning struct of every catalogued instrument
// exposed at `/metrics` and OTLP. Built at `ObservabilityManager::Init()`
// after `meter_provider_` is constructed; subsystems retrieve instrument
// pointers via `manager->catalog()` and emit through them.
//
// Lifetime: instrument pointers are owned by `MeterProvider` (which is
// owned by `ObservabilityManager`); they remain valid for the manager's
// lifetime. Subsystems must never outlive the manager — anchor on
// `weak_ptr<ObservabilityManager>` where lifetime is unclear.

#include "observability/common.h"

namespace OBSERVABILITY_NAMESPACE {

class Counter;
class Histogram;
class UpDownCounter;
class ObservabilityManager;

struct MetricsCatalog {
    // Server-side HTTP -----------------------------------------------
    UpDownCounter* http_server_active_requests = nullptr;
    Histogram*     http_server_request_body_size = nullptr;
    Histogram*     http_server_response_body_size = nullptr;
    UpDownCounter* reactor_http_connections_active = nullptr;
    Counter*       reactor_http_connections_accepted = nullptr;

    // Transport-level connection metrics — incremented at accept() time
    // BEFORE any protocol bytes flow. `reactor.net.connections.active`
    // is the raw transport gauge (TCP/TLS), independent of whether the
    // peer ever sends an HTTP/1, HTTP/2, or WS frame; `accepted` is the
    // monotonic event counter. Both are unlabeled — adding labels would
    // require synthesizing per-connection state before classification.
    UpDownCounter* reactor_net_connections_active = nullptr;
    Counter*       reactor_net_connections_accepted = nullptr;

    // TLS handshake outcome counter — `outcome` ∈ {success, failure}.
    // Emitted at handshake-state transition: success when DoHandshake()
    // returns TLS_COMPLETE; failure at the close-callback site driven by
    // the handshake-failure branch.
    Counter*       reactor_tls_handshakes = nullptr;

    // Client / upstream pool. Instruments are registered at boot so
    // `/metrics` surfaces the series as soon as data points arrive;
    // emit sites for this group are partially deferred — see the
    // observability design doc for the wiring status.
    Histogram*     http_client_request_duration = nullptr;
    UpDownCounter* http_client_active_requests = nullptr;
    Counter*       reactor_upstream_retries = nullptr;
    UpDownCounter* reactor_upstream_pool_connections_idle = nullptr;
    UpDownCounter* reactor_upstream_pool_connections_active = nullptr;
    Histogram*     reactor_upstream_pool_checkout_wait_duration = nullptr;

    // Middleware (auth + rate limit + circuit breaker + ws) ---------
    Counter*       reactor_auth_requests = nullptr;
    Counter*       reactor_auth_cache_lookups = nullptr;
    Counter*       reactor_auth_jwks_refreshes = nullptr;
    Counter*       reactor_rate_limit_decisions = nullptr;
    Histogram*     reactor_rate_limit_tokens = nullptr;
    UpDownCounter* reactor_circuit_breaker_state = nullptr;
    Counter*       reactor_circuit_breaker_rejected = nullptr;
    Counter*       reactor_circuit_breaker_transitions = nullptr;
    Counter*       reactor_dns_resolves = nullptr;
    UpDownCounter* reactor_websocket_active_connections = nullptr;
    Counter*       reactor_websocket_frames = nullptr;

    // Self-metrics (OTel pipeline introspection) --------------------
    Counter*       reactor_otel_spans_created = nullptr;
    Counter*       reactor_otel_spans_dropped_unsampled = nullptr;
    Counter*       reactor_otel_spans_dropped_unended = nullptr;
    Counter*       reactor_otel_spans_dropped_queue_full = nullptr;
    Counter*       reactor_otel_spans_exported = nullptr;
    Histogram*     reactor_otel_export_duration = nullptr;
    Counter*       reactor_otel_propagation_invalid = nullptr;
    Counter*       reactor_otel_metrics_export_skipped = nullptr;
    Counter*       reactor_otel_snapshots_killed_on_timeout = nullptr;
    Counter*       reactor_otel_cardinality_overflow = nullptr;

    // Register every catalog instrument with the manager's MeterProvider.
    // Idempotent: `Meter::Get*` is get-or-create, so calling twice yields
    // the same pointers. Called once from `ObservabilityManager::Init()`
    // after `meter_provider_` is non-null.
    static void Build(ObservabilityManager& manager, MetricsCatalog& out);
};

}  // namespace OBSERVABILITY_NAMESPACE
