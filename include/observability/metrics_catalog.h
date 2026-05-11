#pragma once

// MetricsCatalog — single owning struct of every §7 instrument exposed
// at `/metrics` and OTLP. Built at `ObservabilityManager::Init()` after
// `meter_provider_` is constructed; subsystems retrieve instrument
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
    // §7.1 server -----------------------------------------------------
    UpDownCounter* http_server_active_requests = nullptr;
    Histogram*     http_server_request_body_size = nullptr;
    Histogram*     http_server_response_body_size = nullptr;
    UpDownCounter* reactor_http_connections_active = nullptr;
    Counter*       reactor_http_connections_accepted = nullptr;

    // §7.2 client / upstream pool. Instruments are registered at boot
    // so `/metrics` surfaces the series as soon as data points arrive;
    // emit sites for this group are partially deferred — see the PR
    // description's "Still deferred" section for the wiring status.
    Histogram*     http_client_request_duration = nullptr;
    UpDownCounter* http_client_active_requests = nullptr;
    Counter*       reactor_upstream_retries = nullptr;
    UpDownCounter* reactor_upstream_pool_connections_idle = nullptr;
    UpDownCounter* reactor_upstream_pool_connections_active = nullptr;
    Histogram*     reactor_upstream_pool_checkout_wait_duration = nullptr;

    // §7.3 middleware ------------------------------------------------
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

    // §7.4 self-metrics ----------------------------------------------
    Counter*       reactor_otel_spans_created = nullptr;
    Counter*       reactor_otel_spans_dropped_unsampled = nullptr;
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
