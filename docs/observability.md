# Observability

OpenTelemetry-based observability for the gateway: distributed traces (W3C and Jaeger propagation, OTLP/HTTP push), metrics (Prometheus pull or OTLP push), and structured logs (via spdlog, with trace correlation). All disabled by default — enable per signal.

---

## Quick start

Enable tracing + Prometheus metrics:

```json
{
  "observability": {
    "enabled": true,
    "resource": {
      "service.name": "edge-gateway",
      "service.version": "1.4.0"
    },
    "traces": {
      "enabled": true,
      "exporter": "otlp_http",
      "otlp": { "upstream": "otel-collector" },
      "sampler": { "kind": "trace_id_ratio", "ratio": 0.05 },
      "propagators": ["w3c"]
    },
    "metrics": {
      "enabled": true,
      "exporter": "prometheus_pull",
      "prometheus": { "path": "/metrics" }
    }
  },
  "upstreams": [
    {
      "name": "otel-collector",
      "host": "otel.svc.cluster.local",
      "port": 4318,
      "pool": { "max_connections": 4, "max_idle_connections": 4 }
    }
  ]
}
```

`observability.enabled` is the master switch. When `false`, every per-request hook short-circuits at zero cost; nothing is allocated and no propagator headers are injected. The master switch is **restart-required** — turning observability on for the first time means a restart. Sub-switches (`traces.enabled`, `metrics.enabled`) are live-reloadable.

---

## Master switch and per-signal switches

| Field | Restart required? | Behavior when off |
|---|---|---|
| `observability.enabled` | YES | Subsystem not allocated. Every hook is a `if (!manager_) return` short-circuit. |
| `traces.enabled` | NO (live-reloadable) | Tracer returns non-recording spans; propagator does not inject `sampled=1`. Allocations on the boot-time path still happen so a SIGHUP `false → true` works. |
| `metrics.enabled` | NO (live-reloadable) | `/metrics` handler returns `404`. PMR skips `Export()` calls. Counters keep accumulating in memory so cumulative totals stay coherent across toggles. |

The master switch governs *allocation*; the sub-switches govern *emission*.

---

## Trace pipeline

### Sampler

`traces.sampler.kind` selects the root sampler:

| Kind | Meaning |
|---|---|
| `always_on` | Sample every trace. |
| `always_off` | Sample no traces. |
| `trace_id_ratio` | Sample by hashing the trace-id; configured via `traces.sampler.ratio` (0.0-1.0). |
| `parent_based` | Honor the inbound parent's `sampled` flag; falls back to `traces.sampler.default_root` when no parent. |

Per-route overrides live in `traces.sampler.routes`:

```json
"sampler": {
  "kind": "trace_id_ratio",
  "ratio": 0.05,
  "routes": [
    { "pattern": "/health",    "kind": "always_off" },
    { "pattern": "/checkout/*","kind": "always_on" }
  ]
}
```

Route overrides are evaluated **directly** (not wrapped in `ParentBased`). `/health: always_off` will drop a sampled-parent request and propagate `sampled=0` downstream — that is the documented intent. The default root falls back to `ParentBased`.

All sampler fields above are live-reloadable. In-flight spans keep their original sampler.

### Exporter — OTLP/HTTP push

Set `traces.exporter = "otlp_http"`. The exporter posts OTLP/JSON v1.10 to the upstream named in `traces.otlp.upstream` at path `/v1/traces` (the Collector default). Headers and timeout:

```json
"traces": {
  "exporter": "otlp_http",
  "otlp": {
    "upstream": "otel-collector",
    "path": "/v1/traces",
    "headers": { "authorization": "Bearer ${OTEL_EXPORTER_OTLP_TOKEN}" },
    "timeout_ms": 10000
  }
}
```

Headers and timeout are live-reloadable; `upstream` and `exporter` are restart-required.

### Batch processor tuning

```json
"traces": {
  "batch": {
    "max_queue_size":              2048,
    "max_export_batch_size":       512,
    "schedule_delay_ms":           5000,
    "retries.max_attempts":        3,
    "retries.initial_backoff_ms":  1000,
    "retries.max_backoff_ms":      10000
  }
}
```

The per-batch export deadline is sourced from `traces.otlp.timeout_ms` — there is no separate `batch.export_timeout_ms` field. Batch shape (`max_export_batch_size`, `schedule_delay_ms`) and retry policy (`retries.*`) are all live-reloadable; the worker re-reads them on the next iteration after `cv_.notify_all()`. `max_queue_size` allocates the queue at construction and is restart-only.

### Propagation

`traces.propagators` is an ordered list of formats the gateway **extracts** and **injects**. Default `["w3c"]`. Recognised tokens: `w3c`, `jaeger`. Live-reloadable.

```json
"traces": { "propagators": ["w3c", "jaeger"] }
```

#### Extract precedence

`CompositePropagator::Extract` iterates the list in order and returns the first child that produced a valid context. With `["w3c", "jaeger"]` configured, a request carrying both `traceparent` and `uber-trace-id` is parented by the `traceparent` value; the Jaeger header is ignored on that request. Reverse the list to flip the precedence.

#### Inject behavior

`CompositePropagator::Inject` calls **every** child, so a single SpanContext is emitted in every wire format the operator configured. Each propagator strips its owned headers before injecting, so client-supplied trace headers never leak through the gateway.

| Propagator | Owned headers | Format |
|---|---|---|
| `w3c` | `traceparent`, `tracestate` | `00-{32-hex-trace}-{16-hex-span}-{02-hex-flags}` |
| `jaeger` | `uber-trace-id` | `{trace-id}:{span-id}:{parent-span-id}:{flags}`. trace-id is 16-hex (legacy 64-bit, left-padded with zeros) or 32-hex; flags' sampled bit (`0x01`) is honored on extract; debug/firehose bits are dropped. |

Validation rejects an empty `propagators` list and any unknown token at startup and on SIGHUP.

---

## Metric pipeline

### Prometheus pull

```json
"metrics": {
  "enabled": true,
  "exporter": "prometheus_pull",
  "prometheus": { "path": "/metrics", "include_target_info": true }
}
```

The gateway registers a `GET /metrics` handler at startup if `cli.metrics_endpoint` and `cli.health_endpoint` are configured. The handler returns Prometheus exposition by default; if the request carries `Accept: application/openmetrics-text`, it returns OpenMetrics 1.0 instead.

When `metrics.enabled = false` the route is still registered (so a SIGHUP `false → true` works without restart) but the handler returns `404 Not Found`.

#### Naming sanitization

OTel instrument names are sanitized to Prometheus naming rules: `[a-zA-Z0-9_]` → `_`, leading-digit gets a `_` prepended. Counter names get a `_total` suffix. Sanitization collisions across distinct OTel names are detected per-render: the first instrument wins; subsequent collisions are SUPPRESSED so output never has conflicting `# TYPE` blocks. Each distinct collision pair is logged at most once per process.

### OTLP/HTTP push

```json
"metrics": {
  "enabled": true,
  "exporter": "otlp_http",
  "otlp":   { "upstream": "otel-collector", "path": "/v1/metrics" },
  "export_interval_ms": 10000,
  "export_timeout_ms":  10000
}
```

`export_interval_ms` and `export_timeout_ms` are live-reloadable. `exporter` and `otlp.upstream` are restart-required.

When traces and metrics both target `otlp_http` and the same upstream is configured, the gateway shares **one** `OtlpHttpExporter` instance between the BatchSpanProcessor and the PeriodicMetricReader. The shared-exporter shutdown coordinator ensures the first-finishing worker doesn't drop the other's final batch (see "Shutdown drain" below).

---

## The `/metrics` endpoint

| Aspect | Value |
|---|---|
| Default path | `/metrics` (configurable via `metrics.prometheus.path`) |
| Method | `GET` |
| Default content-type | `text/plain; version=0.0.4; charset=utf-8` (Prometheus exposition) |
| OpenMetrics content-type | `application/openmetrics-text; version=1.0.0; charset=utf-8` (when `Accept` requests it) |
| Live-reload of `path` | When `/metrics` not yet registered, yes. After registration, restart-only. |
| Auth | None by default. Pair with a route-level auth policy if you want to gate scrapes. |

---

## Sampling at high RPS

Tail-sampling is out of scope (see "Out of scope" below). For high-RPS deployments:

1. Set `traces.sampler.kind = "trace_id_ratio"` with a low default ratio (e.g. `0.01`).
2. Use route overrides to *raise* sampling on critical paths and *drop* sampling on health endpoints:

```json
"sampler": {
  "kind": "trace_id_ratio",
  "ratio": 0.01,
  "routes": [
    { "pattern": "/health",     "kind": "always_off" },
    { "pattern": "/api/checkout/*", "kind": "always_on" }
  ]
}
```

3. Route-override sampling is evaluated **direct**, not wrapped by `ParentBased`. `always_off` will drop sampled-parent traces — that is the operator's documented intent (the `/health` row above is the canonical use case).

4. Tune the batch processor: under high RPS, raise `max_queue_size` (default 2048) and `max_export_batch_size` (default 512). A queue-overflow drop increments the `dropped_on_overflow_` counter on the BSP — surface it via the self-metrics catalog when that lands.

---

## Shutdown drain

The gateway's four-phase shutdown ensures observability data finalizes before workers are joined:

1. **StopAccepting + drain inbound.** `WaitForAllAsyncDrain(budget)` waits for in-flight inbound + proxy transactions. Dispatchers + upstream pool still alive.
2. **`FlushObservabilityForShutdown`.** Calls `WaitForAllAsyncDrain` first so finalizes land in the BSP queue, then `ObservabilityManager::FlushAll(deadline)` blocks the BSP until queue depth hits zero (or deadline) and the PMR until its in-flight cycle completes.
3. **`KillAndShutdownObservability`.** If the flush did not drain in time, `KillOutstandingSnapshots` CAS-finalizes survivors with `error_type="shutdown"`. Then the manager joins BSP + PMR workers within remaining budget. When BSP and PMR share an `OtlpHttpExporter` instance, the manager calls `DisableExporterShutdownOnDrain` on each before signalling them, then signals the exporter exactly once after both workers drain.
4. **StopDispatchers.**

Total shutdown time is bounded by `cli.shutdown_drain_timeout_sec` (default 30s).

---

## Live-reloadable vs restart-required

| Field | Live | Notes |
|---|---|---|
| `observability.enabled` (master) | NO | Restart-required. |
| `traces.enabled`, `metrics.enabled` | YES | Sub-switches govern emission, not allocation. |
| `traces.sampler.kind` / `ratio` / `routes` | YES | Atomic-swap; in-flight spans keep their original sampler. |
| `traces.otlp.headers` / `timeout_ms` | YES | `OtlpHttpExporter::ReloadHeaders`. |
| `traces.otlp.upstream`, `traces.exporter` | NO | Restart-required. Boot-time hot-swap from NoopProcessor to BatchSpanProcessor lands automatically once `MarkServerReady` wires the OTLP upstream. |
| `traces.propagators` | YES | Atomic-swap on `propagator_`. New requests immediately use the new composite. |
| `traces.batch.*` | YES | Worker re-reads after `cv_.notify_all()`. |
| `metrics.export_interval_ms` / `export_timeout_ms` | YES | `MeterProvider::Reload`. |
| `metrics.prometheus.path`, `metrics.prometheus.include_target_info` | YES (`path`: only when `/metrics` not yet registered) | |
| `metrics.exporter`, `metrics.otlp.upstream` | NO | Restart-required. |
| `resource.*` (`service.name`, `service.version`, `service.instance.id`) | NO | Span identity baseline. |

---

## Troubleshooting

### Spans not appearing in the collector

1. Confirm `observability.enabled = true` AND `traces.enabled = true`.
2. Confirm `traces.exporter = "otlp_http"` and the `traces.otlp.upstream` name maps to a configured upstream.
3. Check the Collector receives traffic from the gateway upstream IP/port (`tcpdump -i any -n port 4318`).
4. Inspect the gateway's structured logs for `OtlpHttpExporter` failures — non-2xx responses are logged at `warn` with the response status.
5. If the sampler is `trace_id_ratio` with low ratio, generate enough traffic — or raise the ratio temporarily.
6. The BSP drops spans on queue overflow rather than blocking. The drop counter is exposed via the self-metrics catalog (Phase 3) — until that lands, watch for `BatchSpanProcessor::OnEnd dropped span` warnings.

### Metric scrapes return `404`

1. Confirm `metrics.enabled = true` AND `metrics.exporter = "prometheus_pull"`.
2. Confirm the path matches `metrics.prometheus.path` (default `/metrics`).
3. Confirm `cli.health_endpoint` and `cli.metrics_endpoint` are not disabled (`--no-metrics-endpoint`). The route is only registered when both are enabled at startup.

### Cardinality overflow

`MetricLabelRegistry` enforces a per-instrument allowlist + cap. When a label value exceeds the cap, subsequent values for that label key route to `__overflow__`:

```
http_server_request_duration_seconds{route="/api/checkout/*",method="GET",status_code="__overflow__"}
```

If you see `__overflow__` series in `/metrics`, either the upstream emitting the offending value has unbounded cardinality (status code from external API; user-id label) or the configured cap is too low. The cap is a process-startup field today (per-key SIGHUP is restart-only).

### `traces.propagators` rejected on reload

`ConfigLoader::Validate` rejects an empty `propagators` list and any unknown token. Recognised tokens are `w3c` and `jaeger`. Check the SIGHUP target file for typos like `"jeager"` or `"W3C"` (the value is case-sensitive).

### Inbound `traceparent` is ignored

Verify `propagators` includes `"w3c"`. If it does, the inbound `traceparent` value is malformed — the W3C parser rejects:
- length other than 55 chars,
- version field other than `00`,
- non-lowercase hex in any field,
- all-zero trace-id or span-id.

The gateway treats the inbound as no parent and starts a fresh trace. Run with debug logging to surface the per-request reason.

---

## Configuration field reference

### `observability` block

| Field | Type | Default | Live-reloadable | Notes |
|---|---|---|---|---|
| `enabled` | bool | `false` | NO | Master switch. |
| `resource.service.name` | string | (none) | NO | Required when `enabled=true`. |
| `resource.service.version` | string | (none) | NO | |
| `resource.service.instance.id` | string | auto | NO | Defaults to `${HOSTNAME}-${PID}`. |

### `observability.traces` block

| Field | Type | Default | Live-reloadable |
|---|---|---|---|
| `enabled` | bool | `false` | YES |
| `exporter` | string | (empty) | NO |
| `otlp.upstream` | string | (none) | NO |
| `otlp.path` | string | `/v1/traces` | NO |
| `otlp.headers` | object | `{}` | YES |
| `otlp.timeout_ms` | int | 10000 | YES |
| `sampler.kind` | string | `parent_based` | YES |
| `sampler.ratio` | number | `1.0` | YES |
| `sampler.default_root` | string | `always_on` | YES |
| `sampler.routes` | array | `[]` | YES |
| `propagators` | array | `["w3c"]` | YES |
| `batch.max_queue_size` | int | 2048 | NO (allocated at construction) |
| `batch.max_export_batch_size` | int | 512 | YES |
| `batch.schedule_delay_ms` | int | 5000 | YES |
| `batch.retries.max_attempts` | int | 3 | YES |
| `batch.retries.initial_backoff_ms` | int | 1000 | YES |
| `batch.retries.max_backoff_ms` | int | 10000 | YES |

### `observability.metrics` block

| Field | Type | Default | Live-reloadable |
|---|---|---|---|
| `enabled` | bool | `false` | YES |
| `exporter` | string | (empty) | NO |
| `otlp.upstream` | string | (none) | NO |
| `otlp.path` | string | `/v1/metrics` | NO |
| `export_interval_ms` | int | 10000 | YES |
| `export_timeout_ms` | int | 10000 | YES |
| `prometheus.path` | string | `/metrics` | YES (when route not yet registered) |
| `prometheus.include_target_info` | bool | `true` | YES |

---

## Out of scope

The following are deferred and not currently implemented — listed so future readers don't expect them.

- **Per-attempt CLIENT span on proxy.** A separate child span for each upstream attempt of a proxied request, with `error_type` on the terminal callback. Phase 3.
- **`auth.idp_check` INTERNAL span.** A span around each IdP request lifecycle (JWKS fetch, OIDC discovery, RFC 7662 introspection). Phase 3.
- **Full §7 metrics catalog.** Wired counters / histograms across server, client, upstream pool, auth, rate-limit, circuit breaker, DNS, WebSocket, and self-metrics. Phase 3.
- **Per-message WebSocket spans.** Spans for WS frames after the upgrade SERVER span. Phase 3, gated by `traces.websocket_messages` (default `false`).
- **Self-handler shutdown helper.** `ScheduleStopAfterCurrentResponse()` for handlers that want to deliver their response and *then* trigger a graceful stop. Phase 3.
- **Tail sampling.** Out of scope; deploy a Collector with the tail-sampling processor between the gateway and the trace backend.
- **Histogram exemplars.** Out of scope.
- **OTLP/protobuf.** OTLP/JSON is the only serializer; OTLP/protobuf may be added later for collector-side parity.
- **B3, X-Ray propagators.** Only W3C and Jaeger ship today.
- **Logs signal.** Logs continue via spdlog with trace correlation in the log format; the OpenTelemetry logs SDK is not wired.
