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

4. Tune the batch processor: under high RPS, raise `max_queue_size` (default 2048) and `max_export_batch_size` (default 512). A queue-overflow drop increments `reactor.otel.spans.dropped_queue_full` on `/metrics` (see "Pipeline health" below).

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
6. The BSP drops spans on queue overflow rather than blocking. Drop counters now surface via `/metrics`:
    - `reactor.otel.spans.dropped_queue_full` — queue overflow.
    - `reactor.otel.spans.exported{outcome=non_retryable_fail}` — collector returned 4xx (excluding 429), exporter exception, or the payload was rejected outright. Sums batch spans, not events.
    - `reactor.otel.spans.exported{outcome=retryable_fail}` — retryable export attempt that will be retried (or eventually counted as `non_retryable_fail` if the retry budget is exhausted).
   Structured-log lines provide additional context (attempt counts, batch sizes):
    - `BatchSpanProcessor: non-retryable export failure; dropping batch (N spans, attempt=K)`
    - `BatchSpanProcessor: retryable export failed after N attempts; dropping batch (M spans)`
    - `BatchSpanProcessor::Export threw: ... (dropping N spans)` — exporter raised; treated as non-retryable.

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

The gateway also emits a self-metric per overflow event: `reactor.otel.cardinality_overflow{label_key="<key>"}`. Watch for sustained rises on a specific `label_key` — that's the surface for the alert.

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
| `auth_idp_span` | bool | `true` | YES |
| `websocket_messages` | bool | `false` | YES |
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
### Per-attempt CLIENT span on proxy

Every upstream attempt for a proxied request gets its own CLIENT span. Retries produce distinct spans linked to the same SERVER parent; the per-attempt span_id is stamped into the outbound `traceparent` so each attempt is independently identifiable in the collector. Terminal outcomes set `http.response.status_code` (success) or `error.type` (e.g. `upstream_timeout`, `connect_failed`, `circuit_open`, `client_disconnect`).

### `auth.idp_check` INTERNAL span

When `traces.auth_idp_span = true` (default), every deferred IdP introspection POST is wrapped by an INTERNAL span parented at the SERVER span. Setting it to `false` falls back to recording `auth.pending_start` / `auth.pending_end` events on the SERVER span — useful when collector cardinality is a concern. Live-reloadable.

### Per-message WebSocket spans

```json
"traces": { "websocket_messages": true }
```

Default `false`. When enabled, every text/binary frame produces a short `ws.recv` (inbound) or `ws.send` (outbound) INTERNAL span parented at the upgrade SERVER span, with `ws.opcode` and `ws.payload_size` attributes. Control frames (Ping / Pong / Close) are NOT spanned. Live-reloadable. Caveat: WS connections produce far more messages than HTTP requests — enabling this on a high-throughput WS-heavy workload will significantly increase span volume.

### Sampler self-noise auto-derivation

The gateway's own `/health`, `/stats`, and configured Prometheus path are auto-added to `traces.sampler.routes` with `always_off` so operator-side probes never pollute traces. Operator-supplied entries with the same path are preserved verbatim — explicit override always wins.

### `metrics.prometheus.path` reload

When SIGHUP changes `metrics.prometheus.path`, the gateway logs a warn ("restart to apply") and keeps the live value. The HTTP route bound at startup remains the only path served. Restart to register the new path.

> **Breaking (Phase 3):** `metrics.prometheus.path = "/"` is now rejected at boot when `metrics.exporter = "prometheus_pull"`. Previously the sampler self-noise auto-prepend silently no-op'd on this value, leaving `/metrics` traffic to feed its own traces; the loud-fail makes the misconfig visible immediately. Set a distinct path (the default `/metrics` is the canonical choice).

---

## Metrics reference

The gateway emits four families of metrics under `/metrics`. All series carry the configured `resource.*` labels (service.name, service.version, service.instance.id) on top of the per-metric labels documented below. Counter names get a `_total` suffix in Prometheus exposition (e.g., `reactor_otel_spans_created` → `reactor_otel_spans_created_total`).

### Pipeline health — `reactor.otel.*`

These metrics describe the OTel pipeline itself. Surface them on a dashboard alongside collector health so operators can attribute span loss to gateway vs. collector vs. network.

| Metric | Type | Labels | Useful for |
|---|---|---|---|
| `reactor.otel.spans.created` | Counter | (none) | Baseline span volume. Compare against `spans.exported{outcome=success}` to detect drop. |
| `reactor.otel.spans.dropped_unsampled` | Counter | (none) | Spans dropped by the sampler. Expected to be large with low-ratio sampling. |
| `reactor.otel.spans.dropped_unended` | Counter | (none) | Spans destroyed via shutdown kill loop or dtor backstop without `End()`. Should be ~0 on healthy steady-state; rises during graceful shutdown drain. Persistent non-zero in steady-state = a code path missing `FinalizeIfSnapshot`. |
| `reactor.otel.spans.dropped_queue_full` | Counter | (none) | BSP queue overflow drops. If non-zero, either `traces.batch.max_queue_size` is too small for the configured `schedule_delay_ms`, or the exporter is consistently slower than the producer. |
| `reactor.otel.spans.exported` | Counter | `outcome` ∈ `{success, retryable_fail, non_retryable_fail}` | Export attempt outcomes. `retryable_fail` rate indicates collector unhealth (5xx or 429); `non_retryable_fail` indicates payload rejection (4xx, exporter exception, schema mismatch). |
| `reactor.otel.export.duration` | Histogram (seconds) | `signal` ∈ `{traces, metrics}` | Export attempt latency. Pair with `spans.exported` rate to compute effective throughput. Tail latency rising = collector saturation. |
| `reactor.otel.metrics_export_skipped` | Counter | (none) | PMR ticks that skipped `Export()` because `metrics.enabled=false`. A monotonic baseline equal to `uptime / export_interval` is normal when metrics are disabled. |
| `reactor.otel.cardinality_overflow` | Counter | `label_key` | Per-label cap-edge events. A persistent rise on a specific `label_key` indicates either operator-misconfigured cap (too low) OR the upstream producing the label has unbounded cardinality (e.g., a free-form `route` parameter). |
| `reactor.otel.snapshots_killed_on_timeout` | Counter | (none) | Snapshots terminated by the shutdown kill loop. Non-zero only during shutdown; persistent rise across multiple restarts means the drain budget is too tight for in-flight traffic. |

### Connection telemetry — `reactor.net.*`, `reactor.tls.*`, `reactor.http.connections.*`

Fleet-wide connection state, split by layer so transport-truth and application-truth stay separable.

| Metric | Type | Labels | Useful for |
|---|---|---|---|
| `reactor.net.connections.active` | UpDownCounter | (none) | Live transport-level inbound connections. Includes connections in TLS handshake AND pre-classification raw TCP. |
| `reactor.net.connections.accepted` | Counter | (none) | All accepts since boot. Combined with the active gauge, gives accept rate + average lifetime. |
| `reactor.tls.handshakes` | Counter | `outcome` ∈ `{success, failure}` | TLS handshake outcomes. `failure` rate spikes indicate ALPN mismatch, cipher mismatch, expired cert on the client side, or handshake timeout. |
| `reactor.http.connections.active` | UpDownCounter | `protocol` ∈ `{http/1.1, h2, websocket}` | Per-protocol inbound connection count. Increments at PROTOCOL-CONFIRMED time (H1 first-request-parse, H2 preface, WS upgrade success). |
| `reactor.http.connections.accepted` | Counter | `protocol` ∈ `{http/1.1, h2, websocket}` | Per-protocol accepted counter. The pre-existing Phase 3 series. |

**Operator interpretation tips:**

- The relationship `net.accepted - sum(http.accepted{protocol=*}) - tls.handshakes{outcome=failure}` gives the count of connections that completed transport setup but never reached an application protocol — typically socket-scan / port-probe traffic, or clients that disconnected before sending the first byte.
- A WS upgrade transitions the gauge atomically: `http.connections.active{protocol=http/1.1}` decrements as `{protocol=websocket}` increments. A consistent gap means a code path is failing to call `HandOffToWebSocket()`.
- `net.connections.active > sum(http.connections.active{protocol=*}) + tls_handshakes_in_progress` indicates pre-classification raw-TCP connections (clients that opened the socket but haven't sent any bytes yet).

### Upstream pool — `reactor.upstream.pool.*`, `http.client.active_requests`

Pool saturation gauges with the closed `outcome` vocabulary for checkout-wait histograms. All series labelled `{reactor.upstream.service}` (the per-upstream name from `upstreams[].name`).

| Metric | Type | Labels | Useful for |
|---|---|---|---|
| `reactor.upstream.pool.connections.idle` | UpDownCounter | `reactor.upstream.service` | Idle conns in the pool, ready for checkout. Sustained 0 = pool under-provisioned. |
| `reactor.upstream.pool.connections.active` | UpDownCounter | `reactor.upstream.service` | In-use conns. Sustained `active == max_connections` = pool saturated; checkout will queue or reject. |
| `reactor.upstream.pool.checkout.wait.duration` | Histogram (seconds) | `reactor.upstream.service`, `outcome` ∈ `{immediate, queued_satisfied, cancelled, rejected, created}` | Per-checkout latency by exit path. `immediate` = idle reuse hit; `created` = had to spawn a new conn (includes connect latency); `queued_satisfied` = waited for an existing conn to return; `cancelled` / `rejected` = checkout failed without serving traffic. |
| `http.client.active_requests` | UpDownCounter | `reactor.upstream.service` | In-flight per-attempt requests against the upstream. Includes RETRIES — N attempts on a single transaction produce N concurrent `+1`s. Returns to zero on natural finalize, kill loop, or dtor backstop via CAS-safe drain. |

**Operator interpretation tips:**

- `checkout.wait.duration{outcome=queued_satisfied}` p99 rising indicates pool exhaustion — bump `pool.max_connections` or shorten upstream response latency.
- High `outcome=created` rate with stable `outcome=immediate` = the pool isn't sized for the request rate; conn spawn cost dominates.
- Persistent `outcome=rejected` = `pool.checkout_queue_max_size` is hit; either raise the queue limit or back-pressure the inbound side.
- `http.client.active_requests` significantly higher than the inbound `http.server.active_requests` on the same upstream's traffic indicates a retry-heavy workload (or a stuck attempt being held by the response timer).

### Feature middleware — `reactor.{auth, rate_limit, circuit_breaker, dns}.*`

Authoritative source for in-the-loop traffic-management telemetry. `/stats` JSON continues to surface the same counters; the OTel series are useful for time-series dashboards and alerting.

#### `reactor.dns.*`

| Metric | Type | Labels | Vocabulary |
|---|---|---|---|
| `reactor.dns.resolves` | Counter | `outcome` | `{success, cache_hit, nxdomain, timeout, servfail, other_error}` |

- `cache_hit` = literal IP short-circuit (no actual DNS call).
- `nxdomain` includes literal-parse failures (treated as "no such name").

#### `reactor.rate_limit.*`

| Metric | Type | Labels | Vocabulary |
|---|---|---|---|
| `reactor.rate_limit.decisions` | Counter | `zone`, `decision` | `decision ∈ {admit, reject, dry_run_reject}` |
| `reactor.rate_limit.tokens` | Histogram (tokens) | `zone` | Remaining-tokens snapshot at decision time |

- `decision=dry_run_reject` fires when the zone is in `dry_run` mode — operator sees would-reject traffic without enforcement.
- The `tokens` histogram lets operators see how close the zone is to the bucket floor across traffic patterns.

#### `reactor.circuit_breaker.*`

| Metric | Type | Labels | Vocabulary |
|---|---|---|---|
| `reactor.circuit_breaker.state` | UpDownCounter | `service`, `state` | `state ∈ {closed, open, half_open}` |
| `reactor.circuit_breaker.transitions` | Counter | `service`, `from`, `to`, `trigger` | `from`, `to` ∈ `{closed, open, half_open}`; `trigger ∈ {consecutive, rate, probe_success, probe_fail, open_elapsed, dry_run_disabled}` |
| `reactor.circuit_breaker.rejected` | Counter | `service`, `reason` | `reason ∈ {open, open_dry_run, half_open_full, half_open_recovery_failing}` |

- The `state` gauge is per-slice-summed: a `service` with N partitions starts at `{state=closed}=N` and transitions balance across the slices. A non-zero `{state=half_open}` series persisting beyond `half_open` durations is a stuck slice.
- `trigger=dry_run_disabled` is the synthetic same-state OPEN→OPEN signal that fires when `dry_run` flips `true→false` while the breaker is open — it lets operators see when shadow mode ended.
- `rejected{reason=open_dry_run}` = traffic that WOULD have been rejected in enforce mode but was admitted under shadow.

#### `reactor.auth.*`

| Metric | Type | Labels | Vocabulary |
|---|---|---|---|
| `reactor.auth.requests` | Counter | `outcome`, `issuer`, `reason` | `outcome ∈ {admit, deny}`; ALLOW emits `reason=ok`; deny `reason ∈ {missing_token, expired_token, malformed_token, signature_invalid, jwt_verify_failed, aud_mismatch, iss_mismatch, introspection_inactive, introspection_error, policy_denied, cache_miss_no_issuer, other}` |
| `reactor.auth.cache.lookups` | Counter | `outcome`, `issuer` | `outcome ∈ {hit, miss, stale_serve, refresh_fail}` |
| `reactor.auth.jwks.refreshes` | Counter | `issuer`, `outcome` | `outcome ∈ {success, network_error, parse_error}` |

- The `reason` label on `auth.requests` is bounded by the closed vocabulary above — the helper strips unbounded tails (e.g., `jwt_verify_failed: openssl says X` → `jwt_verify_failed`) before emit. Full log lines (with the tail) are preserved at the structured-log emit site for diagnostics.
- `cache.lookups{outcome=stale_serve}` rising on a specific issuer = JWKS refresh is failing AND the stale-serve fallback is keeping traffic flowing. Combine with `jwks.refreshes{outcome=network_error}` on the same issuer to confirm.
- Both positive-cache and negative-cache hits emit `outcome=hit` — the cache's perspective ("we had an answer ready") is more useful than the verdict split.

### Self-handler graceful shutdown

A route handler that needs to terminate the server (e.g. an admin endpoint exposing `/shutdown`) must NOT call `HttpServer::Stop()` synchronously — that deadlocks the dispatcher. Use `HttpServer::ScheduleStopAfterCurrentResponse()` instead. The helper:

- Populates the response normally and returns from the handler.
- Schedules `Stop()` on the conn dispatcher via `NetServer::EnQueueOnConnDispatcher`.
- Drains the calling handler's `active_requests_` decrement naturally before the deferred Stop runs.
- Idempotent — repeated/concurrent calls collapse via internal CAS.

### Kill loop and the CASE B marshal

`ObservabilityManager::KillOutstandingSnapshots` runs during the third shutdown phase to drain snapshots that didn't reach a natural finalize. Each snapshot's `owning_dispatcher` decides the path:

- **Same-thread or no dispatcher** — kill runs inline (`KillSnapshotInline`).
- **Cross-thread** — the manager bumps `kill_marshals_in_flight_`, enqueues the kill onto the owning dispatcher via `EnQueueDelayed(closure, 0ms)`, and an RAII guard decrements the counter when the closure exits (success, weak-pointer lock failure, or exception). If the dispatcher refuses the enqueue (already stopped), the bump is rolled back and the kill falls back to inline.

`HttpServer::Stop`'s drain barrier waits on `kill_marshals_in_flight_` reaching zero (alongside `inflight_finalizations_` and `finalizers_in_progress_`), so the marshal cannot wedge the shutdown — the budget is bounded by `cli.shutdown_drain_timeout_sec`.

The `obs_kill_marshal` regression suite (Phase 3) and `obs_kill_marshal_caseb` suite (Phase 4) together ratchet the contract:
- `kill_marshals_in_flight_` is 0 at steady-state, rises above 0 during cross-thread kill, and returns to 0 before drain converges.
- The `FinalizeFromSnapshot` CAS resolves multi-thread races: every snapshot is finalized exactly once.
- `reactor.otel.snapshots_killed_on_timeout` Counter delta = N for N un-finalized survivors.

---

## Out of scope

The following are deferred and not currently implemented — listed so future readers don't expect them.

- **Tail sampling.** Out of scope; deploy a Collector with the tail-sampling processor between the gateway and the trace backend.
- **Histogram exemplars.** Out of scope.
- **OTLP/protobuf.** OTLP/JSON is the only serializer; OTLP/protobuf may be added later for collector-side parity.
- **B3, X-Ray propagators.** Only W3C and Jaeger ship today.
- **Native gRPC client for OTLP.** Today's transport is HTTP/1.1 / HTTP/2 via the upstream pool; OTLP/JSON over HTTP/2 is the supported shape.
- **Live-swap of `traces.otlp.upstream` / `metrics.otlp.upstream`.** Restart-required by design.
- **Per-key `max_value_cardinality_per_label` SIGHUP.** Restart-only.
- **Logs signal.** Logs continue via spdlog with trace correlation in the log format; the OpenTelemetry logs SDK is not wired.
- **`/stats` reading from the OTel meter.** Today `/stats` and OTel emit in parallel from the same call sites (eventually consistent within ~1s). Eliminating the duplication is a Phase 5 cleanup.
