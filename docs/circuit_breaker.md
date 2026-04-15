# Circuit Breaker

Per-upstream circuit breaking for the gateway, preventing cascading failures when a backend becomes unhealthy. Follows the resilience4j three-state machine (`CLOSED` → `OPEN` → `HALF_OPEN` → `CLOSED`), trips on either consecutive-failure or failure-rate thresholds, and short-circuits checkouts with `503 Service Unavailable` while the circuit is open. A separate **retry budget** caps the fraction of concurrent upstream work that may be retries, bounding the retry-storm amplification factor even when individual retries pass the breaker gate.

---

## Overview

- **Per-dispatcher slices.** One `CircuitBreakerSlice` per dispatcher partition for each upstream. Hot-path `TryAcquire` / `Report*` calls are lock-free — each slice is dispatcher-thread-pinned.
- **Three states.** `CLOSED` = normal traffic. `OPEN` = all requests short-circuited with 503 for the exponential-backoff open duration. `HALF_OPEN` = a bounded number of probe requests are admitted to test recovery; on success, closes; on failure, re-trips with longer backoff.
- **Dual trip paths.** Either `consecutive_failures >= N` OR `failure_rate >= P%` over a sliding window (subject to `minimum_volume`).
- **Retry budget.** Host-level cap: `max(retry_budget_min_concurrency, (in_flight - retries_in_flight) * retry_budget_percent / 100)`. Retries that exceed the cap receive `503` + `X-Retry-Budget-Exhausted: 1` instead of going to the upstream.
- **Wait-queue drain on trip.** On every `CLOSED → OPEN` transition, the corresponding pool partition's wait queue is drained immediately with `503 + X-Circuit-Breaker: open` — queued waiters don't have to wait out the full open window.
- **Dry-run mode.** `dry_run=true` computes decisions and logs them, but still admits traffic. Useful for staging a breaker in production without risk.
- **Hot-reload.** Breaker-field edits (thresholds, window, probe budget, retry budget tuning, enabled toggle) apply live on SIGHUP — no restart required. Topology edits (host/port/pool/proxy/tls) still require a restart.

---

## Configuration

Each `upstream` entry accepts a nested `circuit_breaker` block:

```json
{
  "upstreams": [
    {
      "name": "orders",
      "host": "orders-backend",
      "port": 8080,
      "circuit_breaker": {
        "enabled": true,
        "dry_run": false,
        "consecutive_failure_threshold": 5,
        "failure_rate_threshold": 50,
        "minimum_volume": 20,
        "window_seconds": 10,
        "permitted_half_open_calls": 3,
        "base_open_duration_ms": 5000,
        "max_open_duration_ms": 60000,
        "retry_budget_percent": 20,
        "retry_budget_min_concurrency": 3
      }
    }
  ]
}
```

### Fields

| Field | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `false` | Master switch. When false, the slice is a zero-overhead no-op on the hot path. |
| `dry_run` | bool | `false` | Shadow mode: log would-reject decisions but admit traffic. Both the state machine and the retry budget honor this flag. |
| `consecutive_failure_threshold` | int | `5` | Trip when N consecutive failures are observed in `CLOSED`. Upper bound 10,000. |
| `failure_rate_threshold` | int | `50` | Trip when `(failures / total) * 100 >= this` over the rolling window, provided `total >= minimum_volume`. 0-100. |
| `minimum_volume` | int | `20` | Minimum calls-in-window before rate-based trip is even considered. Upper bound 10,000,000. |
| `window_seconds` | int | `10` | Rolling window duration for the rate trip. >= 1. |
| `permitted_half_open_calls` | int | `3` | Probe admissions allowed per `HALF_OPEN` cycle. A single success flips to `CLOSED`; a single failure re-trips to `OPEN`. Upper bound 1,000. |
| `base_open_duration_ms` | int | `5000` | Initial open duration on first trip. Subsequent trips use `min(base << consecutive_trips, max)`. |
| `max_open_duration_ms` | int | `60000` | Ceiling for the exponential-backoff open duration. |
| `retry_budget_percent` | int | `20` | Retries capped at this % of non-retry in-flight traffic to the same host. 0-100. |
| `retry_budget_min_concurrency` | int | `3` | Floor for the retry cap — always allow at least this many concurrent retries regardless of traffic level. |

### Defaults (when `circuit_breaker` block is absent)

`enabled=false`. The breaker is fully opt-in. No behavioral change from a pre-breaker gateway configuration.

---

## Client-facing responses

Two distinct `503` variants, keyed off the reject source:

**Circuit-open reject** — breaker is `OPEN` or in `HALF_OPEN`-full:
```
HTTP/1.1 503 Service Unavailable
Retry-After: 5
X-Circuit-Breaker: open              # or half_open
X-Upstream-Host: orders-backend:8080
Connection: close
```

- `Retry-After` derivation:
  - `OPEN`: derived from the stored `open_until` deadline (time remaining until next probe).
  - `HALF_OPEN`: derived from the *next* open duration (`base << consecutive_trips`) — reflects what the backoff would be if the in-flight probes fail. Base alone would under-report after multiple trips.
  - Both paths: ceil-divide the millisecond value to seconds, capped at 3600s.
- `X-Circuit-Breaker` distinguishes the two reject paths so operators can tell "backoff active" from "probing, no capacity left".

**Retry-budget reject** — every retry attempt rejected because the host's budget is exhausted:
```
HTTP/1.1 503 Service Unavailable
X-Retry-Budget-Exhausted: 1
Connection: close
```

No `Retry-After` (the budget has no recovery clock — it depends on concurrent traffic). No `X-Circuit-Breaker` header (this reject path is orthogonal to the state machine).

Both responses are **terminal**: the retry loop never retries a circuit-open or retry-budget-exhausted outcome.

---

## Hot reload

All `circuit_breaker` fields on existing upstream services are hot-reloadable via `SIGHUP`. Reload semantics:

| Edit | Behavior |
|---|---|
| Threshold change (failures, rate, window, probe budget, open durations) | Applied on the next `TryAcquire` / `Report*` call on each slice. Live state (`CLOSED`/`OPEN`/`HALF_OPEN`) is preserved. |
| `enabled=true → false` | Live state reset to `CLOSED`; hot path short-circuits to `ADMITTED`. No transition callback fired. |
| `enabled=false → true` | Live state reset to `CLOSED`. The transition callback (wired at startup) re-engages for future trips. |
| `window_seconds` change | Rolling window reset. In-flight reports admitted pre-reload are invalidated (by `closed_gen_` bump); `consecutive_failures_` reset so stale counts can't trip the fresh window. In-flight `HALF_OPEN` probes are NOT invalidated (separate `halfopen_gen_` counter) — probe cycles complete normally. |
| `retry_budget_percent` / `retry_budget_min_concurrency` | Applied immediately (atomic stores). In-flight counters preserved. |

Topology edits (`host`, `port`, `pool.*`, `proxy.*`, `tls.*`) still require a restart; the gateway logs `"Reload: upstream topology changes require a restart to take effect"` and keeps the old pool alive. Breaker edits on the same reload are still applied live. Topology comparison is **name-keyed**: a pure reorder of otherwise-identical upstream entries is not treated as a topology change, so reformatting the upstream list in-place is safe.

The SIGHUP handler returns only after every per-slice `Reload` has committed on its dispatcher (bounded 2s per host). Requests issued after you observe "reload OK" are guaranteed to see the new breaker tuning.

---

## Observability

### Logs

| Event | Level | Sample |
|---|---|---|
| `CLOSED → OPEN` trip | `warn` | `circuit breaker tripped service=orders host=orders-backend:8080 partition=0 trigger=consecutive consecutive_failures=5 window_total=12 window_fail_rate=41 open_for_ms=5000 consecutive_trips=1` |
| `OPEN → HALF_OPEN` | `info` | `circuit breaker half-open ... probes_allowed=3` |
| `HALF_OPEN → CLOSED` | `info` | `circuit breaker closed ... probes_succeeded=3` |
| `HALF_OPEN → OPEN` re-trip | `warn` | `circuit breaker re-tripped ... trigger=probe_fail consecutive_trips=2 open_for_ms=10000` |
| Reject (first of cycle) | `info` | `circuit breaker rejected ... state=open` |
| Reject (subsequent) | `debug` | Same, at debug. |
| Reject (dry-run) | `info` | `[dry-run] circuit breaker would reject ...` |
| Retry budget exhausted | `warn` | `retry budget exhausted service=orders in_flight=45 retries_in_flight=9 cap=9 client_fd=... attempt=1` |
| Reload applied | `info` | `circuit breaker config applied service=orders enabled=true window_s=10 fail_rate=50 consec_threshold=5` |
| Wait-queue drain on trip | `info` | `PoolPartition draining wait queue on breaker trip: orders-backend:8080 queue_size=3` |

### Snapshot API

`CircuitBreakerManager::SnapshotAll()` returns one `CircuitBreakerHostSnapshot` per upstream with per-slice rows (`state`, `trips`, `rejected`, `probe_successes`, `probe_failures`) plus host-level aggregates (`total_trips`, `total_rejected`, `open_partitions`, `half_open_partitions`, `retries_in_flight`, `retries_rejected`, `in_flight`). A `/admin/breakers` HTTP endpoint that JSON-serializes this snapshot is **planned but not yet exposed** — the API is ready for future wiring.

---

## Design notes

- **Dispatcher affinity.** Slices are pinned to their dispatcher thread — no CAS on the hot path. The trade-off: skewed request distribution across dispatchers can cause one partition to trip while another stays `CLOSED`. Uniform hashing keeps this mild in practice.
- **Lazy `HALF_OPEN`.** The transition from `OPEN` happens on the next inbound `TryAcquire` once the open deadline elapses — no background timer. Envoy and resilience4j use the same model.
- **Generation tokens.** Every admission is stamped with a per-domain generation counter (`closed_gen_` or `halfopen_gen_`, depending on state). `Report*` drops stale-generation completions so pre-transition requests can't pollute a fresh cycle. Window resizes bump only `closed_gen_` so in-flight probes aren't stranded.
- **Retry budget CAS.** `TryConsumeRetry` uses `compare_exchange_weak` to serialize concurrent retry admissions. A plain load-check-add would let N callers all observe `current < cap` and all increment past the cap.
- **Non-retry denominator.** The budget base is `in_flight - retries_in_flight`, not raw `in_flight`. Retries count in both terms but subtract out here so admitting a retry doesn't inflate its own cap.
