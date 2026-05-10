# HTTP/2 Upstream Client (Operator Guide)

Lets the proxy engine reach upstream services over multiplexed HTTP/2 instead of HTTP/1.1. Per-upstream opt-in via `upstreams[].http2.enabled = true`; downstream client traffic (toward your users) is unrelated to this setting.

If you don't need it, you can ignore this doc — H1 remains the default for every upstream that doesn't explicitly opt in.

For the field reference, see [docs/configuration.md § Upstream HTTP/2](configuration.md#upstream-http2).

---

## When to enable

H2 outbound is most useful when:

- The upstream is **gRPC** or another protocol that expects HTTP/2 transport.
- The upstream is a high-fanout API that benefits from connection multiplexing (one transport, many concurrent streams).
- You're serving many small requests where HOL blocking on shared keepalive pools is hurting tail latency.

H1 is fine — and often simpler — when:

- The upstream is a legacy service or a CDN that doesn't speak H2.
- The upstream's TLS termination is in front of an H1-only origin (a common pattern for serverless platforms).
- You're already saturating the upstream's per-connection bandwidth and additional multiplexing won't help.

---

## Quick start

```json
{
    "upstreams": [
        {
            "name": "grpc-backend",
            "host": "rpc.internal",
            "port": 443,
            "tls": {
                "enabled": true,
                "ca_file": "/etc/ssl/ca-bundle.crt"
            },
            "http2": {
                "enabled": true,
                "prefer": "auto"
            },
            "proxy": {
                "route_prefix": "/api/grpc",
                "strip_prefix": true
            }
        }
    ]
}
```

That's it. All other H2 settings have sensible defaults. The proxy will:

1. Open a TLS connection on first request, advertise both `h2` and `http/1.1` in ALPN.
2. If the peer selects `h2` → multiplex subsequent requests for this upstream onto the same transport.
3. If the peer selects `http/1.1` → fall back to H1 (one connection per request, same as before).

---

## `prefer` modes

| Mode | Behavior | When to use |
|------|----------|-------------|
| `auto` (default) | Pick H2 iff TLS+ALPN selects `h2`; else H1. | Safe default — works with any peer, picks the best protocol per connection. |
| `always` | Force H2 regardless of ALPN. Connection-time failure if the peer rejects the H2 preface. | When you control both ends and want to fail loudly if the peer is misconfigured. |
| `never` | Force H1 even when the peer would speak H2. | Rolling back from H2 without redeploying TLS configs; debugging. |

`always` requires `tls.enabled = true` — config load rejects `prefer: "always"` over plaintext TCP. `auto` over plaintext silently falls back to H1 (no ALPN signal).

---

## Reload semantics

Most H2 fields are **live-reloadable** via SIGHUP. The exceptions are restart-required:

- `http2.enabled` (toggling H2 on/off changes ALPN advertisement and partition layout)
- `http2.prefer` (changes the dispatch decision for the entire upstream)

Everything else — windows, frame size, PING cadence, GOAWAY drain timeout — propagates to **new** H2 connections within a few seconds of SIGHUP. Existing multiplexed sessions keep their construction-time snapshot until they retire.

Validation rejects out-of-range values at SIGHUP time:

- `prefer` must be `"auto"`, `"always"`, or `"never"`.
- `prefer == "always"` requires `tls.enabled = true` (live-rejected for upstreams already in pools_).
- `max_concurrent_streams_pref`, `initial_window_size` must be in `[1, 2^31-1]`.
- `max_frame_size` must be in `[16384, 16777215]` (RFC 9113 §6.5.2).
- `max_header_list_size` must be ≥ 4096. Defaults to `65536` (64 KB). Advertised in the SETTINGS preface (RFC 9113 §6.5.2); nghttp2 enforces locally on inbound HEADERS+CONTINUATION blocks. Below 4096 every real H2 request is rejected with COMPRESSION_ERROR.
- `header_table_size` is bounded to `[0, 16777216]` (16 MiB). 0 disables HPACK dynamic table.
- `ping_idle_sec`, `ping_timeout_sec`, `goaway_drain_timeout_sec` must be ≥ 0 (0 disables the corresponding check).

If a SIGHUP fails validation, the live config is unchanged — the server logs the rejection and continues with the previous values.

---

## Operational signals

### Logs

Look for these `[reactor]` log lines when H2 is active:

```
[info]    UpstreamH2Connection initialized session=0x... host=rpc.internal:443 max_concurrent=100
[debug]   UpstreamH2Codec submit stream_id=1 method=POST :path=/v1/foo
[warning] UpstreamH2Connection: PING timeout after 12s — closing
[warning] UpstreamH2Connection: GOAWAY received last_stream_id=15 — draining
```

A successful H2 request flow shows: `submit` → `OnHeaders` → `OnBodyChunk` (one or more) → `OnComplete` → stream erase.

### Monitoring

The following metrics aren't currently exposed via `/stats` but show up in logs at debug/info level:

- H2 connection count per upstream (one log line per `Init` and per retire).
- Active stream count at retire time (visible in the GOAWAY-drain logs).
- PING send / ACK latency (correlate `submit_ping` debug log with `OnPingAck`).

`/stats` exposure for these counters is planned for a future release.

---

## Tuning

The defaults are conservative and work for most deployments. Tune only if you observe a problem:

- **Stream concurrency too low** → bump `max_concurrent_streams_pref`. Default 100 is plenty for most APIs but fan-out clients (gRPC streaming) may benefit from 1000+.
- **Large response throughput limited** → bump `initial_window_size` (default 1 MiB). Some upstreams (gRPC servers, large file servers) negotiate larger windows that the client should match.
- **PING storms / log noise** → set `ping_idle_sec` higher (e.g. 120–300). The default 60s is conservative; if your upstream + middlebox tolerate longer idle, less PING traffic is fine.
- **GOAWAY drain timing out** → bump `goaway_drain_timeout_sec` if your upstream's graceful drain is longer than the default 30s. Otherwise stuck streams are force-killed.

---

## Caveats

- **No h2c (cleartext H2)** — H2 outbound requires TLS. `http2.enabled = true` with `tls.enabled = false` is rejected at config load.
- **No server push** — disabled in the SETTINGS preface (H2 server push is rarely useful for a proxy client).
- **No mid-stream SETTINGS update** — reloads apply to NEW connections only. Existing sessions keep their construction-time settings.
- **One H2 connection per upstream per dispatcher** — until saturation routing lands (`saturation_open_pct`), each partition holds one multiplexed connection per upstream. For very-high-fanout workloads this can be a bottleneck; mitigate by increasing the dispatcher count.
- **Per-stream backpressure is not strictly bounded by `initial_window_size`** — the proxy lets nghttp2 manage stream-level flow control with auto-`WINDOW_UPDATE` enabled, so the upstream's effective window is continuously refreshed as bytes are delivered to the on-data-chunk callback. In practice per-stream upstream buffering tracks the auto-update cadence (~`initial_window_size` worth of bytes outstanding under steady traffic) plus the `StreamingResponseSender` high-water mark on the downstream side, but it is not a hard cap: a slow downstream client paired with a fast H2 upstream can buffer somewhat more depending on `MAX_FRAME_SIZE` and how quickly chunks are read. For workloads with bursty downstream stalls and a high `initial_window_size`, watch RSS and consider lowering the window size. A future refinement will disable auto-update and pause per-stream consumption via `nghttp2_session_consume_stream` to enforce a strict cap.
- **CONNECT method is rejected** with 502 + `X-H2-Limitation: connect-not-supported`. The H2 codec emits `:scheme` and `:path` on every request, which RFC 9113 §8.5 forbids on CONNECT pseudo-headers; rather than emit a malformed request, the gateway rejects deterministically. Use an H1 upstream for CONNECT tunnelling.
- **Truncation observability** — when a backend declares `Content-Length` and closes early, nghttp2's HTTP messaging enforcement detects the violation and the gateway surfaces it as `RESULT_UPSTREAM_DISCONNECT` (the same bucket as a torn TCP connection). A dedicated `RESULT_TRUNCATED_RESPONSE` code exists in the binary for defense-in-depth but is not normally observable in production. If you need to distinguish "peer reset / TCP drop" from "Content-Length short read", correlate by upstream-side response logs.
