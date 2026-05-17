# Streaming Request Forwarding (Operator Guide)

Lets the proxy engine forward an inbound request body to the upstream **chunk-by-chunk** instead of buffering the entire body before dispatching. This is essential for large uploads, long-lived ingest streams, and any path where the client sends more than a few hundred KB before the upstream needs to start processing.

If your routes receive bodies under ~1 MB and you don't need reduced first-byte latency, the default buffered mode is simpler. Streaming is opt-in per upstream.

---

## When to enable

Streaming forwarding is most useful when:

- The request body is **large** (hundreds of MB to multi-GB uploads, ingest pipelines).
- The upstream starts processing **before** it has received the full body (stream processors, chunked ingest APIs).
- You want **reduced gateway memory** per in-flight request (buffered mode holds the entire body in RAM).
- The client streams at a controlled rate and you need **backpressure** to propagate end-to-end.

Buffered mode is fine — and simpler — when:

- Request bodies are small (typical REST APIs, form POSTs under a few MB).
- You need retry-on-failure: streaming requests can only retry on the very first attempt before any body bytes have been sent (see [Retry limitations](#retry-limitations)).
- The upstream is stateless and expects to read the complete body atomically.

---

## Quick start

```json
{
    "upstreams": [
        {
            "name": "ingest-service",
            "host": "ingest.internal",
            "port": 8080,
            "proxy": {
                "route_prefix": "/upload"
            },
            "request_mode": "streaming"
        }
    ]
}
```

`request_mode` defaults to `"streaming"` for all proxy-registered routes — the gateway sets this automatically when you use `RegisterProxyRoutes`. You only need to set it explicitly to `"buffered"` to opt out.

---

## Configuration

### `request_mode`

| Value | Behavior |
|-------|----------|
| `"streaming"` (default) | Request body is forwarded chunk-by-chunk using a `ChunkQueueBodyStream` pipeline. Low per-request memory. |
| `"buffered"` | Request body is accumulated in RAM before the upstream connection is acquired. Simpler retry semantics. |

`request_mode` is **restart-only** — changing it in a SIGHUP reload has no effect on already-registered routes. Restart the server to change the mode for a live upstream.

### `http2.streaming` (inbound H2 watermarks)

Controls the `ChunkQueueBodyStream` high-/low-water marks and the WINDOW_UPDATE replenishment threshold for **inbound** HTTP/2 requests. Live-reloadable via SIGHUP.

| Field | Default | Description |
|-------|---------|-------------|
| `http2.streaming.high_water_bytes` | `262144` (256 KB) | When `BytesQueued` crosses this threshold, the inbound H2 layer stops issuing WINDOW_UPDATE credits to the client — effective backpressure. |
| `http2.streaming.low_water_bytes` | `65536` (64 KB) | When `BytesQueued` drains below this, WINDOW_UPDATE credits resume. Must be ≤ `high_water_bytes`. |
| `http2.streaming.window_update_bytes` | `32768` (32 KB) | Minimum bytes consumed before issuing a WINDOW_UPDATE to the client. |

### `http1.streaming` (inbound H1 watermarks)

Controls the backpressure thresholds for **inbound** HTTP/1.1 streaming requests. Live-reloadable via SIGHUP.

| Field | Default | Description |
|-------|---------|-------------|
| `http1.streaming.high_water_bytes` | `262144` (256 KB) | When `BytesQueued` crosses this, the inbound H1 layer pauses the read pump (`IncReadDisable`). |
| `http1.streaming.low_water_bytes` | `65536` (64 KB) | When `BytesQueued` drains below this, the read pump resumes. |

### `http2.streaming` on the upstream (outbound watermarks)

Controls the `ChunkQueueBodyStream` thresholds on the **outbound** side of an H2 upstream connection. Governs how much of the request body can queue in the gateway while waiting for the upstream's H2 flow-control window. Live-reloadable via SIGHUP.

| Field | Default | Description |
|-------|---------|-------------|
| `upstreams[].http2.streaming.high_water_bytes` | `262144` (256 KB) | When the outbound body queue crosses this, nghttp2's flow-control window governs further pacing. |
| `upstreams[].http2.streaming.low_water_bytes` | `65536` (64 KB) | Drain threshold for the low-water callback. |

---

## Request body size limits

The gateway enforces body-size limits from the inbound protocol layer **before** forwarding. If the client sends more than `max_request_body_bytes` (HTTP/2, configurable per-protocol), the inbound layer aborts the `BodyStream` with reason `"body_size_limit_exceeded"`. The proxy detects this abort and returns **413 Payload Too Large** to the client.

The abort can happen mid-stream — after some chunks have already been forwarded. In that case the upstream receives a partial body (the upstream connection is force-closed or RST_STREAMed). Upstream-side handling of an aborted partial body is the upstream's responsibility.

---

## H2 request trailers

When a streaming route receives an HTTP/2 request with trailers, the gateway forwards them to the upstream if the upstream also speaks H2. Trailers are sanitized before emit:

- Pseudo-headers (`:authority`, `:path`, etc.) are dropped.
- Connection-specific headers (`connection`, `keep-alive`, `transfer-encoding`, `te`, `upgrade`) are dropped.
- Sensitive headers (`authorization`, `host`, `content-length`, `content-type`, `content-encoding`, `content-range`) are dropped.
- The `trailer` header itself is dropped.
- Field names are lowercased and trimmed of optional whitespace.

Trailers that survive the sanitizer are emitted as a trailing HEADERS frame on the outbound H2 stream.

**H1 upstreams** do not receive trailers — the outbound H1 codec discards any trailer fields received from the inbound side (chunked H1 trailers are not widely supported by upstream servers).

---

## Failure modes and response codes

| Result code | HTTP response | Cause |
|-------------|---------------|-------|
| `RESULT_REQUEST_BODY_LIMIT_EXCEEDED` (-18) | 413 Payload Too Large | Inbound body exceeded the configured size limit. BodyStream aborted mid-stream. |
| Inbound disconnect | 502 Bad Gateway | Client closed the connection before sending END_STREAM or finishing the chunked body. BodyStream aborted. |
| `RESULT_RETRY_DENIED_STREAMING_SOURCE_CONSUMED` (-15) | 502 Bad Gateway | A retry was attempted after body bytes were already forwarded to the upstream — retry was denied to prevent double-delivery. |
| `RESULT_RETRY_DENIED_STREAMING_BODY_ON_WIRE` (-16) | 502 Bad Gateway | A retry was attempted while the request body was still in flight on the wire. |
| Upstream disconnect mid-body | 502 Bad Gateway | Upstream closed the connection before the gateway finished forwarding the body. |

---

## Retry limitations

Streaming forwarding interacts with retry policy differently than buffered forwarding:

- **First attempt, pre-send**: Retry is allowed on connect-failure or transport errors that occur before any request bytes reach the upstream. The source has not been consumed; a fresh checkout can start over.
- **After body bytes are on the wire**: Retry is **denied** with a 502 (`RESULT_RETRY_DENIED_STREAMING_BODY_ON_WIRE`). Body bytes cannot be rewound because the client has already sent them and the gateway does not hold a copy.
- **After source has been consumed**: If the entire body was forwarded but the upstream returned a 5xx (or disconnected), retry is denied with 502 (`RESULT_RETRY_DENIED_STREAMING_SOURCE_CONSUMED`). The producer-side BodyStream is exhausted; no held-fallback buffer is available to replay from.

To enable retries, switch `request_mode` to `"buffered"`: the gateway buffers the full body and can replay it on retry.

---

## Graceful shutdown

On SIGTERM/SIGINT, the gateway drain covers in-flight streaming requests. The inbound layer stops accepting new data (sends H2 GOAWAY to clients if using H2 inbound), and in-flight `BodyStream` instances are aborted. Active proxy transactions receive the abort, close the upstream connection cleanly (or RST_STREAM on H2), and complete with a 502.

The drain timeout (`server.shutdown_drain_timeout_sec`) applies. Streaming requests that cannot complete within the budget are force-closed.

---

## Backpressure end-to-end

The watermark system provides a natural backpressure path:

1. Client sends request bytes to the gateway.
2. Inbound layer pushes chunks into `ChunkQueueBodyStream`.
3. When `BytesQueued ≥ high_water_bytes`, the inbound layer pauses reading from the client:
   - **H2 inbound**: stops issuing WINDOW_UPDATE credits.
   - **H1 inbound**: pauses the read pump (`IncReadDisable`).
4. The outbound codec drains the queue, forwarding chunks to the upstream.
5. When `BytesQueued < low_water_bytes`, reading resumes.

This means a slow upstream exerts natural backpressure on the client, without unbounded gateway-side buffering. The maximum in-gateway buffering per request is bounded by `high_water_bytes` (inbound) plus `streaming.high_water_bytes` (outbound), typically ~500 KB total with default settings.

---

## Caveats

- **No held-fallback buffer** — streaming requests do not maintain a replay buffer. Once body bytes flow through the gateway, they cannot be retried from a saved copy. If retry-on-failure is critical, use `request_mode: "buffered"`.
- **Trailers forwarded only to H2 upstreams** — H1 upstreams silently discard any trailing headers from the inbound stream.
- **`request_mode` is restart-only** — live config reload (SIGHUP) cannot change the forwarding mode for already-registered routes.
- **Auth async-suspend invalidates the body stream** — if an auth middleware suspends request processing (e.g., token introspection round-trip), the BodyStream's `Aborted()` flag is checked on resume. If the client disconnected during the suspend window, the gateway returns 502 rather than forwarding to a closed upstream.
- **Observability**: per-request `http.server.request.mode` metric label (streaming vs buffered) is planned for a future release.
