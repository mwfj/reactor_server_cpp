# Streaming Request Forwarding (Operator Guide)

Lets the proxy engine forward an inbound request body to the upstream **chunk-by-chunk** instead of buffering the entire body before dispatching. This is essential for large uploads, long-lived ingest streams, and any path where the client sends more than a few hundred KB before the upstream needs to start processing.

Proxy routes default to `request_mode: "streaming"` — the gateway sets this automatically for routes registered via `RegisterProxyRoutes`. If your routes receive bodies under ~1 MB, don't need reduced first-byte latency, and want retry-on-failure semantics, opt into buffered mode by setting `request_mode: "buffered"` on the upstream.

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

### Outbound watermarks (reserved)

There is intentionally **no** `upstreams[].http2.streaming` configuration today: the proxy reuses a single `ChunkQueueBodyStream` end-to-end, so the inbound `http2.streaming.*` watermarks govern producer-side backpressure for the entire request lifetime. A future protocol-translation path (separate outbound body buffer) would re-introduce per-upstream watermarks; the schema is held until a runtime consumer exists.

---

## Request body size limits

The gateway enforces body-size limits from the inbound protocol layer **before** forwarding. If the client sends more than `max_body_size` (top-level server config, default 1 MB), the inbound layer aborts the `BodyStream` and the proxy returns **413 Payload Too Large** to the client.

Three abort points produce the 413 path:

| Abort reason | When it fires | Detection point |
|--------------|---------------|-----------------|
| `body_size_limit_exceeded` | The accumulated body size has crossed the limit (mid-stream), OR — for HTTP/2 — the declared `content-length` HEADER alone already exceeds the limit (pre-dispatch). | Inbound producer (H1 / H2 inbound). For H2 the pre-dispatch path constructs a pre-aborted `BodyStream`, dispatches the streaming handler, and defers `RST_STREAM` until after the 413 response is on the wire so the client cannot lose the 413 to a CLOSING-stream race. |
| `content_length_overrun` | Inbound DATA exceeds the declared `content-length`. | H1 / H2 inbound. |
| `content_length_underrun` | END_STREAM (or trailing HEADERS with END_STREAM) arrives before all declared `content-length` bytes. | H1 / H2 inbound. |

The mid-stream abort variants can fire after some chunks have already been forwarded. In that case the upstream receives a partial body (the upstream connection is force-closed for H1 or `RST_STREAM`'d for H2). Upstream-side handling of an aborted partial body is the upstream's responsibility.

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

### Inbound H2 trailer protocol errors

When a malformed trailer block arrives on an inbound H2 stream — a trailing HEADERS frame WITHOUT END_STREAM (RFC 9113 §8.1 violation), a trailer field the shared sanitizer rejects (e.g. `content-length` in trailers, RFC 9110 §6.5.1), or a trailer block that crosses `http2.max_header_list_size` — the gateway:

1. Aborts the streaming `BodyStream` so any handler parked in `Read()` / `WaitForData()` unblocks immediately. The abort reason names the specific protocol error: `trailer_without_end_stream`, `forbidden_trailer_field`, or `trailer_header_list_overflow`.
2. Clears any pending trailer fields accumulated so far on the stream.
3. Refunds residual per-stream flow-control credit via `nghttp2_session_consume_*` so the connection-level window stays balanced (RFC 9113 §6.9.1).
4. Submits `RST_STREAM` (`PROTOCOL_ERROR` for the first two; `ENHANCE_YOUR_CALM` for header-list overflow).

Streaming handlers should treat ABORTED with any of these reasons the same way they treat `body_size_limit_exceeded` — produce an error response and return. The gateway will not deliver the response to the client (the RST has already torn the stream down) but the handler still needs to release its async-work bookkeeping.

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

## Dispatch timing

For both H1 and H2, the route handler is dispatched at **headers-complete** — as soon as the request line and all headers have been parsed, before the body is fully received. The handler reads from `BodyStream` as bytes arrive, so request-body data flows through the producer/consumer pipeline end-to-end and never accumulates fully in gateway memory.

If a streaming handler responds synchronously based on headers alone (e.g., a middleware rejection), the gateway aborts the in-flight body and closes the connection — the body cannot be safely drained mid-frame.

## Backpressure end-to-end

The watermark system provides a natural backpressure path:

1. Client sends request bytes to the gateway.
2. Inbound layer pushes chunks into `ChunkQueueBodyStream`.
3. When `BytesQueued ≥ high_water_bytes`, the inbound layer pauses reading from the client:
   - **H2 inbound**: stops issuing WINDOW_UPDATE credits.
   - **H1 inbound**: pauses the read pump (`IncReadDisable`).
4. The outbound codec drains the queue, forwarding chunks to the upstream.
5. When `BytesQueued < low_water_bytes`, reading resumes.

This means a slow upstream exerts natural backpressure on the client, without unbounded gateway-side buffering. The maximum in-gateway buffering per request is bounded by `http2.streaming.high_water_bytes` (or `http1.streaming.high_water_bytes` for H1 inbound), typically ~256 KB with default settings.

---

## Caveats

- **No held-fallback buffer** — streaming requests do not maintain a replay buffer. Once body bytes flow through the gateway, they cannot be retried from a saved copy. If retry-on-failure is critical, use `request_mode: "buffered"`.
- **Trailers forwarded only to H2 upstreams** — H1 upstreams silently discard any trailing headers from the inbound stream.
- **`request_mode` is restart-only** — live config reload (SIGHUP) cannot change the forwarding mode for already-registered routes.
- **Auth async-suspend invalidates the body stream** — if an auth middleware suspends request processing (e.g., token introspection round-trip), the BodyStream's `Aborted()` flag is checked on resume. If the client disconnected during the suspend window, the gateway returns 502 rather than forwarding to a closed upstream.
- **Observability**: per-request `http.server.request.mode` metric label (streaming vs buffered) is planned for a future release.
