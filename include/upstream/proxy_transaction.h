#pragma once

#include "common.h"
#include "upstream/upstream_codec.h"
#include "upstream/upstream_http_codec.h"
#include "upstream/upstream_h2_codec.h"
#include "upstream/upstream_response_sink.h"
#include "upstream/upstream_lease.h"
#include "upstream/header_rewriter.h"
#include "upstream/retry_policy.h"
#include "auth/auth_context.h"           // AuthContext (stored by value)
#include "config/server_config.h"        // ProxyConfig (stored by value)
#include "circuit_breaker/retry_budget.h" // RetryBudget::InFlightGuard (member-by-value)
#include "http/http_callbacks.h"
#include "http/http_response.h"
#include "http/body_stream.h"
#include "observability/observability_snapshot.h"  // UpstreamTransactionLink
#include "observability/trace_context.h"            // AttemptTraceContext / RequestTraceContext
// <string>, <map>, <unordered_map>, <memory>, <functional>, <chrono>, <optional> provided by common.h

// Forward declarations
class UpstreamManager;
class ConnectionHandler;
class Dispatcher;
class UpstreamH2Connection;

namespace OBSERVABILITY_NAMESPACE {
class ObservabilityManager;
class Span;
}  // namespace OBSERVABILITY_NAMESPACE

namespace CIRCUIT_BREAKER_NAMESPACE {
class CircuitBreakerSlice;
}  // RetryBudget already defined via retry_budget.h

namespace AUTH_NAMESPACE {
class AuthManager;
}  // namespace AUTH_NAMESPACE

class ProxyTransaction
    : public std::enable_shared_from_this<ProxyTransaction>,
      public UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseSink,
      public OBSERVABILITY_NAMESPACE::UpstreamTransactionLink {
    // Test-only friend that pokes the private H2 dispatch state to
    // exercise OnRequestSubmitted's response_timeout branch without
    // spinning up the full UpstreamManager / dispatcher / pool stack.
    friend struct H2ResponseTimeoutTestFixture;
public:
    // Result codes for internal state tracking
    static constexpr int RESULT_SUCCESS             = 0;
    static constexpr int RESULT_CHECKOUT_FAILED     = -1;  // Upstream connect failure → 502
    static constexpr int RESULT_SEND_FAILED         = -2;
    static constexpr int RESULT_PARSE_ERROR         = -3;
    static constexpr int RESULT_RESPONSE_TIMEOUT    = -4;
    static constexpr int RESULT_UPSTREAM_DISCONNECT = -5;
    static constexpr int RESULT_POOL_EXHAUSTED      = -6;  // Local capacity → 503
    static constexpr int RESULT_RESPONSE_TOO_LARGE  = -9;  // Local buffering cap → 502
    // Circuit breaker rejected this attempt before it touched the upstream.
    // Response carries Retry-After + X-Circuit-Breaker headers. Terminal —
    // retry loop MUST NOT retry this outcome (a same-cycle re-admission
    // would just re-reject and would feed back into the breaker's failure
    // math).
    static constexpr int RESULT_CIRCUIT_OPEN        = -7;
    // Retry budget exhausted. No Retry-After; distinct header
    // X-Retry-Budget-Exhausted so operators can tell the two 503s apart
    // from circuit-open rejects.
    static constexpr int RESULT_RETRY_BUDGET_EXHAUSTED = -8;
    // Upstream response did not match its declared length. Two cases:
    //   - Content-Length declared, peer delivered fewer bytes before clean
    //     close, or more bytes than declared.
    //   - Response classified NO_BODY (status 204/304 or HEAD method) but
    //     peer sent body bytes anyway.
    // Terminal — partial body has already been streamed downstream so retry
    // would double-deliver bytes. Maps to 502 BadGateway in MakeErrorResponse.
    static constexpr int RESULT_TRUNCATED_RESPONSE  = -10;
    // CONNECT method on an H2 upstream. RFC 9113 §8.5 forbids :scheme and
    // :path on CONNECT pseudo-headers, but our H2 codec always emits both;
    // serving CONNECT here would emit a malformed request. Terminal —
    // deterministic policy reject (502 BadGateway + X-H2-Limitation header).
    static constexpr int RESULT_H2_METHOD_NOT_SUPPORTED = -11;
    // Peer sent GOAWAY with last_stream_id < our stream_id. Per RFC 9113
    // §6.8 the peer provably did not process this request — connect-style
    // retryable, breaker-neutral. Maps to 502 BadGateway in
    // MakeErrorResponse.
    static constexpr int RESULT_GOAWAY_UNPROCESSED  = -12;
    // Peer sent GOAWAY with last_stream_id >= our stream_id, then
    // dropped the stream before delivering a complete response.
    // Per RFC 9113 §6.8 we don't know whether the peer processed it —
    // retryable for idempotent methods, response-level backoff,
    // breaker-neutral. Maps to 502 BadGateway in MakeErrorResponse.
    static constexpr int RESULT_GOAWAY_MAYBE_PROCESSED = -13;
    // `prefer = "always"` configured but peer did not negotiate h2 via
    // ALPN. Deterministic policy reject — no upstream contact, no
    // retry. Terminal — breaker-neutral (same shape as
    // RESULT_H2_METHOD_NOT_SUPPORTED). Maps to 502 BadGateway with
    // `X-H2-Limitation: alpn-not-h2` in MakeErrorResponse so operators
    // see a distinct signal from generic checkout-failure.
    static constexpr int RESULT_H2_ALPN_NOT_NEGOTIATED = -14;
    // Streaming-retry-denied terminal codes. The denial reason is
    // per-request semantics (source consumption / body-on-wire /
    // queued-non-idempotent), distinct from RESULT_RETRY_BUDGET_EXHAUSTED
    // which is pool-level budget arithmetic. All three map to 502
    // BadGateway via MakeErrorResponse.
    static constexpr int RESULT_RETRY_DENIED_STREAMING_SOURCE_CONSUMED     = -15;
    static constexpr int RESULT_RETRY_DENIED_STREAMING_BODY_ON_WIRE        = -16;
    static constexpr int RESULT_RETRY_DENIED_NON_IDEMPOTENT_HEADERS_QUEUED = -17;
    // Proxy-side request-body-size enforcement. Fires when the inbound
    // producer aborts the body_stream with reason "body_size_limit_exceeded"
    // AFTER the proxy has begun forwarding. Maps to 413 PayloadTooLarge.
    static constexpr int RESULT_REQUEST_BODY_LIMIT_EXCEEDED                = -18;

    // Constructor copies all needed fields from client_request (method, path,
    // query, headers, body, params, dispatcher_index, client_ip, client_tls,
    // client_fd). The original HttpRequest is invalidated by parser_.Reset()
    // immediately after the async handler returns -- no references may be kept.
    ProxyTransaction(const std::string& service_name,
                     const HttpRequest& client_request,
                     HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender stream_sender,
                     HTTP_CALLBACKS_NAMESPACE::AsyncCompletionCallback complete_cb,
                     UpstreamManager* upstream_manager,
                     const ProxyConfig& config,
                     const HeaderRewriter& header_rewriter,
                     const RetryPolicy& retry_policy,
                     bool upstream_tls,
                     const std::string& upstream_host,
                     int upstream_port,
                     const std::string& sni_hostname,
                     const std::string& upstream_path_override,
                     const std::string& static_prefix,
                     // Non-owning. Nullable. When non-null, Start() takes
                     // a stack-local ForwardConfig() snapshot and passes
                     // it (+ the captured auth_ctx_) to
                     // HeaderRewriter::RewriteRequest.
                     AUTH_NAMESPACE::AuthManager* auth_manager = nullptr);
    ~ProxyTransaction();

    // Non-copyable, non-movable
    ProxyTransaction(const ProxyTransaction&) = delete;
    ProxyTransaction& operator=(const ProxyTransaction&) = delete;

    // Start the proxy transaction. Must be called after wrapping in shared_ptr.
    // Uses shared_from_this() for callback captures.
    void Start();

    // Cancel the transaction. Called from the framework's async abort
    // hook when the client-facing request has been aborted (client
    // disconnect, deferred-response safety cap, HTTP/2 stream RST).
    //
    // Releases the upstream lease back to the pool, clears transport
    // callbacks so in-flight upstream I/O cannot land on a torn-down
    // transaction, and short-circuits any pending retry logic. The
    // stored completion callback is dropped without invocation — the
    // framework's abort hook has already released the client-side
    // bookkeeping, and delivering a response to a disconnected client
    // is pointless.
    //
    // Idempotent and dispatcher-thread-only (invoked via the connection
    // handler's abort hook, which always runs on the dispatcher).
    void Cancel();

    // Hand the per-request snapshot to the transaction so Start() can
    // publish the bidirectional link. Once linked, the shutdown kill
    // loop can mark this transaction; terminal callbacks check the
    // marker before emitting Span::End so shutdown wins every race
    // against in-flight upstream I/O.
    void AttachObservabilitySnapshot(
        std::shared_ptr<OBSERVABILITY_NAMESPACE::ObservabilitySnapshot> snap);

    // Invoked under the snapshot's link_mtx by the shutdown kill loop.
    // Two-part contract:
    //   - kill_for_shutdown_ is the inline gate read by terminal
    //     upstream callbacks (OnHeaders / OnBodyChunk / OnComplete /
    //     OnError / OnUpstreamWriteComplete / OnUpstreamData /
    //     OnStreamIdleTimeout / OnStreamBudgetTimeout / DeliverResponse)
    //     so any callback firing on a still-live transport short-
    //     circuits without writing to the client.
    //   - the dispatcher EnQueue + Cancel() is the cleanup hop — it
    //     releases the upstream lease, retry token, breaker admission,
    //     and async hooks. Without it the proxy would keep using pool
    //     resources after its snapshot was removed from drain counters.
    // Out-of-line definition lets us depend on Dispatcher's full type
    // in the .cc rather than dragging it into this header.
    void MarkKilledForShutdown() noexcept override;
    bool IsKilledForShutdown() const noexcept override {
        return kill_for_shutdown_.load(std::memory_order_acquire);
    }

    // Returns true iff the comma-separated TE header value contains the
    // `trailers` token. Handles RFC 9110 §10.1.4 syntax: each entry MAY
    // carry `;q=...` weight parameters (e.g. `te: trailers;q=1.0`); the
    // matcher splits on the bare token name (substring before the first
    // ';' in each comma-segment), trimmed of OWS. Locale-safe ASCII
    // lowercase via explicit `c | 0x20` branch (NOT std::tolower).
    // Public + static so test code can verify the contract directly.
    static bool ContainsTeTrailersToken(const std::string& value);

    // Computes the H2 send-stall budget. Mirrors H1's zero-disable
    // semantic: response_timeout_ms == 0 opts out of the response-wait
    // timer but the stall-phase hang protection stays on, falling back
    // to SEND_STALL_FALLBACK_MS. Negative values are treated the same
    // as zero (defensive — config validation enforces non-negative,
    // but a future bug must not produce a zero or negative budget that
    // would either fire instantly or never).
    // Public + static so tests verify the contract directly.
    static int ComputeH2StallBudgetMs(int response_timeout_ms) {
        return (response_timeout_ms > 0) ? response_timeout_ms
                                         : SEND_STALL_FALLBACK_MS;
    }

    bool OnHeaders(
        const UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead& head) override;
    bool OnBodyChunk(const char* data, size_t len) override;
    void OnTrailers(
        const std::vector<std::pair<std::string, std::string>>& trailers) override;
    void OnComplete() override;
    void OnError(int error_code, const std::string& message) override;
    void OnRequestSubmitted() override;
    void OnRequestHeadersSubmitted() override;
    void OnRequestBodyProgress(size_t bytes_drained) override;
    void OnRequestBodySourceConsumed(size_t bytes) override;
    UPSTREAM_CALLBACKS_NAMESPACE::H2StreamingAbortCallback
    MakeDeferredErrorCallback() override;

    // Send-phase stall fallback budget when config_.response_timeout_ms == 0.
    // The response-wait timeout is operator-disable-able (set to 0), but the
    // stall-phase hang protection is always on — without it a wedged upstream
    // that stops reading our request body would pin both the client and the
    // pooled connection indefinitely. Used by both the H1 send loop and the
    // H2 send-stall closure (via ComputeH2StallBudgetMs).
    //
    // Public so test code can verify the contract directly. Leaking a
    // static-constexpr int is harmless — no ABI surface, no mutable state.
    static constexpr int SEND_STALL_FALLBACK_MS = 30000;  // 30s

    // Pure static factory mapping RESULT_* codes to HttpResponse — no
    // instance state read. Public so tests can lock the diagnostic-header
    // contract (X-Request-Body-Limit-Exceeded, X-Proxy-Retry-Denied:
    // <reason>) without needing a live ProxyTransaction.
    static HttpResponse MakeErrorResponse(int result_code);

private:
    // Allowlist for H2-path retries from OnError. H1 retries from
    // OnUpstreamData; H2 retries flow through OnError because the H2
    // codec surfaces every transport-level failure via sink->OnError
    // rather than the parser-driven H1 path.
    static bool IsH2RetryableCode(int result_code) noexcept;
    // Map an H2-retryable result code to the RetryPolicy condition.
    // Connect-style codes (peer never processed the stream) map to
    // CONNECT_FAILURE so the first retry runs at zero delay; the rest
    // route through UPSTREAM_DISCONNECT for the response-level backoff
    // policy.
    static RetryPolicy::RetryCondition MapH2CodeToRetryCondition(
        int result_code) noexcept;

    // Bump h2_send_stall_generation_ and queue a fresh send-stall
    // closure for the full budget. Called from DispatchH2 at attempt
    // start. OnRequestBodyProgress does NOT call this directly —
    // refreshes flow through h2_last_progress_at_ + the closure's
    // self-rescheduling check.
    void ArmH2SendStallDeadline(int budget_ms);

    // Queue (or re-queue) the send-stall closure with the given
    // generation and delay. Called by ArmH2SendStallDeadline (initial
    // arm with a fresh generation) and by the closure itself on
    // observed progress (re-queue with the current generation for the
    // remaining budget). Same-generation re-queue is correct because
    // Cleanup / OnRequestSubmitted bump the generation, invalidating
    // any in-flight closure regardless of who queued it.
    void QueueH2SendStallClosure(uint64_t generation, int delay_ms);

    // State machine states
    enum class State {
        INIT,                // Created, not yet started
        CHECKOUT_PENDING,    // Waiting for upstream connection
        SENDING_REQUEST,     // Upstream request being written
        AWAITING_RESPONSE,   // Request sent, waiting for response headers
        RECEIVING_BODY,      // Receiving response body
        COMPLETE,            // Response delivered to client
        FAILED               // Error state, response delivered
    };

    State state_ = State::INIT;
    // After H2 SubmitRequest failure rollback, state_ briefly reads
    // SENDING_REQUEST while h2_path_ is already false. AttemptCheckout
    // (retry path) and DeliverTerminalError (no-retry path) reset it;
    // no live reader observes the gap.
    int attempt_ = 0;  // Current attempt number (0 = first try)
    // Set by Cancel() — short-circuits checkout / retry / response
    // delivery paths so the transaction is torn down even if an
    // upstream response is mid-flight. Dispatcher-thread only.
    bool cancelled_ = false;
    // Shared cancel token passed to UpstreamManager::CheckoutAsync so
    // the pool can drop this transaction's waiter if it's queued when
    // Cancel() fires. Allocated at Start() time; Cancel() sets the
    // atomic which the pool inspects on every pop / sweep.
    std::shared_ptr<std::atomic<bool>> checkout_cancel_token_;

    // Request context (all copied at construction -- the original HttpRequest
    // is INVALIDATED by parser_.Reset() immediately after the async handler
    // returns, so no pointers/references to the original may be stored).
    std::string service_name_;
    std::string method_;
    std::string path_;
    std::string query_;
    int client_http_major_;
    int client_http_minor_;
    std::map<std::string, std::string> client_headers_;
    std::string request_body_;
    int dispatcher_index_;
    std::string client_ip_;
    bool client_tls_;
    int client_fd_;
    bool upstream_tls_;
    std::string upstream_host_;
    int upstream_port_;
    std::string sni_hostname_;  // Preferred Host value for TLS backends behind IPs
    std::string upstream_path_override_;  // If non-empty, use as upstream path (from catch-all param or "/" for exact match)
    std::string static_prefix_;           // Fallback: precomputed by ProxyHandler for strip_prefix

    // Rewritten headers and serialized request (cached for retry)
    std::map<std::string, std::string> rewritten_headers_;
    std::string serialized_request_;
    // Computed upstream path (after strip_prefix / catch-all override).
    // Cached so DispatchH2 builds the H2 :path pseudo-header without
    // recomputing the prefix logic that lives in Start().
    std::string upstream_path_;

    // Captured by value at construction from client_request.auth so the
    // overlay snapshot outlives any retry cycle. HttpRequest is invalidated
    // by parser_.Reset() right after the async handler returns — no
    // references kept. Empty when no policy matched inbound.
    std::optional<AUTH_NAMESPACE::AuthContext> auth_ctx_;

    // Inbound RequestTraceContext copied at construction. Same lifetime
    // contract as auth_ctx_: storing a reference into the original
    // HttpRequest is unsafe because parser_.Reset() invalidates it.
    // Empty when the inbound had no trace context (observability
    // disabled or DROP path with no ObservabilitySnapshot).
    std::optional<OBSERVABILITY_NAMESPACE::RequestTraceContext>
        inbound_trace_ctx_;

    // Dependencies
    UpstreamManager* upstream_manager_;   // non-owning, outlives the transaction
    AUTH_NAMESPACE::AuthManager* auth_manager_ = nullptr;  // non-owning, nullable
    Dispatcher* dispatcher_;              // non-owning, outlives the transaction (for EnQueueDelayed)
    ProxyConfig config_;                  // stored by value — decoupled from ProxyHandler lifetime
    HeaderRewriter header_rewriter_;      // stored by value — small (4 bools config)
    RetryPolicy retry_policy_;            // stored by value — small (1 int + 5 bools config)

    // Completion callback
    HTTP_CALLBACKS_NAMESPACE::AsyncCompletionCallback complete_cb_;
    // Atomic latch — writes happen on dispatcher-thread terminal
    // callbacks (DeliverResponse / Cancel / various stream-error
    // paths), but the destructor reads it on whatever thread releases
    // the last shared_ptr (retry-timer lambda / upstream callback /
    // shutdown kill sweep). Same TSan-flaggable cross-thread shape as
    // kill_for_shutdown_ and inflight_counter_held_; use store(release)
    // / load(acquire) so the dtor sees a published value.
    std::atomic<bool> complete_cb_invoked_{false};

    // Upstream connection state (per attempt)
    UpstreamLease lease_;
    // Codec interface — H1 path always constructs UpstreamHttpCodec; H2
    // path constructs UpstreamH2Codec. Single field through the abstract
    // base lets ProxyTransaction dispatch parsing without protocol-
    // specific downcasts. Protocol-specific extensions (e.g.,
    // UpstreamH2Codec::SubmitH2Request) reach through static_cast at the
    // OnCheckoutReady branch that constructed
    // the matching concrete type.
    std::unique_ptr<UpstreamCodec> codec_;

    // Connection poisoning flag: set when the upstream connection must NOT be
    // returned to the idle pool. Reasons include:
    //   - Early response: upstream responded while request write was still in
    //     progress, leaving stale request bytes in the output buffer.
    //   - Response timeout: upstream may have sent partial response data that
    //     would corrupt the next transaction if the connection were reused.
    // When true, Cleanup() calls MarkClosing() on the UpstreamConnection
    // before releasing the lease, ensuring the connection is destroyed.
    bool poison_connection_ = false;

    // Timing
    std::chrono::steady_clock::time_point start_time_;

    // Circuit breaker integration — resolved once in Start() from
    // `service_name_` + `dispatcher_index_`. Null when there's no
    // CircuitBreakerManager attached (server has no upstreams, or the
    // breaker is being built lazily) — the breaker is simply skipped in
    // that case. Lifetime: the slice is owned by CircuitBreakerHost in
    // CircuitBreakerManager on HttpServer, which outlives this transaction.
    CIRCUIT_BREAKER_NAMESPACE::CircuitBreakerSlice* slice_ = nullptr;

    // Per-host retry budget, resolved alongside `slice_` in Start() from
    // the same CircuitBreakerHost. Null when there's no breaker attached
    // for this service — in that case the transaction skips budget
    // tracking entirely. Lifetime: the budget is owned by the host,
    // which outlives this transaction (destruction order guaranteed by
    // HttpServer member declaration).
    CIRCUIT_BREAKER_NAMESPACE::RetryBudget* retry_budget_ = nullptr;

    // Per-attempt in-flight tracker. Held for the duration of each
    // attempt (first try and retries alike). Replaced on every
    // AttemptCheckout — move-assignment decrements the counter for the
    // prior attempt and increments for the new one, so a retrying
    // transaction stays at a single in_flight unit. Default-constructed
    // guard is empty (counter_ = nullptr): used when retry_budget_ is
    // null or before the first ConsultBreaker admission.
    CIRCUIT_BREAKER_NAMESPACE::RetryBudget::InFlightGuard inflight_guard_;

    // Per-ATTEMPT admission state. Reset on each call to ConsultBreaker();
    // paired Report*() calls thread the `generation` back so the slice
    // can drop stale completions across state transitions (see
    // CircuitBreakerSlice::Admission doc). generation_==0 is a sentinel
    // for "no admission held" — slice domain gens start at 1 so a 0-gen
    // report always drops safely.
    uint64_t admission_generation_ = 0;
    bool is_probe_ = false;

    // Retry-budget token held by this transaction's current retry
    // attempt (attempt_ > 0). Set true after a successful
    // TryConsumeRetry in MaybeRetry; cleared by ReleaseRetryToken in
    // Cleanup. Dry-run rejects proceed but the flag stays false — no
    // token was consumed, so no ReleaseRetry is required.
    bool retry_token_held_ = false;

    // H2 dispatch state. `h2_path_` flips true once DispatchH2 has
    // successfully submitted a stream; cleanup paths gate H1-specific
    // teardown on `!h2_path_`. The H2 session and stream slot live
    // inside `h2_lease_` (Kind::H2) — the lease carries the raw
    // session pointer plus the (partition_alive, conn_alive) dual-token
    // pair so a mid-flight Cleanup / Cancel issue RST_STREAM only if
    // both observers still see the session as live, short-circuiting
    // safely if it was destroyed in between.
    //
    // The lease is constructed AFTER `SubmitRequest` returns a valid
    // `stream_id` (DispatchH2 immediately after the stream-id capture);
    // submit-failure rollback paths leave the lease default-empty
    // (no destructor work to do, no `ReturnH2Stream` BUG-log on -1).
    // Donated H2 leases (the H2 session's permanent transport lease)
    // route through `MarkDonatedToH2`; this per-transaction lease is
    // never marked donated.
    UpstreamLease h2_lease_;
    int32_t h2_stream_id_ = -1;
    bool h2_path_ = false;

    // True iff the inbound request carried `te: trailers` (RFC 7230 §4.3
    // / RFC 9113 §8.2.2 — required by gRPC clients to negotiate trailer
    // support). Captured at construction BEFORE HeaderRewriter strips
    // all te values per RFC 7230 hop-by-hop rules. The H2 outbound nv
    // build re-emits a synthetic `te: trailers` based on this flag; H1
    // path is unchanged (rewriter strips, no re-emit).
    bool client_te_trailers_ = false;

    // H2 send-stall generation counter. Bounds the time spent in
    // SENDING_REQUEST waiting for END_STREAM to flush — without this, a
    // wedged peer that stops reading our DATA frames would pin the H2
    // stream until the peer's PING timeout (or forever, if PING is
    // disabled). Armed BEFORE SubmitRequest so the synchronous
    // on_frame_send_callback path (bodyless requests where nghttp2
    // inline-flushes HEADERS+END_STREAM) can kill it via generation
    // bump. Cleanup also bumps to invalidate any in-flight closure.
    uint64_t h2_send_stall_generation_ = 0;

    // H2 response-timeout arm-once flag. Coordinates the response timer
    // arming between OnHeaders and OnRequestSubmitted: whichever fires
    // first arms ArmResponseTimeout and sets this flag, and the other
    // skips re-arming. Required because the existing H1 OnHeaders path
    // calls ClearResponseTimeout (semantic doesn't apply to H2's
    // two-deadline model) and DispatchH2 cannot arm response-timeout
    // upfront without leaking the budget into the body-write phase.
    // Reset by Cleanup so retry attempts arm fresh.
    bool h2_response_timeout_armed_ = false;

    // True once OnRequestSubmitted has fired. OnRequestBodyProgress
    // gates refresh on this rather than state_ — request-side and
    // response-side phases diverge on the early-final-headers path.
    // Reset by DispatchH2 init + Cleanup.
    bool h2_request_fully_sent_ = false;

    // ---- Streaming-request state ----

    // True when this transaction is forwarding a streaming-mode request.
    // Set in DispatchH1/DispatchH2's streaming branch; preserved across
    // retry resets where idempotent replay is safe (source not yet
    // consumed; body not on wire).
    bool is_streaming_request_ = false;

    // Cumulative DATA bytes whose transport-drain has been observed
    // (OnRequestBodyProgress). Drives the body-on-wire retry-denial
    // check (RESULT_RETRY_DENIED_STREAMING_BODY_ON_WIRE). Latches for
    // the transaction lifetime — NEVER reset by ResetForRetryAttempt
    // because the retry-denial gate must remain truthful across the
    // attempt boundary (a future replayable body source would still
    // honor the latch; this one represents irrevocable wire progress).
    size_t body_bytes_written_to_upstream_ = 0;

    // Cumulative bytes read from the body_stream source (consumer-side
    // BodyStream::Read). Drives the source-consumed retry-denial check
    // (RESULT_RETRY_DENIED_STREAMING_SOURCE_CONSUMED). Bumped via
    // OnRequestBodySourceConsumed virtual. Latches for the transaction
    // lifetime — see body_bytes_written_to_upstream_ above; same rule.
    size_t body_bytes_read_from_source_ = 0;
    // Latched once Read drains any bytes — short-circuit for retry
    // policy checks that don't need exact count. Latches for the
    // transaction lifetime; NEVER reset across retries.
    bool source_consumed_ = false;

    // True after request HEADERS hit the wire. Drives the headers-on-
    // wire retry-denial check for non-idempotent methods
    // (RESULT_RETRY_DENIED_NON_IDEMPOTENT_HEADERS_QUEUED).
    bool request_headers_submitted_ = false;

    // RESERVED: per-request upstream-deadline override (ms). 0 = use
    // ProxyConfig default. API surface for the future gRPC
    // `grpc-timeout` decorator; no middleware writes this today and
    // neither DispatchH1 nor DispatchH2 reads it. Kept as the wiring
    // point for the eventual gRPC plumbing.
    int upstream_deadline_override_ms_ = 0;

    // H1-side parallel to h2_request_fully_sent_. Set when the H1
    // streaming send loop emits its final chunk terminator. Used by
    // SendH1StreamingRequest_'s send-stall fallback.
    bool h1_request_fully_sent_ = false;

    // Gate flag for OnUpstreamWriteComplete: intermediate chunk drains on the
    // H1 streaming path MUST NOT transition state to AWAITING_RESPONSE.
    // EmitH1ChunkedTrailers_ sets this true BEFORE the final SendRaw so the
    // sole post-final-write OnUpstreamWriteComplete fires takes the normal
    // transition path.
    bool h1_streaming_send_complete_ = false;

    // Re-entry + transport-drain backpressure flags for PumpH1StreamingBody_.
    // h1_pump_active_: SendRaw can fire the SetWriteProgressCb callback
    //   synchronously when a direct-write succeeds. The callback re-enters
    //   PumpH1StreamingBody_, which would recurse arbitrarily deep on a
    //   fast upstream. The flag short-circuits the re-entry — the outer
    //   loop picks up additional progress on its next iteration.
    // h1_pump_paused_for_drain_: set when Pump returns because the transport
    //   output buffer crossed the high-water mark. Cleared (and Pump resumed)
    //   when SetWriteProgressCb observes the buffer back below low-water.
    //   Without this, body_stream_->Read() would keep releasing inbound
    //   producer backpressure into output_bf_, defeating the streaming
    //   memory bound on a slow/stalled upstream.
    bool h1_pump_active_ = false;
    bool h1_pump_paused_for_drain_ = false;

    // Cached send-stall budget for the H1 streaming send phase. Parallel to
    // h2_stall_budget_ms_ — computed once at the start of SendH1Streaming
    // Request_ so the SetWriteProgressCb refresh path uses a stable value.
    int h1_stall_budget_ms_ = 0;

    // Active BodyStream for the current streaming request attempt.
    // Non-null when is_streaming_request_=true and the send phase is active.
    std::shared_ptr<http::BodyStream> body_stream_;

    // Last time the H2 codec emitted a request-side DATA frame.
    // Updated by OnRequestBodyProgress; inspected by the single
    // in-flight send-stall closure on fire. The closure re-queues
    // itself for the remaining budget if progress was observed,
    // otherwise it fires the timeout. This keeps the dispatcher's
    // min-heap bounded to one closure per request regardless of
    // upload size, while preserving refresh-on-every-DATA semantics.
    std::chrono::steady_clock::time_point h2_last_progress_at_{};

    // Cached send-stall budget for this attempt. Computed once in
    // DispatchH2 so the closure's progress check doesn't recompute.
    int h2_stall_budget_ms_ = 0;

    // H2 response timeout uses a dispatcher-scheduled task instead of a
    // transport-level deadline: the transport is shared across every
    // stream on the multiplexed session, so SetDeadline would tear down
    // sibling streams when one stalls. The generation counter
    // invalidates a queued task when ClearResponseTimeout fires before
    // the task runs.
    //
    // dispatcher-thread-only: every reader and writer of this field
    // (ArmResponseTimeout, ClearResponseTimeout, the EnQueueDelayed
    // closure) runs on `dispatcher_`'s loop thread. Plain `uint64_t`
    // is sufficient. If the H2 timeout path ever moves to a centralized
    // timer pool or a different dispatcher, this field becomes a race
    // and must promote to `std::atomic<uint64_t>` with relaxed ordering.
    uint64_t h2_response_timeout_generation_ = 0;

    // Snapshot held for the link site in Start(). The shutdown kill
    // loop sets kill_for_shutdown_ via MarkKilledForShutdown(); terminal
    // callbacks read it before Span::End so shutdown wins every race
    // against in-flight upstream I/O.
    std::shared_ptr<OBSERVABILITY_NAMESPACE::ObservabilitySnapshot>
        obs_snapshot_;
    std::atomic<bool> kill_for_shutdown_{false};

    // Per-attempt mutable trace context. Reset on every AttemptCheckout
    // call before propagator strip+inject + re-serialization. Carries the
    // freshly-generated span_id for THIS attempt's outbound `traceparent`
    // (so retries get a fresh CLIENT span rather than reusing the prior
    // attempt's span_id) plus the optional CLIENT span allocated when
    // the inbound is recording. Empty when observability is disabled
    // (`obs_snapshot_` null) — the verbatim-forward path then preserves
    // any client-supplied trace headers.
    OBSERVABILITY_NAMESPACE::AttemptTraceContext current_attempt_;

    // Per-attempt steady-clock start time, captured in AttemptCheckout
    // alongside `current_attempt_`. Read by FinalizeAttemptSpan to
    // emit the `http.client.request.duration` histogram. Set to
    // time_point{} sentinel when observability is disabled — the
    // sentinel suppresses the histogram emit (the catalog instrument
    // would otherwise record a misleading zero on every call).
    std::chrono::steady_clock::time_point attempt_start_steady_{};

    // Lock the manager weak_ptr through the snapshot. Returns nullptr
    // when observability is disabled or the manager has been destroyed.
    OBSERVABILITY_NAMESPACE::ObservabilityManager* obs_manager() const noexcept;
    // Read inbound SERVER span for parent linkage. Null when DROP path
    // OR observability disabled.
    OBSERVABILITY_NAMESPACE::Span* inbound_span() const noexcept;
    // Per-attempt strip-and-inject of `traceparent` / `tracestate` /
    // `uber-trace-id` onto `rewritten_headers_` followed by invalidation
    // of `serialized_request_`. Called from `AttemptCheckout` after
    // `current_attempt_.attempt_local` is built. No-op when
    // observability is disabled or the attempt context is invalid.
    void RebuildOutboundTraceHeaders();
    // Allocate / finalize the per-attempt CLIENT span. End-of-attempt
    // sites (OnComplete / OnError / Cancel / MaybeRetry) call
    // FinalizeAttemptSpan; survivor spans are dropped without End() when
    // shutdown won the kill race.
    void FinalizeAttemptSpan(int status_code,
                              const std::string& error_type);
    // Stamp `network.protocol.version` on the current attempt's CLIENT
    // span at dispatch time — set to "1.1" from DispatchH1 / "2" from
    // DispatchH2 (incl. the TryDispatchExistingH2Session reuse path and
    // the deferred-handshake ALPN-resolved callback). No-op when the
    // attempt span wasn't allocated (DROP / observability-disabled).
    void SetProtocolVersionOnAttemptSpan(const char* version);

    // Latch — Start() bumps inflight_transactions_ exactly once and
    // the destructor decrements iff this is set. Atomic because Start
    // runs on the owning dispatcher thread while ~ProxyTransaction
    // can run on whatever thread releases the last shared_ptr (a
    // retry-timer lambda, an upstream `std::function` callback, or
    // the shutdown kill sweep). Acq_rel exchange establishes a
    // happens-before edge between the Start-thread bump and the
    // dtor-thread decrement.
    std::atomic<bool> inflight_counter_held_{false};
    enum class RelayMode {
        BUFFERED,
        STREAMING,
    };
    RelayMode relay_mode_ = RelayMode::BUFFERED;
    bool response_headers_seen_ = false;
    bool response_committed_ = false;
    bool body_complete_ = false;
    bool retry_from_headers_pending_ = false;
    UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead response_head_;
    std::vector<std::pair<std::string, std::string>> response_trailers_;
    std::string response_body_;
    std::string paused_parse_bytes_;
    HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender stream_sender_;
    std::chrono::steady_clock::time_point response_headers_at_{};
    std::chrono::steady_clock::time_point last_body_progress_at_{};
    uint64_t stream_idle_timer_generation_ = 0;
    uint64_t stream_budget_timer_generation_ = 0;
    bool stream_idle_timer_armed_ = false;
    bool sse_stream_ = false;
    bool pending_retryable_5xx_response_ = false;
    UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead
        pending_retryable_5xx_head_;
    std::string pending_retryable_5xx_body_;
    bool pending_retryable_5xx_body_complete_ = false;
    bool holding_retryable_5xx_response_ = false;
    bool held_retryable_5xx_saw_eof_ = false;

    // Internal methods
    void AttemptCheckout();
    bool PrepareAttemptAdmission();
    void ActivateAttemptTracking();
    void EnsureCheckoutCancelToken();
    void StartCheckoutAsync();
    // Per-attempt observability setup: resets current_attempt_, captures
    // attempt_start_steady_, allocates the CLIENT span (when sampled),
    // and rebuilds the outbound trace headers so the wire carries this
    // attempt's fresh span_id. Called from BOTH AttemptCheckout AND
    // BeginRetryAttemptFromHeld5xx — the held-5xx retry path also needs
    // a fresh CLIENT span + invalidated serialized_request_, otherwise
    // the retry reuses the prior attempt's traceparent on the wire and
    // is invisible in the trace tree.
    void SetupAttemptObservability();
    // Pre-checkout fast path for H2 reuse — see implementation comment.
    // Returns true if the transaction was dispatched through an
    // existing multiplexed H2 session (caller must NOT then call
    // StartCheckoutAsync); false if no existing session is reusable.
    bool TryDispatchExistingH2Session();
    void OnCheckoutReady(UpstreamLease lease);
    void OnCheckoutError(int error_code);

    // H1 streaming send path. Called from the streaming branch in
    // DispatchH1. Implements the three-shape decision and starts the
    // pull loop via WaitForData.
    void SendH1StreamingRequest_(std::shared_ptr<http::BodyStream> body_stream);

    // Continuation invoked from BodyStream::WaitForData callback.
    // Pulls chunks until WOULD_BLOCK/EOS/ABORTED.
    void PumpH1StreamingBody_();

    // Emit the chunked terminator block (final chunk marker + CRLF).
    // H1 upstreams silently discard inbound request trailers per the
    // streaming contract (docs/streaming_request.md §H2 request trailers);
    // the `trailers` parameter is accepted for call-site symmetry with
    // H2 but the entries are NOT written on the wire.
    // Sets h1_streaming_send_complete_ = true BEFORE the final SendRaw so
    // OnUpstreamWriteComplete's guard permits the AWAITING_RESPONSE transition.
    void EmitH1ChunkedTrailers_(
        const std::vector<std::pair<std::string, std::string>>& trailers,
        bool omit_last_chunk_marker);

    // Build "METHOD path?query HTTP/1.1\r\n" + serialized rewritten_headers_.
    // Excludes body framing (caller emits CL:0 or TE:chunked separately).
    std::string BuildH1StreamingRequestHead_() const;

    // H1 dispatch: wires transport callbacks on the lease's transport
    // and serializes the request. Reads `lease_` (already moved in by
    // OnCheckoutReady) and assumes the transport is ready to write.
    void DispatchH1();

    // H2 dispatch: routes the request through the partition's
    // multiplexed H2 session. Reads `lease_`; on a fresh checkout the
    // lease is donated to the H2 connection (transport stays out of
    // the idle pool until every stream exits). On reuse of an existing
    // session, the lease is released back to the pool immediately.
    // No cfg parameter — AcquireH2Connection re-reads the partition's
    // live snapshot via LoadHttp2ConfigSnapshot(), which is always the
    // freshest published value (a SIGHUP between the handshake-defer
    // capture site and the actual dispatch can publish a new snapshot).
    void DispatchH2();

    void SendUpstreamRequest();
    void OnUpstreamData(std::shared_ptr<ConnectionHandler> conn, std::string& data);
    void OnUpstreamWriteComplete(std::shared_ptr<ConnectionHandler> conn);
    void OnResponseComplete();
    void MaybeRetry(RetryPolicy::RetryCondition condition);
    // RST_STREAM the in-flight H2 stream (or MarkClosing on H1) when a
    // pre-body retry is permitted. Enqueues a deferred walker run on the
    // H2 path so the stream slot frees promptly without waiting for the
    // next inbound-bytes drain.
    void TombstonePreBodyHeadersForRetry_();
    // Terminal-failure delivery extracted from OnError so MaybeRetry's
    // retry-not-allowed fallback can avoid bouncing through OnError's
    // H2 retry escape hatch (would otherwise loop). Caller-owned
    // ReportBreakerOutcome inside; idempotent.
    void DeliverTerminalError(int result_code,
                              const std::string& log_message);
    void DeliverResponse(HttpResponse response);
    void Cleanup();
    void ReleaseAttemptAccounting();
    void ReleaseHeldRetryable5xxTransport();
    void ResetForRetryAttempt();
    void BeginRetryAttemptFromHeld5xx();
    void ClearPendingRetryable5xxResponse();
    bool DeliverPendingRetryable5xxResponse(const char* reject_source);
    bool ResumeHeldRetryable5xxResponse(const char* reject_source);

    // Build the final client-facing HttpResponse from the parsed upstream response
    HttpResponse BuildClientResponse();
    HttpResponse BuildResponseFromHead(
        const UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead& head,
        bool include_body,
        std::string* body) const;
    HttpResponse BuildStreamingHeadersResponse() const;
    bool CommitStreamingResponse();
    RelayMode DecideRelayMode(
        const UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead& head) const;
    bool IsNoBodyResponse(
        const UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead& head) const;
    bool ShouldRetryResponse5xx() const;
    bool CanRetryResponse5xxNow();
    void ProcessHeadersRetryDecision();
    void ResumePausedParsing();
    void HandleStreamSendResult(
        HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::SendResult result);
    bool IsSseStream(
        const UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead& head) const;
    void SuspendStreamIdleTimer();
    void RefreshStreamIdleTimer();
    void ScheduleStreamIdleCheck(uint64_t generation,
                                 std::chrono::milliseconds delay);
    void ArmStreamBudgetTimer();
    void InvalidateStreamTimers();
    void OnStreamIdleTimeout(uint64_t generation);
    void OnStreamBudgetTimeout(uint64_t generation);

    // Arm the upstream transport's deadline. When explicit_budget_ms > 0,
    // use that value directly (bypassing config_.response_timeout_ms).
    // Otherwise use config_.response_timeout_ms, which is a no-op when
    // disabled (0). The explicit override is used by the send-phase stall
    // timer to install a protective deadline even when response_timeout_ms
    // is disabled — preventing an indefinite hang on a wedged upstream.
    void ArmResponseTimeout(int explicit_budget_ms = 0);
    void ClearResponseTimeout();

    // Note: MakeErrorResponse is declared public above so test code can
    // pin the diagnostic-header contract without instantiating a full
    // transaction. Circuit-open and retry-budget responses need richer
    // context (Retry-After from slice_, distinguishing header), so they
    // have dedicated factories below — the public static MakeErrorResponse
    // falls back to a plain 503 for those codes if called generically.

    // Emit the circuit-open response:
    //   503 + Retry-After (seconds until slice->OpenUntil())
    //       + X-Circuit-Breaker: open
    //       + X-Upstream-Host: service:host:port
    HttpResponse MakeCircuitOpenResponse() const;

    // Emit the retry-budget-exhausted response:
    //   503 + X-Retry-Budget-Exhausted: 1
    static HttpResponse MakeRetryBudgetResponse();

    // Breaker helpers — gate and outcome classification.
    //
    // ConsultBreaker: call at the top of AttemptCheckout. Populates
    // admission_generation_ and is_probe_ on admission; delivers the
    // circuit-open response and returns false on reject. Dry-run admits
    // and returns true (slice already counted the would-reject).
    // Returns true if the caller should proceed to CheckoutAsync.
    bool ConsultBreaker();

    // ReportBreakerOutcome: classify a result_code into
    // success/failure/neutral and call slice->Report* with
    // admission_generation_. Clears admission_generation_ so a
    // double-report is impossible.
    //
    // failure_kind is ignored unless the outcome is a FailureKind-bearing
    // result; the caller passes the appropriate kind for 5xx vs disconnect
    // vs timeout since the slice treats them differently only for logs.
    void ReportBreakerOutcome(int result_code);

    // ReleaseBreakerAdmissionNeutral: release the admission slot without
    // counting a success or failure. Used when the transaction is aborted
    // locally (Cancel() on client disconnect, cancelled_ early-return
    // after checkout, etc.) before an upstream health signal was observed.
    //
    // Without this, a HALF_OPEN probe slot is stranded if the client
    // disconnects mid-probe — the slice stays in half_open_full until an
    // external reset. No-op if admission_generation_ == 0. Clears
    // admission_generation_ so a following ReportBreakerOutcome is a
    // no-op.
    void ReleaseBreakerAdmissionNeutral();

    // Release the retry-budget token held by this attempt, if any.
    // Idempotent via the retry_token_held_ flag — called from Cleanup
    // between attempts (so the next retry's TryConsumeRetry sees a
    // freshly-released counter) AND from the destructor / Cancel as
    // safety nets. No-op when no budget was attached or no token was
    // consumed (e.g. first attempt, or dry-run reject that didn't
    // consume).
    void ReleaseRetryToken();
};
