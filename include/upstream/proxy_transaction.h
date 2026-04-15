#pragma once

#include "common.h"
#include "upstream/upstream_http_codec.h"
#include "upstream/upstream_response_sink.h"
#include "upstream/upstream_lease.h"
#include "upstream/header_rewriter.h"
#include "upstream/retry_policy.h"
#include "config/server_config.h"        // ProxyConfig (stored by value)
#include "circuit_breaker/retry_budget.h" // RetryBudget::InFlightGuard (member-by-value)
#include "http/http_callbacks.h"
#include "http/http_response.h"
// <string>, <map>, <unordered_map>, <memory>, <functional>, <chrono> provided by common.h

// Forward declarations
class UpstreamManager;
class ConnectionHandler;
class Dispatcher;

namespace CIRCUIT_BREAKER_NAMESPACE {
class CircuitBreakerSlice;
}  // RetryBudget already defined via retry_budget.h

class ProxyTransaction : public std::enable_shared_from_this<ProxyTransaction>,
                         public UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseSink {
public:
    // Result codes for internal state tracking
    static constexpr int RESULT_SUCCESS             = 0;
    static constexpr int RESULT_CHECKOUT_FAILED     = -1;  // Upstream connect failure → 502
    static constexpr int RESULT_SEND_FAILED         = -2;
    static constexpr int RESULT_PARSE_ERROR         = -3;
    static constexpr int RESULT_RESPONSE_TIMEOUT    = -4;
    static constexpr int RESULT_UPSTREAM_DISCONNECT = -5;
    static constexpr int RESULT_POOL_EXHAUSTED      = -6;  // Local capacity → 503
    // Circuit breaker rejected this attempt before it touched the upstream.
    // Carries Retry-After + X-Circuit-Breaker headers (§12.1).
    // Terminal — retry loop MUST NOT retry this outcome (§8).
    static constexpr int RESULT_CIRCUIT_OPEN        = -7;
    // Retry budget exhausted. No Retry-After; distinct header
    // X-Retry-Budget-Exhausted so operators can tell the two 503s apart
    // from circuit-open rejects.
    static constexpr int RESULT_RETRY_BUDGET_EXHAUSTED = -8;

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
                     const std::string& static_prefix);
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

    bool OnHeaders(
        const UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead& head) override;
    bool OnBodyChunk(const char* data, size_t len) override;
    void OnTrailers(
        const std::vector<std::pair<std::string, std::string>>& trailers) override;
    void OnComplete() override;
    void OnError(int error_code, const std::string& message) override;

private:
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

    // Dependencies
    UpstreamManager* upstream_manager_;   // non-owning, outlives the transaction
    Dispatcher* dispatcher_;              // non-owning, outlives the transaction (for EnQueueDelayed)
    ProxyConfig config_;                  // stored by value — decoupled from ProxyHandler lifetime
    HeaderRewriter header_rewriter_;      // stored by value — small (4 bools config)
    RetryPolicy retry_policy_;            // stored by value — small (1 int + 5 bools config)

    // Completion callback
    HTTP_CALLBACKS_NAMESPACE::AsyncCompletionCallback complete_cb_;
    bool complete_cb_invoked_ = false;

    // Upstream connection state (per attempt)
    UpstreamLease lease_;
    UpstreamHttpCodec codec_;

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

    // Internal methods
    void AttemptCheckout();
    void OnCheckoutReady(UpstreamLease lease);
    void OnCheckoutError(int error_code);
    void SendUpstreamRequest();
    void OnUpstreamData(std::shared_ptr<ConnectionHandler> conn, std::string& data);
    void OnUpstreamWriteComplete(std::shared_ptr<ConnectionHandler> conn);
    void OnResponseComplete();
    void MaybeRetry(RetryPolicy::RetryCondition condition);
    void DeliverResponse(HttpResponse response);
    void Cleanup();
    void ClearPendingRetryable5xxResponse();
    bool DeliverPendingRetryable5xxResponse(const char* reject_source);

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
    bool CanRetryResponse5xxNow() const;
    void ProcessHeadersRetryDecision();
    void ResumePausedParsing();
    void HandleStreamSendResult(
        HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::SendResult result);
    bool IsSseStream(
        const UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead& head) const;
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

    // Error response factory (maps result codes to HTTP responses).
    // Circuit-open and retry-budget responses need richer context
    // (Retry-After from slice_, distinguishing header), so they have
    // dedicated factories below — MakeErrorResponse falls back to a
    // plain 503 for those codes if called generically.
    static HttpResponse MakeErrorResponse(int result_code);

    // Emit the circuit-open response (design §12.1):
    //   503 + Retry-After (seconds until slice->OpenUntil())
    //       + X-Circuit-Breaker: open
    //       + X-Upstream-Host: service:host:port
    HttpResponse MakeCircuitOpenResponse() const;

    // Emit the retry-budget-exhausted response (design §12.2):
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
    // success/failure/neutral (per design §7) and call slice->Report*
    // with admission_generation_. Clears admission_generation_ so a
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
