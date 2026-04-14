#include "upstream/proxy_transaction.h"
#include "upstream/upstream_manager.h"
#include "upstream/upstream_connection.h"
#include "upstream/http_request_serializer.h"
#include "circuit_breaker/circuit_breaker_manager.h"
#include "circuit_breaker/circuit_breaker_host.h"
#include "circuit_breaker/circuit_breaker_slice.h"
#include "connection_handler.h"
#include "dispatcher.h"
// config/server_config.h provided by proxy_transaction.h (ProxyConfig stored by value)
#include "http/http_request.h"
#include "http/http_status.h"
#include "log/logger.h"

ProxyTransaction::ProxyTransaction(
    const std::string& service_name,
    const HttpRequest& client_request,
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
    const std::string& static_prefix)
    : service_name_(service_name),
      method_(client_request.method),
      path_(client_request.path),
      query_(client_request.query),
      client_headers_(client_request.headers),
      request_body_(client_request.body),
      dispatcher_index_(client_request.dispatcher_index),
      client_ip_(client_request.client_ip),
      client_tls_(client_request.client_tls),
      client_fd_(client_request.client_fd),
      upstream_tls_(upstream_tls),
      upstream_host_(upstream_host),
      upstream_port_(upstream_port),
      sni_hostname_(sni_hostname),
      upstream_path_override_(upstream_path_override),
      static_prefix_(static_prefix),
      upstream_manager_(upstream_manager),
      dispatcher_(upstream_manager && client_request.dispatcher_index >= 0
                  ? upstream_manager->GetDispatcherForIndex(
                        static_cast<size_t>(client_request.dispatcher_index))
                  : nullptr),
      config_(config),
      header_rewriter_(header_rewriter),
      retry_policy_(retry_policy),
      complete_cb_(std::move(complete_cb)),
      start_time_(std::chrono::steady_clock::now())
{
    logging::Get()->debug("ProxyTransaction created client_fd={} service={} "
                          "{} {}", client_fd_, service_name_, method_, path_);
}

ProxyTransaction::~ProxyTransaction() {
    // Safety net: ensure cleanup runs even if DeliverResponse was never called
    // (e.g., transaction was abandoned due to client disconnect).
    Cleanup();

    if (!complete_cb_invoked_ && complete_cb_) {
        logging::Get()->warn("ProxyTransaction destroyed without delivering "
                             "response client_fd={} service={} state={}",
                             client_fd_, service_name_,
                             static_cast<int>(state_));
    }
}

void ProxyTransaction::Start() {
    // Tell the codec the request method so it handles HEAD correctly
    // (no body despite Content-Length/Transfer-Encoding in response).
    codec_.SetRequestMethod(method_);

    // Compute rewritten headers (strip hop-by-hop, add X-Forwarded-For, etc.)
    rewritten_headers_ = header_rewriter_.RewriteRequest(
        client_headers_, client_ip_, client_tls_,
        upstream_tls_,
        upstream_host_, upstream_port_, sni_hostname_);

    // Compute upstream path with strip_prefix support.
    // Prefer upstream_path_override_ (extracted from catch-all route param by
    // ProxyHandler) — it captures the exact tail matched by the router, which
    // correctly handles dynamic route patterns like /api/:version/*path.
    // Fall back to static_prefix_ string stripping for backward compatibility
    // with routes that don't use catch-all params.
    std::string upstream_path = path_;
    if (!upstream_path_override_.empty()) {
        upstream_path = upstream_path_override_;
        if (upstream_path.empty() || upstream_path[0] != '/') {
            upstream_path = "/" + upstream_path;
        }
    } else if (!static_prefix_.empty()) {
        if (path_.size() >= static_prefix_.size() &&
            path_.compare(0, static_prefix_.size(), static_prefix_) == 0) {
            upstream_path = path_.substr(static_prefix_.size());
            if (upstream_path.empty() || upstream_path[0] != '/') {
                upstream_path = "/" + upstream_path;
            }
        }
    }

    // Serialize the upstream request (cached for retry)
    serialized_request_ = HttpRequestSerializer::Serialize(
        method_, upstream_path, query_, rewritten_headers_, request_body_);

    logging::Get()->debug("ProxyTransaction::Start client_fd={} service={} "
                          "upstream={}:{} {} {}",
                          client_fd_, service_name_,
                          upstream_host_, upstream_port_,
                          method_, upstream_path);

    // Resolve the circuit-breaker slice once. Null when no breaker is
    // attached (server has no upstreams configured), or when the
    // service/dispatcher pair is out of
    // range. In any null case the breaker is simply bypassed — the
    // transaction proceeds as if circuit breaking were disabled.
    if (upstream_manager_ && dispatcher_index_ >= 0) {
        auto* cbm = upstream_manager_->GetCircuitBreakerManager();
        if (cbm) {
            auto* host = cbm->GetHost(service_name_);
            if (host) {
                slice_ = host->GetSlice(static_cast<size_t>(dispatcher_index_));
                // Cache the retry-budget pointer unconditionally when
                // the host exists — usage at each attempt is gated by
                // the live `slice_->config().enabled` flag so that
                // SIGHUP toggles take effect on the next retry within
                // a running transaction. Resolution-time gating would
                // miss the flip in either direction.
                retry_budget_ = host->GetRetryBudget();
            }
        }
    }

    AttemptCheckout();
}

void ProxyTransaction::AttemptCheckout() {
    state_ = State::CHECKOUT_PENDING;

    // Circuit breaker gate — consulted before every attempt (first try and
    // retries both). Each attempt gets a fresh admission stamped with the
    // slice's current generation. If the slice rejects with REJECTED_OPEN,
    // ConsultBreaker delivers the §12.1 response and returns false; the
    // retry loop treats RESULT_CIRCUIT_OPEN as terminal (§8) so a rejected
    // retry produces a single 503 to the client, not a nested retry.
    // Dry-run reject logs inside TryAcquire and returns ADMITTED through
    // the decision enum (REJECTED_OPEN_DRYRUN), so ConsultBreaker proceeds.
    if (!ConsultBreaker()) {
        return;
    }

    // Retry-budget gate for retry attempts (attempt_ > 0). Gating here
    // rather than in MaybeRetry means a delayed retry holds no token
    // during its backoff sleep — the budget's `retries_in_flight`
    // reflects only retries that are actually about to reach (or are
    // reaching) the upstream, matching the "aggregate upstream load"
    // semantics of the %-of-in-flight cap.
    //
    // Live-check `slice_->config().enabled` at each attempt — the
    // cached `retry_budget_` pointer is resolved once in Start(), but
    // the `enabled` flag is the documented live master switch. A
    // SIGHUP flipping enabled=true→false mid-flight must stop
    // enforcing the budget on subsequent retries; enabled=false→true
    // mid-flight must start. Gating at the pointer level would miss
    // both directions.
    //
    // The `!retry_token_held_` guard is defensive — Cleanup() between
    // retry attempts always releases the prior token.
    bool breaker_live_enabled = slice_ && slice_->config().enabled;
    if (retry_budget_ && breaker_live_enabled &&
        attempt_ > 0 && !retry_token_held_) {
        bool is_dry_run = slice_->config().dry_run;
        if (retry_budget_->TryConsumeRetry()) {
            retry_token_held_ = true;
        } else if (is_dry_run) {
            logging::Get()->info(
                "ProxyTransaction retry budget would-reject (dry-run) "
                "client_fd={} service={} attempt={}",
                client_fd_, service_name_, attempt_);
        } else {
            logging::Get()->warn(
                "retry budget exhausted service={} in_flight={} "
                "retries_in_flight={} cap={} client_fd={} attempt={}",
                service_name_,
                retry_budget_->InFlight(),
                retry_budget_->RetriesInFlight(),
                retry_budget_->ComputeCap(),
                client_fd_, attempt_);
            // CRITICAL: release the slice admission before bailing.
            // ConsultBreaker() already admitted this attempt — in
            // HALF_OPEN that means a probe slot was reserved
            // (half_open_inflight_ / half_open_admitted_ both
            // incremented). Returning here without releasing would
            // strand that slot forever, wedging the slice in
            // half_open_full until an operator-driven reload/reset.
            // Neutral release decrements both counters for probes;
            // no-op for non-probe (CLOSED) admissions, matching the
            // general "local cause, no upstream signal" semantic.
            ReleaseBreakerAdmissionNeutral();
            state_ = State::FAILED;
            DeliverResponse(MakeRetryBudgetResponse());
            return;
        }
    }

    // Track this attempt against the host-level retry budget's
    // in_flight counter. Gated by the live `enabled` flag so disabling
    // the breaker mid-flight stops tracking immediately; enabling it
    // starts tracking at the next attempt. No-op when retry_budget_
    // is null (no breaker manager / unknown host).
    if (retry_budget_ && breaker_live_enabled) {
        inflight_guard_ = retry_budget_->TrackInFlight();
    }

    auto self = shared_from_this();

    // Lazily allocate the shared cancel token so the pool can drop
    // this transaction's wait-queue entry if Cancel() fires while the
    // checkout is pending. Reused across retry attempts — Cancel()
    // flips it once for the lifetime of the transaction.
    if (!checkout_cancel_token_) {
        checkout_cancel_token_ =
            std::make_shared<std::atomic<bool>>(false);
    }

    upstream_manager_->CheckoutAsync(
        service_name_,
        static_cast<size_t>(dispatcher_index_),
        // ready callback
        [self](UpstreamLease lease) {
            self->OnCheckoutReady(std::move(lease));
        },
        // error callback
        [self](int error_code) {
            self->OnCheckoutError(error_code);
        },
        checkout_cancel_token_
    );
}

void ProxyTransaction::OnCheckoutReady(UpstreamLease lease) {
    if (cancelled_) {
        // Client disconnected / safety cap fired while the checkout was
        // in flight. Release the lease immediately so the connection
        // returns to the pool for another request to use, instead of
        // sitting idle attached to a torn-down transaction.
        lease.Release();
        // Release the breaker admission neutrally — the upstream was
        // never exercised, and stranding the slot would wedge a
        // HALF_OPEN probe cycle. Cancel() may already have released;
        // the helper is no-op in that case.
        ReleaseBreakerAdmissionNeutral();
        return;
    }
    if (state_ != State::CHECKOUT_PENDING) {
        // Transaction was cancelled or already completed (shouldn't happen
        // in normal flow, but guard defensively).
        logging::Get()->warn("ProxyTransaction::OnCheckoutReady called in "
                             "unexpected state={} client_fd={} service={}",
                             static_cast<int>(state_), client_fd_,
                             service_name_);
        return;
    }

    lease_ = std::move(lease);

    auto* upstream_conn = lease_.Get();
    if (!upstream_conn) {
        OnError(RESULT_CHECKOUT_FAILED,
                "Checkout returned empty lease");
        return;
    }

    auto transport = upstream_conn->GetTransport();
    if (!transport) {
        OnError(RESULT_CHECKOUT_FAILED,
                "Upstream connection has no transport");
        return;
    }

    logging::Get()->debug("ProxyTransaction checkout ready client_fd={} "
                          "service={} upstream_fd={} attempt={}",
                          client_fd_, service_name_, transport->fd(),
                          attempt_);

    // Wire transport callbacks (do NOT overwrite close/error -- pool owns those).
    // Use shared_ptr capture to keep the transaction alive while the upstream
    // connection is in-flight.  The reference cycle (transaction -> lease ->
    // transport -> callbacks -> transaction) is broken by Cleanup(), which
    // nulls out SetOnMessageCb / SetCompletionCb before the transaction is
    // released from DeliverResponse (or from the destructor safety net).
    //
    // IMPORTANT: each callback takes a LOCAL copy of `self` before invoking the
    // member function.  Cleanup() calls SetOnMessageCb(nullptr) inside
    // OnUpstreamData, which destroys the lambda closure and its captured `self`.
    // The local-copy on the stack keeps the transaction alive for the duration
    // of that call, preventing use-after-free.
    auto self = shared_from_this();
    transport->SetOnMessageCb(
        [self](std::shared_ptr<ConnectionHandler> conn, std::string& data) {
            auto txn = self;  // stack copy survives closure destruction
            txn->OnUpstreamData(conn, data);
        }
    );
    transport->SetCompletionCb(
        [self](std::shared_ptr<ConnectionHandler> conn) {
            auto txn = self;  // stack copy survives closure destruction
            txn->OnUpstreamWriteComplete(conn);
        }
    );

    SendUpstreamRequest();
}

void ProxyTransaction::OnCheckoutError(int error_code) {
    if (cancelled_) return;
    if (state_ != State::CHECKOUT_PENDING) {
        return;
    }

    logging::Get()->warn("ProxyTransaction checkout failed client_fd={} "
                         "service={} error={} attempt={}",
                         client_fd_, service_name_, error_code, attempt_);

    // Only retry actual network connect failures. Pool saturation
    // (POOL_EXHAUSTED, QUEUE_TIMEOUT) and shutdown should fail fast —
    // retrying under backpressure amplifies load on an already-stressed
    // pool and stretches client latency with no benefit. A breaker-drain
    // reject (CHECKOUT_CIRCUIT_OPEN from the wait-queue drain) is also
    // terminal: the
    // client gets the same circuit-open response a fresh requester
    // would, and the retry loop must not retry it.
    //
    // Breaker reporting: connect failures (both timeout and refused) are
    // upstream-health signals → ReportFailure(CONNECT_FAILURE). Local
    // capacity (POOL_EXHAUSTED, QUEUE_TIMEOUT) and shutdown are NOT
    // reported — they don't imply upstream unhealthiness (design §7).
    // CHECKOUT_CIRCUIT_OPEN is also not reported to the breaker (would
    // be a feedback loop — our own reject counting against the upstream).
    //
    // Import error codes from PoolPartition:
    //   CHECKOUT_CONNECT_FAILED  = -2  → retryable, report CONNECT_FAILURE
    //   CHECKOUT_CONNECT_TIMEOUT = -3  → retryable, report CONNECT_FAILURE
    //   CHECKOUT_POOL_EXHAUSTED  = -1  → not retryable, neutral-release probe
    //   CHECKOUT_QUEUE_TIMEOUT   = -5  → not retryable, neutral-release probe
    //   CHECKOUT_SHUTTING_DOWN   = -4  → not retryable, neutral-release probe
    //   CHECKOUT_CIRCUIT_OPEN    = -6  → not retryable, do NOT report
    static constexpr int CONNECT_FAILED  = -2;
    static constexpr int CONNECT_TIMEOUT = -3;
    static constexpr int CIRCUIT_OPEN    = -6;

    if (error_code == CIRCUIT_OPEN) {
        // Drain path: breaker tripped while this transaction was queued
        // Do NOT Report to the slice —
        // our own reject must not feed back into the failure math. Emit
        // the §12.1 circuit-open response directly.
        logging::Get()->info(
            "ProxyTransaction checkout drained by circuit breaker "
            "client_fd={} service={}",
            client_fd_, service_name_);
        DeliverResponse(MakeCircuitOpenResponse());
        // Clear admission_generation_ so Cleanup / destructor doesn't
        // double-report. The admission was already fire-and-forget —
        // slice-side bookkeeping is intact (the drain itself doesn't
        // touch inflight counters because the breaker didn't admit).
        admission_generation_ = 0;
        return;
    }

    if (error_code == CONNECT_FAILED || error_code == CONNECT_TIMEOUT) {
        // Report connect failure to the breaker BEFORE retrying —
        // otherwise the retry's ConsultBreaker might admit against a
        // stale success count, delaying trip detection.
        ReportBreakerOutcome(RESULT_CHECKOUT_FAILED);
        MaybeRetry(RetryPolicy::RetryCondition::CONNECT_FAILURE);
    } else {
        // Pool exhaustion, queue timeout, or shutdown — local capacity issue.
        // Use RESULT_POOL_EXHAUSTED → 503 (not 502 which implies upstream failure).
        // Release the breaker slot neutrally — admission never reached upstream.
        ReportBreakerOutcome(RESULT_POOL_EXHAUSTED);
        OnError(RESULT_POOL_EXHAUSTED,
                "Pool checkout failed (local capacity, error=" +
                std::to_string(error_code) + ")");
    }
}

void ProxyTransaction::SendUpstreamRequest() {
    state_ = State::SENDING_REQUEST;

    auto* upstream_conn = lease_.Get();
    if (!upstream_conn) {
        OnError(RESULT_SEND_FAILED, "Upstream connection lost before send");
        return;
    }

    auto transport = upstream_conn->GetTransport();
    if (!transport || transport->IsClosing()) {
        // Stale keep-alive connection closed after checkout but before write.
        // Treat as upstream disconnect so retry_on_disconnect can recover
        // idempotent requests instead of failing immediately with 502.
        poison_connection_ = true;
        logging::Get()->warn("ProxyTransaction stale connection before send "
                             "client_fd={} service={} attempt={}",
                             client_fd_, service_name_, attempt_);
        // Report to the breaker BEFORE retrying — MaybeRetry's
        // AttemptCheckout will overwrite admission_generation_ on the
        // next ConsultBreaker. Without this call, a probe in HALF_OPEN
        // would leak its slot and the slice could stall in
        // half_open_full; in CLOSED, the failure would be under-counted
        // until the last retry ran through OnError.
        ReportBreakerOutcome(RESULT_UPSTREAM_DISCONNECT);
        MaybeRetry(RetryPolicy::RetryCondition::UPSTREAM_DISCONNECT);
        return;
    }

    logging::Get()->debug("ProxyTransaction sending request client_fd={} "
                          "service={} upstream_fd={} bytes={}",
                          client_fd_, service_name_, transport->fd(),
                          serialized_request_.size());

    // Arm a send-phase stall deadline. Without this, a wedged upstream
    // that stops reading our request body would pin both the client and
    // the pooled connection indefinitely — OnUpstreamWriteComplete never
    // fires under back-pressure, and the pool's far-future checkout
    // deadline never trips.
    //
    // The stall budget uses response_timeout_ms when configured, else
    // a hardcoded fallback. Unlike the response-wait phase, the stall
    // phase is ALWAYS protected — the refresh-on-progress callback
    // prevents false positives on large uploads making steady progress,
    // so using a fallback here doesn't penalize any legitimate traffic.
    // Config "disabled" (response_timeout_ms == 0) opts out of the
    // response-wait timeout, NOT the hang protection.
    static constexpr int SEND_STALL_FALLBACK_MS = 30000;  // 30s
    const int stall_budget_ms = config_.response_timeout_ms > 0
                              ? config_.response_timeout_ms
                              : SEND_STALL_FALLBACK_MS;
    ArmResponseTimeout(stall_budget_ms);

    // Install write-progress callback to refresh the stall deadline on
    // each partial write. Cleared in OnUpstreamWriteComplete (and in
    // Cleanup) when the write finishes; the response-wait phase uses a
    // hard (unrefreshed) deadline with the normal budget.
    {
        std::weak_ptr<ProxyTransaction> weak_self = weak_from_this();
        transport->SetWriteProgressCb(
            [weak_self, stall_budget_ms](std::shared_ptr<ConnectionHandler>, size_t) {
                auto self = weak_self.lock();
                if (!self) return;
                // Refresh only while we're still writing the request.
                // Progress events after the transition to
                // AWAITING_RESPONSE/RECEIVING_BODY are ignored so the
                // response-wait deadline stays a hard budget.
                if (self->state_ == State::SENDING_REQUEST) {
                    self->ArmResponseTimeout(stall_budget_ms);
                }
            });
    }

    transport->SendRaw(serialized_request_.data(),
                       serialized_request_.size());
}

void ProxyTransaction::OnUpstreamData(
    std::shared_ptr<ConnectionHandler> conn, std::string& data) {
    // Guard against callbacks after completion/failure
    if (cancelled_) return;
    if (state_ == State::COMPLETE || state_ == State::FAILED) {
        return;
    }

    // Empty data signals upstream disconnect (EOF) from the pool's close
    // callback. For connection-close framing (no Content-Length / TE),
    // llhttp needs an EOF signal to finalize the response. Try Finish()
    // first — if it completes the response, deliver it instead of retrying.
    if (data.empty()) {
        if (codec_.Finish()) {
            // EOF-delimited response completed successfully
            poison_connection_ = true;  // connection-close: not reusable
            OnResponseComplete();
            return;
        }
        int upstream_fd = conn ? conn->fd() : -1;
        logging::Get()->warn("ProxyTransaction upstream disconnect (EOF) "
                             "client_fd={} service={} upstream_fd={} "
                             "state={} attempt={}",
                             client_fd_, service_name_, upstream_fd,
                             static_cast<int>(state_), attempt_);
        // Report BEFORE retry — see stale-connection path above for why.
        ReportBreakerOutcome(RESULT_UPSTREAM_DISCONNECT);
        MaybeRetry(RetryPolicy::RetryCondition::UPSTREAM_DISCONNECT);
        return;
    }

    // Parse upstream response data
    size_t consumed = codec_.Parse(data.data(), data.size());

    // Check for parse error — the HTTP stream is desynchronized and the
    // connection must not be returned to the idle pool.
    if (codec_.HasError()) {
        poison_connection_ = true;
        int upstream_fd = conn ? conn->fd() : -1;
        OnError(RESULT_PARSE_ERROR,
                "Upstream response parse error: " + codec_.GetError() +
                " upstream_fd=" + std::to_string(upstream_fd));
        return;
    }

    const auto& response = codec_.GetResponse();

    // If a complete response was parsed but the read buffer still has
    // unconsumed bytes, the upstream sent trailing data after the
    // response boundary (garbage, an unexpected second response, or
    // pipelined data that violates our outbound one-request-per-wire
    // contract). The socket state is indeterminate — poison the lease
    // so it won't be returned to the idle pool even if keep_alive is
    // true, preventing the next borrower from seeing desynchronized
    // data on the same wire.
    if (response.complete && consumed < data.size()) {
        poison_connection_ = true;
        int upstream_fd = conn ? conn->fd() : -1;
        logging::Get()->warn(
            "ProxyTransaction upstream sent {} trailing bytes after "
            "response client_fd={} service={} upstream_fd={} status={}",
            data.size() - consumed, client_fd_, service_name_,
            upstream_fd, response.status_code);
    }

    // Handle early response (upstream responds while we're still sending)
    if (state_ == State::SENDING_REQUEST) {
        // Transition from send-phase (with the fallback stall deadline)
        // to response-wait-phase, but only when a non-1xx response has
        // begun. The codec discards standalone 1xx interim responses
        // (100/102/103) and resets response_ to empty — status_code
        // stays 0 in that case. The partial-stall hang is handled by
        // the send-phase stall timer installed in SendUpstreamRequest
        // (refreshed on write progress).
        //
        // When response_timeout_ms > 0: re-anchor the deadline at now
        // with the configured response budget (overwrites the stall
        // deadline via SetDeadline).
        // When response_timeout_ms == 0 (explicitly disabled): clear
        // the fallback stall deadline so legitimately slow responses
        // aren't capped at the fallback — honoring the documented
        // "disabled" semantic for the response-wait phase.
        if (response.status_code > 0 || response.headers_complete || response.complete) {
            if (config_.response_timeout_ms > 0) {
                ArmResponseTimeout();
            } else {
                ClearResponseTimeout();
            }
        }

        if (response.complete) {
            // Full response received before request write completed
            poison_connection_ = true;
            int upstream_fd = conn ? conn->fd() : -1;
            logging::Get()->debug("ProxyTransaction early response (complete) "
                                  "client_fd={} service={} upstream_fd={} "
                                  "status={}",
                                  client_fd_, service_name_, upstream_fd,
                                  response.status_code);
            OnResponseComplete();
            return;
        }
        if (response.headers_complete) {
            // Headers arrived but body still incoming -- transition to
            // RECEIVING_BODY. The write-complete callback will be a no-op.
            poison_connection_ = true;
            state_ = State::RECEIVING_BODY;
            int upstream_fd = conn ? conn->fd() : -1;
            logging::Get()->debug("ProxyTransaction early response (headers) "
                                  "client_fd={} service={} upstream_fd={} "
                                  "status={}",
                                  client_fd_, service_name_, upstream_fd,
                                  response.status_code);
            return;
        }
        // Partial data, not enough to determine -- stay in SENDING_REQUEST
        return;
    }

    // Normal response handling (AWAITING_RESPONSE or RECEIVING_BODY)
    if (response.complete) {
        OnResponseComplete();
        return;
    }

    if (state_ == State::AWAITING_RESPONSE && response.headers_complete) {
        state_ = State::RECEIVING_BODY;
    }

    // Refresh deadline on body progress: response_timeout_ms guards the wait
    // for headers, but once body data is flowing, a slow download that makes
    // forward progress should not timeout. Re-arm the deadline from now so
    // only stalls (no data for response_timeout_ms) trigger a timeout.
    if (state_ == State::RECEIVING_BODY && config_.response_timeout_ms > 0) {
        auto* upstream_conn = lease_.Get();
        if (upstream_conn) {
            auto transport = upstream_conn->GetTransport();
            if (transport) {
                transport->SetDeadline(
                    std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(config_.response_timeout_ms));
            }
        }
    }
}

void ProxyTransaction::OnUpstreamWriteComplete(
    std::shared_ptr<ConnectionHandler> conn) {
    if (cancelled_) return;
    // Clear the send-phase write-progress callback installed in
    // SendUpstreamRequest. The response-wait phase uses a hard
    // (unrefreshed) deadline. Done regardless of state so an early
    // response path that already transitioned past SENDING_REQUEST
    // also stops refreshing.
    if (auto* upstream_conn = lease_.Get()) {
        if (auto transport = upstream_conn->GetTransport()) {
            transport->SetWriteProgressCb(nullptr);
        }
    }

    // If state already advanced past SENDING_REQUEST (due to early response),
    // the response deadline is already armed — nothing more to do.
    if (state_ != State::SENDING_REQUEST) {
        return;
    }

    state_ = State::AWAITING_RESPONSE;

    int upstream_fd = conn ? conn->fd() : -1;
    logging::Get()->debug("ProxyTransaction request sent client_fd={} "
                          "service={} upstream_fd={} attempt={}",
                          client_fd_, service_name_, upstream_fd, attempt_);

    // Transition from send-phase (with the fallback stall deadline)
    // to response-wait-phase. When response_timeout_ms > 0, re-anchor
    // the deadline at now with the configured budget (overwrites the
    // stall deadline). When response_timeout_ms == 0 (disabled), clear
    // the fallback stall deadline explicitly — otherwise a slow but
    // legitimate response would be capped at SEND_STALL_FALLBACK_MS
    // (30s), contradicting the documented "disabled" semantic.
    if (config_.response_timeout_ms > 0) {
        ArmResponseTimeout();
    } else {
        ClearResponseTimeout();
    }
}

void ProxyTransaction::OnResponseComplete() {
    ClearResponseTimeout();

    const auto& response = codec_.GetResponse();
    if (!response.keep_alive) {
        poison_connection_ = true;
    }

    // Check for 5xx and retry if policy allows — before setting COMPLETE.
    // COMPLETE is terminal; resetting it back to INIT after setting it would
    // be a logic error (and confusing for any future state assertions).
    if (response.status_code >= HttpStatus::INTERNAL_SERVER_ERROR &&
        response.status_code < 600) {
        logging::Get()->warn("ProxyTransaction upstream 5xx client_fd={} "
                             "service={} status={} attempt={}",
                             client_fd_, service_name_,
                             response.status_code, attempt_);
        // Report failure BEFORE MaybeRetry — the retry's fresh
        // ConsultBreaker must see the just-added failure in the window
        // (and potentially reject if this was the trip-causing call).
        // Pass a synthetic RESULT_CHECKOUT_FAILED-like signal; the
        // classifier maps 5xx → FailureKind::RESPONSE_5XX.
        ReportBreakerOutcome(/* sentinel */ -1000);
        MaybeRetry(RetryPolicy::RetryCondition::RESPONSE_5XX);
        return;
    }

    // 2xx / 3xx / 4xx: upstream is healthy (from the breaker's
    // perspective — 4xx is a client-side problem). Report success.
    ReportBreakerOutcome(RESULT_SUCCESS);

    state_ = State::COMPLETE;

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time_);

    int upstream_fd = -1;
    if (lease_ && lease_.Get() && lease_.Get()->GetTransport()) {
        upstream_fd = lease_.Get()->GetTransport()->fd();
    }

    logging::Get()->info("ProxyTransaction complete client_fd={} service={} "
                         "upstream_fd={} status={} attempt={} duration={}ms",
                         client_fd_, service_name_, upstream_fd,
                         response.status_code, attempt_, duration.count());

    HttpResponse client_response = BuildClientResponse();
    DeliverResponse(std::move(client_response));
}

void ProxyTransaction::OnError(int result_code,
                                const std::string& log_message) {
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time_);

    logging::Get()->warn("ProxyTransaction error client_fd={} service={} "
                         "result={} attempt={} duration={}ms: {}",
                         client_fd_, service_name_, result_code,
                         attempt_, duration.count(), log_message);

    // Report the outcome if an admission is still held. Most error paths
    // call ReportBreakerOutcome themselves BEFORE reaching OnError (so a
    // retry's ConsultBreaker sees the fresh signal) — this is a safety
    // net for error paths that skipped reporting, e.g., RESULT_SEND_FAILED
    // and RESULT_RESPONSE_TIMEOUT from the on-upstream-data paths.
    // ReportBreakerOutcome is idempotent: it clears admission_generation_
    // on the first call so a double-call drops harmlessly.
    ReportBreakerOutcome(result_code);

    state_ = State::FAILED;
    HttpResponse error_response = (result_code == RESULT_CIRCUIT_OPEN)
        ? MakeCircuitOpenResponse()
        : MakeErrorResponse(result_code);
    DeliverResponse(std::move(error_response));
}

void ProxyTransaction::MaybeRetry(RetryPolicy::RetryCondition condition) {
    // Short-circuit on cancellation — no point retrying against a
    // disconnected client.
    if (cancelled_) return;
    // In v1 (buffered), headers_sent is always false -- no response data
    // has been sent to the client yet.
    if (retry_policy_.ShouldRetry(attempt_, method_, condition, false)) {
        attempt_++;

        logging::Get()->info("ProxyTransaction retrying client_fd={} "
                             "service={} attempt={} condition={}",
                             client_fd_, service_name_, attempt_,
                             static_cast<int>(condition));

        // Release old lease, clear callbacks, poison if tainted.
        // Cleanup also releases any retry token held by the previous
        // retry attempt so the next TryConsumeRetry in AttemptCheckout
        // sees a fresh counter. The retry-budget gate itself now lives
        // at the top of AttemptCheckout — that way a delayed retry
        // doesn't hold a token during its backoff sleep, which would
        // otherwise pollute the budget's retries_in_flight with
        // queued-but-sleeping work that hasn't reached the upstream.
        Cleanup();
        codec_.Reset();
        // Re-apply request method after reset — llhttp_init() zeroes
        // parser.method, so HEAD responses would be parsed as if they
        // carry a body, causing the retried request to hang.
        codec_.SetRequestMethod(method_);
        poison_connection_ = false;

        // Condition-dependent first-retry policy:
        // Connection-level failures (stale keep-alive, connect refused)
        // are transient — a different pooled connection will succeed.
        // Immediate first retry avoids penalizing every stale-connection
        // recovery. Response-level failures (5xx, timeout) signal a
        // struggling upstream that needs breathing room — always back
        // off, even on first retry.
        bool is_transient_connection_failure =
            (condition == RetryPolicy::RetryCondition::CONNECT_FAILURE ||
             condition == RetryPolicy::RetryCondition::UPSTREAM_DISCONNECT);

        auto delay = (attempt_ <= 1 && is_transient_connection_failure)
            ? std::chrono::milliseconds(0)
            : retry_policy_.BackoffDelay(attempt_);

        if (delay.count() > 0 && dispatcher_) {
            // Timer-based deferred retry via the dispatcher's delayed task
            // queue. The callback captures shared_from_this() to keep the
            // transaction alive during the backoff wait. If Cancel() fires
            // during the wait, cancelled_ is set and the callback is a no-op.
            logging::Get()->debug(
                "ProxyTransaction backoff {}ms client_fd={} "
                "service={} attempt={} condition={}",
                delay.count(), client_fd_, service_name_,
                attempt_, static_cast<int>(condition));
            auto self = shared_from_this();
            bool enqueued = dispatcher_->EnQueueDelayed(
                [self]() {
                    if (self->cancelled_) return;
                    self->AttemptCheckout();
                },
                delay);
            if (!enqueued) {
                // Dispatcher stopped — task was silently dropped.
                // Deliver an error so the transaction doesn't die
                // without invoking complete_cb_.
                OnError(RESULT_CHECKOUT_FAILED,
                        "Dispatcher stopped during retry backoff");
            }
        } else if (delay.count() > 0) {
            OnError(RESULT_CHECKOUT_FAILED,
                    "Dispatcher unavailable for retry backoff");
        } else {
            // Zero delay (connection-level first retry): immediate
            logging::Get()->debug(
                "ProxyTransaction immediate retry client_fd={} "
                "service={} attempt={} condition={}",
                client_fd_, service_name_, attempt_,
                static_cast<int>(condition));
            AttemptCheckout();
        }
        return;
    }

    // Retry not allowed -- map condition to appropriate error response
    int result_code;
    switch (condition) {
        case RetryPolicy::RetryCondition::CONNECT_FAILURE:
            result_code = RESULT_CHECKOUT_FAILED;
            break;
        case RetryPolicy::RetryCondition::RESPONSE_TIMEOUT:
            result_code = RESULT_RESPONSE_TIMEOUT;
            break;
        case RetryPolicy::RetryCondition::UPSTREAM_DISCONNECT:
            result_code = RESULT_UPSTREAM_DISCONNECT;
            break;
        case RetryPolicy::RetryCondition::RESPONSE_5XX:
            // On 5xx with no retry, deliver the actual upstream response
            // (which may contain useful error details for the client).
            {
                auto duration = std::chrono::duration_cast<
                    std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - start_time_);
                logging::Get()->warn("ProxyTransaction upstream 5xx final "
                                     "client_fd={} service={} status={} "
                                     "attempt={} duration={}ms",
                                     client_fd_, service_name_,
                                     codec_.GetResponse().status_code,
                                     attempt_, duration.count());
                state_ = State::COMPLETE;
                HttpResponse client_response = BuildClientResponse();
                DeliverResponse(std::move(client_response));
                return;
            }
    }

    OnError(result_code, "Retry exhausted or not allowed for condition=" +
            std::to_string(static_cast<int>(condition)));
}

void ProxyTransaction::DeliverResponse(HttpResponse response) {
    if (complete_cb_invoked_) {
        logging::Get()->warn("ProxyTransaction double-deliver prevented "
                             "client_fd={} service={}",
                             client_fd_, service_name_);
        return;
    }
    complete_cb_invoked_ = true;

    // Cleanup BEFORE invoking the completion callback to ensure transport
    // callbacks are cleared and lease is released.
    Cleanup();

    if (complete_cb_) {
        auto cb = std::move(complete_cb_);
        complete_cb_ = nullptr;
        cb(std::move(response));
    }
}

void ProxyTransaction::Cancel() {
    if (cancelled_ || complete_cb_invoked_) {
        return;
    }
    logging::Get()->debug("ProxyTransaction::Cancel client_fd={} service={} "
                          "state={}", client_fd_, service_name_,
                          static_cast<int>(state_));
    cancelled_ = true;
    // Signal the pool's wait queue (if we're still pending). This
    // proactively frees the queue slot so bursts of disconnecting
    // clients don't fill the bounded wait queue with dead waiters
    // and block live requests with pool-exhausted / queue-timeout
    // errors. A set token is also dropped lazily on future pops and
    // PurgeExpiredWaitEntries sweeps, so this is idempotent.
    if (checkout_cancel_token_) {
        checkout_cancel_token_->store(true, std::memory_order_release);
    }
    // Mark the completion callback as "already invoked" so any late
    // DeliverResponse path triggered by an in-flight upstream reply
    // becomes a no-op. The framework's abort hook has already handled
    // the client-side bookkeeping; delivering a response to a
    // disconnected client would be pointless and confuses the complete-
    // closure's one-shot completed/cancelled contract.
    complete_cb_invoked_ = true;
    complete_cb_ = nullptr;
    // POISON the upstream connection before releasing the lease IF we
    // have already started (or finished) writing the upstream request.
    // Without this, Cleanup() would return a keep-alive socket that
    // still has an in-flight response attached to the cancelled client
    // — another waiter could then pick up that connection and parse
    // the abandoned upstream reply as its OWN response, breaking
    // request/response isolation.
    //
    // States beyond CHECKOUT_PENDING all imply bytes have been
    // exchanged with the upstream or are mid-flight:
    //   SENDING_REQUEST   — request partially written, upstream may still respond
    //   AWAITING_RESPONSE — request fully sent, response not yet received
    //   RECEIVING_BODY    — response partially received
    //   COMPLETE / FAILED — terminal, but lease may still be held
    //
    // In INIT and CHECKOUT_PENDING no bytes have left the client side
    // toward the upstream yet, so the connection (if any) is still
    // clean and safe to return to the pool.
    if (state_ != State::INIT && state_ != State::CHECKOUT_PENDING) {
        poison_connection_ = true;
    }
    // Release any held breaker admission neutrally. Cancel() is always
    // a LOCAL termination — client disconnect, framework-level abort,
    // H2 stream reset, etc. Even when we poisoned a pooled connection
    // mid-request, counting that as an upstream-health failure would
    // trip the breaker against a backend that may be perfectly healthy
    // (browser cancels, user-initiated timeouts, etc. are all common
    // causes). The reviewer guidance is explicit: client-initiated
    // aborts must be neutral from the breaker's perspective.
    //
    // Trade-off: in HALF_OPEN, ReportNeutral on a probe decrements
    // both inflight and admitted, so a cancelled probe makes the slot
    // eligible for a replacement admission in the same cycle. That is
    // the documented design contract of ReportNeutral ("the upstream
    // wasn't actually exercised by this admission" from the breaker's
    // decision-math point of view — we didn't observe a success or
    // failure), and it is acceptable: probes that genuinely succeed
    // or fail still close / re-trip the cycle normally, and a broken
    // upstream under cancel-spam will still fail those real probes.
    ReleaseBreakerAdmissionNeutral();
    // Release the upstream lease back to the pool (or destroy it if
    // poisoned) and clear transport callbacks so any in-flight upstream
    // bytes land harmlessly.
    Cleanup();
}

void ProxyTransaction::Cleanup() {
    // Release any retry-budget token held by the attempt that just
    // ended. Must happen BEFORE the next TryConsumeRetry in MaybeRetry
    // so the new attempt sees accurate retries_in_flight. Idempotent
    // via the retry_token_held_ flag.
    ReleaseRetryToken();

    if (lease_) {
        auto* conn = lease_.Get();
        if (conn) {
            auto transport = conn->GetTransport();
            if (transport) {
                transport->SetOnMessageCb(nullptr);
                transport->SetCompletionCb(nullptr);
                // Clear the send-phase write-progress callback in case
                // Cleanup runs mid-write (retry / error before
                // OnUpstreamWriteComplete). The pool's WirePoolCallbacks
                // also clears it on return, but being explicit avoids
                // any window where the callback can still fire on a
                // transaction that's being torn down.
                transport->SetWriteProgressCb(nullptr);
                ClearResponseTimeout();
            }
            // Poison the connection if an early response was received while
            // the request write was still in progress. The transport's output
            // buffer may still contain unsent request bytes that would corrupt
            // the next request if the connection were returned to idle.
            if (poison_connection_) {
                conn->MarkClosing();
            }
        }
        lease_.Release();
    }
    // NOTE: complete_cb_ is intentionally NOT cleared here. Cleanup() is
    // called by MaybeRetry() between retry attempts, and the callback must
    // survive across retries so DeliverResponse() can eventually invoke it.
    // DeliverResponse() itself moves + nulls complete_cb_ after invocation.
}

HttpResponse ProxyTransaction::BuildClientResponse() {
    auto& upstream_resp = codec_.GetResponse();

    HttpResponse response;
    response.Status(upstream_resp.status_code, upstream_resp.status_reason);

    // Rewrite response headers (strip hop-by-hop, add Via).
    // Use AppendHeader to preserve repeated upstream headers (Cache-Control,
    // Link, Via, etc.) that Header()'s set-semantics would collapse.
    auto rewritten = header_rewriter_.RewriteResponse(upstream_resp.headers);
    for (const auto& [name, value] : rewritten) {
        response.AppendHeader(name, value);
    }

    // For HEAD responses, preserve the upstream's Content-Length header
    // instead of auto-computing from body_.size() (which would be 0).
    // RFC 7231 §4.3.2: HEAD responses carry the same Content-Length as
    // the equivalent GET response.
    if (method_ == "HEAD") {
        response.PreserveContentLength();
    }

    // Move body to avoid copying potentially large payloads (up to 64MB)
    if (!upstream_resp.body.empty()) {
        response.Body(std::move(upstream_resp.body));
    }

    return response;
}

void ProxyTransaction::ArmResponseTimeout(int explicit_budget_ms) {
    // Determine the budget: explicit override wins, else use config.
    // Both == 0 means "no timeout configured AND no explicit override" →
    // silently skip.
    int budget_ms = explicit_budget_ms > 0
                  ? explicit_budget_ms
                  : config_.response_timeout_ms;
    if (budget_ms <= 0) {
        return;
    }

    auto* upstream_conn = lease_.Get();
    if (!upstream_conn) return;

    auto transport = upstream_conn->GetTransport();
    if (!transport) return;

    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(budget_ms);
    transport->SetDeadline(deadline);

    // Use weak_ptr to avoid reference cycle: the deadline callback is stored
    // on the transport (ConnectionHandler), which outlives any transaction
    // that timed out. A shared_ptr capture would prevent cleanup.
    auto weak_self = weak_from_this();
    transport->SetDeadlineTimeoutCb([weak_self]() -> bool {
        auto self = weak_self.lock();
        if (!self) {
            // Transaction already destroyed — let the connection close normally
            return false;
        }

        // Timeout handled by the proxy transaction
        logging::Get()->warn(
            "ProxyTransaction response timeout client_fd={} service={} "
            "attempt={}",
            self->client_fd_, self->service_name_, self->attempt_);

        // Poison the connection: it may have received partial response data
        // that would corrupt the next transaction if returned to idle.
        self->poison_connection_ = true;

        // SENDING_REQUEST is retryable: a timeout can fire during an early
        // response where ArmResponseTimeout() ran but state hasn't advanced
        // past SENDING_REQUEST yet (upstream sent partial headers then stalled).
        if (self->state_ == State::SENDING_REQUEST ||
            self->state_ == State::AWAITING_RESPONSE ||
            self->state_ == State::RECEIVING_BODY) {
            // Report BEFORE retry — MaybeRetry's AttemptCheckout will
            // overwrite admission_generation_ on the next
            // ConsultBreaker, stranding the current attempt's
            // admission (probe slot leaks in HALF_OPEN; CLOSED
            // under-counts the failure until the last retry hits
            // OnError).
            self->ReportBreakerOutcome(RESULT_RESPONSE_TIMEOUT);
            self->MaybeRetry(RetryPolicy::RetryCondition::RESPONSE_TIMEOUT);
        } else {
            self->OnError(RESULT_RESPONSE_TIMEOUT, "Response timeout");
        }
        // Return true: we handled the timeout, don't close the connection
        // (the pool owns the connection lifecycle via its close/error callbacks)
        return true;
    });

    logging::Get()->debug("ProxyTransaction armed response timeout {}ms "
                          "client_fd={} service={} upstream_fd={}",
                          budget_ms, client_fd_,
                          service_name_, transport->fd());
}

void ProxyTransaction::ClearResponseTimeout() {
    if (!lease_) return;

    auto* upstream_conn = lease_.Get();
    if (!upstream_conn) return;

    auto transport = upstream_conn->GetTransport();
    if (!transport) return;

    transport->ClearDeadline();
    transport->SetDeadlineTimeoutCb(nullptr);
}

HttpResponse ProxyTransaction::MakeErrorResponse(int result_code) {
    if (result_code == RESULT_RESPONSE_TIMEOUT) {
        return HttpResponse::GatewayTimeout();
    }
    if (result_code == RESULT_POOL_EXHAUSTED) {
        return HttpResponse::ServiceUnavailable();
    }
    if (result_code == RESULT_RETRY_BUDGET_EXHAUSTED) {
        return MakeRetryBudgetResponse();
    }
    if (result_code == RESULT_CIRCUIT_OPEN) {
        // The static factory has no `this`, so it cannot build the
        // fully §12.1-compliant response (Retry-After derived from
        // slice state, X-Upstream-Host). All in-class paths for
        // CIRCUIT_OPEN use the non-static MakeCircuitOpenResponse()
        // — reaching this branch means a future caller forgot that
        // rule. Log loudly so the mistake shows up in logs instead
        // of producing a stealth regression against the contract.
        //
        // Still emit `X-Circuit-Breaker: open` + `Connection: close`
        // so the response remains self-identifying as a circuit-open
        // reject. Clients inspecting that header will correctly back
        // off via their own client-side logic rather than treating
        // this as an anonymous 503.
        logging::Get()->error(
            "ProxyTransaction::MakeErrorResponse(RESULT_CIRCUIT_OPEN) "
            "invoked from static context — use MakeCircuitOpenResponse() "
            "to emit §12.1-compliant headers");
        HttpResponse resp = HttpResponse::ServiceUnavailable();
        resp.Header("X-Circuit-Breaker", "open");
        resp.Header("Connection", "close");
        return resp;
    }
    if (result_code == RESULT_CHECKOUT_FAILED ||
        result_code == RESULT_SEND_FAILED ||
        result_code == RESULT_PARSE_ERROR ||
        result_code == RESULT_UPSTREAM_DISCONNECT) {
        return HttpResponse::BadGateway();
    }
    return HttpResponse::InternalError();
}

HttpResponse ProxyTransaction::MakeCircuitOpenResponse() const {
    // TryAcquire() returns REJECTED_OPEN for three distinct situations:
    //   * True OPEN: slice is in OPEN state, IsOpenDeadlineSet() is true,
    //     Retry-After reflects remaining backoff from OpenUntil().
    //   * HALF_OPEN reject (half_open_full or half_open_recovery_failing):
    //     slice transitioned HALF_OPEN via TransitionOpenToHalfOpen, which
    //     clears open_until. IsOpenDeadlineSet() is false. These rejects
    //     wait on the in-flight probe cycle completing (success → CLOSED,
    //     failure → re-trip with fresh backoff). Retry-After = 1 in this
    //     branch would under-report the likely wait on a re-trip; ceil to
    //     base_open_duration_ms as a conservative hint (the worst case is
    //     re-trip + fresh backoff window).
    // Emit a distinct X-Circuit-Breaker label for observability so
    // operators can separate "true OPEN" from "HALF_OPEN recovery back-
    // pressure" on dashboards.
    int retry_after_secs = 1;
    const char* breaker_label = "open";
    // Absolute sanity ceiling — independent of config. Protects against
    // ridiculous programmatic values that might slip past validation.
    static constexpr int RETRY_AFTER_ABS_MAX_SECS = 3600;  // 1 hour
    if (slice_) {
        if (slice_->IsOpenDeadlineSet()) {
            // True OPEN — Retry-After from the actual stored deadline.
            // The deadline is authoritative: it's what the slice will
            // actually honor, regardless of any subsequent config
            // reload that might lower max_open_duration_ms. Clamping
            // below the stored deadline would tell well-behaved clients
            // to retry early and bounce on more 503s until the original
            // deadline elapses.
            auto open_until = slice_->OpenUntil();
            auto now = std::chrono::steady_clock::now();
            auto ms_remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                open_until - now).count();
            // Ceiling-round to seconds so we never advertise a window
            // shorter than the actual remaining backoff.
            int64_t diff = (ms_remaining + 999) / 1000;
            if (diff < 1) diff = 1;
            if (diff > RETRY_AFTER_ABS_MAX_SECS) diff = RETRY_AFTER_ABS_MAX_SECS;
            retry_after_secs = static_cast<int>(diff);
            breaker_label = "open";
        } else if (slice_->CurrentState() ==
                   circuit_breaker::State::HALF_OPEN) {
            // HALF_OPEN reject — no deadline to read. Hint with the
            // NEXT expected open duration (base << consecutive_trips_,
            // clamped by max_open_duration_ms) rather than base alone:
            // after multiple trips, exponential backoff has already
            // grown the OPEN window, and advertising bare base would
            // tell clients to retry far earlier than the breaker will
            // admit even in the worst case (probe cycle fails, slice
            // re-trips into the larger backoff).
            int64_t next_ms = slice_->NextOpenDurationMs();
            int hint = static_cast<int>(
                std::max<int64_t>(1, (next_ms + 999) / 1000));
            retry_after_secs = std::min(hint, RETRY_AFTER_ABS_MAX_SECS);
            breaker_label = "half_open";
        }
        // Any other state (CLOSED): shouldn't reach here — ConsultBreaker
        // only calls this on REJECTED_OPEN. Fall through with the
        // conservative defaults (Retry-After=1, label="open") so a
        // regression can't silently emit Retry-After=0.
    }

    HttpResponse resp;
    resp.Status(HttpStatus::SERVICE_UNAVAILABLE);
    resp.Text("Upstream circuit breaker is open; please retry later.\n");
    resp.Header("Retry-After", std::to_string(retry_after_secs));
    resp.Header("X-Circuit-Breaker", breaker_label);
    // Hint operators (not clients) at which upstream tripped. Useful
    // when a gateway fronts multiple backends; without this header, a
    // 503 is opaque.
    resp.Header("X-Upstream-Host",
                   upstream_host_ + ":" + std::to_string(upstream_port_));
    resp.Header("Connection", "close");
    return resp;
}

HttpResponse ProxyTransaction::MakeRetryBudgetResponse() {
    HttpResponse resp;
    resp.Status(HttpStatus::SERVICE_UNAVAILABLE);
    resp.Text("Upstream retry budget exhausted.\n");
    resp.Header("X-Retry-Budget-Exhausted", "1");
    resp.Header("Connection", "close");
    return resp;
}

bool ProxyTransaction::ConsultBreaker() {
    if (!slice_) {
        // No breaker attached for this service. Proceed as if the
        // breaker layer didn't exist. admission_generation_ stays 0 so
        // any accidental ReportBreakerOutcome call is a no-op.
        is_probe_ = false;
        admission_generation_ = 0;
        return true;
    }
    auto admission = slice_->TryAcquire();

    // Stash the admission metadata for the paired Report*() call. Note
    // we record this EVEN for REJECTED_OPEN (where generation_==0 is a
    // sentinel) — it's harmless and keeps the branches simpler.
    admission_generation_ = admission.generation;
    is_probe_ = (admission.decision ==
                 circuit_breaker::Decision::ADMITTED_PROBE);

    if (admission.decision == circuit_breaker::Decision::REJECTED_OPEN) {
        // Hard reject — slice counted it, logged it, and we must not
        // touch the upstream. Emit §12.1 response and DO NOT Report
        // back (would create a feedback loop — our own reject counting
        // as a failure against the already-OPEN slice).
        state_ = State::FAILED;
        logging::Get()->info(
            "ProxyTransaction circuit-open reject client_fd={} service={} "
            "attempt={}",
            client_fd_, service_name_, attempt_);
        DeliverResponse(MakeCircuitOpenResponse());
        // Clear admission_generation_ — there's nothing to Report.
        admission_generation_ = 0;
        return false;
    }

    // REJECTED_OPEN_DRYRUN: slice logged the would-reject and counted
    // it; caller proceeds to the upstream. Fall through as admitted.
    // ADMITTED / ADMITTED_PROBE: proceed.
    return true;
}

void ProxyTransaction::ReleaseRetryToken() {
    if (retry_token_held_ && retry_budget_) {
        retry_budget_->ReleaseRetry();
    }
    retry_token_held_ = false;
}

void ProxyTransaction::ReleaseBreakerAdmissionNeutral() {
    if (!slice_ || admission_generation_ == 0) return;

    uint64_t gen = admission_generation_;
    admission_generation_ = 0;
    bool probe = is_probe_;
    is_probe_ = false;

    // Neutral release — no upstream health signal. Decrements the
    // per-partition inflight (CLOSED) or the HALF_OPEN probe admitted
    // counter, so a cancelled probe doesn't wedge the slice in
    // half_open_full.
    slice_->ReportNeutral(probe, gen);
}

void ProxyTransaction::ReportBreakerOutcome(int result_code) {
    // No slice, or already reported: bail. admission_generation_==0 is
    // the sentinel — slice domain generations start at 1, so a 0 gen
    // would be rejected as stale anyway; the early return just avoids
    // an unnecessary atomic load. The Report* methods themselves are
    // idempotent against stale gens, but we also must not increment a
    // probe_*/rejected_ counter for a non-event.
    if (!slice_ || admission_generation_ == 0) return;

    // Capture + clear in one go so concurrent / re-entrant calls bail.
    uint64_t gen = admission_generation_;
    admission_generation_ = 0;
    bool probe = is_probe_;
    is_probe_ = false;

    using circuit_breaker::FailureKind;

    // Synthetic sentinel for the OnResponseComplete 5xx path — maps to
    // RESPONSE_5XX without needing a new public result code. Callers
    // other than OnResponseComplete never use this value.
    static constexpr int SENTINEL_5XX = -1000;

    switch (result_code) {
        case RESULT_SUCCESS:
            slice_->ReportSuccess(probe, gen);
            return;

        case SENTINEL_5XX:
            slice_->ReportFailure(FailureKind::RESPONSE_5XX, probe, gen);
            return;

        case RESULT_CHECKOUT_FAILED:
            slice_->ReportFailure(FailureKind::CONNECT_FAILURE, probe, gen);
            return;

        case RESULT_RESPONSE_TIMEOUT:
            slice_->ReportFailure(FailureKind::RESPONSE_TIMEOUT, probe, gen);
            return;

        case RESULT_UPSTREAM_DISCONNECT:
        case RESULT_SEND_FAILED:
            slice_->ReportFailure(FailureKind::UPSTREAM_DISCONNECT, probe, gen);
            return;

        case RESULT_POOL_EXHAUSTED:
        case RESULT_PARSE_ERROR:
            // Local outcomes — no upstream health signal. Release the
            // admission slot neutrally so a probe doesn't leak the
            // HALF_OPEN slot.
            slice_->ReportNeutral(probe, gen);
            return;

        case RESULT_CIRCUIT_OPEN:
        case RESULT_RETRY_BUDGET_EXHAUSTED:
            // Our own rejects — MUST NOT feed back into the slice.
            // These paths should not reach ReportBreakerOutcome (both
            // clear admission_generation_ before delivering), but the
            // defensive branch keeps the class-wide invariant: these
            // outcomes are invisible to the breaker.
            return;

        default:
            // Unknown result code — log and neutral-release to keep the
            // probe bookkeeping consistent. A runtime log here is
            // cheaper than a slice stuck in HALF_OPEN forever because a
            // new result code slipped through unclassified.
            logging::Get()->error(
                "ReportBreakerOutcome: unclassified result_code={} "
                "service={} — releasing neutrally",
                result_code, service_name_);
            slice_->ReportNeutral(probe, gen);
            return;
    }
}
