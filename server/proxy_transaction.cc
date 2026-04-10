#include "upstream/proxy_transaction.h"
#include "upstream/upstream_manager.h"
#include "upstream/upstream_connection.h"
#include "upstream/http_request_serializer.h"
#include "connection_handler.h"
// config/server_config.h provided by proxy_transaction.h (ProxyConfig stored by value)
#include "http/http_request.h"
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

    AttemptCheckout();
}

void ProxyTransaction::AttemptCheckout() {
    state_ = State::CHECKOUT_PENDING;

    auto self = shared_from_this();

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
        }
    );
}

void ProxyTransaction::OnCheckoutReady(UpstreamLease lease) {
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
    if (state_ != State::CHECKOUT_PENDING) {
        return;
    }

    logging::Get()->warn("ProxyTransaction checkout failed client_fd={} "
                         "service={} error={} attempt={}",
                         client_fd_, service_name_, error_code, attempt_);

    // Only retry actual network connect failures. Pool saturation
    // (POOL_EXHAUSTED, QUEUE_TIMEOUT) and shutdown should fail fast —
    // retrying under backpressure amplifies load on an already-stressed
    // pool and stretches client latency with no benefit.
    // Import error codes from PoolPartition:
    //   CHECKOUT_CONNECT_FAILED  = -2  → retryable
    //   CHECKOUT_CONNECT_TIMEOUT = -3  → retryable
    //   CHECKOUT_POOL_EXHAUSTED  = -1  → not retryable
    //   CHECKOUT_QUEUE_TIMEOUT   = -5  → not retryable
    //   CHECKOUT_SHUTTING_DOWN   = -4  → not retryable
    static constexpr int CONNECT_FAILED  = -2;
    static constexpr int CONNECT_TIMEOUT = -3;

    if (error_code == CONNECT_FAILED || error_code == CONNECT_TIMEOUT) {
        MaybeRetry(RetryPolicy::RetryCondition::CONNECT_FAILURE);
    } else {
        // Pool exhaustion, queue timeout, or shutdown — local capacity issue.
        // Use RESULT_POOL_EXHAUSTED → 503 (not 502 which implies upstream failure).
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
        MaybeRetry(RetryPolicy::RetryCondition::UPSTREAM_DISCONNECT);
        return;
    }

    logging::Get()->debug("ProxyTransaction sending request client_fd={} "
                          "service={} upstream_fd={} bytes={}",
                          client_fd_, service_name_, transport->fd(),
                          serialized_request_.size());

    // Response timeout is armed in OnUpstreamWriteComplete (after the
    // request is fully written) — not here. Arming here would penalize
    // large uploads: a slow upstream receiver that is still making read
    // progress would be timed out before the write buffer drains.

    transport->SendRaw(serialized_request_.data(),
                       serialized_request_.size());
}

void ProxyTransaction::OnUpstreamData(
    std::shared_ptr<ConnectionHandler> conn, std::string& data) {
    // Guard against callbacks after completion/failure
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
        MaybeRetry(RetryPolicy::RetryCondition::UPSTREAM_DISCONNECT);
        return;
    }

    // Parse upstream response data
    codec_.Parse(data.data(), data.size());

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

    // Handle early response (upstream responds while we're still sending)
    if (state_ == State::SENDING_REQUEST) {
        // Arm the response timeout only when a non-1xx response has begun.
        // The codec discards standalone 1xx interim responses (e.g., 100
        // Continue) and resets response_ to empty. If we armed the timeout
        // unconditionally, large or back-pressured uploads that receive a
        // 100 Continue would start the final-response deadline prematurely,
        // causing false retries/504s before the request body is even sent.
        if (response.status_code > 0 || response.headers_complete || response.complete) {
            ArmResponseTimeout();
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
            // Arm timeout: without this, a stalled body after early headers
            // hangs forever (OnUpstreamWriteComplete is a no-op once state
            // has advanced past SENDING_REQUEST).
            ArmResponseTimeout();
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
    // If state already advanced past SENDING_REQUEST (due to early response),
    // this is a no-op.
    if (state_ != State::SENDING_REQUEST) {
        return;
    }

    state_ = State::AWAITING_RESPONSE;

    int upstream_fd = conn ? conn->fd() : -1;
    logging::Get()->debug("ProxyTransaction request sent client_fd={} "
                          "service={} upstream_fd={} attempt={}",
                          client_fd_, service_name_, upstream_fd, attempt_);

    ArmResponseTimeout();
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
    if (response.status_code >= 500 && response.status_code < 600) {
        logging::Get()->warn("ProxyTransaction upstream 5xx client_fd={} "
                             "service={} status={} attempt={}",
                             client_fd_, service_name_,
                             response.status_code, attempt_);
        MaybeRetry(RetryPolicy::RetryCondition::RESPONSE_5XX);
        return;
    }

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

    state_ = State::FAILED;
    HttpResponse error_response = MakeErrorResponse(result_code);
    DeliverResponse(std::move(error_response));
}

void ProxyTransaction::MaybeRetry(RetryPolicy::RetryCondition condition) {
    // In v1 (buffered), headers_sent is always false -- no response data
    // has been sent to the client yet.
    if (retry_policy_.ShouldRetry(attempt_, method_, condition, false)) {
        attempt_++;

        logging::Get()->info("ProxyTransaction retrying client_fd={} "
                             "service={} attempt={} condition={}",
                             client_fd_, service_name_, attempt_,
                             static_cast<int>(condition));

        // Release old lease, clear callbacks, poison if tainted
        Cleanup();
        codec_.Reset();
        // Re-apply request method after reset — llhttp_init() zeroes
        // parser.method, so HEAD responses would be parsed as if they
        // carry a body, causing the retried request to hang.
        codec_.SetRequestMethod(method_);
        poison_connection_ = false;

        // v1: immediate retry (no backoff delay). RetryPolicy::BackoffDelay()
        // is implemented but not wired in yet because sleeping on the
        // dispatcher thread would block the event loop (same class of problem
        // as the accept-retry backoff pitfall in DEVELOPMENT_RULES.md).
        // A timer-based deferred retry via EnQueueDeferred() or dispatcher
        // timer is the correct approach and is planned for a future version.
        // Under max_retries > 0, tight retry loops are bounded to at most
        // 10 retries (validation cap) per transaction.
        AttemptCheckout();
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

void ProxyTransaction::Cleanup() {
    if (lease_) {
        auto* conn = lease_.Get();
        if (conn) {
            auto transport = conn->GetTransport();
            if (transport) {
                transport->SetOnMessageCb(nullptr);
                transport->SetCompletionCb(nullptr);
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

void ProxyTransaction::ArmResponseTimeout() {
    if (config_.response_timeout_ms <= 0) {
        return;
    }

    auto* upstream_conn = lease_.Get();
    if (!upstream_conn) return;

    auto transport = upstream_conn->GetTransport();
    if (!transport) return;

    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(config_.response_timeout_ms);
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
                          config_.response_timeout_ms, client_fd_,
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
    if (result_code == RESULT_CHECKOUT_FAILED ||
        result_code == RESULT_SEND_FAILED ||
        result_code == RESULT_PARSE_ERROR ||
        result_code == RESULT_UPSTREAM_DISCONNECT) {
        return HttpResponse::BadGateway();
    }
    return HttpResponse::InternalError();
}
