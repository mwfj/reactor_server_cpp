#include "auth/upstream_http_client.h"

#include "upstream/upstream_manager.h"
#include "upstream/upstream_http_codec.h"
#include "upstream/upstream_lease.h"
#include "upstream/upstream_connection.h"
#include "upstream/upstream_response_sink.h"
#include "upstream/upstream_response_head.h"
#include "upstream/http_request_serializer.h"
#include "upstream/pool_partition.h"
#include "connection_handler.h"
#include "dispatcher.h"
#include "log/logger.h"
// <functional>, <memory>, <atomic>, <chrono> via common.h

namespace AUTH_NAMESPACE {

namespace {

// Map a PoolPartition::CHECKOUT_* error code to a short stable string
// safe to surface in logs and observability. Mirrors the proxy path's
// mapping but narrower (we don't need per-reason circuit-breaker headers
// here — the JWKS / discovery caller handles retry at a higher layer).
const char* CheckoutErrorLabel(int code) noexcept {
    switch (code) {
        case PoolPartition::CHECKOUT_POOL_EXHAUSTED:  return "pool_exhausted";
        case PoolPartition::CHECKOUT_CONNECT_FAILED:  return "connect_failed";
        case PoolPartition::CHECKOUT_CONNECT_TIMEOUT: return "connect_timeout";
        case PoolPartition::CHECKOUT_SHUTTING_DOWN:   return "shutting_down";
        case PoolPartition::CHECKOUT_QUEUE_TIMEOUT:   return "queue_timeout";
        case PoolPartition::CHECKOUT_CIRCUIT_OPEN:    return "circuit_open";
        default:                                       return "unknown";
    }
}

}  // namespace

// ---------------------------------------------------------------------------
// Per-request state. A Transaction is created on Issue() and torn down
// in `FinishLocked(...)`. Capture always goes through shared_ptr<Transaction>
// so completion / transport / dispatcher callbacks cannot outlive the
// state they touch.
// ---------------------------------------------------------------------------
struct UpstreamHttpClient::Transaction
    : public std::enable_shared_from_this<Transaction>,
      public UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseSink {

    UpstreamHttpClient::Request  req;
    UpstreamHttpClient::DoneCallback cb;
    std::shared_ptr<std::atomic<bool>> cancel_token;
    UpstreamManager* um = nullptr;
    Dispatcher* dispatcher = nullptr;
    size_t dispatcher_index = 0;
    std::string pool_name;

    UpstreamLease lease;
    UpstreamHttpCodec codec;

    bool finished = false;
    // When a sink is installed on UpstreamHttpCodec (as here, see
    // Issue()), the codec routes body bytes ONLY through OnBodyChunk and
    // stops appending to `codec.GetResponse().body`. So the transaction
    // is responsible for accumulating the body itself — OnComplete reads
    // from `body_data` below instead of the codec response. Size is
    // capped by req.max_response_body in OnBodyChunk.
    std::string body_data;
    UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead head;

    // Self-anchor: Issue() sets this to `shared_from_this()` before queueing
    // the start_task so the transaction survives the async dispatch window
    // (EnQueue on a non-local dispatcher drops the caller's local strong ref
    // as soon as Issue() returns). Finish() clears it on every terminal path
    // so the transaction destructs once pending callbacks drop their weaks.
    // See DEVELOPMENT_RULES.md ("Delayed-retry closures capture raw pointers
    // to object atomic members") for the class of bug this prevents.
    std::shared_ptr<Transaction> self_anchor;

    // Mark the lease's upstream connection as non-reusable so the pool
    // destroys rather than recycles it on Finish(). MUST be called BEFORE
    // Finish() at any terminal path where the HTTP stream cannot be
    // trusted for the next borrower: non-keepalive responses, parse/
    // protocol errors, response-budget timeouts, and body-cap overruns.
    // All four shapes leave either a FIN imminent, ambiguous parser
    // state, or a server still emitting bytes that would collide with
    // the next request/response stream on the same partition.
    void PoisonLease() {
        if (!lease) return;
        if (auto* upstream_conn = lease.Get()) {
            upstream_conn->MarkClosing();
        }
    }

    // Mark complete/error exactly once. On any terminal path (success,
    // error, timeout, cancel) release the lease, clear transport callbacks,
    // and invoke the user's DoneCallback. Running on the dispatcher thread
    // that owns this transaction — no mutex required for `finished`.
    void Finish(UpstreamHttpClient::Response response) {
        if (finished) return;
        finished = true;
        // Release the self-anchor AFTER marking finished. Any concurrent
        // callback that still holds a strong ref via the self_anchor copy
        // sees finished==true and bails; when the last such ref drops, the
        // transaction destructs cleanly.
        auto self_keepalive = std::move(self_anchor);

        // Clear any transport-level callbacks that would otherwise fire
        // on the now-torn-down transaction.
        if (lease) {
            if (auto* upstream_conn = lease.Get()) {
                if (auto transport = upstream_conn->GetTransport()) {
                    transport->SetOnMessageCb(nullptr);
                    transport->SetCompletionCb(nullptr);
                    // Clear the response-budget deadline + timeout
                    // callback we installed when the request was sent
                    // (see start_task's SetDeadline/SetDeadlineTimeoutCb
                    // path). PoolPartition::ReturnConnection rewires
                    // OnMessage/Completion but does NOT sweep deadline
                    // state, so leaving it here means the stale deadline
                    // can fire later on an unrelated borrower and close
                    // their healthy fetch as a spurious timeout. Clear
                    // symmetric with install; safe on a transport that
                    // never had one armed (no-op).
                    transport->ClearDeadline();
                    transport->SetDeadlineTimeoutCb(nullptr);
                    // Reset the transport's input cap — we installed a
                    // conservative cap when borrowing it and the pool's
                    // next borrower will re-apply their own.
                    transport->SetMaxInputSize(0);
                }
            }
            // Returning the lease recycles the upstream connection into
            // the pool (or the lease's destructor does it on scope exit).
            lease.Release();
        }

        auto user_cb = std::move(cb);
        cb = nullptr;
        if (user_cb) {
            try {
                user_cb(std::move(response));
            } catch (const std::exception& e) {
                logging::Get()->error(
                    "UpstreamHttpClient done-callback threw: {}", e.what());
            } catch (...) {
                logging::Get()->error(
                    "UpstreamHttpClient done-callback threw non-std exception");
            }
        }
    }

    bool IsCancelled() const {
        return cancel_token &&
               cancel_token->load(std::memory_order_acquire);
    }

    // --- UpstreamResponseSink -------------------------------------------
    bool OnHeaders(const UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead& h) override {
        head = h;
        body_data.clear();
        return true;
    }

    bool OnBodyChunk(const char* data, size_t len) override {
        if (finished) return false;
        const size_t new_total = body_data.size() + len;
        if (new_total > req.max_response_body) {
            logging::Get()->warn(
                "UpstreamHttpClient body too large pool={} accumulated={} "
                "cap={}", pool_name, new_total, req.max_response_body);
            // Partial read — tail bytes would corrupt the next borrower's
            // response stream. Poison before Finish() recycles the lease.
            PoisonLease();
            UpstreamHttpClient::Response r;
            r.error = "body_too_large";
            Finish(std::move(r));
            return false;
        }
        body_data.append(data, len);
        return true;
    }

    void OnTrailers(
        const std::vector<std::pair<std::string, std::string>>& /*trailers*/) override {
        // Trailers are not consumed for JWKS / discovery / introspection
        // responses; ignore.
    }

    void OnComplete() override {
        if (finished) return;
        UpstreamHttpClient::Response resp;
        resp.status_code = codec.GetResponse().status_code;
        resp.headers = codec.GetResponse().headers;
        // Body accumulated by OnBodyChunk — the codec does NOT append
        // to its own body buffer when a sink is installed (see
        // server/upstream_http_codec.cc::on_body). Move into the
        // response to avoid a copy.
        resp.body = std::move(body_data);
        // Non-keepalive responses (Connection: close, HTTP/1.0 without
        // explicit keep-alive, etc.) have a peer FIN imminent. The pool
        // can hand the socket to the next waiter before the FIN lands,
        // so the next JWKS/OIDC request would see upstream_disconnect
        // on an otherwise healthy IdP. Matches ProxyTransaction's
        // `poison_connection_ = true` on `!head.keep_alive`.
        if (!head.keep_alive) {
            PoisonLease();
        }
        Finish(std::move(resp));
    }

    void OnError(int error_code, const std::string& message) override {
        if (finished) return;
        UpstreamHttpClient::Response r;
        r.error = message.empty() ? std::string("parse_error") : message;
        logging::Get()->warn(
            "UpstreamHttpClient OnError pool={} code={} err={}",
            pool_name, error_code, r.error);
        // Parse/protocol errors leave the HTTP stream in an ambiguous
        // state — recycling the socket would risk interpreting trailing
        // bytes as the next borrower's response.
        PoisonLease();
        Finish(std::move(r));
    }
};

UpstreamHttpClient::UpstreamHttpClient(
        UpstreamManager* upstream_manager,
        std::vector<std::shared_ptr<Dispatcher>> dispatchers)
    : upstream_manager_(upstream_manager),
      dispatchers_(std::move(dispatchers)) {
    logging::Get()->debug(
        "UpstreamHttpClient created um={} dispatchers={}",
        static_cast<const void*>(upstream_manager_),
        dispatchers_.size());
}

UpstreamHttpClient::~UpstreamHttpClient() = default;

void UpstreamHttpClient::Issue(const std::string& upstream_pool_name,
                                size_t dispatcher_index,
                                Request req,
                                DoneCallback cb,
                                std::shared_ptr<std::atomic<bool>> cancel_token) {
    auto deliver_error = [](DoneCallback& user_cb, std::string err) {
        Response r;
        r.error = std::move(err);
        if (user_cb) user_cb(std::move(r));
    };

    if (!upstream_manager_) {
        logging::Get()->error(
            "UpstreamHttpClient::Issue with no UpstreamManager pool={}",
            upstream_pool_name);
        deliver_error(cb, "no_upstream_manager");
        return;
    }
    if (!upstream_manager_->HasUpstream(upstream_pool_name)) {
        logging::Get()->warn(
            "UpstreamHttpClient pool unknown: {}", upstream_pool_name);
        deliver_error(cb, "pool_unknown");
        return;
    }
    if (dispatcher_index >= dispatchers_.size()) {
        logging::Get()->error(
            "UpstreamHttpClient dispatcher_index out of range: idx={} size={}",
            dispatcher_index, dispatchers_.size());
        deliver_error(cb, "dispatcher_out_of_range");
        return;
    }

    auto txn = std::make_shared<Transaction>();
    txn->req = std::move(req);
    txn->cb = std::move(cb);
    txn->cancel_token = std::move(cancel_token);
    txn->um = upstream_manager_;
    txn->dispatcher = dispatchers_[dispatcher_index].get();
    txn->dispatcher_index = dispatcher_index;
    txn->pool_name = upstream_pool_name;
    txn->codec.SetRequestMethod(txn->req.method);
    txn->codec.SetSink(txn.get());

    // Kick off on the target dispatcher. If we are already on that
    // dispatcher (typical path — caller explicitly passed their own
    // dispatcher_index), the lambda runs inline after EnQueue; otherwise
    // the dispatcher picks it up on the next loop iteration.
    auto weak_txn = std::weak_ptr<Transaction>(txn);
    auto um = upstream_manager_;
    auto start_task = [weak_txn, um]() {
        auto t = weak_txn.lock();
        if (!t) return;
        if (t->IsCancelled()) {
            logging::Get()->debug(
                "UpstreamHttpClient start cancelled pool={}", t->pool_name);
            UpstreamHttpClient::Response r;
            r.error = "cancelled";
            t->Finish(std::move(r));
            return;
        }

        auto weak2 = std::weak_ptr<Transaction>(t);
        um->CheckoutAsync(
            t->pool_name,
            t->dispatcher_index,
            // ready_cb
            [weak2](UpstreamLease lease) {
                auto t2 = weak2.lock();
                if (!t2) return;
                if (t2->finished) return;
                if (t2->IsCancelled()) {
                    logging::Get()->debug(
                        "UpstreamHttpClient checkout cancelled pool={}",
                        t2->pool_name);
                    lease.Release();
                    UpstreamHttpClient::Response r;
                    r.error = "cancelled";
                    t2->Finish(std::move(r));
                    return;
                }
                t2->lease = std::move(lease);
                auto* upstream_conn = t2->lease.Get();
                if (!upstream_conn) {
                    logging::Get()->error(
                        "UpstreamHttpClient checkout returned empty lease "
                        "pool={}",
                        t2->pool_name);
                    UpstreamHttpClient::Response r;
                    r.error = "checkout_empty_lease";
                    t2->Finish(std::move(r));
                    return;
                }
                auto transport = upstream_conn->GetTransport();
                if (!transport) {
                    logging::Get()->error(
                        "UpstreamHttpClient checkout returned lease with no "
                        "transport pool={}",
                        t2->pool_name);
                    UpstreamHttpClient::Response r;
                    r.error = "checkout_missing_transport";
                    t2->Finish(std::move(r));
                    return;
                }

                // Bound incoming response bytes to the caller's cap. The
                // codec drops bytes past the cap via OnBodyChunk's
                // enforcement, but the transport cap also prevents raw
                // runaway accumulation under ET mode.
                transport->SetMaxInputSize(t2->req.max_response_body);

                transport->SetOnMessageCb(
                    [weak2](std::shared_ptr<ConnectionHandler> /*conn*/,
                             std::string& data) {
                        auto t3 = weak2.lock();
                        if (!t3 || t3->finished) return;
                        if (data.empty()) {
                            // Empty data signals upstream EOF / disconnect
                            // delivered by PoolPartition's on-close hook.
                            // Drive codec to a terminal state: for close-
                            // delimited responses codec.Finish() fires
                            // OnComplete (which in turn calls Finish(resp)
                            // with the accumulated body). If the response is
                            // incomplete (truncated Content-Length, mid-
                            // chunked) Finish returns false and we surface
                            // upstream_disconnect so the done-callback fires
                            // instead of hanging forever. Same pattern as
                            // ProxyTransaction's upstream-close path.
                            bool complete = t3->codec.Finish();
                            if (t3->finished) return;  // OnComplete already ran
                            UpstreamHttpClient::Response r;
                            logging::Get()->warn(
                                "UpstreamHttpClient upstream disconnect "
                                "pool={} body_complete={} has_error={}",
                                t3->pool_name, complete, t3->codec.HasError());
                            r.error = "upstream_disconnect";
                            t3->Finish(std::move(r));
                            return;
                        }
                        size_t consumed = t3->codec.Parse(
                            data.data(), data.size());
                        if (t3->codec.HasError() && !t3->finished) {
                            logging::Get()->warn(
                                "UpstreamHttpClient response parse_error "
                                "pool={}",
                                t3->pool_name);
                            UpstreamHttpClient::Response r;
                            r.error = "parse_error";
                            // Parse failure leaves the HTTP stream in an
                            // ambiguous state — untrusted tail bytes
                            // would be misread as the next borrower's
                            // response. Same contract as the timeout /
                            // OnError paths.
                            t3->PoisonLease();
                            t3->Finish(std::move(r));
                            return;
                        }
                        // Strip consumed bytes from the transport buffer.
                        if (consumed > 0 && consumed <= data.size()) {
                            data.erase(0, consumed);
                        }
                    });
                transport->SetCompletionCb(
                    [weak2](std::shared_ptr<ConnectionHandler> /*conn*/) {
                        // Write-complete for the request — nothing to do;
                        // wait for the response data callback.
                        auto t3 = weak2.lock();
                        if (!t3) return;
                    });

                // Build and ship the HTTP/1.1 request. We rely on the
                // caller's host_header — if empty, fall back to the
                // pool name so the upstream sees a plausible Host.
                //
                // Connection header is NOT auto-injected: HTTP/1.1's
                // default is persistent, and UpstreamManager's pool is
                // the whole point of this client. Forcing `Connection:
                // close` on every JWKS / OIDC / introspection fetch
                // would add a full TCP+TLS handshake per refresh and
                // defeat pooling against a single IdP. Callers that
                // genuinely need one-shot semantics can set
                // `connection: close` in `req.headers` themselves;
                // absence means "let the pool reuse this socket."
                std::map<std::string, std::string> headers = t2->req.headers;
                if (headers.find("host") == headers.end()) {
                    headers["host"] = t2->req.host_header.empty()
                        ? t2->pool_name
                        : t2->req.host_header;
                }
                std::string wire = HttpRequestSerializer::Serialize(
                    t2->req.method, t2->req.path, t2->req.query,
                    headers, t2->req.body);

                // Install a response-budget deadline on the transport so
                // a hung upstream unblocks the client. The deadline is
                // cleared on Finish() via the lease's transport callback
                // clearing; a firing deadline triggers the transport's
                // own close path which the codec treats as EOF.
                if (t2->req.timeout_sec > 0) {
                    transport->SetDeadline(
                        std::chrono::steady_clock::now() +
                        std::chrono::seconds(t2->req.timeout_sec));
                    transport->SetDeadlineTimeoutCb([weak2]() -> bool {
                        auto t3 = weak2.lock();
                        // No transaction left (already dropped) — let the
                        // connection close via the default path.
                        if (!t3) return false;
                        // Transaction already terminated through another
                        // path (response complete, cancel, etc.) — same.
                        if (t3->finished) return false;
                        logging::Get()->warn(
                            "UpstreamHttpClient response timeout pool={} "
                            "timeout_sec={}",
                            t3->pool_name, t3->req.timeout_sec);
                        UpstreamHttpClient::Response r;
                        r.error = "timeout";
                        // Poison BEFORE Finish() releases the lease. The
                        // upstream may still send late response bytes; if
                        // the pool recycled this transport to another
                        // auth fetch first, those bytes would be
                        // interpreted as the next request's response.
                        // MarkClosing ensures the pool destroys the
                        // connection on return instead.
                        t3->PoisonLease();
                        t3->Finish(std::move(r));
                        // Return true to signal the timeout is handled —
                        // otherwise the dispatcher's default close path
                        // (CloseAfterWrite on the same ConnectionHandler)
                        // would tear down the next borrower's in-flight
                        // request. Matches ProxyTransaction::ArmResponseTimeout.
                        return true;
                    });
                }

                transport->SendRaw(wire.data(), wire.size());
            },
            // error_cb
            [weak2](int err_code) {
                auto t2 = weak2.lock();
                if (!t2 || t2->finished) return;
                const char* label = CheckoutErrorLabel(err_code);
                logging::Get()->warn(
                    "UpstreamHttpClient checkout failed pool={} reason={} "
                    "code={}",
                    t2->pool_name, label, err_code);
                UpstreamHttpClient::Response r;
                r.error = label;
                t2->Finish(std::move(r));
            },
            // Pass the transaction's cancel_token through to the pool so
            // a CancelInflight() / OidcDiscovery::Cancel() while the
            // request is queued for a saturated IdP pool removes the dead
            // waiter from the bounded wait queue. Hardcoding nullptr here
            // would leave cancelled waiters consuming queue slots until
            // they hit queue_timeout, which can block later live refreshes.
            t->cancel_token);
    };

    // Install the self-anchor BEFORE any async hand-off. The start_task
    // itself captures weak_txn (to allow cancellation without pinning the
    // transaction if Cancel races), but the caller's local `txn` drops on
    // return — without the anchor a cross-dispatcher EnQueue would lose the
    // transaction before start_task runs. Finish() clears the anchor.
    txn->self_anchor = txn;

    if (txn->dispatcher && txn->dispatcher->is_on_loop_thread()) {
        start_task();
    } else if (txn->dispatcher) {
        txn->dispatcher->EnQueue(std::move(start_task));
    } else {
        // No dispatcher resolved — shouldn't happen because we bounds-
        // checked above, but be defensive.
        logging::Get()->error(
            "UpstreamHttpClient: no dispatcher for index={} pool={}",
            dispatcher_index, upstream_pool_name);
        UpstreamHttpClient::Response r;
        r.error = "no_dispatcher";
        txn->Finish(std::move(r));
    }
}

}  // namespace AUTH_NAMESPACE
