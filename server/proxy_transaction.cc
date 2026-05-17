#include "upstream/proxy_transaction.h"
#include "upstream/upstream_manager.h"
#include "upstream/upstream_connection.h"
#include "upstream/http_request_serializer.h"
#include "auth/auth_manager.h"
#include "circuit_breaker/circuit_breaker_manager.h"
#include "circuit_breaker/circuit_breaker_host.h"
#include "circuit_breaker/circuit_breaker_slice.h"
#include "connection_handler.h"
#include "dispatcher.h"
#include "net/dns_resolver.h"  // FormatAuthority for IPv6 host:port rendering
// config/server_config.h provided by proxy_transaction.h (ProxyConfig stored by value)
#include "http/http_request.h"
#include "http/http_status.h"
#include "http/trailer_policy.h"
#include "http/http2_trailer_sanitizer.h"
#include "log/logger.h"
#include "observability/observability_snapshot.h"
#include "observability/observability_manager.h"
#include "observability/span.h"
#include "observability/span_status.h"
#include "observability/attr_value.h"
#include "observability/counter.h"
#include "observability/histogram.h"
#include "observability/metrics_catalog.h"
#include "observability/propagator.h"
#include "observability/tracer_provider.h"
#include "observability/tracer.h"
#include <unordered_set>

namespace {

std::string LowerCopy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return value;
}

std::optional<std::string> FirstHeaderValue(
    const std::vector<std::pair<std::string, std::string>>& headers,
    const std::string& name_lower) {
    for (const auto& [key, value] : headers) {
        if (LowerCopy(key) == name_lower) return value;
    }
    return std::nullopt;
}

bool HeaderValueStartsWith(
    const std::vector<std::pair<std::string, std::string>>& headers,
    const std::string& name_lower,
    const std::string& prefix_lower) {
    for (const auto& [key, value] : headers) {
        if (LowerCopy(key) != name_lower) continue;
        std::string lower_value = LowerCopy(value);
        return lower_value.rfind(prefix_lower, 0) == 0;
    }
    return false;
}

std::optional<std::string> MergeTrailerDeclarations(
    const std::vector<std::pair<std::string, std::string>>& headers) {
    std::vector<std::string> allowed;
    for (const auto& [key, value] : headers) {
        if (LowerCopy(key) != "trailer") {
            continue;
        }
        size_t start = 0;
        while (start <= value.size()) {
            size_t comma = value.find(',', start);
            std::string token = TrimOptionalWhitespace(
                value.substr(start, comma == std::string::npos
                                        ? std::string::npos
                                        : comma - start));
            if (!token.empty() &&
                !IsForbiddenTrailerFieldName(LowerCopy(token))) {
                allowed.push_back(std::move(token));
            }
            if (comma == std::string::npos) {
                break;
            }
            start = comma + 1;
        }
    }
    if (allowed.empty()) {
        return std::nullopt;
    }
    std::string joined = allowed.front();
    for (size_t i = 1; i < allowed.size(); ++i) {
        joined += ", ";
        joined += allowed[i];
    }
    return joined;
}

std::unordered_set<std::string> CollectDeclaredTrailerNames(
    const std::vector<std::pair<std::string, std::string>>& headers) {
    std::unordered_set<std::string> allowed;
    for (const auto& [key, value] : headers) {
        if (LowerCopy(key) != "trailer") {
            continue;
        }
        size_t start = 0;
        while (start <= value.size()) {
            size_t comma = value.find(',', start);
            std::string token = TrimOptionalWhitespace(
                value.substr(start, comma == std::string::npos
                                        ? std::string::npos
                                        : comma - start));
            std::string lower = LowerCopy(token);
            if (!lower.empty() && !IsForbiddenTrailerFieldName(lower)) {
                allowed.insert(std::move(lower));
            }
            if (comma == std::string::npos) {
                break;
            }
            start = comma + 1;
        }
    }
    return allowed;
}

bool ShouldPreserveKnownContentLength(
    const std::string& method,
    const UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead& head,
    bool include_body) {
    if (method == "HEAD") {
        return true;
    }
    return head.framing ==
               UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead::Framing::
                   CONTENT_LENGTH &&
           !include_body &&
           head.expected_length >= 0;
}

struct Retryable5xxBodySnapshot {
    std::string body;
    bool complete = false;
};

Retryable5xxBodySnapshot SnapshotRetryable5xxBody(
    const UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead& head,
    const std::string& decoded_body,
    const std::string& paused_wire_body) {
    Retryable5xxBodySnapshot snapshot;
    snapshot.body = decoded_body;

    using Framing = UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead::Framing;
    switch (head.framing) {
        case Framing::CONTENT_LENGTH:
            snapshot.body.append(paused_wire_body);
            if (head.expected_length >= 0 &&
                snapshot.body.size() > static_cast<size_t>(head.expected_length)) {
                snapshot.body.resize(static_cast<size_t>(head.expected_length));
            }
            if (head.expected_length >= 0) {
                snapshot.complete =
                    snapshot.body.size() ==
                    static_cast<size_t>(head.expected_length);
            }
            break;
        case Framing::EOF_TERMINATED:
            snapshot.body.append(paused_wire_body);
            break;
        case Framing::CHUNKED: {
            size_t pos = 0;
            while (pos < paused_wire_body.size()) {
                size_t line_end = paused_wire_body.find("\r\n", pos);
                if (line_end == std::string::npos) {
                    break;
                }

                std::string size_line =
                    paused_wire_body.substr(pos, line_end - pos);
                size_t chunk_size = 0;
                if (std::sscanf(size_line.c_str(), "%zx", &chunk_size) != 1) {
                    break;
                }

                pos = line_end + 2;
                if (chunk_size == 0) {
                    snapshot.complete = true;
                    break;
                }
                if (paused_wire_body.size() - pos < chunk_size + 2) {
                    break;
                }
                snapshot.body.append(paused_wire_body.data() + pos, chunk_size);
                pos += chunk_size;
                if (paused_wire_body.compare(pos, 2, "\r\n") != 0) {
                    break;
                }
                pos += 2;
            }
            break;
        }
        case Framing::NO_BODY:
            snapshot.complete = true;
            break;
    }
    return snapshot;
}

// Convert chunk size to hex string for chunked transfer framing.
std::string HexSize_(size_t n) {
    char buf[32];
    int len = std::snprintf(buf, sizeof(buf), "%zx", n);
    return std::string(buf, static_cast<size_t>(len > 0 ? len : 0));
}

}  // namespace

// Public + static so test code can verify the contract. See header
// for full docstring.
bool ProxyTransaction::ContainsTeTrailersToken(const std::string& value) {
    std::string buf;
    buf.reserve(value.size());
    for (char c : value) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c | 0x20);
        buf.push_back(c);
    }
    size_t pos = 0;
    while (pos < buf.size()) {
        const size_t comma = buf.find(',', pos);
        const size_t entry_end = (comma == std::string::npos) ? buf.size() : comma;
        // Within an entry, the bare token name ends at the first ';'
        // (start of parameters per ABNF: `t-codings = "trailers" /
        // ( transfer-coding [ t-ranking ] )`).
        const size_t semi = buf.find(';', pos);
        const size_t token_end_raw = (semi == std::string::npos || semi > entry_end)
                                   ? entry_end : semi;
        size_t token_start = pos;
        size_t token_end = token_end_raw;
        while (token_start < token_end &&
               (buf[token_start] == ' ' || buf[token_start] == '\t')) {
            ++token_start;
        }
        while (token_end > token_start &&
               (buf[token_end - 1] == ' ' || buf[token_end - 1] == '\t')) {
            --token_end;
        }
        if (buf.compare(token_start, token_end - token_start, "trailers") == 0) {
            return true;
        }
        pos = (comma == std::string::npos) ? buf.size() : comma + 1;
    }
    return false;
}

ProxyTransaction::ProxyTransaction(
    const std::string& service_name,
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
    AUTH_NAMESPACE::AuthManager* auth_manager)
    : service_name_(service_name),
      method_(client_request.method),
      path_(client_request.path),
      query_(client_request.query),
      client_http_major_(client_request.http_major),
      client_http_minor_(client_request.http_minor),
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
      // Copy the AuthContext by value — HttpRequest is invalidated after
      // the async handler returns (parser_.Reset()). The overlay at
      // outbound-hop time must consult the validated identity captured
      // here, not a dangling reference.
      auth_ctx_(client_request.auth),
      // Same lifetime contract as auth_ctx_: copy the inbound trace
      // context so per-attempt outbound traceparent injection has a
      // stable source through every retry. Empty when observability is
      // disabled or the inbound had no trace context.
      inbound_trace_ctx_(client_request.trace_ctx),
      upstream_manager_(upstream_manager),
      auth_manager_(auth_manager),
      dispatcher_(upstream_manager && client_request.dispatcher_index >= 0
                  ? upstream_manager->GetDispatcherForIndex(
                        static_cast<size_t>(client_request.dispatcher_index))
                  : nullptr),
      config_(config),
      header_rewriter_(header_rewriter),
      retry_policy_(retry_policy),
      complete_cb_(std::move(complete_cb)),
      codec_(std::make_unique<UpstreamHttpCodec>()),
      start_time_(std::chrono::steady_clock::now()),
      stream_sender_(std::move(stream_sender))
{
    stream_sender_.ConfigureWatermarks(config_.relay_buffer_limit_bytes);

    // Capture client `te: trailers` BEFORE HeaderRewriter::RewriteRequest
    // strips all te values per RFC 7230 §4.3 hop-by-hop rules. gRPC clients
    // send `te: trailers` to negotiate trailer support; the H2 outbound nv
    // build re-emits the token from this flag (RFC 9113 §8.2.2). The
    // helper handles `te: trailers`, case variants, and `te: trailers;q=...`
    // weight parameters. client_headers_ keys are guaranteed lowercase by
    // HttpParser.
    if (auto te_it = client_headers_.find("te"); te_it != client_headers_.end()) {
        client_te_trailers_ = ProxyTransaction::ContainsTeTrailersToken(te_it->second);
    }

    // Capture streaming body source before the request is invalidated.
    // is_streaming_request_ governs H1/H2 send-path branching; body_stream_
    // holds the live producer for the send phase.
    if (client_request.body_stream) {
        is_streaming_request_ = true;
        body_stream_ = client_request.body_stream;
    }

    logging::Get()->debug("ProxyTransaction created client_fd={} service={} "
                          "{} {}", client_fd_, service_name_, method_, path_);
}

ProxyTransaction::~ProxyTransaction() {
    // Safety net: ensure cleanup runs even if DeliverResponse was never called
    // (e.g., transaction was abandoned due to client disconnect).
    Cleanup();

    // Pair the Start()-time IncInflightTransactions; the latch covers
    // the case where the transaction was constructed but never Start()ed.
    // Atomic exchange handles the cross-thread case (dtor may run on a
    // retry-timer / upstream-callback / shutdown-sweep thread) and
    // returns the previous value so we Dec exactly once.
    if (upstream_manager_ &&
        inflight_counter_held_.exchange(false, std::memory_order_acq_rel)) {
        upstream_manager_->DecInflightTransactions();
    }

    if (!complete_cb_invoked_.load(std::memory_order_acquire) && complete_cb_) {
        logging::Get()->warn("ProxyTransaction destroyed without delivering "
                             "response client_fd={} service={} state={}",
                             client_fd_, service_name_,
                             static_cast<int>(state_));
    }
}

void ProxyTransaction::AttachObservabilitySnapshot(
        std::shared_ptr<OBSERVABILITY_NAMESPACE::ObservabilitySnapshot> snap) {
    obs_snapshot_ = std::move(snap);
}

OBSERVABILITY_NAMESPACE::ObservabilityManager*
ProxyTransaction::obs_manager() const noexcept {
    if (!obs_snapshot_) return nullptr;
    if (auto m = obs_snapshot_->manager.lock()) return m.get();
    return nullptr;
}

OBSERVABILITY_NAMESPACE::Span*
ProxyTransaction::inbound_span() const noexcept {
    return obs_snapshot_ ? obs_snapshot_->inbound_span.get() : nullptr;
}

void ProxyTransaction::RebuildOutboundTraceHeaders() {
    if (!current_attempt_.attempt_local.IsValid()) return;
    auto* mgr = obs_manager();
    if (!mgr) return;
    auto p = mgr->propagator();
    if (!p) {
        // Reachable during init/SIGHUP races between manager.Init() and
        // first config commit, or if the operator removed every
        // propagator from `observability.traces.propagators`. Strip
        // still runs in the caller (Propagator::StripAllKnownTrace-
        // Headers); we just can't inject a fresh traceparent.
        logging::Get()->debug(
            "RebuildOutboundTraceHeaders: live propagator null; outbound "
            "request will carry no traceparent for service={} attempt={}",
            service_name_, attempt_);
        return;
    }
    // Strip the UNION of every shipped format, not just the configured
    // live propagator's owned set — a client-forged `uber-trace-id`
    // must not slip through when only W3C is configured. See
    // .claude/rules/pitfalls/OBSERVABILITY.md "strip union" rule.
    OBSERVABILITY_NAMESPACE::Propagator::StripAllKnownTraceHeaders(
        rewritten_headers_);
    p->Inject(current_attempt_.attempt_local, rewritten_headers_);
    // Force the H1 send path to re-serialize with the fresh trace
    // headers — `serialized_request_` is built lazily on first send.
    serialized_request_.clear();
}

namespace {
// Map an internal RESULT_* code to the OTel `error.type` string used on
// the CLIENT span. Closed enum (no operator-supplied free-text) so the
// metric label cardinality stays bounded.
const char* ErrorTypeForResult(int result_code) {
    switch (result_code) {
        case ProxyTransaction::RESULT_CHECKOUT_FAILED:        return "connect_failure";
        case ProxyTransaction::RESULT_SEND_FAILED:            return "send_failed";
        case ProxyTransaction::RESULT_PARSE_ERROR:            return "parse_error";
        case ProxyTransaction::RESULT_RESPONSE_TIMEOUT:       return "timeout";
        case ProxyTransaction::RESULT_UPSTREAM_DISCONNECT:    return "upstream_disconnect";
        case ProxyTransaction::RESULT_POOL_EXHAUSTED:         return "pool_exhausted";
        case ProxyTransaction::RESULT_RESPONSE_TOO_LARGE:     return "response_too_large";
        case ProxyTransaction::RESULT_CIRCUIT_OPEN:           return "circuit_open";
        case ProxyTransaction::RESULT_RETRY_BUDGET_EXHAUSTED: return "retry_budget_exhausted";
        default:                                              return "upstream_error";
    }
}
}  // namespace

void ProxyTransaction::FinalizeAttemptSpan(int status_code,
                                            const std::string& error_type) {
    // Emit `http.client.request.duration` histogram once per attempt
    // at the terminal site, BEFORE the span-finalize early returns.
    // The histogram is independent of trace sampling — every attempt
    // that started gets a duration record. attempt_start_steady_ is
    // zero-sentinel when obs is disabled, so the inner emit gates
    // naturally. Reset the sentinel after emit so a second call from
    // Cleanup's dtor backstop (which runs AFTER OnResponseComplete on
    // the success path) doesn't double-record.
    if (attempt_start_steady_ != std::chrono::steady_clock::time_point{} 
        && !IsKilledForShutdown()) {
        auto* mgr = obs_manager();
        if (mgr) {
            const auto& cat = mgr->catalog();
            if (cat.http_client_request_duration != nullptr) {
                auto elapsed = std::chrono::duration<double>(
                    std::chrono::steady_clock::now() -
                    attempt_start_steady_).count();
                std::vector<std::pair<std::string, std::string>> labels;
                labels.reserve(6);
                if (!method_.empty()) {
                    labels.emplace_back("http.request.method", method_);
                }
                labels.emplace_back("server.address", upstream_host_);
                labels.emplace_back("server.port",
                                     std::to_string(upstream_port_));
                if (status_code > 0) {
                    labels.emplace_back("http.response.status_code",
                                         std::to_string(status_code));
                }
                if (!error_type.empty()) {
                    labels.emplace_back("error.type", error_type);
                }
                labels.emplace_back("reactor.upstream.service",
                                     service_name_);
                cat.http_client_request_duration->Record(elapsed, labels);
            }
            // Matching -1 for the +1 from SetupAttemptObservability.
            // Gated on TryDecrementIfPositive winning the CAS so the
            // kill-loop / dtor backstop and this natural finalize
            // racer cannot both emit a -1 for the same attempt.
            if (cat.http_client_active_requests != nullptr &&
                obs_snapshot_ != nullptr &&
                OBSERVABILITY_NAMESPACE::TryDecrementIfPositive(
                    obs_snapshot_->attempt_active_inflight_)) {
                cat.http_client_active_requests->Add(
                    -1.0,
                    {{"reactor.upstream.service", service_name_}});
            }
        }
        attempt_start_steady_ = std::chrono::steady_clock::time_point{};
    }
    if (!current_attempt_.upstream_span) return;
    // Kill loop already invalidated the span — drop without End() so we
    // don't double-finalize after KillOutstandingSnapshots ran.
    if (IsKilledForShutdown()) {
        current_attempt_.upstream_span->DropWithoutEnd();
        current_attempt_.upstream_span.reset();
        return;
    }
    // Defensive: an End() with neither status_code nor error_type leaves
    // the CLIENT span semantically empty — usually a caller bug (forgot
    // to map a new RESULT_* code, or hit a code path that didn't
    // populate either). Log loudly so the regression surfaces; we still
    // End() the span below so it doesn't leak. trace_id is included so
    // operators can pivot from the warn to the collector record.
    if (status_code <= 0 && error_type.empty()) {
        logging::Get()->warn(
            "FinalizeAttemptSpan: span ended with no status_code AND no "
            "error_type — caller forgot a RESULT_* mapping. service={} "
            "attempt={} trace_id={}",
            service_name_, attempt_,
            current_attempt_.attempt_local.trace_id().ToHex());
    }
    auto& span = current_attempt_.upstream_span;
    if (status_code > 0) {
        span->SetAttribute(
            "http.response.status_code",
            OBSERVABILITY_NAMESPACE::AttrValue(static_cast<int64_t>(status_code)));
        if (status_code >= 400) {
            span->SetStatus(OBSERVABILITY_NAMESPACE::SpanStatusCode::ERROR,
                             std::to_string(status_code));
            span->SetAttribute(
                "error.type",
                OBSERVABILITY_NAMESPACE::AttrValue(std::to_string(status_code)));
        }
    }
    if (!error_type.empty()) {
        span->SetStatus(OBSERVABILITY_NAMESPACE::SpanStatusCode::ERROR,
                         error_type);
        span->SetAttribute(
            "error.type",
            OBSERVABILITY_NAMESPACE::AttrValue(error_type));
    }
    span->End();
    current_attempt_.upstream_span.reset();
}

void ProxyTransaction::SetProtocolVersionOnAttemptSpan(const char* version) {
    if (!current_attempt_.upstream_span || version == nullptr) return;
    current_attempt_.upstream_span->SetAttribute(
        "network.protocol.version",
        OBSERVABILITY_NAMESPACE::AttrValue(std::string(version)));
}

void ProxyTransaction::Start() {
    // Bump exactly once per transaction; the destructor's matching
    // decrement is gated on the same latch. exchange returns the
    // PREVIOUS value, so the !old-value branch fires exactly once
    // even under repeat Start() calls.
    if (upstream_manager_ &&
        !inflight_counter_held_.exchange(true, std::memory_order_acq_rel)) {
        upstream_manager_->IncInflightTransactions();
    }

    // Publish ourselves to the snapshot so the shutdown kill loop can
    // mark us via MarkKilledForShutdown on its terminal sweep.
    //
    // Delegate to ObservabilitySnapshot::AttachTransaction — it owns
    // the canonical link/kill protocol: lock link_mtx, read finalized
    // under the lock, capture the strong ptr if already finalized,
    // publish tx_weak, release the lock, then call
    // MarkKilledForShutdown OUTSIDE the lock.
    //
    // Returns true when the snapshot had already been finalized (kill
    // sweep ran first). In that case the helper has already called
    // MarkKilledForShutdown — which Cancelled us inline because
    // Start() runs on the owning dispatcher — so the rest of Start()
    // would only allocate header-rewrite / request-serialize / slice
    // resolution work that AttemptCheckout's cancelled_ check would
    // immediately discard. Returning here makes the kill barrier
    // explicit so future code added between attach and checkout
    // doesn't silently bypass it. The IncInflightTransactions above
    // is paired by the destructor's gated decrement on
    // inflight_counter_held_, so the early return preserves the
    // counter contract.
    if (obs_snapshot_) {
        if (obs_snapshot_->AttachTransaction(
                std::weak_ptr<OBSERVABILITY_NAMESPACE::UpstreamTransactionLink>(
                    shared_from_this()))) {
            return;
        }
    }

    // Tell the codec the request method so it handles HEAD correctly
    // (no body despite Content-Length/Transfer-Encoding in response).
    codec_->SetRequestMethod(method_);
    codec_->SetSink(this);
    relay_mode_ = RelayMode::BUFFERED;
    response_headers_seen_ = false;
    response_committed_ = false;
    body_complete_ = false;
    retry_from_headers_pending_ = false;
    response_head_ = {};
    response_trailers_.clear();
    response_body_.clear();
    paused_parse_bytes_.clear();
    InvalidateStreamTimers();
    sse_stream_ = false;
    ClearPendingRetryable5xxResponse();

    // Take a stack-local ForwardConfig() snapshot, but ONLY when
    // enforcement is live. The IsEnforcing() gate is at the CALLER:
    // `ForwardConfig()` returns the stored snapshot unconditionally
    // even when IsEnforcing()=false
    // (AuthManager may exist in a "disabled but constructed" state so
    // SIGHUP can flip `auth.enabled: false → true` without a restart).
    // Unconditional snapshotting would let a staged
    // `forward.preserve_authorization=false` strip `Authorization`,
    // or let any identity-inject / undetermined-header-strip fire on
    // proxy hops whose auth is OFF — leaking overlay semantics onto
    // routes the operator has not yet opted into. The `shared_ptr`
    // keeps the snapshot alive for the duration of RewriteRequest even
    // if a concurrent Reload swaps the AuthManager's internal pointer.
    std::shared_ptr<const AUTH_NAMESPACE::AuthForwardConfig> fwd_snap;
    if (auth_manager_ && auth_manager_->IsEnforcing()) {
        fwd_snap = auth_manager_->ForwardConfig();
    }

    // Compute rewritten headers (strip hop-by-hop, add X-Forwarded-For, etc.,
    // apply auth overlay when AuthManager + AuthContext are present).
    rewritten_headers_ = header_rewriter_.RewriteRequest(
        client_headers_, client_ip_, client_tls_,
        upstream_tls_,
        upstream_host_, upstream_port_, sni_hostname_,
        fwd_snap ? fwd_snap.get() : nullptr,
        &auth_ctx_);

    // Outbound trace context. Two regimes coexist:
    //
    //   (1) Observability ENABLED + inbound carries a recording
    //       trace context: AttemptCheckout's RebuildOutboundTraceHeaders
    //       strip-and-replaces traceparent/tracestate with the per-
    //       attempt CLIENT span's identity (fresh span_id per retry,
    //       trace_id inherited). Downstream services see the gateway
    //       CLIENT span as parent — the trace tree continues through us.
    //   (2) Observability DISABLED, or inbound has no trace context:
    //       The client's traceparent/tracestate forward VERBATIM.
    //       Stripping without replacement would break transparent W3C
    //       propagation; injecting a fresh context without emitting a
    //       CLIENT span would leave downstream services with a parent
    //       span_id the gateway never reports.
    //
    // Threat note for operators (applies to regime (2)): a malicious
    // client can populate arbitrary trace_id / span_id / trace-flags
    // in traceparent and arbitrary key=value entries in tracestate,
    // and the verbatim forward replays them to every upstream behind
    // the gateway. Operators MUST NOT trust upstream trace_ids for
    // log correlation across a security boundary — a same-trace_id
    // observation only proves the client claimed it, not that the
    // request originated from a peer in the same trust domain. Auth-
    // path requests bound for an IdP go through
    // UpstreamHttpClient::ApplyOutboundTraceContext, which strips the
    // inbound headers and re-injects from the auth-built IssueTraceContext
    // — that path is the secure default for IdP hops regardless of
    // regime.

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

    // Cache for retry and for the H2 dispatch path's :path pseudo-header.
    upstream_path_ = upstream_path;

    // Note: serialized_request_ is built lazily on the first H1 send so
    // the H2 dispatch path doesn't pay the cost of a second copy of the
    // request body (which is also held in request_body_ for retry replay
    // and in the H2 stream's body_source).

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

bool ProxyTransaction::PrepareAttemptAdmission() {
    // Circuit breaker gate — consulted before every attempt (first try and
    // retries both). Each attempt gets a fresh admission stamped with the
    // slice's current generation. If the slice rejects with REJECTED_OPEN,
    // ConsultBreaker delivers the circuit-open 503 response and returns
    // false; the retry loop treats RESULT_CIRCUIT_OPEN as terminal so a
    // rejected retry produces a single 503 to the client, not a nested retry.
    // Dry-run reject logs inside TryAcquire and returns ADMITTED through
    // the decision enum (REJECTED_OPEN_DRYRUN), so ConsultBreaker proceeds.
    if (!ConsultBreaker()) {
        return false;
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
            if (ResumeHeldRetryable5xxResponse("retry_budget_exhausted")) {
                return false;
            }
            if (DeliverPendingRetryable5xxResponse("retry_budget_exhausted")) {
                return false;
            }
            state_ = State::FAILED;
            DeliverResponse(MakeRetryBudgetResponse());
            return false;
        }
    }

    return true;
}

void ProxyTransaction::ActivateAttemptTracking() {
    bool breaker_live_enabled = slice_ && slice_->config().enabled;

    // Track this attempt against the host-level retry budget's
    // in_flight counter. Gated by the live `enabled` flag so disabling
    // the breaker mid-flight stops tracking immediately; enabling it
    // starts tracking at the next attempt. No-op when retry_budget_
    // is null (no breaker manager / unknown host).
    if (retry_budget_ && breaker_live_enabled) {
        inflight_guard_ = retry_budget_->TrackInFlight();
    }
}

void ProxyTransaction::EnsureCheckoutCancelToken() {
    // Breaker / budget gates for this attempt are complete. Any saved
    // Lazily allocate the shared cancel token so the pool can drop
    // this transaction's wait-queue entry if Cancel() fires while the
    // checkout is pending. Reused across retry attempts — Cancel()
    // flips it once for the lifetime of the transaction.
    if (!checkout_cancel_token_) {
        checkout_cancel_token_ =
            std::make_shared<std::atomic<bool>>(false);
    }
}

void ProxyTransaction::StartCheckoutAsync() {
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
        },
        checkout_cancel_token_
    );
}

void ProxyTransaction::SetupAttemptObservability() {
    // Fresh per-attempt context: trace_id / flags / state inherit from
    // the inbound; span_id is regenerated so retries surface as distinct
    // CLIENT spans. Sentinel start tick → FinalizeAttemptSpan skips emit
    // when observability is off.
    current_attempt_ = OBSERVABILITY_NAMESPACE::AttemptTraceContext{};
    attempt_start_steady_ = std::chrono::steady_clock::time_point{};
    auto* mgr = obs_manager();
    if (mgr) {
        // Duration histogram fires per-attempt regardless of trace sampling.
        attempt_start_steady_ = std::chrono::steady_clock::now();
        // One-time service-name capture under link_mtx; idempotent —
        // only writes if empty so retries don't re-publish. The kill
        // loop / dtor backstop reads this under the same mutex to
        // emit residual -1s with the correct label.
        if (obs_snapshot_) {
            {
                std::lock_guard<std::mutex> g(obs_snapshot_->link_mtx);
                if (obs_snapshot_->upstream_service_for_metrics.empty()) {
                    obs_snapshot_->upstream_service_for_metrics = service_name_;
                }
            }
            // Per-attempt +1: the snapshot tracks its outstanding count so
            // the kill / dtor backstop can drain whatever remains.
            obs_snapshot_->attempt_active_inflight_.fetch_add(
                1, std::memory_order_relaxed);
        }
        
        // Bump http.client.active_requests; matching -1 in
        // FinalizeAttemptSpan (CAS-gated on attempt_active_inflight_)
        // OR in the kill-loop / dtor backstop for survivors.
        const auto& cat = mgr->catalog();
        if (cat.http_client_active_requests != nullptr) {
            cat.http_client_active_requests->Add(
                1.0,
                {{"reactor.upstream.service", service_name_}});
        }
    }
    if (mgr && inbound_trace_ctx_.has_value()) {
        const auto& parent_local = inbound_trace_ctx_->current_local;
        if (parent_local.IsValid()) {
            current_attempt_.attempt_local = OBSERVABILITY_NAMESPACE::SpanContext(
                parent_local.trace_id(),
                mgr->random()->NewSpanId(),
                parent_local.flags(),
                parent_local.state(),
                /*is_remote=*/false);

            // DROP path (not recording / no SERVER span) still emits the
            // fresh span_id outbound with sampled=0 so downstream services
            // see a continuous trace tree; the local CLIENT span is skipped.
            if (inbound_trace_ctx_->is_recording && inbound_span()) {
                OBSERVABILITY_NAMESPACE::StartSpanOptions opts;
                opts.kind = OBSERVABILITY_NAMESPACE::SpanKind::CLIENT;
                opts.parent = inbound_span()->Context();
                opts.has_parent = true;
                opts.precomputed_context = current_attempt_.attempt_local;
                opts.has_precomputed_context = true;
                current_attempt_.upstream_span =
                    mgr->GetTracer("reactor.gateway.http", "1.0.0")
                       ->StartSpan(std::string("HTTP ") + method_,
                                    opts);
                auto& span = current_attempt_.upstream_span;
                span->SetAttribute(
                    "http.request.method",
                    OBSERVABILITY_NAMESPACE::AttrValue(method_));
                span->SetAttribute(
                    "server.address",
                    OBSERVABILITY_NAMESPACE::AttrValue(upstream_host_));
                span->SetAttribute(
                    "server.port",
                    OBSERVABILITY_NAMESPACE::AttrValue(
                        static_cast<int64_t>(upstream_port_)));
                // Placeholder protocol.version — DispatchH1/H2 overwrite
                // it; this preserves a defined attribute if dispatch never
                // runs (e.g. TLS failure before DispatchH1/H2).
                span->SetAttribute(
                    "network.protocol.version",
                    OBSERVABILITY_NAMESPACE::AttrValue(std::string("unknown")));
                span->SetAttribute(
                    "http.request.resend_count",
                    OBSERVABILITY_NAMESPACE::AttrValue(
                        static_cast<int64_t>(attempt_)));
            }

            // Invalidate cached serialized request so the next H1 send
            // carries this attempt's fresh `traceparent`.
            RebuildOutboundTraceHeaders();
        }
    }
}

void ProxyTransaction::AttemptCheckout() {
    state_ = State::CHECKOUT_PENDING;
    if (!PrepareAttemptAdmission()) {
        return;
    }
    ActivateAttemptTracking();
    EnsureCheckoutCancelToken();
    SetupAttemptObservability();

    // Fast path: if a usable multiplexed H2 session already exists for
    // this upstream, dispatch onto it without consuming a pool slot.
    // Without this, with `pool.max_connections` set near 1 the donated
    // H2 transport permanently occupies the only pool slot — subsequent
    // requests would queue forever in CheckoutAsync instead of
    // multiplexing onto the existing session. H2 concurrency would be
    // bounded by spare pool slots rather than max_concurrent_streams_pref.
    if (TryDispatchExistingH2Session()) {
        return;
    }

    StartCheckoutAsync();
}

bool ProxyTransaction::TryDispatchExistingH2Session() {
    if (!upstream_manager_ || dispatcher_index_ < 0) return false;
    PoolPartition* partition = upstream_manager_->GetPoolPartition(
        service_name_, static_cast<size_t>(dispatcher_index_));
    if (!partition) return false;
    auto cfg = partition->LoadHttp2ConfigSnapshot();
    if (!cfg || !cfg->enabled || cfg->prefer == "never") return false;
    // Prefer an under-threshold session.
    auto existing = partition->FindUsableH2ConnectionSaturation(service_name_);
    if (!existing) {
        // No under-threshold session. Fire a capacity probe for FUTURE
        // requests if policy allows.
        if (partition->ShouldOpenAdditionalH2Conn(service_name_)) {
            partition->StartH2CapacityProbe(service_name_, upstream_port_);
        }
        // Fallback: an over-threshold session may still have stream
        // capacity (active_streams_ < max_concurrent_streams_pref AND
        // utilization ≥ saturation_open_pct percent). Reuse it for
        // THIS request rather than queuing in StartCheckoutAsync —
        // CheckoutAsync's `TotalCount() < partition_max_connections_`
        // gate doesn't know about per-H2-session stream capacity, so
        // when cap is reached the request would queue while the
        // multiplexed session sits with free streams. The just-fired
        // probe handles FUTURE load growth; this branch unblocks the
        // current request.
        existing = partition->FindUsableH2Connection(service_name_);
        if (!existing) {
            // No usable H2 session at all. Fall through to checkout
            // which creates a new transport (under cap) or queues.
            return false;
        }
        logging::Get()->debug(
            "TryDispatchExistingH2Session: reusing over-threshold H2 "
            "session for service={} client_fd={} — capacity probe "
            "(if any) handles future load",
            service_name_, client_fd_);
    } else {
        // Under-threshold session picked. Predictive preconnect fires
        // if the session is in the (watermark, saturation) window so
        // the next request finds an additional session already warming
        // up. MaybePreconnectH2 is a no-op when preconnect_watermark_pct
        // == 0 (disabled fast path) and self-gates on cap / in-flight-probe.
        partition->MaybePreconnectH2(service_name_, upstream_port_, *existing);
    }
    // Reusable session in hand (under- or over-threshold). Skip
    // CheckoutAsync entirely and dispatch through the H2 path with an
    // EMPTY lease — DispatchH2's AcquireH2Connection FAST branch returns
    // the same session without touching the lease, and lease_ stays
    // empty (the existing session owns its own donated lease for
    // transport lifetime). Advance to SENDING_REQUEST as if
    // OnCheckoutReady had granted us a lease.
    state_ = State::SENDING_REQUEST;
    DispatchH2();
    return true;
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
        // Empty lease from DrainAnyWaitersForFastH2 — a multiplexed
        // session became usable while we were queued. Re-try the H2
        // fast path; on miss (session evicted in the race window
        // between drain decision and dispatch) route through
        // MaybeRetry(CONNECT_FAILURE) for parity with the
        // error_callback path (OnCheckoutError). The race is exactly
        // the case where retry is appropriate — upstream is healthy,
        // we just lost a slot to a sibling.
        if (TryDispatchExistingH2Session()) {
            return;
        }
        ReleaseBreakerAdmissionNeutral();
        if (DeliverPendingRetryable5xxResponse("checkout_empty_lease")) {
            return;
        }
        logging::Get()->warn(
            "ProxyTransaction empty-lease H2 dispatch miss client_fd={} "
            "service={} attempt={} — routing through MaybeRetry",
            client_fd_, service_name_, attempt_);
        ReportBreakerOutcome(RESULT_CHECKOUT_FAILED);
        MaybeRetry(RetryPolicy::RetryCondition::CONNECT_FAILURE);
        return;
    }

    auto transport = upstream_conn->GetTransport();
    if (!transport) {
        ReleaseBreakerAdmissionNeutral();
        if (DeliverPendingRetryable5xxResponse("checkout_missing_transport")) {
            return;
        }
        OnError(RESULT_CHECKOUT_FAILED,
                "Upstream connection has no transport");
        return;
    }

    logging::Get()->debug("ProxyTransaction checkout ready client_fd={} "
                          "service={} upstream_fd={} attempt={}",
                          client_fd_, service_name_, transport->fd(),
                          attempt_);

    // Decide H1 vs H2 dispatch. The partition holds the live H2
    // sub-config snapshot (atomic-loaded each call so reload-time
    // commits are observed). For TLS upstreams in `auto` prefer mode
    // we wait for the handshake-complete callback to read ALPN; bare
    // TCP `auto` falls through to H1 (no ALPN signal available).
    PoolPartition* partition = nullptr;
    if (upstream_manager_ && dispatcher_index_ >= 0) {
        partition = upstream_manager_->GetPoolPartition(
            service_name_, static_cast<size_t>(dispatcher_index_));
    }
    std::shared_ptr<const Http2UpstreamConfig> cfg;
    if (partition) cfg = partition->LoadHttp2ConfigSnapshot();

    bool want_h2 = false;
    bool defer_for_handshake = false;
    const bool prefer_always = (cfg && cfg->enabled && cfg->prefer == "always");
    if (cfg && cfg->enabled) {
        const std::string& prefer = cfg->prefer;
        if (prefer == "always" || prefer == "auto") {
            if (transport->IsTlsReady()) {
                want_h2 = (transport->GetAlpnProtocol() == "h2");
            } else if (transport->HasTls()) {
                defer_for_handshake = true;
            }
            // Bare TCP under prefer=always cannot satisfy strict h2 —
            // there is no ALPN signal. want_h2 stays false; the strict-fail
            // gate below converts that into an explicit CHECKOUT_FAILED.
        }
    }

    if (defer_for_handshake) {
        std::weak_ptr<ProxyTransaction> wk_self = weak_from_this();
        std::weak_ptr<ConnectionHandler> wk_t = transport;
        // The pool's close/error fan-out routes a disconnect to
        // borrower_cb = handler->GetOnMessageCb() with empty data.
        // Without this transient hook, a TLS handshake failure (peer
        // RST, cert error, ALPN abort) wedges the transaction in
        // CHECKOUT_PENDING with the lease + breaker admission stranded
        // until the request deadline tears it down.
        transport->SetOnMessageCb(
            [wk_self](std::shared_ptr<ConnectionHandler>, std::string& data) {
                if (!data.empty()) return;
                auto self = wk_self.lock();
                if (!self || self->cancelled_) return;
                self->OnError(RESULT_UPSTREAM_DISCONNECT,
                              "upstream disconnected during TLS handshake");
            });
        transport->SetHandshakeCompleteCallback(
            [wk_self, wk_t, prefer_always]() {
                auto self = wk_self.lock();
                if (!self || self->cancelled_) return;
                auto t = wk_t.lock();
                bool h2 = t && (t->GetAlpnProtocol() == "h2");
                if (h2) {
                    self->DispatchH2();
                } else if (prefer_always) {
                    // prefer=always + ALPN!=h2: dedicated terminal so
                    // routing through OnCheckoutError can't burn the
                    // retry budget on a deterministic reject.
                    self->ReleaseBreakerAdmissionNeutral();
                    self->OnError(
                        RESULT_H2_ALPN_NOT_NEGOTIATED,
                        "prefer=always but peer ALPN!=h2");
                } else {
                    self->DispatchH1();
                }
            });
        return;
    }

    // Strict-h2 gate on the immediate (already-ready or bare-TCP) path.
    // Deferred-handshake branch above has its own gate.
    if (prefer_always && !want_h2) {
        ReleaseBreakerAdmissionNeutral();
        OnError(RESULT_H2_ALPN_NOT_NEGOTIATED,
                transport->IsTlsReady()
                    ? "prefer=always but peer ALPN!=h2"
                    : "prefer=always requires TLS+ALPN");
        return;
    }

    if (want_h2) {
        DispatchH2();
    } else {
        DispatchH1();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase E — Outbound H1 streaming
// ─────────────────────────────────────────────────────────────────────────────

std::string ProxyTransaction::BuildH1StreamingRequestHead_() const {
    std::string head;
    head.reserve(256);
    head += method_;
    head += ' ';
    head += upstream_path_;
    if (!query_.empty()) { head += '?'; head += query_; }
    head += " HTTP/1.1\r\n";
    for (const auto& [k, v] : rewritten_headers_) {
        head += k; head += ": "; head += v; head += "\r\n";
    }
    head += "\r\n";
    return head;
}

void ProxyTransaction::SendH1StreamingRequest_(
    std::shared_ptr<http::BodyStream> body_stream) {
    body_stream_ = std::move(body_stream);

    // Wire the consumer dispatcher BEFORE the first Read or WaitForData.
    if (auto* uc = lease_.Get()) {
        if (auto t = uc->GetTransport()) {
            body_stream_->SetConsumerDispatcher(
                t->GetDispatcher()->weak_from_this());
        }
    }

    // Single atomic snapshot for the three-shape decision.
    const auto snap = body_stream_->SnapshotForSubmit();
    const bool pure_bodyless       = snap.eos && !snap.has_trailers && snap.bytes_queued == 0;
    const bool empty_with_trailers = snap.eos &&  snap.has_trailers && snap.bytes_queued == 0;

    // Mutate rewritten_headers_ for framing (already populated by the existing
    // dispatch path via HeaderRewriter::RewriteRequest).
    rewritten_headers_.erase("content-length");
    rewritten_headers_.erase("transfer-encoding");
    rewritten_headers_.erase("trailer");
    if (pure_bodyless) {
        rewritten_headers_["content-length"] = "0";
    } else {
        rewritten_headers_["transfer-encoding"] = "chunked";
    }
    if (pure_bodyless && rewritten_headers_.count("transfer-encoding")) {
        logging::Get()->error("BUG: streaming H1 PureBodyless has transfer-encoding");
    }
    if (!pure_bodyless && rewritten_headers_.count("content-length")) {
        logging::Get()->error("BUG: streaming H1 Bodied/EmptyWithTrailers has content-length");
    }

    std::string head = BuildH1StreamingRequestHead_();
    auto* uc = lease_.Get();
    if (!uc) {
        OnError(RESULT_CHECKOUT_FAILED, "h1 streaming: no upstream connection");
        return;
    }
    auto transport = uc->GetTransport();

    // For pure_bodyless: set completion-gate flags BEFORE SendRaw. The head
    // write is the entire request (CL:0); SendRaw's fast-path direct-write can
    // fire OnUpstreamWriteComplete synchronously inside this call. The guard at
    // the top of OnUpstreamWriteComplete must permit the transition.
    if (pure_bodyless) {
        h1_streaming_send_complete_ = true;
        h1_request_fully_sent_ = true;
    }
    transport->SendRaw(head.data(), head.size());

    // Fire OnRequestHeadersSubmitted immediately — H1 has no async
    // serialization queue equivalent to nghttp2.
    OnRequestHeadersSubmitted();

    if (pure_bodyless) {
        return;
    }
    if (empty_with_trailers) {
        EmitH1ChunkedTrailers_(snap.trailers_copy, /*omit_last_chunk_marker=*/false);
        return;
    }

    // Bodied: install resume callback with weak_from_this capture.
    std::weak_ptr<ProxyTransaction> weak_self = weak_from_this();
    body_stream_->WaitForData([weak_self]() {
        auto self = weak_self.lock();
        if (!self) return;
        if (self->cancelled_ || self->IsKilledForShutdown()) return;
        self->PumpH1StreamingBody_();
    });
}

void ProxyTransaction::PumpH1StreamingBody_() {
    static constexpr size_t MAX_CHUNK_BYTES = 16 * 1024;
    char buf[MAX_CHUNK_BYTES];
    auto* uc = lease_.Get();
    if (!uc) {
        return;
    }
    auto transport = uc->GetTransport();
    while (true) {
        size_t bytes_read = 0;
        auto rc = body_stream_->Read(buf, MAX_CHUNK_BYTES, &bytes_read);
        switch (rc) {
            case http::BodyStreamResult::OK: {
                OnRequestBodySourceConsumed(bytes_read);
                std::string chunk_hdr = HexSize_(bytes_read) + "\r\n";
                transport->SendRaw(chunk_hdr.data(), chunk_hdr.size());
                transport->SendRaw(buf, bytes_read);
                transport->SendRaw("\r\n", 2);
                OnRequestBodyProgress(bytes_read);
                break;
            }
            case http::BodyStreamResult::WOULD_BLOCK: {
                std::weak_ptr<ProxyTransaction> weak_self = weak_from_this();
                body_stream_->WaitForData([weak_self]() {
                    auto self = weak_self.lock();
                    if (!self) return;
                    if (self->cancelled_ || self->IsKilledForShutdown()) return;
                    self->PumpH1StreamingBody_();
                });
                return;
            }
            case http::BodyStreamResult::END_OF_STREAM: {
                const auto& trailers = body_stream_->Trailers();
                EmitH1ChunkedTrailers_(trailers, /*omit_last_chunk_marker=*/false);
                return;
            }
            case http::BodyStreamResult::ABORTED: {
                const std::string& reason = body_stream_->AbortReason();
                const int result_code =
                    (reason == "body_size_limit_exceeded" ||
                     reason == "content_length_overrun"  ||
                     reason == "content_length_underrun")
                        ? RESULT_REQUEST_BODY_LIMIT_EXCEEDED
                        : RESULT_SEND_FAILED;
                logging::Get()->warn(
                    "H1 upstream streaming body_stream aborted: reason={} code={}",
                    reason, result_code);
                if (uc) uc->MarkClosing();
                DeliverTerminalError(result_code,
                                      "streaming body aborted: " + reason);
                return;
            }
        }
    }
}

void ProxyTransaction::EmitH1ChunkedTrailers_(
    const std::vector<std::pair<std::string, std::string>>& trailers,
    bool omit_last_chunk_marker) {
    auto* uc = lease_.Get();
    if (!uc) return;
    auto transport = uc->GetTransport();

    // Pre-flip the gate before the final SendRaw sequence so the eventual
    // OnUpstreamWriteComplete is permitted to transition state.
    h1_streaming_send_complete_ = true;
    h1_request_fully_sent_ = true;

    if (!omit_last_chunk_marker) {
        transport->SendRaw("0\r\n", 3);
    }
    auto filtered = http::SanitizeHttp2TrailerFieldsForOutboundEmit(trailers);
    for (const auto& [name, value] : filtered) {
        std::string line = name + ": " + value + "\r\n";
        transport->SendRaw(line.data(), line.size());
    }
    transport->SendRaw("\r\n", 2);
}

void ProxyTransaction::DispatchH1() {
    // If the previous attempt used H2, codec_ is UpstreamH2Codec.
    // ResetForRetryAttempt() only Reset()s the existing codec — it
    // does NOT re-construct. Without this swap, the H1 fallback's
    // first response bytes would route through UpstreamH2Codec::Parse
    // (HTTP/2 frame parser) and fail immediately with a parse error.
    // Hot-path overhead is one dynamic_cast per DispatchH1 invocation
    // (constant-time, single vtable lookup); the codec swap itself
    // only happens on H2→H1 retry fallback in prefer="auto" mode.
    if (dynamic_cast<UpstreamH2Codec*>(codec_.get()) != nullptr) {
        codec_ = std::make_unique<UpstreamHttpCodec>();
        codec_->SetRequestMethod(method_);
        codec_->SetSink(this);
    }
    // Protocol decision finalized here — stamp the CLIENT span. Safe to
    // call on the prefer="auto" deferred-handshake path: the ALPN-
    // resolved callback invokes DispatchH1/DispatchH2 directly, both of
    // which arrive at this stamp before sending the request.
    SetProtocolVersionOnAttemptSpan("1.1");

    auto* upstream_conn = lease_.Get();
    if (!upstream_conn) {
        ReleaseBreakerAdmissionNeutral();
        if (DeliverPendingRetryable5xxResponse("dispatch_h1_empty_lease")) {
            return;
        }
        OnError(RESULT_CHECKOUT_FAILED,
                "DispatchH1 called without a valid lease");
        return;
    }
    auto transport = upstream_conn->GetTransport();
    if (!transport) {
        ReleaseBreakerAdmissionNeutral();
        if (DeliverPendingRetryable5xxResponse("dispatch_h1_no_transport")) {
            return;
        }
        OnError(RESULT_CHECKOUT_FAILED,
                "DispatchH1: upstream connection has no transport");
        return;
    }

    // Bound how much raw upstream data can accumulate in the transport's
    // ET read loop before the codec/backpressure path gets a chance to run.
    // This cap is per checked-out transaction and is cleared before the
    // connection returns to the pool.
    transport->SetMaxInputSize(config_.relay_buffer_limit_bytes);

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

    if (is_streaming_request_) {
        SendH1StreamingRequest_(body_stream_);
        return;
    }

    SendUpstreamRequest();
}

void ProxyTransaction::DispatchH2() {
    // Stamp the CLIENT span before any H2 acquisition/reuse failure can
    // short-circuit into MaybeRetry/DeliverTerminalError. Without this,
    // failed H2 attempts finalize without network.protocol.version even
    // though successful H2 attempts record "2".
    SetProtocolVersionOnAttemptSpan("2");

    // Primary CONNECT-rejection gate. RFC 9113 §8.5 forbids :scheme and
    // :path on CONNECT pseudo-headers, but our H2 codec always emits
    // both — serving CONNECT through this path would emit a malformed
    // request. Reject deterministically with 502 + X-H2-Limitation
    // header.
    //
    // Released here so the H2-method-not-supported path doesn't leave
    // an admission slot held when OnError fires below. OnError's
    // pre-routing hook also calls ReleaseBreakerAdmissionNeutral on
    // RESULT_H2_METHOD_NOT_SUPPORTED, but that helper is idempotent
    // (no-op when no admission is held — admission_generation_ == 0
    // short-circuit) so the second call is safe.
    if (method_ == "CONNECT") {
        logging::Get()->warn(
            "H2 upstream rejecting CONNECT: not supported in this gateway "
            "fd={} service={}",
            client_fd_, service_name_);
        ReleaseBreakerAdmissionNeutral();
        OnError(RESULT_H2_METHOD_NOT_SUPPORTED,
                "CONNECT not supported on H2 upstream");
        return;
    }

    PoolPartition* partition = nullptr;
    if (upstream_manager_ && dispatcher_index_ >= 0) {
        partition = upstream_manager_->GetPoolPartition(
            service_name_, static_cast<size_t>(dispatcher_index_));
    }
    if (!partition) {
        MaybeRetry(RetryPolicy::RetryCondition::CONNECT_FAILURE);
        return;
    }

    auto h2 = partition->AcquireH2Connection(service_name_, lease_);
    if (!h2) {
        MaybeRetry(RetryPolicy::RetryCondition::CONNECT_FAILURE);
        return;
    }
    // Protocol decision finalized — the span was stamped above before
    // any early-return failure path. Reaching here means the H2 session
    // acquisition succeeded; continue the dispatch using the same span.
    // Reuse path: lease_ was untouched by AcquireH2Connection; fresh-
    // session path: lease_ has been moved into the H2 connection. In
    // either case the transaction no longer needs a direct lease —
    // return any leftover handle to the pool so a sibling H1 dispatch
    // doesn't accidentally reach the same transport.
    if (lease_) lease_.Release();

    // Switch the codec to the H2 implementation. The codec object
    // owns response parsing state for the H1 fallback path; on the H2
    // path it is unused at the connection layer (sink callbacks fire
    // directly from nghttp2 frame callbacks).
    auto h2_codec = std::make_unique<UpstreamH2Codec>();
    h2_codec->SetRequestMethod(method_);
    h2_codec->SetSink(this);
    codec_ = std::move(h2_codec);

    // Build :authority by reusing the H1 Host header that
    // HeaderRewriter::RewriteRequest already produced. RFC 9113 §8.3.1
    // makes :authority the H2 equivalent of the H1 Host header; using
    // the already-resolved value gives us H1/H2 byte-parity for free,
    // including:
    //   * `rewrite_host=false` passthrough (preserves client-supplied
    //     Host, which the static derivation here would silently
    //     overwrite, breaking backend vhost routing for routes that
    //     opt out of rewriting);
    //   * TLS-by-IP with `tls.sni_hostname` set (rewriter prefers SNI);
    //   * IPv6 literal bracketing (via DnsResolver::FormatAuthority);
    //   * default-port elision for the active scheme.
    // Fallback to the static derivation only when the rewriter produced
    // no host at all — defensively handles a rewriter contract change
    // rather than emitting an empty :authority (which nghttp2 would
    // reject).
    std::string authority;
    auto host_it = rewritten_headers_.find("host");
    if (host_it != rewritten_headers_.end() && !host_it->second.empty()) {
        authority = host_it->second;
    } else {
        // Rewriter contract drift: HeaderRewriter::RewriteRequest is
        // expected to emit a Host derived from upstream_host_ / SNI / IPv6
        // brackets / default-port elision. An empty Host here would
        // produce an :authority that nghttp2 rejects (and a wire-invalid
        // H1 request on the parallel codec path). Warn so operators can
        // chase the rewriter regression instead of debugging from the
        // 502 alone, then synthesize a defensive :authority.
        logging::Get()->error(
            "ProxyTransaction H2 :authority fallback fired (rewritten Host "
            "empty) client_fd={} service={} — using upstream_host derivation. "
            "This indicates a HeaderRewriter contract regression.",
            client_fd_, service_name_);
        const std::string& host_src =
            (upstream_tls_ && !sni_hostname_.empty())
                ? sni_hostname_
                : upstream_host_;
        const std::string host_value =
            NET_DNS_NAMESPACE::DnsResolver::StripTrailingDot(host_src);
        const bool omit_port = (!upstream_tls_ && upstream_port_ == 80) ||
                               (upstream_tls_ && upstream_port_ == 443);
        authority = NET_DNS_NAMESPACE::DnsResolver::FormatAuthority(
            host_value, upstream_port_, omit_port);
    }
    const std::string scheme = upstream_tls_ ? "https" : "http";

    // Compose path with query, mirroring the H1 serializer.
    std::string path_with_query = upstream_path_.empty() ? "/" : upstream_path_;
    if (!query_.empty()) {
        path_with_query.push_back('?');
        path_with_query.append(query_);
    }

    // Initialize H2 state BEFORE SubmitRequest. Sink virtuals now fire
    // from the transport's drain callbacks, but the fast-path
    // (DoSendRaw direct-write on a healthy socket with empty buffer)
    // can fire complete_callback SYNCHRONOUSLY inside SendRaw — and
    // SendRaw is called from FlushSend which is called from
    // SubmitRequest. The override's `!h2_path_` guard would otherwise
    // drop the kill of the just-queued send-stall closure.
    // Budget mirrors the H1 zero-disable semantic: response_timeout_ms
    // == 0 opts out of the response-wait timer; stall protection stays
    // on via SEND_STALL_FALLBACK_MS.
    h2_path_ = true;
    state_ = State::SENDING_REQUEST;
    h2_response_timeout_armed_ = false;
    h2_request_fully_sent_ = false;

    h2_stall_budget_ms_ = ComputeH2StallBudgetMs(
        config_.response_timeout_ms);
    h2_last_progress_at_ = std::chrono::steady_clock::now();
    ArmH2SendStallDeadline(h2_stall_budget_ms_);

    int32_t stream_id = -1;

    if (is_streaming_request_) {
        // Wire consumer dispatcher BEFORE SubmitStreamingRequest's first
        // WaitForData/Read — body_stream_ was constructed on the inbound
        // dispatcher; the real consumer is the outbound dispatcher that owns
        // this lease (v8 F4 P1).
        if (auto* uc_raw = h2->transport()) {
            if (auto t = uc_raw->GetTransport()) {
                body_stream_->SetConsumerDispatcher(
                    t->GetDispatcher()->weak_from_this());
            }
        }
        // Fast-path direct-write (DoSendRaw) may run inline inside
        // SubmitStreamingRequest → FlushSend, firing drain callbacks and
        // sink virtuals synchronously. All H2 state flags are already set
        // above so the virtuals arrive in a consistent state.
        stream_id = h2->SubmitStreamingRequest(
            this, method_, scheme, authority, path_with_query,
            rewritten_headers_, client_te_trailers_, body_stream_);
    } else {
        // Buffered (non-streaming) path: body bytes are in request_body_.
        // Fast-path direct-write (DoSendRaw) may run inline here, firing
        // the transport's complete_callback → OnTransportWriteComplete →
        // sink->OnRequestSubmitted → bumps h2_send_stall_generation_,
        // killing the closure above.
        stream_id = h2->SubmitRequest(
            method_, scheme, authority, path_with_query,
            rewritten_headers_, request_body_, this, client_te_trailers_);
    }

    if (stream_id < 0) {
        // Submit failed. Roll back H2 bookkeeping; state_ stays
        // untouched — AttemptCheckout (called by MaybeRetry's
        // deferred-retry timer and immediate-retry branch) resets
        // state_ before the next attempt. Bump BOTH generations:
        // send-stall closure was just queued; response-timeout
        // closure may have been queued synchronously by an inline
        // on_frame_send fire for a bodyless HEADERS+END_STREAM.
        ++h2_send_stall_generation_;
        ++h2_response_timeout_generation_;
        h2_path_ = false;
        h2_response_timeout_armed_ = false;
        h2_request_fully_sent_ = false;
        // h2_lease_ was not constructed yet (construction happens AFTER
        // a successful stream_id capture below); nothing to release.
        logging::Get()->warn(
            "ProxyTransaction H2 submit failed client_fd={} service={} "
            "attempt={}", client_fd_, service_name_, attempt_);
        // Drain queued ANY waiters: the session stays in h2_table_ so a
        // sibling waiter may still multiplex. Capacity-aware drain
        // requeues if IsUsable() reports the session is full.
        partition->DrainAnyWaitersForFastH2();
        MaybeRetry(RetryPolicy::RetryCondition::CONNECT_FAILURE);
        return;
    }

    h2_stream_id_ = stream_id;

    // Construct the H2 lease NOW (post-submit) so its destructor's
    // ReturnH2Stream call carries the real stream_id. Constructing
    // earlier (e.g. at line 1298 alongside h2_path_=true) would invoke
    // ReturnH2Stream(h2, -1, ...) on submit-failure, tripping the
    // BUG-log defense at PoolPartition::ReturnH2Stream. The dual-token
    // pair (partition_alive, conn_alive) gates GetH2Connection() so a
    // mid-flight session/partition destruction short-circuits cleanly.
    // The off-dispatcher counter + dispatcher are captured so an
    // off-thread Release can fire bookkeeping without dereferencing
    // partition_ during its destruction window.
    h2_lease_ = UpstreamLease(
        h2, stream_id, partition,
        partition->alive_token(), h2->alive_token(),
        partition->OffDispatcherReleaseDropsPtr(),
        partition->dispatcher_ptr());

    // Wake any ANY-kind waiters that queued during the connect window.
    // Done HERE (not inside AcquireH2Connection's construct branch) so
    // the just-consumed stream slot is visible to FindUsable's
    // IsUsable() check inside DrainAnyWaitersForFastH2 — otherwise a
    // queued waiter would synchronously dispatch + SubmitRequest, win
    // the only stream slot under max_concurrent_streams=1, and force
    // this transaction's own SubmitRequest above to fail.
    partition->DrainAnyWaitersForFastH2();
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
    // reported — they don't imply upstream unhealthiness.
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
        // Drain path: breaker tripped while this transaction was queued.
        // Do NOT Report success/failure to the slice — our own reject
        // must not feed back into the failure math. Emit the circuit-open
        // response (Retry-After + X-Circuit-Breaker headers) directly.
        logging::Get()->info(
            "ProxyTransaction checkout drained by circuit breaker "
            "client_fd={} service={}",
            client_fd_, service_name_);
        // Neutral-release the slice admission instead of just clearing
        // admission_generation_. Three drain paths reach here:
        //   CLOSED→OPEN  : closed_gen_ was bumped by the trip; our
        //                  generation is now stale → ReportNeutral
        //                  drops as stale-gen. No state mutation. Safe.
        //   HALF_OPEN→OPEN : halfopen_gen_ was bumped by the trip AND
        //                  half_open_inflight_/admitted_ reset to 0 by
        //                  TransitionOpenToHalfOpen's sibling path →
        //                  ReportNeutral drops as stale-gen. Safe.
        //   (Any future same-cycle drain without a generation bump):
        //                  admission_generation_ is still current →
        //                  ReportNeutral correctly returns the slot,
        //                  preventing half_open_inflight_/admitted_
        //                  from leaking and wedging the slice in
        //                  half_open_full until the next reset.
        // ReleaseBreakerAdmissionNeutral clears admission_generation_
        // internally, so Cleanup/destructor won't double-report.
        ReleaseBreakerAdmissionNeutral();
        // Finalize the CLIENT span BEFORE any terminal delivery — these
        // sites all jump straight to Cleanup, which would otherwise hit
        // the dtor backstop and label the span "abandoned". The current
        // attempt failed admission to the circuit breaker; closed-enum
        // error.type = "circuit_open".
        FinalizeAttemptSpan(/*status_code=*/0,
                             ErrorTypeForResult(RESULT_CIRCUIT_OPEN));
        if (ResumeHeldRetryable5xxResponse("checkout_circuit_open")) {
            return;
        }
        if (DeliverPendingRetryable5xxResponse("checkout_circuit_open")) {
            return;
        }
        DeliverResponse(MakeCircuitOpenResponse());
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
        // Held-5xx delivery bypasses OnError → DeliverTerminalError, so
        // finalize the CLIENT span here (same rationale as the CIRCUIT_OPEN
        // branch above). The fall-through OnError path already finalizes.
        if (pending_retryable_5xx_response_) {
            FinalizeAttemptSpan(/*status_code=*/0,
                                 ErrorTypeForResult(RESULT_POOL_EXHAUSTED));
            if (DeliverPendingRetryable5xxResponse("checkout_local_failure")) {
                return;
            }
        }
        OnError(RESULT_POOL_EXHAUSTED,
                "Pool checkout failed (local capacity, error=" +
                std::to_string(error_code) + ")");
    }
}

void ProxyTransaction::SendUpstreamRequest() {
    auto* upstream_conn = lease_.Get();
    if (!upstream_conn) {
        ReleaseBreakerAdmissionNeutral();
        if (DeliverPendingRetryable5xxResponse("send_without_lease")) {
            return;
        }
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

    // The replacement attempt is now live: we have a checked-out transport and
    // are about to put bytes on the wire. From this point onward, local
    // checkout/backoff failures can no longer occur, so the saved retryable 5xx
    // fallback is no longer needed.
    ClearPendingRetryable5xxResponse();
    holding_retryable_5xx_response_ = false;
    held_retryable_5xx_saw_eof_ = false;
    state_ = State::SENDING_REQUEST;

    // Lazy-serialize on first H1 send. Cached on subsequent retries that
    // also land on H1 (rewritten_headers_ / method_ / upstream_path_ /
    // request_body_ are immutable across retries). H2 dispatches never
    // reach this path, avoiding a second large copy of the body.
    if (serialized_request_.empty()) {
        serialized_request_ = HttpRequestSerializer::Serialize(
            method_, upstream_path_, query_, rewritten_headers_, request_body_);
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
    // the class-level SEND_STALL_FALLBACK_MS fallback. Unlike the
    // response-wait phase, the stall phase is ALWAYS protected — the
    // refresh-on-progress callback prevents false positives on large
    // uploads making steady progress, so using a fallback here doesn't
    // penalize any legitimate traffic. Config "disabled"
    // (response_timeout_ms == 0) opts out of the response-wait timeout,
    // NOT the hang protection.
    const int stall_budget_ms = ComputeH2StallBudgetMs(
        config_.response_timeout_ms);
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
    if (cancelled_ || IsKilledForShutdown()) return;
    if (state_ == State::COMPLETE || state_ == State::FAILED) {
        return;
    }

    std::string parse_input;
    if (!paused_parse_bytes_.empty()) {
        parse_input = std::move(paused_parse_bytes_);
        paused_parse_bytes_.clear();
        if (!data.empty()) parse_input.append(data);
    } else {
        parse_input = data;
    }

    // Empty data signals upstream disconnect (EOF) from the pool's close
    // callback. For connection-close framing (no Content-Length / TE),
    // llhttp needs an EOF signal to finalize the response. Try Finish()
    // first — if it completes the response, deliver it instead of retrying.
    if (parse_input.empty()) {
        if (holding_retryable_5xx_response_ && codec_->IsPaused()) {
            held_retryable_5xx_saw_eof_ = true;
            return;
        }
        if (codec_->Finish()) {
            // EOF-delimited response completed successfully
            poison_connection_ = true;  // connection-close: not reusable
            if (body_complete_) {
                OnResponseComplete();
            }
            return;
        }
        int upstream_fd = conn ? conn->fd() : -1;
        logging::Get()->warn("ProxyTransaction upstream EOF with incomplete response "
                             "client_fd={} service={} upstream_fd={} "
                             "body_complete_={} codec_paused={} paused_bytes={}",
                             client_fd_, service_name_, upstream_fd,
                             body_complete_, codec_->IsPaused(), paused_parse_bytes_.size());
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
    size_t consumed = codec_->Parse(parse_input.data(), parse_input.size());

    // Body/header callbacks may have already completed or torn down the
    // transaction (for example, downstream closed during streaming body
    // relay). Ignore parser state after terminal callback-driven cleanup.
    if (state_ == State::COMPLETE || state_ == State::FAILED) {
        return;
    }

    // Check for parse error — the HTTP stream is desynchronized and the
    // connection must not be returned to the idle pool.
    if (codec_->HasError()) {
        poison_connection_ = true;
        int upstream_fd = conn ? conn->fd() : -1;
        OnError(RESULT_PARSE_ERROR,
                "Upstream response parse error: " + codec_->GetError() +
                " upstream_fd=" + std::to_string(upstream_fd));
        return;
    }

    if (codec_->IsPaused() && consumed < parse_input.size()) {
        paused_parse_bytes_.assign(parse_input.data() + consumed,
                                   parse_input.size() - consumed);
        if (holding_retryable_5xx_response_) {
            auto snapshot = SnapshotRetryable5xxBody(
                response_head_, response_body_, paused_parse_bytes_);
            pending_retryable_5xx_body_ = std::move(snapshot.body);
            pending_retryable_5xx_body_complete_ = snapshot.complete;
        }
    }

    if (retry_from_headers_pending_) {
        ProcessHeadersRetryDecision();
        return;
    }

    // If a complete response was parsed but the read buffer still has
    // unconsumed bytes, the upstream sent trailing data after the
    // response boundary (garbage, an unexpected second response, or
    // pipelined data that violates our outbound one-request-per-wire
    // contract). The socket state is indeterminate — poison the lease
    // so it won't be returned to the idle pool even if keep_alive is
    // true, preventing the next borrower from seeing desynchronized
    // data on the same wire.
    if (body_complete_ && consumed < parse_input.size()) {
        poison_connection_ = true;
        int upstream_fd = conn ? conn->fd() : -1;
        logging::Get()->warn(
            "ProxyTransaction upstream sent {} trailing bytes after "
            "response client_fd={} service={} upstream_fd={} status={}",
            parse_input.size() - consumed, client_fd_, service_name_,
            upstream_fd, response_head_.status_code);
    }

    if (body_complete_) {
        OnResponseComplete();
        return;
    }

    if (state_ == State::AWAITING_RESPONSE && response_headers_seen_) {
        state_ = State::RECEIVING_BODY;
    }

}

bool ProxyTransaction::OnHeaders(
    const UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead& head) {
    if (cancelled_ || IsKilledForShutdown()) return false;

    response_headers_seen_ = true;
    response_head_ = head;
    response_headers_at_ = std::chrono::steady_clock::now();
    last_body_progress_at_ = response_headers_at_;
    response_body_.clear();
    response_trailers_.clear();
    relay_mode_ = DecideRelayMode(head);
    sse_stream_ = IsSseStream(head);

    if (!head.keep_alive) {
        poison_connection_ = true;
    }

    if (h2_path_) {
        // H2: early-final-headers — peer responded before our END_STREAM.
        // No poison_connection_: H2 multiplexes streams, so an early
        // status on one stream is not a transport-fatal signal.
        if (state_ == State::SENDING_REQUEST) {
            state_ = State::AWAITING_RESPONSE;
            // Invalidate the send-stall closure. Otherwise it fires
            // after the budget elapses with state in AWAITING_RESPONSE /
            // RECEIVING_BODY and spuriously surfaces RESPONSE_TIMEOUT
            // against a stream whose headers are already in hand.
            ++h2_send_stall_generation_;
            h2_request_fully_sent_ = true;
        }
        // Header phase done; body phase is governed by stream timers.
        ClearResponseTimeout();
        h2_response_timeout_armed_ = false;
    } else {
        if (state_ == State::SENDING_REQUEST) {
            // Early response: subsequent request-write completion must
            // not re-arm the header timer or move us back to the
            // pre-headers state.
            state_ = State::AWAITING_RESPONSE;
            poison_connection_ = true;
        }
        ClearResponseTimeout();
    }

    if (head.status_code >= HttpStatus::INTERNAL_SERVER_ERROR &&
        head.status_code < 600) {
        ReportBreakerOutcome(-1000);
        if (ShouldRetryResponse5xx() && CanRetryResponse5xxNow()) {
            retry_from_headers_pending_ = true;
            poison_connection_ = true;
            codec_->PauseParsing();
            if (auto* upstream_conn = lease_.Get()) {
                // Hold the upstream body at the transport edge while the retry
                // timer/local gates decide whether we will actually abandon
                // this response. Pausing llhttp alone would keep appending raw
                // bytes into paused_parse_bytes_ without the relay cap.
                upstream_conn->IncReadDisable();
            }
            // H2: there is no parser-loop driver to dispatch the retry
            // decision later, and we cannot pause the multiplexed
            // transport without stalling sibling streams. Make the retry
            // decision synchronously so subsequent body chunks land on a
            // detached sink (Cleanup nulls stream->sink via ResetStream)
            // and never reach the client. Snapshot-as-complete fallback
            // if the retry is rejected — whatever H2 DATA arrived before
            // the headers triggered the decision is treated as the full
            // body for replay.
            if (h2_path_) {
                ProcessHeadersRetryDecision();
            }
            return true;
        } else if (ShouldRetryResponse5xx()) {
            logging::Get()->info(
                "ProxyTransaction relaying current upstream 5xx client_fd={} "
                "service={} status={} attempt={} because retry is unavailable",
                client_fd_, service_name_, head.status_code, attempt_);
        }
    }

    if (!IsNoBodyResponse(head)) {
        RefreshStreamIdleTimer();
        ArmStreamBudgetTimer();
    }

    if (relay_mode_ == RelayMode::STREAMING) {
        if (!CommitStreamingResponse()) {
            logging::Get()->debug(
                "ProxyTransaction streaming header commit aborted locally "
                "client_fd={} service={} status={} attempt={}",
                client_fd_, service_name_, head.status_code, attempt_);
            ReleaseBreakerAdmissionNeutral();
            poison_connection_ = true;
            state_ = State::FAILED;
            stream_sender_.Abort(
                HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::AbortReason::UPSTREAM_ERROR);
            complete_cb_invoked_.store(true, std::memory_order_release);
            complete_cb_ = nullptr;
            Cleanup();
            return false;
        }
    }

    return true;
}

bool ProxyTransaction::OnBodyChunk(const char* data, size_t len) {
    if (cancelled_ || IsKilledForShutdown()) return false;
    last_body_progress_at_ = std::chrono::steady_clock::now();
    if (state_ == State::AWAITING_RESPONSE) {
        state_ = State::RECEIVING_BODY;
    }
    RefreshStreamIdleTimer();

    if (relay_mode_ == RelayMode::BUFFERED) {
        if (response_body_.size() >= UpstreamHttpCodec::MAX_RESPONSE_BODY_SIZE ||
            len > UpstreamHttpCodec::MAX_RESPONSE_BODY_SIZE - response_body_.size()) {
            poison_connection_ = true;
            OnError(RESULT_RESPONSE_TOO_LARGE,
                    "Upstream response body exceeds maximum buffered size");
            return false;
        }
        response_body_.append(data, len);
        return true;
    }

    auto result = stream_sender_.SendData(data, len);
    HandleStreamSendResult(result);
    if (result == HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::SendResult::CLOSED) {
        poison_connection_ = true;
        ReleaseBreakerAdmissionNeutral();
        stream_sender_.Abort(
            HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::AbortReason::CLIENT_DISCONNECT);
        state_ = State::FAILED;
        complete_cb_invoked_.store(true, std::memory_order_release);
        complete_cb_ = nullptr;
        Cleanup();
        return false;
    }
    return true;
}

void ProxyTransaction::OnTrailers(
    const std::vector<std::pair<std::string, std::string>>& trailers) {
    if (cancelled_ || IsKilledForShutdown()) return;
    if (!config_.forward_trailers) return;
    if (client_http_major_ == 2) {
        // H2 downstream: sanitize pseudo-headers, hop-by-hop, and framing
        // headers; no Trailer declaration enforcement (H2 doesn't use it).
        response_trailers_ = http::SanitizeHttp2TrailerFieldsForOutboundEmit(trailers);
    } else {
        // H1 downstream: only forward trailers the upstream declared in the
        // Trailer header; undefined trailers are dropped per RFC 7230.
        auto allowed = CollectDeclaredTrailerNames(response_head_.headers);
        response_trailers_.clear();
        if (allowed.empty()) {
            return;
        }
        response_trailers_.reserve(trailers.size());
        for (const auto& [key, value] : trailers) {
            if (allowed.count(LowerCopy(key)) == 0) {
                continue;
            }
            response_trailers_.emplace_back(key, value);
        }
    }
}

void ProxyTransaction::OnComplete() {
    if (cancelled_ || IsKilledForShutdown()) return;
    body_complete_ = true;
    // H2 streams have no per-byte parser loop, so there is no equivalent
    // of the H1 OnUpstreamData path that checks `if (body_complete_)
    // OnResponseComplete()` after each parse. Drive the same delivery
    // flow here for the H2 path.
    if (h2_path_) {
        // Skip if a synchronous retry was already scheduled from
        // OnHeaders — would double-fire OnResponseComplete and race
        // with the in-flight retry.
        if (retry_from_headers_pending_) return;
        OnResponseComplete();
    }
}

void ProxyTransaction::OnUpstreamWriteComplete(
    std::shared_ptr<ConnectionHandler> conn) {
    if (cancelled_ || IsKilledForShutdown()) return;
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

    // Streaming H1: intermediate chunk drains (between the first headers
    // SendRaw and the final EmitH1ChunkedTrailers_ SendRaw) must NOT
    // transition state to AWAITING_RESPONSE. EmitH1ChunkedTrailers_ sets
    // h1_streaming_send_complete_ = true BEFORE its final SendRaw so the
    // sole post-final-write fire takes the normal transition path below.
    if (is_streaming_request_ && !h1_streaming_send_complete_) {
        return;
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
    if (cancelled_ || IsKilledForShutdown()) return;
    ClearResponseTimeout();
    InvalidateStreamTimers();

    if (response_head_.status_code >= HttpStatus::INTERNAL_SERVER_ERROR &&
        response_head_.status_code < 600) {
        // 5xx outcomes are reported at headers so retry/breaker gates see the
        // failure before deciding whether another attempt is allowed.
    } else if (response_head_.status_code >= HttpStatus::BAD_REQUEST) {
        ReleaseBreakerAdmissionNeutral();
    } else {
        ReportBreakerOutcome(RESULT_SUCCESS);
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
                         response_head_.status_code, attempt_, duration.count());

    // End the per-attempt CLIENT span. FinalizeAttemptSpan marks
    // status >= 400 as Error and DropWithoutEnd if shutdown won the
    // kill race.
    FinalizeAttemptSpan(response_head_.status_code, /*error_type=*/"");

    if (relay_mode_ == RelayMode::STREAMING && response_committed_) {
        auto result = stream_sender_.End(response_trailers_);
        if (result == HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::SendResult::CLOSED) {
            stream_sender_.Abort(
                HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::AbortReason::CLIENT_DISCONNECT);
        }
        complete_cb_invoked_.store(true, std::memory_order_release);
        complete_cb_ = nullptr;
        Cleanup();
        return;
    }

    HttpResponse client_response = BuildClientResponse();
    DeliverResponse(std::move(client_response));
}

void ProxyTransaction::OnError(int result_code,
                                const std::string& log_message) {
    if (cancelled_ || IsKilledForShutdown()) return;

    // Centralized neutral breaker release for deterministic policy
    // rejects. Idempotent — ReleaseBreakerAdmissionNeutral is a no-op
    // when no admission is held. Runs BEFORE the H2 retryable-
    // disconnect routing below so these terminal codes don't leak
    // into MaybeRetry.
    if (result_code == RESULT_H2_METHOD_NOT_SUPPORTED ||
        result_code == RESULT_H2_ALPN_NOT_NEGOTIATED) {
        ReleaseBreakerAdmissionNeutral();
    }

    // H2 transport-level failures arrive here through sink->OnError —
    // unlike H1, which detects transport failure inside OnUpstreamData
    // and calls MaybeRetry(UPSTREAM_DISCONNECT) directly before the sink
    // ever sees an error. Bring H2 to feature parity: route every
    // H2-retryable code through MaybeRetry. The state guard rejects a
    // late OnError fired from a stream-close callback after a previous
    // attempt's terminal delivery (Cleanup → ResetStream → sink=nullptr
    // is the primary defense; the local guard makes the invariant
    // explicit). Cleanup() inside MaybeRetry's success branch tears
    // down the H2 stream state; its retry-not-allowed branch falls
    // through to DeliverTerminalError.
    if (h2_path_ && !response_committed_ &&
        state_ != State::FAILED && state_ != State::COMPLETE &&
        IsH2RetryableCode(result_code)) {
        ReportBreakerOutcome(result_code);
        MaybeRetry(MapH2CodeToRetryCondition(result_code));
        return;
    }

    DeliverTerminalError(result_code, log_message);
}

void ProxyTransaction::OnRequestSubmitted() {
    if (cancelled_ || IsKilledForShutdown()) return;
    if (!h2_path_) return;  // H1 infers send completion from socket drain

    // Set BEFORE generation bump: a late OnRequestBodyProgress
    // dispatched in the same callback chain sees the flag and
    // skips re-arming the just-killed closure.
    h2_request_fully_sent_ = true;
    ++h2_send_stall_generation_;

    // Only arm response-timeout if we're transitioning OUT of
    // SENDING_REQUEST here. If OnHeaders already fired (early-headers
    // case: peer responded before our END_STREAM), state has already
    // advanced past SENDING_REQUEST and headers are in hand — the
    // wait-for-headers phase is over. Arming a fresh response-timeout
    // here would resurrect a header-phase timer in the body phase.
    const bool was_sending = (state_ == State::SENDING_REQUEST);
    if (was_sending) {
        state_ = State::AWAITING_RESPONSE;
    }
    if (was_sending && !h2_response_timeout_armed_) {
        // Mirror H1's OnUpstreamWriteComplete contract exactly:
        // response_timeout_ms > 0 → arm with that budget;
        // response_timeout_ms == 0 → clear the deadline entirely so
        // long-poll / SSE / unbounded-response upstreams aren't capped.
        // The send-stall fallback budget is for the PRE-submit phase
        // only — a transport-stuck request never reaches this method
        // under the deferred-drain dispatch semantic (sink virtuals
        // fire from real wire-drain callbacks; a stuck transport
        // keeps the send-stall closure armed).
        if (config_.response_timeout_ms > 0) {
            ArmResponseTimeout();
            h2_response_timeout_armed_ = true;
        } else {
            ClearResponseTimeout();
            h2_response_timeout_armed_ = false;
        }
    }
}

void ProxyTransaction::OnRequestBodyProgress(size_t bytes_drained) {
    if (cancelled_ || IsKilledForShutdown()) return;
    body_bytes_written_to_upstream_ += bytes_drained;
    if (!h2_path_) return;
    if (h2_request_fully_sent_) return;
    // Pure-timestamp refresh: the in-flight send-stall closure
    // inspects this on fire and re-queues itself if progress was
    // observed. No EnQueueDelayed call here — the heap stays at
    // one closure per request regardless of upload size.
    h2_last_progress_at_ = std::chrono::steady_clock::now();
}

void ProxyTransaction::OnRequestHeadersSubmitted() {
    if (cancelled_ || IsKilledForShutdown()) return;
    request_headers_submitted_ = true;
}

void ProxyTransaction::OnRequestBodySourceConsumed(size_t bytes) {
    if (cancelled_ || IsKilledForShutdown()) return;
    body_bytes_read_from_source_ += bytes;
}

std::function<void(int, const std::string&)>
ProxyTransaction::MakeDeferredErrorCallback() {
    // INVARIANT: invoked via virtual dispatch on `sink` from inside
    // SubmitStreamingRequest, which runs on the OnCheckoutReady strong-self
    // capture's call stack. shared_from_this() cannot throw here.
    auto self = shared_from_this();
    return [self](int code, const std::string& msg) {
        // OnError's `cancelled_ || IsKilledForShutdown` guard makes a
        // client-abort-after-EnQueue harmless.
        self->OnError(code, msg);
    };
}

void ProxyTransaction::ArmH2SendStallDeadline(int budget_ms) {
    const uint64_t send_stall_gen = ++h2_send_stall_generation_;
    QueueH2SendStallClosure(send_stall_gen, budget_ms);
}

void ProxyTransaction::QueueH2SendStallClosure(uint64_t generation,
                                                int delay_ms) {
    if (!dispatcher_) return;
    std::weak_ptr<ProxyTransaction> weak_self = weak_from_this();
    dispatcher_->EnQueueDelayed(
        [weak_self, generation]() {
            auto self = weak_self.lock();
            if (!self) return;
            if (self->cancelled_ || self->IsKilledForShutdown()) return;
            if (generation != self->h2_send_stall_generation_) return;

            // Progress check: if we've seen a DATA flush within the
            // budget, the upload is healthy — re-queue ourselves
            // for the remaining time without bumping the generation.
            // Cleanup / OnRequestSubmitted will still invalidate us
            // by bumping the generation; the same-generation re-
            // queue stays valid until they do.
            const auto now = std::chrono::steady_clock::now();
            const auto budget = std::chrono::milliseconds(
                self->h2_stall_budget_ms_);
            const auto since_progress = now - self->h2_last_progress_at_;
            if (since_progress < budget) {
                const auto remaining =
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        budget - since_progress);
                // Clamp to at least 1ms so we don't busy-loop on
                // floating-point edge cases (since_progress == 0).
                const int remaining_ms = std::max<int>(
                    1, static_cast<int>(remaining.count()));
                self->QueueH2SendStallClosure(generation, remaining_ms);
                return;
            }

            // Real stall: peer connected but not draining body.
            // Surface as RESULT_RESPONSE_TIMEOUT to mirror H1's
            // SetDeadline-driven semantic; route through the
            // retryable-timeout path so retry_on_timeout applies and
            // the client sees 504, not 502.
            if (self->state_ == State::SENDING_REQUEST ||
                self->state_ == State::AWAITING_RESPONSE ||
                self->state_ == State::RECEIVING_BODY) {
                self->ReportBreakerOutcome(RESULT_RESPONSE_TIMEOUT);
                self->MaybeRetry(
                    RetryPolicy::RetryCondition::RESPONSE_TIMEOUT);
            } else {
                // Unreachable — Cleanup bumps the generation before
                // any terminal-state transition. Log loud and drop
                // rather than fire OnError on a terminal transaction.
                logging::Get()->error(
                    "ProxyTransaction H2 send-stall closure fired in "
                    "unexpected state={} client_fd={} service={} — "
                    "dropped (invariant break)",
                    static_cast<int>(self->state_),
                    self->client_fd_, self->service_name_);
            }
        },
        std::chrono::milliseconds(delay_ms));
}

void ProxyTransaction::DeliverTerminalError(int result_code,
                                              const std::string& log_message) {
    if (cancelled_ || IsKilledForShutdown()) return;
    InvalidateStreamTimers();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time_);

    logging::Get()->warn("ProxyTransaction error client_fd={} service={} "
                         "result={} attempt={} duration={}ms: {}",
                         client_fd_, service_name_, result_code,
                         attempt_, duration.count(), log_message);

    // Report the outcome if an admission is still held. Most error paths
    // call ReportBreakerOutcome themselves BEFORE reaching here (so a
    // retry's ConsultBreaker sees the fresh signal) — this is a safety
    // net for paths that skipped reporting (RESULT_SEND_FAILED,
    // RESULT_RESPONSE_TIMEOUT from on-upstream-data paths, MaybeRetry's
    // retry-not-allowed fallback). ReportBreakerOutcome is idempotent.
    ReportBreakerOutcome(result_code);

    state_ = State::FAILED;
    // End the per-attempt CLIENT span with the closed-enum error.type
    // string; FinalizeAttemptSpan marks SpanStatusCode::ERROR and
    // (when shutdown won the kill race) DropWithoutEnd.
    FinalizeAttemptSpan(/*status_code=*/0, ErrorTypeForResult(result_code));
    if (response_committed_ && relay_mode_ == RelayMode::STREAMING) {
        using AbortReason = HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::AbortReason;
        AbortReason reason = AbortReason::UPSTREAM_ERROR;
        if (result_code == RESULT_UPSTREAM_DISCONNECT ||
            result_code == RESULT_TRUNCATED_RESPONSE) {
            // Both are framing/short-read violations on the upstream
            // body — surface them as UPSTREAM_TRUNCATED so downstream
            // observability and abort labels distinguish them from
            // generic upstream errors. RESULT_TRUNCATED_RESPONSE is
            // the application-level (defense-in-depth) detection;
            // RESULT_UPSTREAM_DISCONNECT is nghttp2's enforcement
            // path. Same semantic, same abort label.
            reason = AbortReason::UPSTREAM_TRUNCATED;
        } else if (result_code == RESULT_RESPONSE_TIMEOUT) {
            reason = AbortReason::UPSTREAM_TIMEOUT;
        }
        stream_sender_.Abort(reason);
        complete_cb_invoked_.store(true, std::memory_order_release);
        complete_cb_ = nullptr;
        Cleanup();
        return;
    }
    HttpResponse error_response = (result_code == RESULT_CIRCUIT_OPEN)
        ? MakeCircuitOpenResponse()
        : MakeErrorResponse(result_code);
    DeliverResponse(std::move(error_response));
}

void ProxyTransaction::MaybeRetry(RetryPolicy::RetryCondition condition) {
    // Short-circuit on cancellation — no point retrying against a
    // disconnected client.
    if (cancelled_) return;

    if (is_streaming_request_) {
        // Streaming retries are gated on whether body bytes reached the
        // upstream. The three cases produce distinct result codes so
        // operators can distinguish the failure reason from logs/metrics.
        const bool replay_safe = retry_policy_.IsMethodRetryableForReplay(method_);
        const bool headers_queued = request_headers_submitted_;

        if (source_consumed_) {
            logging::Get()->debug(
                "streaming retry blocked: source consumed drained={}",
                body_bytes_written_to_upstream_);
            DeliverTerminalError(RESULT_RETRY_DENIED_STREAMING_SOURCE_CONSUMED,
                                 "streaming source consumed before failure");
            return;
        }
        if (body_bytes_written_to_upstream_ > 0) {
            logging::Get()->debug(
                "streaming retry blocked: body bytes on wire count={}",
                body_bytes_written_to_upstream_);
            DeliverTerminalError(RESULT_RETRY_DENIED_STREAMING_BODY_ON_WIRE,
                                 "streaming body bytes already on wire");
            return;
        }
        if (headers_queued && !replay_safe) {
            logging::Get()->debug(
                "streaming retry blocked: non-idempotent with HEADERS queued method={}",
                method_);
            DeliverTerminalError(RESULT_RETRY_DENIED_NON_IDEMPOTENT_HEADERS_QUEUED,
                                 "non-idempotent method with HEADERS already queued");
            return;
        }
        if (headers_queued) {
            // Idempotent with HEADERS queued but no body on wire —
            // tombstone the in-flight stream/transport and fall through
            // to the normal retry classification below.
            TombstonePreBodyHeadersForRetry_();
        }
    }

    if (retry_policy_.ShouldRetry(attempt_, method_, condition, response_committed_)) {
        if (condition == RetryPolicy::RetryCondition::RESPONSE_5XX) {
            auto snapshot = SnapshotRetryable5xxBody(
                response_head_, response_body_, paused_parse_bytes_);
            pending_retryable_5xx_response_ = true;
            pending_retryable_5xx_head_ = response_head_;
            pending_retryable_5xx_body_ = std::move(snapshot.body);
            pending_retryable_5xx_body_complete_ = snapshot.complete;
            // The keep_held branch below relies on H1's transport-level pause
            // (codec_->PauseParsing + IncReadDisable on the transport) to
            // hold the original 5xx body in case the retry is later rejected.
            // H2 has no equivalent: the multiplexed transport must keep
            // serving sibling streams, lease_ is empty post-DispatchH2 so
            // IncReadDisable is a no-op, and UpstreamH2Codec::PauseParsing
            // only flips a flag nothing reads. Force-clearing the holding
            // flag steers MaybeRetry into the Cleanup-driven path: ResetStream
            // cleanly cancels the in-flight body and the retry attempt
            // actually contacts the upstream. The trade-off is that an H2
            // retry-rejection delivers the headers-only snapshot rather than
            // the full upstream 5xx body — same trade-off the H2 OnHeaders
            // synchronous-decision path already accepts.
            if (h2_path_) {
                // H2 retry path never holds the prior 5xx body — there is
                // no equivalent of H1's lease+PauseParsing+IncReadDisable
                // backpressure for multiplexed streams (sibling streams
                // must keep flowing), so force-complete the pending
                // body so MaybeRetry's Cleanup-driven path runs cleanly.
                pending_retryable_5xx_body_complete_ = true;
            }
            holding_retryable_5xx_response_ =
                !pending_retryable_5xx_body_complete_;
            held_retryable_5xx_saw_eof_ = false;
        } else {
            ClearPendingRetryable5xxResponse();
        }
        // End the previous attempt's CLIENT span BEFORE attempt_++. The
        // next AttemptCheckout allocates a fresh span keyed on the new
        // attempt number; without this, the prior attempt would leak
        // into ~ProxyTransaction without End() / DropWithoutEnd. Map
        // RetryCondition to the closed-enum error.type label, EXCEPT
        // for RESPONSE_5XX which carries the upstream status instead.
        if (condition == RetryPolicy::RetryCondition::RESPONSE_5XX) {
            FinalizeAttemptSpan(response_head_.status_code, /*error_type=*/"");
        } else {
            const char* prev_error = "upstream_error";
            switch (condition) {
                case RetryPolicy::RetryCondition::CONNECT_FAILURE:
                    prev_error = "connect_failure"; break;
                case RetryPolicy::RetryCondition::UPSTREAM_DISCONNECT:
                    prev_error = "upstream_disconnect"; break;
                case RetryPolicy::RetryCondition::RESPONSE_TIMEOUT:
                    prev_error = "timeout"; break;
                case RetryPolicy::RetryCondition::RESPONSE_5XX:
                    break;
            }
            FinalizeAttemptSpan(/*status_code=*/0, prev_error);
        }
        // Bump reactor.upstream.retries with {service, reason}.
        // The closed-enum `reason` label aligns with the RetryCondition
        // taxonomy + retry-budget-exhaustion + breaker-open (see the
        // else-branch below for the latter two — those are NOT retries
        // but rejections of would-be retries; only the retry-accepted
        // path bumps here).
        if (auto* mgr = obs_manager()) {
            const auto& cat = mgr->catalog();
            if (cat.reactor_upstream_retries != nullptr) {
                const char* reason = "unknown";
                switch (condition) {
                    case RetryPolicy::RetryCondition::CONNECT_FAILURE:
                        reason = "connect_failure"; break;
                    case RetryPolicy::RetryCondition::UPSTREAM_DISCONNECT:
                        reason = "upstream_disconnect"; break;
                    case RetryPolicy::RetryCondition::RESPONSE_TIMEOUT:
                        reason = "timeout"; break;
                    case RetryPolicy::RetryCondition::RESPONSE_5XX:
                        reason = "response_5xx"; break;
                }
                cat.reactor_upstream_retries->Add(1.0, {
                    {"reactor.upstream.service", service_name_},
                    {"reason", reason},
                });
            }
        }
        attempt_++;

        logging::Get()->info("ProxyTransaction retrying client_fd={} "
                             "service={} attempt={} condition={}",
                             client_fd_, service_name_, attempt_,
                             static_cast<int>(condition));

        // Release the completed attempt immediately so backoff does not pin a
        // checked-out upstream lease or keep retry/in-flight accounting active
        // for work that is merely waiting to retry. The exception is a
        // retryable 5xx whose saved fallback body is still incomplete: in that
        // case we keep the original response paused so a later local retry
        // reject can resume the real upstream 5xx instead of replaying a
        // truncated snapshot.
        bool keep_retryable_5xx_held =
            condition == RetryPolicy::RetryCondition::RESPONSE_5XX &&
            holding_retryable_5xx_response_;
        if (keep_retryable_5xx_held) {
            ReleaseAttemptAccounting();
        } else {
            if (condition == RetryPolicy::RetryCondition::RESPONSE_5XX) {
                holding_retryable_5xx_response_ = false;
                held_retryable_5xx_saw_eof_ = false;
            } else {
                ClearPendingRetryable5xxResponse();
            }
            Cleanup();
            ResetForRetryAttempt();
        }

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
                    if (self->holding_retryable_5xx_response_) {
                        self->BeginRetryAttemptFromHeld5xx();
                        return;
                    }
                    self->AttemptCheckout();
                },
                delay);
            if (!enqueued) {
                // Dispatcher stopped — task was silently dropped.
                // Deliver an error so the transaction doesn't die
                // without invoking complete_cb_.
                if (condition == RetryPolicy::RetryCondition::RESPONSE_5XX) {
                    if (ResumeHeldRetryable5xxResponse(
                            "retry_backoff_dispatcher_stopped")) {
                        return;
                    }
                    if (DeliverPendingRetryable5xxResponse(
                            "retry_backoff_dispatcher_stopped")) {
                        return;
                    }
                }
                OnError(RESULT_CHECKOUT_FAILED,
                        "Dispatcher stopped during retry backoff");
            }
        } else if (delay.count() > 0) {
            if (condition == RetryPolicy::RetryCondition::RESPONSE_5XX) {
                if (ResumeHeldRetryable5xxResponse(
                        "retry_backoff_dispatcher_unavailable")) {
                    return;
                }
                if (DeliverPendingRetryable5xxResponse(
                        "retry_backoff_dispatcher_unavailable")) {
                    return;
                }
            }
            OnError(RESULT_CHECKOUT_FAILED,
                    "Dispatcher unavailable for retry backoff");
        } else {
            // Zero delay (connection-level first retry): immediate
            logging::Get()->debug(
                "ProxyTransaction immediate retry client_fd={} "
                "service={} attempt={} condition={}",
                client_fd_, service_name_, attempt_,
                static_cast<int>(condition));
            if (condition == RetryPolicy::RetryCondition::RESPONSE_5XX &&
                holding_retryable_5xx_response_) {
                BeginRetryAttemptFromHeld5xx();
            } else {
                AttemptCheckout();
            }
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
                ClearPendingRetryable5xxResponse();
                auto duration = std::chrono::duration_cast<
                    std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - start_time_);
                logging::Get()->warn("ProxyTransaction upstream 5xx final "
                                     "client_fd={} service={} status={} "
                                     "attempt={} duration={}ms",
                                     client_fd_, service_name_,
                                     response_head_.status_code,
                                     attempt_, duration.count());
                state_ = State::COMPLETE;
                // Finalize the CLIENT span with the real upstream status
                // BEFORE Cleanup's backstop. Without this the dtor backstop
                // labels the span error.type="abandoned", masking the actual
                // 5xx — exactly the case where operators need the real code.
                FinalizeAttemptSpan(response_head_.status_code,
                                     /*error_type=*/"");
                HttpResponse client_response = BuildClientResponse();
                DeliverResponse(std::move(client_response));
                return;
            }
    }

    // Use DeliverTerminalError instead of OnError so we don't bounce
    // back through OnError's H2 retry escape hatch — that would loop
    // when the retry was just denied here.
    DeliverTerminalError(
        result_code,
        "Retry exhausted or not allowed for condition=" +
            std::to_string(static_cast<int>(condition)));
}

void ProxyTransaction::DeliverResponse(HttpResponse response) {
    if (complete_cb_invoked_.load(std::memory_order_acquire)) {
        logging::Get()->warn("ProxyTransaction double-deliver prevented "
                             "client_fd={} service={}",
                             client_fd_, service_name_);
        return;
    }
    complete_cb_invoked_.store(true, std::memory_order_release);
    ClearPendingRetryable5xxResponse();

    // Cleanup BEFORE invoking the completion callback to ensure transport
    // callbacks are cleared and lease is released. This MUST run even
    // when killed — otherwise the lease leaks past shutdown.
    Cleanup();

    // Skip the client delivery when the shutdown kill sweep reached us
    // with complete_cb_ still bound (Cancel's EnQueue may not have
    // run yet, or this site bypassed the upstream-callback gate).
    // The framework abort hook is what closes the request from the
    // client side; firing complete_cb_ now would race the kill sweep's
    // terminal accounting and could deliver to an already-finalized
    // observability snapshot.
    if (IsKilledForShutdown()) {
        complete_cb_ = nullptr;
        return;
    }

    if (complete_cb_) {
        auto cb = std::move(complete_cb_);
        complete_cb_ = nullptr;
        cb(std::move(response));
    }
}

void ProxyTransaction::MarkKilledForShutdown() noexcept {
    // Set the flag first so a subsequent dispatcher-thread caller
    // observing it (any future site that gates on IsKilledForShutdown)
    // sees the shutdown intent. The flag is also load-bearing for
    // Start()'s "snapshot already finalized" branch, which calls this
    // BEFORE publishing tx_weak (i.e., we're not yet wired up to the
    // kill loop) — that path is a noop on Cancel because dispatcher_
    // operations are still safe.
    kill_for_shutdown_.store(true, std::memory_order_release);
    // Cancel() touches dispatcher-thread-only state (cancelled_,
    // complete_cb_, retry timers, lease release). The kill loop runs
    // from the stopper thread, so we must hop. dispatcher_ is non-
    // owning and outlives the transaction (per the field comment), so
    // the EnQueue is safe even though MarkKilledForShutdown can fire
    // very late in shutdown.
    if (!dispatcher_) return;
    // If we're already on the owning dispatcher (e.g. Start() called
    // us synchronously after observing snap.finalized), Cancel inline:
    // letting Start go on to AttemptCheckout / write the upstream
    // request just to undo it on the next event-loop tick wastes pool
    // capacity and IO. Off-thread (the common kill-loop path) we hop.
    if (dispatcher_->is_on_loop_thread()) {
        try {
            Cancel();
        } catch (...) {
            // Cancel is noexcept-shaped in practice but defend against
            // future changes — dropping here keeps MarkKilledForShutdown
            // noexcept-safe.
        }
        return;
    }
    std::weak_ptr<ProxyTransaction> weak = weak_from_this();
    try {
        dispatcher_->EnQueue([weak]() {
            if (auto self = weak.lock()) {
                self->Cancel();
            }
        });
    } catch (const std::exception& e) {
        // Dispatcher loop already stopped — Cancel() will not run.
        // kill_for_shutdown_ stays observable to the terminal-callback
        // gates (OnHeaders / OnBodyChunk / OnError / DeliverResponse
        // etc.) so any callbacks that fire on a still-live transport
        // short-circuit. The transaction is destroyed with its
        // connection; the lease, retry token, and breaker admission
        // are released by the destructor's tear-down. Demoted to
        // debug so a drain-timed-out shutdown doesn't spam the log
        // with one warn per surviving transaction.
        try {
            logging::Get()->debug(
                "ProxyTransaction kill EnQueue skipped (dispatcher stopped) "
                "client_fd={} service={}: {}",
                client_fd_, service_name_, e.what());
        } catch (...) {}
    } catch (...) {
        try {
            logging::Get()->debug(
                "ProxyTransaction kill EnQueue skipped (unknown exception) "
                "client_fd={} service={}",
                client_fd_, service_name_);
        } catch (...) {}
    }
}

void ProxyTransaction::Cancel() {
    if (cancelled_ || complete_cb_invoked_.load(std::memory_order_acquire)) {
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
    complete_cb_invoked_.store(true, std::memory_order_release);
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
    InvalidateStreamTimers();
    ClearPendingRetryable5xxResponse();
    // Release any held breaker admission neutrally. Cancel() is always
    // a LOCAL termination — client disconnect, framework-level abort,
    // H2 stream reset, etc. Even when we poisoned a pooled connection
    // mid-request, counting that as an upstream-health failure would
    // trip the breaker against a backend that may be perfectly healthy
    // (browser cancels, user-initiated timeouts, etc. are all common
    // causes). Client-initiated aborts must be neutral from the breaker's perspective.
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
    // End the per-attempt CLIENT span with the closed-enum
    // `client_disconnect` label so cancellation surfaces distinctly
    // from upstream-initiated errors. DropWithoutEnd inside if the
    // shutdown kill loop won the race.
    FinalizeAttemptSpan(/*status_code=*/0, "client_disconnect");
    if (response_committed_ && relay_mode_ == RelayMode::STREAMING) {
        stream_sender_.Abort(
            HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::AbortReason::
                CLIENT_DISCONNECT);
    }
    // Release the upstream lease back to the pool (or destroy it if
    // poisoned) and clear transport callbacks so any in-flight upstream
    // bytes land harmlessly.
    Cleanup();
}

void ProxyTransaction::Cleanup() {
    // Backstop for the per-attempt CLIENT span. Several early-return
    // paths (held-5xx delivery via DeliverPendingRetryable5xxResponse →
    // DeliverResponse) skip the explicit FinalizeAttemptSpan and would
    // otherwise leak a span without End() through ~ProxyTransaction.
    // No-op when an explicit Finalize* already cleared upstream_span.
    //
    // ~ProxyTransaction is implicitly noexcept (C++17); FinalizeAttemptSpan
    // can allocate (Histogram::Record / End / SetAttribute), so any throw
    // here would std::terminate the process. Drop the span without End()
    // on throw — losing the span is strictly better than process death.
    if (current_attempt_.upstream_span) {
        try {
            FinalizeAttemptSpan(/*status_code=*/0, "abandoned");
        } catch (...) {
            if (current_attempt_.upstream_span) {
                current_attempt_.upstream_span->DropWithoutEnd();
                current_attempt_.upstream_span.reset();
            }
            logging::Get()->error(
                "ProxyTransaction::Cleanup backstop FinalizeAttemptSpan "
                "threw; dropped span without End() to keep destructor "
                "noexcept");
        }
    }
    InvalidateStreamTimers();
    stream_sender_.SetDrainListener(nullptr);
    paused_parse_bytes_.clear();

    // Release any retry-budget token held by the attempt that just
    // ended. Must happen BEFORE the next TryConsumeRetry in MaybeRetry
    // so the new attempt sees accurate retries_in_flight. Idempotent
    // via the retry_token_held_ flag.
    ReleaseRetryToken();

    // Release the in-flight guard from the just-ended attempt. If
    // MaybeRetry schedules a delayed backoff, the gap between Cleanup
    // and the eventual AttemptCheckout (which would move-assign a
    // fresh guard) holds the old slot in `retry_budget_->in_flight_`
    // for the entire backoff sleep. That inflates the effective
    // denominator of the percent-cap formula, weakening the budget
    // exactly during retry storms. Move-assign from a default
    // (empty) guard decrements the old counter immediately.
    inflight_guard_ = CIRCUIT_BREAKER_NAMESPACE::RetryBudget::InFlightGuard{};

    // H2 path: two leases are in flight.
    //   (1) Transport lease — donated to the UpstreamH2Connection for its
    //       full lifetime at dispatch time; its callbacks are bound to the
    //       H2 session and must NOT be touched here. Issue RST_STREAM so
    //       the session can continue serving sibling streams.
    //   (2) Per-stream h2_lease_ — holds the stream slot on the H2 session.
    //       Released explicitly via h2_lease_.Release() below so the slot
    //       frees immediately rather than waiting for the lease destructor.
    if (h2_path_) {
        if (h2_stream_id_ >= 0) {
            if (auto* h2 = h2_lease_.GetH2Connection()) {
                h2->ResetStream(h2_lease_.GetH2StreamId());
            }
        }
        h2_stream_id_ = -1;
        // Release the lease BEFORE flipping h2_path_=false at the end
        // of this block. The lease destructor's ReturnH2Stream call
        // logs at debug-level (slot-release admission is the walker's
        // job via RunDeferredEraseWalk); donated leases are skipped
        // automatically via MarkDonatedToH2 / kind_ check.
        h2_lease_.Release();
        // Bump send-stall generation BEFORE the h2_path_ flip so any
        // in-flight send-stall closure no-ops on its eventual fire.
        // Same pattern as h2_response_timeout_generation_ below.
        ++h2_send_stall_generation_;
        // ClearResponseTimeout MUST run while h2_path_ is still true:
        // its H2 branch keys on h2_path_ to bump
        // h2_response_timeout_generation_, which invalidates any queued
        // EnQueueDelayed task. If we cleared h2_path_ first, the queued
        // task would survive — fire later against this transaction (now
        // possibly mid-retry on the H1 path or already destructed) and
        // produce a spurious RESPONSE_TIMEOUT against the wrong attempt.
        ClearResponseTimeout();
        // Reset the arm-once flag so a subsequent retry attempt that
        // lands back on H2 arms response-timeout fresh (otherwise the
        // first OnHeaders/OnRequestSubmitted would skip ArmResponseTimeout
        // because the flag is left over from the prior attempt).
        h2_response_timeout_armed_ = false;
        h2_request_fully_sent_ = false;
        // Reset h2_path_ so a subsequent retry attempt that lands on H1
        // (e.g. ALPN renegotiated, or the H2 connection died and prefer=auto's
        // next probe selects http/1.1) goes through the H1 lease-release
        // branch on its own Cleanup. Without this reset the H1 lease leaks.
        h2_path_ = false;
        // Cancelled mid-stream H2 requests are neutral from the breaker's
        // perspective — RST_STREAM is a client-initiated abort, not an
        // upstream failure. Release any held admission token so the slot
        // is not stranded. Idempotent when OnResponseComplete already ran.
        ReleaseBreakerAdmissionNeutral();
    } else if (lease_) {
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
                // A returned keep-alive transport immediately falls back to the
                // pool's idle on_message callback, which force-closes on any
                // unexpected upstream bytes. Keep a small cap in place so an
                // idle pooled socket cannot buffer an unbounded late response
                // burst before that callback runs.
                transport->SetMaxInputSize(MAX_BUFFER_SIZE);
                ClearResponseTimeout();
            }
            if (conn->IsReadDisabled()) {
                conn->DecReadDisable();
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

    if (body_stream_ &&
        (state_ == State::FAILED || state_ == State::COMPLETE)) {
        // Abort if the REQUEST side hasn't reached terminal sent state.
        // Only fires on terminal Cleanup (FAILED/COMPLETE), not on mid-
        // retry Cleanup where body_stream_ must survive for the next
        // attempt. Request fully-sent flag is path-specific (h1 vs h2)
        // and is set only when the final framing has been handed to the
        // transport or nghttp2 data-source. After that point an abort
        // here would be a no-op against producers but a misleading
        // signal to upstream peers — skip it.
        const bool request_fully_sent =
            (h2_path_ ? h2_request_fully_sent_ : h1_request_fully_sent_);
        if (!request_fully_sent) {
            body_stream_->Abort("proxy_transaction_cleanup");
        }
        body_stream_.reset();
    }
}

void ProxyTransaction::TombstonePreBodyHeadersForRetry_() {
    if (h2_path_ && h2_stream_id_ > 0) {
        if (auto* h2 = h2_lease_.GetH2Connection()) {
            h2->ResetStream(h2_stream_id_);
            // ResetStream calls DropDrainEntriesForStream and marks
            // pending_erase_, but it does NOT invoke RunDeferredEraseWalk.
            // The walker only fires from HandleBytes tails and from submit-
            // failure cleanup. Without an explicit walker enqueue, the
            // pending_erase entry sits in pending_erase_streams_ and
            // active_streams_ stays elevated until the next inbound-bytes
            // arrival. Under pool.max_connections=1 with tight stream caps
            // that delay wedges the next dispatch. Enqueue a walker run so
            // the slot frees promptly.
            //
            // Single conn_alive_ token is correct: the queued work only
            // touches h2->RunDeferredEraseWalk(), which dereferences ONLY
            // the H2 connection — not the partition. Asymmetric with the
            // lease-construction site that captures BOTH partition_alive
            // AND conn_alive because the lease-release path traverses
            // partition_. Intentional asymmetry, not a bug.
            if (auto* uc = h2->transport()) {
                if (auto t = uc->GetTransport()) {
                    if (auto* d = t->GetDispatcher()) {
                        auto alive = h2->alive_token();
                        d->EnQueue([h2, alive]() {
                            if (!alive ||
                                !alive->load(std::memory_order_acquire))
                                return;
                            h2->RunDeferredEraseWalk();
                        });
                    }
                }
            }
        }
    } else {
        // H1: poison the upstream connection so the pool cannot reuse a
        // half-sent request. lease_ is value-typed UpstreamLease
        // (include/upstream/proxy_transaction.h), so .Get() not ->Get().
        // MarkClosing() lives on UpstreamConnection, not ConnectionHandler.
        if (auto* uc = lease_.Get()) {
            uc->MarkClosing();
        }
    }
}

void ProxyTransaction::ReleaseAttemptAccounting() {
    ReleaseRetryToken();
    inflight_guard_ = CIRCUIT_BREAKER_NAMESPACE::RetryBudget::InFlightGuard{};
}

void ProxyTransaction::ReleaseHeldRetryable5xxTransport() {
    InvalidateStreamTimers();
    stream_sender_.SetDrainListener(nullptr);
    paused_parse_bytes_.clear();

    if (!lease_) {
        return;
    }

    auto* conn = lease_.Get();
    if (conn) {
        auto transport = conn->GetTransport();
        if (transport) {
            transport->SetOnMessageCb(nullptr);
            transport->SetCompletionCb(nullptr);
            transport->SetWriteProgressCb(nullptr);
            transport->SetMaxInputSize(MAX_BUFFER_SIZE);
            ClearResponseTimeout();
        }
        if (conn->IsReadDisabled()) {
            conn->DecReadDisable();
        }
        if (poison_connection_) {
            conn->MarkClosing();
        }
    }
    lease_.Release();
}

void ProxyTransaction::ResetForRetryAttempt() {
    codec_->Reset();
    // Re-apply request method after reset — llhttp_init() zeroes
    // parser.method, so HEAD responses would be parsed as if they
    // carry a body, causing the retried request to hang.
    codec_->SetRequestMethod(method_);
    codec_->SetSink(this);
    poison_connection_ = false;
    relay_mode_ = RelayMode::BUFFERED;
    response_headers_seen_ = false;
    response_committed_ = false;
    body_complete_ = false;
    retry_from_headers_pending_ = false;
    response_head_ = {};
    response_body_.clear();
    response_trailers_.clear();
    paused_parse_bytes_.clear();
    InvalidateStreamTimers();
    sse_stream_ = false;
}

void ProxyTransaction::ClearPendingRetryable5xxResponse() {
    pending_retryable_5xx_response_ = false;
    pending_retryable_5xx_head_ = {};
    pending_retryable_5xx_body_.clear();
    pending_retryable_5xx_body_complete_ = false;
}

bool ProxyTransaction::DeliverPendingRetryable5xxResponse(
    const char* reject_source) {
    if (!pending_retryable_5xx_response_) {
        return false;
    }

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time_);
    logging::Get()->warn(
        "ProxyTransaction relaying stored upstream 5xx client_fd={} service={} "
        "status={} attempt={} duration={}ms reject_source={}",
        client_fd_, service_name_, pending_retryable_5xx_head_.status_code,
        attempt_, duration.count(), reject_source);

    state_ = State::COMPLETE;
    std::string body = pending_retryable_5xx_body_;
    HttpResponse response = BuildResponseFromHead(
        pending_retryable_5xx_head_, !body.empty(), &body);
    DeliverResponse(std::move(response));
    return true;
}

bool ProxyTransaction::ResumeHeldRetryable5xxResponse(
    const char* reject_source) {
    if (!holding_retryable_5xx_response_) {
        return false;
    }

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time_);
    logging::Get()->warn(
        "ProxyTransaction abandoning retry and resuming upstream 5xx "
        "client_fd={} service={} status={} attempt={} duration={}ms "
        "reject_source={}",
        client_fd_, service_name_, response_head_.status_code, attempt_,
        duration.count(), reject_source);

    holding_retryable_5xx_response_ = false;
    bool saw_eof = held_retryable_5xx_saw_eof_;
    held_retryable_5xx_saw_eof_ = false;
    ClearPendingRetryable5xxResponse();
    state_ = State::RECEIVING_BODY;

    if (relay_mode_ == RelayMode::STREAMING && !response_committed_) {
        if (!CommitStreamingResponse()) {
            logging::Get()->debug(
                "ProxyTransaction held 5xx streaming commit aborted locally "
                "client_fd={} service={} status={} attempt={}",
                client_fd_, service_name_, response_head_.status_code, attempt_);
            poison_connection_ = true;
            state_ = State::FAILED;
            stream_sender_.Abort(
                HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::AbortReason::UPSTREAM_ERROR);
            complete_cb_invoked_.store(true, std::memory_order_release);
            complete_cb_ = nullptr;
            Cleanup();
            return true;
        }
    }

    if (!IsNoBodyResponse(response_head_)) {
        RefreshStreamIdleTimer();
        ArmStreamBudgetTimer();
    }

    if ((!body_complete_ || !paused_parse_bytes_.empty() || saw_eof) &&
        lease_ && lease_.Get() && lease_.Get()->IsReadDisabled()) {
        lease_.Get()->DecReadDisable();
    }

    ResumePausedParsing();
    if (state_ == State::COMPLETE || state_ == State::FAILED) {
        return true;
    }
    if (!body_complete_ &&
        ((response_head_.framing ==
              UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead::Framing::CONTENT_LENGTH &&
          response_head_.expected_length == 0) ||
         response_head_.framing ==
             UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead::Framing::NO_BODY) &&
        paused_parse_bytes_.empty()) {
        // We paused llhttp at headers, before on_message_complete could mark
        // a zero-length / no-body response finished. When retry is abandoned
        // later, there may be no buffered bytes or EOF edge left to drive
        // completion.
        body_complete_ = true;
    }
    if (body_complete_) {
        OnResponseComplete();
        return true;
    }
    if (saw_eof && state_ != State::COMPLETE && state_ != State::FAILED) {
        auto* upstream_conn = lease_.Get();
        auto transport = upstream_conn ? upstream_conn->GetTransport() : nullptr;
        std::string eof;
        OnUpstreamData(transport, eof);
    }
    return true;
}

void ProxyTransaction::BeginRetryAttemptFromHeld5xx() {
    if (cancelled_) return;
    if (!pending_retryable_5xx_body_complete_) {
        // The saved fallback is still partial. Releasing the held upstream
        // response now would risk a later local retry failure replaying a
        // truncated 5xx body, so prefer relaying the original response over
        // starting a replacement attempt we cannot fall back from correctly.
        ResumeHeldRetryable5xxResponse("retryable_5xx_body_incomplete");
        return;
    }

    state_ = State::CHECKOUT_PENDING;
    if (!PrepareAttemptAdmission()) {
        return;
    }

    holding_retryable_5xx_response_ = false;
    held_retryable_5xx_saw_eof_ = false;
    ReleaseHeldRetryable5xxTransport();
    ResetForRetryAttempt();
    ActivateAttemptTracking();
    EnsureCheckoutCancelToken();
    // Mirror AttemptCheckout: allocate a fresh CLIENT span + rebuild
    // outbound trace headers so the held-5xx retry surfaces as a
    // distinct span_id on the wire. Without this the retry is
    // invisible in the trace tree and replays the prior attempt's
    // traceparent on its serialized request.
    SetupAttemptObservability();
    StartCheckoutAsync();
}

HttpResponse ProxyTransaction::BuildClientResponse() {
    return BuildResponseFromHead(response_head_, true, &response_body_);
}

HttpResponse ProxyTransaction::BuildResponseFromHead(
    const UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead& head,
    bool include_body,
    std::string* body) const {
    HttpResponse response;
    response.Status(head.status_code, head.status_reason);

    auto rewritten = header_rewriter_.RewriteResponse(head.headers);
    for (const auto& [name, value] : rewritten) {
        response.AppendHeader(name, value);
    }

    if (ShouldPreserveKnownContentLength(method_, head, include_body)) {
        response.PreserveContentLength();
        if (head.expected_length >= 0 &&
            !FirstHeaderValue(response.GetHeaders(), "content-length")) {
            response.AppendHeader("Content-Length",
                                  std::to_string(head.expected_length));
        }
    }

    if (include_body && body && !body->empty()) {
        response.Body(std::move(*body));
    }
    return response;
}

HttpResponse ProxyTransaction::BuildStreamingHeadersResponse() const {
    HttpResponse response = BuildResponseFromHead(response_head_, false, nullptr);
    // BuildResponseFromHead/HeaderRewriter strips upstream Trailer as a
    // hop-by-hop field. Re-add it only for the one downstream path that will
    // actually serialize a trailer block: HTTP/1.1 with forward_trailers=true.
    if (config_.forward_trailers &&
        client_http_major_ == 1 && client_http_minor_ == 1) {
        response.RemoveHeader("Trailer");
        auto filtered_trailer =
            MergeTrailerDeclarations(response_head_.headers);
        if (filtered_trailer) {
            response.AppendHeader("Trailer", *filtered_trailer);
        }
    }
    return response;
}

bool ProxyTransaction::CommitStreamingResponse() {
    if (response_committed_) return true;
    HttpResponse response = BuildStreamingHeadersResponse();
    int rv = stream_sender_.SendHeaders(response);
    if (rv < 0) {
        return false;
    }
    response_committed_ = true;
    return true;
}

ProxyTransaction::RelayMode ProxyTransaction::DecideRelayMode(
    const UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead& head) const {
    if (config_.buffering == "always") {
        return RelayMode::BUFFERED;
    }
    if (client_http_major_ == 1 && client_http_minor_ == 0 &&
        config_.h10_streaming == "buffer") {
        return RelayMode::BUFFERED;
    }
    if (config_.buffering == "never") {
        return RelayMode::STREAMING;
    }
    if (IsNoBodyResponse(head)) {
        return RelayMode::BUFFERED;
    }
    if (IsSseStream(head)) {
        return RelayMode::STREAMING;
    }
    if (head.framing ==
            UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead::Framing::CHUNKED ||
        head.framing ==
            UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead::Framing::EOF_TERMINATED) {
        return RelayMode::STREAMING;
    }
    if (head.framing ==
            UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead::Framing::CONTENT_LENGTH &&
        head.expected_length >= 0 &&
        static_cast<uint64_t>(head.expected_length) >
            config_.auto_stream_content_length_threshold_bytes) {
        return RelayMode::STREAMING;
    }
    return RelayMode::BUFFERED;
}

bool ProxyTransaction::IsNoBodyResponse(
    const UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead& head) const {
    return method_ == "HEAD" ||
           head.framing ==
               UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead::Framing::NO_BODY;
}

bool ProxyTransaction::ShouldRetryResponse5xx() const {
    if (response_head_.status_code < HttpStatus::INTERNAL_SERVER_ERROR ||
        response_head_.status_code >= 600) {
        return false;
    }
    return retry_policy_.ShouldRetry(
        attempt_, method_, RetryPolicy::RetryCondition::RESPONSE_5XX, false);
}

bool ProxyTransaction::CanRetryResponse5xxNow() {
    bool breaker_live_enabled = slice_ && slice_->config().enabled;
    if (!breaker_live_enabled) {
        return true;
    }
    if (!slice_->config().dry_run &&
        slice_->CurrentState() == CIRCUIT_BREAKER_NAMESPACE::State::OPEN) {
        return false;
    }
    if (!retry_budget_ || slice_->config().dry_run) {
        return true;
    }

    // Optimistic look-ahead only. The retry budget is ultimately enforced by
    // TryConsumeRetry()'s CAS loop when a retry actually executes. These
    // separate atomic loads can race with other traffic, so this helper is
    // intentionally advisory: it only short-circuits obviously-impossible
    // retries before we tear down a retryable upstream 5xx.
    int64_t in_flight_after = retry_budget_->InFlight();
    if (in_flight_after > 0) {
        --in_flight_after;
    }
    int64_t retries_after = retry_budget_->RetriesInFlight();
    if (retry_token_held_ && retries_after > 0) {
        --retries_after;
    }
    int64_t non_retry_after = in_flight_after - retries_after;
    if (non_retry_after < 0) {
        non_retry_after = 0;
    }
    int64_t pct_cap =
        (non_retry_after * retry_budget_->percent()) / 100;
    int64_t cap = std::max<int64_t>(
        retry_budget_->min_concurrency(), pct_cap);
    if (retries_after < cap) {
        return true;
    }

    retry_budget_->RecordSkippedRetry();
    logging::Get()->warn(
        "retry budget exhausted (preflight) service={} in_flight={} "
        "retries_in_flight={} cap={} client_fd={} attempt={}",
        service_name_,
        in_flight_after,
        retries_after,
        cap,
        client_fd_,
        attempt_ + 1);
    return false;
}

bool ProxyTransaction::IsSseStream(
    const UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead& head) const {
    return HeaderValueStartsWith(
        head.headers, "content-type", "text/event-stream");
}

void ProxyTransaction::ProcessHeadersRetryDecision() {
    if (!retry_from_headers_pending_) return;
    retry_from_headers_pending_ = false;
    MaybeRetry(RetryPolicy::RetryCondition::RESPONSE_5XX);
}

void ProxyTransaction::ResumePausedParsing() {
    if (!codec_->IsPaused()) return;
    codec_->ResumeParsing();
    if (paused_parse_bytes_.empty()) return;
    auto pending = std::move(paused_parse_bytes_);
    paused_parse_bytes_.clear();
    auto* upstream_conn = lease_.Get();
    auto transport = upstream_conn ? upstream_conn->GetTransport() : nullptr;
    if (transport) {
        OnUpstreamData(transport, pending);
        return;
    }
    paused_parse_bytes_ = std::move(pending);
    logging::Get()->debug(
        "ProxyTransaction deferred paused parse replay; upstream transport unavailable "
        "client_fd={} service={} buffered_bytes={}",
        client_fd_, service_name_, paused_parse_bytes_.size());
}

void ProxyTransaction::HandleStreamSendResult(
    HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::SendResult result) {
    using SendResult = HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::SendResult;
    if (result != SendResult::ACCEPTED_ABOVE_HIGH_WATER) {
        return;
    }

    // H2 path: the transport is shared across every multiplexed stream,
    // so transport-level IncReadDisable would pause sibling streams when
    // this stream's downstream is slow. nghttp2's auto-WINDOW_UPDATE is
    // on by default in this code path, so the peer's stream-level window
    // tracks the auto-update cadence (~initial_window_size in practice)
    // plus MAX_FRAME_SIZE rather than a hard cap. Disabling auto-update
    // and pausing per-stream consumption via nghttp2_session_consume_stream
    // is the future refinement that would give a strict bound.
    if (h2_path_) {
        return;
    }

    auto* upstream_conn = lease_.Get();
    if (!upstream_conn || upstream_conn->IsReadDisabled()) {
        return;
    }

    SuspendStreamIdleTimer();
    upstream_conn->IncReadDisable();
    codec_->PauseParsing();
    std::weak_ptr<ProxyTransaction> weak_self = weak_from_this();
    stream_sender_.SetDrainListener([weak_self]() {
        auto self = weak_self.lock();
        if (!self) return;
        if (auto* conn = self->lease_.Get()) {
            conn->DecReadDisable();
        }
        self->stream_sender_.SetDrainListener(nullptr);
        self->last_body_progress_at_ = std::chrono::steady_clock::now();
        self->RefreshStreamIdleTimer();
        self->ResumePausedParsing();
    });
}

void ProxyTransaction::SuspendStreamIdleTimer() {
    ++stream_idle_timer_generation_;
    stream_idle_timer_armed_ = false;
}

void ProxyTransaction::RefreshStreamIdleTimer() {
    if (!dispatcher_ || !response_headers_seen_ || body_complete_ ||
        cancelled_ || sse_stream_ ||
        config_.stream_idle_timeout_sec == 0) {
        return;
    }
    if (stream_idle_timer_armed_) {
        return;
    }

    stream_idle_timer_armed_ = true;
    const uint64_t generation = stream_idle_timer_generation_;
    ScheduleStreamIdleCheck(
        generation,
        std::chrono::milliseconds(
            static_cast<int64_t>(config_.stream_idle_timeout_sec) * 1000));
}

void ProxyTransaction::ScheduleStreamIdleCheck(
    uint64_t generation,
    std::chrono::milliseconds delay) {
    std::weak_ptr<ProxyTransaction> weak_self = weak_from_this();
    bool enqueued = dispatcher_->EnQueueDelayed(
        [weak_self, generation]() {
            if (auto self = weak_self.lock()) {
                self->OnStreamIdleTimeout(generation);
            }
        },
        delay);
    if (!enqueued) {
        stream_idle_timer_armed_ = false;
    }
}

void ProxyTransaction::ArmStreamBudgetTimer() {
    ++stream_budget_timer_generation_;
    if (!dispatcher_ || !response_headers_seen_ || body_complete_ ||
        cancelled_ || config_.stream_max_duration_sec == 0) {
        return;
    }

    const uint64_t generation = stream_budget_timer_generation_;
    std::weak_ptr<ProxyTransaction> weak_self = weak_from_this();
    dispatcher_->EnQueueDelayed(
        [weak_self, generation]() {
            if (auto self = weak_self.lock()) {
                self->OnStreamBudgetTimeout(generation);
            }
        },
        std::chrono::milliseconds(
            static_cast<int64_t>(config_.stream_max_duration_sec) * 1000));
}

void ProxyTransaction::InvalidateStreamTimers() {
    ++stream_idle_timer_generation_;
    ++stream_budget_timer_generation_;
    stream_idle_timer_armed_ = false;
}

void ProxyTransaction::OnStreamIdleTimeout(uint64_t generation) {
    if (generation != stream_idle_timer_generation_ || cancelled_ ||
        IsKilledForShutdown() ||
        body_complete_ || !response_headers_seen_ ||
        state_ == State::COMPLETE || state_ == State::FAILED) {
        if (generation == stream_idle_timer_generation_) {
            stream_idle_timer_armed_ = false;
        }
        return;
    }
    auto timeout = std::chrono::milliseconds(
        static_cast<int64_t>(config_.stream_idle_timeout_sec) * 1000);
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - last_body_progress_at_);
    if (elapsed < timeout) {
        auto remaining = timeout - elapsed;
        if (remaining <= std::chrono::milliseconds(0)) {
            remaining = std::chrono::milliseconds(1);
        }
        ScheduleStreamIdleCheck(generation, remaining);
        return;
    }
    stream_idle_timer_armed_ = false;
    logging::Get()->warn(
        "proxy: stream_idle_timeout svc={} idle_sec={} client_fd={} attempt={}",
        service_name_, config_.stream_idle_timeout_sec, client_fd_, attempt_);
    OnError(RESULT_RESPONSE_TIMEOUT, "Stream idle timeout");
}

void ProxyTransaction::OnStreamBudgetTimeout(uint64_t generation) {
    if (generation != stream_budget_timer_generation_ || cancelled_ ||
        IsKilledForShutdown() ||
        body_complete_ || !response_headers_seen_ ||
        state_ == State::COMPLETE || state_ == State::FAILED) {
        return;
    }
    logging::Get()->warn(
        "proxy: stream_max_duration_exceeded svc={} max_sec={} client_fd={} attempt={}",
        service_name_, config_.stream_max_duration_sec, client_fd_, attempt_);
    OnError(RESULT_RESPONSE_TIMEOUT, "Stream max duration exceeded");
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

    // H2 path: schedule a per-transaction dispatcher task. The transport
    // is shared across every multiplexed stream — installing a transport
    // deadline here would tear down sibling streams when one stalls.
    if (h2_path_) {
        if (!dispatcher_) return;
        const uint64_t generation = ++h2_response_timeout_generation_;
        std::weak_ptr<ProxyTransaction> weak_self = weak_from_this();
        dispatcher_->EnQueueDelayed(
            [weak_self, generation]() {
                auto self = weak_self.lock();
                if (!self) return;
                // IsKilledForShutdown check mirrors the send-stall
                // closure: MarkKilledForShutdown sets the kill flag
                // before Cancel() enqueues, so a matured timeout that
                // fires inside that window must not report a breaker
                // failure or trigger MaybeRetry during drain.
                if (self->cancelled_ || self->IsKilledForShutdown()) return;
                if (generation != self->h2_response_timeout_generation_) return;
                logging::Get()->warn(
                    "ProxyTransaction H2 response timeout client_fd={} "
                    "service={} attempt={} stream={}",
                    self->client_fd_, self->service_name_, self->attempt_,
                    self->h2_stream_id_);
                if (self->state_ == State::SENDING_REQUEST ||
                    self->state_ == State::AWAITING_RESPONSE ||
                    self->state_ == State::RECEIVING_BODY) {
                    self->ReportBreakerOutcome(RESULT_RESPONSE_TIMEOUT);
                    self->MaybeRetry(
                        RetryPolicy::RetryCondition::RESPONSE_TIMEOUT);
                } else {
                    self->OnError(RESULT_RESPONSE_TIMEOUT,
                                  "Response timeout");
                }
            },
            std::chrono::milliseconds(budget_ms));
        logging::Get()->debug("ProxyTransaction armed H2 response timeout "
                              "{}ms client_fd={} service={} stream={}",
                              budget_ms, client_fd_, service_name_,
                              h2_stream_id_);
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
    // H2 path: invalidate any queued response-timeout task by bumping
    // the generation. The closure compares against the current value
    // before firing.
    if (h2_path_) {
        ++h2_response_timeout_generation_;
        return;
    }

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
    if (result_code == RESULT_RESPONSE_TOO_LARGE) {
        return HttpResponse::BadGateway();
    }
    if (result_code == RESULT_RETRY_BUDGET_EXHAUSTED) {
        return MakeRetryBudgetResponse();
    }
    if (result_code == RESULT_CIRCUIT_OPEN) {
        // Static factory has no `this`, so it cannot derive Retry-After
        // from slice state or attach X-Upstream-Host. All in-class paths
        // use the non-static MakeCircuitOpenResponse(); reaching this
        // branch means a future caller forgot. Log loud and emit the
        // self-identifying headers we can build without context.
        logging::Get()->error(
            "ProxyTransaction::MakeErrorResponse(RESULT_CIRCUIT_OPEN) "
            "invoked from static context — use MakeCircuitOpenResponse() "
            "to emit full circuit-open headers");
        HttpResponse resp = HttpResponse::ServiceUnavailable();
        resp.Header("X-Circuit-Breaker", "open");
        resp.Header("Connection", "close");
        return resp;
    }
    if (result_code == RESULT_H2_METHOD_NOT_SUPPORTED) {
        // RFC 9113 §8.5: CONNECT pseudo-headers forbid :scheme and :path,
        // but our H2 codec always emits both. Surface the limitation in
        // a dedicated header so operators can detect the rejection
        // without parsing the body. Self-identifying response analogous
        // to X-Circuit-Breaker / X-Retry-Budget-Exhausted.
        HttpResponse resp = HttpResponse::BadGateway();
        resp.Header("X-H2-Limitation", "connect-not-supported");
        return resp;
    }
    if (result_code == RESULT_H2_ALPN_NOT_NEGOTIATED) {
        // Operator configured `http2.prefer = "always"` but peer did
        // not negotiate h2 via ALPN. Deterministic policy reject —
        // self-identifying header analogous to connect-not-supported.
        HttpResponse resp = HttpResponse::BadGateway();
        resp.Header("X-H2-Limitation", "alpn-not-h2");
        return resp;
    }
    if (result_code == RESULT_CHECKOUT_FAILED ||
        result_code == RESULT_SEND_FAILED ||
        result_code == RESULT_PARSE_ERROR ||
        result_code == RESULT_UPSTREAM_DISCONNECT ||
        result_code == RESULT_TRUNCATED_RESPONSE ||
        result_code == RESULT_GOAWAY_UNPROCESSED ||
        result_code == RESULT_GOAWAY_MAYBE_PROCESSED) {
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
                   CIRCUIT_BREAKER_NAMESPACE::State::HALF_OPEN) {
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
    // Render authority via FormatAuthority so IPv6 literals get RFC 3986
    // §3.2.2 bracket wrapping. Byte-identical for hostnames and IPv4.
    resp.Header("X-Upstream-Host",
                NET_DNS_NAMESPACE::DnsResolver::FormatAuthority(
                    upstream_host_, upstream_port_, /*omit_port=*/false));
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
                 CIRCUIT_BREAKER_NAMESPACE::Decision::ADMITTED_PROBE);

    // Emit reactor.circuit_breaker.rejected{service, reason} for every
    // would-reject outcome — including OPEN_DRYRUN, which falls through
    // as admitted but is observable as a shadow-mode trip-decision. The
    // emit fires once per admission, BEFORE the decision-specific
    // response delivery, so any later return branch carries the metric.
    if (const char* rl = CIRCUIT_BREAKER_NAMESPACE::RejectReasonLabel(
            admission.reject_reason)) {
        if (auto* mgr = obs_manager()) {
            const auto& cat = mgr->catalog();
            if (cat.reactor_circuit_breaker_rejected != nullptr) {
                cat.reactor_circuit_breaker_rejected->Add(
                    1.0,
                    {{"service", service_name_}, {"reason", rl}});
            }
        }
    }

    if (admission.decision == CIRCUIT_BREAKER_NAMESPACE::Decision::REJECTED_OPEN) {
        // Hard reject — slice counted it, logged it, and we must not
        // touch the upstream. Emit circuit-open response and DO NOT Report
        // back (would create a feedback loop — our own reject counting
        // as a failure against the already-OPEN slice).
        if (ResumeHeldRetryable5xxResponse("circuit_open")) {
            admission_generation_ = 0;
            return false;
        }
        if (DeliverPendingRetryable5xxResponse("circuit_open")) {
            admission_generation_ = 0;
            return false;
        }
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

bool ProxyTransaction::IsH2RetryableCode(int result_code) noexcept {
    // RESULT_TRUNCATED_RESPONSE: terminal per the constant's public
    // contract — retrying would double-deliver streamed bytes.
    //
    // RESULT_RESPONSE_TIMEOUT: intentionally NOT in this allowlist.
    // Today's two H2 timeout paths bypass IsH2RetryableCode entirely:
    //   (a) The response-wait closure routes retry-eligible states
    //       (SENDING_REQUEST / AWAITING_RESPONSE / RECEIVING_BODY)
    //       through MaybeRetry(RESPONSE_TIMEOUT) directly without
    //       going through OnError → IsH2RetryableCode.
    //   (b) Per-stream idle/budget timeouts only fire post-commit, so
    //       response_committed_ already gates retry off before any
    //       OnError dispatch.
    // INVARIANT: no caller routes RESULT_RESPONSE_TIMEOUT through
    // OnError on the H2 path with `!response_committed_`. Before
    // landing such a call site, ALSO add the code here AND to
    // MapH2CodeToRetryCondition — otherwise retry silently drops
    // even when retry_on_timeout=true.
    switch (result_code) {
        case RESULT_UPSTREAM_DISCONNECT:
        case RESULT_GOAWAY_UNPROCESSED:
        case RESULT_GOAWAY_MAYBE_PROCESSED:
            return true;
        default:
            return false;
    }
}

RetryPolicy::RetryCondition ProxyTransaction::MapH2CodeToRetryCondition(
    int result_code) noexcept {
    // Caller is expected to gate on IsH2RetryableCode first, so this
    // function only ever sees codes from that allowlist. Switch on the
    // allowlist explicitly with no fallthrough — a future addition to
    // IsH2RetryableCode that misses this function triggers the error
    // log instead of silently classifying as UPSTREAM_DISCONNECT.
    switch (result_code) {
        case RESULT_GOAWAY_UNPROCESSED:
            // Connect-style: peer demonstrably never processed the
            // request. First retry runs at zero delay; breaker neutral.
            return RetryPolicy::RetryCondition::CONNECT_FAILURE;
        case RESULT_UPSTREAM_DISCONNECT:
        case RESULT_GOAWAY_MAYBE_PROCESSED:
            // Response-level: peer may have processed. Backoff applies
            // via the policy's idempotency gate.
            return RetryPolicy::RetryCondition::UPSTREAM_DISCONNECT;
        default:
            // Unreachable if IsH2RetryableCode and this switch stay in
            // sync. Log loud and conservative-default to
            // UPSTREAM_DISCONNECT so a future regression surfaces in
            // logs before causing odd retry-cadence behavior.
            logging::Get()->error(
                "MapH2CodeToRetryCondition: unexpected result_code={} "
                "(missing from H2 retry allowlist switch) — defaulting "
                "to UPSTREAM_DISCONNECT", result_code);
            return RetryPolicy::RetryCondition::UPSTREAM_DISCONNECT;
    }
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

    using CIRCUIT_BREAKER_NAMESPACE::FailureKind;

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
        case RESULT_PARSE_ERROR:
        case RESULT_TRUNCATED_RESPONSE:
            // Truncation (peer ended early or violated framing) is an
            // upstream health signal — repeated truncated bodies must
            // contribute to circuit-open just like disconnects and
            // parse errors do. Folds into UPSTREAM_DISCONNECT bucket.
            slice_->ReportFailure(FailureKind::UPSTREAM_DISCONNECT, probe, gen);
            return;

        case RESULT_H2_METHOD_NOT_SUPPORTED:
        case RESULT_H2_ALPN_NOT_NEGOTIATED:
            // Deterministic policy rejects (CONNECT on H2 upstream, or
            // operator-configured prefer=always with peer ALPN!=h2) —
            // no upstream contact, so no health signal. The OnError
            // pre-routing hook already calls
            // ReleaseBreakerAdmissionNeutral; this case is the
            // defensive fallback if a code path slips past the hook.
            slice_->ReportNeutral(probe, gen);
            return;

        case RESULT_GOAWAY_UNPROCESSED:
        case RESULT_GOAWAY_MAYBE_PROCESSED:
            // RFC 9113 §6.8: GOAWAY signals connection-lifecycle, not
            // upstream health. Counting it as a failure would trip
            // breakers when the peer is rolling sessions for ordinary
            // reasons (graceful drain, deploy, idle timeout). The
            // MAYBE_PROCESSED variant is identical for breaker
            // purposes — the per-attempt retry budget enforces the
            // idempotency gate, not the breaker.
            slice_->ReportNeutral(probe, gen);
            return;

        case RESULT_POOL_EXHAUSTED:
        case RESULT_RESPONSE_TOO_LARGE:
            // Local outcomes — no upstream health signal. RESPONSE_TOO_LARGE
            // is the buffered-relay cap, distinct from RESULT_PARSE_ERROR
            // (malformed/truncated upstream wire data), so only the local-cap
            // branch stays neutral here.
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
