#pragma once

#include "common.h"
#include "upstream/upstream_http_codec.h"
#include "upstream/upstream_lease.h"
#include "upstream/header_rewriter.h"
#include "upstream/retry_policy.h"
#include "config/server_config.h"        // ProxyConfig (stored by value)
#include "http/http_callbacks.h"
#include "http/http_response.h"
// <string>, <map>, <unordered_map>, <memory>, <functional>, <chrono> provided by common.h

// Forward declarations
class UpstreamManager;
class ConnectionHandler;

class ProxyTransaction : public std::enable_shared_from_this<ProxyTransaction> {
public:
    // Result codes for internal state tracking
    static constexpr int RESULT_SUCCESS            = 0;
    static constexpr int RESULT_CHECKOUT_FAILED    = -1;
    static constexpr int RESULT_SEND_FAILED        = -2;
    static constexpr int RESULT_PARSE_ERROR        = -3;
    static constexpr int RESULT_RESPONSE_TIMEOUT   = -4;
    static constexpr int RESULT_UPSTREAM_DISCONNECT = -5;

    // Constructor copies all needed fields from client_request (method, path,
    // query, headers, body, params, dispatcher_index, client_ip, client_tls,
    // client_fd). The original HttpRequest is invalidated by parser_.Reset()
    // immediately after the async handler returns -- no references may be kept.
    ProxyTransaction(const std::string& service_name,
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
                     const std::string& static_prefix);
    ~ProxyTransaction();

    // Non-copyable, non-movable
    ProxyTransaction(const ProxyTransaction&) = delete;
    ProxyTransaction& operator=(const ProxyTransaction&) = delete;

    // Start the proxy transaction. Must be called after wrapping in shared_ptr.
    // Uses shared_from_this() for callback captures.
    void Start();

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

    // Request context (all copied at construction -- the original HttpRequest
    // is INVALIDATED by parser_.Reset() immediately after the async handler
    // returns, so no pointers/references to the original may be stored).
    std::string service_name_;
    std::string method_;
    std::string path_;
    std::string query_;
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

    // Internal methods
    void AttemptCheckout();
    void OnCheckoutReady(UpstreamLease lease);
    void OnCheckoutError(int error_code);
    void SendUpstreamRequest();
    void OnUpstreamData(std::shared_ptr<ConnectionHandler> conn, std::string& data);
    void OnUpstreamWriteComplete(std::shared_ptr<ConnectionHandler> conn);
    void OnResponseComplete();
    void OnError(int result_code, const std::string& log_message);
    void MaybeRetry(RetryPolicy::RetryCondition condition);
    void DeliverResponse(HttpResponse response);
    void Cleanup();

    // Build the final client-facing HttpResponse from the parsed upstream response
    HttpResponse BuildClientResponse();

    // Arm response timeout on the upstream transport's deadline
    void ArmResponseTimeout();
    void ClearResponseTimeout();

    // Error response factory (maps result codes to HTTP responses)
    static HttpResponse MakeErrorResponse(int result_code);
};
