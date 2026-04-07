#pragma once

#include "common.h"
#include "upstream/upstream_http_codec.h"
#include "upstream/upstream_lease.h"
#include "upstream/header_rewriter.h"
#include "upstream/retry_policy.h"
#include "http/http_callbacks.h"
#include "http/http_response.h"
// <string>, <map>, <unordered_map>, <memory>, <functional>, <chrono> provided by common.h

// Forward declarations
class UpstreamManager;
class ConnectionHandler;
struct ProxyConfig;

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
                     const std::string& upstream_host,
                     int upstream_port,
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
    std::string upstream_host_;
    int upstream_port_;
    std::string static_prefix_;  // Precomputed by ProxyHandler for strip_prefix

    // Rewritten headers and serialized request (cached for retry)
    std::map<std::string, std::string> rewritten_headers_;
    std::string serialized_request_;

    // Dependencies (non-owning, outlive the transaction)
    UpstreamManager* upstream_manager_;
    const ProxyConfig& config_;
    const HeaderRewriter& header_rewriter_;
    const RetryPolicy& retry_policy_;

    // Completion callback
    HTTP_CALLBACKS_NAMESPACE::AsyncCompletionCallback complete_cb_;
    bool complete_cb_invoked_ = false;

    // Upstream connection state (per attempt)
    UpstreamLease lease_;
    UpstreamHttpCodec codec_;

    // Early response flag: set when upstream sends response data while the
    // request write is still incomplete (state == SENDING_REQUEST). When true,
    // Cleanup() calls MarkClosing() on the UpstreamConnection before releasing
    // the lease, ensuring the connection is destroyed (not returned to idle).
    bool early_response_ = false;

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
