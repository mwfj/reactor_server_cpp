#pragma once

#include "common.h"
// <string>, <map>, <memory>, <functional>, <vector>, <chrono>, <atomic> via common.h

class UpstreamManager;
class Dispatcher;

namespace AUTH_NAMESPACE {

// ---------------------------------------------------------------------------
// One-shot async HTTP client layered on UpstreamManager. Used by:
//   - OidcDiscovery  (GET .well-known/openid-configuration)
//   - JwksFetcher    (GET jwks_uri)
//   - IntrospectionClient (Phase 3; POST application/x-www-form-urlencoded)
//
// Rationale (§19.3):
// - Reuses UpstreamManager so JWKS / discovery / introspection inherit
//   connection pooling, client TLS, circuit breaking, retries, and metrics
//   for free.
// - Runs the response callback on the dispatcher that initiated the
//   request — matches the partition-per-dispatcher model of the pool.
// - Defensive bounds: max_response_body caps accumulated body bytes; a
//   timeout bounds end-to-end checkout + request + response latency.
//
// Thread-safety envelope:
// - `Issue` must be called from the dispatcher thread identified by
//   `dispatcher_index`. The DoneCallback fires on that same dispatcher.
// - The client is otherwise stateless (no mutable shared state across
//   calls).
// ---------------------------------------------------------------------------
class UpstreamHttpClient {
 public:
    struct Request {
        std::string method = "GET";
        std::string path = "/";
        std::string query;                                 // Without leading '?'
        std::string host_header;                            // Virtual-host override; defaults to pool
        std::map<std::string, std::string> headers;        // Lowercase keys preferred
        std::string body;                                  // For POST
        int timeout_sec = 5;
        size_t max_response_body = 256 * 1024;             // 256 KB default
    };

    struct Response {
        int status_code = 0;
        std::string body;
        std::vector<std::pair<std::string, std::string>> headers;
        // Non-empty when the request did not reach a full HTTP response.
        // Short stable codes — "timeout", "connect_failed", "circuit_open",
        // "pool_exhausted", "parse_error", "body_too_large", "disconnect".
        std::string error;
    };

    // Completion callback. Runs on the dispatcher thread identified by the
    // `dispatcher_index` argument to Issue(). Invoked at most once per
    // call. On error (network / timeout / CB-open / parse / oversize)
    // the callback sees an empty status_code (0) and a non-empty `error`.
    using DoneCallback = std::function<void(Response)>;

    UpstreamHttpClient(UpstreamManager* upstream_manager,
                        std::vector<std::shared_ptr<Dispatcher>> dispatchers);
    ~UpstreamHttpClient();

    UpstreamHttpClient(const UpstreamHttpClient&) = delete;
    UpstreamHttpClient& operator=(const UpstreamHttpClient&) = delete;

    // Issue a one-shot request against `upstream_pool_name`. The request
    // runs on dispatcher `dispatcher_index` and the response callback fires
    // on that same dispatcher. The optional cancel_token lets the caller
    // short-circuit a queued waiter (e.g. during Issuer::Stop or on
    // reload generation bump). The client makes no other use of the token.
    //
    // If the pool is unknown (upstream_manager_->HasUpstream returns
    // false), the callback fires synchronously with error="pool_unknown".
    void Issue(const std::string& upstream_pool_name,
                size_t dispatcher_index,
                Request req,
                DoneCallback cb,
                std::shared_ptr<std::atomic<bool>> cancel_token = nullptr);

    UpstreamManager* upstream_manager() const noexcept {
        return upstream_manager_;
    }
    const std::vector<std::shared_ptr<Dispatcher>>& dispatchers() const {
        return dispatchers_;
    }

 private:
    // Per-request state. Heap-allocated via shared_ptr so response / write
    // / close callbacks that survive beyond a stack frame can safely
    // reference it; lifetime ends when the DoneCallback is invoked.
    struct Transaction;

    UpstreamManager* upstream_manager_;                    // non-owning
    std::vector<std::shared_ptr<Dispatcher>> dispatchers_;
};

}  // namespace AUTH_NAMESPACE
