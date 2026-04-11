#pragma once

#include "common.h"
// <unordered_map> provided by common.h

struct HttpRequest {
    std::string method;           // "GET", "POST", "PUT", "DELETE", etc.
    std::string url;              // Full URL as received ("/path?query=value")
    std::string path;             // URL path component ("/path")
    std::string query;            // Query string ("query=value")
    int http_major = 1;
    int http_minor = 1;
    std::map<std::string, std::string> headers;  // Header names stored lowercase
    std::string body;
    bool keep_alive = true;
    bool upgrade = false;         // Connection: Upgrade (for WebSocket)
    size_t content_length = 0;
    bool headers_complete = false; // True when headers are parsed (body may still be pending)
    bool complete = false;        // True when full request has been parsed

    // Route parameters populated by HttpRouter during dispatch.
    // Mutable because routing is an output of dispatch, not parser input.
    mutable std::unordered_map<std::string, std::string> params;

    // Index of the dispatcher (event loop) handling this request's connection.
    // Set by the connection handler; used for upstream pool partition affinity.
    // Mutable because it's set at dispatch time, not parser time.
    mutable int dispatcher_index = -1;

    // Peer connection metadata -- set by the connection handler at dispatch time.
    // Mutable because they are populated during dispatch, not during parsing.
    mutable std::string client_ip;    // Peer remote address (from ConnectionHandler::ip_addr())
    mutable bool client_tls = false;  // True if downstream connection has TLS
    mutable int client_fd = -1;       // Client socket fd (for log correlation)

    // Cancel channel for async handlers.
    //
    // The framework allocates this before dispatching to an async
    // handler and stashes the shared_ptr in the per-request abort
    // hook's capture set. A handler (e.g. ProxyHandler) may install a
    // cancel callback on the slot that will be fired AT MOST ONCE
    // when the request's async cycle is aborted:
    //   - client disconnect (RemoveConnection → TripAsyncAbortHook)
    //   - deferred-response safety cap (HTTP/1 heartbeat)
    //   - stream-close / async-cap RST (HTTP/2)
    //
    // For proxy routes this is the only reliable way to tell a
    // ProxyTransaction to stop: transport callbacks and queued
    // checkout completions all hold shared_ptrs to the transaction,
    // so without an explicit Cancel() signal a disconnected client
    // would leave the transaction running against a slow/hung upstream
    // until that upstream responds or times out — starving the pool
    // under a burst of disconnects.
    //
    // Dispatcher-thread only: both Set() (from the handler) and Fire()
    // (from the abort hook) run on the connection's dispatcher, so
    // no synchronization is needed. Null on sync routes.
    mutable std::shared_ptr<std::function<void()>> async_cancel_slot;

    // Per-request override for the async-deferred safety cap.
    //
    //   -1 (default): use HttpConnectionHandler::max_async_deferred_sec_
    //                 / Http2ConnectionHandler::max_async_deferred_sec_
    //                 (the global cap computed by RecomputeAsyncDeferredCap
    //                 from proxy.response_timeout_ms + buffer).
    //    0         : DISABLE the safety cap for this specific request —
    //                 the deferred heartbeat / ResetExpiredStreams will
    //                 not abort it on cap expiry. Used by proxy handlers
    //                 whose upstream has response_timeout_ms=0 (SSE,
    //                 long-poll, intentionally unbounded backends).
    //   >0         : use this many seconds as the cap for this request.
    //
    // Rationale: a single global cap cannot satisfy both "protect
    // unrelated routes from stuck handlers" and "honor the configured
    // 'disabled' semantic for specific proxies." Per-request override
    // lets the handler pick the right behavior for its own request:
    //   - Custom async handlers that don't set this → global cap applies.
    //   - Proxies with response_timeout_ms > 0 → don't set this; global
    //     cap still provides the last-resort abort above the per-request
    //     upstream deadline.
    //   - Proxies with response_timeout_ms == 0 → set to 0; the operator
    //     has explicitly opted out of timeouts and expects unbounded
    //     lifetime for the request.
    //
    // Mutable because, like async_cancel_slot / params, it is populated
    // by the handler during dispatch through a const HttpRequest&.
    // Dispatcher-thread only.
    mutable int async_cap_sec_override = -1;

    // Case-insensitive header lookup
    std::string GetHeader(const std::string& name) const {
        std::string lower = name;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c){ return std::tolower(c); });
        auto it = headers.find(lower);
        return (it != headers.end()) ? it->second : "";
    }

    bool HasHeader(const std::string& name) const {
        std::string lower = name;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c){ return std::tolower(c); });
        return headers.find(lower) != headers.end();
    }

    // Reset for reuse (keep-alive pipelining)
    void Reset() {
        method.clear();
        url.clear();
        path.clear();
        query.clear();
        http_major = 1;
        http_minor = 1;
        headers.clear();
        body.clear();
        keep_alive = true;
        upgrade = false;
        content_length = 0;
        headers_complete = false;
        complete = false;
        params.clear();
        dispatcher_index = -1;
        client_ip.clear();
        client_tls = false;
        client_fd = -1;
        async_cancel_slot.reset();
        async_cap_sec_override = -1;
    }
};
