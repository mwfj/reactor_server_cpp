#pragma once

#include "common.h"
#include "config/server_config.h"    // ProxyConfig definition (value member)
#include "upstream/header_rewriter.h"
#include "upstream/retry_policy.h"
#include "http/http_callbacks.h"
// <string>, <functional> provided by common.h

// Forward declarations
class UpstreamManager;
struct HttpRequest;
namespace AUTH_NAMESPACE { class AuthManager; }

class ProxyHandler {
public:
    ProxyHandler(const std::string& service_name,
                 const ProxyConfig& config,
                 bool upstream_tls,
                 const std::string& upstream_host,
                 int upstream_port,
                 const std::string& sni_hostname,
                 UpstreamManager* upstream_manager,
                 // Non-owning, nullable. When non-null, ProxyTransaction
                 // calls `auth_manager->ForwardConfig()` at the start of
                 // every outbound hop (§4.7), takes a stack-local
                 // shared_ptr snapshot, and passes the snapshot through
                 // to HeaderRewriter::RewriteRequest. Null disables the
                 // auth overlay entirely (e.g. when auth.enabled=false).
                 AUTH_NAMESPACE::AuthManager* auth_manager = nullptr);
    ~ProxyHandler();

    // Non-copyable, non-movable: routes capture a raw handler_ptr.
    ProxyHandler(const ProxyHandler&) = delete;
    ProxyHandler& operator=(const ProxyHandler&) = delete;
    ProxyHandler(ProxyHandler&&) = delete;
    ProxyHandler& operator=(ProxyHandler&&) = delete;

    // AsyncHandler-compatible handler function.
    // Captures `this` -- the ProxyHandler must outlive all transactions.
    // Called by the async handler framework after middleware has run.
    void Handle(const HttpRequest& request,
                HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender stream_sender,
                HTTP_CALLBACKS_NAMESPACE::AsyncCompletionCallback complete);

    // Access configuration for tests/logging
    const std::string& service_name() const { return service_name_; }

private:
    std::string service_name_;
    ProxyConfig config_;          // stored by value — not a reference
    bool upstream_tls_ = false;
    std::string upstream_host_;
    int upstream_port_;
    std::string sni_hostname_;  // Preferred Host value for TLS backends behind IPs
    UpstreamManager* upstream_manager_;
    // Non-owning. Lifetime guarantee: HttpServer destructs AuthManager
    // AFTER ProxyHandler (§3.4 ownership tree), so a live ProxyHandler
    // never observes a dangling manager pointer. Null when the server has
    // auth disabled or hasn't wired the manager yet.
    AUTH_NAMESPACE::AuthManager* auth_manager_ = nullptr;
    HeaderRewriter header_rewriter_;
    RetryPolicy retry_policy_;
    std::string static_prefix_;        // Precomputed from route_prefix for strip_prefix
    std::string catch_all_param_;      // Name of the catch-all route param (e.g., "proxy_path" or "rest")
    bool has_catch_all_in_prefix_ = false;  // True if route_prefix contains a catch-all segment
};
