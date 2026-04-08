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

class ProxyHandler {
public:
    ProxyHandler(const std::string& service_name,
                 const ProxyConfig& config,
                 bool upstream_tls,
                 const std::string& upstream_host,
                 int upstream_port,
                 UpstreamManager* upstream_manager);
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
                HTTP_CALLBACKS_NAMESPACE::AsyncCompletionCallback complete);

    // Access configuration for tests/logging
    const std::string& service_name() const { return service_name_; }

private:
    std::string service_name_;
    ProxyConfig config_;          // stored by value — not a reference
    bool upstream_tls_ = false;
    std::string upstream_host_;
    int upstream_port_;
    UpstreamManager* upstream_manager_;
    HeaderRewriter header_rewriter_;
    RetryPolicy retry_policy_;
    std::string static_prefix_;  // Precomputed from route_prefix for strip_prefix
};
