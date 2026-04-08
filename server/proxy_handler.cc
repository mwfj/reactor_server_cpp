#include "upstream/proxy_handler.h"
#include "upstream/proxy_transaction.h"
#include "config/server_config.h"
#include "http/http_request.h"
#include "log/logger.h"

ProxyHandler::ProxyHandler(
    const std::string& service_name,
    const ProxyConfig& config,
    bool upstream_tls,
    const std::string& upstream_host,
    int upstream_port,
    UpstreamManager* upstream_manager)
    : service_name_(service_name),
      config_(config),
      upstream_tls_(upstream_tls),
      upstream_host_(upstream_host),
      upstream_port_(upstream_port),
      upstream_manager_(upstream_manager),
      header_rewriter_(HeaderRewriter::Config{
          config.header_rewrite.set_x_forwarded_for,
          config.header_rewrite.set_x_forwarded_proto,
          config.header_rewrite.set_via_header,
          config.header_rewrite.rewrite_host
      }),
      retry_policy_(RetryPolicy::Config{
          config.retry.max_retries,
          config.retry.retry_on_connect_failure,
          config.retry.retry_on_5xx,
          config.retry.retry_on_timeout,
          config.retry.retry_on_disconnect,
          config.retry.retry_non_idempotent
      })
{
    // Precompute static_prefix for strip_prefix path rewriting.
    // This avoids re-parsing route_prefix on every request.
    //
    // For dynamic route patterns (e.g., "/api/:version/users/*path"),
    // only the leading static segment ("/api") is stripped. This is by
    // design: dynamic segments are resolved at match time and the router
    // captures them as parameters, but the proxy serializer operates on
    // the raw matched path. Users needing full dynamic-prefix stripping
    // should structure their routes with static prefixes.
    if (config_.strip_prefix && !config_.route_prefix.empty()) {
        // Extract catch-all param name from route_prefix (e.g., "*proxy_path"
        // → "proxy_path", "*rest" → "rest"). Used in Handle() to look up the
        // router-extracted tail instead of doing string prefix stripping.
        auto star_pos = config_.route_prefix.rfind('*');
        if (star_pos != std::string::npos) {
            catch_all_param_ = config_.route_prefix.substr(star_pos + 1);
        }

        // Precompute static_prefix as fallback for exact-match routes
        // (no catch-all param available). Only the leading static segment
        // is stripped; dynamic segments like :version are left intact.
        static_prefix_ = config_.route_prefix;
        auto colon_pos = static_prefix_.find(':');
        auto star_pos2 = static_prefix_.find('*');
        size_t cut_pos = std::string::npos;
        if (colon_pos != std::string::npos) cut_pos = colon_pos;
        if (star_pos2 != std::string::npos &&
            (cut_pos == std::string::npos || star_pos2 < cut_pos)) {
            cut_pos = star_pos2;
        }
        if (cut_pos != std::string::npos) {
            static_prefix_ = static_prefix_.substr(0, cut_pos);
            while (!static_prefix_.empty() && static_prefix_.back() == '/') {
                static_prefix_.pop_back();
            }
        }
    }

    logging::Get()->info("ProxyHandler created service={} upstream={}:{} "
                         "route_prefix={} strip_prefix={}",
                         service_name_, upstream_host_, upstream_port_,
                         config_.route_prefix, config_.strip_prefix);
}

ProxyHandler::~ProxyHandler() {
    logging::Get()->debug("ProxyHandler destroyed service={}",
                          service_name_);
}

void ProxyHandler::Handle(
    const HttpRequest& request,
    HTTP_CALLBACKS_NAMESPACE::AsyncCompletionCallback complete) {

    logging::Get()->debug("ProxyHandler::Handle service={} client_fd={} "
                          "{} {}",
                          service_name_, request.client_fd,
                          request.method, request.path);

    // Extract catch-all route param for strip_prefix. The param name is
    // determined by the route pattern: auto-generated routes use "proxy_path",
    // user-defined patterns may use any name (e.g., "*rest" → "rest").
    // catch_all_param_ is extracted from route_prefix at construction time.
    std::string upstream_path_override;
    if (config_.strip_prefix && !catch_all_param_.empty()) {
        auto it = request.params.find(catch_all_param_);
        if (it != request.params.end()) {
            upstream_path_override = it->second;
        }
    }

    auto txn = std::make_shared<ProxyTransaction>(
        service_name_,
        request,
        std::move(complete),
        upstream_manager_,
        config_,
        header_rewriter_,
        retry_policy_,
        upstream_tls_,
        upstream_host_,
        upstream_port_,
        upstream_path_override,
        static_prefix_);

    txn->Start();
    // txn stays alive via shared_ptr captured in async callbacks
}
