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
    const std::string& sni_hostname,
    UpstreamManager* upstream_manager)
    : service_name_(service_name),
      config_(config),
      upstream_tls_(upstream_tls),
      upstream_host_(upstream_host),
      upstream_port_(upstream_port),
      sni_hostname_(sni_hostname),
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
        // Extract catch-all param name from route_prefix (e.g., "/*proxy_path"
        // → "proxy_path", "/*rest" → "rest"). Only match '*' at segment start
        // (after '/') — mid-segment '*' like /file*name is literal.
        for (size_t i = 0; i < config_.route_prefix.size(); ++i) {
            if (config_.route_prefix[i] == '*' &&
                (i == 0 || config_.route_prefix[i - 1] == '/')) {
                catch_all_param_ = config_.route_prefix.substr(i + 1);
                break;
            }
        }

        // Precompute static_prefix as fallback for exact-match routes
        // (no catch-all param available). Only the leading static segment
        // is stripped; dynamic segments like :version are left intact.
        //
        // The route trie only treats ':' and '*' as special at segment start
        // (immediately after '/'). Mid-segment occurrences like /v1:beta or
        // /file*name are literal. Match that behavior here to avoid
        // incorrectly truncating literal route patterns.
        static_prefix_ = config_.route_prefix;
        size_t cut_pos = std::string::npos;
        for (size_t i = 1; i < static_prefix_.size(); ++i) {
            if (static_prefix_[i - 1] == '/' &&
                (static_prefix_[i] == ':' || static_prefix_[i] == '*')) {
                cut_pos = i;
                break;
            }
        }
        // Also handle leading ':' or '*' (pattern starts with param/catch-all)
        if (cut_pos == std::string::npos &&
            !static_prefix_.empty() &&
            (static_prefix_[0] == ':' || static_prefix_[0] == '*')) {
            cut_pos = 0;
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
    //
    // When strip_prefix is active, two route patterns are registered:
    //   1. Exact prefix (e.g., /api/:version)     → no catch-all param
    //   2. Catch-all    (e.g., /api/:version/*pp)  → catch-all param present
    // For case 1, the entire matched prefix IS the route, so the upstream
    // path should be "/" (nothing beyond the prefix to forward).
    std::string upstream_path_override;
    if (config_.strip_prefix) {
        if (!catch_all_param_.empty()) {
            auto it = request.params.find(catch_all_param_);
            if (it != request.params.end() && !it->second.empty()) {
                upstream_path_override = it->second;
            } else {
                // Catch-all param absent (exact-prefix hit) or empty
                // (request ended at the catch-all slash, e.g., /api/v1/).
                // Either way, upstream path is "/" — the entire request
                // path IS the prefix with nothing beyond it to forward.
                // Exact-match hit (no catch-all segment matched) — upstream
                // path is "/" since the entire request path IS the prefix.
                upstream_path_override = "/";
            }
        } else {
            // No catch-all param configured at all — exact-match only route.
            upstream_path_override = "/";
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
        sni_hostname_,
        upstream_path_override,
        static_prefix_);

    txn->Start();
    // txn stays alive via shared_ptr captured in async callbacks
}
