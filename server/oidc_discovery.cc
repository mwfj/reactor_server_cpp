#include "auth/oidc_discovery.h"

#include "auth/auth_url_util.h"
#include "auth/upstream_http_client.h"
#include "dispatcher.h"
#include "log/logger.h"

#include <nlohmann/json.hpp>

// ---------------------------------------------------------------------------
// OIDC discovery: GET `issuer_url/.well-known/openid-configuration`, parse
// the resulting JSON document, extract `jwks_uri` and (optionally)
// `introspection_endpoint`, and hand them back via `on_ready_cb`. On
// failure (network, timeout, non-200, JSON parse), schedules a retry
// after `retry_sec` seconds via EnQueueDelayed on the originating
// dispatcher.
//
// All nlohmann::json calls are wrapped in try/catch — the discovery
// payload is upstream-controlled, so malformed JSON must never crash the
// process (§4.5). Equivalent treatment to jwt-cpp's attacker-reachable
// surfaces (§9 item 16).
// ---------------------------------------------------------------------------

namespace AUTH_NAMESPACE {

// Forward-declared in the header so the class definition stays pure-data.
// Owns the recursive retry closure that drives OidcDiscovery::Start.
struct OidcDiscovery::CycleState {
    std::function<void(size_t)> run;
};

namespace {

// Build the OIDC discovery endpoint from an issuer URL using ParseHttpsUri.
// RFC 8414 / RFC 5785: appends "/.well-known/openid-configuration" under
// the issuer base path, collapsing a trailing slash.
ParsedHttpsUri BuildDiscoveryEndpoint(const std::string& issuer_url) {
    auto out = ParseHttpsUri(issuer_url);
    std::string& path = out.path_with_query;
    if (!path.empty() && path.back() == '/') {
        path.pop_back();
    }
    path += "/.well-known/openid-configuration";
    return out;
}

// Extract (jwks_uri, introspection_endpoint) from the discovery JSON
// body, gated on the document's `issuer` field matching the configured
// issuer URL. Returns non-empty jwks_uri on success; out_introspection_endpoint
// is HTTPS-gated — a non-HTTPS scheme (or any URL where the scheme isn't
// `https`) is cleared and `reason` is set to "introspection_endpoint_not_https".
// Both endpoints may legitimately be empty (not every IdP advertises
// introspection). On JSON or schema failure, returns empty jwks_uri and
// sets `reason`.
//
// `expected_issuer` MUST be the `issuer_url` from the operator's config.
// Per OIDC Connect Discovery 1.0 §4.3, the discovery response's
// `issuer` claim "MUST be identical to the Issuer URL that was used as
// the prefix to /.well-known/openid-configuration." Without this gate, a
// misrouted / multi-tenant / compromised discovery endpoint could serve
// a foreign tenant's JWKS; the verifier would then trust keys that are
// not bound to this issuer, letting attacker-signed tokens validate
// provided they set `iss` to the configured value.
void ExtractEndpoints(const std::string& body,
                       const std::string& expected_issuer,
                       std::string& out_jwks_uri,
                       std::string& out_introspection_endpoint,
                       std::string& reason) {
    try {
        auto j = nlohmann::json::parse(body, /*cb=*/nullptr,
                                        /*allow_exceptions=*/true);
        if (!j.is_object()) {
            reason = "not_object";
            return;
        }
        // Validate `issuer` FIRST. If the response came from the wrong
        // tenant / a spoofed endpoint, nothing else in it can be
        // trusted (jwks_uri included).
        auto iss_it = j.find("issuer");
        if (iss_it == j.end() || !iss_it->is_string()) {
            reason = "missing_issuer";
            return;
        }
        const std::string doc_issuer = iss_it->get<std::string>();
        if (doc_issuer != expected_issuer) {
            reason = "issuer_mismatch";
            return;
        }
        auto jwks_it = j.find("jwks_uri");
        if (jwks_it == j.end() || !jwks_it->is_string()) {
            reason = "missing_jwks_uri";
            return;
        }
        out_jwks_uri = jwks_it->get<std::string>();
        auto intro_it = j.find("introspection_endpoint");
        if (intro_it != j.end() && intro_it->is_string()) {
            const auto candidate = intro_it->get<std::string>();
            // A non-HTTPS introspection_endpoint would leak the IdP
            // client_secret (RFC 7662 §2.1 sends it as Basic credentials)
            // AND every bearer token introspected. Clear and surface the
            // reason; jwks_uri stays valid so JWT-mode discovery still
            // succeeds when the IdP only mis-advertises introspection.
            if (HasHttpsScheme(candidate)) {
                out_introspection_endpoint = candidate;
            } else {
                out_introspection_endpoint.clear();
                reason = "introspection_endpoint_not_https";
            }
        }
        // Enforce https on jwks_uri to match the TLS-mandatory IdP policy.
        // Case-insensitive scheme per RFC 3986 §3.1 — compliant IdPs may
        // return `HTTPS://…` and shouldn't be rejected as plaintext.
        if (!HasHttpsScheme(out_jwks_uri)) {
            reason = "jwks_uri_not_https";
            out_jwks_uri.clear();
            return;
        }
    } catch (const nlohmann::json::exception& ex) {
        reason = "json_exception";
        logging::Get()->warn(
            "OIDC discovery JSON parse failed: {}", ex.what());
    } catch (const std::exception& ex) {
        reason = "std_exception";
        logging::Get()->warn(
            "OIDC discovery parse threw: {}", ex.what());
    } catch (...) {
        reason = "unknown_exception";
        logging::Get()->warn(
            "OIDC discovery parse threw non-std exception");
    }
}

}  // namespace

void OidcDiscovery::ExtractEndpointsForTest(
        const std::string& body,
        const std::string& expected_issuer,
        std::string& out_jwks_uri,
        std::string& out_introspection_endpoint,
        std::string& reason) {
    ExtractEndpoints(body, expected_issuer, out_jwks_uri,
                      out_introspection_endpoint, reason);
}

OidcDiscovery::OidcDiscovery(std::string issuer_name,
                              std::string issuer_url,
                              std::shared_ptr<UpstreamHttpClient> client,
                              std::string upstream_pool_name,
                              int retry_sec)
    : issuer_name_(std::move(issuer_name)),
      issuer_url_(std::move(issuer_url)),
      client_(std::move(client)),
      upstream_pool_name_(std::move(upstream_pool_name)),
      retry_sec_(retry_sec > 0 ? retry_sec : 30),
      ready_(std::make_shared<std::atomic<bool>>(false)),
      cancel_token_(std::make_shared<std::atomic<bool>>(false)) {
    logging::Get()->debug(
        "OidcDiscovery constructed issuer={} url={} pool={} retry_sec={}",
        issuer_name_, issuer_url_, upstream_pool_name_, retry_sec_);
}

OidcDiscovery::~OidcDiscovery() {
    Cancel();
}

void OidcDiscovery::SetRetrySec(int retry_sec) noexcept {
    retry_sec_ = retry_sec > 0 ? retry_sec : 30;
}

void OidcDiscovery::Start(size_t dispatcher_index,
                           uint64_t generation,
                           std::function<void(uint64_t,
                                               const std::string&,
                                               const std::string&)> on_ready_cb) {
    if (!client_) {
        logging::Get()->error(
            "OidcDiscovery::Start called with no UpstreamHttpClient "
            "issuer={}", issuer_name_);
        return;
    }

    // Refresh the cancel token per cycle; old token stays live only for
    // the in-flight response it was captured into.
    auto token = std::make_shared<std::atomic<bool>>(false);
    cancel_token_ = token;
    // Reset ready_ for this cycle (shared_ptr captured by closures for safe
    // access after ~OidcDiscovery).
    ready_->store(false, std::memory_order_release);

    {
        // Log the intended endpoint at Start time without building a
        // redundant Request object — the actual request is built inside
        // the state->run lambda.
        auto ep = BuildDiscoveryEndpoint(issuer_url_);
        logging::Get()->info(
            "OIDC discovery starting issuer={} pool={} path={} host={} gen={}",
            issuer_name_, upstream_pool_name_,
            ep.path_with_query, ep.host, generation);
    }

    std::string issuer_name = issuer_name_;
    std::string issuer_url = issuer_url_;
    std::string pool_name = upstream_pool_name_;
    auto client_copy = client_;
    auto* dispatcher =
        dispatcher_index < client_->dispatchers().size()
            ? client_->dispatchers()[dispatcher_index].get()
            : nullptr;
    int retry_sec = retry_sec_;

    // Capture ready_ by shared_ptr value so closures can safely access it
    // after ~OidcDiscovery runs while a delayed retry task is queued. The
    // cancel token (captured as `token`) already guards the cancel path.
    auto ready_flag = ready_;

    // CycleState owns the recursive retry closure. OidcDiscovery holds the
    // sole strong reference via cycle_state_; closures capture weak_ptr so
    // destruction of OidcDiscovery (or an explicit Cancel()) releases the
    // CycleState immediately. The previous implementation captured `state`
    // strongly inside `state->run`, forming a self-referential cycle that
    // leaked the CycleState + its captured function objects on every
    // Issuer::Start / reload.
    cycle_state_ = std::make_shared<CycleState>();
    std::weak_ptr<CycleState> weak_state = cycle_state_;
    cycle_state_->run =
        [weak_state, issuer_name, issuer_url, pool_name, client_copy,
         dispatcher, retry_sec, generation, on_ready_cb, token,
         ready_flag](size_t disp_index) {
            if (token->load(std::memory_order_acquire)) {
                return;
            }

            UpstreamHttpClient::Request req;
            auto ep = BuildDiscoveryEndpoint(issuer_url);
            req.method = "GET";
            req.path = ep.path_with_query;
            req.host_header = ep.host;
            req.headers["accept"] = "application/json";
            req.timeout_sec = 10;
            req.max_response_body = 64 * 1024;

            client_copy->Issue(
                pool_name, disp_index, std::move(req),
                [weak_state, issuer_name, issuer_url, dispatcher, retry_sec,
                 generation, on_ready_cb, token, ready_flag, disp_index](
                        UpstreamHttpClient::Response resp) {
                    if (token->load(std::memory_order_acquire)) {
                        return;
                    }
                    // Re-arm after retry_sec seconds on the same dispatcher.
                    // weak_state avoids a strong self-cycle but still reaches
                    // `run` because OidcDiscovery holds the sole strong ref.
                    auto schedule_retry = [dispatcher, weak_state, disp_index,
                                            retry_sec]() {
                        if (!dispatcher) return;
                        dispatcher->EnQueueDelayed(
                            [weak_state, disp_index]() {
                                if (auto s = weak_state.lock()) {
                                    s->run(disp_index);
                                }
                            },
                            std::chrono::seconds(retry_sec));
                    };
                    if (!resp.error.empty() || resp.status_code != 200) {
                        logging::Get()->warn(
                            "OIDC discovery failed issuer={} status={} error={} "
                            "retry_in={}s",
                            issuer_name, resp.status_code,
                            resp.error.empty() ? "-" : resp.error, retry_sec);
                        schedule_retry();
                        return;
                    }
                    std::string jwks_uri;
                    std::string intro_endpoint;
                    std::string reason;
                    ExtractEndpoints(resp.body, issuer_url,
                                     jwks_uri, intro_endpoint, reason);
                    if (jwks_uri.empty()) {
                        logging::Get()->warn(
                            "OIDC discovery parse failed issuer={} reason={} "
                            "retry_in={}s",
                            issuer_name, reason, retry_sec);
                        schedule_retry();
                        return;
                    }
                    logging::Get()->info(
                        "OIDC discovery ok issuer={} has_introspection={}",
                        issuer_name, !intro_endpoint.empty());
                    // Flip ready_flag AFTER on_ready_cb runs so this
                    // OidcDiscovery::IsReady() cannot briefly report true
                    // for a cycle whose callback the Issuer's own
                    // generation gate would reject. Issuer::ready_ is the
                    // authoritative admission flag; this ordering makes
                    // OidcDiscovery's own IsReady() safely consistent with
                    // it for any future consumer that reads this flag.
                    if (on_ready_cb) {
                        on_ready_cb(generation, jwks_uri, intro_endpoint);
                    }
                    ready_flag->store(true, std::memory_order_release);
                },
                token);
        };

    if (dispatcher) {
        cycle_state_->run(dispatcher_index);
    }
}

void OidcDiscovery::Cancel() {
    if (cancel_token_) {
        cancel_token_->store(true, std::memory_order_release);
    }
    // Drop the CycleState so any delayed-retry weak_ptrs lock null. Without
    // this, the closure would stay pinned by cycle_state_ until ~OidcDiscovery.
    cycle_state_.reset();
}

}  // namespace AUTH_NAMESPACE
