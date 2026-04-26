#include "auth/introspection_client.h"

#include "auth/auth_claims.h"
#include "auth/auth_url_util.h"
#include "auth/issuer.h"
#include "base64.h"
#include "cli/version.h"
#include "log/log_utils.h"
#include "log/logger.h"

#include <nlohmann/json.hpp>

#include <cstdio>
#include <exception>
// <string>, <vector>, <memory>, <functional>, <atomic> via common.h

namespace AUTH_NAMESPACE {

namespace {

// 64 KB cap for introspection response bodies. RFC 7662 responses are
// typically <2 KB; anything larger is almost certainly a misconfigured IdP
// or a pathological response. Surfaces as `body_too_large` on overflow.
constexpr size_t kIntrospectionMaxBodyBytes = 64 * 1024;

// Read int64 from json["exp"] without throwing. Returns 0 on absent or
// non-integer / non-convertible field.
int64_t ExtractExpSafe(const nlohmann::json& body) {
    try {
        auto it = body.find("exp");
        if (it == body.end()) return 0;
        if (it->is_number_integer()) {
            return it->get<int64_t>();
        }
        if (it->is_number_unsigned()) {
            return static_cast<int64_t>(it->get<uint64_t>());
        }
        if (it->is_number_float()) {
            return static_cast<int64_t>(it->get<double>());
        }
        return 0;
    } catch (const std::exception&) {
        return 0;
    } catch (...) {
        return 0;
    }
}

// Apply the policy's per-request claim checks against a populated
// AuthContext + the parsed response body. Order mirrors the JWT-mode
// path: audience -> scopes. Issuer-level required_claims enforcement
// continues to be handled by JwtVerifier on the JWT path; the
// introspection path runs only the policy-scoped checks here.
VerifyResult RunPerRequestClaimChecks(const AuthPolicy& policy,
                                       const AuthContext& ctx,
                                       const nlohmann::json& body) {
    if (!policy.required_audience.empty() &&
        !MatchesAudience(body, policy.required_audience)) {
        return VerifyResult::InvalidToken(
            "audience mismatch", "audience_mismatch");
    }
    if (!HasRequiredScopes(ctx.scopes, policy.required_scopes)) {
        return VerifyResult::InsufficientScope(
            "insufficient scope", "insufficient_scope");
    }
    return VerifyResult::Allow();
}

// Build a headers map for the introspection POST. `auth_header_value`
// is empty when auth_style != "basic".
std::map<std::string, std::string> BuildHeaders(
        const std::string& host,
        const std::string& auth_header_value,
        size_t body_size) {
    std::map<std::string, std::string> headers;
    if (!host.empty()) {
        headers["host"] = host;
    }
    if (!auth_header_value.empty()) {
        headers["authorization"] = auth_header_value;
    }
    headers["content-type"] = "application/x-www-form-urlencoded";
    headers["content-length"] = std::to_string(body_size);
    headers["accept"] = "application/json";
    headers["user-agent"] = std::string("reactor-gateway/")
        + REACTOR_SERVER_VERSION;
    return headers;
}

}  // namespace

IntrospectionClient::IntrospectionClient(
        std::shared_ptr<UpstreamHttpClient> client)
    : client_(std::move(client)) {
    logging::Get()->debug(
        "IntrospectionClient constructed client={}",
        static_cast<const void*>(client_.get()));
}

std::string IntrospectionClient::UrlEncode(const std::string& in) {
    static const char* kHex = "0123456789ABCDEF";
    std::string out;
    out.reserve(in.size());
    for (unsigned char c : in) {
        const bool unreserved =
            (c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~';
        if (unreserved) {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(kHex[(c >> 4) & 0xF]);
            out.push_back(kHex[c & 0xF]);
        }
    }
    return out;
}

std::string IntrospectionClient::BuildAuthorizationHeaderBasic(
        const std::string& client_id,
        const std::string& client_secret) {
    std::string credentials;
    credentials.reserve(client_id.size() + 1 + client_secret.size());
    credentials.append(client_id);
    credentials.push_back(':');
    credentials.append(client_secret);
    std::string b64 = base64_util::EncodeNoNewline(credentials);
    if (b64.empty()) {
        return std::string();
    }
    return std::string("Basic ") + b64;
}

std::string IntrospectionClient::BuildBodyBasic(const std::string& token) {
    std::string out;
    out.reserve(8 + token.size());
    out.append("token=");
    out.append(UrlEncode(token));
    return out;
}

std::string IntrospectionClient::BuildBodyBodyStyle(
        const std::string& token,
        const std::string& client_id,
        const std::string& client_secret) {
    std::string out;
    out.reserve(64 + token.size() + client_id.size() + client_secret.size());
    out.append("token=");
    out.append(UrlEncode(token));
    out.append("&client_id=");
    out.append(UrlEncode(client_id));
    out.append("&client_secret=");
    out.append(UrlEncode(client_secret));
    return out;
}

IntrospectionClient::Result IntrospectionClient::ParseResponseSafe(
        const UpstreamHttpClient::Response& resp,
        const AuthPolicy& policy,
        const std::vector<std::string>& claim_keys,
        const std::string& issuer_name) {
    Result result;

    nlohmann::json body;
    try {
        body = nlohmann::json::parse(resp.body);
    } catch (const std::exception& ex) {
        logging::Get()->warn(
            "introspection malformed response issuer={} body_size={} err={}",
            issuer_name, resp.body.size(), ex.what());
        result.vr = VerifyResult::Undetermined("introspection_malformed_response");
        return result;
    } catch (...) {
        logging::Get()->warn(
            "introspection malformed response issuer={} body_size={} err=non_std",
            issuer_name, resp.body.size());
        result.vr = VerifyResult::Undetermined("introspection_malformed_response");
        return result;
    }

    if (!body.is_object()) {
        logging::Get()->warn(
            "introspection malformed response issuer={} body_size={} reason=not_object",
            issuer_name, resp.body.size());
        result.vr = VerifyResult::Undetermined("introspection_malformed_response");
        return result;
    }

    bool active_value = false;
    bool active_present = false;
    try {
        auto it = body.find("active");
        if (it != body.end() && it->is_boolean()) {
            active_value = it->get<bool>();
            active_present = true;
        }
    } catch (const std::exception&) {
        active_present = false;
    } catch (...) {
        active_present = false;
    }

    if (!active_present) {
        logging::Get()->warn(
            "introspection missing/invalid active field issuer={}", issuer_name);
        result.vr = VerifyResult::Undetermined("introspection_missing_active");
        return result;
    }

    if (!active_value) {
        result.vr = VerifyResult::InvalidToken(
            "token is not active", "introspection_inactive");
        result.idp_active = false;
        return result;
    }

    // active == true. Populate AuthContext from the response body and run
    // per-request claim checks. idp_active stays true regardless of whether
    // the claim checks produce ALLOW / DENY_401 / DENY_403 — the IdP did
    // validate the token, so the cache layer can still record a positive
    // entry that's reusable across other policies.
    result.idp_active = true;
    try {
        PopulateFromPayload(body, claim_keys, result.ctx);
    } catch (const std::exception& ex) {
        logging::Get()->warn(
            "introspection populate_from_payload threw issuer={} err={}",
            issuer_name, ex.what());
        result.vr = VerifyResult::Undetermined("introspection_malformed_response");
        result.idp_active = false;
        return result;
    } catch (...) {
        logging::Get()->warn(
            "introspection populate_from_payload threw issuer={} err=non_std",
            issuer_name);
        result.vr = VerifyResult::Undetermined("introspection_malformed_response");
        result.idp_active = false;
        return result;
    }

    result.exp_from_resp = ExtractExpSafe(body);
    result.vr = RunPerRequestClaimChecks(policy, result.ctx, body);
    return result;
}

IntrospectionClient::Result IntrospectionClient::TranslateError(
        const UpstreamHttpClient::Response& resp,
        const std::string& issuer_name) {
    Result result;
    result.idp_active = false;

    const std::string& err = resp.error;

    if (!err.empty()) {
        if (err == "timeout") {
            logging::Get()->warn(
                "introspection timeout issuer={}", issuer_name);
            result.vr = VerifyResult::Undetermined("introspection_timeout");
            return result;
        }
        if (err == "connect_failed") {
            logging::Get()->warn(
                "introspection connect_failed issuer={}", issuer_name);
            result.vr = VerifyResult::Undetermined("introspection_connect_failed");
            return result;
        }
        if (err == "connect_timeout") {
            logging::Get()->warn(
                "introspection connect_timeout issuer={}", issuer_name);
            result.vr = VerifyResult::Undetermined("introspection_connect_timeout");
            return result;
        }
        if (err == "queue_timeout") {
            logging::Get()->warn(
                "introspection queue_timeout issuer={}", issuer_name);
            result.vr = VerifyResult::Undetermined("introspection_queue_timeout");
            return result;
        }
        if (err == "pool_exhausted") {
            logging::Get()->warn(
                "introspection pool_exhausted issuer={}", issuer_name);
            result.vr = VerifyResult::Undetermined("introspection_pool_exhausted");
            return result;
        }
        if (err == "circuit_open") {
            logging::Get()->warn(
                "introspection circuit_open issuer={}", issuer_name);
            result.vr = VerifyResult::Undetermined("introspection_circuit_open");
            return result;
        }
        if (err == "shutting_down") {
            logging::Get()->debug(
                "introspection shutting_down issuer={}", issuer_name);
            result.vr = VerifyResult::Undetermined("introspection_shutting_down");
            return result;
        }
        if (err == "parse_error") {
            logging::Get()->warn(
                "introspection parse_error issuer={}", issuer_name);
            result.vr = VerifyResult::Undetermined("introspection_parse_error");
            return result;
        }
        if (err == "body_too_large") {
            logging::Get()->error(
                "introspection body_too_large issuer={}", issuer_name);
            result.vr = VerifyResult::Undetermined("introspection_body_too_large");
            return result;
        }
        if (err == "upstream_disconnect") {
            logging::Get()->warn(
                "introspection upstream_disconnect issuer={}", issuer_name);
            result.vr = VerifyResult::Undetermined("introspection_upstream_disconnect");
            return result;
        }
        if (err == "dispatcher_out_of_range") {
            logging::Get()->error(
                "introspection_dispatcher_out_of_range issuer={} — "
                "wiring fault: dispatcher index outside configured count",
                logging::SanitizeLogValue(issuer_name));
            result.vr = VerifyResult::Undetermined("introspection_dispatcher_out_of_range");
            return result;
        }
        if (err == "no_upstream_manager" || err == "pool_unknown") {
            logging::Get()->error(
                "introspection upstream not configured issuer={} err={}",
                issuer_name, err);
            result.vr = VerifyResult::Undetermined(
                std::string("introspection_") + err);
            return result;
        }
        // Unknown shipped label — surface it so operators see it in logs
        // and the UNDETERMINED counter rolls up. The label remains stable
        // across releases because the upstream HTTP client uses fixed
        // strings.
        logging::Get()->error(
            "introspection unknown error label issuer={} err={}",
            issuer_name, err);
        result.vr = VerifyResult::Undetermined(
            std::string("introspection_unknown_error_") + err);
        return result;
    }

    // err empty -> a full HTTP response was received but status_code != 200.
    const int status = resp.status_code;
    if (status == 401) {
        logging::Get()->error(
            "introspection client_auth_failed issuer={} status=401", issuer_name);
        result.vr = VerifyResult::Undetermined("introspection_client_auth_failed");
        return result;
    }
    if (status >= 400 && status < 500) {
        logging::Get()->error(
            "introspection 4xx response issuer={} status={}", issuer_name, status);
        char buf[64];
        std::snprintf(buf, sizeof(buf), "introspection_4xx_status_%d", status);
        result.vr = VerifyResult::Undetermined(std::string(buf));
        return result;
    }
    if (status >= 500 && status < 600) {
        logging::Get()->warn(
            "introspection 5xx response issuer={} status={}", issuer_name, status);
        char buf[64];
        std::snprintf(buf, sizeof(buf), "introspection_5xx_status_%d", status);
        result.vr = VerifyResult::Undetermined(std::string(buf));
        return result;
    }

    // Any other non-200 / non-error path (1xx, 3xx, 0). Surface a generic
    // UNDETERMINED so operators can see the unexpected status.
    logging::Get()->error(
        "introspection unexpected status issuer={} status={}",
        issuer_name, status);
    char buf[64];
    std::snprintf(buf, sizeof(buf), "introspection_unexpected_status_%d", status);
    result.vr = VerifyResult::Undetermined(std::string(buf));
    return result;
}

void IntrospectionClient::Verify(
        std::weak_ptr<Issuer> weak_issuer,
        const std::string& endpoint,
        const std::string& client_id,
        const std::string& client_secret,
        const std::string& auth_style,
        const std::string& token,
        size_t dispatcher_index,
        const AuthPolicy& policy,
        const std::vector<std::string>& claim_keys,
        uint64_t generation,
        DoneCallback cb,
        std::shared_ptr<std::atomic<bool>> cancel_token) {
    auto deliver = [&](Result r) {
        if (cb) cb(std::move(r));
    };

    if (!client_) {
        Result r;
        r.vr = VerifyResult::Undetermined("introspection_client_not_configured");
        logging::Get()->error("IntrospectionClient::Verify with null client");
        deliver(std::move(r));
        return;
    }

    auto parsed = ParseHttpsUri(endpoint);
    if (parsed.host.empty()) {
        Result r;
        r.vr = VerifyResult::Undetermined("introspection_endpoint_invalid");
        logging::Get()->error(
            "IntrospectionClient endpoint missing host endpoint_size={}",
            endpoint.size());
        deliver(std::move(r));
        return;
    }
    std::string path = parsed.path_with_query;
    std::string query;
    auto qpos = path.find('?');
    if (qpos != std::string::npos) {
        query = path.substr(qpos + 1);
        path = path.substr(0, qpos);
    }

    // Build the request body and (optionally) the Authorization header
    // SYNCHRONOUSLY. client_secret is consumed entirely here and never
    // captured into the closure.
    std::string body_str;
    std::string auth_header;
    if (auth_style == "body") {
        body_str = BuildBodyBodyStyle(token, client_id, client_secret);
    } else {
        // Default / "basic". Anything other than "body" is treated as
        // basic — the config layer is responsible for the allowlist.
        body_str = BuildBodyBasic(token);
        auth_header = BuildAuthorizationHeaderBasic(client_id, client_secret);
        if (auth_header.empty()) {
            Result r;
            r.vr = VerifyResult::Undetermined("introspection_auth_header_build_failed");
            logging::Get()->error(
                "IntrospectionClient failed to build basic auth header");
            deliver(std::move(r));
            return;
        }
    }

    // Pin the issuer long enough to capture pool name + timeout; release
    // the strong ref before queueing the request.
    auto issuer = weak_issuer.lock();
    if (!issuer) {
        Result r;
        r.vr = VerifyResult::Undetermined("issuer_unavailable");
        logging::Get()->warn(
            "IntrospectionClient issuer gone before Issue endpoint_host_size={}",
            parsed.host.size());
        deliver(std::move(r));
        return;
    }

    auto snap = issuer->LoadSnapshot();
    const std::string issuer_name = issuer->name();
    const std::string upstream_pool_name = issuer->upstream();
    const int timeout_sec = (snap && snap->introspection.timeout_sec > 0)
        ? snap->introspection.timeout_sec
        : 3;

    UpstreamHttpClient::Request req;
    req.method = "POST";
    req.path = path.empty() ? std::string("/") : path;
    req.query = query;
    req.host_header = parsed.host;
    req.headers = BuildHeaders(parsed.host, auth_header, body_str.size());
    req.body = std::move(body_str);
    req.timeout_sec = timeout_sec;
    req.max_response_body = kIntrospectionMaxBodyBytes;

    // Drop the strong ref BEFORE Issue so the closure is the sole live
    // reference path. The closure captures weak_issuer + generation by
    // value; the strong ref returns through weak_issuer.lock() inside the
    // closure only when needed.
    issuer.reset();

    // By-value snapshot of every field the closure reads after Issue
    // returns. policy and claim_keys are copied (cheap — vector<string>).
    AuthPolicy policy_copy = policy;
    std::vector<std::string> claim_keys_copy = claim_keys;

    DoneCallback cb_local = std::move(cb);

    client_->Issue(
        upstream_pool_name,
        dispatcher_index,
        std::move(req),
        [weak_issuer, generation, cb_local, policy_copy, claim_keys_copy,
         issuer_name](UpstreamHttpClient::Response resp) {
            // Always-deliver discipline: every drop path constructs a
            // Result and calls cb_local exactly once, so the AsyncPending
            // state's Complete is reached and active_requests_ decrements.
            auto deliver_inner = [&](Result r) {
                if (cb_local) cb_local(std::move(r));
            };

            auto live_issuer = weak_issuer.lock();
            if (!live_issuer) {
                Result r;
                r.vr = VerifyResult::Undetermined("issuer_unavailable");
                logging::Get()->info(
                    "introspection drop issuer_unavailable issuer={}",
                    issuer_name);
                deliver_inner(std::move(r));
                return;
            }
            if (live_issuer->generation() != generation) {
                Result r;
                r.vr = VerifyResult::Undetermined("reload_in_flight");
                // info — outer auth_manager callback emits the canonical warn for these.
                logging::Get()->info(
                    "introspection drop reload_in_flight issuer={} captured_gen={} live_gen={}",
                    issuer_name, generation, live_issuer->generation());
                deliver_inner(std::move(r));
                return;
            }
            if (live_issuer->stopping()) {
                Result r;
                r.vr = VerifyResult::Undetermined("issuer_stopping");
                deliver_inner(std::move(r));
                return;
            }

            if (resp.error.empty() && resp.status_code == 200) {
                Result r = ParseResponseSafe(resp, policy_copy, claim_keys_copy,
                                              issuer_name);
                deliver_inner(std::move(r));
                return;
            }
            Result r = TranslateError(resp, issuer_name);
            deliver_inner(std::move(r));
        },
        cancel_token);
}

}  // namespace AUTH_NAMESPACE
