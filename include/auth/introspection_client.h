#pragma once

#include "common.h"
#include "auth/auth_config.h"
#include "auth/auth_context.h"
#include "auth/auth_result.h"
#include "auth/upstream_http_client.h"
// <string>, <vector>, <memory>, <functional>, <atomic>, <cstdint> via common.h

namespace AUTH_NAMESPACE {

class Issuer;

// One-shot RFC 7662 introspection client. Stateless except for the shared
// UpstreamHttpClient pointer; the actual per-request state lives on
// UpstreamHttpClient::Transaction (heap-owned via shared_ptr there).
//
// Lifetime: AuthManager owns a single instance and reuses it for every
// introspection POST. The completion callback fires on the dispatcher
// identified by `dispatcher_index` and ALWAYS runs exactly once — including
// on issuer-unavailable / generation-mismatch / stopping drop paths, so the
// caller never has to worry about a suspended request being orphaned.
//
// Thread-safety: `Verify` must be called on the dispatcher thread identified
// by `dispatcher_index` (same envelope as UpstreamHttpClient::Issue).
class IntrospectionClient {
 public:
    explicit IntrospectionClient(std::shared_ptr<UpstreamHttpClient> client);
    ~IntrospectionClient() = default;

    IntrospectionClient(const IntrospectionClient&) = delete;
    IntrospectionClient& operator=(const IntrospectionClient&) = delete;
    IntrospectionClient(IntrospectionClient&&) = delete;
    IntrospectionClient& operator=(IntrospectionClient&&) = delete;

    // Outcome of a single introspection round-trip. `vr` carries the verify-
    // pipeline verdict; `ctx` is populated only when `idp_active == true`.
    // `exp_from_resp` is the raw `exp` field (seconds since epoch) used by
    // the cache layer to clamp positive-entry TTLs; 0 when absent or
    // unparseable. `idp_active` is set explicitly from the JSON `active`
    // field — never inferred from optional fields like `ctx.subject`.
    struct Result {
        VerifyResult vr;
        AuthContext ctx;
        int64_t exp_from_resp = 0;
        bool idp_active = false;
    };
    using DoneCallback = std::function<void(Result)>;

    // Issue a POST to `endpoint` with `token` and route the parsed outcome
    // to `cb`. Inputs:
    //   issuer        - per-issuer state captured as weak_ptr in the
    //                   completion closure for the cache-insert path.
    //   endpoint      - https:// URL of the IdP introspection endpoint.
    //   client_id     - OAuth client id.
    //   client_secret - OAuth client secret. Consumed synchronously into
    //                   the Authorization header / body BEFORE Issue is
    //                   called; never captured into the closure.
    //   auth_style    - "basic" (Authorization: Basic ...) or "body"
    //                   (credentials in the form-encoded body).
    //   token         - raw bearer token. NEVER LOGGED.
    //   policy        - the matched AuthPolicy (full copy; cheap).
    //   claim_keys    - operator-configured forward-overlay claim names.
    //   generation    - issuer->generation() snapshot at dispatch time;
    //                   the closure compares against the live generation
    //                   to gate the cache insert.
    //   cb            - dispatcher-thread completion callback. Always
    //                   invoked exactly once per Verify call.
    //   cancel_token  - shared atomic flag observed by UpstreamHttpClient
    //                   to short-circuit queued waiters. Caller flips it
    //                   via cancel_token->store(true, release).
    void Verify(std::weak_ptr<Issuer> issuer,
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
                std::shared_ptr<std::atomic<bool>> cancel_token);

    // Test-visible helpers. Static so unit tests can exercise them without
    // standing up an UpstreamHttpClient. None of these touch the network.
    static std::string BuildAuthorizationHeaderBasic(const std::string& client_id,
                                                      const std::string& client_secret);
    static std::string UrlEncode(const std::string& in);
    static std::string BuildBodyBasic(const std::string& token);
    static std::string BuildBodyBodyStyle(const std::string& token,
                                           const std::string& client_id,
                                           const std::string& client_secret);

    // Parse a 200 response body and produce a fully-populated Result.
    // Exception-safe: every nlohmann::json call is in a try/catch; on any
    // failure path returns an UNDETERMINED Result with the appropriate
    // log_reason and idp_active=false.
    static Result ParseResponseSafe(const UpstreamHttpClient::Response& resp,
                                     const AuthPolicy& policy,
                                     const std::vector<std::string>& claim_keys,
                                     const std::string& issuer_name);

    // Translate a non-200 / network-error UpstreamHttpClient::Response into
    // an UNDETERMINED Result. Covers every shipped error label plus the
    // 4xx / 5xx HTTP-status branches; unknown error labels surface as
    // "introspection_unknown_error_<label>" so operators see them.
    static Result TranslateError(const UpstreamHttpClient::Response& resp,
                                  const std::string& issuer_name);

 private:
    std::shared_ptr<UpstreamHttpClient> client_;
};

}  // namespace AUTH_NAMESPACE
