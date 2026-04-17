#include "config/config_loader.h"
#include "auth/auth_config.h"
#include "http2/http2_constants.h"
#include "http/route_trie.h"         // ParsePattern, ValidatePattern for proxy route_prefix
#include "log/logger.h"
#include "rate_limit/rate_limit_zone.h"  // RateLimitZone::SHARD_COUNT
#include "nlohmann/json.hpp"

#include <fstream>
#include <sstream>
#include <arpa/inet.h>
#include <cstdlib>
#include <stdexcept>
#include <algorithm>
#include <unordered_set>
#include <limits>

using json = nlohmann::json;

// Strict integer parser for security-sensitive auth knobs.
//
// nlohmann/json's `j.value("key", default)` silently coerces non-integer
// JSON values — `true` becomes 1, `1.9` becomes 1 — which would let invalid
// configuration pass validation for fields like `leeway_sec`, `cache_sec`,
// `timeout_sec`, etc. An operator typo that stores `"leeway_sec": true`
// would result in a 1-second leeway instead of surfacing as a config error.
//
// This helper rejects non-integer JSON at parse time. `is_number_integer()`
// is the right gate: it returns true for both signed and unsigned integers
// and false for booleans, floats, null, strings, arrays, and objects.
//
// Range hardening (review round): `is_number_integer()` returns true for
// ANY integer that fits in nlohmann/json's internal int64/uint64
// representation, including ones that DON'T fit in `int`. Without an
// explicit range check, `v.get<int>()` would wrap or truncate values like
// 4294967297 — letting an operator's intended-large `leeway_sec` quietly
// validate as a small wrapped value. We read as int64/uint64 first,
// range-check against [INT_MIN, INT_MAX], and throw on overflow so
// out-of-range never reaches the caller.
static int ParseStrictInt(const nlohmann::json& j, const std::string& key,
                          int default_value, const std::string& context) {
    if (!j.contains(key)) return default_value;
    const auto& v = j[key];
    if (v.is_null()) return default_value;
    if (!v.is_number_integer()) {
        throw std::invalid_argument(
            context + "." + key + " must be an integer "
            "(got " + std::string(v.type_name()) + ")");
    }
    // Unsigned values that overflow uint64-to-int64 must be caught with
    // is_number_unsigned() FIRST — get<int64_t>() on a too-large unsigned
    // value would itself wrap before our range check could catch it.
    if (v.is_number_unsigned()) {
        uint64_t u = v.get<uint64_t>();
        if (u > static_cast<uint64_t>(std::numeric_limits<int>::max())) {
            throw std::invalid_argument(
                context + "." + key + " value " + std::to_string(u) +
                " is out of int range (max " +
                std::to_string(std::numeric_limits<int>::max()) + ")");
        }
        return static_cast<int>(u);
    }
    int64_t s = v.get<int64_t>();
    if (s < std::numeric_limits<int>::min() ||
        s > std::numeric_limits<int>::max()) {
        throw std::invalid_argument(
            context + "." + key + " value " + std::to_string(s) +
            " is out of int range [" +
            std::to_string(std::numeric_limits<int>::min()) + ", " +
            std::to_string(std::numeric_limits<int>::max()) + "]");
    }
    return static_cast<int>(s);
}

// Header-name allow-list helper for auth.forward.
//
// auth.forward injects HTTP request headers into the forwarded upstream
// request via HeaderRewriter (Phase 2 wiring). If an operator misconfigures
// the output names to reserved categories, the resulting request would be
// either malformed, ambiguous, or spoofable:
//
//   - HTTP/2 pseudo-headers (`:method`, `:path`, `:scheme`, `:authority`,
//     `:status`): nghttp2 rejects these as regular headers; injecting them
//     would either fail the request or be silently dropped depending on
//     the encoder.
//   - Hop-by-hop headers (RFC 7230 §6.1: Connection, Keep-Alive,
//     Proxy-Authenticate, Proxy-Authorization, TE, Trailer,
//     Transfer-Encoding, Upgrade): these are local to a single hop and
//     MUST NOT be forwarded; injecting them via auth would fight the
//     existing HeaderRewriter hop-by-hop strip.
//   - Framing-critical headers (Host, Content-Length, Content-Type,
//     Content-Encoding): a client-controlled claim could rewrite Host
//     (request smuggling vector against backends that trust it for
//     virtual-hosting), Content-Length (HTTP request smuggling), or
//     content typing (JSON/XML parser confusion).
//   - Authorization: would conflict with `preserve_authorization` —
//     either both write and one wins unpredictably, or the upstream
//     receives a forged identity.
//
// Match is case-insensitive. Caller passes already-lowercased name.
static bool IsReservedAuthForwardHeader(const std::string& lower) {
    if (!lower.empty() && lower[0] == ':') return true;  // HTTP/2 pseudo
    static const std::unordered_set<std::string> kReserved = {
        // Hop-by-hop per RFC 7230 §6.1
        "connection", "keep-alive", "proxy-authenticate",
        "proxy-authorization", "te", "trailer", "transfer-encoding",
        "upgrade",
        // Non-standard hop-by-hop legacy header that
        // HeaderRewriter::IsHopByHopHeader() also strips. Forwarding
        // identity through `proxy-connection` would be silently dropped
        // at outbound time, so reject at config load with a clear error
        // instead of a confusing empty-header symptom later.
        "proxy-connection",
        // Framing-critical (corrupting these is a smuggling/parser-confusion
        // vector against the upstream)
        "host", "content-length", "content-type", "content-encoding",
        // Conflicts with preserve_authorization
        "authorization",
    };
    return kReserved.count(lower) > 0;
}

// Serialize a single AuthPolicy to JSON (mirror of ParseAuthPolicy for
// ToJson round-trip). Omits defaulted fields only when they would collapse
// noisily; defaulted simple fields are always emitted to keep the output
// shape stable across round-trips.
static nlohmann::json SerializeAuthPolicy(const auth::AuthPolicy& p) {
    nlohmann::json out;
    if (!p.name.empty()) out["name"] = p.name;
    out["enabled"] = p.enabled;
    if (!p.applies_to.empty()) out["applies_to"] = p.applies_to;
    if (!p.issuers.empty()) out["issuers"] = p.issuers;
    if (!p.required_scopes.empty()) out["required_scopes"] = p.required_scopes;
    if (!p.required_audience.empty()) out["required_audience"] = p.required_audience;
    out["on_undetermined"] = p.on_undetermined;
    out["realm"] = p.realm;
    return out;
}

// Parse a single AuthPolicy JSON object. Used both for inline
// `upstreams[i].proxy.auth` and for top-level `auth.policies[]` entries.
// `context` is embedded in error messages so operators can locate the
// offending block.
//
// `allow_applies_to` controls whether the `applies_to` field is permitted
// in this JSON. Top-level policies set it to true (applies_to is the
// REQUIRED prefix declaration). Inline proxy.auth blocks set it to false:
// per design spec §3.2 / §5.2, the prefix for an inline policy is
// derived from `proxy.route_prefix` at AuthManager::RegisterPolicy time,
// and an inline `applies_to` would be silently ignored — the JSON would
// then describe a different protected path than what the runtime uses,
// which is a config-correctness bug. Reject loudly at parse time.
static void ParseAuthPolicy(const nlohmann::json& j, auth::AuthPolicy& out,
                            const std::string& context,
                            bool allow_applies_to = true) {
    if (!j.is_object()) {
        throw std::invalid_argument(context + " must be a JSON object");
    }
    // Defensive reset: callers today pass fresh AuthPolicy locals, but the
    // reload path (future Phase 3) can easily re-parse into an existing
    // object, in which case the *_vec fields would otherwise accumulate
    // entries across reloads. Clear up front — the only state preserved
    // across ParseAuthPolicy is what this function explicitly rewrites.
    out.applies_to.clear();
    out.issuers.clear();
    out.required_scopes.clear();
    out.name = j.value("name", std::string{});
    out.enabled = j.value("enabled", false);
    if (j.contains("applies_to")) {
        // Inline-policy guard: applies_to is meaningless inside an inline
        // proxy.auth block (the prefix comes from proxy.route_prefix).
        // Accepting it would let the JSON describe one protected path
        // while the runtime applies a different one — a misleading
        // round-trip and a likely operator-confusion vector. Reject and
        // tell the operator where the prefix actually comes from.
        if (!allow_applies_to) {
            throw std::invalid_argument(
                context + ".applies_to is not permitted on inline auth "
                "(the prefix is derived from the surrounding proxy's "
                "route_prefix, see design spec §3.2 / §5.2). Remove "
                "applies_to here, or move this policy to top-level "
                "auth.policies[] if it needs an explicit prefix list.");
        }
        if (!j["applies_to"].is_array()) {
            throw std::invalid_argument(
                context + ".applies_to must be an array of strings");
        }
        for (const auto& p : j["applies_to"]) {
            if (!p.is_string()) {
                throw std::invalid_argument(
                    context + ".applies_to entries must be strings");
            }
            out.applies_to.push_back(p.get<std::string>());
        }
    }
    if (j.contains("issuers")) {
        if (!j["issuers"].is_array()) {
            throw std::invalid_argument(
                context + ".issuers must be an array of strings");
        }
        for (const auto& p : j["issuers"]) {
            if (!p.is_string()) {
                throw std::invalid_argument(
                    context + ".issuers entries must be strings");
            }
            out.issuers.push_back(p.get<std::string>());
        }
    }
    if (j.contains("required_scopes")) {
        if (!j["required_scopes"].is_array()) {
            throw std::invalid_argument(
                context + ".required_scopes must be an array of strings");
        }
        for (const auto& p : j["required_scopes"]) {
            if (!p.is_string()) {
                throw std::invalid_argument(
                    context + ".required_scopes entries must be strings");
            }
            out.required_scopes.push_back(p.get<std::string>());
        }
    }
    out.required_audience = j.value("required_audience", std::string{});
    out.on_undetermined = j.value("on_undetermined", std::string("deny"));
    out.realm = j.value("realm", std::string("api"));
}

// Parse a single IssuerConfig JSON object for the top-level
// `auth.issuers[name]` map.
static void ParseIssuerConfig(const std::string& name, const nlohmann::json& j,
                              auth::IssuerConfig& out) {
    const std::string ctx = "auth.issuers." + name;
    if (!j.is_object()) {
        throw std::invalid_argument(ctx + " must be a JSON object");
    }
    out.name = name;
    out.issuer_url = j.value("issuer_url", std::string{});
    out.discovery = j.value("discovery", true);
    out.jwks_uri = j.value("jwks_uri", std::string{});
    out.upstream = j.value("upstream", std::string{});
    out.mode = j.value("mode", std::string("jwt"));
    out.leeway_sec = ParseStrictInt(j, "leeway_sec", 30, ctx);
    out.jwks_cache_sec = ParseStrictInt(j, "jwks_cache_sec", 300, ctx);
    out.jwks_refresh_timeout_sec =
        ParseStrictInt(j, "jwks_refresh_timeout_sec", 5, ctx);
    out.discovery_retry_sec =
        ParseStrictInt(j, "discovery_retry_sec", 30, ctx);

    if (j.contains("audiences")) {
        if (!j["audiences"].is_array()) {
            throw std::invalid_argument(ctx + ".audiences must be an array");
        }
        out.audiences.clear();
        for (const auto& v : j["audiences"]) {
            if (!v.is_string()) {
                throw std::invalid_argument(
                    ctx + ".audiences entries must be strings");
            }
            out.audiences.push_back(v.get<std::string>());
        }
    }
    if (j.contains("algorithms")) {
        if (!j["algorithms"].is_array()) {
            throw std::invalid_argument(ctx + ".algorithms must be an array");
        }
        out.algorithms.clear();
        for (const auto& v : j["algorithms"]) {
            if (!v.is_string()) {
                throw std::invalid_argument(
                    ctx + ".algorithms entries must be strings");
            }
            out.algorithms.push_back(v.get<std::string>());
        }
    }
    if (j.contains("required_claims")) {
        if (!j["required_claims"].is_array()) {
            throw std::invalid_argument(
                ctx + ".required_claims must be an array");
        }
        out.required_claims.clear();
        for (const auto& v : j["required_claims"]) {
            if (!v.is_string()) {
                throw std::invalid_argument(
                    ctx + ".required_claims entries must be strings");
            }
            out.required_claims.push_back(v.get<std::string>());
        }
    }
    if (j.contains("introspection")) {
        if (!j["introspection"].is_object()) {
            throw std::invalid_argument(
                ctx + ".introspection must be an object");
        }
        const auto& i = j["introspection"];
        // Reject inline client_secret — only env-var sourcing is allowed
        // (design spec §9 item 8, §5.3).
        if (i.contains("client_secret")) {
            throw std::invalid_argument(
                ctx + ".introspection.client_secret must NOT be set inline; "
                "use client_secret_env instead");
        }
        out.introspection.endpoint = i.value("endpoint", std::string{});
        out.introspection.client_id = i.value("client_id", std::string{});
        out.introspection.client_secret_env =
            i.value("client_secret_env", std::string{});
        out.introspection.auth_style =
            i.value("auth_style", std::string("basic"));
        const std::string ictx = ctx + ".introspection";
        out.introspection.timeout_sec =
            ParseStrictInt(i, "timeout_sec", 3, ictx);
        out.introspection.cache_sec =
            ParseStrictInt(i, "cache_sec", 60, ictx);
        out.introspection.negative_cache_sec =
            ParseStrictInt(i, "negative_cache_sec", 10, ictx);
        out.introspection.stale_grace_sec =
            ParseStrictInt(i, "stale_grace_sec", 30, ictx);
        out.introspection.max_entries =
            ParseStrictInt(i, "max_entries", 100000, ictx);
        out.introspection.shards = ParseStrictInt(i, "shards", 16, ictx);
    }
}

// Parse the top-level `auth` block into ServerConfig::auth.
static void ParseAuthConfig(const nlohmann::json& j, auth::AuthConfig& out) {
    if (!j.is_object()) {
        throw std::invalid_argument("auth must be a JSON object");
    }
    out.enabled = j.value("enabled", false);
    out.hmac_cache_key_env = j.value("hmac_cache_key_env", std::string{});

    if (j.contains("issuers")) {
        if (!j["issuers"].is_object()) {
            throw std::invalid_argument(
                "auth.issuers must be an object mapping name -> IssuerConfig");
        }
        for (auto it = j["issuers"].begin(); it != j["issuers"].end(); ++it) {
            auth::IssuerConfig ic;
            ParseIssuerConfig(it.key(), it.value(), ic);
            out.issuers.emplace(it.key(), std::move(ic));
        }
    }

    if (j.contains("policies")) {
        if (!j["policies"].is_array()) {
            throw std::invalid_argument(
                "auth.policies must be an array of AuthPolicy objects");
        }
        for (size_t i = 0; i < j["policies"].size(); ++i) {
            auth::AuthPolicy p;
            ParseAuthPolicy(j["policies"][i], p,
                            "auth.policies[" + std::to_string(i) + "]");
            out.policies.push_back(std::move(p));
        }
    }

    if (j.contains("forward")) {
        if (!j["forward"].is_object()) {
            throw std::invalid_argument("auth.forward must be an object");
        }
        const auto& f = j["forward"];
        out.forward.subject_header =
            f.value("subject_header", std::string("X-Auth-Subject"));
        out.forward.issuer_header =
            f.value("issuer_header", std::string("X-Auth-Issuer"));
        out.forward.scopes_header =
            f.value("scopes_header", std::string("X-Auth-Scopes"));
        out.forward.raw_jwt_header =
            f.value("raw_jwt_header", std::string{});
        out.forward.strip_inbound_identity_headers =
            f.value("strip_inbound_identity_headers", true);
        out.forward.preserve_authorization =
            f.value("preserve_authorization", true);
        if (f.contains("claims_to_headers")) {
            if (!f["claims_to_headers"].is_object()) {
                throw std::invalid_argument(
                    "auth.forward.claims_to_headers must be an object "
                    "mapping claim-name -> header-name");
            }
            for (auto it = f["claims_to_headers"].begin();
                 it != f["claims_to_headers"].end(); ++it) {
                if (!it.value().is_string()) {
                    throw std::invalid_argument(
                        "auth.forward.claims_to_headers values must be strings");
                }
                out.forward.claims_to_headers.emplace(
                    it.key(), it.value().get<std::string>());
            }
        }
    }
}

ServerConfig ConfigLoader::LoadFromFile(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open config file: " + path);
    }

    std::ostringstream ss;
    ss << file.rdbuf();
    return LoadFromString(ss.str());
}

ServerConfig ConfigLoader::LoadFromString(const std::string& json_str) {
    json j;
    try {
        j = json::parse(json_str);
    } catch (const json::parse_error& e) {
        throw std::runtime_error(std::string("JSON parse error: ") + e.what());
    }

    ServerConfig config;

    // Top-level fields
    if (j.contains("bind_host")) {
        if (!j["bind_host"].is_string())
            throw std::runtime_error("bind_host must be a string");
        config.bind_host = j["bind_host"].get<std::string>();
    }
    if (j.contains("bind_port")) {
        if (!j["bind_port"].is_number_integer())
            throw std::runtime_error("bind_port must be an integer");
        config.bind_port = j["bind_port"].get<int>();
    }
    if (j.contains("max_connections")) {
        if (!j["max_connections"].is_number_integer())
            throw std::runtime_error("max_connections must be an integer");
        config.max_connections = j["max_connections"].get<int>();
    }
    if (j.contains("idle_timeout_sec")) {
        if (!j["idle_timeout_sec"].is_number_integer())
            throw std::runtime_error("idle_timeout_sec must be an integer");
        config.idle_timeout_sec = j["idle_timeout_sec"].get<int>();
    }
    if (j.contains("worker_threads")) {
        if (!j["worker_threads"].is_number_integer())
            throw std::runtime_error("worker_threads must be an integer");
        config.worker_threads = j["worker_threads"].get<int>();
    }
    if (j.contains("max_header_size")) {
        if (j["max_header_size"].is_number_unsigned()) {
            config.max_header_size = j["max_header_size"].get<size_t>();
        } else {
            throw std::runtime_error("max_header_size must be a non-negative integer");
        }
    }
    if (j.contains("max_body_size")) {
        if (j["max_body_size"].is_number_unsigned()) {
            config.max_body_size = j["max_body_size"].get<size_t>();
        } else {
            throw std::runtime_error("max_body_size must be a non-negative integer");
        }
    }
    if (j.contains("max_ws_message_size")) {
        if (j["max_ws_message_size"].is_number_unsigned()) {
            config.max_ws_message_size = j["max_ws_message_size"].get<size_t>();
        } else {
            throw std::runtime_error("max_ws_message_size must be a non-negative integer");
        }
    }
    if (j.contains("request_timeout_sec")) {
        if (!j["request_timeout_sec"].is_number_integer())
            throw std::runtime_error("request_timeout_sec must be an integer");
        config.request_timeout_sec = j["request_timeout_sec"].get<int>();
    }
    if (j.contains("shutdown_drain_timeout_sec")) {
        if (!j["shutdown_drain_timeout_sec"].is_number_integer())
            throw std::runtime_error("shutdown_drain_timeout_sec must be an integer");
        config.shutdown_drain_timeout_sec = j["shutdown_drain_timeout_sec"].get<int>();
    }

    // TLS section
    if (j.contains("tls")) {
        if (!j["tls"].is_object())
            throw std::runtime_error("tls must be an object");
    }
    if (j.contains("tls") && j["tls"].is_object()) {
        auto& tls = j["tls"];
        if (tls.contains("enabled")) {
            if (!tls["enabled"].is_boolean())
                throw std::runtime_error("tls.enabled must be a boolean");
            config.tls.enabled = tls["enabled"].get<bool>();
        }
        if (tls.contains("cert_file")) {
            if (!tls["cert_file"].is_string())
                throw std::runtime_error("tls.cert_file must be a string");
            config.tls.cert_file = tls["cert_file"].get<std::string>();
        }
        if (tls.contains("key_file")) {
            if (!tls["key_file"].is_string())
                throw std::runtime_error("tls.key_file must be a string");
            config.tls.key_file = tls["key_file"].get<std::string>();
        }
        if (tls.contains("min_version")) {
            if (!tls["min_version"].is_string())
                throw std::runtime_error("tls.min_version must be a string");
            config.tls.min_version = tls["min_version"].get<std::string>();
        }
    }

    // HTTP/2 section
    if (j.contains("http2")) {
        if (!j["http2"].is_object())
            throw std::runtime_error("http2 must be an object");
        auto& h2 = j["http2"];
        if (h2.contains("enabled")) {
            if (!h2["enabled"].is_boolean())
                throw std::runtime_error("http2.enabled must be a boolean");
            config.http2.enabled = h2["enabled"].get<bool>();
        }
        if (h2.contains("max_concurrent_streams")) {
            if (!h2["max_concurrent_streams"].is_number_unsigned())
                throw std::runtime_error("http2.max_concurrent_streams must be a non-negative integer");
            config.http2.max_concurrent_streams = h2["max_concurrent_streams"].get<uint32_t>();
        }
        if (h2.contains("initial_window_size")) {
            if (!h2["initial_window_size"].is_number_unsigned())
                throw std::runtime_error("http2.initial_window_size must be a non-negative integer");
            config.http2.initial_window_size = h2["initial_window_size"].get<uint32_t>();
        }
        if (h2.contains("max_frame_size")) {
            if (!h2["max_frame_size"].is_number_unsigned())
                throw std::runtime_error("http2.max_frame_size must be a non-negative integer");
            config.http2.max_frame_size = h2["max_frame_size"].get<uint32_t>();
        }
        if (h2.contains("max_header_list_size")) {
            if (!h2["max_header_list_size"].is_number_unsigned())
                throw std::runtime_error("http2.max_header_list_size must be a non-negative integer");
            config.http2.max_header_list_size = h2["max_header_list_size"].get<uint32_t>();
        }
        if (h2.contains("enable_push")) {
            if (!h2["enable_push"].is_boolean())
                throw std::runtime_error("http2.enable_push must be a boolean");
            config.http2.enable_push = h2["enable_push"].get<bool>();
        }
    }

    // Log section
    if (j.contains("log")) {
        if (!j["log"].is_object())
            throw std::runtime_error("log must be an object");
    }
    if (j.contains("log") && j["log"].is_object()) {
        auto& log = j["log"];
        if (log.contains("level")) {
            if (!log["level"].is_string())
                throw std::runtime_error("log.level must be a string");
            config.log.level = log["level"].get<std::string>();
        }
        if (log.contains("file")) {
            if (!log["file"].is_string())
                throw std::runtime_error("log.file must be a string");
            config.log.file = log["file"].get<std::string>();
        }
        if (log.contains("max_file_size")) {
            if (log["max_file_size"].is_number_unsigned()) {
                config.log.max_file_size = log["max_file_size"].get<size_t>();
            } else {
                throw std::runtime_error("log.max_file_size must be a non-negative integer");
            }
        }
        if (log.contains("max_files")) {
            if (!log["max_files"].is_number_integer())
                throw std::runtime_error("log.max_files must be an integer");
            config.log.max_files = log["max_files"].get<int>();
        }
    }

    // Upstreams section
    if (j.contains("upstreams")) {
        if (!j["upstreams"].is_array())
            throw std::runtime_error("upstreams must be an array");
        for (const auto& item : j["upstreams"]) {
            if (!item.is_object())
                throw std::runtime_error("each upstream entry must be an object");
            UpstreamConfig upstream;
            upstream.name = item.value("name", "");
            upstream.host = item.value("host", "");
            upstream.port = item.value("port", 80);

            if (item.contains("tls")) {
                if (!item["tls"].is_object())
                    throw std::runtime_error("upstream tls must be an object");
                auto& tls = item["tls"];
                upstream.tls.enabled = tls.value("enabled", false);
                upstream.tls.ca_file = tls.value("ca_file", "");
                upstream.tls.verify_peer = tls.value("verify_peer", true);
                upstream.tls.sni_hostname = tls.value("sni_hostname", "");
                upstream.tls.min_version = tls.value("min_version", "1.2");
            }

            if (item.contains("pool")) {
                if (!item["pool"].is_object())
                    throw std::runtime_error("upstream pool must be an object");
                auto& pool = item["pool"];
                upstream.pool.max_connections = pool.value("max_connections", 64);
                upstream.pool.max_idle_connections = pool.value("max_idle_connections", 16);
                upstream.pool.connect_timeout_ms = pool.value("connect_timeout_ms", 5000);
                upstream.pool.idle_timeout_sec = pool.value("idle_timeout_sec", 90);
                upstream.pool.max_lifetime_sec = pool.value("max_lifetime_sec", 3600);
                upstream.pool.max_requests_per_conn = pool.value("max_requests_per_conn", 0);
            }

            if (item.contains("proxy")) {
                if (!item["proxy"].is_object())
                    throw std::runtime_error("upstream proxy must be an object");
                auto& proxy = item["proxy"];
                upstream.proxy.route_prefix = proxy.value("route_prefix", "");
                upstream.proxy.strip_prefix = proxy.value("strip_prefix", false);
                upstream.proxy.response_timeout_ms = proxy.value("response_timeout_ms", 30000);

                if (proxy.contains("methods")) {
                    if (!proxy["methods"].is_array())
                        throw std::runtime_error("upstream proxy methods must be an array");
                    for (const auto& m : proxy["methods"]) {
                        if (!m.is_string())
                            throw std::runtime_error("upstream proxy method must be a string");
                        upstream.proxy.methods.push_back(m.get<std::string>());
                    }
                }

                if (proxy.contains("header_rewrite")) {
                    if (!proxy["header_rewrite"].is_object())
                        throw std::runtime_error("upstream proxy header_rewrite must be an object");
                    auto& hr = proxy["header_rewrite"];
                    upstream.proxy.header_rewrite.set_x_forwarded_for = hr.value("set_x_forwarded_for", true);
                    upstream.proxy.header_rewrite.set_x_forwarded_proto = hr.value("set_x_forwarded_proto", true);
                    upstream.proxy.header_rewrite.set_via_header = hr.value("set_via_header", true);
                    upstream.proxy.header_rewrite.rewrite_host = hr.value("rewrite_host", true);
                }

                if (proxy.contains("retry")) {
                    if (!proxy["retry"].is_object())
                        throw std::runtime_error("upstream proxy retry must be an object");
                    auto& r = proxy["retry"];
                    upstream.proxy.retry.max_retries = r.value("max_retries", 0);
                    upstream.proxy.retry.retry_on_connect_failure = r.value("retry_on_connect_failure", true);
                    upstream.proxy.retry.retry_on_5xx = r.value("retry_on_5xx", false);
                    upstream.proxy.retry.retry_on_timeout = r.value("retry_on_timeout", false);
                    upstream.proxy.retry.retry_on_disconnect = r.value("retry_on_disconnect", true);
                    upstream.proxy.retry.retry_non_idempotent = r.value("retry_non_idempotent", false);
                }

                // Inline per-proxy auth policy. `applies_to` is derived from
                // `route_prefix` at AuthManager::RegisterPolicy time — the
                // inline stanza never declares its own `applies_to`. See
                // design spec §3.2 / §5.2. Pass `allow_applies_to=false`
                // so the parser rejects misleading inline applies_to
                // declarations at parse time, before they can mislead an
                // operator into thinking that field governs runtime
                // matching.
                if (proxy.contains("auth")) {
                    ParseAuthPolicy(
                        proxy["auth"],
                        upstream.proxy.auth,
                        "upstreams[" + upstream.name + "].proxy.auth",
                        /*allow_applies_to=*/false);
                }
            }

            if (item.contains("circuit_breaker")) {
                if (!item["circuit_breaker"].is_object())
                    throw std::runtime_error("upstream circuit_breaker must be an object");
                auto& cb = item["circuit_breaker"];
                // Strict integer accessor: rejects float/bool/string inputs
                // that nlohmann's default value<int>() would silently coerce
                // (e.g., 1.9 → 1, true → 1). Without this, malformed configs
                // pass Validate() and change breaker behavior in production.
                auto cb_int = [&cb](const char* name, int default_val) -> int {
                    if (!cb.contains(name)) return default_val;
                    const auto& v = cb[name];
                    if (!v.is_number_integer()) {
                        throw std::invalid_argument(
                            std::string("circuit_breaker.") + name +
                            " must be an integer");
                    }
                    return v.get<int>();
                };
                auto cb_bool = [&cb](const char* name, bool default_val) -> bool {
                    if (!cb.contains(name)) return default_val;
                    const auto& v = cb[name];
                    if (!v.is_boolean()) {
                        throw std::invalid_argument(
                            std::string("circuit_breaker.") + name +
                            " must be a boolean");
                    }
                    return v.get<bool>();
                };
                upstream.circuit_breaker.enabled =
                    cb_bool("enabled", false);
                upstream.circuit_breaker.dry_run =
                    cb_bool("dry_run", false);
                upstream.circuit_breaker.consecutive_failure_threshold =
                    cb_int("consecutive_failure_threshold", 5);
                upstream.circuit_breaker.failure_rate_threshold =
                    cb_int("failure_rate_threshold", 50);
                upstream.circuit_breaker.minimum_volume =
                    cb_int("minimum_volume", 20);
                upstream.circuit_breaker.window_seconds =
                    cb_int("window_seconds", 10);
                upstream.circuit_breaker.permitted_half_open_calls =
                    cb_int("permitted_half_open_calls", 5);
                upstream.circuit_breaker.base_open_duration_ms =
                    cb_int("base_open_duration_ms", 5000);
                upstream.circuit_breaker.max_open_duration_ms =
                    cb_int("max_open_duration_ms", 60000);
                upstream.circuit_breaker.max_ejection_percent_per_host_set =
                    cb_int("max_ejection_percent_per_host_set", 50);
                upstream.circuit_breaker.retry_budget_percent =
                    cb_int("retry_budget_percent", 20);
                upstream.circuit_breaker.retry_budget_min_concurrency =
                    cb_int("retry_budget_min_concurrency", 3);
            }

            config.upstreams.push_back(std::move(upstream));
        }
    }

    // Rate limit section
    if (j.contains("rate_limit")) {
        if (!j["rate_limit"].is_object())
            throw std::runtime_error("rate_limit must be an object");
        auto& rl = j["rate_limit"];
        if (rl.contains("enabled")) {
            if (!rl["enabled"].is_boolean())
                throw std::runtime_error("rate_limit.enabled must be a boolean");
            config.rate_limit.enabled = rl["enabled"].get<bool>();
        }
        if (rl.contains("dry_run")) {
            if (!rl["dry_run"].is_boolean())
                throw std::runtime_error("rate_limit.dry_run must be a boolean");
            config.rate_limit.dry_run = rl["dry_run"].get<bool>();
        }
        if (rl.contains("status_code")) {
            if (!rl["status_code"].is_number_integer())
                throw std::runtime_error("rate_limit.status_code must be an integer");
            config.rate_limit.status_code = rl["status_code"].get<int>();
        }
        if (rl.contains("include_headers")) {
            if (!rl["include_headers"].is_boolean())
                throw std::runtime_error("rate_limit.include_headers must be a boolean");
            config.rate_limit.include_headers = rl["include_headers"].get<bool>();
        }
        if (rl.contains("zones")) {
            if (!rl["zones"].is_array())
                throw std::runtime_error("rate_limit.zones must be an array");
            for (const auto& item : rl["zones"]) {
                if (!item.is_object())
                    throw std::runtime_error("each rate_limit zone entry must be an object");
                RateLimitZoneConfig zone;
                zone.name = item.value("name", "");
                if (item.contains("rate")) {
                    if (!item["rate"].is_number())
                        throw std::runtime_error("rate_limit zone rate must be a number");
                    zone.rate = item["rate"].get<double>();
                }
                if (item.contains("capacity")) {
                    if (!item["capacity"].is_number_integer())
                        throw std::runtime_error("rate_limit zone capacity must be an integer");
                    zone.capacity = item["capacity"].get<int64_t>();
                }
                zone.key_type = item.value("key_type", "client_ip");
                zone.max_entries = item.value("max_entries", 100000);
                if (item.contains("applies_to")) {
                    if (!item["applies_to"].is_array())
                        throw std::runtime_error("rate_limit zone applies_to must be an array");
                    for (const auto& prefix : item["applies_to"]) {
                        if (!prefix.is_string())
                            throw std::runtime_error("rate_limit zone applies_to entry must be a string");
                        std::string p = prefix.get<std::string>();
                        // Reject empty prefixes: RateLimitZone::Check() calls
                        // prefix.back() which is UB on empty strings, and an
                        // empty prefix semantically means "no filter" which
                        // should be expressed as an empty applies_to array.
                        if (p.empty())
                            throw std::runtime_error("rate_limit zone applies_to entry must not be empty");
                        zone.applies_to.push_back(std::move(p));
                    }
                }
                config.rate_limit.zones.push_back(std::move(zone));
            }
        }
    }

    // Top-level auth config section (OAuth 2.0 token validation — §5.1).
    // Parsed into config.auth; actually consumed by AuthManager at startup
    // and by HttpServer::Reload() via AuthManager::Reload(). Per-proxy
    // auth stanzas are handled inline in the upstreams loop above; the
    // top-level section here owns the named issuers registry, the
    // top-level `auth.policies[]` with explicit applies_to, the forward
    // overlay config, and the HMAC cache-key env-var name.
    if (j.contains("auth")) {
        ParseAuthConfig(j["auth"], config.auth);
    }

    return config;
}

// Helper: parse env var as int, throw descriptive error on invalid input
static int EnvToInt(const char* val, const char* env_name) {
    try {
        size_t pos = 0;
        int result = std::stoi(val, &pos);
        // Reject trailing non-numeric characters (e.g., "8080junk")
        if (pos != std::strlen(val)) {
            throw std::runtime_error(
                std::string("Invalid integer for ") + env_name + ": " + val);
        }
        return result;
    } catch (const std::invalid_argument&) {
        throw std::runtime_error(
            std::string("Invalid integer for ") + env_name + ": " + val);
    } catch (const std::out_of_range&) {
        throw std::runtime_error(
            std::string("Integer out of range for ") + env_name + ": " + val);
    }
}

void ConfigLoader::ApplyEnvOverrides(ServerConfig& config) {
    const char* val = nullptr;

    val = std::getenv("REACTOR_BIND_HOST");
    if (val) config.bind_host = val;

    val = std::getenv("REACTOR_BIND_PORT");
    if (val) config.bind_port = EnvToInt(val, "REACTOR_BIND_PORT");

    val = std::getenv("REACTOR_TLS_ENABLED");
    if (val) {
        std::string s(val);
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::tolower(c); });
        if (s == "1" || s == "true" || s == "yes") {
            config.tls.enabled = true;
        } else if (s == "0" || s == "false" || s == "no") {
            config.tls.enabled = false;
        } else {
            throw std::invalid_argument(
                "Invalid REACTOR_TLS_ENABLED: '" + std::string(val) +
                "' (must be true/false/yes/no/1/0)");
        }
    }

    val = std::getenv("REACTOR_TLS_CERT");
    if (val) config.tls.cert_file = val;

    val = std::getenv("REACTOR_TLS_KEY");
    if (val) config.tls.key_file = val;

    val = std::getenv("REACTOR_LOG_LEVEL");
    if (val) config.log.level = val;

    val = std::getenv("REACTOR_LOG_FILE");
    if (val) config.log.file = val;

    val = std::getenv("REACTOR_MAX_CONNECTIONS");
    if (val) config.max_connections = EnvToInt(val, "REACTOR_MAX_CONNECTIONS");

    val = std::getenv("REACTOR_IDLE_TIMEOUT");
    if (val) config.idle_timeout_sec = EnvToInt(val, "REACTOR_IDLE_TIMEOUT");

    val = std::getenv("REACTOR_WORKER_THREADS");
    if (val) config.worker_threads = EnvToInt(val, "REACTOR_WORKER_THREADS");

    val = std::getenv("REACTOR_REQUEST_TIMEOUT");
    if (val) config.request_timeout_sec = EnvToInt(val, "REACTOR_REQUEST_TIMEOUT");

    val = std::getenv("REACTOR_SHUTDOWN_DRAIN_TIMEOUT");
    if (val) config.shutdown_drain_timeout_sec = EnvToInt(val, "REACTOR_SHUTDOWN_DRAIN_TIMEOUT");

    // HTTP/2 env overrides
    val = std::getenv("REACTOR_HTTP2_ENABLED");
    if (val) {
        std::string s(val);
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::tolower(c); });
        if (s == "1" || s == "true" || s == "yes") {
            config.http2.enabled = true;
        } else if (s == "0" || s == "false" || s == "no") {
            config.http2.enabled = false;
        } else {
            throw std::invalid_argument(
                "Invalid REACTOR_HTTP2_ENABLED: '" + std::string(val) +
                "' (must be true/false/yes/no/1/0)");
        }
    }
    val = std::getenv("REACTOR_HTTP2_MAX_CONCURRENT_STREAMS");
    if (val) {
        int v = EnvToInt(val, "REACTOR_HTTP2_MAX_CONCURRENT_STREAMS");
        if (v < 0) throw std::runtime_error(
            "REACTOR_HTTP2_MAX_CONCURRENT_STREAMS must be non-negative");
        config.http2.max_concurrent_streams = static_cast<uint32_t>(v);
    }
    val = std::getenv("REACTOR_HTTP2_INITIAL_WINDOW_SIZE");
    if (val) {
        int v = EnvToInt(val, "REACTOR_HTTP2_INITIAL_WINDOW_SIZE");
        if (v < 0) throw std::runtime_error(
            "REACTOR_HTTP2_INITIAL_WINDOW_SIZE must be non-negative");
        config.http2.initial_window_size = static_cast<uint32_t>(v);
    }
    val = std::getenv("REACTOR_HTTP2_MAX_FRAME_SIZE");
    if (val) {
        int v = EnvToInt(val, "REACTOR_HTTP2_MAX_FRAME_SIZE");
        if (v < 0) throw std::runtime_error(
            "REACTOR_HTTP2_MAX_FRAME_SIZE must be non-negative");
        config.http2.max_frame_size = static_cast<uint32_t>(v);
    }
    val = std::getenv("REACTOR_HTTP2_MAX_HEADER_LIST_SIZE");
    if (val) {
        int v = EnvToInt(val, "REACTOR_HTTP2_MAX_HEADER_LIST_SIZE");
        if (v < 0) throw std::runtime_error(
            "REACTOR_HTTP2_MAX_HEADER_LIST_SIZE must be non-negative");
        config.http2.max_header_list_size = static_cast<uint32_t>(v);
    }
    val = std::getenv("REACTOR_HTTP2_ENABLE_PUSH");
    if (val) {
        std::string s(val);
        std::transform(s.begin(), s.end(), s.begin(),
                       [](unsigned char c){ return std::tolower(c); });
        if (s == "1" || s == "true" || s == "yes" || s == "on") {
            config.http2.enable_push = true;
        } else if (s == "0" || s == "false" || s == "no" || s == "off") {
            config.http2.enable_push = false;
        } else {
            throw std::invalid_argument(
                "Invalid REACTOR_HTTP2_ENABLE_PUSH: '" + std::string(val) +
                "' (must be true/false/yes/no/on/off/1/0)");
        }
    }

    // No per-upstream environment variable overrides. Upstream configuration
    // is complex (array of named objects) and best managed through the JSON
    // config file. Individual upstream settings are not overridable via env.

    // Rate limit env overrides
    val = std::getenv("REACTOR_RATE_LIMIT_ENABLED");
    if (val) {
        std::string s(val);
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::tolower(c); });
        if (s == "1" || s == "true" || s == "yes") {
            config.rate_limit.enabled = true;
        } else if (s == "0" || s == "false" || s == "no") {
            config.rate_limit.enabled = false;
        } else {
            throw std::invalid_argument(
                "Invalid REACTOR_RATE_LIMIT_ENABLED: '" + std::string(val) +
                "' (must be true/false/yes/no/1/0)");
        }
    }
    val = std::getenv("REACTOR_RATE_LIMIT_DRY_RUN");
    if (val) {
        std::string s(val);
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::tolower(c); });
        if (s == "1" || s == "true" || s == "yes") {
            config.rate_limit.dry_run = true;
        } else if (s == "0" || s == "false" || s == "no") {
            config.rate_limit.dry_run = false;
        } else {
            throw std::invalid_argument(
                "Invalid REACTOR_RATE_LIMIT_DRY_RUN: '" + std::string(val) +
                "' (must be true/false/yes/no/1/0)");
        }
    }
    val = std::getenv("REACTOR_RATE_LIMIT_STATUS_CODE");
    if (val) config.rate_limit.status_code = EnvToInt(val, "REACTOR_RATE_LIMIT_STATUS_CODE");
}

void ConfigLoader::ValidateHotReloadable(
        const ServerConfig& config,
        const std::unordered_set<std::string>& live_upstream_names) {
    // Mirrors the circuit_breaker validation block in Validate().
    // Kept in lock-step with that block — any rule added there for a
    // hot-reloadable field must be added here too, or the SIGHUP
    // reload path would silently accept values the startup path
    // rejects (which is exactly the regression this helper exists
    // to prevent).

    // Reject duplicate upstream service names BEFORE the per-upstream
    // CB validation. Even for new/renamed entries, the file is
    // malformed if names collide: `CircuitBreakerManager::Reload`
    // iterates the new upstream list and applies each entry's
    // `circuit_breaker` block to GetHost(name); duplicates would
    // silently overwrite (last-write wins). Startup's full Validate()
    // rejects the file outright; the hot-reload path must match.
    // This rule runs UNCONDITIONALLY on the new config — it doesn't
    // depend on `live_upstream_names`.
    {
        std::unordered_set<std::string> seen;
        seen.reserve(config.upstreams.size());
        for (size_t i = 0; i < config.upstreams.size(); ++i) {
            const auto& name = config.upstreams[i].name;
            if (!seen.insert(name).second) {
                throw std::invalid_argument(
                    "upstreams[" + std::to_string(i) +
                    "] duplicate service name '" + name +
                    "' (upstream service names must be unique)");
            }
        }
    }

    for (size_t i = 0; i < config.upstreams.size(); ++i) {
        const auto& u = config.upstreams[i];
        const std::string idx = "upstreams[" + std::to_string(i) + "]";

        // CB-field validation is scoped to upstreams that are LIVE in
        // the running server. CircuitBreakerManager::Reload only
        // applies CB changes to pre-existing hosts — new/renamed
        // entries are restart-only and skipped with a warn — so
        // validating their CB blocks here would block otherwise-safe
        // reloads (e.g. a reload that stages a new upstream alongside
        // a log-level edit would abort even though the live server
        // would never apply the new upstream's CB block).
        //
        // The empty-set case (no live upstreams yet) is handled by
        // the same check: every entry is "new", so every entry is
        // skipped — only the duplicate-name check runs.
        if (live_upstream_names.find(u.name) == live_upstream_names.end()) {
            continue;
        }
        const auto& cb = u.circuit_breaker;
        if (cb.consecutive_failure_threshold < 1 ||
            cb.consecutive_failure_threshold > 10000) {
            throw std::invalid_argument(
                idx + " ('" + u.name +
                "'): circuit_breaker.consecutive_failure_threshold must be in [1, 10000]");
        }
        if (cb.failure_rate_threshold < 0 || cb.failure_rate_threshold > 100) {
            throw std::invalid_argument(
                idx + " ('" + u.name +
                "'): circuit_breaker.failure_rate_threshold must be in [0, 100]");
        }
        if (cb.minimum_volume < 1 || cb.minimum_volume > 10000000) {
            throw std::invalid_argument(
                idx + " ('" + u.name +
                "'): circuit_breaker.minimum_volume must be in [1, 10000000]");
        }
        if (cb.window_seconds < 1 || cb.window_seconds > 3600) {
            throw std::invalid_argument(
                idx + " ('" + u.name +
                "'): circuit_breaker.window_seconds must be in [1, 3600]");
        }
        if (cb.permitted_half_open_calls < 1 ||
            cb.permitted_half_open_calls > 1000) {
            throw std::invalid_argument(
                idx + " ('" + u.name +
                "'): circuit_breaker.permitted_half_open_calls must be in [1, 1000]");
        }
        if (cb.base_open_duration_ms < 100) {
            throw std::invalid_argument(
                idx + " ('" + u.name +
                "'): circuit_breaker.base_open_duration_ms must be >= 100");
        }
        if (cb.max_open_duration_ms < cb.base_open_duration_ms) {
            throw std::invalid_argument(
                idx + " ('" + u.name +
                "'): circuit_breaker.max_open_duration_ms must be >= base_open_duration_ms");
        }
        if (cb.max_ejection_percent_per_host_set < 0 ||
            cb.max_ejection_percent_per_host_set > 100) {
            throw std::invalid_argument(
                idx + " ('" + u.name +
                "'): circuit_breaker.max_ejection_percent_per_host_set must be in [0, 100]");
        }
        if (cb.retry_budget_percent < 0 || cb.retry_budget_percent > 100) {
            throw std::invalid_argument(
                idx + " ('" + u.name +
                "'): circuit_breaker.retry_budget_percent must be in [0, 100]");
        }
        if (cb.retry_budget_min_concurrency < 0) {
            throw std::invalid_argument(
                idx + " ('" + u.name +
                "'): circuit_breaker.retry_budget_min_concurrency must be >= 0");
        }
    }
}

void ConfigLoader::Validate(const ServerConfig& config) {
    // Validate bind_host is a strict dotted-quad IPv4 address.
    // Use inet_pton (not inet_addr) to reject legacy shorthand forms
    // like "1" (→ 0.0.0.1) or octal "0127.0.0.1" (→ 87.0.0.1).
    if (config.bind_host.empty()) {
        throw std::invalid_argument("bind_host must not be empty");
    }
    {
        struct in_addr addr{};
        if (inet_pton(AF_INET, config.bind_host.c_str(), &addr) != 1) {
            throw std::invalid_argument(
                "Invalid bind_host: '" + config.bind_host +
                "' (must be a dotted-quad IPv4 address, e.g. '0.0.0.0' or '127.0.0.1')");
        }
    }

    if (config.bind_port < 0 || config.bind_port > 65535) {
        throw std::invalid_argument(
            "Invalid bind_port: " + std::to_string(config.bind_port) +
            " (must be 0-65535)");
    }

    // 0 = unlimited (sentinel), negative = invalid
    if (config.max_connections < 0) {
        throw std::invalid_argument(
            "Invalid max_connections: " + std::to_string(config.max_connections) +
            " (must be >= 0, 0 = unlimited)");
    }

    // 0 = auto-detect (hardware_concurrency), negative = invalid
    if (config.worker_threads < 0) {
        throw std::invalid_argument(
            "Invalid worker_threads: " + std::to_string(config.worker_threads) +
            " (must be >= 0, 0 = auto)");
    }

    // 0 = disabled (sentinel), negative = invalid
    if (config.idle_timeout_sec < 0) {
        throw std::invalid_argument(
            "Invalid idle_timeout_sec: " + std::to_string(config.idle_timeout_sec) +
            " (must be >= 0, 0 = disabled)");
    }

    if (config.shutdown_drain_timeout_sec < 0 || config.shutdown_drain_timeout_sec > 300) {
        throw std::invalid_argument(
            "Invalid shutdown_drain_timeout_sec: " +
            std::to_string(config.shutdown_drain_timeout_sec) +
            " (must be 0-300)");
    }

    if (config.request_timeout_sec < 0) {
        throw std::invalid_argument(
            "Invalid request_timeout_sec: " + std::to_string(config.request_timeout_sec) +
            " (must be >= 0, 0 = disabled)");
    }

    // Bound size limits to prevent overflow in ComputeInputCap() where
    // max_header_size + max_body_size must not wrap size_t. Individual cap
    // at SIZE_MAX/2 ensures any pair sums safely on both 32-bit and 64-bit.
    static constexpr size_t MAX_SIZE_LIMIT = SIZE_MAX / 2;
    if (config.max_body_size > MAX_SIZE_LIMIT) {
        throw std::invalid_argument(
            "Invalid max_body_size: " + std::to_string(config.max_body_size) +
            " (exceeds maximum)");
    }
    if (config.max_header_size > MAX_SIZE_LIMIT) {
        throw std::invalid_argument(
            "Invalid max_header_size: " + std::to_string(config.max_header_size) +
            " (exceeds maximum)");
    }
    if (config.max_ws_message_size > MAX_SIZE_LIMIT) {
        throw std::invalid_argument(
            "Invalid max_ws_message_size: " + std::to_string(config.max_ws_message_size) +
            " (exceeds maximum)");
    }

    // Validate log level against the set recognized by logging::ParseLevel().
    // ParseLevel returns info for unrecognized strings — if the input isn't
    // literally "info" but maps to info, it's unrecognized (including empty).
    {
        spdlog::level::level_enum parsed = logging::ParseLevel(config.log.level);
        if (parsed == spdlog::level::info && config.log.level != "info") {
            throw std::invalid_argument(
                "Invalid log.level: '" + config.log.level +
                "' (must be trace, debug, info, warn, error, or critical)");
        }
    }

    // Validate log rotation settings when file logging is configured.
    // spdlog::rotating_file_sink_mt throws on max_size == 0, and negative
    // max_files converts to a huge size_t causing resource exhaustion.
    if (!config.log.file.empty()) {
        // Reject paths with empty basename (e.g., "/tmp/logs/" or just "/")
        // which would produce malformed date-based filenames.
        {
            auto last_slash = config.log.file.rfind('/');
            std::string basename = (last_slash != std::string::npos)
                ? config.log.file.substr(last_slash + 1)
                : config.log.file;
            if (basename.empty() || basename == "." || basename == "..") {
                throw std::invalid_argument(
                    "Invalid log.file: '" + config.log.file +
                    "' (must include a valid filename, not a directory path)");
            }
        }
        if (config.log.max_file_size == 0) {
            throw std::invalid_argument(
                "Invalid log.max_file_size: 0 (must be > 0 when log.file is set)");
        }
        if (config.log.max_files < 1) {
            throw std::invalid_argument(
                "Invalid log.max_files: " + std::to_string(config.log.max_files) +
                " (must be >= 1 when log.file is set)");
        }
    }

    // HTTP/2 validation (RFC 9113 constraints)
    if (config.http2.enabled) {
        if (config.http2.max_concurrent_streams < 1) {
            throw std::invalid_argument(
                "http2.max_concurrent_streams must be >= 1");
        }
        if (config.http2.initial_window_size < 1 ||
            config.http2.initial_window_size > HTTP2_CONSTANTS::MAX_WINDOW_SIZE) {
            throw std::invalid_argument(
                "http2.initial_window_size must be 1 to 2^31-1");
        }
        if (config.http2.max_frame_size < HTTP2_CONSTANTS::MIN_MAX_FRAME_SIZE ||
            config.http2.max_frame_size > HTTP2_CONSTANTS::MAX_MAX_FRAME_SIZE) {
            throw std::invalid_argument(
                "http2.max_frame_size must be 16384 to 16777215");
        }
        if (config.http2.max_header_list_size < 1) {
            throw std::invalid_argument(
                "http2.max_header_list_size must be >= 1");
        }
    }

    if (config.tls.enabled) {
        if (config.tls.cert_file.empty()) {
            throw std::invalid_argument(
                "TLS is enabled but cert_file is empty");
        }
        if (config.tls.key_file.empty()) {
            throw std::invalid_argument(
                "TLS is enabled but key_file is empty");
        }
        // Check cert/key files exist and are regular files. Uses stat()
        // which only needs directory traversal permission, not read access —
        // so CI/operator validation works even when the certs are owned by
        // the daemon user. TlsContext does the full OpenSSL load at runtime.
        {
            struct stat st{};
            if (stat(config.tls.cert_file.c_str(), &st) != 0) {
                if (errno == EACCES) {
                    // Can't traverse path — skip check, TlsContext handles it
                } else {
                    throw std::invalid_argument(
                        "TLS cert_file not found: '" + config.tls.cert_file +
                        "' (" + std::strerror(errno) + ")");
                }
            } else if (!S_ISREG(st.st_mode)) {
                throw std::invalid_argument(
                    "TLS cert_file is not a regular file: '" + config.tls.cert_file + "'");
            }
        }
        {
            struct stat st{};
            if (stat(config.tls.key_file.c_str(), &st) != 0) {
                if (errno == EACCES) {
                    // Can't traverse path — skip check, TlsContext handles it
                } else {
                    throw std::invalid_argument(
                        "TLS key_file not found: '" + config.tls.key_file +
                        "' (" + std::strerror(errno) + ")");
                }
            } else if (!S_ISREG(st.st_mode)) {
                throw std::invalid_argument(
                    "TLS key_file is not a regular file: '" + config.tls.key_file + "'");
            }
        }
        if (config.tls.min_version != "1.2" && config.tls.min_version != "1.3") {
            throw std::invalid_argument(
                "Invalid tls.min_version: '" + config.tls.min_version +
                "' (must be '1.2' or '1.3')");
        }
    }

    // Upstream validation
    {
        std::unordered_set<std::string> seen_names;
        for (size_t i = 0; i < config.upstreams.size(); ++i) {
            const auto& u = config.upstreams[i];
            const std::string idx = "upstreams[" + std::to_string(i) + "]";

            if (u.name.empty()) {
                throw std::invalid_argument(idx + ".name must not be empty");
            }
            if (!seen_names.insert(u.name).second) {
                throw std::invalid_argument(
                    "Duplicate upstream name: '" + u.name + "'");
            }
            if (u.host.empty()) {
                throw std::invalid_argument(
                    idx + " ('" + u.name + "'): host must not be empty");
            }
            // Upstream host must be a dotted-quad IPv4 address (no hostnames).
            // Hostnames would pass validation but fail at connect time with
            // inet_addr() returning INADDR_NONE. Reject early with a clear error.
            {
                struct in_addr upstream_addr{};
                if (inet_pton(AF_INET, u.host.c_str(), &upstream_addr) != 1) {
                    throw std::invalid_argument(
                        idx + " ('" + u.name + "'): host must be a valid IPv4 address, got '" +
                        u.host + "'");
                }
            }
            if (u.port < 1 || u.port > 65535) {
                throw std::invalid_argument(
                    idx + " ('" + u.name + "'): port must be 1-65535, got " +
                    std::to_string(u.port));
            }

            // Pool constraints
            if (u.pool.max_connections < 1) {
                throw std::invalid_argument(
                    idx + " ('" + u.name + "'): pool.max_connections must be >= 1");
            }
            // When max_connections < worker_threads, some dispatcher
            // partitions will have zero capacity (requests queue and time
            // out). This is intentional for deployments that cap upstream
            // concurrency tightly (e.g., 4 backend connections across 8
            // workers). UpstreamHostPool logs a warning at construction;
            // validation does not reject the config.
            if (u.pool.max_idle_connections < 0 ||
                u.pool.max_idle_connections > u.pool.max_connections) {
                throw std::invalid_argument(
                    idx + " ('" + u.name +
                    "'): pool.max_idle_connections must be 0 to pool.max_connections (" +
                    std::to_string(u.pool.max_connections) + ")");
            }
            if (u.pool.connect_timeout_ms < 1000) {
                throw std::invalid_argument(
                    idx + " ('" + u.name +
                    "'): pool.connect_timeout_ms must be >= 1000 (timer resolution is 1s)");
            }
            if (u.pool.idle_timeout_sec < 1) {
                throw std::invalid_argument(
                    idx + " ('" + u.name +
                    "'): pool.idle_timeout_sec must be >= 1");
            }
            if (u.pool.max_lifetime_sec < 0) {
                throw std::invalid_argument(
                    idx + " ('" + u.name +
                    "'): pool.max_lifetime_sec must be >= 0 (0 = unlimited)");
            }
            if (u.pool.max_requests_per_conn < 0) {
                throw std::invalid_argument(
                    idx + " ('" + u.name +
                    "'): pool.max_requests_per_conn must be >= 0 (0 = unlimited)");
            }

            // Proxy config validation.
            //
            // route_prefix is the only field that's skipped when empty —
            // the manual HttpServer::Proxy() API intentionally leaves it
            // empty and passes the pattern as a code argument, so there's
            // nothing to parse here. All the other proxy settings
            // (methods, response_timeout_ms, retry) are read by the manual
            // API at registration time and need to be validated up-front
            // so bad values fail fast at config load instead of surfacing
            // later as a logged "Proxy: registration error" that silently
            // drops the route.
            if (!u.proxy.route_prefix.empty()) {
                // Validate route_prefix is a well-formed route pattern.
                // Catches double slashes, duplicate param names, catch-all
                // not last, etc. — these would otherwise crash at startup
                // when RegisterProxyRoutes calls RouteAsync.
                try {
                    auto segments = ROUTE_TRIE::ParsePattern(u.proxy.route_prefix);
                    ROUTE_TRIE::ValidatePattern(u.proxy.route_prefix, segments);
                } catch (const std::invalid_argument& e) {
                    throw std::invalid_argument(
                        idx + " ('" + u.name +
                        "'): proxy.route_prefix is invalid: " + e.what());
                }
            }

            // 0 = disabled (no response deadline). Otherwise minimum
            // 1000ms: deadline checks run on the dispatcher's timer scan
            // which has 1-second resolution. Sub-second positive values
            // can't be honored accurately — reject them.
            if (u.proxy.response_timeout_ms != 0 &&
                u.proxy.response_timeout_ms < 1000) {
                throw std::invalid_argument(
                    idx + " ('" + u.name +
                    "'): proxy.response_timeout_ms must be 0 (disabled) "
                    "or >= 1000 (timer scan resolution is 1s)");
            }
            if (u.proxy.retry.max_retries < 0 || u.proxy.retry.max_retries > 10) {
                throw std::invalid_argument(
                    idx + " ('" + u.name +
                    "'): proxy.retry.max_retries must be >= 0 and <= 10");
            }

            // Circuit breaker validation.
            //
            // Upper bounds on counting fields are generous — they exist to
            // catch pathological configs (typo like "10_000_000_000" or a
            // missing unit conversion), not to constrain legitimate tuning.
            // Defaults are 5 / 20 / 5; limits are 1000× to 50000× the defaults.
            {
                const auto& cb = u.circuit_breaker;
                if (cb.consecutive_failure_threshold < 1 ||
                    cb.consecutive_failure_threshold > 10000) {
                    throw std::invalid_argument(
                        idx + " ('" + u.name +
                        "'): circuit_breaker.consecutive_failure_threshold must be in [1, 10000]");
                }
                if (cb.failure_rate_threshold < 0 || cb.failure_rate_threshold > 100) {
                    throw std::invalid_argument(
                        idx + " ('" + u.name +
                        "'): circuit_breaker.failure_rate_threshold must be in [0, 100]");
                }
                if (cb.minimum_volume < 1 || cb.minimum_volume > 10000000) {
                    throw std::invalid_argument(
                        idx + " ('" + u.name +
                        "'): circuit_breaker.minimum_volume must be in [1, 10000000]");
                }
                if (cb.window_seconds < 1 || cb.window_seconds > 3600) {
                    throw std::invalid_argument(
                        idx + " ('" + u.name +
                        "'): circuit_breaker.window_seconds must be in [1, 3600]");
                }
                if (cb.permitted_half_open_calls < 1 ||
                    cb.permitted_half_open_calls > 1000) {
                    throw std::invalid_argument(
                        idx + " ('" + u.name +
                        "'): circuit_breaker.permitted_half_open_calls must be in [1, 1000]");
                }
                if (cb.base_open_duration_ms < 100) {
                    throw std::invalid_argument(
                        idx + " ('" + u.name +
                        "'): circuit_breaker.base_open_duration_ms must be >= 100");
                }
                if (cb.max_open_duration_ms < cb.base_open_duration_ms) {
                    throw std::invalid_argument(
                        idx + " ('" + u.name +
                        "'): circuit_breaker.max_open_duration_ms must be >= base_open_duration_ms");
                }
                if (cb.max_ejection_percent_per_host_set < 0 ||
                    cb.max_ejection_percent_per_host_set > 100) {
                    throw std::invalid_argument(
                        idx + " ('" + u.name +
                        "'): circuit_breaker.max_ejection_percent_per_host_set must be in [0, 100]");
                }
                if (cb.retry_budget_percent < 0 || cb.retry_budget_percent > 100) {
                    throw std::invalid_argument(
                        idx + " ('" + u.name +
                        "'): circuit_breaker.retry_budget_percent must be in [0, 100]");
                }
                if (cb.retry_budget_min_concurrency < 0) {
                    throw std::invalid_argument(
                        idx + " ('" + u.name +
                        "'): circuit_breaker.retry_budget_min_concurrency must be >= 0");
                }
            }
            // Validate method names — reject unknowns and duplicates.
            // Duplicates would cause RouteAsync to throw at startup.
            {
                static const std::unordered_set<std::string> valid_methods = {
                    "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"
                };
                std::unordered_set<std::string> seen_methods;
                for (const auto& m : u.proxy.methods) {
                    if (valid_methods.find(m) == valid_methods.end()) {
                        throw std::invalid_argument(
                            idx + " ('" + u.name +
                            "'): proxy.methods contains invalid method: " + m);
                    }
                    if (!seen_methods.insert(m).second) {
                        throw std::invalid_argument(
                            idx + " ('" + u.name +
                            "'): proxy.methods contains duplicate method: " + m);
                    }
                }
            }

            // Upstream TLS validation
            if (u.tls.enabled) {
                if (u.tls.min_version != "1.2" && u.tls.min_version != "1.3") {
                    throw std::invalid_argument(
                        idx + " ('" + u.name +
                        "'): tls.min_version must be '1.2' or '1.3', got '" +
                        u.tls.min_version + "'");
                }
                // When verify_peer is true, sni_hostname must be set so
                // SSL_set1_host() can verify the certificate's CN/SAN.
                // Without it, only CA trust is checked — any trusted cert passes.
                if (u.tls.verify_peer && u.tls.sni_hostname.empty()) {
                    throw std::invalid_argument(
                        idx + " ('" + u.name +
                        "'): tls.sni_hostname is required when verify_peer is true "
                        "(upstream host is an IPv4 address, which cannot be verified "
                        "against certificate CN/SAN)");
                }
                // CA file validation — only when TLS + verify_peer is enabled.
                // When verify_peer=false, the runtime skips CA loading, so a
                // stale ca_file path should not block startup/reload.
                if (u.tls.verify_peer && !u.tls.ca_file.empty()) {
                    struct stat st{};
                    if (stat(u.tls.ca_file.c_str(), &st) != 0) {
                        if (errno == EACCES) {
                            // Can't traverse path — skip check, runtime handles it
                        } else {
                            throw std::invalid_argument(
                                idx + " ('" + u.name +
                                "'): tls.ca_file not found: '" + u.tls.ca_file +
                                "' (" + std::strerror(errno) + ")");
                        }
                    } else if (!S_ISREG(st.st_mode)) {
                        throw std::invalid_argument(
                            idx + " ('" + u.name +
                            "'): tls.ca_file is not a regular file: '" +
                            u.tls.ca_file + "'");
                    }
                }
            }  // if (u.tls.enabled)
        }
    }

    // Rate limit validation
    {
        const auto& rl = config.rate_limit;
        if (rl.enabled && rl.zones.empty()) {
            throw std::invalid_argument(
                "rate_limit enabled but no zones configured");
        }
        if (rl.status_code < 400 || rl.status_code > 599) {
            throw std::invalid_argument(
                "rate_limit.status_code must be 400-599, got " +
                std::to_string(rl.status_code));
        }

        static const std::unordered_set<std::string> valid_key_types = {
            "client_ip", "path"
        };
        // key_type prefixes that require a suffix (e.g., "header:X-API-Key")
        static const std::vector<std::string> valid_key_prefixes = {
            "header:", "client_ip+path", "client_ip+header:"
        };

        // Rate limit zone bounds (scoped to this validation block).
        //   MIN_RATE: sub-millitoken rates truncate to 0 and buckets never refill.
        //   MAX_RATE: guards the `rate * 1000` conversion in TokenBucket from
        //             int64_t overflow. 1e9 req/s is astronomical — real
        //             deployments never approach this.
        //   MAX_CAPACITY: guards `capacity * 1000` in TokenBucket's constructor
        //                 from int64_t overflow. 1e12 is 1 trillion — more than
        //                 any realistic burst budget.
        //   RATE_LIMIT_SHARD_COUNT: pulled from RateLimitZone to stay in sync.
        constexpr double MIN_RATE = 0.001;
        constexpr double MAX_RATE = 1e9;
        constexpr int64_t MAX_CAPACITY = 1'000'000'000'000LL;  // 1e12
        constexpr int RATE_LIMIT_SHARD_COUNT =
            static_cast<int>(RateLimitZone::SHARD_COUNT);

        std::unordered_set<std::string> seen_zone_names;
        for (size_t i = 0; i < rl.zones.size(); ++i) {
            const auto& z = rl.zones[i];
            const std::string idx = "rate_limit.zones[" + std::to_string(i) + "]";

            if (z.name.empty()) {
                throw std::invalid_argument(idx + ".name must not be empty");
            }
            if (!seen_zone_names.insert(z.name).second) {
                throw std::invalid_argument(
                    "Duplicate rate_limit zone name: '" + z.name + "'");
            }
            if (z.rate < MIN_RATE) {
                throw std::invalid_argument(
                    idx + " ('" + z.name + "'): rate must be >= " +
                    std::to_string(MIN_RATE) + " (got " + std::to_string(z.rate) + ")");
            }
            if (z.rate > MAX_RATE) {
                throw std::invalid_argument(
                    idx + " ('" + z.name + "'): rate must be <= " +
                    std::to_string(MAX_RATE) + " (got " + std::to_string(z.rate) + ")");
            }
            if (z.capacity < 1) {
                throw std::invalid_argument(
                    idx + " ('" + z.name + "'): capacity must be >= 1");
            }
            if (z.capacity > MAX_CAPACITY) {
                throw std::invalid_argument(
                    idx + " ('" + z.name + "'): capacity must be <= " +
                    std::to_string(MAX_CAPACITY) +
                    " (got " + std::to_string(z.capacity) + ")");
            }
            if (z.max_entries < RATE_LIMIT_SHARD_COUNT) {
                // Below shard count, the runtime cap becomes SHARD_COUNT (one
                // per shard) rather than max_entries. Reject to keep the
                // configured value meaningful.
                throw std::invalid_argument(
                    idx + " ('" + z.name + "'): max_entries must be >= " +
                    std::to_string(RATE_LIMIT_SHARD_COUNT) +
                    " (shard count; runtime cap is rounded down to a multiple "
                    "of shard count, minimum one entry per shard)");
            }

            // Validate key_type: exact match or prefix+name match.
            // Bare prefixes like "header:" or "client_ip+header:" (no name
            // after colon) are rejected — MakeKeyExtractor can't build a
            // useful extractor and silently becomes pass-through.
            bool valid_key = valid_key_types.count(z.key_type) > 0;
            if (!valid_key) {
                for (const auto& prefix : valid_key_prefixes) {
                    if (prefix.back() == ':') {
                        // Prefix ending with ':' requires at least one char after it
                        if (z.key_type.size() > prefix.size() &&
                            z.key_type.substr(0, prefix.size()) == prefix) {
                            valid_key = true;
                            break;
                        }
                    } else {
                        // Exact match (e.g., "client_ip+path")
                        if (z.key_type == prefix) {
                            valid_key = true;
                            break;
                        }
                    }
                }
            }
            if (!valid_key) {
                throw std::invalid_argument(
                    idx + " ('" + z.name + "'): invalid key_type '" + z.key_type +
                    "' (must be client_ip, path, header:<name>, "
                    "client_ip+path, or client_ip+header:<name>)");
            }

            // Warn if capacity < rate (burst smaller than sustained rate)
            if (static_cast<double>(z.capacity) < z.rate) {
                logging::Get()->warn(
                    "rate_limit zone '{}': capacity ({}) < rate ({:.1f}) "
                    "— burst will be smaller than sustained rate",
                    z.name, z.capacity, z.rate);
            }
        }
    }

    // -------------------------------------------------------------------
    // Auth validation (design spec §5.3).
    //
    // Scope: defensive input validation on the parsed auth config. Hard-
    // reject conditions that cannot safely be live-applied later by
    // AuthManager — e.g. HS256 which has no symmetric-secret provisioning
    // surface in v1, or alg `none` which would constitute an
    // authentication bypass if silently accepted. Validator runs once at
    // startup (via ConfigLoader::Validate) and whenever reload wiring
    // gets added — the runtime code downstream can then trust the parsed
    // shape.
    // -------------------------------------------------------------------
    {
        // Supported asymmetric algorithm allowlist — v1.
        const std::unordered_set<std::string> kAllowedAlgs = {
            "RS256", "RS384", "RS512", "ES256", "ES384"
        };
        // Collect upstream names to validate `issuer.upstream` references.
        std::unordered_set<std::string> upstream_names;
        for (const auto& u : config.upstreams) upstream_names.insert(u.name);

        // Issuer validation.
        for (const auto& [name, ic] : config.auth.issuers) {
            const std::string ctx = "auth.issuers." + name;
            if (name.empty()) {
                throw std::invalid_argument(
                    "auth.issuers key must be a non-empty string");
            }
            if (ic.issuer_url.empty()) {
                throw std::invalid_argument(ctx + ".issuer_url is required");
            }
            // TLS-mandatory to IdP (design spec §9 item 4). Plaintext rejected.
            if (ic.issuer_url.rfind("https://", 0) != 0) {
                throw std::invalid_argument(
                    ctx + ".issuer_url must start with https:// (plaintext "
                    "IdP traffic is rejected for security)");
            }
            // Mode whitelist; `auto` is deferred per spec §15.
            if (ic.mode != "jwt" && ic.mode != "introspection") {
                throw std::invalid_argument(
                    ctx + ".mode must be one of: \"jwt\", \"introspection\"");
            }
            // Algorithm allowlist — reject HS*/none/PS*/unknown. Phase 1 is
            // asymmetric-only; HS* needs symmetric-secret provisioning
            // (deferred, spec §15).
            for (const auto& a : ic.algorithms) {
                if (kAllowedAlgs.count(a) == 0) {
                    throw std::invalid_argument(
                        ctx + ".algorithms contains unsupported value '" + a +
                        "' (v1 supports only RS256/RS384/RS512/ES256/ES384; "
                        "HS*/none/PS*/auto are deferred per design spec §15)");
                }
            }
            // Referenced upstream must exist (for outbound IdP calls).
            //
            // Reload-safe: HttpServer::Reload calls ConfigLoader::Validate on
            // a copy whose upstreams[] has been deliberately stripped (see
            // server/http_server.cc:3601 — `validation_copy.upstreams.clear()`)
            // because upstream topology is restart-only and the reload path
            // intentionally re-validates only the live-reloadable bits. If we
            // ran the cross-reference check unconditionally, ANY hot reload
            // of a config that has populated auth.issuers — even an
            // entirely auth-unrelated reload (e.g. a rate-limit edit) —
            // would fail with "unknown issuer upstream" because the source
            // map is empty. That would block the forward-compatible auth
            // schema the final enforcement-not-yet-wired gate intentionally
            // permits.
            //
            // Skip the cross-ref when upstream_names is empty (i.e. we're
            // running in a stripped reload context). The startup path
            // always passes the full upstreams list, so the typo-catching
            // value of this check is preserved there. When upstreams is
            // truly empty at startup (a no-proxies gateway), the issuer's
            // upstream reference is unverifiable here anyway — Phase 2's
            // AuthManager::Start will surface it at first IdP outbound
            // attempt, which is acceptable for that uncommon case.
            if (!ic.upstream.empty() && !upstream_names.empty() &&
                upstream_names.count(ic.upstream) == 0) {
                throw std::invalid_argument(
                    ctx + ".upstream references unknown upstream '" +
                    ic.upstream + "' — define it under `upstreams[]` first");
            }
            // Basic range checks.
            if (ic.leeway_sec < 0) {
                throw std::invalid_argument(ctx + ".leeway_sec must be >= 0");
            }
            if (ic.jwks_cache_sec <= 0) {
                throw std::invalid_argument(ctx + ".jwks_cache_sec must be > 0");
            }

            // Mode-specific required fields (design spec §5.3).
            // jwt mode requires at least one algorithm (the allowlist the
            // Phase-2 verifier will build `allow_algorithm(key)` calls over)
            // and a key source — either OIDC discovery OR a static jwks_uri.
            // introspection mode requires the endpoint (the POST target).
            if (ic.mode == "jwt") {
                if (ic.algorithms.empty()) {
                    throw std::invalid_argument(
                        ctx + ".algorithms must contain at least one entry "
                        "for mode=\"jwt\" (supported: RS256/RS384/RS512/"
                        "ES256/ES384)");
                }
                if (!ic.discovery && ic.jwks_uri.empty()) {
                    throw std::invalid_argument(
                        ctx + ": mode=\"jwt\" with discovery=false requires "
                        "a non-empty jwks_uri (static JWKS location)");
                }
            } else if (ic.mode == "introspection") {
                if (ic.introspection.endpoint.empty()) {
                    throw std::invalid_argument(
                        ctx + ".introspection.endpoint is required for "
                        "mode=\"introspection\"");
                }
            }

            // TLS-mandatory on actual outbound IdP endpoints, not just on
            // issuer_url (design spec §9 item 4 hardening). The issuer_url
            // check above protects discovery; these checks protect the two
            // other URLs that carry security-sensitive data:
            //
            //   - jwks_uri (static, used when discovery=false): a plaintext
            //     JWKS lets a network attacker substitute their own public
            //     keys, which would cause our verifier to accept tokens
            //     they signed → token forgery.
            //   - introspection.endpoint: a plaintext POST exposes both the
            //     bearer token (authentication credential) and our
            //     client_id / client_secret (the gateway's IdP credential)
            //     to anyone on the wire.
            //
            // Both checks are conditional — if the field is empty, mode
            // validation above has already either required it (and would
            // have thrown) or made it discovery-supplied (and the discovered
            // URL gets validated at fetch time in Phase 2). We only need
            // to validate the static value here.
            if (!ic.jwks_uri.empty() &&
                ic.jwks_uri.rfind("https://", 0) != 0) {
                throw std::invalid_argument(
                    ctx + ".jwks_uri must start with https:// — plaintext "
                    "JWKS allows MITM key substitution and would compromise "
                    "token verification (design spec §9 item 4)");
            }
            if (!ic.introspection.endpoint.empty() &&
                ic.introspection.endpoint.rfind("https://", 0) != 0) {
                throw std::invalid_argument(
                    ctx + ".introspection.endpoint must start with https:// "
                    "— plaintext introspection would leak bearer tokens and "
                    "client credentials over the wire (design spec §9 item 4)");
            }

            // Mode/endpoint mismatch — warn per design spec §5.3. Not a
            // hard-reject because operators sometimes template both blocks
            // and select mode dynamically; emitting a warn ensures the
            // unused field is noticed without blocking deployment.
            if (ic.mode == "jwt" &&
                !ic.introspection.endpoint.empty()) {
                logging::Get()->warn(
                    "{}: mode=\"jwt\" but introspection.endpoint is set — "
                    "introspection config will be ignored", ctx);
            }
            if (ic.mode == "introspection" && !ic.jwks_uri.empty()) {
                logging::Get()->warn(
                    "{}: mode=\"introspection\" but jwks_uri is set — "
                    "JWKS config will be ignored", ctx);
            }
        }

        // Top-level policy validation.
        for (size_t i = 0; i < config.auth.policies.size(); ++i) {
            const auto& p = config.auth.policies[i];
            const std::string ctx =
                "auth.policies[" + std::to_string(i) + "]";
            if (p.on_undetermined != "deny" && p.on_undetermined != "allow") {
                throw std::invalid_argument(
                    ctx + ".on_undetermined must be \"deny\" or \"allow\"");
            }
            for (const auto& issuer_name : p.issuers) {
                if (config.auth.issuers.count(issuer_name) == 0) {
                    throw std::invalid_argument(
                        ctx + ".issuers references unknown issuer '" +
                        issuer_name + "'");
                }
            }
        }

        // Inline proxy.auth validation + exact-prefix collision detection.
        // Per spec §3.2 / §5.2: a prefix that appears in both an inline
        // proxy.auth and a top-level auth.policies[].applies_to is a
        // hard-reject config error (ambiguity, not resolved at runtime).
        // Same rule applies across ALL prefix sources: two inline proxies
        // with the same route_prefix, one top-level policy with the same
        // prefix declared twice in its applies_to, or two top-level
        // policies sharing any prefix.
        //
        // Unified `all_prefixes` map catches every collision shape. Keyed
        // by prefix string; value is a human-readable owner description.
        std::unordered_map<std::string, std::string> all_prefixes;

        for (const auto& u : config.upstreams) {
            const auto& p = u.proxy.auth;
            const std::string ctx = "upstreams['" + u.name + "'].proxy.auth";

            // ---- Structural validation: runs regardless of `enabled` ----
            //
            // Per the rollout plan (design spec §14), operators are EXPECTED
            // to pre-stage inline auth blocks with `enabled=false` while
            // request-time enforcement is being wired in follow-up PRs.
            // If we only validated when enabled=true, typos in the staged
            // configs (unknown issuer names, invalid on_undetermined
            // values) would silently slip through and only surface when
            // the operator flips enabled to true at deployment. That's a
            // bad operator experience and a hidden-correctness vector.
            //
            // The structural checks below have well-defined semantics for
            // ANY populated AuthPolicy and so are safe to run on disabled
            // blocks — they catch typos BEFORE deploy.
            if (p.on_undetermined != "deny" && p.on_undetermined != "allow") {
                throw std::invalid_argument(
                    ctx + ".on_undetermined must be \"deny\" or \"allow\" "
                    "(checked regardless of `enabled` so staged disabled "
                    "policies still get typo-rejection)");
            }
            for (const auto& issuer_name : p.issuers) {
                if (config.auth.issuers.count(issuer_name) == 0) {
                    throw std::invalid_argument(
                        ctx + ".issuers references unknown issuer '" +
                        issuer_name + "' (checked regardless of `enabled` "
                        "so staged disabled policies still get typo-rejection)");
                }
            }

            // route_prefix non-empty is required ONLY when the operator
            // has actually populated the inline auth block. A proxy with
            // a fully-default auth block (the operator never wrote
            // `proxy.auth: {...}`) shouldn't be required to have a
            // route_prefix — it might be a programmatic-only proxy. So
            // gate this specific check on whether ANY field of the block
            // was touched by the operator. Detection: any field differs
            // from the AuthPolicy default constructor.
            //
            // Includes p.enabled in the populated check because an
            // operator who writes `"auth": {"enabled": true}` literally
            // (even with no other fields) is signaling intent and should
            // still be told their proxy lacks a route_prefix. Same for
            // any other non-default field.
            const bool inline_auth_populated = (p != auth::AuthPolicy{});
            if (inline_auth_populated && u.proxy.route_prefix.empty()) {
                throw std::invalid_argument(
                    ctx + " has no route_prefix — inline auth requires a "
                    "non-empty proxy.route_prefix to derive applies_to");
            }

            // ---- Collision detection: ENABLED-only ----
            //
            // Per spec §3.2, only enabled inline policies participate in
            // the runtime longest-prefix matcher. Disabled policies are
            // inert at request time, so they shouldn't collide with each
            // other or with top-level policies. (This matches the prior
            // reviewer round's guidance that the "enable a disabled
            // policy and discover a collision later" flow is a deliberate
            // UX trade-off, not a bug — and confirms the gate is the
            // right place to draw the structural-vs-collision line.)
            if (!p.enabled) continue;

            const std::string owner =
                "inline proxy.auth on upstream '" + u.name + "'";
            auto ins = all_prefixes.emplace(u.proxy.route_prefix, owner);
            if (!ins.second) {
                throw std::invalid_argument(
                    "auth policy prefix '" + u.proxy.route_prefix +
                    "' declared by both " + ins.first->second + " and " +
                    owner + " — exact-prefix collisions must be resolved at "
                    "config time (design spec §3.2)");
            }
        }
        // Top-level policies: catches (a) top-level vs inline, (b) two
        // top-level policies sharing a prefix, (c) one top-level policy
        // listing the same prefix twice in its applies_to. This is the
        // guarantee the `auth_policy_matcher::ValidatePolicyList` helper
        // was designed to enforce — ConfigLoader::Validate is the correct
        // place to call it because collisions must be a load-time error,
        // not a silent runtime first-wins.
        //
        // SYMMETRY with inline policies: only ENABLED top-level policies
        // participate in the runtime longest-prefix matcher (per spec §3.2),
        // so only they should drive collision detection. We already skip
        // disabled inline proxy.auth above — applying the same rule to
        // top-level keeps the two paths consistent and lets operators
        // pre-stage disabled top-level policies during the rollout
        // without spurious collision errors. (Without this, an operator
        // who staged two top-level policies with identical applies_to
        // — both disabled, intentionally inert — would see Validate
        // reject the config even though the runtime would never match
        // either of them.)
        for (size_t i = 0; i < config.auth.policies.size(); ++i) {
            const auto& p = config.auth.policies[i];
            if (!p.enabled) continue;  // Symmetry with inline path
            const std::string policy_owner =
                p.name.empty()
                    ? ("auth.policies[" + std::to_string(i) + "]")
                    : ("auth.policies['" + p.name + "']");
            for (const auto& pref : p.applies_to) {
                auto ins = all_prefixes.emplace(pref, policy_owner);
                if (!ins.second) {
                    throw std::invalid_argument(
                        "auth policy prefix '" + pref + "' declared by both " +
                        ins.first->second + " and " + policy_owner +
                        " — exact-prefix collisions must be resolved at "
                        "config time (design spec §3.2)");
                }
            }
        }

        // Forward config: reject header-name collisions among the fixed
        // output slots and the claims_to_headers map. Design §5.3.
        // Run unconditionally — the default AuthForwardConfig has three
        // distinct non-empty header names that trivially pass the set
        // insertion, and an operator who writes the defaults back
        // explicitly in JSON gets the same (correct) treatment.
        {
            std::unordered_set<std::string> output_headers;
            auto add_header = [&output_headers](const std::string& name,
                                                const std::string& which) {
                if (name.empty()) return;
                std::string lower;
                lower.reserve(name.size());
                for (char c : name) {
                    lower.push_back(static_cast<char>(
                        std::tolower(static_cast<unsigned char>(c))));
                }
                // Reserved-name check FIRST (security): hop-by-hop / pseudo /
                // framing-critical / Authorization names would corrupt or
                // spoof the forwarded request. See IsReservedAuthForwardHeader
                // for the full categorization. Reject before the duplicate
                // check so the operator sees the more-actionable error.
                if (IsReservedAuthForwardHeader(lower)) {
                    throw std::invalid_argument(
                        "auth.forward." + which + " '" + name +
                        "' is a reserved/hop-by-hop/pseudo/framing header "
                        "name and must not be used as an auth-forward output "
                        "(would corrupt or spoof the upstream request); pick "
                        "an X-prefixed name like 'X-Auth-Subject' instead");
                }
                if (!output_headers.insert(lower).second) {
                    throw std::invalid_argument(
                        "auth.forward." + which + " '" + name +
                        "' collides with another output header name "
                        "(case-insensitive)");
                }
            };
            add_header(config.auth.forward.subject_header, "subject_header");
            add_header(config.auth.forward.issuer_header, "issuer_header");
            add_header(config.auth.forward.scopes_header, "scopes_header");
            add_header(config.auth.forward.raw_jwt_header, "raw_jwt_header");
            for (const auto& [claim, header] :
                 config.auth.forward.claims_to_headers) {
                add_header(header, "claims_to_headers[" + claim + "]");
            }
        }

        // ----- Final gate: enforcement-not-yet-wired master rejection -----
        //
        // This PR (Phase 1, Steps 1–2) lands the auth config schema, the
        // pure utilities (token_hasher / jwt_decode-via-jwt-cpp /
        // auth_policy_matcher / auth_claims), and the data-structure plumbing
        // (HttpRequest::auth, ProxyConfig::auth, ServerConfig::auth) — but
        // request-time enforcement (AuthManager + middleware + JwtVerifier
        // wiring) is scheduled for follow-up PRs per design spec §14
        // (Phase 1 Steps 3–7 / Phase 2). Until that lands, a config that
        // toggles auth ON would silently behave as unauthenticated — i.e.
        // an operator who deploys `auth.enabled=true` thinking their proxy
        // is now protected would be wrong. That's an authentication-bypass
        // misconfiguration vector.
        //
        // To prevent silent unenforced-policy acceptance, the validator
        // hard-rejects ANY config that flips an auth enable flag on. The
        // schema (issuers, policies, forward) may stay populated for
        // forward-compatibility — operators can prepare their config in
        // advance of the enforcement PR — but the master switches must
        // remain false until enforcement is wired.
        //
        // Same fail-closed discipline used for HS256 / alg:none / mode:auto
        // throughout this design: features that are not safely usable yet
        // must reject loudly at config load, not silently accept.
        if (config.auth.enabled) {
            throw std::invalid_argument(
                "auth.enabled=true rejected: request-time enforcement "
                "(AuthManager + middleware) is not yet wired in this build. "
                "Schedule: design spec §14 Phase 2 / follow-up PR. To prevent "
                "silent unenforced-policy acceptance, the validator hard-"
                "rejects this flag until enforcement lands. Set "
                "auth.enabled=false for now; auth.issuers / policies / "
                "forward may remain populated for upgrade.");
        }
        for (const auto& u : config.upstreams) {
            if (u.proxy.auth.enabled) {
                throw std::invalid_argument(
                    "upstreams['" + u.name +
                    "'].proxy.auth.enabled=true rejected: request-time "
                    "enforcement is not yet wired in this build (design spec "
                    "§14 Phase 2). Set proxy.auth.enabled=false for now; the "
                    "auth block (issuers reference, required_scopes, etc.) "
                    "may remain populated for upgrade.");
            }
        }
    }
}

ServerConfig ConfigLoader::Default() {
    return ServerConfig{};
}

std::string ConfigLoader::ToJson(const ServerConfig& config) {
    nlohmann::json j;
    j["bind_host"]          = config.bind_host;
    j["bind_port"]          = config.bind_port;
    j["max_connections"]    = config.max_connections;
    j["idle_timeout_sec"]   = config.idle_timeout_sec;
    j["worker_threads"]     = config.worker_threads;
    j["max_header_size"]    = config.max_header_size;
    j["max_body_size"]      = config.max_body_size;
    j["max_ws_message_size"]= config.max_ws_message_size;
    j["request_timeout_sec"]= config.request_timeout_sec;
    j["shutdown_drain_timeout_sec"] = config.shutdown_drain_timeout_sec;
    j["tls"]["enabled"]     = config.tls.enabled;
    j["tls"]["cert_file"]   = config.tls.cert_file;
    j["tls"]["key_file"]    = config.tls.key_file;
    j["tls"]["min_version"] = config.tls.min_version;
    j["log"]["level"]       = config.log.level;
    j["log"]["file"]        = config.log.file;
    j["log"]["max_file_size"] = config.log.max_file_size;
    j["log"]["max_files"]   = config.log.max_files;
    j["http2"]["enabled"]                = config.http2.enabled;
    j["http2"]["max_concurrent_streams"] = config.http2.max_concurrent_streams;
    j["http2"]["initial_window_size"]    = config.http2.initial_window_size;
    j["http2"]["max_frame_size"]         = config.http2.max_frame_size;
    j["http2"]["max_header_list_size"]   = config.http2.max_header_list_size;
    j["http2"]["enable_push"]            = config.http2.enable_push;

    j["upstreams"] = nlohmann::json::array();
    for (const auto& u : config.upstreams) {
        nlohmann::json uj;
        uj["name"] = u.name;
        uj["host"] = u.host;
        uj["port"] = u.port;
        uj["tls"]["enabled"]      = u.tls.enabled;
        uj["tls"]["ca_file"]      = u.tls.ca_file;
        uj["tls"]["verify_peer"]  = u.tls.verify_peer;
        uj["tls"]["sni_hostname"] = u.tls.sni_hostname;
        uj["tls"]["min_version"]  = u.tls.min_version;
        uj["pool"]["max_connections"]      = u.pool.max_connections;
        uj["pool"]["max_idle_connections"] = u.pool.max_idle_connections;
        uj["pool"]["connect_timeout_ms"]   = u.pool.connect_timeout_ms;
        uj["pool"]["idle_timeout_sec"]     = u.pool.idle_timeout_sec;
        uj["pool"]["max_lifetime_sec"]     = u.pool.max_lifetime_sec;
        uj["pool"]["max_requests_per_conn"]= u.pool.max_requests_per_conn;
        // Always serialize proxy settings — an upstream may have non-default
        // proxy config (methods, retry, header_rewrite, timeout) even when
        // route_prefix is empty (exposed via programmatic Proxy() API).
        // Skipping this block on empty route_prefix would silently reset
        // those settings on a ToJson() / LoadFromString() round-trip.
        //
        // The gate also explicitly checks for an auth-only difference:
        // ProxyConfig::operator== INTENTIONALLY ignores the `auth` field
        // (live-reloadable per same-PR `AuthManager::Reload` discipline,
        // see DEVELOPMENT_RULES.md). Without the second clause, a proxy
        // that only customizes inline auth — exactly the staged config
        // shape operators are expected to write before request-time
        // enforcement is wired — would compare equal to the default and
        // get its entire proxy block (including `auth`) silently dropped
        // by ToJson(). Round-trip would lose the staged policy. Treat
        // any non-default auth as sufficient reason to serialize.
        if (u.proxy != ProxyConfig{} || u.proxy.auth != auth::AuthPolicy{}) {
            nlohmann::json pj;
            pj["route_prefix"] = u.proxy.route_prefix;
            pj["strip_prefix"] = u.proxy.strip_prefix;
            pj["response_timeout_ms"] = u.proxy.response_timeout_ms;
            pj["methods"] = u.proxy.methods;

            nlohmann::json hrj;
            hrj["set_x_forwarded_for"] = u.proxy.header_rewrite.set_x_forwarded_for;
            hrj["set_x_forwarded_proto"] = u.proxy.header_rewrite.set_x_forwarded_proto;
            hrj["set_via_header"] = u.proxy.header_rewrite.set_via_header;
            hrj["rewrite_host"] = u.proxy.header_rewrite.rewrite_host;
            pj["header_rewrite"] = hrj;

            nlohmann::json rj;
            rj["max_retries"] = u.proxy.retry.max_retries;
            rj["retry_on_connect_failure"] = u.proxy.retry.retry_on_connect_failure;
            rj["retry_on_5xx"] = u.proxy.retry.retry_on_5xx;
            rj["retry_on_timeout"] = u.proxy.retry.retry_on_timeout;
            rj["retry_on_disconnect"] = u.proxy.retry.retry_on_disconnect;
            rj["retry_non_idempotent"] = u.proxy.retry.retry_non_idempotent;
            pj["retry"] = rj;

            // Inline per-proxy auth policy. Only emitted when differs from
            // default — same shape as the circuit_breaker block below —
            // because an empty/disabled stanza is the common case and
            // serializing it adds noise to every config dump.
            if (u.proxy.auth != auth::AuthPolicy{}) {
                pj["auth"] = SerializeAuthPolicy(u.proxy.auth);
            }

            uj["proxy"] = pj;
        }
        // Always serialize circuit_breaker — same rationale as proxy block.
        if (u.circuit_breaker != CircuitBreakerConfig{}) {
            nlohmann::json cbj;
            cbj["enabled"] = u.circuit_breaker.enabled;
            cbj["dry_run"] = u.circuit_breaker.dry_run;
            cbj["consecutive_failure_threshold"] =
                u.circuit_breaker.consecutive_failure_threshold;
            cbj["failure_rate_threshold"] =
                u.circuit_breaker.failure_rate_threshold;
            cbj["minimum_volume"] = u.circuit_breaker.minimum_volume;
            cbj["window_seconds"] = u.circuit_breaker.window_seconds;
            cbj["permitted_half_open_calls"] =
                u.circuit_breaker.permitted_half_open_calls;
            cbj["base_open_duration_ms"] =
                u.circuit_breaker.base_open_duration_ms;
            cbj["max_open_duration_ms"] =
                u.circuit_breaker.max_open_duration_ms;
            cbj["max_ejection_percent_per_host_set"] =
                u.circuit_breaker.max_ejection_percent_per_host_set;
            cbj["retry_budget_percent"] =
                u.circuit_breaker.retry_budget_percent;
            cbj["retry_budget_min_concurrency"] =
                u.circuit_breaker.retry_budget_min_concurrency;
            uj["circuit_breaker"] = cbj;
        }
        j["upstreams"].push_back(uj);
    }

    // Rate limit serialization
    {
        nlohmann::json rlj;
        rlj["enabled"] = config.rate_limit.enabled;
        rlj["dry_run"] = config.rate_limit.dry_run;
        rlj["status_code"] = config.rate_limit.status_code;
        rlj["include_headers"] = config.rate_limit.include_headers;
        rlj["zones"] = nlohmann::json::array();
        for (const auto& z : config.rate_limit.zones) {
            nlohmann::json zj;
            zj["name"] = z.name;
            zj["rate"] = z.rate;
            zj["capacity"] = z.capacity;
            zj["key_type"] = z.key_type;
            zj["max_entries"] = z.max_entries;
            zj["applies_to"] = z.applies_to;
            rlj["zones"].push_back(zj);
        }
        j["rate_limit"] = rlj;
    }

    // Auth top-level block serialization. Emitted whenever it differs
    // from defaults so a round-trip preserves operator intent.
    if (config.auth != auth::AuthConfig{}) {
        nlohmann::json aj;
        aj["enabled"] = config.auth.enabled;
        if (!config.auth.hmac_cache_key_env.empty()) {
            aj["hmac_cache_key_env"] = config.auth.hmac_cache_key_env;
        }
        if (!config.auth.issuers.empty()) {
            nlohmann::json ij = nlohmann::json::object();
            for (const auto& [name, ic] : config.auth.issuers) {
                nlohmann::json ijv;
                ijv["issuer_url"] = ic.issuer_url;
                ijv["discovery"] = ic.discovery;
                if (!ic.jwks_uri.empty()) ijv["jwks_uri"] = ic.jwks_uri;
                ijv["upstream"] = ic.upstream;
                ijv["mode"] = ic.mode;
                if (!ic.audiences.empty()) ijv["audiences"] = ic.audiences;
                ijv["algorithms"] = ic.algorithms;
                ijv["leeway_sec"] = ic.leeway_sec;
                ijv["jwks_cache_sec"] = ic.jwks_cache_sec;
                ijv["jwks_refresh_timeout_sec"] = ic.jwks_refresh_timeout_sec;
                ijv["discovery_retry_sec"] = ic.discovery_retry_sec;
                if (!ic.required_claims.empty()) {
                    ijv["required_claims"] = ic.required_claims;
                }
                if (ic.introspection != auth::IntrospectionConfig{}) {
                    nlohmann::json inj;
                    inj["endpoint"] = ic.introspection.endpoint;
                    inj["client_id"] = ic.introspection.client_id;
                    inj["client_secret_env"] =
                        ic.introspection.client_secret_env;
                    inj["auth_style"] = ic.introspection.auth_style;
                    inj["timeout_sec"] = ic.introspection.timeout_sec;
                    inj["cache_sec"] = ic.introspection.cache_sec;
                    inj["negative_cache_sec"] =
                        ic.introspection.negative_cache_sec;
                    inj["stale_grace_sec"] =
                        ic.introspection.stale_grace_sec;
                    inj["max_entries"] = ic.introspection.max_entries;
                    inj["shards"] = ic.introspection.shards;
                    ijv["introspection"] = inj;
                }
                ij[name] = ijv;
            }
            aj["issuers"] = ij;
        }
        if (!config.auth.policies.empty()) {
            nlohmann::json pj = nlohmann::json::array();
            for (const auto& p : config.auth.policies) {
                pj.push_back(SerializeAuthPolicy(p));
            }
            aj["policies"] = pj;
        }
        if (config.auth.forward != auth::AuthForwardConfig{}) {
            nlohmann::json fj;
            fj["subject_header"] = config.auth.forward.subject_header;
            fj["issuer_header"] = config.auth.forward.issuer_header;
            fj["scopes_header"] = config.auth.forward.scopes_header;
            fj["raw_jwt_header"] = config.auth.forward.raw_jwt_header;
            fj["strip_inbound_identity_headers"] =
                config.auth.forward.strip_inbound_identity_headers;
            fj["preserve_authorization"] =
                config.auth.forward.preserve_authorization;
            if (!config.auth.forward.claims_to_headers.empty()) {
                fj["claims_to_headers"] =
                    config.auth.forward.claims_to_headers;
            }
            aj["forward"] = fj;
        }
        j["auth"] = aj;
    }

    return j.dump(4);
}
