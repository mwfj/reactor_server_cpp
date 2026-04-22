#include "auth/jwks_fetcher.h"

#include "auth/auth_url_util.h"
#include "auth/upstream_http_client.h"
#include "auth/jwks_cache.h"
#include "log/logger.h"

// jwt-cpp pulled in AFTER the common.h-driven includes to avoid spdlog's
// fmt clashing with picojson (we opt out of picojson project-wide).
#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/nlohmann-json/traits.h>

#include <sstream>
#include <system_error>

// ---------------------------------------------------------------------------
// JwksFetcher — retrieves a JWKS via UpstreamHttpClient, parses it with
// jwt::parse_jwks (exception-contained), converts each JWK to PEM, and
// installs the resulting (kid, PEM) map into the provided JwksCache.
//
// Every jwt-cpp and OpenSSL boundary is wrapped in try/catch. On ANY
// parse / conversion failure, the cache is untouched (stale-on-error per
// §7.1) and `OnFetchError` is called with a short stable reason. Design
// §9 item 16 is the normative reference.
// ---------------------------------------------------------------------------

namespace AUTH_NAMESPACE {

namespace {

// Convert a single JWK into an OpenSSL PEM-encoded public key string.
// Supports RSA ("kty":"RSA") and EC ("kty":"EC") per RFC 7518.
// Returns empty on unsupported kty / missing fields / conversion failure.
// All jwt-cpp / OpenSSL exceptions are contained.
std::string JwkToPem(const jwt::jwk<jwt::traits::nlohmann_json>& jwk,
                      const std::string& issuer_name,
                      const std::string& kid_hint) {
    try {
        if (!jwk.has_key_type()) {
            logging::Get()->warn(
                "JwksFetcher issuer={} kid={} missing kty; skipped",
                issuer_name, kid_hint);
            return {};
        }
        const auto kty = jwk.get_key_type();
        std::error_code ec;
        if (kty == "RSA") {
            if (!jwk.has_jwk_claim("n") || !jwk.has_jwk_claim("e")) {
                logging::Get()->warn(
                    "JwksFetcher issuer={} kid={} RSA missing n/e; skipped",
                    issuer_name, kid_hint);
                return {};
            }
            std::string n = jwk.get_jwk_claim("n").as_string();
            std::string e = jwk.get_jwk_claim("e").as_string();
            auto pem = jwt::helper::create_public_key_from_rsa_components(
                n, e, ec);
            if (ec) {
                logging::Get()->warn(
                    "JwksFetcher issuer={} kid={} RSA conversion failed: {}",
                    issuer_name, kid_hint, ec.message());
                return {};
            }
            return pem;
        }
        if (kty == "EC") {
            if (!jwk.has_curve() || !jwk.has_jwk_claim("x") ||
                !jwk.has_jwk_claim("y")) {
                logging::Get()->warn(
                    "JwksFetcher issuer={} kid={} EC missing crv/x/y; skipped",
                    issuer_name, kid_hint);
                return {};
            }
            std::string curve = jwk.get_curve();
            std::string x = jwk.get_jwk_claim("x").as_string();
            std::string y = jwk.get_jwk_claim("y").as_string();
            auto pem = jwt::helper::create_public_key_from_ec_components(
                curve, x, y, ec);
            if (ec) {
                logging::Get()->warn(
                    "JwksFetcher issuer={} kid={} EC conversion failed: {}",
                    issuer_name, kid_hint, ec.message());
                return {};
            }
            return pem;
        }
        // Anything else (oct = HS256 — deferred in v1, OKP, etc.) is
        // intentionally rejected per §9 items 11 & 16.
        logging::Get()->warn(
            "JwksFetcher issuer={} kid={} unsupported kty={}; skipped",
            issuer_name, kid_hint, kty);
        return {};
    } catch (const std::exception& ex) {
        logging::Get()->warn(
            "JwksFetcher issuer={} kid={} JWK conversion threw: {}",
            issuer_name, kid_hint, ex.what());
        return {};
    } catch (...) {
        logging::Get()->warn(
            "JwksFetcher issuer={} kid={} JWK conversion threw non-std",
            issuer_name, kid_hint);
        return {};
    }
}

// Try to parse the JWKS body and return (kid, PEM) pairs. On parse /
// conversion failure, returns an empty vector and `reason` is set to a
// short stable label.
std::vector<std::pair<std::string, std::string>>
ParseAndConvert(const std::string& body,
                 const std::string& issuer_name,
                 std::string& reason) {
    std::vector<std::pair<std::string, std::string>> out;
    jwt::jwks<jwt::traits::nlohmann_json> parsed;
    try {
        parsed = jwt::parse_jwks<jwt::traits::nlohmann_json>(body);
    } catch (const std::exception& ex) {
        reason = "parse_error";
        logging::Get()->warn(
            "JwksFetcher issuer={} parse_jwks threw: {}", issuer_name, ex.what());
        return out;
    } catch (...) {
        reason = "parse_error";
        logging::Get()->warn(
            "JwksFetcher issuer={} parse_jwks threw non-std", issuer_name);
        return out;
    }

    size_t accepted = 0;
    for (const auto& jwk : parsed) {
        std::string kid = jwk.has_key_id() ? jwk.get_key_id() : std::string();
        std::string pem = JwkToPem(jwk, issuer_name, kid);
        if (pem.empty()) continue;
        out.emplace_back(std::move(kid), std::move(pem));
        ++accepted;
    }
    if (out.empty()) {
        reason = "no_keys";
        logging::Get()->warn(
            "JwksFetcher issuer={} parsed JWKS but produced zero usable keys",
            issuer_name);
    } else {
        logging::Get()->debug(
            "JwksFetcher issuer={} parsed {} keys from body ({} bytes)",
            issuer_name, accepted, body.size());
    }
    return out;
}

}  // namespace

JwksFetcher::JwksFetcher(std::string issuer_name,
                          std::shared_ptr<UpstreamHttpClient> client,
                          std::shared_ptr<JwksCache> cache,
                          std::string upstream_pool_name,
                          std::shared_ptr<std::atomic<uint64_t>> owner_generation)
    : issuer_name_(std::move(issuer_name)),
      client_(std::move(client)),
      cache_(std::move(cache)),
      upstream_pool_name_(std::move(upstream_pool_name)),
      owner_generation_(std::move(owner_generation)),
      cancel_token_(std::make_shared<std::atomic<bool>>(false)) {
    logging::Get()->debug(
        "JwksFetcher constructed issuer={} pool={}",
        issuer_name_, upstream_pool_name_);
}

JwksFetcher::~JwksFetcher() {
    CancelInflight();
}

void JwksFetcher::StartFetch(const std::string& jwks_uri,
                              size_t dispatcher_index,
                              int timeout_sec,
                              uint64_t generation,
                              std::function<void(uint64_t)> after_cb) {
    if (!client_ || !cache_) {
        logging::Get()->error(
            "JwksFetcher::StartFetch called before dependencies wired "
            "issuer={}", issuer_name_);
        if (cache_) cache_->ReleaseRefreshSlot();
        if (after_cb) after_cb(generation);
        return;
    }

    // Refresh fresh cancel token per cycle so a previous CancelInflight
    // doesn't immediately short-circuit this request. The old token
    // remains live only until the old fetch's callback dereferences it.
    auto token = std::make_shared<std::atomic<bool>>(false);
    cancel_token_ = token;

    auto parsed_uri = ParseHttpsUri(jwks_uri);
    // Split path from query string in-place.
    std::string path = parsed_uri.path_with_query;
    std::string query;
    auto qpos = path.find('?');
    if (qpos != std::string::npos) {
        query = path.substr(qpos + 1);
        path = path.substr(0, qpos);
    }

    UpstreamHttpClient::Request req;
    req.method = "GET";
    req.path = path;
    req.query = query;
    req.host_header = parsed_uri.host;
    req.headers["accept"] = "application/json, application/jwk-set+json";
    req.timeout_sec = timeout_sec > 0 ? timeout_sec : 5;
    // JWKS documents are typically <10 KB. Cap generously at 256 KB.
    req.max_response_body = 256 * 1024;

    logging::Get()->debug(
        "JwksFetcher issuing GET issuer={} pool={} path={} host={} gen={}",
        issuer_name_, upstream_pool_name_, req.path, req.host_header,
        generation);

    std::string issuer_name = issuer_name_;
    std::shared_ptr<JwksCache> cache = cache_;
    auto cb = after_cb;
    std::shared_ptr<std::atomic<uint64_t>> owner_generation = owner_generation_;

    client_->Issue(
        upstream_pool_name_,
        dispatcher_index,
        std::move(req),
        // Lambda captures `cache` + `owner_generation` as shared_ptr BY
        // VALUE. If `~JwksFetcher` / `~Issuer` runs concurrently with
        // the dispatcher-thread completion, the shared ownership keeps
        // the cache and generation atomic alive until the lambda ends
        // — avoids UAF that would otherwise arise from raw-pointer
        // captures surviving into a teardown window.
        [cache, issuer_name, generation, owner_generation, cb, token](
                UpstreamHttpClient::Response resp) {
            // Terminal callback — guaranteed at most once. Always release
            // the refresh slot, regardless of outcome.
            const bool cancelled = token &&
                token->load(std::memory_order_acquire);
            if (cancelled) {
                logging::Get()->debug(
                    "JwksFetcher cancelled issuer={} gen={}",
                    issuer_name, generation);
                if (cache) cache->ReleaseRefreshSlot();
                if (cb) cb(generation);
                return;
            }
            if (!resp.error.empty() || resp.status_code != 200) {
                std::string reason = !resp.error.empty()
                    ? resp.error
                    : std::string("http_") + std::to_string(resp.status_code);
                logging::Get()->warn(
                    "JwksFetcher fetch failed issuer={} status={} reason={}",
                    issuer_name, resp.status_code, reason);
                if (cache) cache->OnFetchError(reason);
                if (cache) cache->ReleaseRefreshSlot();
                if (cb) cb(generation);
                return;
            }
            std::string parse_reason;
            auto pairs = ParseAndConvert(resp.body, issuer_name, parse_reason);
            if (pairs.empty()) {
                if (cache) cache->OnFetchError(parse_reason);
            } else {
                // Generation gate: drop the install if the Issuer's
                // generation advanced while this fetch was in flight
                // (reload bumped it, or Stop). Without this, an old
                // response could overwrite cache state that has already
                // been conceptually invalidated — subsequent verifies
                // would run against stale keys until the next refresh.
                // `owner_generation` is null only for legacy test
                // fixtures that don't thread a generation; production
                // (Issuer) always provides it.
                const uint64_t current_gen =
                    owner_generation
                        ? owner_generation->load(std::memory_order_acquire)
                        : generation;
                if (current_gen != generation) {
                    logging::Get()->info(
                        "JwksFetcher drop stale install issuer={} "
                        "captured_gen={} current_gen={}",
                        issuer_name, generation, current_gen);
                    if (cache) cache->OnFetchError("stale_generation");
                } else if (cache) {
                    cache->InstallKeys(std::move(pairs));
                }
            }
            if (cache) cache->ReleaseRefreshSlot();
            if (cb) cb(generation);
        },
        token);
}

void JwksFetcher::CancelInflight() {
    if (cancel_token_) {
        cancel_token_->store(true, std::memory_order_release);
    }
}

}  // namespace AUTH_NAMESPACE
