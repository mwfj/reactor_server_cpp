#pragma once

// Minimal test coverage for the auth-foundation pieces landed in this PR.
// Full Phase 1 / Phase 2 test suites (jwt_verifier_test, jwks_cache_test,
// auth_policy_matcher_test, etc.) are tracked in §13.1 of the design spec and
// land in later PRs. The coverage here is deliberately narrow — it pins the
// security-critical invariants introduced by the r3/r5 revisions so that a
// regression is caught in CI:
//
//   - TokenHasher::Hash returns std::optional — never "" on failure
//     (r3 finding #2: cross-token cache-key collision risk).
//   - LoadHmacKeyFromEnv never propagates an exception from jwt::base::decode
//     (r5 finding #2 / §9 item 16: exception containment at library boundary).
//   - Base64url-encoded 32-byte env value is preferred over raw interpretation
//     (§12.1 spec contract).

#include "test_framework.h"
#include "auth/token_hasher.h"
#include "auth/auth_claims.h"
#include "auth/auth_context.h"
#include "config/config_loader.h"
#include "jwt-cpp/base.h"
#include <nlohmann/json.hpp>

#include <cstdlib>
#include <string>

namespace AuthFoundationTests {

// -----------------------------------------------------------------------------
// TokenHasher::Hash — returns std::optional, never empty-string sentinel.
// -----------------------------------------------------------------------------
void TestHasherBasicDeterminism() {
    std::cout << "\n[TEST] TokenHasher::Hash determinism + optional contract..." << std::endl;
    try {
        auth::TokenHasher hasher(std::string(32, 'k'));

        auto a1 = hasher.Hash("token-A");
        auto a2 = hasher.Hash("token-A");
        auto b  = hasher.Hash("token-B");

        bool has_values = a1.has_value() && a2.has_value() && b.has_value();
        bool deterministic = has_values && *a1 == *a2;
        bool distinct = has_values && *a1 != *b;
        bool hex128 = has_values && a1->size() == 32;  // 128 bits = 32 hex chars

        bool pass = deterministic && distinct && hex128;
        std::string err;
        if (!has_values) err = "Hash() returned nullopt on valid input";
        else if (!deterministic) err = "Hash() non-deterministic: " + *a1 + " vs " + *a2;
        else if (!distinct) err = "Hash() collision between distinct tokens";
        else if (!hex128) err = "Hash() output not 32 hex chars";

        TestFramework::RecordTest("AuthFoundation: TokenHasher basic",
                                  pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("AuthFoundation: TokenHasher basic",
                                  false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// -----------------------------------------------------------------------------
// LoadHmacKeyFromEnv — exception containment (§9 item 16).
// jwt::base::decode throws on invalid base64url input. The env-var loader
// MUST catch this and fall through to the raw-bytes interpretation. Without
// the try/catch, an invalid base64url env value would propagate as an
// uncaught exception into AuthManager::Start() and abort server startup.
// -----------------------------------------------------------------------------
void TestLoadHmacKeyFromEnvDoesNotThrow() {
    std::cout << "\n[TEST] LoadHmacKeyFromEnv exception containment..." << std::endl;

    // Preserve/restore the env var across the test. No bleedthrough to
    // other tests (most of which run servers and don't touch this var).
    //
    // Hoisted out of the try/catch so the outer catch can reference the
    // saved original value — evaluating std::getenv() in the catch would
    // return the test-fixture value instead of the pre-test original.
    const char* kVarName = "REACTOR_TEST_AUTH_BAD_KEY";
    auto restore_env = [](const char* name, const char* prev) {
        if (prev) setenv(name, prev, 1);
        else unsetenv(name);
    };
    const char* pre_test_prev = std::getenv(kVarName);
    std::string saved = pre_test_prev ? pre_test_prev : "";
    bool had_original = pre_test_prev != nullptr;

    try {
        // Case 1: illegal-char base64url (@ is not a base64url alphabet char).
        // This is a syntactically invalid input that jwt::base::decode throws on.
        setenv(kVarName, "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@", 1);  // 43 chars, all invalid
        std::string bad_key;
        bool threw = false;
        try {
            bad_key = auth::LoadHmacKeyFromEnv(kVarName);
        } catch (const std::exception& e) {
            threw = true;
        }
        // Contract: must not throw. Must return the raw env string as a
        // fallback (auto-detect declined base64url → raw interpretation).
        bool case1_pass = !threw && bad_key.size() == 43;
        std::string case1_err = threw
            ? "LoadHmacKeyFromEnv PROPAGATED exception — §9 item 16 violated"
            : (case1_pass ? "" : "Expected raw-bytes fallback of length 43, got " +
                                 std::to_string(bad_key.size()));

        // Case 2: length-1-remainder base64url (4n+1 chars — impossible shape).
        // jwt::base::decode typically throws on this length pattern.
        setenv(kVarName, "A", 1);
        std::string short_key;
        bool threw2 = false;
        try {
            short_key = auth::LoadHmacKeyFromEnv(kVarName);
        } catch (const std::exception& e) {
            threw2 = true;
        }
        bool case2_pass = !threw2 && short_key == "A";
        std::string case2_err = threw2
            ? "LoadHmacKeyFromEnv PROPAGATED exception on length-1 input"
            : (case2_pass ? "" : "Expected raw-bytes fallback 'A', got '" + short_key + "'");

        restore_env(kVarName, had_original ? saved.c_str() : nullptr);

        bool pass = case1_pass && case2_pass;
        std::string err;
        if (!case1_pass) err = case1_err;
        else if (!case2_pass) err = case2_err;

        TestFramework::RecordTest(
            "AuthFoundation: LoadHmacKeyFromEnv contains jwt-cpp exceptions",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        // Restore using the HOISTED saved value — not std::getenv(), which
        // would return the test-fixture value at this point.
        restore_env(kVarName, had_original ? saved.c_str() : nullptr);
        TestFramework::RecordTest(
            "AuthFoundation: LoadHmacKeyFromEnv contains jwt-cpp exceptions",
            false, std::string("unexpected test harness failure: ") + e.what(),
            TestFramework::TestCategory::OTHER);
    }
}

// -----------------------------------------------------------------------------
// LoadHmacKeyFromEnv — base64url auto-detect: 32-byte decode preferred.
// Per §12.1 / §5.1: a valid base64url-encoded 32-byte key is used decoded.
// Anything else (wrong length after decode, non-base64url chars) falls to raw.
// -----------------------------------------------------------------------------
void TestLoadHmacKeyFromEnvAutoDetect() {
    std::cout << "\n[TEST] LoadHmacKeyFromEnv base64url auto-detect..." << std::endl;

    const char* kVarName = "REACTOR_TEST_AUTH_GOOD_KEY";
    auto restore_env = [](const char* name, const char* prev) {
        if (prev) setenv(name, prev, 1);
        else unsetenv(name);
    };
    // Hoisted out of the try/catch so the outer catch restores the
    // pre-test value, not the test-fixture value.
    const char* pre_test_prev = std::getenv(kVarName);
    std::string saved = pre_test_prev ? pre_test_prev : "";
    bool had_original = pre_test_prev != nullptr;

    try {
        // Derive the correct base64url encoding of 32 bytes of 0x41 via
        // jwt-cpp's public helper — avoids a hand-computed constant that
        // would drift if the encoder ever changed or get mis-hand-counted.
        const std::string raw32(32, 'A');  // 32 bytes of 0x41
        // RFC 7515 standard form: trim any padding. LoadHmacKeyFromEnv's
        // normalizer accepts either padded or unpadded input — we test the
        // unpadded form because that's the form JWT tooling produces.
        std::string base64url_unpadded =
            jwt::base::trim<jwt::alphabet::base64url>(
                jwt::base::encode<jwt::alphabet::base64url>(raw32));

        // Case A: unpadded base64url (RFC 7515 standard — the review's
        // finding that this branch must work).
        setenv(kVarName, base64url_unpadded.c_str(), 1);
        std::string decoded_unpadded = auth::LoadHmacKeyFromEnv(kVarName);

        // Case B: same value but with jwt-cpp "%3d" padding (what
        // jwt::base::encode produces natively) — must also work.
        std::string base64url_padded =
            jwt::base::encode<jwt::alphabet::base64url>(raw32);
        setenv(kVarName, base64url_padded.c_str(), 1);
        std::string decoded_padded = auth::LoadHmacKeyFromEnv(kVarName);

        // Case C: raw fallback — 16-char string decodes to 12 bytes (not 32)
        // so auto-detect should decline and return the raw bytes.
        setenv(kVarName, "AAAAAAAAAAAAAAAA", 1);
        std::string raw_fallback = auth::LoadHmacKeyFromEnv(kVarName);

        restore_env(kVarName, had_original ? saved.c_str() : nullptr);

        bool unpadded_ok = decoded_unpadded.size() == 32 &&
            decoded_unpadded.find_first_not_of('A') == std::string::npos;
        bool padded_ok = decoded_padded.size() == 32 &&
            decoded_padded.find_first_not_of('A') == std::string::npos;
        bool raw_ok = raw_fallback == "AAAAAAAAAAAAAAAA";

        bool pass = unpadded_ok && padded_ok && raw_ok;
        std::string err;
        if (!unpadded_ok) {
            err = "RFC 7515 unpadded base64url not accepted; got size=" +
                  std::to_string(decoded_unpadded.size());
        } else if (!padded_ok) {
            err = "jwt-cpp '%3d'-padded base64url not accepted; got size=" +
                  std::to_string(decoded_padded.size());
        } else if (!raw_ok) {
            err = "16-char input (decodes to 12 bytes) should fall to raw, got '" +
                  raw_fallback + "'";
        }

        TestFramework::RecordTest(
            "AuthFoundation: LoadHmacKeyFromEnv base64url auto-detect",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        // Restore using the HOISTED saved value, NOT std::getenv(), which
        // at this point returns the test-fixture value.
        restore_env(kVarName, had_original ? saved.c_str() : nullptr);
        TestFramework::RecordTest(
            "AuthFoundation: LoadHmacKeyFromEnv base64url auto-detect",
            false, std::string("unexpected exception: ") + e.what(),
            TestFramework::TestCategory::OTHER);
    }
}

// -----------------------------------------------------------------------------
// ExtractScopes — accept `scp` as a string (Azure AD / Entra) not just array.
// Pins the review-round-N+1 P2 fix for auth_claims.cc.
// -----------------------------------------------------------------------------
void TestExtractScopesScpAsString() {
    std::cout << "\n[TEST] ExtractScopes scp-as-string (Azure AD)..." << std::endl;
    try {
        // Azure AD delegated flow: scp is a space-separated string.
        auto payload_str = nlohmann::json::parse(
            R"({"scp":"read:data read:profile write:data"})");
        auto scopes_str = auth::ExtractScopes(payload_str);

        // Traditional array form must still work.
        auto payload_arr = nlohmann::json::parse(
            R"({"scp":["read:data","read:profile"]})");
        auto scopes_arr = auth::ExtractScopes(payload_arr);

        // `scope` (space-sep string, OAuth2 classic) must still work.
        auto payload_scope = nlohmann::json::parse(
            R"({"scope":"alpha beta gamma"})");
        auto scopes_scope = auth::ExtractScopes(payload_scope);

        bool str_ok = scopes_str.size() == 3 &&
                      scopes_str[0] == "read:data" &&
                      scopes_str[1] == "read:profile" &&
                      scopes_str[2] == "write:data";
        bool arr_ok = scopes_arr.size() == 2 &&
                      scopes_arr[0] == "read:data" &&
                      scopes_arr[1] == "read:profile";
        bool scope_ok = scopes_scope.size() == 3 &&
                        scopes_scope[0] == "alpha";

        bool pass = str_ok && arr_ok && scope_ok;
        std::string err;
        if (!str_ok) err = "scp string-valued form not split into scope list";
        else if (!arr_ok) err = "scp array-valued form broke";
        else if (!scope_ok) err = "scope (space-sep) form broke";

        TestFramework::RecordTest(
            "AuthFoundation: ExtractScopes scp-as-string",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "AuthFoundation: ExtractScopes scp-as-string",
            false, std::string("unexpected exception: ") + e.what(),
            TestFramework::TestCategory::OTHER);
    }
}

// -----------------------------------------------------------------------------
// ConfigLoader round-trip for the auth block — pins review round N+1 P1 fix.
// A config-driven deployment's top-level `auth` block and per-proxy
// `proxy.auth` policy must survive LoadFromString → ToJson → LoadFromString.
// Before the fix these were silently dropped; this test ensures the loader
// actually reads and writes the fields.
// -----------------------------------------------------------------------------
void TestConfigLoaderAuthRoundTrip() {
    std::cout << "\n[TEST] ConfigLoader auth round-trip..." << std::endl;
    try {
        const std::string kInput = R"({
            "bind_host": "127.0.0.1",
            "bind_port": 8080,
            "upstreams": [
                {
                    "name": "internal-api",
                    "host": "127.0.0.1",
                    "port": 8080,
                    "proxy": {
                        "route_prefix": "/api/v1",
                        "auth": {
                            "enabled": true,
                            "issuers": ["google"],
                            "required_scopes": ["read:data"],
                            "on_undetermined": "deny",
                            "realm": "api"
                        }
                    }
                },
                {
                    "name": "idp_google",
                    "host": "127.0.0.2",
                    "port": 443
                }
            ],
            "auth": {
                "enabled": true,
                "hmac_cache_key_env": "MY_HMAC_KEY",
                "issuers": {
                    "google": {
                        "issuer_url": "https://accounts.google.com",
                        "discovery": true,
                        "upstream": "idp_google",
                        "mode": "jwt",
                        "audiences": ["my-backend"],
                        "algorithms": ["RS256"],
                        "leeway_sec": 30
                    }
                },
                "policies": [
                    {
                        "name": "public-health",
                        "enabled": false,
                        "applies_to": ["/public/"]
                    }
                ],
                "forward": {
                    "subject_header": "X-Auth-Subject",
                    "claims_to_headers": {"email": "X-Auth-Email"},
                    "preserve_authorization": true,
                    "raw_jwt_header": ""
                }
            }
        })";

        ServerConfig c1 = ConfigLoader::LoadFromString(kInput);

        // Post-parse assertions — prove the fields aren't silently dropped.
        bool parsed_top =
            c1.auth.enabled &&
            c1.auth.hmac_cache_key_env == "MY_HMAC_KEY" &&
            c1.auth.issuers.count("google") == 1 &&
            c1.auth.issuers.at("google").issuer_url ==
                "https://accounts.google.com" &&
            c1.auth.issuers.at("google").upstream == "idp_google" &&
            c1.auth.issuers.at("google").mode == "jwt" &&
            c1.auth.issuers.at("google").audiences.size() == 1 &&
            c1.auth.issuers.at("google").audiences[0] == "my-backend" &&
            c1.auth.issuers.at("google").algorithms.size() == 1 &&
            c1.auth.issuers.at("google").algorithms[0] == "RS256" &&
            c1.auth.issuers.at("google").leeway_sec == 30 &&
            c1.auth.policies.size() == 1 &&
            c1.auth.policies[0].name == "public-health" &&
            !c1.auth.policies[0].enabled &&
            c1.auth.policies[0].applies_to.size() == 1 &&
            c1.auth.policies[0].applies_to[0] == "/public/" &&
            c1.auth.forward.subject_header == "X-Auth-Subject" &&
            c1.auth.forward.claims_to_headers.count("email") == 1 &&
            c1.auth.forward.claims_to_headers.at("email") == "X-Auth-Email" &&
            c1.auth.forward.preserve_authorization &&
            c1.auth.forward.raw_jwt_header.empty();

        // Inline proxy.auth must also survive parse.
        bool parsed_inline = false;
        for (const auto& u : c1.upstreams) {
            if (u.name == "internal-api") {
                const auto& a = u.proxy.auth;
                parsed_inline =
                    a.enabled &&
                    a.issuers.size() == 1 && a.issuers[0] == "google" &&
                    a.required_scopes.size() == 1 &&
                    a.required_scopes[0] == "read:data" &&
                    a.on_undetermined == "deny" &&
                    a.realm == "api";
            }
        }

        // Validation must accept this config (algorithms OK, upstream exists,
        // no collisions, https issuer).
        bool validation_ok = true;
        std::string validation_err;
        try {
            ConfigLoader::Validate(c1);
        } catch (const std::exception& e) {
            validation_ok = false;
            validation_err = e.what();
        }

        // Round-trip through ToJson → LoadFromString must preserve both
        // top-level auth and inline proxy.auth.
        std::string reserialized = ConfigLoader::ToJson(c1);
        ServerConfig c2 = ConfigLoader::LoadFromString(reserialized);

        bool round_trip_ok =
            c2.auth == c1.auth &&
            c2.upstreams.size() == c1.upstreams.size();
        if (round_trip_ok) {
            for (size_t i = 0; i < c1.upstreams.size(); ++i) {
                if (!(c1.upstreams[i].proxy.auth ==
                      c2.upstreams[i].proxy.auth)) {
                    round_trip_ok = false;
                    break;
                }
            }
        }

        bool pass = parsed_top && parsed_inline && validation_ok && round_trip_ok;
        std::string err;
        if (!parsed_top) err = "top-level auth block not parsed — fields silently dropped";
        else if (!parsed_inline) err = "upstreams[].proxy.auth not parsed — inline policy silently dropped";
        else if (!validation_ok) err = "validation rejected a valid config: " + validation_err;
        else if (!round_trip_ok) err = "ToJson -> LoadFromString did not preserve auth config";

        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader auth round-trip",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader auth round-trip",
            false, std::string("unexpected exception: ") + e.what(),
            TestFramework::TestCategory::OTHER);
    }
}

// -----------------------------------------------------------------------------
// ConfigLoader::Validate — reject HS256 / none / non-https / unknown issuer
// referenced by policy. Pins the validation rules from §5.3.
// -----------------------------------------------------------------------------
void TestConfigLoaderAuthValidation() {
    std::cout << "\n[TEST] ConfigLoader auth validation rejects bad inputs..." << std::endl;
    try {
        auto validate_expect_failure = [](const std::string& json,
                                          const std::string& what_to_contain) -> std::string {
            try {
                auto c = ConfigLoader::LoadFromString(json);
                ConfigLoader::Validate(c);
            } catch (const std::exception& e) {
                std::string msg = e.what();
                if (msg.find(what_to_contain) != std::string::npos) return {};
                return "expected error containing '" + what_to_contain +
                       "', got: " + msg;
            }
            return "expected exception not thrown (should contain '" +
                   what_to_contain + "')";
        };

        std::string err;

        // Case 1: HS256 algorithm.
        err = validate_expect_failure(R"({
            "upstreams": [{"name":"x","host":"127.0.0.1","port":80}],
            "auth": {"issuers": {"ours": {
                "issuer_url":"https://auth.internal",
                "upstream":"x", "mode":"jwt",
                "algorithms":["HS256"]
            }}}
        })", "HS256");
        if (!err.empty()) throw std::runtime_error("HS256 case: " + err);

        // Case 2: alg `none`.
        err = validate_expect_failure(R"({
            "upstreams": [{"name":"x","host":"127.0.0.1","port":80}],
            "auth": {"issuers": {"ours": {
                "issuer_url":"https://auth.internal",
                "upstream":"x", "mode":"jwt",
                "algorithms":["none"]
            }}}
        })", "none");
        if (!err.empty()) throw std::runtime_error("alg=none case: " + err);

        // Case 3: non-https issuer URL.
        err = validate_expect_failure(R"({
            "upstreams": [{"name":"x","host":"127.0.0.1","port":80}],
            "auth": {"issuers": {"ours": {
                "issuer_url":"http://insecure.example.com",
                "upstream":"x"
            }}}
        })", "https://");
        if (!err.empty()) throw std::runtime_error("non-https case: " + err);

        // Case 4: policy references unknown issuer.
        err = validate_expect_failure(R"({
            "upstreams": [{"name":"x","host":"127.0.0.1","port":80}],
            "auth": {
                "issuers": {"ours": {"issuer_url":"https://a","upstream":"x"}},
                "policies": [{"name":"p","enabled":true,"applies_to":["/a"],"issuers":["unknown"]}]
            }
        })", "unknown issuer");
        if (!err.empty()) throw std::runtime_error("unknown issuer case: " + err);

        // Case 5: inline client_secret (forbidden — must use env var).
        err = validate_expect_failure(R"({
            "upstreams": [{"name":"x","host":"127.0.0.1","port":80}],
            "auth": {"issuers": {"ours": {
                "issuer_url":"https://a","upstream":"x","mode":"introspection",
                "introspection":{"client_id":"c","client_secret":"s"}
            }}}
        })", "client_secret");
        if (!err.empty()) throw std::runtime_error("inline client_secret case: " + err);

        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader auth validation",
            true, "", TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader auth validation",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

inline void RunAllTests() {
    std::cout << "\n===== Auth Foundation Tests =====" << std::endl;
    TestHasherBasicDeterminism();
    TestLoadHmacKeyFromEnvDoesNotThrow();
    TestLoadHmacKeyFromEnvAutoDetect();
    TestExtractScopesScpAsString();
    TestConfigLoaderAuthRoundTrip();
    TestConfigLoaderAuthValidation();
}

}  // namespace AuthFoundationTests
