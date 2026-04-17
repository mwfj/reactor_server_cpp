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

        // Validation behavior on this fixture (which has auth.enabled=true):
        // The fixture is structurally well-formed (algorithms OK, upstream
        // exists, no collisions, https issuer, etc.) AND it has the master
        // auth flag flipped on. Until request-time enforcement lands per
        // design spec §14 Phase 2, the validator's enforcement-not-yet-wired
        // gate fires for any enabled=true config. This block confirms the
        // gate behaves correctly on a fully-formed but enabled fixture —
        // it must throw with the gate's distinctive "not yet wired" message,
        // proving that all the structural checks passed (otherwise an
        // earlier throw with a different message would fire).
        //
        // When enforcement lands, this assertion flips back to "must
        // succeed" and the gate logic in ConfigLoader::Validate is removed.
        bool validation_ok = false;  // success means gate fired with right msg
        std::string validation_err;
        try {
            ConfigLoader::Validate(c1);
            validation_err = "Validate() unexpectedly accepted enabled=true; "
                             "the enforcement-not-yet-wired gate should have "
                             "rejected it";
        } catch (const std::invalid_argument& e) {
            std::string msg = e.what();
            if (msg.find("not yet wired") != std::string::npos &&
                msg.find("auth.enabled") != std::string::npos) {
                validation_ok = true;
            } else {
                validation_err =
                    "Validate() threw a DIFFERENT error than the expected "
                    "enforcement-not-yet-wired gate (this means an earlier "
                    "structural check failed when it shouldn't have); "
                    "got: " + msg;
            }
        } catch (const std::exception& e) {
            validation_err =
                std::string("Validate() threw an unexpected exception type: ") +
                e.what();
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

// -----------------------------------------------------------------------------
// LoadHmacKeyFromEnv — standard base64 fallback (base64 alphabet uses +/=,
// not base64url's -_). Operators running `openssl rand -base64 32` (the most
// common JWT-key-generation command in tutorials) get 44-char output with
// '+' or '/' characters that base64url rejects. This test pins the fallback
// path that decodes via `jwt::alphabet::base64` after base64url fails —
// added in the review round that introduced the Step-3 fallback in
// server/token_hasher.cc.
// -----------------------------------------------------------------------------
void TestLoadHmacKeyFromEnvStandardBase64() {
    std::cout << "\n[TEST] LoadHmacKeyFromEnv standard base64 fallback..." << std::endl;

    const char* kVarName = "REACTOR_TEST_AUTH_STD_B64_KEY";
    auto restore_env = [](const char* name, const char* prev, bool had) {
        if (had) setenv(name, prev, 1);
        else unsetenv(name);
    };

    // Hoist saved state above the try so the catch block sees the correct
    // pre-test value (matches the pattern from the other tests — fixes the
    // restore-corruption regression flagged in an earlier round).
    const char* prev = std::getenv(kVarName);
    std::string saved = prev ? prev : "";
    bool had_original = (prev != nullptr);

    try {
        // Craft a 32-byte binary key whose STANDARD base64 encoding contains
        // '+' or '/'. Byte pattern 0xFF 0xFB 0xFF 0xFB ... produces bit groups
        // that base64-encode to chars including '/' (0x3F = 63) and '+' (0x3E
        // = 62) — neither of which is in the base64url alphabet.
        std::string raw_key;
        raw_key.reserve(32);
        for (int i = 0; i < 32; ++i) {
            raw_key.push_back(
                static_cast<char>(i % 2 == 0 ? 0xFF : 0xFB));
        }
        // Encode using STANDARD base64 (mirrors `openssl rand -base64 32`
        // output, which uses '+' / '/' / '='). jwt-cpp's base64 alphabet
        // emits '=' padding by default, producing the 44-char form.
        std::string encoded =
            jwt::base::encode<jwt::alphabet::base64>(raw_key);

        // Fixture self-check: if the encoded string happens not to contain
        // any base64-only character, this test wouldn't exercise the
        // fallback — a base64url decode would succeed and we'd never hit
        // Step 3. Fail loudly rather than silently pass a no-op test.
        bool has_std_only_char =
            encoded.find('+') != std::string::npos ||
            encoded.find('/') != std::string::npos;
        if (!has_std_only_char) {
            TestFramework::RecordTest(
                "AuthFoundation: LoadHmacKeyFromEnv standard base64 fallback",
                false,
                "fixture: chosen byte pattern didn't produce '+' or '/' in "
                "base64 encoding — test would not exercise the Step-3 "
                "fallback path",
                TestFramework::TestCategory::OTHER);
            return;
        }

        setenv(kVarName, encoded.c_str(), 1);
        std::string decoded_key = auth::LoadHmacKeyFromEnv(kVarName);

        restore_env(kVarName, saved.c_str(), had_original);

        bool decoded_to_32 = decoded_key.size() == 32;
        bool matches_raw = decoded_to_32 && decoded_key == raw_key;

        bool pass = decoded_to_32 && matches_raw;
        std::string err;
        if (!decoded_to_32) {
            err = "standard-base64 input (" + std::to_string(encoded.size()) +
                  " chars containing '+' or '/') not decoded via Step-3 "
                  "fallback; returned size=" +
                  std::to_string(decoded_key.size());
        } else if (!matches_raw) {
            err = "standard-base64 decoded bytes differ from original raw key "
                  "(HMAC key would silently change)";
        }

        TestFramework::RecordTest(
            "AuthFoundation: LoadHmacKeyFromEnv standard base64 fallback",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        restore_env(kVarName, saved.c_str(), had_original);
        TestFramework::RecordTest(
            "AuthFoundation: LoadHmacKeyFromEnv standard base64 fallback",
            false, std::string("unexpected exception: ") + e.what(),
            TestFramework::TestCategory::OTHER);
    }
}

// -----------------------------------------------------------------------------
// ConfigLoader::Validate — same-header collision in claims_to_headers.
// Two distinct claim keys mapping to the same header NAME must be rejected
// at config-load time. Without this rejection, the runtime HeaderRewriter
// would get last-write-wins behavior and operators would see silently
// wrong values in the selected claim header. The unified header-collision
// set in Validate() already catches this — the test pins that guarantee
// against a future refactor that might inadvertently narrow the check.
// -----------------------------------------------------------------------------
void TestConfigLoaderClaimHeaderCollision() {
    std::cout << "\n[TEST] ConfigLoader rejects claim->same-header collision..." << std::endl;
    try {
        // NOTE: enabled=false here is deliberate — the structural header-
        // collision check runs unconditionally, and we want to exercise it
        // in isolation. With enabled=true, the new "enforcement-not-yet-
        // wired" gate would fire first and we'd never reach the collision
        // check. The collision is purely a config-shape issue, not gated
        // on the master switch.
        const std::string bad_json = R"({
            "bind_host": "127.0.0.1",
            "bind_port": 8080,
            "auth": {
                "enabled": false,
                "issuers": {
                    "google": {
                        "issuer_url": "https://accounts.google.com",
                        "upstream": "idp_google",
                        "mode": "jwt",
                        "algorithms": ["RS256"]
                    }
                },
                "forward": {
                    "claims_to_headers": {
                        "email": "X-Shared-Header",
                        "sub":   "X-Shared-Header"
                    }
                }
            },
            "upstreams": [{"name": "idp_google", "host": "127.0.0.1", "port": 443}]
        })";
        bool threw = false;
        std::string err_msg;
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(bad_json);
            ConfigLoader::Validate(cfg);
        } catch (const std::invalid_argument& e) {
            threw = true;
            err_msg = e.what();
        }
        bool mentions_collision =
            threw && err_msg.find("collides") != std::string::npos;

        bool pass = threw && mentions_collision;
        std::string err;
        if (!threw) {
            err = "expected Validate() to reject duplicate header names in "
                  "claims_to_headers but it accepted the config";
        } else if (!mentions_collision) {
            err = "Validate() threw but error text didn't mention "
                  "'collides'; got: " + err_msg;
        }

        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader rejects claim->same-header collision",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader rejects claim->same-header collision",
            false, std::string("unexpected harness error: ") + e.what(),
            TestFramework::TestCategory::OTHER);
    }
}

// -----------------------------------------------------------------------------
// ConfigLoader::Validate — auth-enabled fail-closed gate (review P1 #1).
//
// Until AuthManager + middleware lands (design spec §14 Phase 2), a config
// that toggles auth ON would silently behave as unauthenticated — i.e. the
// gateway would accept the config but route requests to upstreams without
// any token validation. To prevent that auth-bypass-by-misconfig scenario,
// Validate() hard-rejects any config with auth.enabled=true OR
// upstreams[].proxy.auth.enabled=true. Schema fields (issuers, policies,
// forward) may still be populated for forward-compatibility — only the
// master switches are gated.
//
// These tests pin the gate. When enforcement actually lands, both
// throw-cases below are removed (the gate logic is deleted from
// ConfigLoader::Validate) AND these test cases are flipped to assert
// successful validation. Until then, the gate is the safety net.
// -----------------------------------------------------------------------------
void TestConfigLoaderRejectsAuthEnabled() {
    std::cout << "\n[TEST] ConfigLoader rejects auth.enabled=true (gateway-wide)..." << std::endl;
    try {
        const std::string json_with_auth_enabled = R"({
            "bind_host": "127.0.0.1",
            "bind_port": 8080,
            "auth": {
                "enabled": true,
                "issuers": {
                    "google": {
                        "issuer_url": "https://accounts.google.com",
                        "upstream": "idp_google",
                        "mode": "jwt",
                        "algorithms": ["RS256"]
                    }
                }
            },
            "upstreams": [{"name": "idp_google", "host": "127.0.0.1", "port": 443}]
        })";
        bool threw = false;
        std::string err_msg;
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(json_with_auth_enabled);
            ConfigLoader::Validate(cfg);
        } catch (const std::invalid_argument& e) {
            threw = true;
            err_msg = e.what();
        }
        // Contract: must throw, and message must be informative — mention
        // both that enforcement isn't wired and how to disable. We check
        // for the canonical phrase "not yet wired" and "auth.enabled" so
        // the test fails loudly if the wording silently regresses to a
        // less-actionable message.
        bool good_msg = threw &&
            err_msg.find("not yet wired") != std::string::npos &&
            err_msg.find("auth.enabled") != std::string::npos;
        bool pass = threw && good_msg;
        std::string err;
        if (!threw) {
            err = "expected Validate() to reject auth.enabled=true but it accepted";
        } else if (!good_msg) {
            err = "Validate() threw but message lacked 'not yet wired' or "
                  "'auth.enabled'; got: " + err_msg;
        }
        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader rejects gateway auth.enabled=true",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader rejects gateway auth.enabled=true",
            false, std::string("unexpected harness error: ") + e.what(),
            TestFramework::TestCategory::OTHER);
    }
}

void TestConfigLoaderRejectsProxyAuthEnabled() {
    std::cout << "\n[TEST] ConfigLoader rejects proxy.auth.enabled=true..." << std::endl;
    try {
        const std::string json_with_proxy_auth_enabled = R"({
            "bind_host": "127.0.0.1",
            "bind_port": 8080,
            "auth": {
                "enabled": false,
                "issuers": {
                    "google": {
                        "issuer_url": "https://accounts.google.com",
                        "upstream": "idp_google",
                        "mode": "jwt",
                        "algorithms": ["RS256"]
                    }
                }
            },
            "upstreams": [
                {"name": "idp_google", "host": "127.0.0.1", "port": 443},
                {
                    "name": "internal-api",
                    "host": "127.0.0.1",
                    "port": 8080,
                    "proxy": {
                        "route_prefix": "/api/v1",
                        "auth": {
                            "enabled": true,
                            "issuers": ["google"]
                        }
                    }
                }
            ]
        })";
        bool threw = false;
        std::string err_msg;
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(json_with_proxy_auth_enabled);
            ConfigLoader::Validate(cfg);
        } catch (const std::invalid_argument& e) {
            threw = true;
            err_msg = e.what();
        }
        // Message must name the offending upstream so operators can find it
        // quickly, and mention the gate phrasing.
        bool good_msg = threw &&
            err_msg.find("not yet wired") != std::string::npos &&
            err_msg.find("internal-api") != std::string::npos &&
            err_msg.find("proxy.auth.enabled") != std::string::npos;
        bool pass = threw && good_msg;
        std::string err;
        if (!threw) {
            err = "expected Validate() to reject proxy.auth.enabled=true but it accepted";
        } else if (!good_msg) {
            err = "Validate() threw but message lacked one of "
                  "{'not yet wired', 'internal-api', 'proxy.auth.enabled'}; "
                  "got: " + err_msg;
        }
        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader rejects per-proxy auth.enabled=true",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader rejects per-proxy auth.enabled=true",
            false, std::string("unexpected harness error: ") + e.what(),
            TestFramework::TestCategory::OTHER);
    }
}

// -----------------------------------------------------------------------------
// ConfigLoader::Validate — TLS-mandatory on outbound IdP endpoints
// (review P1 #2). issuer_url already has the https check; this test pins
// the same protection for jwks_uri (when discovery=false) and
// introspection.endpoint. Plaintext on either is a critical security bug:
//   - http://jwks → MITM key substitution → token forgery
//   - http://introspect → bearer token + client credential exposure
// -----------------------------------------------------------------------------
void TestConfigLoaderRejectsPlaintextIdpEndpoints() {
    std::cout << "\n[TEST] ConfigLoader rejects plaintext jwks_uri / introspection.endpoint..." << std::endl;
    auto validate_expect_failure = [](const std::string& json,
                                       const std::string& expected_phrase)
        -> std::string {
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(json);
            ConfigLoader::Validate(cfg);
            return "expected Validate() to throw containing '" +
                   expected_phrase + "' but it accepted";
        } catch (const std::invalid_argument& e) {
            std::string msg = e.what();
            if (msg.find(expected_phrase) == std::string::npos) {
                return "Validate() threw but message lacked '" +
                       expected_phrase + "'; got: " + msg;
            }
            return "";
        } catch (const std::exception& e) {
            return std::string("unexpected exception type: ") + e.what();
        }
    };

    try {
        // Case 1: plaintext jwks_uri (discovery=false case).
        std::string err = validate_expect_failure(R"({
            "upstreams": [{"name":"x","host":"127.0.0.1","port":80}],
            "auth": {
                "issuers": {
                    "ours": {
                        "issuer_url": "https://issuer.example",
                        "discovery": false,
                        "jwks_uri": "http://issuer.example/jwks.json",
                        "upstream": "x",
                        "mode": "jwt",
                        "algorithms": ["RS256"]
                    }
                }
            }
        })", "jwks_uri must start with https://");
        if (!err.empty()) throw std::runtime_error("plaintext jwks_uri case: " + err);

        // Case 2: plaintext introspection.endpoint.
        err = validate_expect_failure(R"({
            "upstreams": [{"name":"x","host":"127.0.0.1","port":80}],
            "auth": {
                "issuers": {
                    "ours": {
                        "issuer_url": "https://issuer.example",
                        "upstream": "x",
                        "mode": "introspection",
                        "introspection": {
                            "endpoint": "http://issuer.example/introspect",
                            "client_id": "c",
                            "client_secret_env": "E"
                        }
                    }
                }
            }
        })", "introspection.endpoint must start with https://");
        if (!err.empty()) throw std::runtime_error("plaintext introspection case: " + err);

        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader rejects plaintext IdP endpoints",
            true, "", TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader rejects plaintext IdP endpoints",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// -----------------------------------------------------------------------------
// PopulateFromPayload — iss/sub now optional (review P1 #3).
// RFC 7519 §4.1.1 / §4.1.2 mark both as OPTIONAL; RFC 7662 introspection
// only requires `active`. Common scenarios where one or both are absent:
//   - Client-credentials access tokens (no human subject)
//   - Minimal introspection responses ({"active": true, "scope": "..."})
// Pre-fix behavior would 401 these tokens. This test pins that absent-but-
// well-formed payloads now succeed and leave ctx fields empty for downstream
// HeaderRewriter to skip emitting when populated values aren't present.
// -----------------------------------------------------------------------------
void TestPopulateFromPayloadOptionalIssSub() {
    std::cout << "\n[TEST] PopulateFromPayload accepts payloads without iss/sub..." << std::endl;
    try {
        // Case 1: client-credentials shape — no `sub`, scope present.
        nlohmann::json client_cred = nlohmann::json::parse(R"({
            "iss": "https://issuer.example",
            "client_id": "machine-a",
            "scope": "read:data"
        })");
        auth::AuthContext ctx1;
        bool ok1 = auth::PopulateFromPayload(client_cred, {"client_id"}, ctx1);
        bool case1_pass = ok1 &&
            ctx1.issuer == "https://issuer.example" &&
            ctx1.subject.empty() &&
            ctx1.scopes.size() == 1 && ctx1.scopes[0] == "read:data" &&
            ctx1.claims.count("client_id") == 1 &&
            ctx1.claims.at("client_id") == "machine-a";

        // Case 2: minimal introspection response — only active + scope.
        nlohmann::json minimal_introspect = nlohmann::json::parse(R"({
            "active": true,
            "scope": "read:data write:data"
        })");
        auth::AuthContext ctx2;
        bool ok2 = auth::PopulateFromPayload(minimal_introspect, {}, ctx2);
        bool case2_pass = ok2 &&
            ctx2.issuer.empty() &&
            ctx2.subject.empty() &&
            ctx2.scopes.size() == 2;

        // Case 3: structurally invalid payload (not an object) — STILL rejected.
        // The relaxation is only about iss/sub; structural validity is
        // unchanged.
        nlohmann::json not_an_object = nlohmann::json::parse(R"("a string")");
        auth::AuthContext ctx3;
        bool ok3 = auth::PopulateFromPayload(not_an_object, {}, ctx3);
        bool case3_pass = !ok3;  // must return false

        bool pass = case1_pass && case2_pass && case3_pass;
        std::string err;
        if (!case1_pass) err = "client-credentials case (no sub) failed";
        else if (!case2_pass) err = "minimal introspection case (no iss, no sub) failed";
        else if (!case3_pass) err = "non-object payload should still be rejected";

        TestFramework::RecordTest(
            "AuthFoundation: PopulateFromPayload accepts payloads without iss/sub",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "AuthFoundation: PopulateFromPayload accepts payloads without iss/sub",
            false, std::string("unexpected exception: ") + e.what(),
            TestFramework::TestCategory::OTHER);
    }
}

// -----------------------------------------------------------------------------
// ConfigLoader::Validate — issuer.upstream cross-reference is reload-safe
// via the EXPLICIT `reload_copy=true` flag (review P2). HttpServer::Reload()
// validates a copy with upstreams[] stripped and now passes
// `reload_copy=true` so topology cross-refs are skipped. Earlier iterations
// used `upstream_names.empty()` as an implicit reload sentinel — that
// overloaded "no upstreams" to mean "reload context", which incorrectly
// skipped checks on legitimate startup configs with programmatic-only
// routes. The explicit flag fixes that. This test pins three behaviors:
//
//   1. reload_copy=true + empty upstreams → cross-ref skipped (reload safe)
//   2. reload_copy=false + full upstreams + missing target → reject
//   3. reload_copy=false + empty upstreams + populated issuer → reject
//      (regression catch — programmatic-only startup must still validate)
// -----------------------------------------------------------------------------
void TestConfigLoaderUpstreamCrossRefReloadSafe() {
    std::cout << "\n[TEST] ConfigLoader issuer.upstream cross-ref is reload-safe..." << std::endl;
    try {
        // Reload-context shape: full auth schema, upstreams[] cleared.
        // With reload_copy=true the cross-ref must be skipped.
        const std::string reload_shape = R"({
            "bind_host": "127.0.0.1",
            "bind_port": 8080,
            "upstreams": [],
            "auth": {
                "enabled": false,
                "issuers": {
                    "google": {
                        "issuer_url": "https://accounts.google.com",
                        "upstream": "idp_google",
                        "mode": "jwt",
                        "algorithms": ["RS256"]
                    }
                }
            }
        })";

        bool threw = false;
        std::string err_msg;
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(reload_shape);
            ConfigLoader::Validate(cfg, /*reload_copy=*/true);
        } catch (const std::exception& e) {
            threw = true;
            err_msg = e.what();
        }

        // Regression #1: at STARTUP (full upstreams, missing target),
        // the cross-ref must still fire. This confirms the flag default
        // (false) preserves the typo-catching value of the check.
        const std::string startup_shape = R"({
            "bind_host": "127.0.0.1",
            "bind_port": 8080,
            "upstreams": [{"name":"some_other_upstream","host":"127.0.0.1","port":80}],
            "auth": {
                "enabled": false,
                "issuers": {
                    "google": {
                        "issuer_url": "https://accounts.google.com",
                        "upstream": "idp_google",
                        "mode": "jwt",
                        "algorithms": ["RS256"]
                    }
                }
            }
        })";
        bool startup_threw = false;
        std::string startup_err;
        try {
            ServerConfig cfg2 = ConfigLoader::LoadFromString(startup_shape);
            ConfigLoader::Validate(cfg2);  // default reload_copy=false
        } catch (const std::exception& e) {
            startup_threw = true;
            startup_err = e.what();
        }

        // Regression #2 (the new behavior the explicit flag fixes):
        // genuine startup config with empty upstreams[] (a programmatic-
        // only deployment that uses top-level auth.policies[] to protect
        // its handlers) MUST still reject an issuer.upstream pointing
        // at a nonexistent pool. Before the flag, this slipped through
        // because empty upstreams was the reload sentinel.
        bool prog_only_startup_threw = false;
        std::string prog_only_err;
        try {
            ServerConfig cfg3 = ConfigLoader::LoadFromString(reload_shape);
            ConfigLoader::Validate(cfg3);  // default reload_copy=false
        } catch (const std::exception& e) {
            prog_only_startup_threw = true;
            prog_only_err = e.what();
        }

        bool reload_pass = !threw;
        bool startup_pass = startup_threw &&
            startup_err.find("references unknown upstream") != std::string::npos;
        bool prog_only_pass = prog_only_startup_threw &&
            prog_only_err.find("references unknown upstream") != std::string::npos;

        bool pass = reload_pass && startup_pass && prog_only_pass;
        std::string err;
        if (!reload_pass) {
            err = "reload-shape (reload_copy=true, empty upstreams) should "
                  "NOT throw on issuer.upstream cross-ref but did: " + err_msg;
        } else if (!startup_pass) {
            err = startup_threw
                ? "startup-shape threw but with wrong error (expected "
                  "'references unknown upstream'); got: " + startup_err
                : "startup-shape (reload_copy=false, full upstreams, missing "
                  "idp_google) should still reject the cross-ref but accepted";
        } else if (!prog_only_pass) {
            err = prog_only_startup_threw
                ? "programmatic-only startup threw but with wrong error "
                  "(expected 'references unknown upstream'); got: " + prog_only_err
                : "programmatic-only startup (reload_copy=false, empty "
                  "upstreams, populated issuer.upstream) should reject the "
                  "cross-ref — this is the gap the explicit reload_copy "
                  "flag was added to fix. Test failure means the fix has "
                  "regressed.";
        }

        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader issuer.upstream check is reload-safe",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader issuer.upstream check is reload-safe",
            false, std::string("unexpected harness error: ") + e.what(),
            TestFramework::TestCategory::OTHER);
    }
}

// -----------------------------------------------------------------------------
// ParseStrictInt — out-of-int-range JSON integers must throw, not wrap
// (review P2 #2). is_number_integer() returns true for any integer that
// fits in nlohmann's internal int64/uint64 representation. v.get<int>()
// then wraps/truncates oversized values — a 4294967297 leeway_sec would
// silently become a small wrapped value. Pin both the unsigned-too-big
// path (UINT_MAX > INT_MAX) and the signed-out-of-range path (negative
// large or near-INT64 boundary).
// -----------------------------------------------------------------------------
void TestConfigLoaderRejectsOutOfRangeIntegers() {
    std::cout << "\n[TEST] ConfigLoader rejects out-of-range integers..." << std::endl;
    auto validate_expect_failure = [](const std::string& json,
                                       const std::string& expected_phrase)
        -> std::string {
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(json);
            ConfigLoader::Validate(cfg);
            return "expected throw containing '" + expected_phrase +
                   "' but accepted";
        } catch (const std::invalid_argument& e) {
            std::string msg = e.what();
            if (msg.find(expected_phrase) == std::string::npos) {
                return "threw with wrong message; expected '" +
                       expected_phrase + "', got: " + msg;
            }
            return "";
        } catch (const std::exception& e) {
            return std::string("unexpected exception type: ") + e.what();
        }
    };

    try {
        // Case 1: leeway_sec exceeding INT_MAX (2^32 + 1 = 4294967297).
        std::string err = validate_expect_failure(R"({
            "upstreams": [{"name":"x","host":"127.0.0.1","port":80}],
            "auth": {
                "enabled": false,
                "issuers": {
                    "ours": {
                        "issuer_url": "https://issuer.example",
                        "upstream": "x",
                        "mode": "jwt",
                        "algorithms": ["RS256"],
                        "leeway_sec": 4294967297
                    }
                }
            }
        })", "out of int range");
        if (!err.empty()) throw std::runtime_error("oversized leeway_sec: " + err);

        // Case 2: introspection.timeout_sec exceeding INT_MAX.
        err = validate_expect_failure(R"({
            "upstreams": [{"name":"x","host":"127.0.0.1","port":80}],
            "auth": {
                "enabled": false,
                "issuers": {
                    "ours": {
                        "issuer_url": "https://issuer.example",
                        "upstream": "x",
                        "mode": "introspection",
                        "introspection": {
                            "endpoint": "https://issuer.example/introspect",
                            "client_id": "c",
                            "client_secret_env": "E",
                            "timeout_sec": 9999999999
                        }
                    }
                }
            }
        })", "out of int range");
        if (!err.empty()) throw std::runtime_error("oversized timeout_sec: " + err);

        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader rejects out-of-range integers",
            true, "", TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader rejects out-of-range integers",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// -----------------------------------------------------------------------------
// ConfigLoader::Validate — auth.forward header names must not be reserved
// (review P2 #3). Hop-by-hop, HTTP/2 pseudo, framing-critical, and
// Authorization names would corrupt or spoof the upstream request. Test
// all four categories on different config positions (subject_header,
// raw_jwt_header, claims_to_headers value).
// -----------------------------------------------------------------------------
void TestConfigLoaderRejectsReservedForwardHeaders() {
    std::cout << "\n[TEST] ConfigLoader rejects reserved auth.forward header names..." << std::endl;
    auto validate_expect_reserved = [](const std::string& bad_header_field,
                                        const std::string& bad_header_name)
        -> std::string {
        std::string json = R"({
            "upstreams": [{"name":"x","host":"127.0.0.1","port":80}],
            "auth": {
                "enabled": false,
                "issuers": {
                    "ours": {
                        "issuer_url": "https://issuer.example",
                        "upstream": "x",
                        "mode": "jwt",
                        "algorithms": ["RS256"]
                    }
                },
                "forward": {)" + bad_header_field + R"(}
            }
        })";
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(json);
            ConfigLoader::Validate(cfg);
            return "expected reserved-name rejection for '" + bad_header_name +
                   "' but accepted";
        } catch (const std::invalid_argument& e) {
            std::string msg = e.what();
            // Accept EITHER rejection path:
            //   - "reserved" — the name is syntactically valid tchar but
            //     in the reserved list (Connection, Host, etc.)
            //   - "not valid in an HTTP field name" — the name contains
            //     non-tchar characters (e.g. ':path' has a colon)
            // Both are valid reasons to reject; pseudo-headers like :path
            // are syntactically invalid AND reserved. The tchar check now
            // fires first for pseudo-headers — either message is fine for
            // this test as long as the offending name appears.
            bool has_rejection_phrase =
                msg.find("reserved") != std::string::npos ||
                msg.find("not valid in an HTTP field name") != std::string::npos;
            if (!has_rejection_phrase) {
                return "threw but message lacked both 'reserved' and "
                       "'not valid in an HTTP field name'; got: " + msg;
            }
            if (msg.find(bad_header_name) == std::string::npos) {
                return "threw but message lacked offending name '" +
                       bad_header_name + "'; got: " + msg;
            }
            return "";
        } catch (const std::exception& e) {
            return std::string("unexpected exception type: ") + e.what();
        }
    };

    try {
        // Case 1: hop-by-hop in subject_header.
        std::string err = validate_expect_reserved(
            R"("subject_header": "Connection")", "Connection");
        if (!err.empty()) throw std::runtime_error("Connection: " + err);

        // Case 2: HTTP/2 pseudo-header in raw_jwt_header.
        // Note: `:path` fails the tchar check first (colon isn't a valid
        // tchar char) — the reserved check is secondary. Either rejection
        // path is accepted by the helper above; the test still pins the
        // "pseudo-headers cannot appear in auth.forward outputs" intent.
        err = validate_expect_reserved(
            R"("raw_jwt_header": ":path")", ":path");
        if (!err.empty()) throw std::runtime_error(":path: " + err);

        // Case 3: framing-critical Host in claims_to_headers value.
        err = validate_expect_reserved(
            R"("claims_to_headers": {"sub": "Host"})", "Host");
        if (!err.empty()) throw std::runtime_error("Host: " + err);

        // Case 4: Content-Length (smuggling vector) in claims_to_headers.
        err = validate_expect_reserved(
            R"("claims_to_headers": {"sub": "Content-Length"})", "Content-Length");
        if (!err.empty()) throw std::runtime_error("Content-Length: " + err);

        // Case 5: Authorization (conflicts with preserve_authorization).
        err = validate_expect_reserved(
            R"("issuer_header": "Authorization")", "Authorization");
        if (!err.empty()) throw std::runtime_error("Authorization: " + err);

        // Case 6: case-insensitive — "connection" lowercase rejected too.
        err = validate_expect_reserved(
            R"("subject_header": "connection")", "connection");
        if (!err.empty()) throw std::runtime_error("connection (lowercase): " + err);

        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader rejects reserved auth.forward headers",
            true, "", TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader rejects reserved auth.forward headers",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// -----------------------------------------------------------------------------
// PopulateFromPayload — clears stale fields on reuse (review P2 #1).
// A second call with a payload missing iss/sub/claims must NOT inherit
// the previous call's values. Principal-confusion bug if not cleared.
// -----------------------------------------------------------------------------
void TestPopulateFromPayloadClearsStaleFields() {
    std::cout << "\n[TEST] PopulateFromPayload clears stale fields on reuse..." << std::endl;
    try {
        auth::AuthContext ctx;

        // First call: populate ctx with iss/sub/email/groups (groups
        // ignored — it's an array — but email is a scalar that lands
        // in claims).
        nlohmann::json first = nlohmann::json::parse(R"({
            "iss": "https://issuer-A.example",
            "sub": "alice",
            "email": "alice@example.com",
            "scope": "read:data"
        })");
        bool ok1 = auth::PopulateFromPayload(first, {"email"}, ctx);
        bool first_pass = ok1 &&
            ctx.issuer == "https://issuer-A.example" &&
            ctx.subject == "alice" &&
            ctx.claims.count("email") == 1 &&
            ctx.scopes.size() == 1;
        if (!first_pass) {
            TestFramework::RecordTest(
                "AuthFoundation: PopulateFromPayload clears stale fields",
                false, "first call failed to populate baseline state",
                TestFramework::TestCategory::OTHER);
            return;
        }

        // Second call REUSING the same ctx: payload has NEITHER iss NOR
        // sub, no email, and a different scope. After this call, ctx
        // must reflect ONLY the second payload — no carryover.
        nlohmann::json second = nlohmann::json::parse(R"({
            "scope": "write:data"
        })");
        bool ok2 = auth::PopulateFromPayload(second, {"email"}, ctx);

        bool second_pass = ok2 &&
            ctx.issuer.empty() &&         // NOT "https://issuer-A.example"
            ctx.subject.empty() &&        // NOT "alice"
            ctx.claims.count("email") == 0 &&  // NOT alice@example.com
            ctx.scopes.size() == 1 &&
            ctx.scopes[0] == "write:data";

        // Third case: structurally invalid payload also clears (caller
        // who accidentally trusts ctx after a false return gets clean
        // state, not stale carryover from the first successful call).
        ctx.issuer = "leftover";
        ctx.subject = "leftover";
        ctx.claims["leftover"] = "leftover";
        nlohmann::json bad = nlohmann::json::parse(R"("a string")");
        bool ok3 = auth::PopulateFromPayload(bad, {}, ctx);
        bool third_pass = !ok3 &&  // returns false on non-object
            ctx.issuer.empty() &&
            ctx.subject.empty() &&
            ctx.claims.empty();

        bool pass = second_pass && third_pass;
        std::string err;
        if (!second_pass) {
            err = "stale-field carryover on reuse: ctx still holds prior "
                  "values (iss='" + ctx.issuer + "', sub='" + ctx.subject +
                  "', claims.size=" + std::to_string(ctx.claims.size()) + ")";
        } else if (!third_pass) {
            err = "non-object payload didn't clear ctx — fail-closed "
                  "contract violated";
        }
        TestFramework::RecordTest(
            "AuthFoundation: PopulateFromPayload clears stale fields",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "AuthFoundation: PopulateFromPayload clears stale fields",
            false, std::string("unexpected exception: ") + e.what(),
            TestFramework::TestCategory::OTHER);
    }
}

// -----------------------------------------------------------------------------
// ConfigLoader::Validate — disabled inline proxy.auth still gets structural
// validation (review P2 #2). Operators are expected to pre-stage disabled
// auth blocks during the rollout; typos must surface NOW, not at the
// deploy where they flip enabled=true.
// -----------------------------------------------------------------------------
void TestConfigLoaderValidatesDisabledInlineAuth() {
    std::cout << "\n[TEST] ConfigLoader validates disabled inline proxy.auth..." << std::endl;
    auto validate_expect_failure = [](const std::string& json,
                                       const std::string& expected_phrase)
        -> std::string {
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(json);
            ConfigLoader::Validate(cfg);
            return "expected throw containing '" + expected_phrase +
                   "' but accepted";
        } catch (const std::invalid_argument& e) {
            std::string msg = e.what();
            if (msg.find(expected_phrase) == std::string::npos) {
                return "threw with wrong message; expected '" +
                       expected_phrase + "', got: " + msg;
            }
            return "";
        } catch (const std::exception& e) {
            return std::string("unexpected exception type: ") + e.what();
        }
    };

    try {
        // Case 1: DISABLED inline auth references unknown issuer — must reject.
        std::string err = validate_expect_failure(R"({
            "upstreams": [
                {"name":"x","host":"127.0.0.1","port":80},
                {
                    "name": "internal-api",
                    "host": "127.0.0.1",
                    "port": 8080,
                    "proxy": {
                        "route_prefix": "/api/v1",
                        "auth": {
                            "enabled": false,
                            "issuers": ["typo-not-a-real-issuer"]
                        }
                    }
                }
            ],
            "auth": {
                "enabled": false,
                "issuers": {
                    "google": {
                        "issuer_url": "https://accounts.google.com",
                        "upstream": "x",
                        "mode": "jwt",
                        "algorithms": ["RS256"]
                    }
                }
            }
        })", "references unknown issuer");
        if (!err.empty()) throw std::runtime_error("disabled unknown issuer: " + err);

        // Case 2: DISABLED inline auth with bad on_undetermined value.
        err = validate_expect_failure(R"({
            "upstreams": [
                {"name":"x","host":"127.0.0.1","port":80},
                {
                    "name": "internal-api",
                    "host": "127.0.0.1",
                    "port": 8080,
                    "proxy": {
                        "route_prefix": "/api/v1",
                        "auth": {
                            "enabled": false,
                            "issuers": ["google"],
                            "on_undetermined": "maybe"
                        }
                    }
                }
            ],
            "auth": {
                "enabled": false,
                "issuers": {
                    "google": {
                        "issuer_url": "https://accounts.google.com",
                        "upstream": "x",
                        "mode": "jwt",
                        "algorithms": ["RS256"]
                    }
                }
            }
        })", "on_undetermined must be");
        if (!err.empty()) throw std::runtime_error("disabled bad on_undetermined: " + err);

        // Case 3: DISABLED inline auth populated but no route_prefix.
        err = validate_expect_failure(R"({
            "upstreams": [
                {"name":"x","host":"127.0.0.1","port":80},
                {
                    "name": "internal-api",
                    "host": "127.0.0.1",
                    "port": 8080,
                    "proxy": {
                        "auth": {
                            "enabled": false,
                            "issuers": ["google"]
                        }
                    }
                }
            ],
            "auth": {
                "enabled": false,
                "issuers": {
                    "google": {
                        "issuer_url": "https://accounts.google.com",
                        "upstream": "x",
                        "mode": "jwt",
                        "algorithms": ["RS256"]
                    }
                }
            }
        })", "no route_prefix");
        if (!err.empty()) throw std::runtime_error("disabled no route_prefix: " + err);

        // Case 4: NEGATIVE — proxy with no auth block at all and no
        // route_prefix (programmatic-only proxy). Must NOT trigger the
        // route_prefix check (the populated-detection guards it).
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(R"({
                "upstreams": [
                    {
                        "name": "programmatic-only",
                        "host": "127.0.0.1",
                        "port": 8080
                    }
                ]
            })");
            ConfigLoader::Validate(cfg);
            // Expected: no throw. If we got here, good.
        } catch (const std::exception& e) {
            throw std::runtime_error(
                "no-auth-block proxy without route_prefix should pass "
                "validation, but threw: " + std::string(e.what()));
        }

        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader validates disabled inline proxy.auth",
            true, "", TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader validates disabled inline proxy.auth",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// -----------------------------------------------------------------------------
// ConfigLoader::ToJson — serializes proxy block when only auth differs
// (review P2 #3). ProxyConfig::operator== ignores `auth` (correct, by
// design — auth is live-reloadable). Without an explicit auth-difference
// check in the serialization gate, a proxy customizing only the inline
// auth stanza gets its entire block dropped on round-trip. That's exactly
// the staged-config shape operators are expected to use during the
// pre-Phase-2 rollout, so the round-trip loss is a config-data-loss bug.
// -----------------------------------------------------------------------------
void TestConfigLoaderRoundTripsAuthOnlyProxy() {
    std::cout << "\n[TEST] ConfigLoader round-trips auth-only proxy block..." << std::endl;
    try {
        // Proxy that ONLY customizes inline auth — every other proxy
        // field is at its default (empty route_prefix would fail the
        // populated-route-prefix structural check, so we set
        // route_prefix to something non-empty; everything ELSE is at
        // default). Notable: enabled=false on the auth (so the master
        // gate doesn't fire) but issuers/realm are populated to make
        // the auth block clearly non-default.
        const std::string original = R"({
            "bind_host": "127.0.0.1",
            "bind_port": 8080,
            "upstreams": [
                {"name":"x","host":"127.0.0.1","port":80},
                {
                    "name": "internal-api",
                    "host": "127.0.0.1",
                    "port": 8080,
                    "proxy": {
                        "route_prefix": "/api/v1",
                        "auth": {
                            "enabled": false,
                            "issuers": ["google"],
                            "realm": "internal-api"
                        }
                    }
                }
            ],
            "auth": {
                "enabled": false,
                "issuers": {
                    "google": {
                        "issuer_url": "https://accounts.google.com",
                        "upstream": "x",
                        "mode": "jwt",
                        "algorithms": ["RS256"]
                    }
                }
            }
        })";

        ServerConfig c1 = ConfigLoader::LoadFromString(original);
        // Confirm the original fixture parsed the inline auth block.
        bool parsed_inline = false;
        for (const auto& u : c1.upstreams) {
            if (u.name == "internal-api") {
                parsed_inline =
                    !u.proxy.auth.issuers.empty() &&
                    u.proxy.auth.issuers[0] == "google" &&
                    u.proxy.auth.realm == "internal-api";
                break;
            }
        }
        if (!parsed_inline) {
            TestFramework::RecordTest(
                "AuthFoundation: ConfigLoader round-trips auth-only proxy",
                false, "fixture: parser failed to capture the inline auth "
                       "block on the first parse — test cannot proceed",
                TestFramework::TestCategory::OTHER);
            return;
        }

        // Serialize and re-parse. THIS is the path that previously dropped
        // the proxy block because operator== ignores auth and the gate
        // used `u.proxy != ProxyConfig{}`.
        std::string reserialized = ConfigLoader::ToJson(c1);
        ServerConfig c2 = ConfigLoader::LoadFromString(reserialized);

        // The round-trip must preserve the inline auth block.
        bool round_trip_preserved = false;
        for (const auto& u : c2.upstreams) {
            if (u.name == "internal-api") {
                round_trip_preserved =
                    !u.proxy.auth.issuers.empty() &&
                    u.proxy.auth.issuers[0] == "google" &&
                    u.proxy.auth.realm == "internal-api";
                break;
            }
        }

        bool pass = round_trip_preserved;
        std::string err;
        if (!pass) {
            err = "round-trip dropped the auth-only proxy block — "
                  "ToJson() gate didn't recognize the auth-only "
                  "difference. Reserialized JSON: " +
                  reserialized.substr(0, 300) + "...";
        }
        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader round-trips auth-only proxy",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader round-trips auth-only proxy",
            false, std::string("unexpected exception: ") + e.what(),
            TestFramework::TestCategory::OTHER);
    }
}

// -----------------------------------------------------------------------------
// ConfigLoader::Validate — disabled top-level policies skip collision
// detection, matching the inline-policy treatment (review P2 #1).
// Operators staging policies during the rollout get a usable config; the
// runtime matcher already ignores disabled entries so collision is moot.
// -----------------------------------------------------------------------------
void TestConfigLoaderDisabledTopLevelPoliciesDoNotCollide() {
    std::cout << "\n[TEST] ConfigLoader skips disabled top-level policies in collision check..." << std::endl;
    try {
        // Two top-level policies with IDENTICAL applies_to but BOTH
        // disabled. Pre-fix: rejected with "exact-prefix collision".
        // Post-fix: accepted (neither participates in runtime matching).
        const std::string both_disabled = R"({
            "upstreams": [{"name":"x","host":"127.0.0.1","port":80}],
            "auth": {
                "enabled": false,
                "issuers": {
                    "google": {
                        "issuer_url": "https://issuer.example",
                        "upstream": "x",
                        "mode": "jwt",
                        "algorithms": ["RS256"]
                    }
                },
                "policies": [
                    {"name":"a", "enabled":false, "applies_to":["/api/"], "issuers":["google"]},
                    {"name":"b", "enabled":false, "applies_to":["/api/"], "issuers":["google"]}
                ]
            }
        })";
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(both_disabled);
            ConfigLoader::Validate(cfg);
            // Expected: no throw.
        } catch (const std::exception& e) {
            throw std::runtime_error(
                "two disabled policies sharing a prefix should be ACCEPTED "
                "(neither participates in runtime matching) but Validate "
                "threw: " + std::string(e.what()));
        }

        // Regression: ENABLED policies with same prefix must STILL reject.
        // Confirms the relaxation is scoped to disabled entries only.
        const std::string both_enabled = R"({
            "upstreams": [{"name":"x","host":"127.0.0.1","port":80}],
            "auth": {
                "enabled": false,
                "issuers": {
                    "google": {
                        "issuer_url": "https://issuer.example",
                        "upstream": "x",
                        "mode": "jwt",
                        "algorithms": ["RS256"]
                    }
                },
                "policies": [
                    {"name":"a", "enabled":true, "applies_to":["/api/"], "issuers":["google"]},
                    {"name":"b", "enabled":true, "applies_to":["/api/"], "issuers":["google"]}
                ]
            }
        })";
        bool enabled_threw = false;
        std::string enabled_err;
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(both_enabled);
            ConfigLoader::Validate(cfg);
        } catch (const std::invalid_argument& e) {
            enabled_threw = true;
            enabled_err = e.what();
        }
        bool enabled_collision_msg = enabled_threw &&
            enabled_err.find("declared by both") != std::string::npos;

        // Mixed: one enabled, one disabled with same prefix. Should NOT
        // collide because the disabled one doesn't enter the registry.
        const std::string mixed = R"({
            "upstreams": [{"name":"x","host":"127.0.0.1","port":80}],
            "auth": {
                "enabled": false,
                "issuers": {
                    "google": {
                        "issuer_url": "https://issuer.example",
                        "upstream": "x",
                        "mode": "jwt",
                        "algorithms": ["RS256"]
                    }
                },
                "policies": [
                    {"name":"a", "enabled":true,  "applies_to":["/api/"], "issuers":["google"]},
                    {"name":"b", "enabled":false, "applies_to":["/api/"], "issuers":["google"]}
                ]
            }
        })";
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(mixed);
            ConfigLoader::Validate(cfg);
            // Expected: no throw.
        } catch (const std::exception& e) {
            throw std::runtime_error(
                "mixed enabled/disabled at same prefix should be ACCEPTED "
                "but Validate threw: " + std::string(e.what()));
        }

        bool pass = enabled_collision_msg;
        std::string err;
        if (!enabled_threw) {
            err = "two ENABLED policies sharing a prefix should still "
                  "reject (regression check failed)";
        } else if (!enabled_collision_msg) {
            err = "enabled-collision threw but with wrong message; expected "
                  "'declared by both', got: " + enabled_err;
        }
        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader skips disabled top-level policies in collision",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader skips disabled top-level policies in collision",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// -----------------------------------------------------------------------------
// ConfigLoader::Validate — inline proxy.auth must reject applies_to
// (review P2 #2). The prefix is derived from proxy.route_prefix; an inline
// applies_to is silently ignored at runtime, so a JSON with both would
// describe a different protected path than what's actually enforced.
// -----------------------------------------------------------------------------
void TestConfigLoaderRejectsInlineAuthAppliesTo() {
    std::cout << "\n[TEST] ConfigLoader rejects applies_to inside inline proxy.auth..." << std::endl;
    try {
        const std::string bad = R"({
            "upstreams": [
                {"name":"x","host":"127.0.0.1","port":80},
                {
                    "name": "internal-api",
                    "host": "127.0.0.1",
                    "port": 8080,
                    "proxy": {
                        "route_prefix": "/api/",
                        "auth": {
                            "enabled": false,
                            "applies_to": ["/admin/"],
                            "issuers": ["google"]
                        }
                    }
                }
            ],
            "auth": {
                "enabled": false,
                "issuers": {
                    "google": {
                        "issuer_url": "https://issuer.example",
                        "upstream": "x",
                        "mode": "jwt",
                        "algorithms": ["RS256"]
                    }
                }
            }
        })";
        bool threw = false;
        std::string err_msg;
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(bad);
            ConfigLoader::Validate(cfg);
        } catch (const std::invalid_argument& e) {
            threw = true;
            err_msg = e.what();
        }
        // Message should mention applies_to and route_prefix so operators
        // know the prefix actually comes from the surrounding proxy.
        bool good_msg = threw &&
            err_msg.find("applies_to") != std::string::npos &&
            err_msg.find("route_prefix") != std::string::npos;
        bool pass = threw && good_msg;
        std::string err;
        if (!threw) {
            err = "expected inline applies_to to be rejected at parse time "
                  "but config was accepted";
        } else if (!good_msg) {
            err = "threw but message lacked one of {'applies_to', "
                  "'route_prefix'}; got: " + err_msg;
        }

        // Regression: TOP-LEVEL applies_to must STILL be accepted (only
        // inline rejects it). Confirms the parser parameter is wired
        // correctly per call site.
        try {
            const std::string ok = R"({
                "upstreams": [{"name":"x","host":"127.0.0.1","port":80}],
                "auth": {
                    "enabled": false,
                    "issuers": {
                        "google": {
                            "issuer_url": "https://issuer.example",
                            "upstream": "x",
                            "mode": "jwt",
                            "algorithms": ["RS256"]
                        }
                    },
                    "policies": [
                        {"name":"p", "enabled":false, "applies_to":["/admin/"], "issuers":["google"]}
                    ]
                }
            })";
            ServerConfig c2 = ConfigLoader::LoadFromString(ok);
            ConfigLoader::Validate(c2);
        } catch (const std::exception& e) {
            err = "regression: top-level applies_to should still be accepted "
                  "but threw: " + std::string(e.what());
            pass = false;
        }

        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader rejects applies_to in inline proxy.auth",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader rejects applies_to in inline proxy.auth",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// -----------------------------------------------------------------------------
// ConfigLoader::Validate — Proxy-Connection is reserved (review P3).
// HeaderRewriter::IsHopByHopHeader strips Proxy-Connection at outbound
// time (server/header_rewriter.cc:18); auth.forward must reject it at
// config load to avoid the silently-dropped-identity-header symptom.
// -----------------------------------------------------------------------------
void TestConfigLoaderRejectsProxyConnectionInAuthForward() {
    std::cout << "\n[TEST] ConfigLoader rejects Proxy-Connection in auth.forward..." << std::endl;
    auto validate_expect_reserved = [](const std::string& bad_header_field,
                                        const std::string& bad_name)
        -> std::string {
        std::string json = R"({
            "upstreams": [{"name":"x","host":"127.0.0.1","port":80}],
            "auth": {
                "enabled": false,
                "issuers": {
                    "google": {
                        "issuer_url": "https://issuer.example",
                        "upstream": "x",
                        "mode": "jwt",
                        "algorithms": ["RS256"]
                    }
                },
                "forward": {)" + bad_header_field + R"(}
            }
        })";
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(json);
            ConfigLoader::Validate(cfg);
            return "expected reserved-name rejection for '" + bad_name +
                   "' but accepted";
        } catch (const std::invalid_argument& e) {
            std::string msg = e.what();
            if (msg.find("reserved") == std::string::npos ||
                msg.find(bad_name) == std::string::npos) {
                return "threw but message missing 'reserved' or offending "
                       "name '" + bad_name + "'; got: " + msg;
            }
            return "";
        } catch (const std::exception& e) {
            return std::string("unexpected exception type: ") + e.what();
        }
    };

    try {
        // Test all three fixed-slot positions.
        std::string err = validate_expect_reserved(
            R"("subject_header": "Proxy-Connection")", "Proxy-Connection");
        if (!err.empty()) throw std::runtime_error("subject_header: " + err);

        err = validate_expect_reserved(
            R"("raw_jwt_header": "Proxy-Connection")", "Proxy-Connection");
        if (!err.empty()) throw std::runtime_error("raw_jwt_header: " + err);

        err = validate_expect_reserved(
            R"("claims_to_headers": {"sub": "Proxy-Connection"})",
            "Proxy-Connection");
        if (!err.empty()) throw std::runtime_error("claims_to_headers: " + err);

        // Case-insensitive: lowercase variant rejected too.
        err = validate_expect_reserved(
            R"("subject_header": "proxy-connection")", "proxy-connection");
        if (!err.empty()) throw std::runtime_error("lowercase: " + err);

        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader rejects Proxy-Connection in auth.forward",
            true, "", TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader rejects Proxy-Connection in auth.forward",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// -----------------------------------------------------------------------------
// ConfigLoader::Validate — enabled top-level policy must declare applies_to
// (review P2 #1). A policy with enabled=true and no prefixes never matches
// any path; the operator's intended-protected routes silently stay open.
// Disabled policies allowed to be empty (mid-construction state during
// rollout — same logic that lets us skip them in collision detection).
// -----------------------------------------------------------------------------
void TestConfigLoaderRejectsEnabledPolicyWithoutAppliesTo() {
    std::cout << "\n[TEST] ConfigLoader rejects enabled policy without applies_to..." << std::endl;
    try {
        // Case 1: enabled + empty applies_to → reject.
        const std::string bad = R"({
            "upstreams": [{"name":"x","host":"127.0.0.1","port":80}],
            "auth": {
                "enabled": false,
                "issuers": {
                    "google": {
                        "issuer_url": "https://issuer.example",
                        "upstream": "x",
                        "mode": "jwt",
                        "algorithms": ["RS256"]
                    }
                },
                "policies": [
                    {"name":"dead", "enabled":true, "issuers":["google"]}
                ]
            }
        })";
        bool threw = false;
        std::string err_msg;
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(bad);
            ConfigLoader::Validate(cfg);
        } catch (const std::invalid_argument& e) {
            threw = true;
            err_msg = e.what();
        }
        bool good_msg = threw &&
            err_msg.find("applies_to") != std::string::npos &&
            err_msg.find("never match") != std::string::npos;

        // Case 2: disabled + empty applies_to → ACCEPT (mid-construction).
        const std::string ok_disabled = R"({
            "upstreams": [{"name":"x","host":"127.0.0.1","port":80}],
            "auth": {
                "enabled": false,
                "issuers": {
                    "google": {
                        "issuer_url": "https://issuer.example",
                        "upstream": "x",
                        "mode": "jwt",
                        "algorithms": ["RS256"]
                    }
                },
                "policies": [
                    {"name":"staged", "enabled":false, "issuers":["google"]}
                ]
            }
        })";
        bool disabled_passed = true;
        try {
            ServerConfig cfg2 = ConfigLoader::LoadFromString(ok_disabled);
            ConfigLoader::Validate(cfg2);
        } catch (const std::exception& e) {
            disabled_passed = false;
            err_msg = std::string("disabled+empty rejected when it shouldn't: ") + e.what();
        }

        bool pass = threw && good_msg && disabled_passed;
        std::string err;
        if (!threw) {
            err = "expected enabled+empty applies_to to reject, but accepted";
        } else if (!good_msg) {
            err = "rejected but message missing 'applies_to' / 'never match'; got: " + err_msg;
        } else if (!disabled_passed) {
            err = err_msg;
        }
        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader rejects enabled policy without applies_to",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader rejects enabled policy without applies_to",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// -----------------------------------------------------------------------------
// ConfigLoader::Validate — introspection knobs (review P2 #2). auth_style
// must be "basic"|"body"; timeout/cache/max_entries/shards must be > 0;
// negative_cache_sec / stale_grace_sec must be >= 0 (0 disables feature).
// -----------------------------------------------------------------------------
void TestConfigLoaderValidatesIntrospectionKnobs() {
    std::cout << "\n[TEST] ConfigLoader validates introspection knobs..." << std::endl;
    auto introspection_with = [](const std::string& fields) -> std::string {
        return R"({
            "upstreams": [{"name":"x","host":"127.0.0.1","port":80}],
            "auth": {
                "enabled": false,
                "issuers": {
                    "ours": {
                        "issuer_url": "https://issuer.example",
                        "upstream": "x",
                        "mode": "introspection",
                        "introspection": {
                            "endpoint": "https://issuer.example/introspect",
                            "client_id": "c",
                            "client_secret_env": "E")"
            + fields + R"(
                        }
                    }
                }
            }
        })";
    };
    auto validate_expect_failure = [&](const std::string& json,
                                        const std::string& expected_phrase)
        -> std::string {
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(json);
            ConfigLoader::Validate(cfg);
            return "expected throw containing '" + expected_phrase +
                   "' but accepted";
        } catch (const std::invalid_argument& e) {
            std::string msg = e.what();
            if (msg.find(expected_phrase) == std::string::npos) {
                return "threw but message missing '" + expected_phrase +
                       "'; got: " + msg;
            }
            return "";
        } catch (const std::exception& e) {
            return std::string("unexpected exception type: ") + e.what();
        }
    };

    try {
        // 1. auth_style="weird" rejected.
        std::string err = validate_expect_failure(
            introspection_with(R"(, "auth_style": "weird")"),
            "auth_style must be");
        if (!err.empty()) throw std::runtime_error("auth_style: " + err);

        // 2. timeout_sec=-1 rejected.
        err = validate_expect_failure(
            introspection_with(R"(, "timeout_sec": -1)"),
            "timeout_sec must be > 0");
        if (!err.empty()) throw std::runtime_error("timeout_sec=-1: " + err);

        // 3. timeout_sec=0 also rejected (strict positive).
        err = validate_expect_failure(
            introspection_with(R"(, "timeout_sec": 0)"),
            "timeout_sec must be > 0");
        if (!err.empty()) throw std::runtime_error("timeout_sec=0: " + err);

        // 4. cache_sec=0 rejected.
        err = validate_expect_failure(
            introspection_with(R"(, "cache_sec": 0)"),
            "cache_sec must be > 0");
        if (!err.empty()) throw std::runtime_error("cache_sec=0: " + err);

        // 5. shards=0 rejected.
        err = validate_expect_failure(
            introspection_with(R"(, "shards": 0)"),
            "shards must be > 0");
        if (!err.empty()) throw std::runtime_error("shards=0: " + err);

        // 6. max_entries=0 rejected.
        err = validate_expect_failure(
            introspection_with(R"(, "max_entries": 0)"),
            "max_entries must be > 0");
        if (!err.empty()) throw std::runtime_error("max_entries=0: " + err);

        // 7. negative_cache_sec=-1 rejected.
        err = validate_expect_failure(
            introspection_with(R"(, "negative_cache_sec": -1)"),
            "negative_cache_sec must be >= 0");
        if (!err.empty()) throw std::runtime_error("negative_cache_sec=-1: " + err);

        // 8. stale_grace_sec=-5 rejected.
        err = validate_expect_failure(
            introspection_with(R"(, "stale_grace_sec": -5)"),
            "stale_grace_sec must be >= 0");
        if (!err.empty()) throw std::runtime_error("stale_grace_sec=-5: " + err);

        // 9. POSITIVE: negative_cache_sec=0 accepted (means "disable
        // negative caching" — meaningful 0 semantics, not an error).
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(
                introspection_with(R"(, "negative_cache_sec": 0)"));
            ConfigLoader::Validate(cfg);
        } catch (const std::exception& e) {
            throw std::runtime_error(
                std::string("negative_cache_sec=0 should be ACCEPTED ")
                + "(disables feature) but rejected: " + e.what());
        }

        // 10. POSITIVE: stale_grace_sec=0 accepted (disable stale serving).
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(
                introspection_with(R"(, "stale_grace_sec": 0)"));
            ConfigLoader::Validate(cfg);
        } catch (const std::exception& e) {
            throw std::runtime_error(
                std::string("stale_grace_sec=0 should be ACCEPTED ")
                + "but rejected: " + e.what());
        }

        // 11. POSITIVE: auth_style="body" accepted.
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(
                introspection_with(R"(, "auth_style": "body")"));
            ConfigLoader::Validate(cfg);
        } catch (const std::exception& e) {
            throw std::runtime_error(
                std::string("auth_style=body should be ACCEPTED but ")
                + "rejected: " + e.what());
        }

        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader validates introspection knobs",
            true, "", TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader validates introspection knobs",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// -----------------------------------------------------------------------------
// ConfigLoader::Validate — inline auth rejects patterned route_prefix
// (review P1). auth::FindPolicyForPath does byte-prefix matching; a proxy
// with /api/:v/users/*path cannot be matched via the auth overlay because
// the literal string never appears in real request paths. Reject at load.
// -----------------------------------------------------------------------------
void TestConfigLoaderRejectsPatternedInlineAuthPrefix() {
    std::cout << "\n[TEST] ConfigLoader rejects patterned route_prefix in inline auth..." << std::endl;
    auto validate_expect_failure = [](const std::string& json,
                                       const std::string& expected_phrase)
        -> std::string {
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(json);
            ConfigLoader::Validate(cfg);
            return "expected throw containing '" + expected_phrase +
                   "' but accepted";
        } catch (const std::invalid_argument& e) {
            std::string msg = e.what();
            if (msg.find(expected_phrase) == std::string::npos) {
                return "threw but message missing '" + expected_phrase +
                       "'; got: " + msg;
            }
            return "";
        } catch (const std::exception& e) {
            return std::string("unexpected exception type: ") + e.what();
        }
    };

    auto make_json = [](const std::string& route_prefix) -> std::string {
        return R"({
            "upstreams": [
                {"name":"x","host":"127.0.0.1","port":80},
                {
                    "name": "api",
                    "host": "127.0.0.1",
                    "port": 8080,
                    "proxy": {
                        "route_prefix": ")" + route_prefix + R"(",
                        "auth": {
                            "enabled": false,
                            "issuers": ["google"]
                        }
                    }
                }
            ],
            "auth": {
                "enabled": false,
                "issuers": {
                    "google": {
                        "issuer_url": "https://issuer.example",
                        "upstream": "x",
                        "mode": "jwt",
                        "algorithms": ["RS256"]
                    }
                }
            }
        })";
    };

    try {
        // Case 1: :param segment.
        std::string err = validate_expect_failure(
            make_json("/api/:version/users"), "LITERAL prefix");
        if (!err.empty()) throw std::runtime_error(":version case: " + err);

        // Case 2: *splat segment.
        err = validate_expect_failure(
            make_json("/api/*rest"), "LITERAL prefix");
        if (!err.empty()) throw std::runtime_error("*rest case: " + err);

        // Case 3: mixed — both :param and *splat.
        err = validate_expect_failure(
            make_json("/api/:version/users/*path"), "LITERAL prefix");
        if (!err.empty()) throw std::runtime_error("mixed case: " + err);

        // POSITIVE: pure literal prefix accepted.
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(
                make_json("/api/v1/"));
            ConfigLoader::Validate(cfg);
        } catch (const std::exception& e) {
            throw std::runtime_error(
                std::string("pure literal prefix should be ACCEPTED but ")
                + "rejected: " + e.what());
        }

        // POSITIVE: proxy with :param prefix but NO auth block at all —
        // should still be accepted (route_trie handles the pattern; auth
        // overlay isn't involved).
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(R"({
                "upstreams": [
                    {
                        "name": "api",
                        "host": "127.0.0.1",
                        "port": 8080,
                        "proxy": {"route_prefix": "/api/:v/users"}
                    }
                ]
            })");
            ConfigLoader::Validate(cfg);
        } catch (const std::exception& e) {
            throw std::runtime_error(
                std::string("patterned route WITHOUT inline auth should be ")
                + "ACCEPTED (auth overlay not involved) but rejected: " + e.what());
        }

        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader rejects patterned route_prefix in inline auth",
            true, "", TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader rejects patterned route_prefix in inline auth",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// -----------------------------------------------------------------------------
// ConfigLoader::Validate — issuer.upstream is structurally required
// (review P2 #1). Separate the "field present" check (fires always) from
// the "cross-ref to existing upstream" check (reload-safe-skipped when
// upstreams is empty).
// -----------------------------------------------------------------------------
void TestConfigLoaderRequiresIssuerUpstream() {
    std::cout << "\n[TEST] ConfigLoader requires issuer.upstream..." << std::endl;
    auto validate_expect_failure = [](const std::string& json,
                                       const std::string& expected_phrase)
        -> std::string {
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(json);
            ConfigLoader::Validate(cfg);
            return "expected throw containing '" + expected_phrase +
                   "' but accepted";
        } catch (const std::invalid_argument& e) {
            std::string msg = e.what();
            if (msg.find(expected_phrase) == std::string::npos) {
                return "threw but message missing '" + expected_phrase +
                       "'; got: " + msg;
            }
            return "";
        } catch (const std::exception& e) {
            return std::string("unexpected exception type: ") + e.what();
        }
    };

    try {
        // Case 1: issuer omits `upstream` entirely — rejected as structural
        // requirement (fires even on reload-path with empty upstreams).
        std::string err = validate_expect_failure(R"({
            "upstreams": [{"name":"x","host":"127.0.0.1","port":80}],
            "auth": {
                "enabled": false,
                "issuers": {
                    "ours": {
                        "issuer_url": "https://issuer.example",
                        "mode": "jwt",
                        "algorithms": ["RS256"]
                    }
                }
            }
        })", "upstream is required");
        if (!err.empty()) throw std::runtime_error("missing upstream: " + err);

        // Case 2: structural check fires on reload-path shape (empty
        // upstreams) too. Before the split, a config with upstream=""
        // and empty upstreams[] would silently accept because both
        // branches of the combined check were short-circuited.
        err = validate_expect_failure(R"({
            "upstreams": [],
            "auth": {
                "enabled": false,
                "issuers": {
                    "ours": {
                        "issuer_url": "https://issuer.example",
                        "mode": "jwt",
                        "algorithms": ["RS256"]
                    }
                }
            }
        })", "upstream is required");
        if (!err.empty()) throw std::runtime_error("empty-upstreams reload shape: " + err);

        // Case 3: regression — upstream set but pointing at unknown name,
        // with full startup upstreams list, STILL rejected by the
        // cross-ref check.
        err = validate_expect_failure(R"({
            "upstreams": [{"name":"x","host":"127.0.0.1","port":80}],
            "auth": {
                "enabled": false,
                "issuers": {
                    "ours": {
                        "issuer_url": "https://issuer.example",
                        "upstream": "nonexistent",
                        "mode": "jwt",
                        "algorithms": ["RS256"]
                    }
                }
            }
        })", "references unknown upstream");
        if (!err.empty()) throw std::runtime_error("unknown upstream at startup: " + err);

        // Case 4: regression — reload-safe path still skips cross-ref
        // when called with reload_copy=true (avoids blocking unrelated
        // hot reloads). Upstream IS set here; upstreams list is empty;
        // caller signals reload context explicitly via the flag.
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(R"({
                "upstreams": [],
                "auth": {
                    "enabled": false,
                    "issuers": {
                        "ours": {
                            "issuer_url": "https://issuer.example",
                            "upstream": "somewhere",
                            "mode": "jwt",
                            "algorithms": ["RS256"]
                        }
                    }
                }
            })");
            ConfigLoader::Validate(cfg, /*reload_copy=*/true);
        } catch (const std::exception& e) {
            throw std::runtime_error(
                std::string("reload-shape with reload_copy=true ")
                + "should pass cross-ref check but threw: " + e.what());
        }

        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader requires issuer.upstream",
            true, "", TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader requires issuer.upstream",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// -----------------------------------------------------------------------------
// ConfigLoader::Validate — header names must be RFC 7230 §3.2.6 tchar
// (review P2 #2). Space, slash, paren, and other non-tchar characters
// would produce malformed HTTP on the forwarded request.
// -----------------------------------------------------------------------------
void TestConfigLoaderValidatesHeaderNameTchar() {
    std::cout << "\n[TEST] ConfigLoader validates header-name tchar..." << std::endl;
    auto validate_expect_tchar_reject = [](const std::string& field_fragment,
                                            const std::string& offending_name)
        -> std::string {
        std::string json = R"({
            "upstreams": [{"name":"x","host":"127.0.0.1","port":80}],
            "auth": {
                "enabled": false,
                "issuers": {
                    "ours": {
                        "issuer_url": "https://issuer.example",
                        "upstream": "x",
                        "mode": "jwt",
                        "algorithms": ["RS256"]
                    }
                },
                "forward": {)" + field_fragment + R"(}
            }
        })";
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(json);
            ConfigLoader::Validate(cfg);
            return "expected tchar rejection for '" + offending_name +
                   "' but accepted";
        } catch (const std::invalid_argument& e) {
            std::string msg = e.what();
            if (msg.find("not valid in an HTTP field name") == std::string::npos) {
                return "threw but message lacked 'not valid in an HTTP "
                       "field name'; got: " + msg;
            }
            if (msg.find(offending_name) == std::string::npos) {
                return "threw but message lacked offending name '" +
                       offending_name + "'; got: " + msg;
            }
            return "";
        } catch (const std::exception& e) {
            return std::string("unexpected exception type: ") + e.what();
        }
    };

    try {
        // Case 1: space in subject_header — most common real-world typo.
        std::string err = validate_expect_tchar_reject(
            R"("subject_header": "X Bad")", "X Bad");
        if (!err.empty()) throw std::runtime_error("space: " + err);

        // Case 2: slash (common mistake from URL paths).
        err = validate_expect_tchar_reject(
            R"("raw_jwt_header": "X/Bad")", "X/Bad");
        if (!err.empty()) throw std::runtime_error("slash: " + err);

        // Case 3: paren (commonly copied from function names in config).
        // Use a non-default raw-string delimiter `raw(...)raw` because the
        // default `(...)` terminates at the first `)"` — which appears
        // inside the literal header name `"X(Bad)"`.
        err = validate_expect_tchar_reject(
            R"raw("claims_to_headers": {"sub": "X(Bad)"})raw", "X(Bad)");
        if (!err.empty()) throw std::runtime_error("paren: " + err);

        // Case 4: at-sign.
        err = validate_expect_tchar_reject(
            R"("issuer_header": "X@Bad")", "X@Bad");
        if (!err.empty()) throw std::runtime_error("at-sign: " + err);

        // POSITIVE: valid tchar punctuation should be accepted.
        // RFC 7230 allows !#$%&'*+-.^_`|~ in tchar.
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(R"({
                "upstreams": [{"name":"x","host":"127.0.0.1","port":80}],
                "auth": {
                    "enabled": false,
                    "issuers": {
                        "ours": {
                            "issuer_url": "https://issuer.example",
                            "upstream": "x",
                            "mode": "jwt",
                            "algorithms": ["RS256"]
                        }
                    },
                    "forward": {
                        "subject_header": "X-Auth-Subject",
                        "claims_to_headers": {"email": "X-User.Email_v1"}
                    }
                }
            })");
            ConfigLoader::Validate(cfg);
        } catch (const std::exception& e) {
            throw std::runtime_error(
                std::string("valid tchar names should be ACCEPTED but ")
                + "rejected: " + e.what());
        }

        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader validates header-name tchar",
            true, "", TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader validates header-name tchar",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// -----------------------------------------------------------------------------
// ConfigLoader::Validate — top-level auth.policies[].applies_to entries
// are LITERAL byte prefixes and may contain any printable characters —
// INCLUDING ':' and '*' that look like route-trie pattern syntax but are
// actually literal path components. An earlier iteration parsed these
// with ROUTE_TRIE::ParsePattern and rejected ':' / '*' segments; that
// was over-strict and blocked legitimate literal URLs like "/docs/:faq"
// or "/assets/*latest". The auth matcher has NO concept of route-trie
// patterns — it just does byte-prefix comparison — so accepting these
// strings is correct.
//
// This test pins the acceptance behavior (regression protection against
// reintroducing the over-strict check). The inline `proxy.auth`
// route_prefix check is SEPARATE and DOES still reject patterned
// prefixes, because inline route_prefix is consumed by TWO matchers
// (route_trie + auth) with different semantics — see
// TestConfigLoaderRejectsPatternedInlineAuthPrefix.
// -----------------------------------------------------------------------------
void TestConfigLoaderAcceptsLiteralPatternCharsInAppliesTo() {
    std::cout << "\n[TEST] ConfigLoader accepts literal :/* chars in top-level applies_to..." << std::endl;

    auto make_json = [](const std::string& applies_to_array,
                         bool enabled) -> std::string {
        return std::string(R"({
            "upstreams": [{"name":"x","host":"127.0.0.1","port":80}],
            "auth": {
                "enabled": false,
                "issuers": {
                    "google": {
                        "issuer_url": "https://issuer.example",
                        "upstream": "x",
                        "mode": "jwt",
                        "algorithms": ["RS256"]
                    }
                },
                "policies": [{"name":"p","enabled":)") +
               (enabled ? "true" : "false") + R"(,"applies_to":)" +
               applies_to_array + R"(,"issuers":["google"]}]
            }
        })";
    };

    auto expect_accepted = [&make_json](const std::string& applies_to_array,
                                         const std::string& label,
                                         bool enabled) -> std::string {
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(
                make_json(applies_to_array, enabled));
            ConfigLoader::Validate(cfg);
            return "";
        } catch (const std::exception& e) {
            return label + " rejected (should be accepted): " + e.what();
        }
    };

    try {
        // Case 1: literal ":faq" segment (e.g. docs/wiki system with
        // literal ':' in URL path) — accepted.
        std::string err = expect_accepted(
            R"(["/docs/:faq"])", "/docs/:faq", /*enabled=*/true);
        if (!err.empty()) throw std::runtime_error(err);

        // Case 2: literal "*latest" segment (e.g. asset versioning URL) —
        // accepted.
        err = expect_accepted(
            R"(["/assets/*latest"])", "/assets/*latest", /*enabled=*/true);
        if (!err.empty()) throw std::runtime_error(err);

        // Case 3: mixed — pure-literal and pattern-looking entries in
        // same policy — all accepted.
        err = expect_accepted(
            R"(["/api/", "/api/:version/"])", "mixed", /*enabled=*/true);
        if (!err.empty()) throw std::runtime_error(err);

        // Case 4: disabled policy with pattern-looking entry also
        // accepted (consistency — no reason to reject based on enable
        // state when the entry itself is legal).
        err = expect_accepted(
            R"(["/api/:id"])", "disabled /api/:id", /*enabled=*/false);
        if (!err.empty()) throw std::runtime_error(err);

        // Case 5: pure literal entry (the common case) — accepted.
        err = expect_accepted(
            R"(["/api/v1/"])", "literal /api/v1/", /*enabled=*/true);
        if (!err.empty()) throw std::runtime_error(err);

        // Case 6: empty string (catch-all) — accepted per auth_policy_matcher.h.
        err = expect_accepted(
            R"([""])", "empty catch-all", /*enabled=*/true);
        if (!err.empty()) throw std::runtime_error(err);

        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader accepts literal :/* in top-level applies_to",
            true, "", TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader accepts literal :/* in top-level applies_to",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// -----------------------------------------------------------------------------
// ConfigLoader::ValidateProxyAuth — reload-path gate for inline per-proxy
// auth (review P1). HttpServer::Reload strips upstreams[] from its
// validation copy to avoid topology-restart-only noise — that stripping
// also skipped the in-Validate per-proxy auth loop entirely, leaving the
// enforcement-not-yet-wired gate bypassable via reload.
//
// This test calls ValidateProxyAuth directly with a full upstreams[]
// list (simulating what HttpServer::Reload now passes), covering:
//   - proxy.auth.enabled=true must reject
//   - bad inline issuer reference must reject (structural)
//   - bad on_undetermined value must reject (structural)
//   - patterned route_prefix with inline auth must reject
//   - clean disabled inline auth must accept
//   - proxy with no auth block at all must accept
// -----------------------------------------------------------------------------
void TestValidateProxyAuthReloadGate() {
    std::cout << "\n[TEST] ConfigLoader::ValidateProxyAuth reload gate..." << std::endl;

    auto validate_expect_failure = [](const std::string& json,
                                       const std::string& expected_phrase)
        -> std::string {
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(json);
            ConfigLoader::ValidateProxyAuth(cfg);
            return "expected throw containing '" + expected_phrase +
                   "' but accepted";
        } catch (const std::invalid_argument& e) {
            std::string msg = e.what();
            if (msg.find(expected_phrase) == std::string::npos) {
                return "threw but message missing '" + expected_phrase +
                       "'; got: " + msg;
            }
            return "";
        } catch (const std::exception& e) {
            return std::string("unexpected exception type: ") + e.what();
        }
    };

    try {
        // Case 1: enforcement gate — proxy.auth.enabled=true. This is
        // the primary security concern the reviewer flagged: a reload
        // toggling auth on MUST be rejected even when the full Validate
        // runs on a stripped copy.
        std::string err = validate_expect_failure(R"({
            "upstreams": [
                {"name":"x","host":"127.0.0.1","port":80},
                {
                    "name": "api",
                    "host": "127.0.0.1",
                    "port": 8080,
                    "proxy": {
                        "route_prefix": "/api/v1/",
                        "auth": {
                            "enabled": true,
                            "issuers": ["google"]
                        }
                    }
                }
            ],
            "auth": {
                "enabled": false,
                "issuers": {
                    "google": {
                        "issuer_url": "https://issuer.example",
                        "upstream": "x",
                        "mode": "jwt",
                        "algorithms": ["RS256"]
                    }
                }
            }
        })", "proxy.auth.enabled=true rejected");
        if (!err.empty()) throw std::runtime_error("enforcement gate: " + err);

        // Case 2: structural — unknown issuer reference. Staged
        // disabled policy with a typo should fail the reload gate.
        err = validate_expect_failure(R"({
            "upstreams": [
                {"name":"x","host":"127.0.0.1","port":80},
                {
                    "name": "api",
                    "host": "127.0.0.1",
                    "port": 8080,
                    "proxy": {
                        "route_prefix": "/api/v1/",
                        "auth": {
                            "enabled": false,
                            "issuers": ["typo"]
                        }
                    }
                }
            ],
            "auth": {
                "enabled": false,
                "issuers": {
                    "google": {
                        "issuer_url": "https://issuer.example",
                        "upstream": "x",
                        "mode": "jwt",
                        "algorithms": ["RS256"]
                    }
                }
            }
        })", "references unknown issuer");
        if (!err.empty()) throw std::runtime_error("unknown issuer: " + err);

        // Case 3: structural — bad on_undetermined.
        err = validate_expect_failure(R"({
            "upstreams": [
                {"name":"x","host":"127.0.0.1","port":80},
                {
                    "name": "api",
                    "host": "127.0.0.1",
                    "port": 8080,
                    "proxy": {
                        "route_prefix": "/api/v1/",
                        "auth": {
                            "enabled": false,
                            "issuers": ["google"],
                            "on_undetermined": "maybe"
                        }
                    }
                }
            ],
            "auth": {
                "enabled": false,
                "issuers": {
                    "google": {
                        "issuer_url": "https://issuer.example",
                        "upstream": "x",
                        "mode": "jwt",
                        "algorithms": ["RS256"]
                    }
                }
            }
        })", "on_undetermined must be");
        if (!err.empty()) throw std::runtime_error("bad on_undetermined: " + err);

        // Case 4: structural — patterned route_prefix with inline auth.
        err = validate_expect_failure(R"({
            "upstreams": [
                {"name":"x","host":"127.0.0.1","port":80},
                {
                    "name": "api",
                    "host": "127.0.0.1",
                    "port": 8080,
                    "proxy": {
                        "route_prefix": "/api/:v/users",
                        "auth": {
                            "enabled": false,
                            "issuers": ["google"]
                        }
                    }
                }
            ],
            "auth": {
                "enabled": false,
                "issuers": {
                    "google": {
                        "issuer_url": "https://issuer.example",
                        "upstream": "x",
                        "mode": "jwt",
                        "algorithms": ["RS256"]
                    }
                }
            }
        })", "LITERAL prefix");
        if (!err.empty()) throw std::runtime_error("patterned prefix: " + err);

        // Case 5: POSITIVE — clean disabled inline auth passes. Proves
        // the helper doesn't over-reject.
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(R"({
                "upstreams": [
                    {"name":"x","host":"127.0.0.1","port":80},
                    {
                        "name": "api",
                        "host": "127.0.0.1",
                        "port": 8080,
                        "proxy": {
                            "route_prefix": "/api/v1/",
                            "auth": {
                                "enabled": false,
                                "issuers": ["google"]
                            }
                        }
                    }
                ],
                "auth": {
                    "enabled": false,
                    "issuers": {
                        "google": {
                            "issuer_url": "https://issuer.example",
                            "upstream": "x",
                            "mode": "jwt",
                            "algorithms": ["RS256"]
                        }
                    }
                }
            })");
            ConfigLoader::ValidateProxyAuth(cfg);
        } catch (const std::exception& e) {
            throw std::runtime_error(
                std::string("clean disabled inline auth should be ACCEPTED ")
                + "but ValidateProxyAuth threw: " + e.what());
        }

        // Case 6: POSITIVE — proxy with NO auth block at all must pass.
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(R"({
                "upstreams": [
                    {
                        "name": "api",
                        "host": "127.0.0.1",
                        "port": 8080,
                        "proxy": {"route_prefix": "/api/v1/"}
                    }
                ]
            })");
            ConfigLoader::ValidateProxyAuth(cfg);
        } catch (const std::exception& e) {
            throw std::runtime_error(
                std::string("proxy without auth block should be ACCEPTED ")
                + "but ValidateProxyAuth threw: " + e.what());
        }

        // Case 7: POSITIVE — empty upstreams list passes (no-op).
        // Mirrors the reload-copy scenario where ValidateProxyAuth is
        // also called separately by HttpServer::Reload on the REAL
        // upstreams, but in the hypothetical case that it gets called
        // on a stripped copy it should be a harmless no-op.
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(R"({
                "upstreams": [],
                "auth": {"enabled": false}
            })");
            ConfigLoader::ValidateProxyAuth(cfg);
        } catch (const std::exception& e) {
            throw std::runtime_error(
                std::string("empty upstreams should be a no-op for ")
                + "ValidateProxyAuth but threw: " + e.what());
        }

        TestFramework::RecordTest(
            "AuthFoundation: ValidateProxyAuth reload gate",
            true, "", TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "AuthFoundation: ValidateProxyAuth reload gate",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// -----------------------------------------------------------------------------
// ExtractScopes — `scopes` claim as a whitespace-delimited STRING is also
// accepted (review P2). The helper already handled `scope` and `scp` in
// both array + string forms; `scopes` only accepted the array form which
// inconsistently rejected legitimate tokens from providers that serialize
// scopes as a single string under the plural field name.
// -----------------------------------------------------------------------------
void TestExtractScopesScopesAsString() {
    std::cout << "\n[TEST] ExtractScopes handles 'scopes' as string..." << std::endl;
    try {
        // Case 1: `scopes` as a whitespace-separated string.
        nlohmann::json p1 = nlohmann::json::parse(R"({
            "scopes": "read:data write:data admin:all"
        })");
        auto scopes1 = auth::ExtractScopes(p1);
        bool case1 = scopes1.size() == 3 &&
            scopes1[0] == "read:data" &&
            scopes1[1] == "write:data" &&
            scopes1[2] == "admin:all";

        // Case 2: `scopes` as an array still works (regression).
        nlohmann::json p2 = nlohmann::json::parse(R"({
            "scopes": ["read:data", "write:data"]
        })");
        auto scopes2 = auth::ExtractScopes(p2);
        bool case2 = scopes2.size() == 2 &&
            scopes2[0] == "read:data" &&
            scopes2[1] == "write:data";

        // Case 3: `scope` precedence over `scopes` (when both are
        // present — `scope` wins, matches existing behavior).
        nlohmann::json p3 = nlohmann::json::parse(R"({
            "scope": "a b",
            "scopes": "x y z"
        })");
        auto scopes3 = auth::ExtractScopes(p3);
        bool case3 = scopes3.size() == 2 && scopes3[0] == "a" && scopes3[1] == "b";

        // Case 4: `scopes` as a non-string/non-array (e.g. object) —
        // returns empty (graceful degradation).
        nlohmann::json p4 = nlohmann::json::parse(R"({
            "scopes": {"something": "weird"}
        })");
        auto scopes4 = auth::ExtractScopes(p4);
        bool case4 = scopes4.empty();

        bool pass = case1 && case2 && case3 && case4;
        std::string err;
        if (!case1) err = "string form of scopes returned " +
            std::to_string(scopes1.size()) + " tokens (expected 3)";
        else if (!case2) err = "array form of scopes broke";
        else if (!case3) err = "scope-precedence-over-scopes broke";
        else if (!case4) err = "non-string/non-array scopes should return empty";

        TestFramework::RecordTest(
            "AuthFoundation: ExtractScopes handles scopes-as-string",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "AuthFoundation: ExtractScopes handles scopes-as-string",
            false, std::string("unexpected exception: ") + e.what(),
            TestFramework::TestCategory::OTHER);
    }
}

// -----------------------------------------------------------------------------
// ValidateProxyAuth — runs the issuer.upstream cross-reference check
// (review P3 #1). The reload path's stripped-copy Validate skips this
// because reload_copy=true disables cross-refs; ValidateProxyAuth now
// runs it explicitly on the real upstreams so reload and startup enforce
// this equally.
// -----------------------------------------------------------------------------
void TestValidateProxyAuthIssuerUpstreamCrossRef() {
    std::cout << "\n[TEST] ValidateProxyAuth rejects unknown issuer.upstream..." << std::endl;
    try {
        // Case 1: issuer.upstream points at a non-existent pool.
        const std::string bad = R"({
            "upstreams": [{"name":"x","host":"127.0.0.1","port":80}],
            "auth": {
                "enabled": false,
                "issuers": {
                    "google": {
                        "issuer_url": "https://issuer.example",
                        "upstream": "typo_not_a_real_upstream",
                        "mode": "jwt",
                        "algorithms": ["RS256"]
                    }
                }
            }
        })";
        bool threw = false;
        std::string err_msg;
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(bad);
            ConfigLoader::ValidateProxyAuth(cfg);
        } catch (const std::invalid_argument& e) {
            threw = true;
            err_msg = e.what();
        }
        bool good_msg = threw &&
            err_msg.find("references unknown upstream") != std::string::npos &&
            err_msg.find("typo_not_a_real_upstream") != std::string::npos;

        // Case 2: missing upstream field entirely — also rejected as
        // structural error.
        const std::string missing = R"({
            "upstreams": [{"name":"x","host":"127.0.0.1","port":80}],
            "auth": {
                "enabled": false,
                "issuers": {
                    "google": {
                        "issuer_url": "https://issuer.example",
                        "mode": "jwt",
                        "algorithms": ["RS256"]
                    }
                }
            }
        })";
        bool missing_threw = false;
        std::string missing_err;
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(missing);
            ConfigLoader::ValidateProxyAuth(cfg);
        } catch (const std::invalid_argument& e) {
            missing_threw = true;
            missing_err = e.what();
        }
        bool missing_msg = missing_threw &&
            missing_err.find("upstream is required") != std::string::npos;

        // Case 3: POSITIVE — valid cross-ref passes.
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(R"({
                "upstreams": [{"name":"x","host":"127.0.0.1","port":80}],
                "auth": {
                    "enabled": false,
                    "issuers": {
                        "google": {
                            "issuer_url": "https://issuer.example",
                            "upstream": "x",
                            "mode": "jwt",
                            "algorithms": ["RS256"]
                        }
                    }
                }
            })");
            ConfigLoader::ValidateProxyAuth(cfg);
        } catch (const std::exception& e) {
            throw std::runtime_error(
                std::string("valid upstream ref should be ACCEPTED but ")
                + "ValidateProxyAuth threw: " + e.what());
        }

        bool pass = threw && good_msg && missing_threw && missing_msg;
        std::string err;
        if (!threw) {
            err = "unknown-upstream case should reject but accepted";
        } else if (!good_msg) {
            err = "rejected but wrong message; got: " + err_msg;
        } else if (!missing_threw) {
            err = "missing-upstream case should reject but accepted";
        } else if (!missing_msg) {
            err = "missing case rejected but wrong message; got: " + missing_err;
        }
        TestFramework::RecordTest(
            "AuthFoundation: ValidateProxyAuth rejects unknown issuer.upstream",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "AuthFoundation: ValidateProxyAuth rejects unknown issuer.upstream",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// -----------------------------------------------------------------------------
// LoadHmacKeyFromEnv — raw env keys containing middle '%3d' or '=' must
// be preserved verbatim (review P3 #2). jwt::base::trim uses find() so
// it truncates at the FIRST occurrence of the padding sequence;
// previously this mis-decoded raw keys with embedded padding as 32-byte
// base64 keys. The fix strips padding only at the tail.
// -----------------------------------------------------------------------------
void TestLoadHmacKeyFromEnvPreservesMiddlePadding() {
    std::cout << "\n[TEST] LoadHmacKeyFromEnv preserves middle %3d / = chars..." << std::endl;

    const char* kVarName = "REACTOR_TEST_AUTH_MID_PAD_KEY";
    auto restore_env = [](const char* name, const char* prev, bool had) {
        if (had) setenv(name, prev, 1);
        else unsetenv(name);
    };

    const char* prev = std::getenv(kVarName);
    std::string saved = prev ? prev : "";
    bool had_original = (prev != nullptr);

    try {
        // Case 1: raw env key with "%3d" in the MIDDLE. Under the
        // previous jwt::base::trim behavior this would be truncated at
        // the first '%3d', leaving a short prefix that might decode to
        // 32 bytes → silent HMAC key change. Post-fix: the middle '%3d'
        // is preserved and the raw string is used verbatim (falls
        // through to raw-bytes after base64 decode fails).
        const std::string tricky = "AAAA%3dBBBBCCCCDDDDEEEEFFFF";
        setenv(kVarName, tricky.c_str(), 1);
        std::string loaded1 = auth::LoadHmacKeyFromEnv(kVarName);
        // The string is not a valid 32-byte base64/base64url decode, so
        // it falls through to raw-bytes and is returned verbatim. The
        // CRITICAL assertion: the returned bytes are the full tricky
        // string, NOT a truncated substring.
        bool case1 = loaded1 == tricky;

        // Case 2: raw env key with literal '=' in the middle — similar
        // concern (the loop at the top strips TRAILING '=' only; middle
        // '=' should remain intact).
        const std::string tricky_eq = "AAAA=BBBBCCCCDDDDEEEEFFFF";
        setenv(kVarName, tricky_eq.c_str(), 1);
        std::string loaded2 = auth::LoadHmacKeyFromEnv(kVarName);
        bool case2 = loaded2 == tricky_eq;

        // Case 3: REGRESSION — valid base64url still decodes to 32 bytes
        // when the operator provides that form. Uses jwt::base::encode
        // so the encoding is exactly what the decoder expects.
        std::string raw_key(32, 'K');
        std::string encoded =
            jwt::base::encode<jwt::alphabet::base64url>(raw_key);
        // Strip standard '=' padding (operator-typical form).
        while (!encoded.empty() && encoded.back() == '=') encoded.pop_back();
        setenv(kVarName, encoded.c_str(), 1);
        std::string loaded3 = auth::LoadHmacKeyFromEnv(kVarName);
        bool case3 = loaded3.size() == 32 && loaded3 == raw_key;

        // Case 4: raw key with TRAILING '%3d' — should still strip
        // (that's the legitimate padding case). The remainder
        // ("AAAABBBB") should decode to 6 bytes via base64url, but that
        // doesn't equal 32 so falls to raw. Returned value must equal
        // the original string (with padding stripped OR kept — test
        // accepts either; the PRIMARY contract is "not mid-truncated").
        const std::string trailing = "AAAABBBB%3d";
        setenv(kVarName, trailing.c_str(), 1);
        std::string loaded4 = auth::LoadHmacKeyFromEnv(kVarName);
        // Must be either the full string OR the stripped-tail version.
        // Must NOT be empty and must NOT be a middle-truncated variant
        // (i.e. if we see just "AAAABBBB" that's fine; if we see
        // anything shorter that's a bug).
        bool case4 = (loaded4 == trailing) || (loaded4 == "AAAABBBB");

        restore_env(kVarName, saved.c_str(), had_original);

        bool pass = case1 && case2 && case3 && case4;
        std::string err;
        if (!case1) err = "middle '%3d' caused truncation — got '" +
            loaded1 + "' (expected '" + tricky + "')";
        else if (!case2) err = "middle '=' caused truncation — got '" +
            loaded2 + "' (expected '" + tricky_eq + "')";
        else if (!case3) err = "valid base64url decode regression — got size=" +
            std::to_string(loaded3.size());
        else if (!case4) err = "trailing '%3d' case produced unexpected "
            "result '" + loaded4 + "'";

        TestFramework::RecordTest(
            "AuthFoundation: LoadHmacKeyFromEnv preserves middle padding",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        restore_env(kVarName, saved.c_str(), had_original);
        TestFramework::RecordTest(
            "AuthFoundation: LoadHmacKeyFromEnv preserves middle padding",
            false, std::string("unexpected exception: ") + e.what(),
            TestFramework::TestCategory::OTHER);
    }
}

// -----------------------------------------------------------------------------
// ParseStrictInt — JSON null is rejected (review P3). Previously null was
// treated as "field absent" and returned the default. A templated config
// that renders `"key": null` (missing variable, unrendered) would silently
// get default values for security-sensitive knobs. Strict typing means
// null fails the same way `true` or `1.9` would.
// -----------------------------------------------------------------------------
void TestParseStrictIntRejectsNull() {
    std::cout << "\n[TEST] ParseStrictInt rejects JSON null..." << std::endl;
    try {
        // Exercised indirectly via ConfigLoader::LoadFromString parsing
        // an auth issuer with a null-valued integer field.
        const std::string with_null = R"({
            "upstreams": [{"name":"x","host":"127.0.0.1","port":80}],
            "auth": {
                "enabled": false,
                "issuers": {
                    "ours": {
                        "issuer_url": "https://issuer.example",
                        "upstream": "x",
                        "mode": "jwt",
                        "algorithms": ["RS256"],
                        "leeway_sec": null
                    }
                }
            }
        })";
        bool threw = false;
        std::string err_msg;
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(with_null);
        } catch (const std::invalid_argument& e) {
            threw = true;
            err_msg = e.what();
        }
        bool good = threw &&
            err_msg.find("leeway_sec") != std::string::npos &&
            err_msg.find("must be an integer") != std::string::npos;

        bool pass = threw && good;
        std::string err;
        if (!threw) {
            err = "expected null value to reject but LoadFromString accepted";
        } else if (!good) {
            err = "threw but message missing 'leeway_sec' or 'must be an "
                  "integer'; got: " + err_msg;
        }
        TestFramework::RecordTest(
            "AuthFoundation: ParseStrictInt rejects JSON null",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "AuthFoundation: ParseStrictInt rejects JSON null",
            false, std::string("unexpected exception: ") + e.what(),
            TestFramework::TestCategory::OTHER);
    }
}

// -----------------------------------------------------------------------------
// ConfigLoader::Validate — introspection issuers require client_id AND
// client_secret_env (review P2 #2). RFC 7662 basic/body auth both need
// these; without them introspection calls fail at runtime. Reject now.
// -----------------------------------------------------------------------------
void TestConfigLoaderRequiresIntrospectionCredentials() {
    std::cout << "\n[TEST] ConfigLoader requires introspection credentials..." << std::endl;
    auto validate_expect_failure = [](const std::string& json,
                                       const std::string& expected_phrase)
        -> std::string {
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(json);
            ConfigLoader::Validate(cfg);
            return "expected throw containing '" + expected_phrase +
                   "' but accepted";
        } catch (const std::invalid_argument& e) {
            std::string msg = e.what();
            if (msg.find(expected_phrase) == std::string::npos) {
                return "threw but message missing '" + expected_phrase +
                       "'; got: " + msg;
            }
            return "";
        } catch (const std::exception& e) {
            return std::string("unexpected exception type: ") + e.what();
        }
    };

    try {
        // Case 1: missing client_id.
        std::string err = validate_expect_failure(R"({
            "upstreams": [{"name":"x","host":"127.0.0.1","port":80}],
            "auth": {
                "enabled": false,
                "issuers": {
                    "ours": {
                        "issuer_url": "https://issuer.example",
                        "upstream": "x",
                        "mode": "introspection",
                        "introspection": {
                            "endpoint": "https://issuer.example/introspect",
                            "client_secret_env": "E"
                        }
                    }
                }
            }
        })", "client_id is required");
        if (!err.empty()) throw std::runtime_error("missing client_id: " + err);

        // Case 2: missing client_secret_env.
        err = validate_expect_failure(R"({
            "upstreams": [{"name":"x","host":"127.0.0.1","port":80}],
            "auth": {
                "enabled": false,
                "issuers": {
                    "ours": {
                        "issuer_url": "https://issuer.example",
                        "upstream": "x",
                        "mode": "introspection",
                        "introspection": {
                            "endpoint": "https://issuer.example/introspect",
                            "client_id": "c"
                        }
                    }
                }
            }
        })", "client_secret_env is required");
        if (!err.empty()) throw std::runtime_error("missing client_secret_env: " + err);

        // POSITIVE: with both credentials present, validation passes.
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(R"({
                "upstreams": [{"name":"x","host":"127.0.0.1","port":80}],
                "auth": {
                    "enabled": false,
                    "issuers": {
                        "ours": {
                            "issuer_url": "https://issuer.example",
                            "upstream": "x",
                            "mode": "introspection",
                            "introspection": {
                                "endpoint": "https://issuer.example/introspect",
                                "client_id": "c",
                                "client_secret_env": "E"
                            }
                        }
                    }
                }
            })");
            ConfigLoader::Validate(cfg);
        } catch (const std::exception& e) {
            throw std::runtime_error(
                std::string("introspection with credentials should pass but ")
                + "threw: " + e.what());
        }

        // POSITIVE: jwt-mode issuer without credentials still valid.
        // (credentials are REQUIRED only for mode="introspection")
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(R"({
                "upstreams": [{"name":"x","host":"127.0.0.1","port":80}],
                "auth": {
                    "enabled": false,
                    "issuers": {
                        "ours": {
                            "issuer_url": "https://issuer.example",
                            "upstream": "x",
                            "mode": "jwt",
                            "algorithms": ["RS256"]
                        }
                    }
                }
            })");
            ConfigLoader::Validate(cfg);
        } catch (const std::exception& e) {
            throw std::runtime_error(
                std::string("jwt mode without introspection creds should ")
                + "pass but threw: " + e.what());
        }

        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader requires introspection credentials",
            true, "", TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader requires introspection credentials",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// -----------------------------------------------------------------------------
// ConfigLoader::LoadFromString — upstream/pool/proxy integer fields parsed
// strictly (review P2 #1). Pre-existing issue: nlohmann's json::value<int>()
// silently coerces booleans, floats, and oversized unsigned values. For
// routing-critical fields (port, timeouts, retry counts), that would let
// a typo'd config silently retarget traffic or rewrite behavior.
// -----------------------------------------------------------------------------
void TestConfigLoaderStrictUpstreamIntegers() {
    std::cout << "\n[TEST] ConfigLoader strict upstream integer parsing..." << std::endl;
    auto load_expect_failure = [](const std::string& json,
                                   const std::string& expected_phrase)
        -> std::string {
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(json);
            return "expected throw containing '" + expected_phrase +
                   "' but accepted";
        } catch (const std::invalid_argument& e) {
            std::string msg = e.what();
            if (msg.find(expected_phrase) == std::string::npos) {
                return "threw but message missing '" + expected_phrase +
                       "'; got: " + msg;
            }
            return "";
        } catch (const std::exception& e) {
            return std::string("unexpected exception type: ") + e.what();
        }
    };

    try {
        // Case 1: upstream.port as boolean (the reviewer's true→1 example).
        std::string err = load_expect_failure(R"({
            "upstreams": [{"name":"x","host":"127.0.0.1","port":true}]
        })", "must be an integer");
        if (!err.empty()) throw std::runtime_error("port as bool: " + err);

        // Case 2: upstream.port as float.
        err = load_expect_failure(R"({
            "upstreams": [{"name":"x","host":"127.0.0.1","port":80.5}]
        })", "must be an integer");
        if (!err.empty()) throw std::runtime_error("port as float: " + err);

        // Case 3: pool.max_connections oversized (reviewer's 4294967297 → 1 example).
        err = load_expect_failure(R"({
            "upstreams": [{"name":"x","host":"127.0.0.1","port":80,
                           "pool":{"max_connections":4294967297}}]
        })", "out of int range");
        if (!err.empty()) throw std::runtime_error("max_connections oversized: " + err);

        // Case 4: proxy.response_timeout_ms as bool.
        err = load_expect_failure(R"({
            "upstreams": [{"name":"x","host":"127.0.0.1","port":80,
                           "proxy":{"response_timeout_ms":true}}]
        })", "must be an integer");
        if (!err.empty()) throw std::runtime_error("response_timeout_ms as bool: " + err);

        // Case 5: proxy.retry.max_retries as bool.
        err = load_expect_failure(R"({
            "upstreams": [{"name":"x","host":"127.0.0.1","port":80,
                           "proxy":{"retry":{"max_retries":true}}}]
        })", "must be an integer");
        if (!err.empty()) throw std::runtime_error("max_retries as bool: " + err);

        // POSITIVE: valid config with normal integers parses fine.
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(R"({
                "upstreams": [{
                    "name":"x",
                    "host":"127.0.0.1",
                    "port":8080,
                    "pool":{"max_connections":128,"connect_timeout_ms":3000},
                    "proxy":{"response_timeout_ms":10000,
                             "retry":{"max_retries":2}}
                }]
            })");
            bool all_set =
                cfg.upstreams.size() == 1 &&
                cfg.upstreams[0].port == 8080 &&
                cfg.upstreams[0].pool.max_connections == 128 &&
                cfg.upstreams[0].pool.connect_timeout_ms == 3000 &&
                cfg.upstreams[0].proxy.response_timeout_ms == 10000 &&
                cfg.upstreams[0].proxy.retry.max_retries == 2;
            if (!all_set) {
                throw std::runtime_error(
                    "valid integers parsed but values didn't land in struct");
            }
        } catch (const std::runtime_error& e) {
            throw;
        } catch (const std::exception& e) {
            throw std::runtime_error(
                std::string("valid integer config rejected by strict parser: ")
                + e.what());
        }

        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader strict upstream integer parsing",
            true, "", TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "AuthFoundation: ConfigLoader strict upstream integer parsing",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

inline void RunAllTests() {
    std::cout << "\n===== Auth Foundation Tests =====" << std::endl;
    TestHasherBasicDeterminism();
    TestLoadHmacKeyFromEnvDoesNotThrow();
    TestLoadHmacKeyFromEnvAutoDetect();
    TestLoadHmacKeyFromEnvStandardBase64();
    TestExtractScopesScpAsString();
    TestConfigLoaderAuthRoundTrip();
    TestConfigLoaderAuthValidation();
    TestConfigLoaderRejectsAuthEnabled();
    TestConfigLoaderRejectsProxyAuthEnabled();
    TestConfigLoaderRejectsPlaintextIdpEndpoints();
    TestPopulateFromPayloadOptionalIssSub();
    TestConfigLoaderUpstreamCrossRefReloadSafe();
    TestConfigLoaderRejectsOutOfRangeIntegers();
    TestConfigLoaderRejectsReservedForwardHeaders();
    TestPopulateFromPayloadClearsStaleFields();
    TestConfigLoaderValidatesDisabledInlineAuth();
    TestConfigLoaderRoundTripsAuthOnlyProxy();
    TestConfigLoaderDisabledTopLevelPoliciesDoNotCollide();
    TestConfigLoaderRejectsInlineAuthAppliesTo();
    TestConfigLoaderRejectsProxyConnectionInAuthForward();
    TestConfigLoaderRejectsEnabledPolicyWithoutAppliesTo();
    TestConfigLoaderValidatesIntrospectionKnobs();
    TestConfigLoaderRejectsPatternedInlineAuthPrefix();
    TestConfigLoaderRequiresIssuerUpstream();
    TestConfigLoaderValidatesHeaderNameTchar();
    TestConfigLoaderAcceptsLiteralPatternCharsInAppliesTo();
    TestValidateProxyAuthReloadGate();
    TestExtractScopesScopesAsString();
    TestValidateProxyAuthIssuerUpstreamCrossRef();
    TestLoadHmacKeyFromEnvPreservesMiddlePadding();
    TestParseStrictIntRejectsNull();
    TestConfigLoaderRequiresIntrospectionCredentials();
    TestConfigLoaderStrictUpstreamIntegers();
    TestConfigLoaderClaimHeaderCollision();
}

}  // namespace AuthFoundationTests
