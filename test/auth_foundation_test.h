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
#include "jwt-cpp/base.h"

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
    const char* kVarName = "REACTOR_TEST_AUTH_BAD_KEY";
    auto restore_env = [](const char* name, const char* prev) {
        if (prev) setenv(name, prev, 1);
        else unsetenv(name);
    };

    try {
        // Case 1: illegal-char base64url (@ is not a base64url alphabet char).
        // This is a syntactically invalid input that jwt::base::decode throws on.
        const char* prev = std::getenv(kVarName);
        std::string saved = prev ? prev : "";
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

        restore_env(kVarName, saved.empty() ? nullptr : saved.c_str());

        bool pass = case1_pass && case2_pass;
        std::string err;
        if (!case1_pass) err = case1_err;
        else if (!case2_pass) err = case2_err;

        TestFramework::RecordTest(
            "AuthFoundation: LoadHmacKeyFromEnv contains jwt-cpp exceptions",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        restore_env(kVarName, std::getenv(kVarName));
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

    try {
        // Derive the correct base64url encoding of 32 bytes of 0x41 via
        // jwt-cpp's public helper — avoids a hand-computed constant that
        // would drift if the encoder ever changed or get mis-hand-counted.
        const std::string raw32(32, 'A');  // 32 bytes of 0x41
        std::string base64url_of_32_As =
            jwt::base::encode<jwt::alphabet::base64url>(raw32);
        // Strip any trailing '=' padding chars — LoadHmacKeyFromEnv's
        // auto-detect supports both padded and no-padding forms but the
        // contract is "exactly 32 bytes after decode" regardless.
        while (!base64url_of_32_As.empty() &&
               base64url_of_32_As.back() == '=') {
            base64url_of_32_As.pop_back();
        }

        const char* prev = std::getenv(kVarName);
        std::string saved = prev ? prev : "";
        setenv(kVarName, base64url_of_32_As.c_str(), 1);
        std::string decoded_key = auth::LoadHmacKeyFromEnv(kVarName);

        // Contract: must be interpreted as base64url → 32 bytes, NOT raw 43.
        bool decoded_to_32 = decoded_key.size() == 32;
        bool all_As = decoded_to_32 &&
                       decoded_key.find_first_not_of('A') == std::string::npos;

        // Also check raw fallback: a 16-char string that decodes to 12 bytes
        // (not 32) should fall back to raw.
        setenv(kVarName, "AAAAAAAAAAAAAAAA", 1);  // 16 chars base64url -> 12 bytes
        std::string raw_fallback = auth::LoadHmacKeyFromEnv(kVarName);
        bool raw_ok = raw_fallback == "AAAAAAAAAAAAAAAA";

        restore_env(kVarName, saved.empty() ? nullptr : saved.c_str());

        bool pass = all_As && raw_ok;
        std::string err;
        if (!decoded_to_32) {
            err = "base64url 32-byte input not auto-detected; got size=" +
                  std::to_string(decoded_key.size());
        } else if (!all_As) {
            err = "base64url decode produced wrong bytes";
        } else if (!raw_ok) {
            err = "16-char input (decodes to 12 bytes) should fall to raw, got '" +
                  raw_fallback + "'";
        }

        TestFramework::RecordTest(
            "AuthFoundation: LoadHmacKeyFromEnv base64url auto-detect",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        restore_env(kVarName, std::getenv(kVarName));
        TestFramework::RecordTest(
            "AuthFoundation: LoadHmacKeyFromEnv base64url auto-detect",
            false, std::string("unexpected exception: ") + e.what(),
            TestFramework::TestCategory::OTHER);
    }
}

inline void RunAllTests() {
    std::cout << "\n===== Auth Foundation Tests =====" << std::endl;
    TestHasherBasicDeterminism();
    TestLoadHmacKeyFromEnvDoesNotThrow();
    TestLoadHmacKeyFromEnvAutoDetect();
}

}  // namespace AuthFoundationTests
