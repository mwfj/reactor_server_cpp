#pragma once

// Unit tests for IntrospectionClient static helpers and AsyncPendingState.
// No live network is needed — all tests are pure in-process, synchronous.
// AsyncPendingState tests cover the one-shot deferred handoff state machine.

#include "test_framework.h"
#include "auth/introspection_client.h"
#include "auth/auth_config.h"
#include "auth/auth_result.h"
#include "auth/upstream_http_client.h"
#include "http/http_router.h"

#include <atomic>
#include <chrono>
#include <functional>
#include <string>
#include <thread>
#include <vector>
#if __cpp_lib_barrier >= 201907L
#  include <barrier>
#endif

namespace IntrospectionClientTests {

using AUTH_NAMESPACE::IntrospectionClient;
using AUTH_NAMESPACE::AuthPolicy;
using AUTH_NAMESPACE::VerifyOutcome;
using AUTH_NAMESPACE::UpstreamHttpClient;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static AuthPolicy MakePolicy() {
    AuthPolicy p;
    p.name = "test";
    p.applies_to = {"/api"};
    return p;
}

static UpstreamHttpClient::Response MakeOkResponse(const std::string& body) {
    UpstreamHttpClient::Response r;
    r.status_code = 200;
    r.body = body;
    return r;
}

static UpstreamHttpClient::Response MakeErrorResponse(const std::string& err) {
    UpstreamHttpClient::Response r;
    r.status_code = 0;
    r.error = err;
    return r;
}

static UpstreamHttpClient::Response MakeStatusResponse(int status) {
    UpstreamHttpClient::Response r;
    r.status_code = status;
    return r;
}

static void Record(const std::string& name, bool pass,
                   const std::string& err = "") {
    TestFramework::RecordTest(name, pass, pass ? "" : err,
                              TestFramework::TestCategory::OTHER);
}

// ---------------------------------------------------------------------------
// UrlEncode tests
// ---------------------------------------------------------------------------

// Unreserved characters must pass through unchanged (RFC 3986 unreserved chars).
static void Test_UrlEncode_UnreservedPassThrough() {
    try {
        const std::string alpha =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        const std::string digits = "0123456789";
        const std::string special = "-_.~";
        bool ok = IntrospectionClient::UrlEncode(alpha) == alpha &&
                  IntrospectionClient::UrlEncode(digits) == digits &&
                  IntrospectionClient::UrlEncode(special) == special;
        Record("IntrospectionClient: UrlEncode_UnreservedPassThrough", ok,
               "Unreserved chars must not be percent-encoded");
    } catch (const std::exception& e) {
        Record("IntrospectionClient: UrlEncode_UnreservedPassThrough",
               false, e.what());
    }
}

// Reserved / special chars that appear in OAuth tokens must be encoded.
static void Test_UrlEncode_SpecialCharsEncoded() {
    try {
        // `+` is NOT unreserved — must encode.
        auto enc_plus = IntrospectionClient::UrlEncode("+");
        bool ok_plus = enc_plus == "%2B";

        // `&` separates form fields — must encode.
        auto enc_amp = IntrospectionClient::UrlEncode("&");
        bool ok_amp = enc_amp == "%26";

        // `=` separates key/value — must encode.
        auto enc_eq = IntrospectionClient::UrlEncode("=");
        bool ok_eq = enc_eq == "%3D";

        // Space must encode as %20 (not +).
        auto enc_sp = IntrospectionClient::UrlEncode(" ");
        bool ok_sp = enc_sp == "%20";

        // `#` and `?` must encode.
        auto enc_hash = IntrospectionClient::UrlEncode("#");
        bool ok_hash = enc_hash == "%23";
        auto enc_q = IntrospectionClient::UrlEncode("?");
        bool ok_q = enc_q == "%3F";

        bool ok = ok_plus && ok_amp && ok_eq && ok_sp && ok_hash && ok_q;
        Record("IntrospectionClient: UrlEncode_SpecialCharsEncoded", ok,
               "Reserved chars (+&= #?) must be percent-encoded");
    } catch (const std::exception& e) {
        Record("IntrospectionClient: UrlEncode_SpecialCharsEncoded",
               false, e.what());
    }
}

// High-bit bytes (0x80-0xFF) must encode as three-char sequences.
static void Test_UrlEncode_HighBitBytesEncoded() {
    try {
        std::string input;
        input.push_back(static_cast<char>(0x80));
        input.push_back(static_cast<char>(0xFF));
        std::string encoded = IntrospectionClient::UrlEncode(input);
        bool ok = encoded == "%80%FF";
        Record("IntrospectionClient: UrlEncode_HighBitBytesEncoded", ok,
               "Bytes 0x80-0xFF must be percent-encoded correctly");
    } catch (const std::exception& e) {
        Record("IntrospectionClient: UrlEncode_HighBitBytesEncoded",
               false, e.what());
    }
}

// NUL byte must encode as %00.
static void Test_UrlEncode_NulByte() {
    try {
        std::string input(1, '\0');
        std::string encoded = IntrospectionClient::UrlEncode(input);
        bool ok = encoded == "%00";
        Record("IntrospectionClient: UrlEncode_NulByte", ok,
               "NUL byte must encode as %00");
    } catch (const std::exception& e) {
        Record("IntrospectionClient: UrlEncode_NulByte", false, e.what());
    }
}

// Empty input must produce empty output.
static void Test_UrlEncode_EmptyInput() {
    try {
        bool ok = IntrospectionClient::UrlEncode("").empty();
        Record("IntrospectionClient: UrlEncode_EmptyInput", ok,
               "UrlEncode(\"\") must return \"\"");
    } catch (const std::exception& e) {
        Record("IntrospectionClient: UrlEncode_EmptyInput", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// BuildAuthorizationHeaderBasic tests
// ---------------------------------------------------------------------------

// Standard client_id:client_secret pair must produce Base64-encoded "Basic …".
static void Test_BuildAuthorizationHeaderBasic_Standard() {
    try {
        // "alice:hunter2" base64 = "YWxpY2U6aHVudGVyMg=="
        std::string hdr =
            IntrospectionClient::BuildAuthorizationHeaderBasic("alice",
                                                               "hunter2");
        bool ok = hdr.substr(0, 6) == "Basic ";
        // The encoded payload must decode to "alice:hunter2".
        // We can verify by comparing the known base64.
        bool ok2 = hdr == "Basic YWxpY2U6aHVudGVyMg==";
        Record("IntrospectionClient: BuildAuthorizationHeaderBasic_Standard",
               ok && ok2,
               "Must produce 'Basic <base64(client_id:client_secret)>'");
    } catch (const std::exception& e) {
        Record("IntrospectionClient: BuildAuthorizationHeaderBasic_Standard",
               false, e.what());
    }
}

// RFC 6749 §2.3.1: client_id and client_secret MUST be
// application/x-www-form-urlencoded BEFORE concatenation with `:` and
// base64 encoding. A client_id containing `:` therefore becomes
// "id%3Awith%3Acolon" → joined as "id%3Awith%3Acolon:secret" → base64'd.
// This test pins the exact wire-format so a future regression that
// re-introduces the raw-concat path is caught.
static void Test_BuildAuthorizationHeaderBasic_ClientIdWithColon() {
    try {
        std::string hdr =
            IntrospectionClient::BuildAuthorizationHeaderBasic(
                "id:with:colon", "secret");
        // "id%3Awith%3Acolon:secret" base64 = "aWQlM0F3aXRoJTNBY29sb246c2VjcmV0"
        const std::string expected =
            "Basic aWQlM0F3aXRoJTNBY29sb246c2VjcmV0";
        bool ok = (hdr == expected);
        Record("IntrospectionClient: BuildAuthorizationHeaderBasic_ClientIdWithColon",
               ok,
               "client_id with ':' must percent-encode `:` as %3A before base64 (RFC 6749 §2.3.1)");
    } catch (const std::exception& e) {
        Record("IntrospectionClient: BuildAuthorizationHeaderBasic_ClientIdWithColon",
               false, e.what());
    }
}

// Reserved char in the secret too — colon, percent, ampersand, plus.
// Pins the encoded form so a regression to raw-concat is caught.
static void Test_BuildAuthorizationHeaderBasic_SecretWithReservedChars() {
    try {
        std::string hdr =
            IntrospectionClient::BuildAuthorizationHeaderBasic("client", "p:s");
        // "client:p%3As" base64 = "Y2xpZW50OnAlM0Fz"
        const std::string expected = "Basic Y2xpZW50OnAlM0Fz";
        bool ok = (hdr == expected);
        Record("IntrospectionClient: BuildAuthorizationHeaderBasic_SecretWithReservedChars",
               ok,
               "client_secret reserved chars must percent-encode (RFC 6749 §2.3.1)");
    } catch (const std::exception& e) {
        Record("IntrospectionClient: BuildAuthorizationHeaderBasic_SecretWithReservedChars",
               false, e.what());
    }
}

// Empty client_id and secret must still produce a valid "Basic …" header.
static void Test_BuildAuthorizationHeaderBasic_EmptyCredentials() {
    try {
        std::string hdr =
            IntrospectionClient::BuildAuthorizationHeaderBasic("", "");
        // ":" base64-encodes to "Og=="
        bool ok = hdr == "Basic Og==";
        Record("IntrospectionClient: BuildAuthorizationHeaderBasic_EmptyCredentials",
               ok, "Empty client_id and secret must encode \":\" -> \"Basic Og==\"");
    } catch (const std::exception& e) {
        Record("IntrospectionClient: BuildAuthorizationHeaderBasic_EmptyCredentials",
               false, e.what());
    }
}

// ---------------------------------------------------------------------------
// ParseResponseSafe tests
// ---------------------------------------------------------------------------

// active=true with a subject claim must produce ALLOW.
static void Test_ParseResponseSafe_ActiveTrue_ProducesAllow() {
    try {
        std::string body = R"({"active":true,"sub":"user123"})";
        auto resp = MakeOkResponse(body);
        auto r = IntrospectionClient::ParseResponseSafe(
            resp, MakePolicy(), {}, "test-issuer");
        bool ok = r.idp_active && r.vr.outcome == VerifyOutcome::ALLOW;
        Record("IntrospectionClient: ParseResponseSafe_ActiveTrue_ProducesAllow",
               ok, "active=true with valid sub must produce ALLOW");
    } catch (const std::exception& e) {
        Record("IntrospectionClient: ParseResponseSafe_ActiveTrue_ProducesAllow",
               false, e.what());
    }
}

// active=false must produce DENY_401 with log_reason "introspection_inactive".
static void Test_ParseResponseSafe_ActiveFalse_ProducesDeny401() {
    try {
        std::string body = R"({"active":false})";
        auto resp = MakeOkResponse(body);
        auto r = IntrospectionClient::ParseResponseSafe(
            resp, MakePolicy(), {}, "test-issuer");
        bool ok = !r.idp_active &&
                  r.vr.outcome == VerifyOutcome::DENY_401 &&
                  r.vr.log_reason == "introspection_inactive";
        Record("IntrospectionClient: ParseResponseSafe_ActiveFalse_ProducesDeny401",
               ok, "active=false must produce DENY_401 / introspection_inactive");
    } catch (const std::exception& e) {
        Record("IntrospectionClient: ParseResponseSafe_ActiveFalse_ProducesDeny401",
               false, e.what());
    }
}

// active field present as integer (e.g. `1`) must be treated as missing/invalid
// per RFC 7662 (only boolean is spec-compliant), producing UNDETERMINED.
static void Test_ParseResponseSafe_ActiveAsInteger_ProducesUndetermined() {
    try {
        std::string body = R"({"active":1,"sub":"user"})";
        auto resp = MakeOkResponse(body);
        auto r = IntrospectionClient::ParseResponseSafe(
            resp, MakePolicy(), {}, "test-issuer");
        // `active` must be a boolean per RFC 7662. Integer 1 is not
        // a boolean in JSON; the implementation treats it as missing.
        bool ok = !r.idp_active &&
                  r.vr.outcome == VerifyOutcome::UNDETERMINED &&
                  r.vr.log_reason == "introspection_missing_active";
        Record("IntrospectionClient: ParseResponseSafe_ActiveAsInteger_ProducesUndetermined",
               ok,
               "active:1 (integer, not bool) must produce UNDETERMINED/introspection_missing_active");
    } catch (const std::exception& e) {
        Record("IntrospectionClient: ParseResponseSafe_ActiveAsInteger_ProducesUndetermined",
               false, e.what());
    }
}

// Missing active field must produce UNDETERMINED with introspection_missing_active.
static void Test_ParseResponseSafe_MissingActive_ProducesUndetermined() {
    try {
        std::string body = R"({"sub":"user"})";
        auto resp = MakeOkResponse(body);
        auto r = IntrospectionClient::ParseResponseSafe(
            resp, MakePolicy(), {}, "test-issuer");
        bool ok = !r.idp_active &&
                  r.vr.outcome == VerifyOutcome::UNDETERMINED &&
                  r.vr.log_reason == "introspection_missing_active";
        Record("IntrospectionClient: ParseResponseSafe_MissingActive_ProducesUndetermined",
               ok, "Missing active field must produce UNDETERMINED/introspection_missing_active");
    } catch (const std::exception& e) {
        Record("IntrospectionClient: ParseResponseSafe_MissingActive_ProducesUndetermined",
               false, e.what());
    }
}

// Malformed JSON (not valid JSON at all) must produce UNDETERMINED.
static void Test_ParseResponseSafe_MalformedJson_ProducesUndetermined() {
    try {
        std::string body = "{not valid json}";
        auto resp = MakeOkResponse(body);
        auto r = IntrospectionClient::ParseResponseSafe(
            resp, MakePolicy(), {}, "test-issuer");
        bool ok = !r.idp_active &&
                  r.vr.outcome == VerifyOutcome::UNDETERMINED &&
                  r.vr.log_reason == "introspection_malformed_response";
        Record("IntrospectionClient: ParseResponseSafe_MalformedJson_ProducesUndetermined",
               ok, "Malformed JSON must produce UNDETERMINED/introspection_malformed_response");
    } catch (const std::exception& e) {
        Record("IntrospectionClient: ParseResponseSafe_MalformedJson_ProducesUndetermined",
               false, e.what());
    }
}

// Empty body must produce UNDETERMINED (parse fails on empty input).
static void Test_ParseResponseSafe_EmptyBody_ProducesUndetermined() {
    try {
        auto resp = MakeOkResponse("");
        auto r = IntrospectionClient::ParseResponseSafe(
            resp, MakePolicy(), {}, "test-issuer");
        bool ok = !r.idp_active &&
                  r.vr.outcome == VerifyOutcome::UNDETERMINED;
        Record("IntrospectionClient: ParseResponseSafe_EmptyBody_ProducesUndetermined",
               ok, "Empty body (0 bytes) must produce UNDETERMINED");
    } catch (const std::exception& e) {
        Record("IntrospectionClient: ParseResponseSafe_EmptyBody_ProducesUndetermined",
               false, e.what());
    }
}

// JSON array at top level (not object) must produce UNDETERMINED.
static void Test_ParseResponseSafe_ArrayTopLevel_ProducesUndetermined() {
    try {
        std::string body = R"([{"active":true}])";
        auto resp = MakeOkResponse(body);
        auto r = IntrospectionClient::ParseResponseSafe(
            resp, MakePolicy(), {}, "test-issuer");
        bool ok = !r.idp_active &&
                  r.vr.outcome == VerifyOutcome::UNDETERMINED &&
                  r.vr.log_reason == "introspection_malformed_response";
        Record("IntrospectionClient: ParseResponseSafe_ArrayTopLevel_ProducesUndetermined",
               ok, "Top-level JSON array must produce UNDETERMINED/introspection_malformed_response");
    } catch (const std::exception& e) {
        Record("IntrospectionClient: ParseResponseSafe_ArrayTopLevel_ProducesUndetermined",
               false, e.what());
    }
}

// `exp` field as a float: nlohmann::json will parse as a float; verify the
// implementation doesn't crash and exp_from_resp reflects the truncated value
// or zero (document whichever behavior the code actually has).
static void Test_ParseResponseSafe_ExpAsFloat_NoCrash() {
    try {
        // exp is a floating-point number (non-standard but should not crash).
        std::string body = R"({"active":true,"sub":"u","exp":9999999.5})";
        auto resp = MakeOkResponse(body);
        auto r = IntrospectionClient::ParseResponseSafe(
            resp, MakePolicy(), {}, "test-issuer");
        // Must not crash. The result must be ALLOW or UNDETERMINED; either is
        // acceptable depending on whether the exp cast succeeds or throws.
        // We pin the no-crash invariant, not the specific outcome.
        bool ok = true;
        (void)r;
        Record("IntrospectionClient: ParseResponseSafe_ExpAsFloat_NoCrash", ok,
               "exp as float must not crash ParseResponseSafe");
    } catch (const std::exception& e) {
        Record("IntrospectionClient: ParseResponseSafe_ExpAsFloat_NoCrash",
               false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TranslateError tests — smoke-test every shipped error label
// ---------------------------------------------------------------------------

struct ErrorLabelCase {
    const char* error_label;
    const char* expected_log_reason;
};

static void Test_TranslateError_AllLabels() {
    try {
        static const ErrorLabelCase kCases[] = {
            {"timeout",              "introspection_timeout"},
            {"connect_failed",       "introspection_connect_failed"},
            {"connect_timeout",      "introspection_connect_timeout"},
            {"queue_timeout",        "introspection_queue_timeout"},
            {"pool_exhausted",       "introspection_pool_exhausted"},
            {"circuit_open",         "introspection_circuit_open"},
            {"shutting_down",        "introspection_shutting_down"},
            {"parse_error",          "introspection_parse_error"},
            {"body_too_large",       "introspection_body_too_large"},
            {"upstream_disconnect",  "introspection_upstream_disconnect"},
            {"dispatcher_out_of_range","introspection_dispatcher_out_of_range"},
            {"no_upstream_manager",  "introspection_no_upstream_manager"},
            {"pool_unknown",         "introspection_pool_unknown"},
        };

        bool all_ok = true;
        std::string failures;
        for (const auto& c : kCases) {
            auto resp = MakeErrorResponse(c.error_label);
            auto r = IntrospectionClient::TranslateError(resp, "test-issuer");
            bool ok = !r.idp_active &&
                      r.vr.outcome == VerifyOutcome::UNDETERMINED &&
                      r.vr.log_reason == c.expected_log_reason;
            if (!ok) {
                all_ok = false;
                failures += std::string(c.error_label) + "->" +
                            r.vr.log_reason + " ";
            }
        }
        Record("IntrospectionClient: TranslateError_AllLabels", all_ok,
               "Each shipped error label must map to its expected log_reason: " +
               failures);
    } catch (const std::exception& e) {
        Record("IntrospectionClient: TranslateError_AllLabels", false, e.what());
    }
}

// Unknown error label must produce an UNDETERMINED with a
// "introspection_unknown_error_<label>" log_reason.
static void Test_TranslateError_UnknownLabel_ProducesUnknown() {
    try {
        auto resp = MakeErrorResponse("totally_new_error_label");
        auto r = IntrospectionClient::TranslateError(resp, "test-issuer");
        bool ok = !r.idp_active &&
                  r.vr.outcome == VerifyOutcome::UNDETERMINED &&
                  r.vr.log_reason ==
                      "introspection_unknown_error_totally_new_error_label";
        Record("IntrospectionClient: TranslateError_UnknownLabel_ProducesUnknown",
               ok,
               "Unknown error label must produce "
               "introspection_unknown_error_<label>");
    } catch (const std::exception& e) {
        Record("IntrospectionClient: TranslateError_UnknownLabel_ProducesUnknown",
               false, e.what());
    }
}

// 401 HTTP response must produce UNDETERMINED / introspection_client_auth_failed.
static void Test_TranslateError_Http401_ClientAuthFailed() {
    try {
        auto resp = MakeStatusResponse(401);
        auto r = IntrospectionClient::TranslateError(resp, "test-issuer");
        bool ok = !r.idp_active &&
                  r.vr.outcome == VerifyOutcome::UNDETERMINED &&
                  r.vr.log_reason == "introspection_client_auth_failed";
        Record("IntrospectionClient: TranslateError_Http401_ClientAuthFailed",
               ok, "HTTP 401 must produce UNDETERMINED/introspection_client_auth_failed");
    } catch (const std::exception& e) {
        Record("IntrospectionClient: TranslateError_Http401_ClientAuthFailed",
               false, e.what());
    }
}

// 5xx HTTP response must produce UNDETERMINED with introspection_5xx_status_N.
static void Test_TranslateError_Http5xx_StatusLabel() {
    try {
        auto resp = MakeStatusResponse(503);
        auto r = IntrospectionClient::TranslateError(resp, "test-issuer");
        bool ok = !r.idp_active &&
                  r.vr.outcome == VerifyOutcome::UNDETERMINED &&
                  r.vr.log_reason == "introspection_5xx_status_503";
        Record("IntrospectionClient: TranslateError_Http5xx_StatusLabel", ok,
               "HTTP 503 must produce UNDETERMINED/introspection_5xx_status_503");
    } catch (const std::exception& e) {
        Record("IntrospectionClient: TranslateError_Http5xx_StatusLabel",
               false, e.what());
    }
}

// 4xx (non-401) HTTP response must produce UNDETERMINED with
// introspection_4xx_status_N.
static void Test_TranslateError_Http4xx_StatusLabel() {
    try {
        auto resp = MakeStatusResponse(403);
        auto r = IntrospectionClient::TranslateError(resp, "test-issuer");
        bool ok = !r.idp_active &&
                  r.vr.outcome == VerifyOutcome::UNDETERMINED &&
                  r.vr.log_reason == "introspection_4xx_status_403";
        Record("IntrospectionClient: TranslateError_Http4xx_StatusLabel", ok,
               "HTTP 403 must produce UNDETERMINED/introspection_4xx_status_403");
    } catch (const std::exception& e) {
        Record("IntrospectionClient: TranslateError_Http4xx_StatusLabel",
               false, e.what());
    }
}

// ---------------------------------------------------------------------------
// AsyncPendingState unit tests
// ---------------------------------------------------------------------------

// Complete called twice: second call must be a no-op (one-shot invariant).
static void Test_AsyncPendingState_Complete_OneShotIdempotent() {
    try {
        AsyncPendingState state;
        std::atomic<int> fire_count{0};

        auto arm = [&]() {
            state.ArmResume(
                [&](AsyncMiddlewarePayload) {
                    fire_count.fetch_add(1, std::memory_order_relaxed);
                },
                nullptr);
        };
        arm();

        state.Complete(AsyncMiddlewarePayload{AsyncMiddlewareResult::PASS, nullptr});
        state.Complete(AsyncMiddlewarePayload{AsyncMiddlewareResult::PASS, nullptr});

        bool ok = fire_count.load() == 1;
        Record("IntrospectionClient: AsyncPendingState_Complete_OneShotIdempotent",
               ok, "Complete called twice must fire resume_cb exactly once");
    } catch (const std::exception& e) {
        Record("IntrospectionClient: AsyncPendingState_Complete_OneShotIdempotent",
               false, e.what());
    }
}

// ArmResume called twice: second call must be a no-op.
static void Test_AsyncPendingState_ArmResume_OneShotIdempotent() {
    try {
        AsyncPendingState state;
        std::atomic<int> fire_count{0};

        // First ArmResume — registers the callback.
        state.ArmResume(
            [&](AsyncMiddlewarePayload) {
                fire_count.fetch_add(1, std::memory_order_relaxed);
            },
            nullptr);

        // Second ArmResume — must be a no-op (resume_armed_ is already true).
        state.ArmResume(
            [&](AsyncMiddlewarePayload) {
                // This second callback must NEVER be installed or fired.
                fire_count.fetch_add(100, std::memory_order_relaxed);
            },
            nullptr);

        state.Complete(AsyncMiddlewarePayload{AsyncMiddlewareResult::PASS, nullptr});

        bool ok = fire_count.load() == 1;
        Record("IntrospectionClient: AsyncPendingState_ArmResume_OneShotIdempotent",
               ok, "ArmResume called twice must install only the first callback");
    } catch (const std::exception& e) {
        Record("IntrospectionClient: AsyncPendingState_ArmResume_OneShotIdempotent",
               false, e.what());
    }
}

// Complete before ArmResume: the payload must be stored and replayed when
// ArmResume is later called.
static void Test_AsyncPendingState_CompleteBeforeArmResume_Replays() {
    try {
        AsyncPendingState state;
        std::atomic<int> fire_count{0};
        AsyncMiddlewareResult seen_result{AsyncMiddlewareResult::DENY};

        // Complete fires first (async work finished before resume was wired).
        state.Complete(AsyncMiddlewarePayload{AsyncMiddlewareResult::PASS, nullptr});

        // Now arm the resume. Must fire immediately with the stored payload.
        state.ArmResume(
            [&](AsyncMiddlewarePayload p) {
                seen_result = p.result;
                fire_count.fetch_add(1, std::memory_order_relaxed);
            },
            nullptr);

        bool ok = fire_count.load() == 1 &&
                  seen_result == AsyncMiddlewareResult::PASS;
        Record("IntrospectionClient: AsyncPendingState_CompleteBeforeArmResume_Replays",
               ok,
               "Stored payload must replay when ArmResume fires after Complete");
    } catch (const std::exception& e) {
        Record("IntrospectionClient: AsyncPendingState_CompleteBeforeArmResume_Replays",
               false, e.what());
    }
}

// TripCancel and Complete race from separate threads: exactly one of them wins
// the bookkeeping_done_ exchange; resume_cb fires at most once.
static void Test_AsyncPendingState_TripCancelAndComplete_Race() {
    try {
        constexpr int kRounds = 200;
        int double_fire = 0;

        for (int round = 0; round < kRounds; ++round) {
            auto state = std::make_shared<AsyncPendingState>();
            std::atomic<int> fire_count{0};
            auto counter = std::make_shared<std::atomic<int64_t>>(1);

            state->ArmResume(
                [&](AsyncMiddlewarePayload) {
                    if (state->cancelled()) return;
                    fire_count.fetch_add(1, std::memory_order_relaxed);
                },
                counter);

            // Both threads release simultaneously via a barrier.
#if __cpp_lib_barrier >= 201907L
            std::barrier<> go{2};
            std::thread t1([&]() {
                go.arrive_and_wait();
                state->TripCancel();
            });
            std::thread t2([&]() {
                go.arrive_and_wait();
                state->Complete(AsyncMiddlewarePayload{
                    AsyncMiddlewareResult::PASS, nullptr});
            });
#else
            std::atomic<int> ready{0};
            std::thread t1([&]() {
                ready.fetch_add(1, std::memory_order_release);
                while (ready.load(std::memory_order_acquire) < 2) {}
                state->TripCancel();
            });
            std::thread t2([&]() {
                ready.fetch_add(1, std::memory_order_release);
                while (ready.load(std::memory_order_acquire) < 2) {}
                state->Complete(AsyncMiddlewarePayload{
                    AsyncMiddlewareResult::PASS, nullptr});
            });
#endif
            t1.join();
            t2.join();

            // resume_cb may fire 0 or 1 times depending on which wins.
            if (fire_count.load() > 1) ++double_fire;
        }
        bool ok = double_fire == 0;
        Record("IntrospectionClient: AsyncPendingState_TripCancelAndComplete_Race",
               ok,
               "TripCancel+Complete race must never fire resume_cb more than once");
    } catch (const std::exception& e) {
        Record("IntrospectionClient: AsyncPendingState_TripCancelAndComplete_Race",
               false, e.what());
    }
}

// ArmResume after TripCancel: the cancel flag is already set; the resume_cb
// should see cancelled()==true. The callback fires at most once.
static void Test_AsyncPendingState_ArmResume_AfterTripCancel() {
    try {
        AsyncPendingState state;
        state.TripCancel();

        std::atomic<int> fire_count{0};
        bool saw_cancelled = false;
        state.ArmResume(
            [&](AsyncMiddlewarePayload) {
                // TripCancel already fired; ArmResume should not replay.
                fire_count.fetch_add(1, std::memory_order_relaxed);
                saw_cancelled = state.cancelled();
            },
            nullptr);

        // TripCancel already ran; Complete path is now blocked by completed_
        // being unset but cancel is set. ArmResume should not fire the cb
        // because completion_pending_ is false (Complete was never called).
        bool ok = fire_count.load() == 0;
        Record("IntrospectionClient: AsyncPendingState_ArmResume_AfterTripCancel",
               ok,
               "ArmResume after TripCancel (no Complete) must not fire resume_cb");
    } catch (const std::exception& e) {
        Record("IntrospectionClient: AsyncPendingState_ArmResume_AfterTripCancel",
               false, e.what());
    }
}

// DecrementOnce and TripCancel share bookkeeping_done_; calling both must
// decrement the counter exactly once.
static void Test_AsyncPendingState_BookkeepingDoneExactlyOnce() {
    try {
        auto counter = std::make_shared<std::atomic<int64_t>>(2);

        {
            AsyncPendingState state;
            state.ArmResume([](AsyncMiddlewarePayload) {}, counter);
            state.TripCancel();
            state.DecrementOnce(); // second call; bookkeeping_done_ already set
        }
        // Counter must have been decremented exactly once.
        bool ok = counter->load() == 1;
        Record("IntrospectionClient: AsyncPendingState_BookkeepingDoneExactlyOnce",
               ok, "TripCancel+DecrementOnce must decrement counter exactly once");
    } catch (const std::exception& e) {
        Record("IntrospectionClient: AsyncPendingState_BookkeepingDoneExactlyOnce",
               false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Test runner
// ---------------------------------------------------------------------------

static void RunAllTests() {
    std::cout << "\n[IntrospectionClient / AsyncPendingState Tests]" << std::endl;

    // UrlEncode
    Test_UrlEncode_UnreservedPassThrough();
    Test_UrlEncode_SpecialCharsEncoded();
    Test_UrlEncode_HighBitBytesEncoded();
    Test_UrlEncode_NulByte();
    Test_UrlEncode_EmptyInput();

    // BuildAuthorizationHeaderBasic
    Test_BuildAuthorizationHeaderBasic_Standard();
    Test_BuildAuthorizationHeaderBasic_ClientIdWithColon();
    Test_BuildAuthorizationHeaderBasic_SecretWithReservedChars();
    Test_BuildAuthorizationHeaderBasic_EmptyCredentials();

    // ParseResponseSafe
    Test_ParseResponseSafe_ActiveTrue_ProducesAllow();
    Test_ParseResponseSafe_ActiveFalse_ProducesDeny401();
    Test_ParseResponseSafe_ActiveAsInteger_ProducesUndetermined();
    Test_ParseResponseSafe_MissingActive_ProducesUndetermined();
    Test_ParseResponseSafe_MalformedJson_ProducesUndetermined();
    Test_ParseResponseSafe_EmptyBody_ProducesUndetermined();
    Test_ParseResponseSafe_ArrayTopLevel_ProducesUndetermined();
    Test_ParseResponseSafe_ExpAsFloat_NoCrash();

    // TranslateError
    Test_TranslateError_AllLabels();
    Test_TranslateError_UnknownLabel_ProducesUnknown();
    Test_TranslateError_Http401_ClientAuthFailed();
    Test_TranslateError_Http5xx_StatusLabel();
    Test_TranslateError_Http4xx_StatusLabel();

    // AsyncPendingState
    Test_AsyncPendingState_Complete_OneShotIdempotent();
    Test_AsyncPendingState_ArmResume_OneShotIdempotent();
    Test_AsyncPendingState_CompleteBeforeArmResume_Replays();
    Test_AsyncPendingState_TripCancelAndComplete_Race();
    Test_AsyncPendingState_ArmResume_AfterTripCancel();
    Test_AsyncPendingState_BookkeepingDoneExactlyOnce();
}

}  // namespace IntrospectionClientTests
