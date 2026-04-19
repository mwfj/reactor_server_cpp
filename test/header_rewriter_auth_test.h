#pragma once

// ============================================================================
// HeaderRewriter auth-overlay unit tests — Phase 2 test suite.
//
// Exercises the auth-overlay path in HeaderRewriter::RewriteRequest:
//   - Strip inbound identity headers when strip_inbound_identity_headers=true
//   - Do NOT strip when strip_inbound_identity_headers=false
//   - Inject AuthContext fields into the outbound header set
//   - Scopes space-joined when multiple scopes present
//   - raw_jwt_header forwarding opt-in / opt-out
//   - X-Auth-Undetermined set when AuthContext::undetermined=true
//   - preserve_authorization=true / false
//   - claims_to_headers mapping
//   - Reserved overlay headers (authorization, host, via, etc.) are NOT
//     injected even when the operator config points at them
//   - auth_forward=nullptr → no auth processing (no-op overlay)
//   - auth_ctx=nullptr (empty optional) with strip enabled → strip-only run
//   - Non-auth rewriter behaviour unchanged by auth params
// ============================================================================

#include "test_framework.h"
#include "upstream/header_rewriter.h"
#include "auth/auth_config.h"
#include "auth/auth_context.h"
#include "log/logger.h"

#include <map>
#include <string>
#include <optional>
#include <vector>

namespace HeaderRewriterAuthTests {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static HeaderRewriter MakeRewriter(bool xff = true,
                                    bool xfp = true,
                                    bool via = true,
                                    bool rewrite_host = true) {
    HeaderRewriter::Config cfg;
    cfg.set_x_forwarded_for  = xff;
    cfg.set_x_forwarded_proto = xfp;
    cfg.set_via_header        = via;
    cfg.rewrite_host          = rewrite_host;
    return HeaderRewriter(cfg);
}

static AUTH_NAMESPACE::AuthForwardConfig MakeFwdConfig(
        bool strip           = true,
        bool preserve_auth   = true,
        const std::string& subject_hdr = "x-auth-subject",
        const std::string& issuer_hdr  = "x-auth-issuer",
        const std::string& scopes_hdr  = "x-auth-scopes",
        const std::string& raw_jwt_hdr = "") {
    AUTH_NAMESPACE::AuthForwardConfig fwd;
    fwd.strip_inbound_identity_headers = strip;
    fwd.preserve_authorization         = preserve_auth;
    fwd.subject_header                 = subject_hdr;
    fwd.issuer_header                  = issuer_hdr;
    fwd.scopes_header                  = scopes_hdr;
    fwd.raw_jwt_header                 = raw_jwt_hdr;
    return fwd;
}

static AUTH_NAMESPACE::AuthContext MakeCtx(
        const std::string& sub  = "user-123",
        const std::string& iss  = "https://idp.example.com",
        const std::vector<std::string>& scopes = {"read", "write"},
        bool undetermined        = false) {
    AUTH_NAMESPACE::AuthContext ctx;
    ctx.subject       = sub;
    ctx.issuer        = iss;
    ctx.scopes        = scopes;
    ctx.undetermined  = undetermined;
    return ctx;
}

// ---------------------------------------------------------------------------
// Test 1: strip_inbound_identity_headers=true removes spoofed headers
// ---------------------------------------------------------------------------
static bool TestStripInboundIdentityHeaders() {
    auto rw = MakeRewriter(false, false, false, false);
    AUTH_NAMESPACE::AuthForwardConfig fwd = MakeFwdConfig(/*strip=*/true);

    std::map<std::string, std::string> in = {
        {"x-auth-subject", "spoofed-subject"},
        {"x-auth-issuer",  "spoofed-issuer"},
        {"x-auth-scopes",  "spoofed-scopes"},
        {"accept",         "application/json"},
    };
    std::optional<AUTH_NAMESPACE::AuthContext> ctx_opt = MakeCtx();

    auto out = rw.RewriteRequest(in, "1.2.3.4", false, false,
                                   "upstream.example.com", 80,
                                   "", &fwd, &ctx_opt);

    bool stripped_subject = out.find("x-auth-subject") == out.end() ||
                            out.at("x-auth-subject") != "spoofed-subject";
    bool stripped_issuer  = out.find("x-auth-issuer") == out.end() ||
                            out.at("x-auth-issuer")  != "spoofed-issuer";
    bool accept_preserved = out.count("accept") && out.at("accept") == "application/json";

    bool ok = stripped_subject && stripped_issuer && accept_preserved;
    TestFramework::RecordTest("HeaderRewriter auth: strip inbound identity headers",
                               ok,
                               ok ? "" : "inbound spoofed identity headers not stripped");
    return ok;
}

// ---------------------------------------------------------------------------
// Test 2: strip_inbound_identity_headers=false passes spoofed headers through
//         (intentional operator opt-out; rare but supported per config schema)
// ---------------------------------------------------------------------------
static bool TestNoStripWhenDisabled() {
    auto rw = MakeRewriter(false, false, false, false);
    AUTH_NAMESPACE::AuthForwardConfig fwd = MakeFwdConfig(/*strip=*/false);

    std::map<std::string, std::string> in = {
        {"x-auth-subject", "client-value"},
        {"x-auth-issuer",  "client-issuer"},
    };
    std::optional<AUTH_NAMESPACE::AuthContext> ctx_opt = MakeCtx();

    auto out = rw.RewriteRequest(in, "1.2.3.4", false, false,
                                   "upstream", 80, "", &fwd, &ctx_opt);

    // Client values should still be present (not stripped), but then the
    // inject step overwrites them with validated values.
    // Because inject overrides the key, the validated ctx.subject wins.
    bool has_subject = out.count("x-auth-subject") > 0;
    bool ok = has_subject;
    TestFramework::RecordTest("HeaderRewriter auth: strip disabled passes headers",
                               ok,
                               ok ? "" : "subject header missing entirely");
    return ok;
}

// ---------------------------------------------------------------------------
// Test 3: AuthContext fields are injected into the output
// ---------------------------------------------------------------------------
static bool TestIdentityInject() {
    auto rw = MakeRewriter(false, false, false, false);
    AUTH_NAMESPACE::AuthForwardConfig fwd = MakeFwdConfig(true, true,
        "x-auth-subject", "x-auth-issuer", "x-auth-scopes");
    std::optional<AUTH_NAMESPACE::AuthContext> ctx_opt = MakeCtx(
        "u-abc", "https://idp.example.com", {"read", "write"});

    auto out = rw.RewriteRequest({}, "1.2.3.4", false, false,
                                   "upstream", 80, "", &fwd, &ctx_opt);

    bool sub_ok    = out.count("x-auth-subject") && out.at("x-auth-subject") == "u-abc";
    bool iss_ok    = out.count("x-auth-issuer")  && out.at("x-auth-issuer") == "https://idp.example.com";
    bool scopes_ok = out.count("x-auth-scopes")  && out.at("x-auth-scopes") == "read write";

    bool ok = sub_ok && iss_ok && scopes_ok;
    TestFramework::RecordTest("HeaderRewriter auth: identity inject",
                               ok,
                               ok ? "" : "missing injected identity headers");
    return ok;
}

// ---------------------------------------------------------------------------
// Test 4: Single scope — joined string has no trailing/leading space
// ---------------------------------------------------------------------------
static bool TestSingleScopeJoin() {
    auto rw = MakeRewriter(false, false, false, false);
    AUTH_NAMESPACE::AuthForwardConfig fwd = MakeFwdConfig();
    std::optional<AUTH_NAMESPACE::AuthContext> ctx_opt = MakeCtx("u", "https://i", {"openid"});

    auto out = rw.RewriteRequest({}, "1.2.3.4", false, false,
                                   "upstream", 80, "", &fwd, &ctx_opt);

    bool ok = out.count("x-auth-scopes") && out.at("x-auth-scopes") == "openid";
    TestFramework::RecordTest("HeaderRewriter auth: single scope no trailing space",
                               ok,
                               ok ? "" : "scope value: '" +
                                   (out.count("x-auth-scopes") ? out.at("x-auth-scopes") : "<missing>") + "'");
    return ok;
}

// ---------------------------------------------------------------------------
// Test 5: raw_jwt_header is empty by default — raw token NOT forwarded
// ---------------------------------------------------------------------------
static bool TestRawJwtHeaderDisabledByDefault() {
    auto rw = MakeRewriter(false, false, false, false);
    AUTH_NAMESPACE::AuthForwardConfig fwd = MakeFwdConfig();
    fwd.raw_jwt_header = "";  // explicit empty = disabled
    AUTH_NAMESPACE::AuthContext ctx = MakeCtx();
    ctx.raw_token = "my.raw.token";
    std::optional<AUTH_NAMESPACE::AuthContext> ctx_opt = ctx;

    auto out = rw.RewriteRequest({}, "1.2.3.4", false, false,
                                   "upstream", 80, "", &fwd, &ctx_opt);

    // No header should carry the raw token.
    bool no_raw = true;
    for (const auto& [k, v] : out) {
        if (v == "my.raw.token") { no_raw = false; break; }
    }
    TestFramework::RecordTest("HeaderRewriter auth: raw JWT not forwarded when disabled",
                               no_raw,
                               no_raw ? "" : "raw token found in output headers");
    return no_raw;
}

// ---------------------------------------------------------------------------
// Test 6: raw_jwt_header set — raw token forwarded under that name
// ---------------------------------------------------------------------------
static bool TestRawJwtHeaderEnabled() {
    auto rw = MakeRewriter(false, false, false, false);
    AUTH_NAMESPACE::AuthForwardConfig fwd = MakeFwdConfig();
    fwd.raw_jwt_header = "x-forwarded-jwt";
    AUTH_NAMESPACE::AuthContext ctx = MakeCtx();
    ctx.raw_token = "header.payload.sig";
    std::optional<AUTH_NAMESPACE::AuthContext> ctx_opt = ctx;

    auto out = rw.RewriteRequest({}, "1.2.3.4", false, false,
                                   "upstream", 80, "", &fwd, &ctx_opt);

    bool ok = out.count("x-forwarded-jwt") &&
              out.at("x-forwarded-jwt") == "header.payload.sig";
    TestFramework::RecordTest("HeaderRewriter auth: raw JWT forwarded when opt-in",
                               ok,
                               ok ? "" : "raw JWT not in output");
    return ok;
}

// ---------------------------------------------------------------------------
// Test 7: preserve_authorization=true — Authorization header passes through
// ---------------------------------------------------------------------------
static bool TestPreserveAuthorizationTrue() {
    auto rw = MakeRewriter(false, false, false, false);
    AUTH_NAMESPACE::AuthForwardConfig fwd = MakeFwdConfig(
        /*strip=*/true, /*preserve_auth=*/true);

    std::map<std::string, std::string> in = {
        {"authorization", "Bearer eyJhbGciOiJSUzI1NiJ9.x.y"},
        {"content-type",  "application/json"},
    };
    std::optional<AUTH_NAMESPACE::AuthContext> ctx_opt = MakeCtx();

    auto out = rw.RewriteRequest(in, "1.2.3.4", false, false,
                                   "upstream", 80, "", &fwd, &ctx_opt);

    bool ok = out.count("authorization") &&
              out.at("authorization") == "Bearer eyJhbGciOiJSUzI1NiJ9.x.y";
    TestFramework::RecordTest("HeaderRewriter auth: preserve_authorization=true keeps header",
                               ok,
                               ok ? "" : "Authorization header missing");
    return ok;
}

// ---------------------------------------------------------------------------
// Test 8: preserve_authorization=false — Authorization header stripped
// ---------------------------------------------------------------------------
static bool TestPreserveAuthorizationFalse() {
    auto rw = MakeRewriter(false, false, false, false);
    AUTH_NAMESPACE::AuthForwardConfig fwd = MakeFwdConfig(
        /*strip=*/true, /*preserve_auth=*/false);

    std::map<std::string, std::string> in = {
        {"authorization", "Bearer secret.token"},
        {"content-type",  "application/json"},
    };
    std::optional<AUTH_NAMESPACE::AuthContext> ctx_opt = MakeCtx();

    auto out = rw.RewriteRequest(in, "1.2.3.4", false, false,
                                   "upstream", 80, "", &fwd, &ctx_opt);

    bool ok = out.find("authorization") == out.end();
    TestFramework::RecordTest("HeaderRewriter auth: preserve_authorization=false strips header",
                               ok,
                               ok ? "" : "Authorization header should have been stripped");
    return ok;
}

// ---------------------------------------------------------------------------
// Test 9: X-Auth-Undetermined set when AuthContext::undetermined=true
// ---------------------------------------------------------------------------
static bool TestUndeterminedFlag() {
    auto rw = MakeRewriter(false, false, false, false);
    AUTH_NAMESPACE::AuthForwardConfig fwd = MakeFwdConfig(true, true,
        "x-auth-subject", "x-auth-issuer", "x-auth-scopes");
    std::optional<AUTH_NAMESPACE::AuthContext> ctx_opt = MakeCtx("", "", {}, /*undetermined=*/true);

    auto out = rw.RewriteRequest({}, "1.2.3.4", false, false,
                                   "upstream", 80, "", &fwd, &ctx_opt);

    bool has_flag = out.count("x-auth-undetermined") &&
                    out.at("x-auth-undetermined") == "true";
    TestFramework::RecordTest("HeaderRewriter auth: X-Auth-Undetermined set when undetermined",
                               has_flag,
                               has_flag ? "" : "x-auth-undetermined header missing or wrong value");
    return has_flag;
}

// ---------------------------------------------------------------------------
// Test 10: X-Auth-Undetermined NOT set when AuthContext::undetermined=false
// ---------------------------------------------------------------------------
static bool TestNoUndeterminedFlagWhenDetermined() {
    auto rw = MakeRewriter(false, false, false, false);
    AUTH_NAMESPACE::AuthForwardConfig fwd = MakeFwdConfig();
    std::optional<AUTH_NAMESPACE::AuthContext> ctx_opt = MakeCtx("u", "i", {"r"}, false);

    auto out = rw.RewriteRequest({}, "1.2.3.4", false, false,
                                   "upstream", 80, "", &fwd, &ctx_opt);

    bool no_flag = out.find("x-auth-undetermined") == out.end();
    TestFramework::RecordTest("HeaderRewriter auth: X-Auth-Undetermined absent when not undetermined",
                               no_flag,
                               no_flag ? "" : "unexpected x-auth-undetermined header present");
    return no_flag;
}

// ---------------------------------------------------------------------------
// Test 11: claims_to_headers mapping
// ---------------------------------------------------------------------------
static bool TestClaimsToHeadersMapping() {
    auto rw = MakeRewriter(false, false, false, false);
    AUTH_NAMESPACE::AuthForwardConfig fwd = MakeFwdConfig();
    fwd.claims_to_headers["department"] = "x-user-department";
    fwd.claims_to_headers["tenant_id"]  = "x-tenant";

    AUTH_NAMESPACE::AuthContext ctx = MakeCtx("u", "i", {});
    ctx.claims["department"] = "engineering";
    ctx.claims["tenant_id"]  = "acme-corp";
    ctx.claims["secret"]     = "should-not-appear";  // not in mapping
    std::optional<AUTH_NAMESPACE::AuthContext> ctx_opt = ctx;

    auto out = rw.RewriteRequest({}, "1.2.3.4", false, false,
                                   "upstream", 80, "", &fwd, &ctx_opt);

    bool dept_ok    = out.count("x-user-department") &&
                      out.at("x-user-department") == "engineering";
    bool tenant_ok  = out.count("x-tenant") && out.at("x-tenant") == "acme-corp";
    bool no_secret  = out.find("secret") == out.end();

    bool ok = dept_ok && tenant_ok && no_secret;
    TestFramework::RecordTest("HeaderRewriter auth: claims_to_headers mapping",
                               ok,
                               ok ? "" : "claims mapping incorrect");
    return ok;
}

// ---------------------------------------------------------------------------
// Test 12: auth_forward=nullptr — no auth processing at all
// ---------------------------------------------------------------------------
static bool TestNullAuthForwardNoOp() {
    auto rw = MakeRewriter(false, false, false, false);

    std::map<std::string, std::string> in = {
        {"x-auth-subject", "spoofed"},
        {"x-auth-issuer",  "spoofed-issuer"},
        {"custom-header",  "preserved"},
    };
    // No auth_forward / auth_ctx.
    auto out = rw.RewriteRequest(in, "1.2.3.4", false, false,
                                   "upstream", 80);

    // With no auth params, inbound x-auth-* headers pass through untouched.
    bool subj_present = out.count("x-auth-subject") &&
                        out.at("x-auth-subject") == "spoofed";
    bool custom_ok    = out.count("custom-header") &&
                        out.at("custom-header") == "preserved";

    bool ok = subj_present && custom_ok;
    TestFramework::RecordTest("HeaderRewriter auth: null auth_forward is no-op",
                               ok,
                               ok ? "" : "unexpected header mutation without auth_forward");
    return ok;
}

// ---------------------------------------------------------------------------
// Test 13: auth_ctx=nullopt with strip enabled — strip runs, no inject
//          (the case where undetermined auth allows request through)
// ---------------------------------------------------------------------------
static bool TestNulloptAuthCtxStripOnly() {
    auto rw = MakeRewriter(false, false, false, false);
    AUTH_NAMESPACE::AuthForwardConfig fwd = MakeFwdConfig(/*strip=*/true);

    std::map<std::string, std::string> in = {
        {"x-auth-subject", "evil-spoof"},
        {"x-auth-issuer",  "evil-issuer"},
        {"content-type",   "application/json"},
    };
    // auth_ctx is a pointer to nullopt — auth_forward is set but ctx is empty.
    std::optional<AUTH_NAMESPACE::AuthContext> ctx_opt;  // empty optional

    auto out = rw.RewriteRequest(in, "1.2.3.4", false, false,
                                   "upstream", 80, "", &fwd, &ctx_opt);

    // Strip should have run (x-auth-subject removed), but no inject (no subject value set).
    bool stripped  = out.find("x-auth-subject") == out.end();
    bool ct_ok     = out.count("content-type") && out.at("content-type") == "application/json";

    bool ok = stripped && ct_ok;
    TestFramework::RecordTest("HeaderRewriter auth: nullopt ctx strips but does not inject",
                               ok,
                               ok ? "" : "inbound identity header not stripped with empty ctx");
    return ok;
}

// ---------------------------------------------------------------------------
// Test 14: Reserved overlay headers cannot be injected via claims_to_headers
//          Operator mistake: maps "admin" claim → "authorization" header.
//          Defense-in-depth check per DEVELOPMENT_RULES.md.
// ---------------------------------------------------------------------------
static bool TestReservedHeaderDefense() {
    auto rw = MakeRewriter(false, false, false, false);
    AUTH_NAMESPACE::AuthForwardConfig fwd = MakeFwdConfig();
    fwd.claims_to_headers["admin"]   = "authorization";    // reserved — blocked
    fwd.claims_to_headers["host_claim"] = "host";           // reserved — blocked
    fwd.claims_to_headers["dept"]    = "x-department";     // allowed

    std::map<std::string, std::string> in = {
        {"authorization", "Bearer original.token"},
    };
    AUTH_NAMESPACE::AuthContext ctx;
    ctx.claims["admin"]      = "Bearer injected-token";
    ctx.claims["host_claim"] = "evil.example.com";
    ctx.claims["dept"]       = "finance";
    std::optional<AUTH_NAMESPACE::AuthContext> ctx_opt = ctx;

    auto out = rw.RewriteRequest(in, "1.2.3.4", false, false,
                                   "upstream", 80, "", &fwd, &ctx_opt);

    // authorization should remain as the original (not overwritten by claim inject)
    bool auth_safe = !out.count("authorization") ||
                     out.at("authorization") == "Bearer original.token";
    // host should not be overwritten by the claim
    bool host_safe = !out.count("host") ||
                     out.at("host") != "evil.example.com";
    // x-department should be injected normally
    bool dept_ok   = out.count("x-department") &&
                     out.at("x-department") == "finance";

    bool ok = auth_safe && host_safe && dept_ok;
    TestFramework::RecordTest("HeaderRewriter auth: reserved headers not overwritten by claims",
                               ok,
                               ok ? "" : "reserved header defense failed");
    return ok;
}

// ---------------------------------------------------------------------------
// Test 15: Standard non-auth rewriting still works with auth params present
//          (XFF, XFP, Via — ensures auth overlay doesn't interfere)
// ---------------------------------------------------------------------------
static bool TestStandardRewriterWorksWithAuth() {
    auto rw = MakeRewriter(true, true, true, true);
    AUTH_NAMESPACE::AuthForwardConfig fwd = MakeFwdConfig();
    std::optional<AUTH_NAMESPACE::AuthContext> ctx_opt = MakeCtx("u", "i", {"r"});

    std::map<std::string, std::string> in = {
        {"content-type", "application/json"},
    };

    auto out = rw.RewriteRequest(in, "10.0.0.1", false, false,
                                   "backend.example.com", 8080, "", &fwd, &ctx_opt);

    bool xff_ok = out.count("x-forwarded-for") &&
                  out.at("x-forwarded-for") == "10.0.0.1";
    bool xfp_ok = out.count("x-forwarded-proto") &&
                  out.at("x-forwarded-proto") == "http";
    bool via_ok = out.count("via");
    bool host_ok = out.count("host") &&
                   out.at("host") == "backend.example.com:8080";
    bool identity_ok = out.count("x-auth-subject") &&
                       out.at("x-auth-subject") == "u";

    bool ok = xff_ok && xfp_ok && via_ok && host_ok && identity_ok;
    TestFramework::RecordTest("HeaderRewriter auth: standard rewrites work alongside auth",
                               ok,
                               ok ? "" : "standard rewriting broken by auth overlay");
    return ok;
}

// ---------------------------------------------------------------------------
// Test 16: Inbound X-Auth-Undetermined header is stripped (it's a reserved
//          overlay header — clients should not be able to inject it)
// ---------------------------------------------------------------------------
static bool TestInboundUndeterminedHeaderStripped() {
    auto rw = MakeRewriter(false, false, false, false);
    AUTH_NAMESPACE::AuthForwardConfig fwd = MakeFwdConfig(/*strip=*/true);

    std::map<std::string, std::string> in = {
        {"x-auth-undetermined", "true"},  // client trying to spoof undetermined
        {"x-real-header",       "value"},
    };
    std::optional<AUTH_NAMESPACE::AuthContext> ctx_opt = MakeCtx("u", "i", {});

    auto out = rw.RewriteRequest(in, "1.2.3.4", false, false,
                                   "upstream", 80, "", &fwd, &ctx_opt);

    // x-auth-undetermined is a reserved overlay header — IsReservedOverlayHeader
    // returns true for it, so ApplyInboundIdentityStrip will skip it (can't erase
    // reserved headers); but since it's not in fwd.subject_header etc., it would
    // not be in the strip list anyway.
    // The actual defense is: it's reserved → ApplyIdentityInject can't overwrite it.
    // The strip of x-auth-undetermined when ctx is determined is the key guarantee.
    bool flag_absent_or_false = out.find("x-auth-undetermined") == out.end() ||
                                out.at("x-auth-undetermined") != "true";
    // Because the determined ctx does NOT call ApplyUndeterminedInject, the value
    // should be absent (the inbound value MAY pass through since it's not in the
    // subject/issuer/scopes strip list — that's by design per the reserved overlay
    // defense: clients can send x-auth-undetermined but the gateway will overwrite
    // it with the true value if needed, or not emit it for non-undetermined paths).
    // The real protection: when ctx.undetermined=false, we emit no x-auth-undetermined.
    TestFramework::RecordTest("HeaderRewriter auth: x-auth-undetermined not emitted when determined",
                               flag_absent_or_false,
                               flag_absent_or_false ? "" : "x-auth-undetermined='true' unexpectedly present");
    return flag_absent_or_false;
}

// ---------------------------------------------------------------------------
// Test 17: Empty subject/issuer/scopes in AuthContext — no empty headers emitted
// ---------------------------------------------------------------------------
static bool TestEmptyAuthContextNoEmptyHeaders() {
    auto rw = MakeRewriter(false, false, false, false);
    AUTH_NAMESPACE::AuthForwardConfig fwd = MakeFwdConfig(true, true,
        "x-auth-subject", "x-auth-issuer", "x-auth-scopes");
    AUTH_NAMESPACE::AuthContext ctx;  // all fields empty
    ctx.undetermined = false;
    std::optional<AUTH_NAMESPACE::AuthContext> ctx_opt = ctx;

    auto out = rw.RewriteRequest({}, "1.2.3.4", false, false,
                                   "upstream", 80, "", &fwd, &ctx_opt);

    // Empty values should not be emitted.
    bool no_empty_sub    = !out.count("x-auth-subject");
    bool no_empty_issuer = !out.count("x-auth-issuer");
    bool no_empty_scopes = !out.count("x-auth-scopes");

    bool ok = no_empty_sub && no_empty_issuer && no_empty_scopes;
    TestFramework::RecordTest("HeaderRewriter auth: empty AuthContext emits no empty headers",
                               ok,
                               ok ? "" : "empty header value found in output");
    return ok;
}

// ---------------------------------------------------------------------------
// Test 18: Hop-by-hop headers are stripped even when auth params are present
// ---------------------------------------------------------------------------
static bool TestHopByHopStillStrippedWithAuth() {
    auto rw = MakeRewriter(false, false, false, false);
    AUTH_NAMESPACE::AuthForwardConfig fwd = MakeFwdConfig();
    std::optional<AUTH_NAMESPACE::AuthContext> ctx_opt = MakeCtx("u", "i", {"r"});

    std::map<std::string, std::string> in = {
        {"connection",        "keep-alive"},
        {"keep-alive",        "timeout=5"},
        {"transfer-encoding", "chunked"},
        {"content-type",      "text/plain"},
    };

    auto out = rw.RewriteRequest(in, "1.2.3.4", false, false,
                                   "upstream", 80, "", &fwd, &ctx_opt);

    bool no_conn = out.find("connection") == out.end();
    bool no_ka   = out.find("keep-alive") == out.end();
    bool no_te   = out.find("transfer-encoding") == out.end();
    bool ct_ok   = out.count("content-type");

    bool ok = no_conn && no_ka && no_te && ct_ok;
    TestFramework::RecordTest("HeaderRewriter auth: hop-by-hop headers stripped with auth present",
                               ok,
                               ok ? "" : "hop-by-hop header leaked through");
    return ok;
}

// ---------------------------------------------------------------------------
// RunAllTests
// ---------------------------------------------------------------------------
static void RunAllTests() {
    TestStripInboundIdentityHeaders();
    TestNoStripWhenDisabled();
    TestIdentityInject();
    TestSingleScopeJoin();
    TestRawJwtHeaderDisabledByDefault();
    TestRawJwtHeaderEnabled();
    TestPreserveAuthorizationTrue();
    TestPreserveAuthorizationFalse();
    TestUndeterminedFlag();
    TestNoUndeterminedFlagWhenDetermined();
    TestClaimsToHeadersMapping();
    TestNullAuthForwardNoOp();
    TestNulloptAuthCtxStripOnly();
    TestReservedHeaderDefense();
    TestStandardRewriterWorksWithAuth();
    TestInboundUndeterminedHeaderStripped();
    TestEmptyAuthContextNoEmptyHeaders();
    TestHopByHopStillStrippedWithAuth();
}

}  // namespace HeaderRewriterAuthTests
