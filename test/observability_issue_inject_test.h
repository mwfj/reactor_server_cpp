#pragma once

// IssueTraceContext outbound injection tests. Verifies that
// UpstreamHttpClient::ApplyOutboundTraceContext follows the §6.3 strip-
// and-replace contract for the JWKS / OIDC / introspection / OTLP
// outbound paths.

#include "test_framework.h"
#include "auth/upstream_http_client.h"
#include "observability/observability_manager.h"
#include "observability/propagator.h"
#include "observability/span_context.h"
#include "observability/trace_context.h"
#include "observability/trace_id.h"
#include "observability/tracer.h"
#include "observability/tracer_provider.h"
#include "observability_test_helpers.h"

#include <cstdint>
#include <string>

namespace ObservabilityIssueInjectTests {

using AUTH_NAMESPACE::UpstreamHttpClient;
using OBSERVABILITY_NAMESPACE::IssueTraceContext;
using OBSERVABILITY_NAMESPACE::RandomSource;
using OBSERVABILITY_NAMESPACE::SpanContext;
using OBSERVABILITY_NAMESPACE::SpanId;
using OBSERVABILITY_NAMESPACE::TraceFlags;
using OBSERVABILITY_NAMESPACE::TraceId;
using OBSERVABILITY_NAMESPACE::Tracer;
using OBSERVABILITY_NAMESPACE::TraceState;
using OBSERVABILITY_NAMESPACE::W3CPropagator;

namespace {

SpanContext MakeRecordingContext(uint64_t seed) {
    RandomSource rs(seed);
    auto tid = rs.NewTraceId();
    auto sid = rs.NewSpanId();
    return SpanContext(tid, sid, TraceFlags(TraceFlags::kSampled),
                        TraceState{}, false);
}

}  // namespace

// When no issue_ctx is set, both headers must be stripped if present
// AND no traceparent must be injected (defense in depth — never leak
// inbound traceparent through internal hops).
void TestStripWithoutIssueContext() {
    try {
        UpstreamHttpClient::Request req;
        req.headers["traceparent"] =
            "00-00000000000000000000000000000001-0000000000000002-01";
        req.headers["tracestate"] = "vendor=foo";
        req.headers["x-other"]    = "preserved";

        UpstreamHttpClient::ApplyOutboundTraceContext(req);

        bool pass = req.headers.count("traceparent") == 0
                  && req.headers.count("tracestate") == 0
                  && req.headers.count("x-other") == 1;
        TestFramework::RecordTest(
            "ObsIssue: strips client traceparent when no issue_ctx",
            pass, pass ? "" : "did not strip / preserved unrelated wrong",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsIssue: strips client traceparent when no issue_ctx",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// When issue_ctx is set with a valid SpanContext, the strip drops any
// pre-existing header AND a fresh traceparent is injected from local.
void TestInjectFromIssueContext() {
    try {
        UpstreamHttpClient::Request req;
        // Stale inbound traceparent — must be replaced, not retained.
        req.headers["traceparent"] =
            "00-deadbeefdeadbeefdeadbeefdeadbeef-aabbccddeeff0011-01";

        // Spin up a Tracer so the issue_ctx satisfies the
        // ApplyOutboundTraceContext contract (only inject when a
        // tracer is bound — tracer presence signals the caller is
        // emitting a CLIENT span around the outbound call).
        auto mgr = ObservabilityTestHelpers::MakeManager("issue-inject-test");
        Tracer* tracer = mgr->GetTracer("test.issue");
        IssueTraceContext ictx;
        ictx.local = MakeRecordingContext(0x12345);
        ictx.tracer = tracer;
        req.issue_ctx = ictx;

        UpstreamHttpClient::ApplyOutboundTraceContext(req);

        auto it = req.headers.find("traceparent");
        bool present = it != req.headers.end();
        bool not_stale = present && it->second.find("deadbeef") == std::string::npos;
        // Round-trip check: parse the injected header back and confirm
        // it carries our local trace_id / span_id.
        bool round_trip = false;
        if (present) {
            auto parsed = W3CPropagator::ParseTraceparent(it->second);
            if (parsed
                && parsed->trace_id() == ictx.local.trace_id()
                && parsed->span_id() == ictx.local.span_id()) {
                round_trip = true;
            }
        }
        bool pass = present && not_stale && round_trip;
        TestFramework::RecordTest(
            "ObsIssue: injects fresh traceparent from issue_ctx.local",
            pass, pass ? "" : "inject did not replace stale header",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsIssue: injects fresh traceparent from issue_ctx.local",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// An issue_ctx whose `local` SpanContext is invalid (e.g. zero IDs)
// must NOT inject a malformed traceparent — strip-only semantics, same
// as the no-issue_ctx case. Validates the IsValid() guard.
void TestInvalidIssueContextStripsOnly() {
    try {
        UpstreamHttpClient::Request req;
        req.headers["traceparent"] =
            "00-00000000000000000000000000000001-0000000000000002-01";

        IssueTraceContext ictx;  // local default-constructed → invalid
        req.issue_ctx = ictx;

        UpstreamHttpClient::ApplyOutboundTraceContext(req);

        bool pass = req.headers.count("traceparent") == 0;
        TestFramework::RecordTest(
            "ObsIssue: invalid issue_ctx strips without injecting",
            pass, pass ? "" : "injected from invalid context",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsIssue: invalid issue_ctx strips without injecting",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Tracestate from local SpanContext should ride along when non-empty,
// and a stale inbound tracestate is dropped first.
void TestTracestateRoundTrip() {
    try {
        UpstreamHttpClient::Request req;
        req.headers["tracestate"] = "stale=value";

        TraceState ts;
        ts.Set("vendor", "fresh");
        IssueTraceContext ictx;
        RandomSource rs(0x7777);
        auto tid = rs.NewTraceId();
        auto sid = rs.NewSpanId();
        ictx.local = SpanContext(tid, sid,
                                 TraceFlags(TraceFlags::kSampled),
                                 ts, false);
        // Bind a Tracer so the inject path fires under the new
        // contract — see TestInjectFromIssueContext above.
        auto mgr = ObservabilityTestHelpers::MakeManager("tracestate-test");
        ictx.tracer = mgr->GetTracer("test.issue");
        req.issue_ctx = ictx;

        UpstreamHttpClient::ApplyOutboundTraceContext(req);

        auto it = req.headers.find("tracestate");
        bool present = it != req.headers.end();
        bool fresh = present && it->second.find("vendor=fresh") != std::string::npos;
        bool not_stale = present && it->second.find("stale=value") == std::string::npos;
        bool pass = present && fresh && not_stale;
        TestFramework::RecordTest(
            "ObsIssue: tracestate strip + fresh inject",
            pass, pass ? "" : "tracestate not refreshed",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsIssue: tracestate strip + fresh inject",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void RunAllTests() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "OBSERVABILITY ISSUE-INJECT TESTS" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    TestStripWithoutIssueContext();
    TestInjectFromIssueContext();
    TestInvalidIssueContextStripsOnly();
    TestTracestateRoundTrip();
}

}  // namespace ObservabilityIssueInjectTests
