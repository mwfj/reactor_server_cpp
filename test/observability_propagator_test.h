#pragma once

// W3C Trace Context propagator tests. Pure value-type tests
// — no I/O. Covers traceparent parse + serialize round-trip, the
// W3C §3.2.2.5 invalid-form rejections, tracestate forward/back, and
// outbound Inject's strip-then-replace behavior.

#include "test_framework.h"
#include "observability/propagator.h"
#include "observability/span_context.h"
#include "observability/trace_id.h"
#include "observability/trace_state.h"

#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace ObservabilityPropagatorTests {

using OBSERVABILITY_NAMESPACE::SpanContext;
using OBSERVABILITY_NAMESPACE::SpanId;
using OBSERVABILITY_NAMESPACE::TraceFlags;
using OBSERVABILITY_NAMESPACE::TraceId;
using OBSERVABILITY_NAMESPACE::TraceState;
using OBSERVABILITY_NAMESPACE::W3CPropagator;

// Round-trip a known-good traceparent header.
void TestTraceparentRoundTrip() {
    try {
        const std::string hdr =
            "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01";
        auto ctx = W3CPropagator::ParseTraceparent(hdr);
        bool pass = ctx.has_value() && ctx->IsValid() && ctx->is_remote() &&
                    ctx->trace_id().ToHex() == "0af7651916cd43dd8448eb211c80319c" &&
                    ctx->span_id().ToHex() == "00f067aa0ba902b7" &&
                    ctx->flags().IsSampled();
        if (pass) {
            auto out = W3CPropagator::SerializeTraceparent(*ctx);
            pass = out.has_value() && *out == hdr;
        }
        TestFramework::RecordTest(
            "ObsProp: traceparent parse + serialize round-trip",
            pass, pass ? "" : "round-trip mismatch",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsProp: traceparent parse + serialize round-trip",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// W3C §3.2.2.5 — every invalid form must be rejected.
void TestTraceparentInvalidForms() {
    try {
        struct Variant { const char* name; const char* hdr; };
        const Variant variants[] = {
            // Wrong length (54 chars).
            { "short",
              "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-0" },
            // Wrong length (56 chars — extra trailing char).
            { "long",
              "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-011" },
            // Bad version "ff" (only "00" supported).
            { "version_ff",
              "ff-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01" },
            // Non-hex char in trace_id.
            { "non_hex_trace",
              "00-0af7651916cd43dd8448eb211c80319g-00f067aa0ba902b7-01" },
            // Non-hex char in flags.
            { "non_hex_flags",
              "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-zz" },
            // All-zero trace_id (W3C "invalid").
            { "all_zero_trace",
              "00-00000000000000000000000000000000-00f067aa0ba902b7-01" },
            // All-zero parent_id (W3C "invalid").
            { "all_zero_parent",
              "00-0af7651916cd43dd8448eb211c80319c-0000000000000000-01" },
            // Missing dash separator at offset 2.
            { "missing_dash",
              "000a0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b701" },
        };
        bool pass = true;
        std::string err;
        for (const auto& v : variants) {
            auto ctx = W3CPropagator::ParseTraceparent(v.hdr);
            if (ctx.has_value()) {
                pass = false;
                err = std::string{v.name} + " not rejected";
                break;
            }
        }
        TestFramework::RecordTest(
            "ObsProp: traceparent rejects W3C invalid forms",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsProp: traceparent rejects W3C invalid forms",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Sampled bit round-trip.
void TestTraceparentSampledBit() {
    try {
        const std::string sampled =
            "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01";
        const std::string unsampled =
            "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-00";
        auto a = W3CPropagator::ParseTraceparent(sampled);
        auto b = W3CPropagator::ParseTraceparent(unsampled);
        bool pass = a.has_value() && b.has_value() &&
                    a->flags().IsSampled() && !b->flags().IsSampled();
        TestFramework::RecordTest(
            "ObsProp: traceparent sampled-bit round-trip",
            pass, pass ? "" : "sampled bit not preserved",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsProp: traceparent sampled-bit round-trip",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// High-level Extract: pulls both traceparent + tracestate from a
// header map.
void TestExtractCombined() {
    try {
        std::map<std::string, std::string> headers;
        headers["traceparent"] =
            "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01";
        headers["tracestate"] = "vendor1=abc,vendor2=xyz";
        auto ctx = W3CPropagator::Extract(headers);
        bool pass = ctx.has_value() && ctx->IsValid() &&
                    ctx->state().Size() == 2 &&
                    ctx->state().Get("vendor1") == "abc" &&
                    ctx->state().Get("vendor2") == "xyz";
        TestFramework::RecordTest(
            "ObsProp: Extract pulls combined traceparent + tracestate",
            pass, pass ? "" : "Extract returned wrong context",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsProp: Extract pulls combined traceparent + tracestate",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Per W3C §3.3.5: invalid tracestate must be DROPPED, not invalidate
// the traceparent.
void TestExtractTracestateInvalidDropped() {
    try {
        std::map<std::string, std::string> headers;
        headers["traceparent"] =
            "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01";
        // Build a 33-member tracestate (W3C cap is 32).
        std::string ts;
        for (int i = 0; i < 33; ++i) {
            if (!ts.empty()) ts.push_back(',');
            ts += "k" + std::to_string(i) + "=v" + std::to_string(i);
        }
        headers["tracestate"] = ts;

        auto ctx = W3CPropagator::Extract(headers);
        // Traceparent valid → ctx is present, but tracestate is dropped.
        bool pass = ctx.has_value() && ctx->state().Empty();
        TestFramework::RecordTest(
            "ObsProp: Extract drops invalid tracestate but keeps traceparent",
            pass, pass ? "" : "tracestate not dropped",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsProp: Extract drops invalid tracestate but keeps traceparent",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Missing traceparent → Extract returns nullopt.
void TestExtractAbsentTraceparent() {
    try {
        std::map<std::string, std::string> headers;
        headers["host"] = "example.com";
        auto ctx = W3CPropagator::Extract(headers);
        bool pass = !ctx.has_value();
        TestFramework::RecordTest(
            "ObsProp: Extract returns nullopt when traceparent missing",
            pass, pass ? "" : "non-null on absent traceparent",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsProp: Extract returns nullopt when traceparent missing",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Inject into a map: writes traceparent + tracestate.
void TestInjectIntoMap() {
    try {
        SpanContext ctx;
        ctx.SetTraceId(TraceId::FromHex("0af7651916cd43dd8448eb211c80319c"));
        ctx.SetSpanId(SpanId::FromHex("00f067aa0ba902b7"));
        ctx.SetFlags(TraceFlags{0x01});
        auto ts = TraceState::Parse("vendor1=abc");
        if (ts) ctx.mutable_state() = std::move(*ts);

        std::map<std::string, std::string> headers;
        bool ok = W3CPropagator::Inject(ctx, headers);
        bool pass = ok &&
                    headers["traceparent"] ==
                        "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01" &&
                    headers["tracestate"] == "vendor1=abc";
        TestFramework::RecordTest(
            "ObsProp: Inject writes traceparent + tracestate to map",
            pass, pass ? "" : "inject wrong",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsProp: Inject writes traceparent + tracestate to map",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Inject into a vector: replaces existing traceparent (case-insensitive)
// — the strip-then-inject contract from §4.4.
void TestInjectStripsExistingHeaderInVector() {
    try {
        SpanContext ctx;
        ctx.SetTraceId(TraceId::FromHex("0af7651916cd43dd8448eb211c80319c"));
        ctx.SetSpanId(SpanId::FromHex("00f067aa0ba902b7"));
        ctx.SetFlags(TraceFlags{0x01});

        std::vector<std::pair<std::string, std::string>> headers;
        // Pre-existing inbound traceparent (mixed case to test
        // case-insensitive strip).
        headers.emplace_back("TraceParent", "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-00");
        headers.emplace_back("host", "example.com");

        bool ok = W3CPropagator::Inject(ctx, headers);
        // Old traceparent should be gone; new one appended; host preserved.
        size_t tp_count = 0;
        std::string tp_value;
        bool has_host = false;
        for (const auto& [k, v] : headers) {
            std::string lk;
            for (char c : k) lk.push_back(
                static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
            if (lk == "traceparent") {
                ++tp_count;
                tp_value = v;
            } else if (lk == "host") {
                has_host = true;
            }
        }
        bool pass = ok && tp_count == 1 &&
                    tp_value == "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01" &&
                    has_host;
        TestFramework::RecordTest(
            "ObsProp: Inject strips pre-existing traceparent (case-insensitive)",
            pass, pass ? "" : "strip-then-replace wrong",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsProp: Inject strips pre-existing traceparent (case-insensitive)",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Inject with invalid context returns false + does not mutate headers.
void TestInjectInvalidContextNoOp() {
    try {
        SpanContext ctx;  // default — all-zero ids, IsValid() == false
        std::map<std::string, std::string> headers;
        headers["host"] = "example.com";
        bool ok = W3CPropagator::Inject(ctx, headers);
        bool pass = !ok && headers.find("traceparent") == headers.end() &&
                    headers["host"] == "example.com";
        TestFramework::RecordTest(
            "ObsProp: Inject with invalid SpanContext is a no-op",
            pass, pass ? "" : "invalid context wrote header",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsProp: Inject with invalid SpanContext is a no-op",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void RunAllTests() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "OBSERVABILITY PROPAGATOR TESTS" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    TestTraceparentRoundTrip();
    TestTraceparentInvalidForms();
    TestTraceparentSampledBit();
    TestExtractCombined();
    TestExtractTracestateInvalidDropped();
    TestExtractAbsentTraceparent();
    TestInjectIntoMap();
    TestInjectStripsExistingHeaderInVector();
    TestInjectInvalidContextNoOp();
}

}  // namespace ObservabilityPropagatorTests
