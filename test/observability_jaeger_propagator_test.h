#pragma once

// Jaeger propagator tests — `uber-trace-id` parser. Covers 128-bit and
// 64-bit (left-padded) trace ids, sampled flag, and W3C-style
// invalid-form rejections (all-zero ids, bad hex, missing parts).

#include "test_framework.h"
#include "observability/propagator.h"
#include "observability/span_context.h"
#include "observability/trace_id.h"
#include "observability/trace_state.h"

#include <map>
#include <string>

namespace ObservabilityJaegerPropagatorTests {

using OBSERVABILITY_NAMESPACE::CompositePropagator;
using OBSERVABILITY_NAMESPACE::JaegerPropagator;
using OBSERVABILITY_NAMESPACE::Propagator;
using OBSERVABILITY_NAMESPACE::SpanContext;
using OBSERVABILITY_NAMESPACE::SpanId;
using OBSERVABILITY_NAMESPACE::TraceFlags;
using OBSERVABILITY_NAMESPACE::TraceId;
using OBSERVABILITY_NAMESPACE::TraceState;
using OBSERVABILITY_NAMESPACE::W3CPropagator;

// Canonical 128-bit input: 32-hex trace id + 16-hex span id +
// parent="0" + flags="1" (sampled).
void TestParse128BitTraceId() {
    try {
        JaegerPropagator p;
        Propagator::HeadersMap h = {
            {"uber-trace-id",
             "1234567890abcdef1234567890abcdef:0011223344556677:0:1"}};
        auto ctx = p.Extract(h);
        bool pass = ctx.has_value()
                  && ctx->trace_id().ToHex() == "1234567890abcdef1234567890abcdef"
                  && ctx->span_id().ToHex()  == "0011223344556677"
                  && ctx->flags().IsSampled()
                  && ctx->is_remote();
        TestFramework::RecordTest(
            "ObsJaeger: parse 128-bit uber-trace-id",
            pass, pass ? "" : "extracted context mismatch",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsJaeger: parse 128-bit uber-trace-id",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Legacy 64-bit trace id is left-padded with 16 zero hex chars to
// round-trip through the 128-bit TraceId carrier.
void TestParse64BitTraceIdLeftPads() {
    try {
        JaegerPropagator p;
        Propagator::HeadersMap h = {
            {"uber-trace-id", "abcdef1234567890:0011223344556677:0:1"}};
        auto ctx = p.Extract(h);
        bool pass = ctx.has_value()
                  && ctx->trace_id().ToHex()
                      == "0000000000000000abcdef1234567890";
        TestFramework::RecordTest(
            "ObsJaeger: parse 64-bit trace id left-pads to 128",
            pass, pass ? "" : "left-pad failed",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsJaeger: parse 64-bit trace id left-pads to 128",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// parent_id="0" is legal (root span on the inbound side); we must
// still accept the header.
void TestParseLegacyZeroParent() {
    try {
        JaegerPropagator p;
        Propagator::HeadersMap h = {
            {"uber-trace-id",
             "1234567890abcdef1234567890abcdef:0011223344556677:0:1"}};
        bool pass = p.Extract(h).has_value();
        TestFramework::RecordTest(
            "ObsJaeger: zero parent_id accepted (root span)",
            pass, pass ? "" : "rejected legal root-span parent",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsJaeger: zero parent_id accepted (root span)",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Sampled bit is the only flag bit honored; flags="0" must yield an
// unsampled context.
void TestParseUnsampledFlag() {
    try {
        JaegerPropagator p;
        Propagator::HeadersMap h = {
            {"uber-trace-id",
             "1234567890abcdef1234567890abcdef:0011223344556677:0:0"}};
        auto ctx = p.Extract(h);
        bool pass = ctx.has_value() && !ctx->flags().IsSampled();
        TestFramework::RecordTest(
            "ObsJaeger: unsampled flag preserved",
            pass, pass ? "" : "sampled bit not respected",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsJaeger: unsampled flag preserved",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestParseRejectsMalformed() {
    try {
        JaegerPropagator p;
        struct Variant { const char* name; const char* hdr; };
        const Variant variants[] = {
            {"empty", ""},
            {"too_few_parts", "not:enough:parts"},
            {"non_hex_trace", "zzz:0011223344556677:0:1"},
            {"all_zero_trace",
             "00000000000000000000000000000000:0011223344556677:0:1"},
            {"all_zero_span",
             "1234567890abcdef1234567890abcdef:0000000000000000:0:1"},
            {"short_span",
             "1234567890abcdef1234567890abcdef:001122:0:1"},
            {"upper_hex_trace",
             "1234567890ABCDEF1234567890abcdef:0011223344556677:0:1"},
            // Trailing 5th colon must be rejected. The previous post-loop
            // length check used the wrong base and accidentally accepted
            // "a:b:c:d:e" whenever len(e) happened to equal len(d).
            {"five_parts_equal_lengths",
             "1234567890abcdef1234567890abcdef:0011223344556677:0:1:2"},
            {"five_parts_long_extra",
             "1234567890abcdef1234567890abcdef:0011223344556677:0:1:extra"},
            {"trailing_colon_no_extra",
             "1234567890abcdef1234567890abcdef:0011223344556677:0:1:"},
            // Empty parent-span-id contradicts the documented 4-part
            // contract — must reject (was silently accepted before).
            {"empty_parent_span_id",
             "1234567890abcdef1234567890abcdef:0011223344556677::1"},
        };
        bool pass = true;
        std::string err;
        for (const auto& v : variants) {
            Propagator::HeadersMap h = {{"uber-trace-id", v.hdr}};
            if (p.Extract(h).has_value()) {
                pass = false;
                err = std::string{v.name} + " not rejected";
                break;
            }
        }
        TestFramework::RecordTest(
            "ObsJaeger: rejects malformed uber-trace-id",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsJaeger: rejects malformed uber-trace-id",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestParseHeaderAbsent() {
    try {
        JaegerPropagator p;
        Propagator::HeadersMap h;
        bool pass = !p.Extract(h).has_value();
        TestFramework::RecordTest(
            "ObsJaeger: absent header returns nullopt",
            pass, pass ? "" : "extracted from empty headers",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsJaeger: absent header returns nullopt",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestStripOwnedHeaders() {
    try {
        JaegerPropagator p;
        Propagator::HeadersMap h = {
            {"uber-trace-id",
             "1234567890abcdef1234567890abcdef:0011223344556677:0:1"},
            {"content-type", "application/json"}};
        p.StripOwnedHeaders(h);
        bool pass = h.count("uber-trace-id") == 0
                  && h.count("content-type") == 1;
        TestFramework::RecordTest(
            "ObsJaeger: StripOwnedHeaders removes uber-trace-id only",
            pass, pass ? "" : "strip dropped unrelated headers",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsJaeger: StripOwnedHeaders removes uber-trace-id only",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Mixed-case headers must extract correctly — production traffic over
// HTTP/1 lowercases by convention and HTTP/2 forces lowercase, but a
// raw-header caller (test fixture, future code path) would otherwise
// silently see no parent and fall through to a fresh trace.
void TestExtractCaseInsensitive() {
    try {
        JaegerPropagator p;
        Propagator::HeadersMap h = {
            {"Uber-Trace-Id",
             "1234567890abcdef1234567890abcdef:0011223344556677:0:1"}};
        auto ctx = p.Extract(h);
        const bool extracted = ctx.has_value() && ctx->IsValid();
        const bool flag_ok = extracted && ctx->flags().IsSampled();
        const bool pass = extracted && flag_ok;
        TestFramework::RecordTest(
            "ObsJaeger: Extract is case-insensitive (Uber-Trace-Id)",
            pass, pass ? ""
                      : "extracted=" + std::to_string(extracted)
                       + " sampled=" + std::to_string(flag_ok),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsJaeger: Extract is case-insensitive (Uber-Trace-Id)",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Mixed-case duplicates ("Uber-Trace-Id") would otherwise leak through
// to the upstream — Strip must match case-insensitively, like W3C.
void TestStripOwnedHeadersCaseInsensitive() {
    try {
        JaegerPropagator p;
        Propagator::HeadersMap h = {
            {"Uber-Trace-Id",
             "1234567890abcdef1234567890abcdef:0011223344556677:0:1"},
            {"UBER-TRACE-ID",
             "0000000000000000aaaaaaaaaaaaaaaa:0011223344556677:0:0"},
            {"content-type", "application/json"}};
        p.StripOwnedHeaders(h);
        bool pass = h.count("Uber-Trace-Id") == 0
                  && h.count("UBER-TRACE-ID") == 0
                  && h.count("uber-trace-id") == 0
                  && h.count("content-type") == 1;
        TestFramework::RecordTest(
            "ObsJaeger: StripOwnedHeaders is case-insensitive",
            pass, pass ? "" : "case-variant uber-trace-id leaked through",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsJaeger: StripOwnedHeaders is case-insensitive",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestNameIsJaeger() {
    try {
        JaegerPropagator p;
        bool pass = std::string(p.Name()) == "jaeger";
        TestFramework::RecordTest(
            "ObsJaeger: Name() returns 'jaeger'",
            pass, pass ? "" : "wrong name",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsJaeger: Name() returns 'jaeger'",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestInjectAlways128Bit() {
    try {
        JaegerPropagator p;
        SpanContext ctx(TraceId::FromHex(std::string(32, 'a')),
                         SpanId::FromHex("0011223344556677"),
                         TraceFlags{TraceFlags::kSampled},
                         TraceState{}, /*is_remote=*/false);
        Propagator::HeadersMap out;
        bool ok = p.Inject(ctx, out);
        auto it = out.find(JaegerPropagator::kHeader);
        bool pass = ok && it != out.end()
                  && it->second == std::string(32, 'a')
                                  + ":0011223344556677:0:01";
        TestFramework::RecordTest(
            "ObsJaeger: Inject emits 128-bit trace + 16-bit span + flags=01",
            pass, pass ? "" : "header mismatch",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsJaeger: Inject emits 128-bit trace + 16-bit span + flags=01",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestInjectUnsampledFlagsZero() {
    try {
        JaegerPropagator p;
        SpanContext ctx(TraceId::FromHex(std::string(32, 'b')),
                         SpanId::FromHex("aabbccddeeff0011"),
                         TraceFlags{0},
                         TraceState{}, /*is_remote=*/false);
        Propagator::HeadersMap out;
        bool ok = p.Inject(ctx, out);
        const auto& v = out[JaegerPropagator::kHeader];
        bool pass = ok && v.find(":0:00") != std::string::npos;
        TestFramework::RecordTest(
            "ObsJaeger: Inject unsampled context emits flags=00",
            pass, pass ? "" : "expected ':0:00' suffix; got " + v,
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsJaeger: Inject unsampled context emits flags=00",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestInjectInvalidContextNoOp() {
    try {
        JaegerPropagator p;
        SpanContext ctx;   // default = invalid
        Propagator::HeadersMap out;
        bool ok = p.Inject(ctx, out);
        bool pass = !ok && out.empty();
        TestFramework::RecordTest(
            "ObsJaeger: Inject invalid SpanContext is no-op",
            pass, pass ? "" : "wrote header for invalid context",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsJaeger: Inject invalid SpanContext is no-op",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestInjectStripReplace() {
    try {
        JaegerPropagator p;
        Propagator::HeadersMap out = {
            {JaegerPropagator::kHeader,
             "ffffffffffffffffffffffffffffffff:0000000000000001:0:01"}};
        SpanContext ctx(TraceId::FromHex(std::string(32, 'c')),
                         SpanId::FromHex("1234567890abcdef"),
                         TraceFlags{TraceFlags::kSampled},
                         TraceState{}, /*is_remote=*/false);
        p.Inject(ctx, out);
        const auto& v = out[JaegerPropagator::kHeader];
        bool pass = v.find(std::string(32, 'c')) == 0
                  && v.find("ffffffffff") == std::string::npos;
        TestFramework::RecordTest(
            "ObsJaeger: Inject replaces existing uber-trace-id",
            pass, pass ? "" : "stale value not replaced: " + v,
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsJaeger: Inject replaces existing uber-trace-id",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Inject(HeadersMap&) honors strip-then-inject for mixed-case
// duplicates. Without the explicit StripOwnedHeaders call inside
// Inject, a client-supplied "Uber-Trace-Id" would survive the
// canonical lowercase upsert, and the upstream would see two trace
// headers. Mirrors the W3C Map-form strip test.
void TestInjectMapStripsMixedCaseDuplicate() {
    try {
        JaegerPropagator p;
        Propagator::HeadersMap out;
        out["Uber-Trace-Id"] =
            "deadbeefdeadbeefdeadbeefdeadbeef:0000000000000001:0:01";
        out["host"] = "example.com";

        SpanContext ctx(TraceId::FromHex(std::string(32, 'a')),
                         SpanId::FromHex("1234567890abcdef"),
                         TraceFlags{TraceFlags::kSampled},
                         TraceState{}, /*is_remote=*/false);
        p.Inject(ctx, out);

        bool pass = out.count("Uber-Trace-Id") == 0 &&
                    out.count(JaegerPropagator::kHeader) == 1 &&
                    out[JaegerPropagator::kHeader].find(
                        std::string(32, 'a')) == 0 &&
                    out["host"] == "example.com";
        TestFramework::RecordTest(
            "ObsJaeger: Inject(map) strips mixed-case Uber-Trace-Id",
            pass, pass ? "" : "mixed-case duplicate survived inject",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsJaeger: Inject(map) strips mixed-case Uber-Trace-Id",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- CompositePropagator (Task 8.4) ----

void TestCompositeExtractPrecedence() {
    try {
        auto comp = CompositePropagator::Build({"jaeger", "w3c"});
        Propagator::HeadersMap h = {
            {"traceparent",
             "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01"},
            {"uber-trace-id",
             "1234567890abcdef1234567890abcdef:0011223344556677:0:1"}};
        auto ctx = comp->Extract(h);
        bool pass = ctx.has_value()
                  && ctx->trace_id().ToHex()
                      == "1234567890abcdef1234567890abcdef";
        TestFramework::RecordTest(
            "ObsJaeger: composite Extract honors precedence (jaeger first)",
            pass, pass ? "" : "wrong winner",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsJaeger: composite Extract honors precedence (jaeger first)",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestCompositeExtractFallthrough() {
    try {
        auto comp = CompositePropagator::Build({"jaeger", "w3c"});
        Propagator::HeadersMap h = {
            {"traceparent",
             "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01"}};
        auto ctx = comp->Extract(h);
        bool pass = ctx.has_value()
                  && ctx->trace_id().ToHex() == std::string(32, 'a');
        TestFramework::RecordTest(
            "ObsJaeger: composite Extract falls through when first is absent",
            pass, pass ? "" : "fallthrough failed",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsJaeger: composite Extract falls through when first is absent",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestCompositeInjectAll() {
    try {
        auto comp = CompositePropagator::Build({"w3c", "jaeger"});
        SpanContext ctx(TraceId::FromHex(std::string(32, 'c')),
                         SpanId::FromHex("00aabbccddeeff00"),
                         TraceFlags{TraceFlags::kSampled},
                         TraceState{}, /*is_remote=*/false);
        Propagator::HeadersMap out;
        bool ok = comp->Inject(ctx, out);
        bool pass = ok && out.count("traceparent") == 1
                       && out.count("uber-trace-id") == 1;
        TestFramework::RecordTest(
            "ObsJaeger: composite Inject writes all child formats",
            pass, pass ? "" : "missing format(s)",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsJaeger: composite Inject writes all child formats",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestCompositeStripsAllOwnedHeaders() {
    try {
        auto comp = CompositePropagator::Build({"w3c", "jaeger"});
        Propagator::HeadersMap h = {
            {"traceparent", "x"},
            {"tracestate",  "y"},
            {"uber-trace-id", "z"},
            {"x-other", "keep"}};
        comp->StripOwnedHeaders(h);
        bool pass = h.count("traceparent")   == 0
                  && h.count("tracestate")    == 0
                  && h.count("uber-trace-id") == 0
                  && h.count("x-other")       == 1;
        TestFramework::RecordTest(
            "ObsJaeger: composite strips every child-owned header",
            pass, pass ? "" : "strip wrong set",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsJaeger: composite strips every child-owned header",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Vec-form Strip override on Composite delegates to each child's Vec
// StripOwnedHeaders. Verifies (a) every child-owned name is stripped,
// (b) case-insensitive sweep covers mixed-case duplicates, (c)
// non-trace headers are preserved, (d) order of remaining entries is
// preserved (Vec semantics, no map reordering).
void TestCompositeStripsAllOwnedHeadersVec() {
    try {
        auto comp = CompositePropagator::Build({"w3c", "jaeger"});
        std::vector<std::pair<std::string, std::string>> headers;
        headers.emplace_back("traceparent", "x");
        headers.emplace_back("TraceState",  "y");          // mixed case
        headers.emplace_back("Uber-Trace-Id", "z");        // mixed case
        headers.emplace_back("host", "example.com");
        headers.emplace_back("x-other", "keep");

        comp->StripOwnedHeaders(headers);

        size_t tp_count = 0, ts_count = 0, ut_count = 0;
        bool host_kept = false, other_kept = false;
        std::vector<std::string> remaining_order;
        for (const auto& [k, v] : headers) {
            (void)v;
            std::string lk;
            for (char c : k) lk.push_back(
                static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
            if (lk == "traceparent")        ++tp_count;
            else if (lk == "tracestate")     ++ts_count;
            else if (lk == "uber-trace-id")  ++ut_count;
            else if (lk == "host")           host_kept = true;
            else if (lk == "x-other")        other_kept = true;
            remaining_order.push_back(k);
        }
        // Surviving entries must be host then x-other (declaration
        // order); strip must not reorder unrelated headers.
        bool order_preserved = remaining_order.size() == 2 &&
                                remaining_order[0] == "host" &&
                                remaining_order[1] == "x-other";

        bool pass = tp_count == 0 && ts_count == 0 && ut_count == 0 &&
                    host_kept && other_kept && order_preserved;
        TestFramework::RecordTest(
            "ObsJaeger: composite strips every child-owned header (vec form)",
            pass, pass ? ""
                      : "tp=" + std::to_string(tp_count)
                       + " ts=" + std::to_string(ts_count)
                       + " ut=" + std::to_string(ut_count)
                       + " host=" + std::to_string(host_kept)
                       + " other=" + std::to_string(other_kept)
                       + " order_preserved=" + std::to_string(order_preserved),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsJaeger: composite strips every child-owned header (vec form)",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestCompositeBuildEmptyRejected() {
    try {
        bool threw_empty = false;
        try { CompositePropagator::Build({}); }
        catch (const std::invalid_argument&) { threw_empty = true; }

        bool threw_unknown = false;
        try { CompositePropagator::Build({"w3c", "unknown"}); }
        catch (const std::invalid_argument&) { threw_unknown = true; }

        bool pass = threw_empty && threw_unknown;
        TestFramework::RecordTest(
            "ObsJaeger: composite Build rejects empty + unknown",
            pass, pass ? ""
                      : "empty=" + std::to_string(threw_empty)
                       + " unknown=" + std::to_string(threw_unknown),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsJaeger: composite Build rejects empty + unknown",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Build is a public API and ConfigLoader is not its only caller. A
// programmatic / test caller passing ["w3c", "w3c"] would otherwise
// silently produce two W3C children — duplicate header writes and
// ambiguous Extract precedence. Build must reject duplicates itself.
void TestCompositeBuildRejectsDuplicates() {
    try {
        bool threw_dup_w3c = false;
        try { CompositePropagator::Build({"w3c", "w3c"}); }
        catch (const std::invalid_argument&) { threw_dup_w3c = true; }

        bool threw_dup_jaeger = false;
        try { CompositePropagator::Build({"jaeger", "w3c", "jaeger"}); }
        catch (const std::invalid_argument&) { threw_dup_jaeger = true; }

        bool pass = threw_dup_w3c && threw_dup_jaeger;
        TestFramework::RecordTest(
            "ObsJaeger: composite Build rejects duplicate names",
            pass, pass ? ""
                      : "dup_w3c=" + std::to_string(threw_dup_w3c)
                       + " dup_jaeger=" + std::to_string(threw_dup_jaeger),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsJaeger: composite Build rejects duplicate names",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Composite Inject(HeadersVec&) must honor the strip-then-inject
// contract on the vector form. The previous base-default fallback
// only stripped vec keys present in the temp map after each child
// wrote — but a child that intentionally OMITS a header (e.g. W3C
// with empty tracestate) leaves any pre-existing entry of that name
// behind. Pairing fresh traceparent with stale vendor tracestate
// corrupts the trace context for downstream services.
void TestCompositeVecInjectStripsStaleTracestate() {
    try {
        auto comp = CompositePropagator::Build({"w3c", "jaeger"});

        SpanContext ctx;
        ctx.SetTraceId(TraceId::FromHex("0af7651916cd43dd8448eb211c80319c"));
        ctx.SetSpanId(SpanId::FromHex("00f067aa0ba902b7"));
        ctx.SetFlags(TraceFlags{0x01});
        // ctx.state() is default — Empty() == true, so W3C must STRIP
        // tracestate without writing a fresh one.

        std::vector<std::pair<std::string, std::string>> headers;
        headers.emplace_back("traceparent",
            "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-00");
        headers.emplace_back("tracestate", "vendorA=stale,vendorB=alsostale");
        headers.emplace_back("uber-trace-id",
            "ffffffffffffffffffffffffffffffff:0000000000000001:0:00");
        headers.emplace_back("host", "example.com");

        bool ok = comp->Inject(ctx, headers);

        size_t ts_count = 0;
        size_t tp_count = 0;
        size_t ut_count = 0;
        bool has_host = false;
        for (const auto& [k, v] : headers) {
            (void)v;
            std::string lk;
            for (char c : k) lk.push_back(
                static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
            if (lk == "tracestate")          ++ts_count;
            else if (lk == "traceparent")     ++tp_count;
            else if (lk == "uber-trace-id")   ++ut_count;
            else if (lk == "host")            has_host = true;
        }
        // Stale tracestate must be gone. Fresh traceparent and fresh
        // uber-trace-id each appear exactly once.
        bool pass = ok &&
                    ts_count == 0 &&
                    tp_count == 1 &&
                    ut_count == 1 &&
                    has_host;
        TestFramework::RecordTest(
            "ObsJaeger: composite Inject(vec) strips stale tracestate when ctx.state empty",
            pass, pass ? ""
                      : "ts=" + std::to_string(ts_count)
                       + " tp=" + std::to_string(tp_count)
                       + " ut=" + std::to_string(ut_count)
                       + " host=" + std::to_string(has_host),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsJaeger: composite Inject(vec) strips stale tracestate when ctx.state empty",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void RunAllTests() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "OBSERVABILITY JAEGER PROPAGATOR TESTS" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    TestParse128BitTraceId();
    TestParse64BitTraceIdLeftPads();
    TestParseLegacyZeroParent();
    TestParseUnsampledFlag();
    TestParseRejectsMalformed();
    TestParseHeaderAbsent();
    TestStripOwnedHeaders();
    TestStripOwnedHeadersCaseInsensitive();
    TestExtractCaseInsensitive();
    TestNameIsJaeger();
    TestInjectAlways128Bit();
    TestInjectUnsampledFlagsZero();
    TestInjectInvalidContextNoOp();
    TestInjectStripReplace();
    TestInjectMapStripsMixedCaseDuplicate();
    TestCompositeExtractPrecedence();
    TestCompositeExtractFallthrough();
    TestCompositeInjectAll();
    TestCompositeStripsAllOwnedHeaders();
    TestCompositeStripsAllOwnedHeadersVec();
    TestCompositeBuildEmptyRejected();
    TestCompositeBuildRejectsDuplicates();
    TestCompositeVecInjectStripsStaleTracestate();
}

}  // namespace ObservabilityJaegerPropagatorTests
