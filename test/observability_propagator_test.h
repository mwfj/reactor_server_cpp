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
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace ObservabilityPropagatorTests {

using OBSERVABILITY_NAMESPACE::Propagator;
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
        auto ctx = W3CPropagator{}.ParseTraceparent(hdr);
        bool pass = ctx.has_value() && ctx->IsValid() && ctx->is_remote() &&
                    ctx->trace_id().ToHex() == "0af7651916cd43dd8448eb211c80319c" &&
                    ctx->span_id().ToHex() == "00f067aa0ba902b7" &&
                    ctx->flags().IsSampled();
        if (pass) {
            auto out = W3CPropagator{}.SerializeTraceparent(*ctx);
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
            auto ctx = W3CPropagator{}.ParseTraceparent(v.hdr);
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
        auto a = W3CPropagator{}.ParseTraceparent(sampled);
        auto b = W3CPropagator{}.ParseTraceparent(unsampled);
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
        auto ctx = W3CPropagator{}.Extract(headers);
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

        auto ctx = W3CPropagator{}.Extract(headers);
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
        auto ctx = W3CPropagator{}.Extract(headers);
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
        bool ok = W3CPropagator{}.Inject(ctx, headers);
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

        bool ok = W3CPropagator{}.Inject(ctx, headers);
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

// Inject into a vector with EMPTY tracestate must still strip a pre-
// existing tracestate. The contract is strip-then-inject; leaving stale
// vendor state paired with a fresh traceparent corrupts the trace
// context for downstream services.
void TestInjectStripsTracestateOnEmptyState() {
    try {
        SpanContext ctx;
        ctx.SetTraceId(TraceId::FromHex("0af7651916cd43dd8448eb211c80319c"));
        ctx.SetSpanId(SpanId::FromHex("00f067aa0ba902b7"));
        ctx.SetFlags(TraceFlags{0x01});
        // Default-constructed TraceState ⇒ Empty() == true.

        std::vector<std::pair<std::string, std::string>> headers;
        headers.emplace_back("traceparent", "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-00");
        headers.emplace_back("TraceState", "vendorA=stale,vendorB=alsostale");
        headers.emplace_back("host", "example.com");

        bool ok = W3CPropagator{}.Inject(ctx, headers);
        size_t ts_count = 0;
        for (const auto& [k, v] : headers) {
            (void)v;
            std::string lk;
            for (char c : k) lk.push_back(
                static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
            if (lk == "tracestate") ++ts_count;
        }
        bool pass = ok && ts_count == 0;
        TestFramework::RecordTest(
            "ObsProp: Inject strips stale tracestate even when new state is empty",
            pass, pass ? "" : "stale tracestate left in headers",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsProp: Inject strips stale tracestate even when new state is empty",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Inject(HeadersMap&) honors strip-then-inject for mixed-case
// duplicates. The map upsert below would otherwise leave a
// client-supplied "Traceparent" entry alongside the canonical
// lowercase one — the upstream would see two trace headers and the
// spoofing-defense documented in the design would fail.
void TestInjectMapStripsMixedCaseDuplicates() {
    try {
        SpanContext ctx;
        ctx.SetTraceId(TraceId::FromHex("0af7651916cd43dd8448eb211c80319c"));
        ctx.SetSpanId(SpanId::FromHex("00f067aa0ba902b7"));
        ctx.SetFlags(TraceFlags{0x01});

        std::map<std::string, std::string> headers;
        // Pre-existing client-supplied mixed-case copies (a forging
        // client would write these to escape the lowercase upsert).
        headers["Traceparent"] = "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-00";
        headers["TraceState"] = "vendorA=stale";
        headers["host"] = "example.com";

        bool ok = W3CPropagator{}.Inject(ctx, headers);
        // After Inject: only canonical lowercase entries should remain
        // for the propagator-owned keys.
        bool pass = ok &&
                    headers.count("Traceparent") == 0 &&
                    headers.count("TraceState") == 0 &&
                    headers.count("traceparent") == 1 &&
                    // Empty tracestate => no canonical entry either.
                    headers.count("tracestate") == 0 &&
                    headers["traceparent"] ==
                        "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01" &&
                    headers["host"] == "example.com";
        TestFramework::RecordTest(
            "ObsProp: Inject(map) strips mixed-case Traceparent/TraceState",
            pass, pass ? "" : "mixed-case duplicate survived inject",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsProp: Inject(map) strips mixed-case Traceparent/TraceState",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Test-only Propagator subclass that conditionally omits a header in
// Inject(HeadersMap&). Exercises the base-default Inject(HeadersVec&)
// path: future propagators may rely on the documented strip-then-inject
// contract without overriding the Vec form.
class ConditionalOmitPropagator : public Propagator {
public:
    static constexpr const char* kAlwaysHeader   = "x-test-always";
    static constexpr const char* kSometimesHeader = "x-test-sometimes";

    // Bring the base Inject(HeadersVec&) into scope — overriding the
    // Map-form alone would otherwise hide it via name lookup.
    using Propagator::Inject;

    std::optional<SpanContext> Extract(const HeadersMap&) const override {
        return std::nullopt;
    }
    bool Inject(const SpanContext& ctx, HeadersMap& headers) const override {
        if (!ctx.IsValid()) return false;
        headers[kAlwaysHeader] = "1";
        // Conditionally omit kSometimesHeader. The base default for
        // Inject(HeadersVec&) must still strip both owned headers from
        // the vec, otherwise a stale x-test-sometimes survives.
        if (ctx.flags().IsSampled()) {
            headers[kSometimesHeader] = "1";
        }
        return true;
    }
    void StripOwnedHeaders(HeadersMap& h) const override {
        h.erase(kAlwaysHeader);
        h.erase(kSometimesHeader);
    }
    const char* Name() const noexcept override { return "test_omit"; }
};

// Base-default Inject(HeadersVec&) must strip the FULL owned-key set,
// not just the keys the child Inject happened to write. A child that
// conditionally omits a header (e.g. W3C with empty tracestate) would
// otherwise leave a stale entry for that name behind on the wire.
void TestBaseInjectVecStripsOmittedOwnedHeaders() {
    try {
        ConditionalOmitPropagator p;
        SpanContext ctx;
        ctx.SetTraceId(TraceId::FromHex("0af7651916cd43dd8448eb211c80319c"));
        ctx.SetSpanId(SpanId::FromHex("00f067aa0ba902b7"));
        // Unsampled — Inject(HeadersMap&) writes only kAlwaysHeader.
        ctx.SetFlags(TraceFlags{0x00});

        std::vector<std::pair<std::string, std::string>> headers;
        headers.emplace_back("x-test-always", "stale");
        headers.emplace_back("x-test-sometimes", "stale");
        headers.emplace_back("host", "example.com");

        bool ok = p.Inject(ctx, headers);

        size_t always_count = 0;
        size_t sometimes_count = 0;
        bool host_kept = false;
        for (const auto& [k, v] : headers) {
            (void)v;
            if (k == "x-test-always")     ++always_count;
            else if (k == "x-test-sometimes") ++sometimes_count;
            else if (k == "host")             host_kept = true;
        }
        // Conditionally-omitted x-test-sometimes must be stripped even
        // though the child Inject(HeadersMap&) didn't write it.
        bool pass = ok &&
                    always_count == 1 &&
                    sometimes_count == 0 &&
                    host_kept;
        TestFramework::RecordTest(
            "ObsProp: base Inject(vec) strips full owned-key set including omitted",
            pass, pass ? ""
                      : "always=" + std::to_string(always_count)
                       + " sometimes=" + std::to_string(sometimes_count)
                       + " host=" + std::to_string(host_kept),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsProp: base Inject(vec) strips full owned-key set including omitted",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Inject with invalid context returns false + does not mutate headers.
void TestInjectInvalidContextNoOp() {
    try {
        SpanContext ctx;  // default — all-zero ids, IsValid() == false
        std::map<std::string, std::string> headers;
        headers["host"] = "example.com";
        bool ok = W3CPropagator{}.Inject(ctx, headers);
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

// W3CPropagator must satisfy the Propagator base interface so the
// composite can fan calls across multiple propagators uniformly.
void TestW3CPropagatorImplementsInterface() {
    try {
        std::unique_ptr<Propagator> p =
            std::make_unique<W3CPropagator>();
        std::map<std::string, std::string> headers = {
            {"traceparent",
             "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01"}};
        auto ctx = p->Extract(headers);
        bool extracted = ctx.has_value()
                       && ctx->trace_id().ToHex()
                           == "0af7651916cd43dd8448eb211c80319c";

        std::map<std::string, std::string> out;
        bool injected = ctx.has_value() && p->Inject(*ctx, out)
                      && out.count("traceparent") == 1;

        std::map<std::string, std::string> stripped = headers;
        p->StripOwnedHeaders(stripped);
        bool stripped_ok = stripped.count("traceparent") == 0
                         && stripped.count("tracestate") == 0;

        bool name_ok = std::string(p->Name()) == "w3c";
        bool pass = extracted && injected && stripped_ok && name_ok;
        TestFramework::RecordTest(
            "ObsProp: W3CPropagator implements Propagator interface",
            pass, pass ? ""
                      : "extracted=" + std::to_string(extracted)
                       + " injected=" + std::to_string(injected)
                       + " stripped=" + std::to_string(stripped_ok)
                       + " name=" + std::to_string(name_ok),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsProp: W3CPropagator implements Propagator interface",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Mixed-case duplicates ("Traceparent", "TRACESTATE") must be scrubbed
// by the strip sweep — the EqualsLowerAscii hot-path replacement
// (no per-iteration std::string allocation) must remain functionally
// equivalent to the prior ToLower-based loop.
void TestW3CStripCaseInsensitive() {
    try {
        W3CPropagator p;
        std::map<std::string, std::string> h = {
            {"Traceparent", "00-0af7651916cd43dd8448eb211c80319c"
                            "-b7ad6b7169203331-01"},
            {"TRACESTATE",  "vendor=value"},
            {"content-type", "application/json"}};
        p.StripOwnedHeaders(h);
        bool pass = h.count("Traceparent") == 0
                  && h.count("TRACESTATE")  == 0
                  && h.count("traceparent") == 0
                  && h.count("tracestate")  == 0
                  && h.count("content-type") == 1;
        TestFramework::RecordTest(
            "ObsProp: StripOwnedHeaders is case-insensitive",
            pass, pass ? "" : "case-variant traceparent/tracestate leaked",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsProp: StripOwnedHeaders is case-insensitive",
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
    TestInjectStripsTracestateOnEmptyState();
    TestInjectMapStripsMixedCaseDuplicates();
    TestBaseInjectVecStripsOmittedOwnedHeaders();
    TestInjectInvalidContextNoOp();
    TestW3CPropagatorImplementsInterface();
    TestW3CStripCaseInsensitive();
}

}  // namespace ObservabilityPropagatorTests
