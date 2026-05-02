#pragma once

#include "test_framework.h"
#include "observability/attr_value.h"
#include "observability/span_context.h"
#include "observability/trace_id.h"
#include "observability/trace_state.h"

#include <unordered_set>
#include <string>

// Foundational value-type tests for the OpenTelemetry observability
// pipeline (task #62). Covers the pure value types only — Span /
// Tracer / Meter / exporter pipeline tests live in
// observability_test.h once those slices land.

namespace ObservabilityFoundationTests {

using OBSERVABILITY_NAMESPACE::AttrValue;
using OBSERVABILITY_NAMESPACE::LabelSet;
using OBSERVABILITY_NAMESPACE::RandomSource;
using OBSERVABILITY_NAMESPACE::SpanContext;
using OBSERVABILITY_NAMESPACE::SpanId;
using OBSERVABILITY_NAMESPACE::TraceFlags;
using OBSERVABILITY_NAMESPACE::TraceId;
using OBSERVABILITY_NAMESPACE::TraceState;

// ---------------------------------------------------------------------------
// TraceId / SpanId hex round-trip
// ---------------------------------------------------------------------------
void TestTraceIdHexRoundTrip() {
    try {
        const std::string hex = "0af7651916cd43dd8448eb211c80319c";
        TraceId id = TraceId::FromHex(hex);
        bool pass = id.IsValid() && id.ToHex() == hex;
        TestFramework::RecordTest(
            "ObsFoundation: TraceId hex round-trip",
            pass, pass ? "" : "round-trip mismatch: " + id.ToHex(),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsFoundation: TraceId hex round-trip",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestSpanIdHexRoundTrip() {
    try {
        const std::string hex = "00f067aa0ba902b7";
        SpanId id = SpanId::FromHex(hex);
        bool pass = id.IsValid() && id.ToHex() == hex;
        TestFramework::RecordTest(
            "ObsFoundation: SpanId hex round-trip",
            pass, pass ? "" : "round-trip mismatch: " + id.ToHex(),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsFoundation: SpanId hex round-trip",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// All-zero is invalid per W3C.
void TestTraceIdAllZeroInvalid() {
    try {
        TraceId id = TraceId::FromHex("00000000000000000000000000000000");
        bool pass = !id.IsValid();
        TestFramework::RecordTest(
            "ObsFoundation: TraceId all-zero is invalid",
            pass, pass ? "" : "all-zero TraceId reported valid",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsFoundation: TraceId all-zero is invalid",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Wrong length / non-hex chars produce an invalid id.
void TestTraceIdMalformedRejected() {
    try {
        // Wrong length (31 chars).
        TraceId a = TraceId::FromHex("0af7651916cd43dd8448eb211c80319");
        // Non-hex char.
        TraceId b = TraceId::FromHex("0af7651916cd43dd8448eb211c80319z");
        bool pass = !a.IsValid() && !b.IsValid();
        TestFramework::RecordTest(
            "ObsFoundation: TraceId malformed rejected",
            pass, pass ? "" : "malformed TraceId not rejected",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsFoundation: TraceId malformed rejected",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// TraceFlags sampled bit round-trip.
void TestTraceFlagsSampled() {
    try {
        TraceFlags f{0x00};
        bool pass = !f.IsSampled();
        f.SetSampled(true);
        pass = pass && f.IsSampled() && f.value == 0x01;
        f.SetSampled(false);
        pass = pass && !f.IsSampled() && f.value == 0x00;
        // Preserves reserved bits.
        TraceFlags g{0xfe};
        g.SetSampled(true);
        pass = pass && g.value == 0xff;
        TestFramework::RecordTest(
            "ObsFoundation: TraceFlags sampled bit round-trip",
            pass, pass ? "" : "sampled bit toggle wrong",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsFoundation: TraceFlags sampled bit round-trip",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// RandomSource produces non-zero, non-colliding ids
// ---------------------------------------------------------------------------
void TestRandomSourceNonZero() {
    try {
        RandomSource src(0x1234567890abcdefULL);
        bool pass = true;
        // Generate 1000 trace ids; each must be valid (non-zero) and
        // sufficiently distinct (no exact duplicates in the batch).
        std::unordered_set<std::string> seen;
        for (int i = 0; i < 1000; ++i) {
            TraceId t = src.NewTraceId();
            if (!t.IsValid()) { pass = false; break; }
            std::string hex = t.ToHex();
            if (!seen.insert(hex).second) { pass = false; break; }
        }
        TestFramework::RecordTest(
            "ObsFoundation: RandomSource produces 1000 distinct non-zero TraceIds",
            pass, pass ? "" : "duplicate or zero TraceId in batch",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsFoundation: RandomSource produces 1000 distinct non-zero TraceIds",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// TraceState parser / writer
// ---------------------------------------------------------------------------
void TestTraceStateRoundTrip() {
    try {
        auto ts = TraceState::Parse("vendor1=abc,vendor2=xyz");
        bool pass = ts.has_value() &&
                    ts->Size() == 2 &&
                    ts->Get("vendor1") == "abc" &&
                    ts->Get("vendor2") == "xyz" &&
                    ts->Serialize() == "vendor1=abc,vendor2=xyz";
        TestFramework::RecordTest(
            "ObsFoundation: TraceState parse + serialize round-trip",
            pass, pass ? "" : "round-trip mismatch",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsFoundation: TraceState parse + serialize round-trip",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// >32 list-members → drop the entire tracestate per W3C.
void TestTraceStateOversized() {
    try {
        std::string header;
        for (int i = 0; i < 33; ++i) {
            if (!header.empty()) header.push_back(',');
            header += "k" + std::to_string(i) + "=v" + std::to_string(i);
        }
        auto ts = TraceState::Parse(header);
        bool pass = !ts.has_value();
        TestFramework::RecordTest(
            "ObsFoundation: TraceState oversized (33 members) dropped",
            pass, pass ? "" : "33-member tracestate not rejected",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsFoundation: TraceState oversized (33 members) dropped",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Set-on-existing-key moves the entry to the head per W3C §3.3.
void TestTraceStateSetMovesToHead() {
    try {
        auto ts = TraceState::Parse("a=1,b=2,c=3");
        if (!ts.has_value()) {
            TestFramework::RecordTest(
                "ObsFoundation: TraceState Set moves key to head",
                false, "parse failed", TestFramework::TestCategory::OTHER);
            return;
        }
        ts->Set("b", "99");
        bool pass = ts->Serialize() == "b=99,a=1,c=3";
        TestFramework::RecordTest(
            "ObsFoundation: TraceState Set moves key to head",
            pass, pass ? "" : "got: " + ts->Serialize(),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsFoundation: TraceState Set moves key to head",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestTraceStateEmptyParse() {
    try {
        auto ts = TraceState::Parse("");
        bool pass = ts.has_value() && ts->Empty() && ts->Serialize().empty();
        TestFramework::RecordTest(
            "ObsFoundation: TraceState empty header parses to empty",
            pass, pass ? "" : "empty header mishandled",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsFoundation: TraceState empty header parses to empty",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// SpanContext validity rules
// ---------------------------------------------------------------------------
void TestSpanContextValidity() {
    try {
        TraceId tid = TraceId::FromHex("0af7651916cd43dd8448eb211c80319c");
        SpanId  sid = SpanId::FromHex("00f067aa0ba902b7");
        SpanContext sc(tid, sid, TraceFlags{0x01}, TraceState{}, /*is_remote=*/true);
        bool pass = sc.IsValid() && sc.is_remote() && sc.flags().IsSampled();

        SpanContext invalid;  // default → all-zero ids
        pass = pass && !invalid.IsValid();
        TestFramework::RecordTest(
            "ObsFoundation: SpanContext validity rules",
            pass, pass ? "" : "validity check wrong",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsFoundation: SpanContext validity rules",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// LabelSet sort + hash determinism
// ---------------------------------------------------------------------------
void TestLabelSetSortAndHash() {
    try {
        // Two LabelSets with the same kv pairs but different insertion
        // orders must produce the same hash AFTER SortAndHash.
        LabelSet a;
        a.kv = {{"method", "GET"}, {"route", "/users/:id"}, {"status", "200"}};
        a.SortAndHash();

        LabelSet b;
        b.kv = {{"status", "200"}, {"method", "GET"}, {"route", "/users/:id"}};
        b.SortAndHash();

        bool pass = a.hash == b.hash && a.kv == b.kv;

        // A different value on one key must produce a different hash.
        LabelSet c;
        c.kv = {{"method", "POST"}, {"route", "/users/:id"}, {"status", "200"}};
        c.SortAndHash();
        pass = pass && c.hash != a.hash;

        TestFramework::RecordTest(
            "ObsFoundation: LabelSet sort + hash determinism",
            pass, pass ? "" : "hash collision or order-sensitivity",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsFoundation: LabelSet sort + hash determinism",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------------
// AttrValue tagged-union variants
// ---------------------------------------------------------------------------
void TestAttrValueVariants() {
    try {
        AttrValue v_unset;
        AttrValue v_bool(true);
        AttrValue v_int(int64_t{42});
        AttrValue v_double(3.14);
        AttrValue v_str(std::string{"hello"});

        bool pass = v_unset.IsUnset() &&
                    !v_bool.IsUnset() &&
                    std::holds_alternative<bool>(v_bool.value) &&
                    std::get<bool>(v_bool.value) == true &&
                    std::holds_alternative<int64_t>(v_int.value) &&
                    std::get<int64_t>(v_int.value) == 42 &&
                    std::holds_alternative<double>(v_double.value) &&
                    std::get<double>(v_double.value) == 3.14 &&
                    std::holds_alternative<std::string>(v_str.value) &&
                    std::get<std::string>(v_str.value) == "hello";
        TestFramework::RecordTest(
            "ObsFoundation: AttrValue tagged-union variants",
            pass, pass ? "" : "variant access wrong",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsFoundation: AttrValue tagged-union variants",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void RunAllTests() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "OBSERVABILITY FOUNDATION - VALUE-TYPE TESTS" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    TestTraceIdHexRoundTrip();
    TestSpanIdHexRoundTrip();
    TestTraceIdAllZeroInvalid();
    TestTraceIdMalformedRejected();
    TestTraceFlagsSampled();
    TestRandomSourceNonZero();
    TestTraceStateRoundTrip();
    TestTraceStateOversized();
    TestTraceStateSetMovesToHead();
    TestTraceStateEmptyParse();
    TestSpanContextValidity();
    TestLabelSetSortAndHash();
    TestAttrValueVariants();
}

}  // namespace ObservabilityFoundationTests
