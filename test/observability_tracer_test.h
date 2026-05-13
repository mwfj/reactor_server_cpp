#pragma once

// Tracer / Sampler / Span unit tests. No I/O — uses
// InMemorySpanProcessor to capture finished SpanData for inspection.

#include "test_framework.h"
#include "observability/instrumentation_scope.h"
#include "observability/resource.h"
#include "observability/sampler.h"
#include "observability/span.h"
#include "observability/span_processor.h"
#include "observability/trace_id.h"
#include "observability/tracer.h"
#include "observability/tracer_provider.h"

#include <memory>
#include <stdexcept>
#include <string>

namespace ObservabilityTracerTests {

using OBSERVABILITY_NAMESPACE::AlwaysOffSampler;
using OBSERVABILITY_NAMESPACE::AlwaysOnSampler;
using OBSERVABILITY_NAMESPACE::AttrValue;
using OBSERVABILITY_NAMESPACE::InMemorySpanProcessor;
using OBSERVABILITY_NAMESPACE::ParentBasedSampler;
using OBSERVABILITY_NAMESPACE::ProcessorOptions;
using OBSERVABILITY_NAMESPACE::RandomSource;
using OBSERVABILITY_NAMESPACE::Resource;
using OBSERVABILITY_NAMESPACE::SamplingDecision;
using OBSERVABILITY_NAMESPACE::Sampler;
using OBSERVABILITY_NAMESPACE::Span;
using OBSERVABILITY_NAMESPACE::SpanContext;
using OBSERVABILITY_NAMESPACE::SpanData;
using OBSERVABILITY_NAMESPACE::SpanKind;
using OBSERVABILITY_NAMESPACE::SpanStatusCode;
using OBSERVABILITY_NAMESPACE::StartSpanOptions;
using OBSERVABILITY_NAMESPACE::TraceFlags;
using OBSERVABILITY_NAMESPACE::TraceId;
using OBSERVABILITY_NAMESPACE::Tracer;
using OBSERVABILITY_NAMESPACE::TracerProvider;
using OBSERVABILITY_NAMESPACE::TraceIdRatioSampler;

namespace {
struct Bench {
    std::shared_ptr<InMemorySpanProcessor> processor =
        std::make_shared<InMemorySpanProcessor>();
    std::shared_ptr<Resource>     resource = std::make_shared<Resource>();
    std::shared_ptr<RandomSource> random   = std::make_shared<RandomSource>(0xCAFEBABEULL);
    std::unique_ptr<TracerProvider> provider;

    explicit Bench(std::shared_ptr<const Sampler> sampler =
                       std::make_shared<AlwaysOnSampler>())
        : provider(std::make_unique<TracerProvider>(
              resource, processor, std::move(sampler), random,
              /*manager=*/nullptr)) {}

    Tracer* tracer() { return provider->GetTracer("test", "1.0"); }
};
}  // namespace

// ---- Sampler unit tests ----
void TestAlwaysOnSampler() {
    try {
        AlwaysOnSampler s;
        TraceId t = TraceId::FromHex("0af7651916cd43dd8448eb211c80319c");
        auto r = s.ShouldSample({}, t, "name", SpanKind::SERVER);
        bool pass = r.decision == SamplingDecision::RECORD_AND_SAMPLE &&
                    s.Description() == "always_on";
        TestFramework::RecordTest("ObsTracer: AlwaysOnSampler",
            pass, pass ? "" : "decision wrong",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsTracer: AlwaysOnSampler",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestAlwaysOffSampler() {
    try {
        AlwaysOffSampler s;
        TraceId t = TraceId::FromHex("0af7651916cd43dd8448eb211c80319c");
        auto r = s.ShouldSample({}, t, "name", SpanKind::SERVER);
        bool pass = r.decision == SamplingDecision::DROP &&
                    s.Description() == "always_off";
        TestFramework::RecordTest("ObsTracer: AlwaysOffSampler",
            pass, pass ? "" : "decision wrong",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsTracer: AlwaysOffSampler",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Ratio sampler — ratio=0 drops all, ratio=1 samples all,
// ratio=0.5 samples roughly half.
void TestTraceIdRatioSampler() {
    try {
        TraceIdRatioSampler s_zero(0.0);
        TraceIdRatioSampler s_one(1.0);
        TraceIdRatioSampler s_half(0.5);

        RandomSource rng(0xAABBCCDDULL);
        int sampled_zero = 0, sampled_one = 0, sampled_half = 0;
        constexpr int N = 2000;
        for (int i = 0; i < N; ++i) {
            TraceId t = rng.NewTraceId();
            if (s_zero.ShouldSample({}, t, "n", SpanKind::INTERNAL).decision ==
                SamplingDecision::RECORD_AND_SAMPLE) ++sampled_zero;
            if (s_one.ShouldSample({}, t, "n", SpanKind::INTERNAL).decision ==
                SamplingDecision::RECORD_AND_SAMPLE) ++sampled_one;
            if (s_half.ShouldSample({}, t, "n", SpanKind::INTERNAL).decision ==
                SamplingDecision::RECORD_AND_SAMPLE) ++sampled_half;
        }

        // ratio=0 should sample 0; ratio=1 should sample N; ratio=0.5
        // should sample within ±15% of N/2 (sampler is deterministic
        // per-trace_id so this is a strict probabilistic bound on
        // 2000 random ids).
        bool pass = sampled_zero == 0 &&
                    sampled_one == N &&
                    std::abs(sampled_half - N/2) < N/7;  // ~14% slack
        std::string err;
        if (!pass) {
            err = "sampled_zero=" + std::to_string(sampled_zero) +
                  " sampled_one=" + std::to_string(sampled_one) +
                  " sampled_half=" + std::to_string(sampled_half);
        }
        TestFramework::RecordTest("ObsTracer: TraceIdRatioSampler distribution",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsTracer: TraceIdRatioSampler distribution",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Same trace_id always lands the same way (deterministic per-trace).
void TestTraceIdRatioSamplerDeterministic() {
    try {
        TraceIdRatioSampler s(0.5);
        RandomSource rng(0xDEADBEEFULL);
        for (int i = 0; i < 100; ++i) {
            TraceId t = rng.NewTraceId();
            auto r1 = s.ShouldSample({}, t, "n", SpanKind::INTERNAL);
            auto r2 = s.ShouldSample({}, t, "n", SpanKind::INTERNAL);
            if (r1.decision != r2.decision) {
                TestFramework::RecordTest(
                    "ObsTracer: TraceIdRatioSampler is per-trace deterministic",
                    false, "non-deterministic decision",
                    TestFramework::TestCategory::OTHER);
                return;
            }
        }
        TestFramework::RecordTest(
            "ObsTracer: TraceIdRatioSampler is per-trace deterministic",
            true, "", TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsTracer: TraceIdRatioSampler is per-trace deterministic",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestParentBasedSamplerInheritsParent() {
    try {
        auto root = std::make_shared<AlwaysOnSampler>();
        ParentBasedSampler s(root);

        TraceId t = TraceId::FromHex("0af7651916cd43dd8448eb211c80319c");

        // Sampled remote parent → record and sample (defers to parent flag).
        SpanContext sampled_parent(
            t, TraceId::FromHex("00f067aa0ba902b7").bytes.size() == 8
                   ? OBSERVABILITY_NAMESPACE::SpanId::FromHex("00f067aa0ba902b7")
                   : OBSERVABILITY_NAMESPACE::SpanId{},
            TraceFlags{0x01}, OBSERVABILITY_NAMESPACE::TraceState{}, true);
        auto r1 = s.ShouldSample(sampled_parent, t, "n", SpanKind::SERVER);

        // Non-sampled remote parent + no remote_not_sampled override → drop.
        SpanContext unsampled_parent(
            t, OBSERVABILITY_NAMESPACE::SpanId::FromHex("00f067aa0ba902b7"),
            TraceFlags{0x00}, OBSERVABILITY_NAMESPACE::TraceState{}, true);
        auto r2 = s.ShouldSample(unsampled_parent, t, "n", SpanKind::SERVER);

        // Root span → defer to root sampler (always_on).
        auto r3 = s.ShouldSample({}, t, "n", SpanKind::SERVER);

        bool pass =
            r1.decision == SamplingDecision::RECORD_AND_SAMPLE &&
            r2.decision == SamplingDecision::DROP &&
            r3.decision == SamplingDecision::RECORD_AND_SAMPLE;
        TestFramework::RecordTest(
            "ObsTracer: ParentBasedSampler inherits parent decision",
            pass, pass ? "" : "decision wrong",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsTracer: ParentBasedSampler inherits parent decision",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- Tracer / Span lifecycle tests ----

void TestStartSpanRecordsAndExports() {
    try {
        Bench b;
        auto span = b.tracer()->StartSpan("op", {});
        bool pass = span && span->IsRecording() && span->Context().IsValid();
        span->SetAttribute("k", AttrValue(int64_t{42}));
        span->End();
        // After End, IsRecording flips false and SpanData lands in processor.
        pass = pass && !span->IsRecording();
        auto drained = b.processor->Drain();
        pass = pass && drained.size() == 1 &&
               drained[0].name == "op" &&
               drained[0].attributes.size() == 1 &&
               drained[0].attributes[0].key == "k";
        TestFramework::RecordTest(
            "ObsTracer: StartSpan records + End exports SpanData",
            pass, pass ? "" : "lifecycle wrong",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsTracer: StartSpan records + End exports SpanData",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// AlwaysOff sampler → span returned but IsRecording=false; End is a noop.
void TestAlwaysOffSpanHasNoExport() {
    try {
        Bench b(std::make_shared<AlwaysOffSampler>());
        auto span = b.tracer()->StartSpan("op", {});
        bool pass = span && !span->IsRecording();
        span->End();
        auto drained = b.processor->Drain();
        pass = pass && drained.empty();
        TestFramework::RecordTest(
            "ObsTracer: AlwaysOff span IsRecording=false, no export",
            pass, pass ? "" : "AlwaysOff span exported",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsTracer: AlwaysOff span IsRecording=false, no export",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// End is idempotent — repeat End() doesn't re-export.
void TestEndIdempotent() {
    try {
        Bench b;
        auto span = b.tracer()->StartSpan("op");
        span->End();
        span->End();
        span->End();
        auto drained = b.processor->Drain();
        bool pass = drained.size() == 1;
        TestFramework::RecordTest(
            "ObsTracer: Span::End is idempotent",
            pass, pass ? "" : "End fired multiple times",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsTracer: Span::End is idempotent",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// DropWithoutEnd cancels OnEnd dispatch.
void TestDropWithoutEnd() {
    try {
        Bench b;
        auto span = b.tracer()->StartSpan("op");
        span->DropWithoutEnd();
        span->End();  // no-op after Drop
        auto drained = b.processor->Drain();
        bool pass = drained.empty() && !span->IsRecording();
        TestFramework::RecordTest(
            "ObsTracer: DropWithoutEnd cancels OnEnd",
            pass, pass ? "" : "OnEnd fired despite Drop",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsTracer: DropWithoutEnd cancels OnEnd",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// precomputed_context: span_id matches the precomputed value verbatim.
void TestPrecomputedContext() {
    try {
        Bench b;
        // Build a precomputed context with a known span_id.
        SpanContext ctx;
        ctx.SetTraceId(TraceId::FromHex("0af7651916cd43dd8448eb211c80319c"));
        ctx.SetSpanId(OBSERVABILITY_NAMESPACE::SpanId::FromHex("00f067aa0ba902b7"));
        ctx.SetFlags(TraceFlags{0x01});

        StartSpanOptions opts;
        opts.kind = SpanKind::CLIENT;
        opts.precomputed_context = ctx;
        opts.has_precomputed_context = true;

        auto span = b.tracer()->StartSpan("client_op", opts);
        bool pass = span->Context().trace_id() == ctx.trace_id() &&
                    span->Context().span_id() == ctx.span_id();
        span->End();
        auto drained = b.processor->Drain();
        pass = pass && drained.size() == 1 &&
               drained[0].context.span_id() == ctx.span_id();
        TestFramework::RecordTest(
            "ObsTracer: precomputed_context preserves span_id verbatim",
            pass, pass ? "" : "span_id mismatch",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsTracer: precomputed_context preserves span_id verbatim",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Parent inheritance: child span's trace_id matches parent's.
void TestSpanInheritsParentTraceId() {
    try {
        Bench b;
        auto parent = b.tracer()->StartSpan("parent");
        StartSpanOptions opts;
        opts.has_parent = true;
        opts.parent = parent->Context();
        opts.kind = SpanKind::CLIENT;
        auto child = b.tracer()->StartSpan("child", opts);

        bool pass =
            child->Context().trace_id() == parent->Context().trace_id() &&
            child->Context().span_id() != parent->Context().span_id();
        parent->End();
        child->End();
        TestFramework::RecordTest(
            "ObsTracer: child span inherits parent trace_id, fresh span_id",
            pass, pass ? "" : "trace_id / span_id rules wrong",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsTracer: child span inherits parent trace_id, fresh span_id",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// SetStatus: ERROR overrides UNSET, but OK→ERROR transition is forbidden.
void TestSpanStatusTransition() {
    try {
        Bench b;
        auto a = b.tracer()->StartSpan("a");
        a->SetStatus(SpanStatusCode::ERROR, "boom");
        a->End();
        auto da = b.processor->Drain();

        auto bspan = b.tracer()->StartSpan("b");
        bspan->SetStatus(SpanStatusCode::OK, "fine");
        bspan->SetStatus(SpanStatusCode::ERROR, "should not stick");
        bspan->End();
        auto db = b.processor->Drain();

        bool pass = da.size() == 1 &&
                    da[0].status_code == SpanStatusCode::ERROR &&
                    db.size() == 1 &&
                    db[0].status_code == SpanStatusCode::OK;
        TestFramework::RecordTest(
            "ObsTracer: SetStatus ERROR sticks; OK→ERROR is forbidden",
            pass, pass ? "" : "status transition wrong",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsTracer: SetStatus ERROR sticks; OK→ERROR is forbidden",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// TracerProvider::GetTracer caches per (name, version).
void TestProviderCachesTracers() {
    try {
        Bench b;
        Tracer* a = b.provider->GetTracer("svc", "1.0");
        Tracer* a2 = b.provider->GetTracer("svc", "1.0");
        Tracer* b2 = b.provider->GetTracer("svc", "1.1");
        bool pass = a == a2 && a != b2;
        TestFramework::RecordTest(
            "ObsTracer: TracerProvider caches per (name, version)",
            pass, pass ? "" : "caching wrong",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsTracer: TracerProvider caches per (name, version)",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Reload swaps sampler — new spans see the new decision.
void TestProviderReloadSwapsSampler() {
    try {
        Bench b(std::make_shared<AlwaysOnSampler>());
        auto on_span = b.tracer()->StartSpan("on");
        bool was_recording_on = on_span->IsRecording();
        on_span->End();
        b.processor->Drain();

        b.provider->Reload(std::make_shared<AlwaysOffSampler>(),
                            ProcessorOptions{});

        auto off_span = b.tracer()->StartSpan("off");
        bool was_recording_off = off_span->IsRecording();
        off_span->End();
        auto drained = b.processor->Drain();

        bool pass = was_recording_on && !was_recording_off && drained.empty();
        TestFramework::RecordTest(
            "ObsTracer: TracerProvider::Reload atomically swaps sampler",
            pass, pass ? "" : "reload didn't swap",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsTracer: TracerProvider::Reload atomically swaps sampler",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// SwapProcessorAcrossTracers — Phase 2 single-shot swap that the manager
// uses during the boot-time NoopSpanProcessor → BatchSpanProcessor handoff.
// Every previously-cached tracer must route to the new processor, and any
// tracer obtained AFTER the swap must also see the new one.
void TestSwapProcessorAcrossTracersFanout() {
    try {
        Bench b(std::make_shared<AlwaysOnSampler>());
        Tracer* a = b.provider->GetTracer("scope_a", "1");
        Tracer* c = b.provider->GetTracer("scope_b", "1");

        // Establish that the old InMemoryProcessor is wired.
        a->StartSpan("warm")->End();
        size_t warm_size = b.processor->Size();
        b.processor->Drain();

        auto in_memory = std::make_shared<InMemorySpanProcessor>();
        b.provider->SwapProcessorAcrossTracers(in_memory);

        a->StartSpan("op_a")->End();
        c->StartSpan("op_b")->End();
        bool prior_routed = in_memory->Size() == 2;

        Tracer* d = b.provider->GetTracer("scope_c", "1");
        d->StartSpan("op_c")->End();
        bool fresh_routed = in_memory->Size() == 3;

        bool pass = warm_size == 1 && prior_routed && fresh_routed;
        TestFramework::RecordTest(
            "ObsTracer: SwapProcessorAcrossTracers fans out to cached + new tracers",
            pass, pass ? ""
                      : "size=" + std::to_string(in_memory->Size())
                       + " prior=" + std::to_string(prior_routed)
                       + " fresh=" + std::to_string(fresh_routed),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsTracer: SwapProcessorAcrossTracers fans out to cached + new tracers",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void RunAllTests() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "OBSERVABILITY TRACER / SAMPLER / SPAN UNIT TESTS" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    TestAlwaysOnSampler();
    TestAlwaysOffSampler();
    TestTraceIdRatioSampler();
    TestTraceIdRatioSamplerDeterministic();
    TestParentBasedSamplerInheritsParent();
    TestStartSpanRecordsAndExports();
    TestAlwaysOffSpanHasNoExport();
    TestEndIdempotent();
    TestDropWithoutEnd();
    TestPrecomputedContext();
    TestSpanInheritsParentTraceId();
    TestSpanStatusTransition();
    TestProviderCachesTracers();
    TestProviderReloadSwapsSampler();
    TestSwapProcessorAcrossTracersFanout();
}

}  // namespace ObservabilityTracerTests
