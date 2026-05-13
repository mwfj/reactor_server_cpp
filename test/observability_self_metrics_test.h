#pragma once

// MetricLabelRegistry cardinality-overflow self-metric tests.
//
// The slow path in `BuildLabelSet` emits
// `reactor.otel.cardinality_overflow{label_key=...}` when a label
// value is rewritten to `__overflow__`. Coverage:
//
//   * Slow-path latch — the first value past the cap latches
//     `cap_full=true` and bumps the counter.
//   * Fast-path post-latch — subsequent overflow lookups skip the
//     unique_lock but still bump the counter (so /metrics surfaces
//     ongoing overflow pressure, not just the one-shot latch event).
//   * Null-manager safety — a registry constructed without a manager
//     pointer must not crash on overflow.
//   * Catalog registration — the `signal` label on
//     `reactor.otel.export.duration` is plumbed through the catalog.
//
// No I/O, no dispatcher: pure unit tests against the registry +
// MeterProvider snapshot.

#include "test_framework.h"
#include "observability/batch_span_processor.h"
#include "observability/counter.h"
#include "observability/histogram.h"
#include "observability/meter.h"
#include "observability/meter_provider.h"
#include "observability/metric_label_registry.h"
#include "observability/metric_exporter.h"
#include "observability/metrics_catalog.h"
#include "observability/observability_config.h"
#include "observability/observability_manager.h"
#include "observability/periodic_metric_reader.h"
#include "observability/resource.h"
#include "observability/sampler.h"
#include "observability/span.h"
#include "observability/span_data.h"
#include "observability/span_exporter.h"
#include "observability/span_processor.h"
#include "observability/tracer.h"

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace ObservabilitySelfMetricsTests {

using OBSERVABILITY_NAMESPACE::BatchSpanProcessor;
using OBSERVABILITY_NAMESPACE::BatchSpanProcessorOptions;
using OBSERVABILITY_NAMESPACE::Counter;
using OBSERVABILITY_NAMESPACE::CounterPoint;
using OBSERVABILITY_NAMESPACE::ExportResult;
using OBSERVABILITY_NAMESPACE::HistogramPoint;
using OBSERVABILITY_NAMESPACE::InMemorySpanProcessor;
using OBSERVABILITY_NAMESPACE::InstrumentKind;
using OBSERVABILITY_NAMESPACE::InstrumentSnapshot;
using OBSERVABILITY_NAMESPACE::MeterReaderOptions;
using OBSERVABILITY_NAMESPACE::MetricExporter;
using OBSERVABILITY_NAMESPACE::MetricLabelRegistry;
using OBSERVABILITY_NAMESPACE::MetricsSnapshot;
using OBSERVABILITY_NAMESPACE::ObservabilityConfig;
using OBSERVABILITY_NAMESPACE::ObservabilityManager;
using OBSERVABILITY_NAMESPACE::PeriodicMetricReader;
using OBSERVABILITY_NAMESPACE::RandomSource;
using OBSERVABILITY_NAMESPACE::Resource;
using OBSERVABILITY_NAMESPACE::SamplerType;
using OBSERVABILITY_NAMESPACE::SpanData;
using OBSERVABILITY_NAMESPACE::SpanExporter;
using OBSERVABILITY_NAMESPACE::kOverflowSentinel;

namespace {

// Build a manager identical to ObservabilityCatalogTests::ManagerFixture
// so the catalog is wired and the cardinality-overflow Counter is
// retrievable via `manager->catalog()`.
struct ManagerFixture {
    std::shared_ptr<InMemorySpanProcessor> processor =
        std::make_shared<InMemorySpanProcessor>();
    std::shared_ptr<ObservabilityManager> manager;

    explicit ManagerFixture() {
        ObservabilityConfig cfg;
        cfg.enabled = true;
        cfg.traces.enabled = true;
        cfg.metrics.enabled = true;
        cfg.traces.sampler.type = SamplerType::AlwaysOn;
        cfg.resource.service_name = "obs-self-metrics-test";
        manager = ObservabilityManager::Create(
            std::move(cfg),
            std::make_shared<Resource>(),
            processor,
            std::make_shared<RandomSource>(0xCA7A7068ULL));
    }
};

// Sum the values of every CounterPoint whose `label_key` label matches
// `label_key_value` for the instrument named `inst_name`.
double SumOverflowForLabelKey(const MetricsSnapshot& snap,
                                const std::string& inst_name,
                                const std::string& label_key_value) {
    double total = 0;
    for (const auto& inst : snap.instruments) {
        if (inst.name != inst_name) continue;
        for (const auto& p : inst.counter_points) {
            for (const auto& [k, v] : p.labels.kv) {
                if (k == "label_key" && v == label_key_value) {
                    total += p.value;
                }
            }
        }
    }
    return total;
}

// Sum every CounterPoint for the named instrument regardless of labels.
// Used for unlabeled counters like `reactor.otel.spans.created`.
double SumCounter(const MetricsSnapshot& snap,
                    const std::string& inst_name) {
    double total = 0;
    for (const auto& inst : snap.instruments) {
        if (inst.name != inst_name) continue;
        for (const auto& p : inst.counter_points) {
            total += p.value;
        }
    }
    return total;
}

// Sum every CounterPoint whose label `key` equals `value` for the named
// instrument. Used to slice outcome-labeled counters.
double SumCounterByLabel(const MetricsSnapshot& snap,
                          const std::string& inst_name,
                          const std::string& key,
                          const std::string& value) {
    double total = 0;
    for (const auto& inst : snap.instruments) {
        if (inst.name != inst_name) continue;
        for (const auto& p : inst.counter_points) {
            for (const auto& [k, v] : p.labels.kv) {
                if (k == key && v == value) {
                    total += p.value;
                }
            }
        }
    }
    return total;
}

// Sum the `count` field of every HistogramPoint whose label `key` equals
// `value` for the named instrument. Used to slice signal-labeled
// histograms (e.g., `reactor.otel.export.duration{signal=traces}`).
uint64_t HistogramCountByLabel(const MetricsSnapshot& snap,
                                const std::string& inst_name,
                                const std::string& key,
                                const std::string& value) {
    uint64_t total = 0;
    for (const auto& inst : snap.instruments) {
        if (inst.name != inst_name) continue;
        for (const auto& p : inst.histogram_points) {
            for (const auto& [k, v] : p.labels.kv) {
                if (k == key && v == value) {
                    total += p.count;
                }
            }
        }
    }
    return total;
}

// Minimal SpanExporter recording call count + returning a configurable
// fixed result. Mirrors the CaptureSpanExporter shape from
// observability_export_pipeline_test.h but tracks per-call results so
// the worker-loop self-metric assertions can pin outcome attribution.
class FixedResultSpanExporter : public SpanExporter {
public:
    explicit FixedResultSpanExporter(ExportResult result)
        : result_(result) {}
    ExportResult Export(std::vector<SpanData> batch,
                         std::chrono::steady_clock::time_point) override {
        std::lock_guard<std::mutex> g(mtx_);
        ++calls_;
        last_size_ = batch.size();
        total_received_ += batch.size();
        return result_;
    }
    void SignalShutdown() override {}
    void CancelAllActiveExports() override {}
    int  calls() {
        std::lock_guard<std::mutex> g(mtx_);
        return calls_;
    }
    size_t total_received() {
        std::lock_guard<std::mutex> g(mtx_);
        return total_received_;
    }
private:
    ExportResult result_;
    std::mutex   mtx_;
    int          calls_       = 0;
    size_t       last_size_   = 0;
    size_t       total_received_ = 0;
};

// MetricExporter that counts Export() calls and always returns kSuccess.
class RecordingMetricExporter : public MetricExporter {
public:
    ExportResult Export(MetricsSnapshot,
                         std::chrono::steady_clock::time_point) override {
        export_calls_.fetch_add(1, std::memory_order_relaxed);
        return ExportResult::kSuccess;
    }
    void SignalShutdown() override {}
    void CancelAllActiveExports() override {}
    int  export_calls() const {
        return export_calls_.load(std::memory_order_relaxed);
    }
private:
    std::atomic<int> export_calls_{0};
};

// SpanExporter that blocks every Export call indefinitely until
// `unblock` is signaled. Used to stall the worker so OnEnd's queue-
// overflow drop branch is exercised deterministically.
class BlockingSpanExporter : public SpanExporter {
public:
    ExportResult Export(std::vector<SpanData>,
                         std::chrono::steady_clock::time_point) override {
        while (!unblock_.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(std::chrono::milliseconds{5});
        }
        return ExportResult::kSuccess;
    }
    void SignalShutdown() override { unblock_.store(true); }
    void CancelAllActiveExports() override { unblock_.store(true); }
    void Unblock() { unblock_.store(true); }
private:
    std::atomic<bool> unblock_{false};
};

MetricLabelRegistry::Catalog SmallCatalog(size_t cap = 2) {
    MetricLabelRegistry::Catalog c;
    c.allowed_keys = {"http.route"};
    c.value_cardinality_caps["http.route"] = cap;
    return c;
}

}  // namespace

// ---------------------------------------------------------------------
// Test 1 — slow path triggers the self-metric on first overflow.
// ---------------------------------------------------------------------
inline void TestCardinalityOverflowEmitsSelfMetricSlowPath() {
    std::cout << "\n[TEST] SelfMetrics: cardinality_overflow emit on slow-path"
              << std::endl;
    try {
        ManagerFixture fix;
        // Use a real catalog-wired Counter from the manager so the
        // emit path hits the production registration.
        auto* meter = fix.manager->meter_provider()->GetMeter("test.self");
        Counter* c = meter->GetCounter(
            "test.counter", "", "1",
            SmallCatalog(/*cap=*/2));

        // Fill the cap then overflow once. Cap=2 means values 1 and 2
        // land literally; value 3 trips the slow-path overflow branch.
        c->Add(1, {{"http.route", "/a"}});
        c->Add(1, {{"http.route", "/b"}});
        c->Add(1, {{"http.route", "/c"}});  // first overflow — slow path

        auto snap = fix.manager->meter_provider()->Snapshot();
        double overflow_for_route =
            SumOverflowForLabelKey(snap,
                                     "reactor.otel.cardinality_overflow",
                                     "http.route");
        bool pass = overflow_for_route >= 1.0;
        TestFramework::RecordTest(
            "SelfMetrics: slow-path overflow bumps reactor.otel.cardinality_overflow",
            pass,
            pass ? "" : "expected >=1, got " +
                          std::to_string(overflow_for_route),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "SelfMetrics: slow-path overflow bumps reactor.otel.cardinality_overflow",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Test 2 — fast path (post-latch) also bumps the counter.
//
// After the first overflow latches `cap_full=true`, subsequent
// overflowing lookups skip the unique_lock and hit only the shared_lock
// branch. That branch must also count the overflow, otherwise /metrics
// would show a one-shot blip the first time the cap was crossed and
// silence after.
// ---------------------------------------------------------------------
inline void TestCardinalityOverflowEmitsSelfMetricFastPath() {
    std::cout << "\n[TEST] SelfMetrics: cardinality_overflow emit on fast-path"
              << std::endl;
    try {
        ManagerFixture fix;
        auto* meter = fix.manager->meter_provider()->GetMeter("test.self.fast");
        Counter* c = meter->GetCounter(
            "test.counter.fast", "", "1",
            SmallCatalog(/*cap=*/2));

        // Fill cap and latch cap_full via one slow-path overflow.
        c->Add(1, {{"http.route", "/a"}});
        c->Add(1, {{"http.route", "/b"}});
        c->Add(1, {{"http.route", "/c"}});  // latches cap_full

        // Snapshot the count after the latch, then send several more
        // overflowing values — each should bump the counter via the
        // fast-path branch.
        auto mid_snap = fix.manager->meter_provider()->Snapshot();
        double before = SumOverflowForLabelKey(
            mid_snap,
            "reactor.otel.cardinality_overflow",
            "http.route");

        for (int i = 0; i < 5; ++i) {
            c->Add(1, {{"http.route", "/extra-" + std::to_string(i)}});
        }

        auto final_snap = fix.manager->meter_provider()->Snapshot();
        double after = SumOverflowForLabelKey(
            final_snap,
            "reactor.otel.cardinality_overflow",
            "http.route");

        bool pass = (after - before) >= 5.0;
        TestFramework::RecordTest(
            "SelfMetrics: fast-path overflow bumps reactor.otel.cardinality_overflow",
            pass,
            pass ? "" : "expected delta >=5, got " +
                          std::to_string(after - before),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "SelfMetrics: fast-path overflow bumps reactor.otel.cardinality_overflow",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Test 3 — null-manager safety. A registry built outside an
// ObservabilityManager (test fixtures, ad-hoc usage) must not crash
// on overflow. The overflow rewrite still fires; the self-metric emit
// is silently skipped.
// ---------------------------------------------------------------------
inline void TestNullManagerOverflowSafe() {
    std::cout << "\n[TEST] SelfMetrics: null-manager registry no-crash on overflow"
              << std::endl;
    try {
        MetricLabelRegistry r(SmallCatalog(/*cap=*/2),
                                /*manager=*/nullptr);
        r.BuildLabelSet({{"http.route", "/a"}});
        r.BuildLabelSet({{"http.route", "/b"}});
        auto ls = r.BuildLabelSet({{"http.route", "/c"}});
        bool pass = ls.kv.size() == 1 &&
                    ls.kv[0].second == std::string(kOverflowSentinel);
        TestFramework::RecordTest(
            "SelfMetrics: null-manager registry rewrites to __overflow__ without crash",
            pass,
            pass ? "" : "overflow rewrite missing or unexpected shape",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "SelfMetrics: null-manager registry rewrites to __overflow__ without crash",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Test 4 — `reactor.otel.export.duration` is registered with the
// {signal} label allowed (closed vocabulary {"traces", "metrics"}).
// This ratchets the catalog wiring so a future refactor that drops the
// {signal} label trips the test rather than producing a labelless
// series that misleads operators about which exporter is slow.
// ---------------------------------------------------------------------
inline void TestExportDurationHasSignalLabel() {
    std::cout << "\n[TEST] SelfMetrics: reactor.otel.export.duration has {signal} label"
              << std::endl;
    try {
        ManagerFixture fix;
        const auto& cat = fix.manager->catalog();
        if (cat.reactor_otel_export_duration == nullptr) {
            TestFramework::RecordTest(
                "SelfMetrics: reactor.otel.export.duration registered with {signal} label",
                false,
                "reactor.otel.export.duration not registered",
                TestFramework::TestCategory::OTHER);
            return;
        }
        // Record a sample with signal=traces and verify the series
        // carries the {signal=traces} label after snapshot.
        cat.reactor_otel_export_duration->Record(
            0.025, {{"signal", "traces"}});

        auto snap = fix.manager->meter_provider()->Snapshot();
        bool found_traces = false;
        for (const auto& inst : snap.instruments) {
            if (inst.name != "reactor.otel.export.duration") continue;
            for (const auto& p : inst.histogram_points) {
                for (const auto& [k, v] : p.labels.kv) {
                    if (k == "signal" && v == "traces") {
                        found_traces = true;
                    }
                }
            }
        }
        TestFramework::RecordTest(
            "SelfMetrics: reactor.otel.export.duration registered with {signal} label",
            found_traces,
            found_traces ? "" : "{signal=traces} label not surfaced in snapshot",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "SelfMetrics: reactor.otel.export.duration registered with {signal} label",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Test 4b — cap=2 on the {signal} allowlist actually rejects a third
// distinct value.  Recording "traces", "metrics", and a third unknown
// value must collapse the unknown value to "__overflow__" in the
// snapshot.  If someone drops cap=2 from the catalog, this test trips.
// ---------------------------------------------------------------------
inline void TestExportDurationSignalCapRejectsThirdValue() {
    std::cout << "\n[TEST] SelfMetrics: {signal} cap=2 collapses unknown third value"
              << std::endl;
    try {
        ManagerFixture fix;
        const auto& cat = fix.manager->catalog();
        if (cat.reactor_otel_export_duration == nullptr) {
            TestFramework::RecordTest(
                "SelfMetrics: {signal} cap=2 collapses unknown third value",
                false,
                "reactor.otel.export.duration not registered",
                TestFramework::TestCategory::OTHER);
            return;
        }

        // Fill both cap slots with the two legal values, then push a
        // third unknown value that must overflow to __overflow__.
        cat.reactor_otel_export_duration->Record(0.010, {{"signal", "traces"}});
        cat.reactor_otel_export_duration->Record(0.020, {{"signal", "metrics"}});
        cat.reactor_otel_export_duration->Record(0.030, {{"signal", "invalid_third"}});

        auto snap = fix.manager->meter_provider()->Snapshot();
        bool found_overflow = false;
        int  distinct_legal = 0;
        for (const auto& inst : snap.instruments) {
            if (inst.name != "reactor.otel.export.duration") continue;
            for (const auto& p : inst.histogram_points) {
                for (const auto& [k, v] : p.labels.kv) {
                    if (k == "signal") {
                        if (v == "__overflow__")      { found_overflow = true; }
                        if (v == "traces" || v == "metrics") { ++distinct_legal; }
                    }
                }
            }
        }

        bool ok = found_overflow && distinct_legal == 2;
        std::string msg;
        if (!ok) {
            if (!found_overflow)    msg += "third value did not collapse to __overflow__; ";
            if (distinct_legal != 2) msg += "expected exactly 2 legal signal values, got "
                                             + std::to_string(distinct_legal) + "; ";
        }
        TestFramework::RecordTest(
            "SelfMetrics: {signal} cap=2 collapses unknown third value",
            ok, msg, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "SelfMetrics: {signal} cap=2 collapses unknown third value",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Test 5 — `reactor.otel.spans.created` increments on every StartSpan
// regardless of sampler decision. With AlwaysOn the counter advances by
// exactly one per span; the unsampled counter stays at zero.
// ---------------------------------------------------------------------
inline void TestSpanCreationIncrementsCounter() {
    std::cout << "\n[TEST] SelfMetrics: spans.created increments per StartSpan"
              << std::endl;
    try {
        ManagerFixture fix;
        auto* tracer = fix.manager->GetTracer("test.tracer", "1.0");

        auto snap_before = fix.manager->meter_provider()->Snapshot();
        const double created_before =
            SumCounter(snap_before, "reactor.otel.spans.created");
        const double dropped_before = SumCounter(
            snap_before, "reactor.otel.spans.dropped_unsampled");

        constexpr int kSpans = 10;
        for (int i = 0; i < kSpans; ++i) {
            auto span = tracer->StartSpan("op");
            span->End();
        }

        auto snap_after = fix.manager->meter_provider()->Snapshot();
        const double created_after =
            SumCounter(snap_after, "reactor.otel.spans.created");
        const double dropped_after = SumCounter(
            snap_after, "reactor.otel.spans.dropped_unsampled");

        const double created_delta = created_after - created_before;
        const double dropped_delta = dropped_after - dropped_before;

        // AlwaysOn ⇒ created bumps once per StartSpan, dropped_unsampled
        // stays flat for this fixture.
        bool pass = created_delta >= static_cast<double>(kSpans) &&
                    dropped_delta == 0.0;
        std::string msg;
        if (!pass) {
            msg = "created_delta=" + std::to_string(created_delta) +
                  " (expected >=" + std::to_string(kSpans) + ") " +
                  "dropped_delta=" + std::to_string(dropped_delta) +
                  " (expected 0)";
        }
        TestFramework::RecordTest(
            "SelfMetrics: spans.created bumps per StartSpan under AlwaysOn",
            pass, msg, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "SelfMetrics: spans.created bumps per StartSpan under AlwaysOn",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Test 6 — AlwaysOff sampler causes `spans.dropped_unsampled` to
// increment by exactly the same count as `spans.created`. Verifies the
// DROP branch on `Tracer::StartSpan` AND confirms the unsampled counter
// is wired to the sampler decision (not to e.g. `IsRecording()`).
// ---------------------------------------------------------------------
inline void TestSpanDropIncrementsDroppedUnsampled() {
    std::cout << "\n[TEST] SelfMetrics: spans.dropped_unsampled increments under AlwaysOff"
              << std::endl;
    try {
        // Build a manager with AlwaysOff sampler so every StartSpan
        // takes the DROP branch.
        ObservabilityConfig cfg;
        cfg.enabled = true;
        cfg.traces.enabled = true;
        cfg.metrics.enabled = true;
        cfg.traces.sampler.type = SamplerType::AlwaysOff;
        cfg.resource.service_name = "obs-self-metrics-drop";
        auto manager = ObservabilityManager::Create(
            std::move(cfg),
            std::make_shared<Resource>(),
            std::make_shared<InMemorySpanProcessor>(),
            std::make_shared<RandomSource>(0xCA7AD20BULL));

        auto* tracer = manager->GetTracer("test.drop.tracer", "1.0");

        auto snap_before = manager->meter_provider()->Snapshot();
        const double created_before =
            SumCounter(snap_before, "reactor.otel.spans.created");
        const double dropped_before = SumCounter(
            snap_before, "reactor.otel.spans.dropped_unsampled");

        constexpr int kSpans = 7;
        for (int i = 0; i < kSpans; ++i) {
            auto span = tracer->StartSpan("op");
            span->End();
        }

        auto snap_after = manager->meter_provider()->Snapshot();
        const double created_after =
            SumCounter(snap_after, "reactor.otel.spans.created");
        const double dropped_after = SumCounter(
            snap_after, "reactor.otel.spans.dropped_unsampled");

        const double created_delta = created_after - created_before;
        const double dropped_delta = dropped_after - dropped_before;

        // AlwaysOff ⇒ both counters bump in lockstep. Exact equality:
        // every StartSpan is both created and dropped_unsampled.
        bool pass = created_delta >= static_cast<double>(kSpans) &&
                    dropped_delta == created_delta;
        std::string msg;
        if (!pass) {
            msg = "created_delta=" + std::to_string(created_delta) +
                  " dropped_delta=" + std::to_string(dropped_delta) +
                  " (expected dropped == created >= " +
                  std::to_string(kSpans) + ")";
        }
        TestFramework::RecordTest(
            "SelfMetrics: spans.dropped_unsampled matches created under AlwaysOff",
            pass, msg, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "SelfMetrics: spans.dropped_unsampled matches created under AlwaysOff",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Test 7 — `reactor.otel.spans.dropped_unended` increments when
// `Span::DropWithoutEnd` runs. Verifies the first consumer of the
// `SpanProcessor::manager()` virtual is live and that the catalog
// pointer is wired correctly.
// ---------------------------------------------------------------------
inline void TestDropWithoutEndIncrementsCounter() {
    std::cout << "\n[TEST] SelfMetrics: spans.dropped_unended increments on DropWithoutEnd"
              << std::endl;
    try {
        ManagerFixture fix;
        // InMemorySpanProcessor returns nullptr from manager() by
        // default; wire the manager explicitly so Span::DropWithoutEnd
        // can reach the catalog. Production wires this at BSP ctor.
        fix.processor->set_manager(fix.manager.get());

        auto* tracer = fix.manager->GetTracer("test.drop_unended", "1.0");

        auto snap_before = fix.manager->meter_provider()->Snapshot();
        const double before = SumCounter(
            snap_before, "reactor.otel.spans.dropped_unended");

        constexpr int kSpans = 4;
        for (int i = 0; i < kSpans; ++i) {
            auto span = tracer->StartSpan("op");
            span->DropWithoutEnd();
        }

        auto snap_after = fix.manager->meter_provider()->Snapshot();
        const double after = SumCounter(
            snap_after, "reactor.otel.spans.dropped_unended");
        const double delta = after - before;

        const bool pass = delta == static_cast<double>(kSpans);
        std::string msg;
        if (!pass) {
            msg = "delta=" + std::to_string(delta) +
                  " (expected " + std::to_string(kSpans) + ")";
        }
        TestFramework::RecordTest(
            "SelfMetrics: spans.dropped_unended bumps once per DropWithoutEnd",
            pass, msg, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "SelfMetrics: spans.dropped_unended bumps once per DropWithoutEnd",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Test 8 — `DropWithoutEnd` is idempotent. Repeated calls on the same
// span must bump the counter exactly once. Guards against future
// refactors that move the emit outside the CAS branch.
// ---------------------------------------------------------------------
inline void TestDropWithoutEndIsIdempotent() {
    std::cout << "\n[TEST] SelfMetrics: spans.dropped_unended is CAS-once idempotent"
              << std::endl;
    try {
        ManagerFixture fix;
        fix.processor->set_manager(fix.manager.get());

        auto* tracer = fix.manager->GetTracer("test.drop_idempotent", "1.0");

        auto snap_before = fix.manager->meter_provider()->Snapshot();
        const double before = SumCounter(
            snap_before, "reactor.otel.spans.dropped_unended");

        auto span = tracer->StartSpan("op");
        span->DropWithoutEnd();
        span->DropWithoutEnd();  // second call must no-op.
        span->DropWithoutEnd();  // third call must no-op.
        span->End();             // End after Drop must no-op (no extra emit).

        auto snap_after = fix.manager->meter_provider()->Snapshot();
        const double after = SumCounter(
            snap_after, "reactor.otel.spans.dropped_unended");
        const double delta = after - before;

        const bool pass = delta == 1.0;
        std::string msg;
        if (!pass) {
            msg = "delta=" + std::to_string(delta) + " (expected 1)";
        }
        TestFramework::RecordTest(
            "SelfMetrics: spans.dropped_unended idempotent across repeated DropWithoutEnd",
            pass, msg, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "SelfMetrics: spans.dropped_unended idempotent across repeated DropWithoutEnd",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Test 9 — BatchSpanProcessor worker-loop self-metrics.
//
// Feed N spans through a BSP wired to the manager and assert:
//   * `reactor.otel.spans.exported{outcome=success}` increments by N
//     (one Export attempt, batch size = N).
//   * `reactor.otel.export.duration{signal=traces}` HistogramCount >= 1.
// ---------------------------------------------------------------------
inline void TestBspExportSelfMetrics() {
    std::cout << "\n[TEST] SelfMetrics: BSP emits spans.exported{outcome=success} "
                 "+ export.duration{signal=traces}" << std::endl;
    try {
        ManagerFixture fix;
        auto exporter = std::make_shared<FixedResultSpanExporter>(
            ExportResult::kSuccess);
        BatchSpanProcessorOptions opts;
        opts.max_export_batch_size = 64;
        opts.schedule_delay = std::chrono::milliseconds{30};
        BatchSpanProcessor bsp(exporter, opts, fix.manager.get());

        auto snap_before = fix.manager->meter_provider()->Snapshot();
        const double exported_before = SumCounterByLabel(
            snap_before, "reactor.otel.spans.exported",
            "outcome", "success");
        const uint64_t hist_before = HistogramCountByLabel(
            snap_before, "reactor.otel.export.duration",
            "signal", "traces");

        constexpr int kSpans = 50;
        for (int i = 0; i < kSpans; ++i) {
            SpanData sd;
            sd.name = "op";
            bsp.OnEnd(std::move(sd));
        }
        bsp.ForceFlush(std::chrono::milliseconds{2000});

        // Wait for the worker to advance past the export attempt — the
        // counter increment is outside ForceFlush's poll predicate.
        for (int i = 0; i < 100 && exporter->total_received() < kSpans; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
        }

        auto snap_after = fix.manager->meter_provider()->Snapshot();
        const double exported_after = SumCounterByLabel(
            snap_after, "reactor.otel.spans.exported",
            "outcome", "success");
        const uint64_t hist_after = HistogramCountByLabel(
            snap_after, "reactor.otel.export.duration",
            "signal", "traces");

        bsp.SignalShutdown();
        bsp.JoinWorkers(std::chrono::milliseconds{500});

        const double exported_delta = exported_after - exported_before;
        const uint64_t hist_delta = hist_after - hist_before;
        bool pass = exported_delta >= static_cast<double>(kSpans) &&
                    hist_delta >= 1;
        std::string msg;
        if (!pass) {
            msg = "exported_delta=" + std::to_string(exported_delta) +
                  " (expected >=" + std::to_string(kSpans) +
                  ") hist_delta=" + std::to_string(hist_delta) +
                  " (expected >=1)";
        }
        TestFramework::RecordTest(
            "SelfMetrics: BSP emits spans.exported{success} + export.duration{traces}",
            pass, msg, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "SelfMetrics: BSP emits spans.exported{success} + export.duration{traces}",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Test 10 — kFailedNotRetryable exporter result must increment
// `spans.exported{outcome=non_retryable_fail}`.
//
// Ratchets the outcome classifier so a future refactor that fuses
// success + non-retryable_fail into a single label trips the test.
// ---------------------------------------------------------------------
inline void TestBspNonRetryableFailureSelfMetric() {
    std::cout << "\n[TEST] SelfMetrics: BSP emits spans.exported{outcome=non_retryable_fail}"
              << std::endl;
    try {
        ManagerFixture fix;
        auto exporter = std::make_shared<FixedResultSpanExporter>(
            ExportResult::kFailedNotRetryable);
        BatchSpanProcessorOptions opts;
        opts.max_export_batch_size = 16;
        opts.schedule_delay = std::chrono::milliseconds{30};
        BatchSpanProcessor bsp(exporter, opts, fix.manager.get());

        auto snap_before = fix.manager->meter_provider()->Snapshot();
        const double before = SumCounterByLabel(
            snap_before, "reactor.otel.spans.exported",
            "outcome", "non_retryable_fail");

        constexpr int kSpans = 8;
        for (int i = 0; i < kSpans; ++i) {
            SpanData sd;
            sd.name = "op";
            bsp.OnEnd(std::move(sd));
        }
        bsp.ForceFlush(std::chrono::milliseconds{2000});
        // Wait for worker to advance past the Export call.
        for (int i = 0; i < 100 && exporter->calls() < 1; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
        }

        auto snap_after = fix.manager->meter_provider()->Snapshot();
        const double after = SumCounterByLabel(
            snap_after, "reactor.otel.spans.exported",
            "outcome", "non_retryable_fail");

        bsp.SignalShutdown();
        bsp.JoinWorkers(std::chrono::milliseconds{500});

        const double delta = after - before;
        bool pass = delta >= static_cast<double>(kSpans);
        std::string msg;
        if (!pass) {
            msg = "delta=" + std::to_string(delta) +
                  " (expected >=" + std::to_string(kSpans) + ")";
        }
        TestFramework::RecordTest(
            "SelfMetrics: BSP emits spans.exported{non_retryable_fail} on kFailedNotRetryable",
            pass, msg, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "SelfMetrics: BSP emits spans.exported{non_retryable_fail} on kFailedNotRetryable",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Test 11 — OnEnd queue-overflow drop emits
// `reactor.otel.spans.dropped_queue_full`.
//
// Blocks the exporter so the worker can't drain, fills past
// max_queue_size, and verifies the counter bumps for the drop-oldest
// path. Drop-on-shutdown is tested implicitly by the manager-shutdown
// suite; this test focuses on the steady-state overflow case.
// ---------------------------------------------------------------------
inline void TestBspDropOnOverflowSelfMetric() {
    std::cout << "\n[TEST] SelfMetrics: BSP emits spans.dropped_queue_full on overflow"
              << std::endl;
    try {
        ManagerFixture fix;
        auto exporter = std::make_shared<BlockingSpanExporter>();
        BatchSpanProcessorOptions opts;
        opts.max_queue_size        = 4;
        opts.max_export_batch_size = 2;
        opts.schedule_delay        = std::chrono::milliseconds{15};
        BatchSpanProcessor bsp(exporter, opts, fix.manager.get());

        auto snap_before = fix.manager->meter_provider()->Snapshot();
        const double before = SumCounter(
            snap_before, "reactor.otel.spans.dropped_queue_full");

        // Inject many more than max_queue_size so the drop-oldest
        // branch fires repeatedly. Worker is blocked inside Export so
        // the queue stays at the cap.
        for (int i = 0; i < 20; ++i) {
            SpanData sd;
            sd.name = "op";
            bsp.OnEnd(std::move(sd));
        }
        // Give the OnEnd-path emits time to propagate through the
        // counter shard's atomic.
        std::this_thread::sleep_for(std::chrono::milliseconds{50});

        auto snap_after = fix.manager->meter_provider()->Snapshot();
        const double after = SumCounter(
            snap_after, "reactor.otel.spans.dropped_queue_full");

        // Unblock + shutdown so the destructor can join.
        exporter->Unblock();
        bsp.SignalShutdown();
        bsp.JoinWorkers(std::chrono::milliseconds{1000});

        const double delta = after - before;
        bool pass = delta >= 1.0;
        std::string msg;
        if (!pass) {
            msg = "delta=" + std::to_string(delta) + " (expected >=1)";
        }
        TestFramework::RecordTest(
            "SelfMetrics: BSP emits spans.dropped_queue_full on OnEnd overflow",
            pass, msg, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "SelfMetrics: BSP emits spans.dropped_queue_full on OnEnd overflow",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Test 12 — PeriodicMetricReader emits
// `reactor.otel.export.duration{signal=metrics}` once per cycle.
//
// Builds a PMR with a short interval and a recording exporter; waits
// for a couple of cycles and asserts the histogram count climbs.
// ---------------------------------------------------------------------
inline void TestPmrExportSelfMetrics() {
    std::cout << "\n[TEST] SelfMetrics: PMR emits export.duration{signal=metrics}"
              << std::endl;
    try {
        ManagerFixture fix;
        auto exporter = std::make_shared<RecordingMetricExporter>();
        MeterReaderOptions opts;
        opts.export_interval = std::chrono::milliseconds{40};
        opts.export_timeout  = std::chrono::milliseconds{500};

        auto reader = std::make_shared<PeriodicMetricReader>(
            fix.manager->meter_provider(), exporter, opts, fix.manager.get());
        reader->SetEnabled(true);

        // Wait until the recording exporter has handled at least two
        // cycles. Time-bound the wait to keep the test fast.
        const auto t_end = std::chrono::steady_clock::now() +
                           std::chrono::milliseconds{2000};
        while (std::chrono::steady_clock::now() < t_end &&
               exporter->export_calls() < 2) {
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
        }

        auto snap = fix.manager->meter_provider()->Snapshot();
        const uint64_t metrics_count = HistogramCountByLabel(
            snap, "reactor.otel.export.duration",
            "signal", "metrics");

        reader->SignalShutdown();
        reader->JoinWorkers(std::chrono::milliseconds{500});

        bool pass = metrics_count >= 1 && exporter->export_calls() >= 1;
        std::string msg;
        if (!pass) {
            msg = "metrics_count=" + std::to_string(metrics_count) +
                  " (expected >=1) export_calls=" +
                  std::to_string(exporter->export_calls()) +
                  " (expected >=1)";
        }
        TestFramework::RecordTest(
            "SelfMetrics: PMR emits export.duration{signal=metrics}",
            pass, msg, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "SelfMetrics: PMR emits export.duration{signal=metrics}",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

inline void RunAllTests() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "OBSERVABILITY SELF-METRICS TESTS" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    TestCardinalityOverflowEmitsSelfMetricSlowPath();
    TestCardinalityOverflowEmitsSelfMetricFastPath();
    TestNullManagerOverflowSafe();
    TestExportDurationHasSignalLabel();
    TestExportDurationSignalCapRejectsThirdValue();
    TestSpanCreationIncrementsCounter();
    TestSpanDropIncrementsDroppedUnsampled();
    TestDropWithoutEndIncrementsCounter();
    TestDropWithoutEndIsIdempotent();
    TestBspExportSelfMetrics();
    TestBspNonRetryableFailureSelfMetric();
    TestBspDropOnOverflowSelfMetric();
    TestPmrExportSelfMetrics();
}

}  // namespace ObservabilitySelfMetricsTests
