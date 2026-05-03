#pragma once

// Counter / Histogram / Meter / MeterProvider unit tests.
// No I/O — exercises the in-process metrics pipeline directly via
// MeterProvider::Snapshot().

#include "test_framework.h"
#include "observability/counter.h"
#include "observability/histogram.h"
#include "observability/meter.h"
#include "observability/meter_provider.h"
#include "observability/metric_label_registry.h"
#include "observability/resource.h"

#include <atomic>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace ObservabilityMetricsTests {

using OBSERVABILITY_NAMESPACE::Counter;
using OBSERVABILITY_NAMESPACE::CounterPoint;
using OBSERVABILITY_NAMESPACE::Histogram;
using OBSERVABILITY_NAMESPACE::HistogramPoint;
using OBSERVABILITY_NAMESPACE::InstrumentKind;
using OBSERVABILITY_NAMESPACE::InstrumentSnapshot;
using OBSERVABILITY_NAMESPACE::Meter;
using OBSERVABILITY_NAMESPACE::MeterProvider;
using OBSERVABILITY_NAMESPACE::MeterReaderOptions;
using OBSERVABILITY_NAMESPACE::MetricLabelRegistry;
using OBSERVABILITY_NAMESPACE::MetricWriterContext;
using OBSERVABILITY_NAMESPACE::Resource;
using OBSERVABILITY_NAMESPACE::UpDownCounter;
using OBSERVABILITY_NAMESPACE::kDefaultHttpHistogramBuckets;
using OBSERVABILITY_NAMESPACE::kOverflowSentinel;

namespace {
MetricLabelRegistry::Catalog HttpServerCatalog(size_t route_cap = 256) {
    MetricLabelRegistry::Catalog c;
    c.allowed_keys = {"http.request.method", "http.route",
                       "http.response.status_code"};
    c.value_cardinality_caps["http.route"] = route_cap;
    return c;
}

CounterPoint* FindByLabels(std::vector<CounterPoint>& points,
                           const std::string& route_value) {
    for (auto& p : points) {
        for (const auto& [k, v] : p.labels.kv) {
            if (k == "http.route" && v == route_value) return &p;
        }
    }
    return nullptr;
}
}  // namespace

// ---- MetricLabelRegistry ----
void TestRegistryDropsDisallowedKey() {
    try {
        MetricLabelRegistry r(HttpServerCatalog());
        auto ls = r.BuildLabelSet({
            {"http.route", "/users/:id"},
            {"definitely_not_in_allowlist", "x"},
        });
        bool pass = ls.kv.size() == 1 && ls.kv[0].first == "http.route";
        TestFramework::RecordTest("ObsMetrics: registry drops keys not in allowlist",
            pass, pass ? "" : "disallowed key not dropped",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsMetrics: registry drops keys not in allowlist",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestRegistryOverflowRewrite() {
    try {
        MetricLabelRegistry r(HttpServerCatalog(/*route_cap=*/4));
        // Insert 5 distinct values for http.route — the 5th should
        // get rewritten to __overflow__.
        std::vector<std::string> emitted;
        for (int i = 0; i < 5; ++i) {
            auto ls = r.BuildLabelSet({{"http.route", "/r" + std::to_string(i)}});
            for (const auto& kv : ls.kv) {
                if (kv.first == "http.route") emitted.push_back(kv.second);
            }
        }
        // The first 4 lands literally; the 5th must be __overflow__.
        bool pass = emitted.size() == 5 &&
                    emitted[0] == "/r0" && emitted[1] == "/r1" &&
                    emitted[2] == "/r2" && emitted[3] == "/r3" &&
                    emitted[4] == std::string(kOverflowSentinel);
        TestFramework::RecordTest("ObsMetrics: registry overflow rewrite",
            pass, pass ? "" : "5th distinct value not __overflow__",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsMetrics: registry overflow rewrite",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestRegistryRepeatedValueAfterCap() {
    try {
        MetricLabelRegistry r(HttpServerCatalog(/*route_cap=*/2));
        // Insert /a then /b (cap full). Subsequent /a re-emits /a;
        // /c emits __overflow__.
        r.BuildLabelSet({{"http.route", "/a"}});
        r.BuildLabelSet({{"http.route", "/b"}});
        auto a_again = r.BuildLabelSet({{"http.route", "/a"}});
        auto c       = r.BuildLabelSet({{"http.route", "/c"}});
        bool pass = a_again.kv.size() == 1 && a_again.kv[0].second == "/a" &&
                    c.kv.size() == 1 &&
                    c.kv[0].second == std::string(kOverflowSentinel);
        TestFramework::RecordTest(
            "ObsMetrics: registry preserves seen values after cap",
            pass, pass ? "" : "post-cap behavior wrong",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsMetrics: registry preserves seen values after cap",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- Counter ----
void TestCounterBasicAdd() {
    try {
        auto provider = std::make_unique<MeterProvider>(
            std::make_shared<Resource>(), /*shard_count=*/1);
        Meter* m = provider->GetMeter("test", "1.0");
        Counter* c = m->GetCounter("requests_total", "desc", "1",
                                    HttpServerCatalog());
        c->Add(1, {{"http.route", "/a"}});
        c->Add(2, {{"http.route", "/a"}});
        c->Add(5, {{"http.route", "/b"}});

        auto snap = provider->Snapshot();
        bool pass = snap.instruments.size() == 1 &&
                    snap.instruments[0].kind == InstrumentKind::Counter &&
                    snap.instruments[0].counter_points.size() == 2;
        if (pass) {
            auto* a = FindByLabels(snap.instruments[0].counter_points, "/a");
            auto* b = FindByLabels(snap.instruments[0].counter_points, "/b");
            pass = a && b && a->value == 3.0 && b->value == 5.0;
        }
        TestFramework::RecordTest("ObsMetrics: Counter::Add accumulates per series",
            pass, pass ? "" : "values wrong",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsMetrics: Counter::Add accumulates per series",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestCounterRejectsNegative() {
    try {
        auto provider = std::make_unique<MeterProvider>(
            std::make_shared<Resource>());
        Meter* m = provider->GetMeter("test");
        Counter* c = m->GetCounter("foo", "", "1", HttpServerCatalog());
        c->Add(5, {{"http.route", "/a"}});
        c->Add(-3, {{"http.route", "/a"}});  // rejected
        auto snap = provider->Snapshot();
        bool pass = snap.instruments.size() == 1 &&
                    snap.instruments[0].counter_points.size() == 1 &&
                    snap.instruments[0].counter_points[0].value == 5.0;
        TestFramework::RecordTest("ObsMetrics: Counter rejects negative deltas",
            pass, pass ? "" : "negative not rejected",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsMetrics: Counter rejects negative deltas",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestUpDownCounterAcceptsNegative() {
    try {
        auto provider = std::make_unique<MeterProvider>(
            std::make_shared<Resource>());
        Meter* m = provider->GetMeter("test");
        UpDownCounter* u = m->GetUpDownCounter("inflight", "", "1",
                                                  HttpServerCatalog());
        u->Add(10, {{"http.route", "/a"}});
        u->Add(-3, {{"http.route", "/a"}});
        auto snap = provider->Snapshot();
        bool pass = snap.instruments.size() == 1 &&
                    snap.instruments[0].kind == InstrumentKind::UpDownCounter &&
                    snap.instruments[0].counter_points.size() == 1 &&
                    snap.instruments[0].counter_points[0].value == 7.0;
        TestFramework::RecordTest("ObsMetrics: UpDownCounter accepts negative deltas",
            pass, pass ? "" : "value wrong",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsMetrics: UpDownCounter accepts negative deltas",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- Histogram ----
void TestHistogramBucketing() {
    try {
        auto provider = std::make_unique<MeterProvider>(
            std::make_shared<Resource>());
        Meter* m = provider->GetMeter("test");
        std::vector<double> bounds = {0.005, 0.01, 0.025, 0.05, 0.1, 0.25,
                                       0.5, 1.0, 2.5, 5.0, 10.0};
        Histogram* h = m->GetHistogram("dur", "", "s", bounds, HttpServerCatalog());

        h->Record(0.001, {{"http.route", "/a"}});  // bucket[0]
        h->Record(0.020, {{"http.route", "/a"}});  // bucket[2]
        h->Record(7.0,   {{"http.route", "/a"}});  // bucket[10]
        h->Record(20.0,  {{"http.route", "/a"}});  // +Inf bucket[11]

        auto snap = provider->Snapshot();
        bool pass = snap.instruments.size() == 1 &&
                    snap.instruments[0].kind == InstrumentKind::Histogram &&
                    snap.instruments[0].histogram_points.size() == 1;
        if (pass) {
            const auto& p = snap.instruments[0].histogram_points[0];
            pass = p.count == 4 &&
                   p.bucket_counts.size() == bounds.size() + 1 &&
                   p.bucket_counts[0] == 1 &&
                   p.bucket_counts[2] == 1 &&
                   p.bucket_counts[10] == 1 &&
                   p.bucket_counts[11] == 1 &&
                   p.has_min_max && p.min == 0.001 && p.max == 20.0;
        }
        TestFramework::RecordTest("ObsMetrics: Histogram bucketing + min/max",
            pass, pass ? "" : "bucket counts wrong",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsMetrics: Histogram bucketing + min/max",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestHistogramMultipleSeries() {
    try {
        auto provider = std::make_unique<MeterProvider>(
            std::make_shared<Resource>());
        Meter* m = provider->GetMeter("test");
        std::vector<double> bounds = {0.1, 1.0};
        Histogram* h = m->GetHistogram("dur", "", "s", bounds, HttpServerCatalog());

        h->Record(0.05, {{"http.route", "/a"}});
        h->Record(0.05, {{"http.route", "/a"}});
        h->Record(0.5,  {{"http.route", "/b"}});

        auto snap = provider->Snapshot();
        bool pass = snap.instruments.size() == 1 &&
                    snap.instruments[0].histogram_points.size() == 2;
        if (pass) {
            uint64_t a_count = 0, b_count = 0;
            for (const auto& p : snap.instruments[0].histogram_points) {
                for (const auto& [k, v] : p.labels.kv) {
                    if (k == "http.route" && v == "/a") a_count = p.count;
                    if (k == "http.route" && v == "/b") b_count = p.count;
                }
            }
            pass = a_count == 2 && b_count == 1;
        }
        TestFramework::RecordTest("ObsMetrics: Histogram per-series isolation",
            pass, pass ? "" : "series mixed",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsMetrics: Histogram per-series isolation",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- Meter caching ----
void TestMeterCachesInstruments() {
    try {
        auto provider = std::make_unique<MeterProvider>(
            std::make_shared<Resource>());
        Meter* m = provider->GetMeter("svc");
        Counter* a = m->GetCounter("foo", "d", "1", HttpServerCatalog());
        Counter* a2 = m->GetCounter("foo", "DIFFERENT desc", "2",
                                      HttpServerCatalog());
        Counter* b = m->GetCounter("bar", "d", "1", HttpServerCatalog());
        bool pass = a == a2 && a != b;
        TestFramework::RecordTest("ObsMetrics: Meter caches per instrument name",
            pass, pass ? "" : "caching wrong",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsMetrics: Meter caches per instrument name",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- Multi-shard concurrent writes ----
void TestCounterConcurrentMultiShard() {
    try {
        constexpr int kThreads = 8;
        constexpr int kPerThread = 10000;
        auto provider = std::make_unique<MeterProvider>(
            std::make_shared<Resource>(), /*shard_count=*/8);
        Meter* m = provider->GetMeter("svc");
        Counter* c = m->GetCounter("hits", "", "1", HttpServerCatalog());

        std::atomic<bool> go{false};
        std::vector<std::thread> threads;
        threads.reserve(kThreads);
        for (int t = 0; t < kThreads; ++t) {
            threads.emplace_back([&, t]() {
                MetricWriterContext::SetShardId(t);
                while (!go.load(std::memory_order_acquire)) {
                    std::this_thread::yield();
                }
                for (int i = 0; i < kPerThread; ++i) {
                    c->Add(1, {{"http.route", "/api"}});
                }
            });
        }
        go.store(true, std::memory_order_release);
        for (auto& th : threads) th.join();

        auto snap = provider->Snapshot();
        bool pass = snap.instruments.size() == 1;
        double total = 0;
        if (pass) {
            for (const auto& p : snap.instruments[0].counter_points) {
                total += p.value;
            }
        }
        pass = pass && total == static_cast<double>(kThreads * kPerThread);
        std::string err = pass ? "" :
            "expected " + std::to_string(kThreads * kPerThread) +
            ", got " + std::to_string(total);
        TestFramework::RecordTest(
            "ObsMetrics: Counter concurrent 8-thread × 8-shard add merges correctly",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "ObsMetrics: Counter concurrent 8-thread × 8-shard add merges correctly",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ---- Reload ----
void TestMeterProviderReloadStoresReaderOptions() {
    try {
        auto provider = std::make_unique<MeterProvider>(
            std::make_shared<Resource>());
        MeterReaderOptions opts;
        opts.export_interval = std::chrono::milliseconds{30000};
        opts.export_timeout  = std::chrono::milliseconds{5000};
        provider->Reload(opts);
        auto live = provider->reader_options();
        bool pass = live.export_interval == opts.export_interval &&
                    live.export_timeout  == opts.export_timeout;
        TestFramework::RecordTest("ObsMetrics: MeterProvider::Reload stores reader options",
            pass, pass ? "" : "reload didn't store options",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ObsMetrics: MeterProvider::Reload stores reader options",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void RunAllTests() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "OBSERVABILITY METRICS UNIT TESTS" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    TestRegistryDropsDisallowedKey();
    TestRegistryOverflowRewrite();
    TestRegistryRepeatedValueAfterCap();
    TestCounterBasicAdd();
    TestCounterRejectsNegative();
    TestUpDownCounterAcceptsNegative();
    TestHistogramBucketing();
    TestHistogramMultipleSeries();
    TestMeterCachesInstruments();
    TestCounterConcurrentMultiShard();
    TestMeterProviderReloadStoresReaderOptions();
}

}  // namespace ObservabilityMetricsTests
