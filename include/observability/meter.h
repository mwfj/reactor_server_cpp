#pragma once

// Meter — instrument factory bound to a single InstrumentationScope.
// Owned by MeterProvider; callers obtain via `provider->GetMeter(name,
// version)`. Same get-or-create caching as Tracer.
//
// Instruments themselves are owned by the Meter; the Meter owns the
// SeriesMap state internally. Counters / Histograms returned to the
// caller are raw pointers; the caller never destroys them.

#include "observability/counter.h"
#include "observability/histogram.h"
#include "observability/instrumentation_scope.h"
#include "observability/metric_label_registry.h"
#include "observability/metrics_snapshot.h"

#include "../common.h"
// <memory>, <mutex>, <string>, <unordered_map>, <vector> via common.h

namespace OBSERVABILITY_NAMESPACE {

class ObservabilityManager;

class Meter {
public:
    Meter(std::shared_ptr<const InstrumentationScope> scope,
          std::shared_ptr<const Resource>             resource,
          size_t                                       shard_count,
          ObservabilityManager*                        manager);

    Meter(const Meter&) = delete;
    Meter& operator=(const Meter&) = delete;

    // Get-or-create a Counter with the given (name, allowed_keys, caps).
    // Repeat calls with the same name return the same Counter*; the
    // (description, unit, allowed_keys, caps) of the FIRST call wins —
    // subsequent calls' instrument-shape arguments are ignored. This
    // matches OTel SDK semantics ("instrument identity is name").
    Counter* GetCounter(const std::string& name,
                          const std::string& description,
                          const std::string& unit,
                          MetricLabelRegistry::Catalog catalog);

    UpDownCounter* GetUpDownCounter(const std::string& name,
                                       const std::string& description,
                                       const std::string& unit,
                                       MetricLabelRegistry::Catalog catalog);

    Histogram* GetHistogram(const std::string& name,
                              const std::string& description,
                              const std::string& unit,
                              std::vector<double> bucket_boundaries,
                              MetricLabelRegistry::Catalog catalog);

    // Snapshot every instrument owned by this Meter. Used by
    // MeterProvider::Snapshot().
    void SnapshotInto(std::vector<InstrumentSnapshot>& out) const;

    const InstrumentationScope& scope() const { return *scope_; }

private:
    std::shared_ptr<const InstrumentationScope> scope_;
    std::shared_ptr<const Resource>             resource_;
    size_t                                       shard_count_;

    // Mutex protects the instrument maps (insertion is rare — only on
    // get-or-create); it does NOT serialize Counter::Add / Histogram::Record
    // calls (those use their own per-shard SeriesMap mutexes).
    mutable std::mutex                                          inst_mtx_;
    std::unordered_map<std::string, std::unique_ptr<Counter>>   counters_;
    std::unordered_map<std::string, std::unique_ptr<UpDownCounter>> updowns_;
    std::unordered_map<std::string, std::unique_ptr<Histogram>> histograms_;

    // Raw pointer; manager storage outlives every Meter (MeterProvider
    // destructs as part of ~ObservabilityManager's body). Forwarded
    // into every MetricLabelRegistry constructed by GetCounter /
    // GetUpDownCounter / GetHistogram so the slow path can emit
    // `reactor.otel.cardinality_overflow`. 
    // See batch_span_processor.h::manager() docstring for the SHUTDOWN
    // CAVEAT that applies to any code path consuming manager_->
    // sub-members.
    // (Today this dtor is default and emits nothing — caveat applies
    // only if a future dtor adds emission paths.)
    ObservabilityManager*                                       manager_ = nullptr;
};

}  // namespace OBSERVABILITY_NAMESPACE
