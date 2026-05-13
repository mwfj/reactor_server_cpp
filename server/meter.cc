#include "observability/meter.h"

#include "common.h"

namespace OBSERVABILITY_NAMESPACE {

Meter::Meter(std::shared_ptr<const InstrumentationScope>   scope,
              std::shared_ptr<const Resource>              resource,
              size_t                                       shard_count,
              ObservabilityManager*                        manager)
    : scope_(std::move(scope)),
      resource_(std::move(resource)),
      shard_count_(shard_count > 0 ? shard_count : 1),
      manager_(manager) {}

Counter* Meter::GetCounter(const std::string& name,
                           const std::string& description,
                           const std::string& unit,
                           MetricLabelRegistry::Catalog catalog) {
    std::lock_guard<std::mutex> g(inst_mtx_);
    auto it = counters_.find(name);
    if (it != counters_.end()) return it->second.get();
    auto registry = std::make_shared<MetricLabelRegistry>(std::move(catalog),
                                                            manager_);
    auto inst = std::make_unique<Counter>(
        name, description, unit, std::move(registry), shard_count_);
    Counter* raw = inst.get();
    counters_.emplace(name, std::move(inst));
    return raw;
}

UpDownCounter* Meter::GetUpDownCounter(const std::string& name,
                                       const std::string& description,
                                       const std::string& unit,
                                       MetricLabelRegistry::Catalog catalog) {
    std::lock_guard<std::mutex> g(inst_mtx_);
    auto it = updowns_.find(name);
    if (it != updowns_.end()) return it->second.get();
    auto registry = std::make_shared<MetricLabelRegistry>(std::move(catalog),
                                                            manager_);
    auto inst = std::make_unique<UpDownCounter>(
        name, description, unit, std::move(registry), shard_count_);
    UpDownCounter* raw = inst.get();
    updowns_.emplace(name, std::move(inst));
    return raw;
}

Histogram* Meter::GetHistogram(const std::string& name,
                               const std::string& description,
                               const std::string& unit,
                               std::vector<double> bucket_boundaries,
                               MetricLabelRegistry::Catalog catalog) {
    std::lock_guard<std::mutex> g(inst_mtx_);
    auto it = histograms_.find(name);
    if (it != histograms_.end()) return it->second.get();
    auto registry = std::make_shared<MetricLabelRegistry>(std::move(catalog),
                                                            manager_);
    auto inst = std::make_unique<Histogram>(
        name, description, unit, std::move(bucket_boundaries),
        std::move(registry), shard_count_);
    Histogram* raw = inst.get();
    histograms_.emplace(name, std::move(inst));
    return raw;
}

void Meter::SnapshotInto(std::vector<InstrumentSnapshot>& out) const {
    std::lock_guard<std::mutex> g(inst_mtx_);
    for (const auto& [n, inst] : counters_) {
        InstrumentSnapshot s;
        s.name           = inst->name();
        s.description    = inst->description();
        s.unit           = inst->unit();
        s.kind           = inst->kind();
        s.scope          = scope_;
        s.counter_points = inst->SnapshotPoints();
        out.emplace_back(std::move(s));
    }
    for (const auto& [n, inst] : updowns_) {
        InstrumentSnapshot s;
        s.name           = inst->name();
        s.description    = inst->description();
        s.unit           = inst->unit();
        s.kind           = inst->kind();
        s.scope          = scope_;
        s.counter_points = inst->SnapshotPoints();
        out.emplace_back(std::move(s));
    }
    for (const auto& [n, inst] : histograms_) {
        InstrumentSnapshot s;
        s.name             = inst->name();
        s.description      = inst->description();
        s.unit             = inst->unit();
        s.kind             = inst->kind();
        s.scope            = scope_;
        s.histogram_points = inst->SnapshotPoints();
        out.emplace_back(std::move(s));
    }
}

}  // namespace OBSERVABILITY_NAMESPACE
