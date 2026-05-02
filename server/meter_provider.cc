#include "observability/meter_provider.h"

namespace OBSERVABILITY_NAMESPACE {

MeterProvider::MeterProvider(std::shared_ptr<const Resource> resource,
                               size_t shard_count)
    : resource_(std::move(resource)),
      shard_count_(shard_count > 0 ? shard_count : 1) {}

Meter* MeterProvider::GetMeter(const std::string& name,
                                 const std::string& version) {
    std::string key = name;
    key.push_back('\0');
    key.append(version);

    std::lock_guard<std::mutex> g(meter_mtx_);
    auto it = meters_.find(key);
    if (it != meters_.end()) return it->second.get();
    auto scope = std::make_shared<InstrumentationScope>(name, version);
    auto meter = std::make_unique<Meter>(
        std::move(scope), resource_, shard_count_);
    Meter* raw = meter.get();
    meters_.emplace(std::move(key), std::move(meter));
    return raw;
}

void MeterProvider::Reload(MeterReaderOptions reader_options) {
    std::lock_guard<std::mutex> g(meter_mtx_);
    reader_options_ = reader_options;
}

MeterReaderOptions MeterProvider::reader_options() const noexcept {
    std::lock_guard<std::mutex> g(meter_mtx_);
    return reader_options_;
}

MetricsSnapshot MeterProvider::Snapshot() const {
    MetricsSnapshot snap;
    snap.resource  = resource_;
    snap.timestamp = std::chrono::system_clock::now();

    std::lock_guard<std::mutex> g(meter_mtx_);
    for (const auto& [key, meter] : meters_) {
        meter->SnapshotInto(snap.instruments);
    }
    return snap;
}

}  // namespace OBSERVABILITY_NAMESPACE
