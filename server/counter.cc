#include "observability/counter.h"

#include "log/logger.h"
#include "observability/metric_writer_context.h"

#include "common.h"
#include <cmath>

namespace OBSERVABILITY_NAMESPACE {

Counter::Counter(std::string name,
                  std::string description,
                  std::string unit,
                  std::shared_ptr<MetricLabelRegistry> registry,
                  size_t shard_count)
    : name_(std::move(name)),
      description_(std::move(description)),
      unit_(std::move(unit)),
      kind_(InstrumentKind::Counter),
      registry_(std::move(registry)),
      shards_(shard_count > 0 ? shard_count : 1) {}

void Counter::Add(double value,
                   const std::vector<std::pair<std::string, std::string>>& kvs) {
    // NaN < 0 is false, so a NaN delta would slip past the negative
    // gate and contaminate the atomic sum (NaN contagion → all
    // subsequent reads return NaN). Reject non-finite values up
    // front, matching Histogram::Record.
    if (!std::isfinite(value)) {
        logging::Get()->warn(
            "Counter::Add rejected non-finite value for instrument '{}'",
            name_);
        return;
    }
    if (value < 0) {
        logging::Get()->warn(
            "Counter::Add rejected negative value {} for instrument '{}'",
            value, name_);
        return;
    }
    AddInternal(value, kvs);
}

void Counter::AddInternal(double value,
                            const std::vector<std::pair<std::string, std::string>>& kvs) {
    // UpDownCounter::Add bypasses the public Counter::Add gate, so
    // mirror the non-finite reject here too — otherwise a NaN/Inf
    // delta from the UpDownCounter path would taint the same atomic
    // sum and corrupt the gauge series.
    if (!std::isfinite(value)) {
        logging::Get()->warn(
            "Counter::AddInternal rejected non-finite value for instrument '{}'",
            name_);
        return;
    }
    LabelSet labels = registry_->BuildLabelSet(kvs);
    const size_t shard_id = MetricWriterContext::GetShardId(shards_.size());
    Shard& shard = shards_[shard_id];

    // Fast path: shared_lock + bucket lookup.
    {
        std::shared_lock<std::shared_mutex> g(shard.mtx);
        auto it = shard.by_hash.find(labels.hash);
        if (it != shard.by_hash.end()) {
            for (auto& s : it->second) {
                if (s->labels == labels) {
                    AtomicAdd(*s, value);
                    return;
                }
            }
        }
    }
    // Slow path: unique_lock + maybe-insert.
    std::unique_lock<std::shared_mutex> g(shard.mtx);
    auto& bucket = shard.by_hash[labels.hash];
    for (auto& s : bucket) {
        if (s->labels == labels) {
            AtomicAdd(*s, value);
            return;
        }
    }
    auto fresh = std::make_unique<Series>();
    fresh->labels = std::move(labels);
    AtomicAdd(*fresh, value);
    bucket.emplace_back(std::move(fresh));
}

void Counter::AtomicAdd(Series& s, double value) noexcept {
    // Compare-exchange loop on the bit-pattern of the running double.
    // memcpy round-trip is the std::bit_cast equivalent for C++17.
    uint64_t old_bits = s.bits.load(std::memory_order_relaxed);
    while (true) {
        double current;
        std::memcpy(&current, &old_bits, sizeof(double));
        const double next = current + value;
        uint64_t next_bits;
        std::memcpy(&next_bits, &next, sizeof(double));
        if (s.bits.compare_exchange_weak(old_bits, next_bits,
                                            std::memory_order_release,
                                            std::memory_order_relaxed)) {
            return;
        }
    }
}

std::vector<CounterPoint> Counter::SnapshotPoints() const {
    // Walk every shard under shared_lock; entries from concurrent
    // Add()s during the snapshot land either in the merged result or
    // get picked up next snapshot — never split.
    std::vector<CounterPoint> out;
    for (const auto& shard : shards_) {
        std::shared_lock<std::shared_mutex> g(shard.mtx);
        for (const auto& [hash, bucket] : shard.by_hash) {
            (void)hash;
            for (const auto& s : bucket) {
                CounterPoint p;
                p.labels = s->labels;
                uint64_t bits = s->bits.load(std::memory_order_acquire);
                std::memcpy(&p.value, &bits, sizeof(double));
                out.emplace_back(std::move(p));
            }
        }
    }
    // Two shards may have the same LabelSet (a process re-pinning of
    // shard ids would be unusual but harmless). Merge same-labels
    // entries by sum so the exporter sees one point per series.
    if (shards_.size() > 1) {
        std::unordered_map<uint64_t, size_t> first_idx;
        std::vector<CounterPoint> merged;
        merged.reserve(out.size());
        for (auto& p : out) {
            auto it = first_idx.find(p.labels.hash);
            if (it != first_idx.end() &&
                merged[it->second].labels == p.labels) {
                merged[it->second].value += p.value;
            } else {
                first_idx[p.labels.hash] = merged.size();
                merged.emplace_back(std::move(p));
            }
        }
        return merged;
    }
    return out;
}

}  // namespace OBSERVABILITY_NAMESPACE
