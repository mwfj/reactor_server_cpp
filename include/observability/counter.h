#pragma once

// Counter / UpDownCounter — sharded series-map with per-LabelSet
// running totals. `Counter::Add` is monotonic (negative deltas
// rejected with a warn log); `UpDownCounter::Add` accepts both
// directions.
//
// SeriesMap uses shared_lock for steady-state reads (existing series
// found) + unique_lock for new series creation. Concurrent record()
// from multiple dispatchers shards across `kDefaultMetricShards`
// parallel maps so writers never collide on the same mutex;
// Snapshot() merges shards at scrape time.

#include "observability/attr_value.h"
#include "observability/metric_label_registry.h"
#include "observability/metrics_snapshot.h"

#include "../common.h"

namespace OBSERVABILITY_NAMESPACE {

class Meter;  // forward — instruments are created via Meter, never directly.

class Counter {
public:
    Counter(std::string name,
            std::string description,
            std::string unit,
            std::shared_ptr<MetricLabelRegistry> registry,
            size_t shard_count);

    // Add `value` to the series identified by `kvs`. `value < 0` is
    // rejected with a warn log (Counter is monotonic). For
    // UpDownCounter use the dedicated subclass below.
    //
    // Hot-path: builds the LabelSet via the registry (cardinality cap
    // applied), routes to a shard via MetricWriterContext, takes a
    // shared_lock + map find on the shard. New-series creation
    // upgrades to unique_lock.
    void Add(double value,
             const std::vector<std::pair<std::string, std::string>>& kvs);

    // Snapshot all shards into a single CounterPoint vector. Acquires
    // shared_lock on each shard; produces a consistent point-in-time
    // view (concurrent Add() during the snapshot lands in either the
    // PRE or POST snapshot, never split).
    std::vector<CounterPoint> SnapshotPoints() const;

    const std::string& name() const noexcept { return name_; }
    const std::string& description() const noexcept { return description_; }
    const std::string& unit() const noexcept { return unit_; }
    InstrumentKind kind() const noexcept { return kind_; }

protected:
    explicit Counter(InstrumentKind kind,
                      std::string name,
                      std::string description,
                      std::string unit,
                      std::shared_ptr<MetricLabelRegistry> registry,
                      size_t shard_count)
        : name_(std::move(name)),
          description_(std::move(description)),
          unit_(std::move(unit)),
          kind_(kind),
          registry_(std::move(registry)),
          shards_(shard_count > 0 ? shard_count : 1) {}

    void AddInternal(double value,
                      const std::vector<std::pair<std::string, std::string>>& kvs);

private:
    std::string name_;
    std::string description_;
    std::string unit_;
    InstrumentKind kind_ = InstrumentKind::Counter;
    std::shared_ptr<MetricLabelRegistry> registry_;

    struct Series {
        LabelSet labels;
        std::atomic<uint64_t> bits{0};  // Encodes a double via memcpy round-trip.
    };

    struct Shard {
        mutable std::shared_mutex mtx;
        // Hash-based bucketing within a shard — std::unordered_map
        // keyed on LabelSet.hash, with collisions disambiguated by
        // LabelSet equality. We use a vector<Series> per bucket to
        // keep iteration cache-friendly during Snapshot.
        std::unordered_map<uint64_t, std::vector<std::unique_ptr<Series>>> by_hash;
    };
    mutable std::vector<Shard> shards_;

    // Atomically add `value` to a Series's running total. Counter:
    // value >= 0 enforced upstream; UpDownCounter: any sign.
    static void AtomicAdd(Series& s, double value) noexcept;
};

class UpDownCounter : public Counter {
public:
    UpDownCounter(std::string name,
                   std::string description,
                   std::string unit,
                   std::shared_ptr<MetricLabelRegistry> registry,
                   size_t shard_count)
        : Counter(InstrumentKind::UpDownCounter,
                   std::move(name), std::move(description), std::move(unit),
                   std::move(registry), shard_count) {}

    // Same as Counter::Add but accepts negative deltas.
    void Add(double value,
             const std::vector<std::pair<std::string, std::string>>& kvs) {
        AddInternal(value, kvs);
    }
};

}  // namespace OBSERVABILITY_NAMESPACE
