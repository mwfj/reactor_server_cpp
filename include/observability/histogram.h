#pragma once

// Histogram — bucketed distribution + sum/count + min/max per OTel
// SDK spec. Sharded SeriesMap (same shape as Counter) so concurrent
// dispatcher writes never contend.
//
// Bucket boundaries are fixed at construction time per
// OPENTELEMETRY_DESIGN.md §11.2 ("histogram_buckets is restart-only —
// reshaping live histograms drops counts"). The default boundaries
// match OTel HTTP semconv recommendations (14 buckets covering
// 5ms..10s).

#include "observability/attr_value.h"
#include "observability/metric_label_registry.h"
#include "observability/metrics_snapshot.h"

#include <atomic>
#include <cstddef>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace OBSERVABILITY_NAMESPACE {

// OTel HTTP semconv recommended boundaries (14 buckets).
inline constexpr double kDefaultHttpHistogramBuckets[] = {
    0.005, 0.01, 0.025, 0.05, 0.075, 0.1,
    0.25,  0.5,  0.75,  1.0,  2.5,   5.0, 7.5, 10.0
};

class Histogram {
public:
    Histogram(std::string name,
              std::string description,
              std::string unit,
              std::vector<double> bucket_boundaries,
              std::shared_ptr<MetricLabelRegistry> registry,
              size_t shard_count);

    // Record `value` into the series identified by `kvs`. Per OTel
    // spec, negative values are recorded — they're rare for latency
    // histograms but valid for general distributions.
    void Record(double value,
                 const std::vector<std::pair<std::string, std::string>>& kvs);

    std::vector<HistogramPoint> SnapshotPoints() const;

    const std::string& name() const noexcept { return name_; }
    const std::string& description() const noexcept { return description_; }
    const std::string& unit() const noexcept { return unit_; }
    const std::vector<double>& boundaries() const noexcept {
        return bucket_boundaries_;
    }
    InstrumentKind kind() const noexcept { return InstrumentKind::Histogram; }

private:
    std::string name_;
    std::string description_;
    std::string unit_;
    std::vector<double> bucket_boundaries_;  // size N → N+1 buckets (last = +Inf)
    std::shared_ptr<MetricLabelRegistry> registry_;

    // Each Series tracks: per-bucket count, sum, count, min, max.
    // Counts are uint64; sum/min/max are doubles encoded as uint64
    // bits via memcpy (matching Counter's atomic update pattern).
    struct Series {
        LabelSet                       labels;
        std::vector<std::atomic<uint64_t>> bucket_counts;  // size = boundaries+1
        std::atomic<uint64_t>          count{0};
        std::atomic<uint64_t>          sum_bits{0};
        std::atomic<uint64_t>          min_bits{0};
        std::atomic<uint64_t>          max_bits{0};
        std::atomic<bool>              has_min_max{false};

        explicit Series(size_t bucket_n) : bucket_counts(bucket_n) {
            for (auto& b : bucket_counts) {
                b.store(0, std::memory_order_relaxed);
            }
        }
    };

    struct Shard {
        mutable std::shared_mutex mtx;
        std::unordered_map<uint64_t,
                            std::vector<std::unique_ptr<Series>>> by_hash;
    };
    mutable std::vector<Shard> shards_;

    static void AtomicAddDouble(std::atomic<uint64_t>& bits,
                                  double delta) noexcept;
    static void AtomicMin(std::atomic<uint64_t>& bits, double v) noexcept;
    static void AtomicMax(std::atomic<uint64_t>& bits, double v) noexcept;
};

}  // namespace OBSERVABILITY_NAMESPACE
