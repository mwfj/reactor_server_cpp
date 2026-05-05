#include "observability/histogram.h"

#include "observability/metric_writer_context.h"

#include "common.h"
#include <cmath>

namespace OBSERVABILITY_NAMESPACE {

namespace {

inline double BitsToDouble(uint64_t bits) noexcept {
    double d;
    std::memcpy(&d, &bits, sizeof(double));
    return d;
}
inline uint64_t DoubleToBits(double d) noexcept {
    uint64_t bits;
    std::memcpy(&bits, &d, sizeof(double));
    return bits;
}

}  // namespace

Histogram::Histogram(std::string name,
                      std::string description,
                      std::string unit,
                      std::vector<double> bucket_boundaries,
                      std::shared_ptr<MetricLabelRegistry> registry,
                      size_t shard_count)
    : name_(std::move(name)),
      description_(std::move(description)),
      unit_(std::move(unit)),
      bucket_boundaries_(std::move(bucket_boundaries)),
      registry_(std::move(registry)),
      shards_(shard_count > 0 ? shard_count : 1) {
    // Caller-supplied boundaries should be sorted ascending; we
    // defensively sort + dedupe to keep the bucket-walk cheap.
    std::sort(bucket_boundaries_.begin(), bucket_boundaries_.end());
    bucket_boundaries_.erase(std::unique(bucket_boundaries_.begin(),
                                          bucket_boundaries_.end()),
                              bucket_boundaries_.end());
}

void Histogram::Record(double value,
                        const std::vector<std::pair<std::string, std::string>>& kvs) {
    // Reject non-finite samples up front. NaN would fall through to
    // the +Inf bucket, taint sum_bits via AtomicAddDouble (NaN
    // contagion), and could publish has_min_max=true while min/max
    // remain at the +inf/-inf sentinels — corrupting the series for
    // every subsequent observer. ±Inf has the same Prometheus-format
    // and OTLP-output hazard as the histogram_buckets validator
    // already rejects at config load. The HTTP duration recorder
    // never produces these, but custom callers can.
    if (!std::isfinite(value)) return;

    LabelSet labels = registry_->BuildLabelSet(kvs);
    const size_t shard_id = MetricWriterContext::GetShardId(shards_.size());
    Shard& shard = shards_[shard_id];

    Series* series = nullptr;
    {
        std::shared_lock<std::shared_mutex> g(shard.mtx);
        auto it = shard.by_hash.find(labels.hash);
        if (it != shard.by_hash.end()) {
            for (auto& s : it->second) {
                if (s->labels == labels) { series = s.get(); break; }
            }
        }
    }
    if (!series) {
        std::unique_lock<std::shared_mutex> g(shard.mtx);
        auto& bucket = shard.by_hash[labels.hash];
        for (auto& s : bucket) {
            if (s->labels == labels) { series = s.get(); break; }
        }
        if (!series) {
            auto fresh = std::make_unique<Series>(bucket_boundaries_.size() + 1);
            fresh->labels = std::move(labels);
            series = fresh.get();
            bucket.emplace_back(std::move(fresh));
        }
    }

    // Bucket walk — find first boundary >= value; that's the bucket
    // index. Values larger than every boundary land in the +Inf
    // bucket (last index = boundaries.size()).
    size_t bucket_idx = bucket_boundaries_.size();
    for (size_t i = 0; i < bucket_boundaries_.size(); ++i) {
        if (value <= bucket_boundaries_[i]) {
            bucket_idx = i;
            break;
        }
    }
    series->bucket_counts[bucket_idx].fetch_add(1, std::memory_order_release);
    series->count.fetch_add(1, std::memory_order_release);
    AtomicAddDouble(series->sum_bits, value);

    // min/max are pre-initialised to +inf/-inf so the first observation
    // always wins the CAS and overwrites the sentinel — no init-vs-update
    // race. Set has_min_max AFTER the value lands so a snapshot reader
    // never sees has_min_max=true with sentinel values.
    AtomicMin(series->min_bits, value);
    AtomicMax(series->max_bits, value);
    series->has_min_max.store(true, std::memory_order_release);
}

void Histogram::AtomicAddDouble(std::atomic<uint64_t>& bits,
                                  double delta) noexcept {
    uint64_t old_bits = bits.load(std::memory_order_relaxed);
    while (true) {
        const double current = BitsToDouble(old_bits);
        const uint64_t next_bits = DoubleToBits(current + delta);
        if (bits.compare_exchange_weak(old_bits, next_bits,
                                          std::memory_order_release,
                                          std::memory_order_relaxed)) {
            return;
        }
    }
}

void Histogram::AtomicMin(std::atomic<uint64_t>& bits, double v) noexcept {
    uint64_t old_bits = bits.load(std::memory_order_acquire);
    while (BitsToDouble(old_bits) > v) {
        const uint64_t new_bits = DoubleToBits(v);
        if (bits.compare_exchange_weak(old_bits, new_bits,
                                          std::memory_order_release,
                                          std::memory_order_acquire)) {
            return;
        }
    }
}

void Histogram::AtomicMax(std::atomic<uint64_t>& bits, double v) noexcept {
    uint64_t old_bits = bits.load(std::memory_order_acquire);
    while (BitsToDouble(old_bits) < v) {
        const uint64_t new_bits = DoubleToBits(v);
        if (bits.compare_exchange_weak(old_bits, new_bits,
                                          std::memory_order_release,
                                          std::memory_order_acquire)) {
            return;
        }
    }
}

std::vector<HistogramPoint> Histogram::SnapshotPoints() const {
    std::vector<HistogramPoint> out;
    for (const auto& shard : shards_) {
        std::shared_lock<std::shared_mutex> g(shard.mtx);
        for (const auto& [hash, bucket] : shard.by_hash) {
            (void)hash;
            for (const auto& s : bucket) {
                HistogramPoint p;
                p.labels = s->labels;
                p.bucket_boundaries = bucket_boundaries_;
                p.bucket_counts.reserve(s->bucket_counts.size());
                for (const auto& bc : s->bucket_counts) {
                    p.bucket_counts.push_back(bc.load(std::memory_order_acquire));
                }
                p.count = s->count.load(std::memory_order_acquire);
                p.sum   = BitsToDouble(s->sum_bits.load(std::memory_order_acquire));
                p.has_min_max = s->has_min_max.load(std::memory_order_acquire);
                if (p.has_min_max) {
                    p.min = BitsToDouble(s->min_bits.load(std::memory_order_acquire));
                    p.max = BitsToDouble(s->max_bits.load(std::memory_order_acquire));
                }
                out.emplace_back(std::move(p));
            }
        }
    }
    // Cross-shard merge same-labels entries (mirrors Counter::SnapshotPoints).
    if (shards_.size() > 1) {
        std::vector<HistogramPoint> merged;
        merged.reserve(out.size());
        for (auto& p : out) {
            bool merged_in = false;
            for (auto& q : merged) {
                if (q.labels == p.labels) {
                    for (size_t i = 0; i < q.bucket_counts.size(); ++i) {
                        q.bucket_counts[i] += p.bucket_counts[i];
                    }
                    q.count += p.count;
                    q.sum   += p.sum;
                    if (p.has_min_max) {
                        if (!q.has_min_max) {
                            q.min = p.min;
                            q.max = p.max;
                            q.has_min_max = true;
                        } else {
                            q.min = std::min(q.min, p.min);
                            q.max = std::max(q.max, p.max);
                        }
                    }
                    merged_in = true;
                    break;
                }
            }
            if (!merged_in) merged.emplace_back(std::move(p));
        }
        return merged;
    }
    return out;
}

}  // namespace OBSERVABILITY_NAMESPACE
