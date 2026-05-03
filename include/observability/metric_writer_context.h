#pragma once

// MetricWriterContext — per-thread shard ID used to spread Counter /
// Histogram writes across multiple per-shard maps so concurrent record()
// calls from different dispatchers don't contend on a single mutex.
//
// Each dispatcher pins a stable shard ID at construction; the metric
// Counter/Histogram pipelines fan out to `shard_count` parallel maps
// and merge at Snapshot() time. shard_count == 0 means "no sharding"
// (single map, all writes converge on one mutex — fine for low-
// concurrency tests).

#include <cstddef>

namespace OBSERVABILITY_NAMESPACE {

// Default shard count — small enough that Snapshot() iteration is
// cheap, large enough to absorb dispatcher contention. Tunable via
// MeterProvider construction options.
inline constexpr size_t kDefaultMetricShards = 8;

class MetricWriterContext {
public:
    // Returns a stable shard ID for the calling thread. Threads that
    // never call this get a deterministic mapping based on
    // `std::thread::id` hash; threads that DO call SetShardId() (e.g.
    // dispatchers at construction) get a hand-picked value.
    static size_t GetShardId(size_t shard_count) noexcept;

    // Pin the calling thread's shard ID. Called by Dispatcher
    // constructor (or equivalent) to give each dispatcher a distinct
    // shard so concurrent writes never collide on the same map.
    static void SetShardId(size_t shard_id) noexcept;

private:
    // thread_local doesn't compose with constexpr in C++17 — define
    // in the .cc.
    static thread_local int  pinned_shard_;
    static thread_local bool has_pinned_;
};

}  // namespace OBSERVABILITY_NAMESPACE
