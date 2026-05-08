#include "observability/metric_writer_context.h"

#include <functional>
#include <thread>

namespace OBSERVABILITY_NAMESPACE {

thread_local int  MetricWriterContext::pinned_shard_ = -1;
thread_local bool MetricWriterContext::has_pinned_   = false;

size_t MetricWriterContext::GetShardId(size_t shard_count) noexcept {
    if (shard_count == 0) return 0;
    if (has_pinned_) {
        return static_cast<size_t>(pinned_shard_) % shard_count;
    }
    // Fall back to a thread_id-hash mapping. Stable per-thread for the
    // thread's lifetime; cheap to compute (one hash + modulo).
    const auto h =
        std::hash<std::thread::id>{}(std::this_thread::get_id());
    return static_cast<size_t>(h) % shard_count;
}

void MetricWriterContext::SetShardId(size_t shard_id) noexcept {
    pinned_shard_ = static_cast<int>(shard_id);
    has_pinned_   = true;
}

}  // namespace OBSERVABILITY_NAMESPACE
