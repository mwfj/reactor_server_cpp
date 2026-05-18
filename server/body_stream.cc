#include "http/body_stream_impl.h"
#include "dispatcher.h"
#include "log/logger.h"

namespace http {

ChunkQueueBodyStream::ChunkQueueBodyStream(Config cfg)
    : cfg_(std::move(cfg)),
      producer_dispatcher_(cfg_.producer_dispatcher),
      consumer_dispatcher_(cfg_.consumer_dispatcher) {}

ChunkQueueBodyStream::~ChunkQueueBodyStream() = default;

// ---------- Consumer side ----------

BodyStreamResult ChunkQueueBodyStream::Read(char* buf, size_t max_len, size_t* bytes_read) {
    if (!buf || !bytes_read) {
        return BodyStreamResult::ABORTED;
    }
    *bytes_read = 0;
    if (max_len == 0) {
        return BodyStreamResult::OK;
    }

    size_t drained = 0;
    bool fire_below_low_water = false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        // Drain partial-front-cursor style until max_len bytes or queue empty.
        while (!queue_.empty() && drained < max_len) {
            const std::string& front = queue_.front();
            const size_t remaining_in_front = front.size() - front_offset_;
            const size_t want = std::min(remaining_in_front, max_len - drained);
            std::memcpy(buf + drained, front.data() + front_offset_, want);
            drained += want;
            front_offset_ += want;
            if (front_offset_ == front.size()) {
                queue_.pop_front();
                front_offset_ = 0;
            }
        }

        if (drained > 0) {
            // Update relaxed mirror under the lock.
            const size_t prev = bytes_queued_relaxed_.load(std::memory_order_relaxed);
            const size_t now = (prev > drained) ? (prev - drained) : 0;
            bytes_queued_relaxed_.store(now, std::memory_order_relaxed);
            // Hysteresis: fire on_below_low_water only when on_above_high_water
            // previously fired. A queue that climbed between low and high (but
            // never crossed high) must NOT fire below_low_water, since
            // above_high_water never paused the producer — a spurious resume
            // call would unbalance the IncReadDisable/DecReadDisable counter
            // and over-enable reads.
            if (above_high_water_latched_ && now <= cfg_.low_water_bytes) {
                above_high_water_latched_ = false;
                above_low_water_latched_ = false;  // reset both latches for next cycle
                fire_below_low_water = true;
            }
        }

        *bytes_read = drained;

        if (drained == 0) {
            // No bytes drained — classify based on state.
            if (aborted_.load(std::memory_order_acquire)) {
                return BodyStreamResult::ABORTED;
            }
            if (eos_.load(std::memory_order_acquire)) {
                // Publish trailers exactly once on first END_OF_STREAM observation.
                if (!trailers_published_) {
                    trailers_ = std::move(pending_trailers_);
                    pending_trailers_.clear();
                    trailers_published_ = true;
                }
                return BodyStreamResult::END_OF_STREAM;
            }
            return BodyStreamResult::WOULD_BLOCK;
        }
    }

    // Post-lock-release fan-out on producer dispatcher.
    if (drained > 0 && cfg_.on_bytes_consumed) {
        if (auto d = producer_dispatcher_.lock()) {
            d->EnQueue([cb = cfg_.on_bytes_consumed, drained]() { cb(drained); });
        } else {
            cfg_.on_bytes_consumed(drained);
        }
    }
    if (fire_below_low_water && cfg_.on_below_low_water) {
        if (auto d = producer_dispatcher_.lock()) {
            d->EnQueue([cb = cfg_.on_below_low_water]() { cb(); });
        } else {
            cfg_.on_below_low_water();
        }
    }
    return BodyStreamResult::OK;
}

bool ChunkQueueBodyStream::IsEndOfStream() const {
    return eos_.load(std::memory_order_acquire);
}

bool ChunkQueueBodyStream::Aborted() const {
    return aborted_.load(std::memory_order_acquire);
}

const std::vector<std::pair<std::string, std::string>>& ChunkQueueBodyStream::Trailers() const {
    // trailers_ is written exactly once inside Read() under mtx_ (when EOS is
    // first observed and pending_trailers_ is moved over). Lock here so the
    // initial publication is visible to the caller's thread even when it
    // differs from the consumer that ran Read(); after publication the
    // container is immutable, so the returned reference outlives the lock.
    std::lock_guard<std::mutex> lk(mtx_);
    return trailers_;
}

const std::string& ChunkQueueBodyStream::AbortReason() const {
    // abort_reason_ is written under mtx_ inside Abort() before aborted_.store.
    // The release-store + matching acquire-load on aborted_ would normally
    // cover the read, but TSan tracks the access independently — lock here
    // to satisfy the formal memory model and silence the race report.
    // The field is written at most once (Abort() is idempotent), so the
    // reference is valid past the lock release.
    std::lock_guard<std::mutex> lk(mtx_);
    return abort_reason_;
}

void ChunkQueueBodyStream::WaitForData(DataAvailableCallback callback) {
    if (!callback) return;
    DataAvailableCallback fire_immediately;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        const bool has_data = !queue_.empty();
        const bool eos = eos_.load(std::memory_order_acquire);
        const bool aborted = aborted_.load(std::memory_order_acquire);
        if (has_data || eos || aborted) {
            // Already satisfied — fire immediately (still via the consumer
            // dispatcher so ordering with future Push notifications stays
            // consistent).
            fire_immediately = std::move(callback);
        } else {
            pending_consumer_callback_ = std::move(callback);
        }
    }
    if (fire_immediately) {
        if (auto d = consumer_dispatcher_.lock()) {
            d->EnQueue([cb = std::move(fire_immediately)]() mutable { cb(); });
        } else {
            fire_immediately();
        }
    }
}

size_t ChunkQueueBodyStream::BytesQueued() const {
    return bytes_queued_relaxed_.load(std::memory_order_relaxed);
}

// ---------- Producer side ----------

void ChunkQueueBodyStream::Push(std::string chunk) {
    if (chunk.empty()) return;
    DataAvailableCallback fire_consumer;
    bool fire_above_high_water = false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (eos_.load(std::memory_order_relaxed) ||
            aborted_.load(std::memory_order_relaxed)) {
            logging::Get()->warn(
                "ChunkQueueBodyStream::Push after eos/aborted — dropping {} bytes",
                chunk.size());
            return;
        }
        const size_t added = chunk.size();
        queue_.push_back(std::move(chunk));
        const size_t now = bytes_queued_relaxed_.load(std::memory_order_relaxed) + added;
        bytes_queued_relaxed_.store(now, std::memory_order_relaxed);
        if (!above_low_water_latched_ && now > cfg_.low_water_bytes) {
            above_low_water_latched_ = true;
        }
        if (!above_high_water_latched_ && now >= cfg_.high_water_bytes) {
            above_high_water_latched_ = true;
            fire_above_high_water = true;
        }
        if (pending_consumer_callback_) {
            fire_consumer.swap(pending_consumer_callback_);
        }
    }
    if (fire_above_high_water && cfg_.on_above_high_water) {
        if (auto d = producer_dispatcher_.lock()) {
            d->EnQueue([cb = cfg_.on_above_high_water]() { cb(); });
        } else {
            cfg_.on_above_high_water();
        }
    }
    if (fire_consumer) {
        if (auto d = consumer_dispatcher_.lock()) {
            d->EnQueue([cb = std::move(fire_consumer)]() mutable { cb(); });
        } else {
            fire_consumer();
        }
    }
}

void ChunkQueueBodyStream::PushTrailersAndClose(
    std::vector<std::pair<std::string, std::string>> trailers) {
    DataAvailableCallback fire_consumer;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (eos_.load(std::memory_order_relaxed) ||
            aborted_.load(std::memory_order_relaxed)) {
            logging::Get()->warn(
                "ChunkQueueBodyStream::PushTrailersAndClose after eos/aborted — ignored");
            return;
        }
        pending_trailers_ = std::move(trailers);
        eos_.store(true, std::memory_order_release);
        if (pending_consumer_callback_) {
            fire_consumer.swap(pending_consumer_callback_);
        }
    }
    if (fire_consumer) {
        if (auto d = consumer_dispatcher_.lock()) {
            d->EnQueue([cb = std::move(fire_consumer)]() mutable { cb(); });
        } else {
            fire_consumer();
        }
    }
}

void ChunkQueueBodyStream::CloseEmpty() {
    DataAvailableCallback fire_consumer;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        // Idempotent — second call observes eos and returns silently.
        if (eos_.load(std::memory_order_relaxed) ||
            aborted_.load(std::memory_order_relaxed)) {
            return;
        }
        eos_.store(true, std::memory_order_release);
        if (pending_consumer_callback_) {
            fire_consumer.swap(pending_consumer_callback_);
        }
    }
    if (fire_consumer) {
        if (auto d = consumer_dispatcher_.lock()) {
            d->EnQueue([cb = std::move(fire_consumer)]() mutable { cb(); });
        } else {
            fire_consumer();
        }
    }
}

void ChunkQueueBodyStream::Abort(std::string reason) {
    DataAvailableCallback fire_consumer;
    bool fire_below_low_water = false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        // Idempotent — first Abort wins; subsequent calls are dropped.
        if (aborted_.load(std::memory_order_relaxed)) {
            return;
        }
        // Write abort_reason_ BEFORE the release-store on aborted_ so a
        // lockless consumer that observes aborted_=true via acquire-load
        // is guaranteed to see the published reason. Lockless AbortReason()
        // accessors still take the mutex defensively (Trailers() / a future
        // accessor that runs off the consumer dispatcher), but the
        // happens-before chain here covers the common in-flight check.
        abort_reason_ = std::move(reason);
        aborted_.store(true, std::memory_order_release);
        // Drop queued bytes — they will never be drained.
        queue_.clear();
        front_offset_ = 0;
        bytes_queued_relaxed_.store(0, std::memory_order_relaxed);
        pending_trailers_.clear();
        // Mirror Read()'s hysteresis: fire on_below_low_water iff the
        // producer was previously paused via on_above_high_water. Without
        // this, the producer-side IncReadDisable/SuspendWindowUpdate
        // counter stays pinned past abort, wedging the connection on the
        // next high-water-paused stream that never drains.
        if (above_high_water_latched_) {
            above_high_water_latched_ = false;
            above_low_water_latched_ = false;
            fire_below_low_water = true;
        }
        if (pending_consumer_callback_) {
            fire_consumer.swap(pending_consumer_callback_);
        }
    }
    if (fire_below_low_water && cfg_.on_below_low_water) {
        if (auto d = producer_dispatcher_.lock()) {
            d->EnQueue([cb = cfg_.on_below_low_water]() { cb(); });
        } else {
            cfg_.on_below_low_water();
        }
    }
    if (fire_consumer) {
        if (auto d = consumer_dispatcher_.lock()) {
            d->EnQueue([cb = std::move(fire_consumer)]() mutable { cb(); });
        } else {
            fire_consumer();
        }
    }
}

// ---------- Shape decision + late-binding ----------

BodyStream::SubmitSnapshot ChunkQueueBodyStream::SnapshotForSubmit() {
    std::lock_guard<std::mutex> lk(mtx_);
    SubmitSnapshot snap;
    snap.eos          = eos_.load(std::memory_order_relaxed);
    snap.aborted      = aborted_.load(std::memory_order_relaxed);
    snap.bytes_queued = bytes_queued_relaxed_.load(std::memory_order_relaxed);
    snap.has_trailers = !pending_trailers_.empty();
    if (snap.has_trailers) {
        snap.trailers_copy = pending_trailers_;
    }
    return snap;
}

void ChunkQueueBodyStream::SetConsumerDispatcher(std::weak_ptr<Dispatcher> d) {
    std::lock_guard<std::mutex> lk(mtx_);
    consumer_dispatcher_ = std::move(d);
}

}  // namespace http
