#pragma once
#include "common.h"
#include "http/body_stream.h"

class Dispatcher;

namespace http {

// Concrete ChunkQueueBodyStream — the production BodyStream impl backing
// streaming routes. Producer pushes chunks under mtx_; consumer drains via
// Read with partial-front semantics; high-/low-water marks drive
// producer-side backpressure (inbound H1 read-pause + inbound H2 WINDOW_UPDATE
// throttling). See body_stream.cc for the locking discipline.
class ChunkQueueBodyStream : public BodyStream {
public:
    struct Config {
        size_t high_water_bytes = 262144;
        size_t low_water_bytes  = 65536;
        // Producer-notification callbacks (fired post-lock-release on
        // producer_dispatcher). Used by inbound H2 layer for
        // WINDOW_UPDATE-credit replenishment and by inbound H1 layer for
        // read-pause/resume.
        BodyStream::BytesConsumedCallback on_bytes_consumed = nullptr;
        BodyStream::BelowLowWaterCallback on_below_low_water = nullptr;
        // Fired (post-lock-release) when BytesQueued first crosses high_water_bytes
        // going upward. Used by inbound H1 to pause the read pump (IncReadDisable).
        // The latch resets when bytes drop back below low_water_bytes (at which
        // point on_below_low_water fires to resume). Null disables back-pressure.
        std::function<void()> on_above_high_water = nullptr;
        // Dispatcher binding. consumer_dispatcher is a placeholder at
        // construction; outbound layer late-binds via SetConsumerDispatcher
        // before the first cross-dispatcher Read/WaitForData.
        std::weak_ptr<Dispatcher> producer_dispatcher;
        std::weak_ptr<Dispatcher> consumer_dispatcher;
    };

    explicit ChunkQueueBodyStream(Config cfg);
    ~ChunkQueueBodyStream() override;

    // ---- BodyStream consumer-side overrides ----
    BodyStreamResult Read(char* buf, size_t max_len, size_t* bytes_read) override;
    bool IsEndOfStream() const override;
    bool Aborted() const override;
    const std::vector<std::pair<std::string, std::string>>& Trailers() const override;
    const std::string& AbortReason() const override;
    void WaitForData(DataAvailableCallback callback) override;
    size_t BytesQueued() const override;

    // ---- BodyStream producer-side overrides ----
    void Push(std::string chunk) override;
    void PushTrailersAndClose(std::vector<std::pair<std::string, std::string>> trailers) override;
    void CloseEmpty() override;
    void Abort(std::string reason) override;

    // ---- Shape-decision + late-binding overrides ----
    SubmitSnapshot SnapshotForSubmit() override;
    void SetConsumerDispatcher(std::weak_ptr<Dispatcher> d) override;

private:
    Config cfg_;
    mutable std::mutex mtx_;

    std::deque<std::string> queue_;
    size_t front_offset_ = 0;
    std::atomic<size_t> bytes_queued_relaxed_{0};

    std::atomic<bool> eos_{false};
    std::atomic<bool> aborted_{false};
    std::string abort_reason_;

    std::vector<std::pair<std::string, std::string>> pending_trailers_;
    std::vector<std::pair<std::string, std::string>> trailers_;  // exposed via Trailers() after eos
    bool trailers_published_ = false;

    DataAvailableCallback pending_consumer_callback_;

    std::weak_ptr<Dispatcher> producer_dispatcher_;
    // Latched copy swapped under mtx_ on every SetConsumerDispatcher. weak_ptr
    // remains the canonical access (impl always lock() against it).
    std::weak_ptr<Dispatcher> consumer_dispatcher_;

    // Tracks whether BytesQueued crossed the low-water mark on the last
    // drain — used to gate on_below_low_water_ fire.
    bool above_low_water_latched_ = false;
    // Tracks whether BytesQueued crossed high_water_bytes upward — used to
    // fire on_above_high_water exactly once per high→low→high cycle.
    bool above_high_water_latched_ = false;
};

}  // namespace http
