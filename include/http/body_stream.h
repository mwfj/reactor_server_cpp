#pragma once
#include "common.h"
#include "http/http_callbacks.h"

class Dispatcher;

namespace http {

enum class BodyStreamResult {
    OK,
    WOULD_BLOCK,
    END_OF_STREAM,
    ABORTED
};

// Abstract base for the streaming-request body pipeline. Producer (inbound
// dispatcher) pushes chunks; consumer (outbound dispatcher) pulls. WaitForData
// registers a one-shot resume callback when Read returns WOULD_BLOCK.
class BodyStream {
public:
    // Re-export from HTTP_CALLBACKS_NAMESPACE so callers can keep using
    // the short `BodyStream::DataAvailableCallback` form while the canonical
    // alias lives with the rest of the HTTP-layer callbacks
    // (CODE_CONVENTIONS.md §Callbacks & Callback Registries).
    using DataAvailableCallback =
        HTTP_CALLBACKS_NAMESPACE::BodyStreamDataAvailableCallback;
    using BytesConsumedCallback =
        HTTP_CALLBACKS_NAMESPACE::BodyStreamBytesConsumedCallback;
    using BelowLowWaterCallback =
        HTTP_CALLBACKS_NAMESPACE::BodyStreamBelowLowWaterCallback;

    virtual ~BodyStream() = default;

    // ---- Consumer side (outbound dispatcher) ----

    virtual BodyStreamResult Read(char* buf, size_t max_len, size_t* bytes_read) = 0;
    virtual bool IsEndOfStream() const = 0;
    virtual bool Aborted() const = 0;
    virtual const std::vector<std::pair<std::string, std::string>>& Trailers() const = 0;
    virtual const std::string& AbortReason() const = 0;
    virtual void WaitForData(DataAvailableCallback callback) = 0;
    virtual size_t BytesQueued() const = 0;

    // ---- Producer side (inbound dispatcher) ----

    virtual void Push(std::string chunk) = 0;
    virtual void PushTrailersAndClose(std::vector<std::pair<std::string, std::string>> trailers) = 0;
    virtual void CloseEmpty() = 0;
    virtual void Abort(std::string reason) = 0;

    // ---- Outbound submit-time shape decision ----

    // Atomic snapshot of (eos, aborted, bytes_queued, has_trailers, trailers).
    // The outbound codec consults this once at submit time to pick one of
    // three shapes (PureBodyless / EmptyBodyWithTrailers / Bodied); after
    // the shape commits to the wire, subsequent state changes are observed
    // through WaitForData / Read returns. Separate accessors on the four
    // pieces would race PushTrailersAndClose across the producer/consumer
    // dispatcher boundary.
    struct SubmitSnapshot {
        bool   eos;
        bool   aborted;
        size_t bytes_queued;
        bool   has_trailers;
        std::vector<std::pair<std::string, std::string>> trailers_copy;
    };
    virtual SubmitSnapshot SnapshotForSubmit() = 0;

    // ---- Consumer-dispatcher late-binding ----

    // Re-bind the consumer-side dispatcher. Inbound H2/H1 streaming
    // constructs body_stream at HEADERS-complete BEFORE the outbound
    // dispatcher is known (the outbound dispatcher is the dispatcher that
    // owns the lease/connection picked up at checkout time). The producer
    // dispatcher is used as a placeholder at construction; the consumer
    // MUST call SetConsumerDispatcher() BEFORE its first Read / WaitForData.
    // Idempotent: subsequent calls swap the weak_ptr under mtx_ to coexist
    // with any in-flight WaitForData fire. Calling concurrently with a
    // Read/WaitForData on a different dispatcher is undefined.
    virtual void SetConsumerDispatcher(std::weak_ptr<Dispatcher> d) = 0;
};

}  // namespace http
