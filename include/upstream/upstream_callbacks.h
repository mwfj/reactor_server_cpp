#pragma once

#include "common.h"
// <functional> provided by common.h

// Forward declaration
class UpstreamLease;

namespace UPSTREAM_CALLBACKS_NAMESPACE {

    // Checkout callbacks — invoked on the dispatcher thread that owns
    // the PoolPartition. ReadyCallback delivers a valid lease; ErrorCallback
    // delivers a PoolPartition::CHECKOUT_* error code.
    using ReadyCallback = std::function<void(UpstreamLease)>;
    using ErrorCallback = std::function<void(int error_code)>;

    // Per-H2-stream txn keepalive + deferred terminal-error callable used
    // by UpstreamH2Stream::streaming_abort_callback. Constructed at
    // SubmitStreamingRequest time while the OnCheckoutReady strong-self
    // capture is on the stack; serves double duty: (a) keeps the
    // ProxyTransaction alive for the entire H2 stream lifetime so the
    // raw `sink` pointer cannot dangle, (b) deferred terminal-error
    // callable consumed by OnStreamClose's streaming-abort branch.
    // Args: (result_code, message).
    using H2StreamingAbortCallback =
        std::function<void(int, const std::string&)>;

} // namespace UPSTREAM_CALLBACKS_NAMESPACE
