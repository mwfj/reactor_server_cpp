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

} // namespace UPSTREAM_CALLBACKS_NAMESPACE
