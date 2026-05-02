#pragma once

// SpanExporter — the wire-format export interface.
//
// Per OPENTELEMETRY_DESIGN.md §8.2 r84: the exporter owns NO worker
// thread (BatchSpanProcessor / PeriodicMetricReader own worker
// shutdown). The exporter's lifecycle is the trio:
//
//   SignalShutdown()           — refuse new Export() calls; subsequent
//                                  Export() returns kFailedNotRetryable.
//                                  Idempotent.
//   CancelAllActiveExports()   — ONLY called from §13's self-dispatcher /
//                                  single-dispatcher branch; force-cancels
//                                  in-flight exports so the processor's
//                                  drain loop can exit without blocking
//                                  on a queued dispatcher hop. Idempotent.
//   RebindDispatcher(d)        — re-home in-flight export hops onto a
//                                  surviving dispatcher when the original
//                                  pinned dispatcher is being torn down.
//                                  Optional; default no-op.

#include "observability/span_data.h"

#include <chrono>
#include <vector>

class Dispatcher;  // include/dispatcher.h forward — pointer parameter only.

namespace OBSERVABILITY_NAMESPACE {

enum class ExportResult {
    kSuccess              = 0,
    kFailedRetryable      = 1,  // network blip, 5xx, retry budget allows another attempt.
    kFailedNotRetryable   = 2,  // shutdown, 4xx (except 429), permanent classifier.
};

class SpanExporter {
public:
    virtual ~SpanExporter() = default;

    // Send `batch` to the wire. `deadline = max()` means "no caller-
    // imposed deadline" (the exporter's per-attempt sig.timeout still
    // applies); shutdown paths compute `now() + t` and pass it through.
    virtual ExportResult Export(std::vector<SpanData> batch,
                                 std::chrono::steady_clock::time_point deadline =
                                     std::chrono::steady_clock::time_point::max()) = 0;

    // r84 shutdown trio.
    virtual void SignalShutdown() = 0;
    virtual void CancelAllActiveExports() = 0;
    virtual void RebindDispatcher(Dispatcher* /*new_export_dispatcher*/) {}
};

}  // namespace OBSERVABILITY_NAMESPACE
