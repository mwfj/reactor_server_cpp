#pragma once

// ObservabilitySnapshot — per-request bookkeeping snapshot captured at
// handler dispatch. Carries trace identity + route + timing + manager
// weak_ptr through to FinalizeFromSnapshot, where the request-completion
// fan-out (sync handler return / async-completion / streaming
// End/Abort / middleware-rejection / Phase 1c kill) lands a single
// terminal event via the `finalized` CAS gate.
//
// Per OPENTELEMETRY_DESIGN.md §6.1.2 + §13:
//   - finalized: atomic CAS-from-false-to-true gate. Only ONE caller
//                wins; subsequent callers no-op. Guarantees idempotent
//                Span::End + metric record + inflight_finalizations
//                decrement.
//   - link_mtx_: synchronized link/kill protocol mutex per r63. Used
//                between ProxyTransaction::Start (writes tx_weak) AND
//                Phase 1c kill loop (reads tx_weak + sets
//                kill_for_shutdown). Either ordering converges; no
//                "linked-but-not-marked" snapshot can exist.
//   - tx_weak:   weak_ptr<ProxyTransaction> set by ProxyTransaction::Start
//                under link_mtx_ when the transaction is observability-
//                linked. Phase 1c kill loop reads under the same mutex
//                + calls tx->MarkKilledForShutdown() when CAS-winning.
//   - manager:   weak_ptr<ObservabilityManager> captured at snapshot
//                creation. FinalizeFromSnapshot's opening lock() proves
//                the manager outlived the request; null lock = early-
//                return (idempotent kill path already ran).
//   - inbound_span: SERVER span allocated by the observability middleware,
//                captured here so streaming/async paths can attach
//                child spans against it without re-reading the
//                potentially-Reset HttpRequest.
//   - owning_dispatcher: dispatcher that owns the originating connection;
//                Phase 1c kill loop uses this to choose CASE A
//                (off-dispatcher EnQueue) vs CASE B (self-dispatcher
//                inline) per r80.

#include "observability/common.h"
#include "observability/span_context.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>

class Dispatcher;  // include/dispatcher.h forward — pointer member only.

namespace OBSERVABILITY_NAMESPACE {

class Span;                 // forward — span.h
class ObservabilityManager; // forward — observability_manager.h
class UpstreamTransactionLink;  // forward — abstract base in this header

// Abstract handle for the per-request proxy transaction. We cannot
// take a hard dependency on ProxyTransaction (upstream layer); the
// snapshot only needs `MarkKilledForShutdown()` from the kill loop.
// ProxyTransaction implements this interface (header in upstream/);
// non-proxy requests leave `tx_weak` empty.
class UpstreamTransactionLink {
public:
    virtual ~UpstreamTransactionLink() = default;
    virtual void MarkKilledForShutdown() noexcept = 0;
    virtual bool IsKilledForShutdown() const noexcept = 0;
};

struct ObservabilitySnapshot {
    // ---- Identity (immutable post-construction) ----
    SpanContext   trace_context;     // server-hop SpanContext (current_local).
    std::string   route_pattern;     // http.route — copy-from-RouteMatch.pattern.
    std::string   method;            // http.request.method.
    std::string   url_scheme;        // url.scheme.
    std::string   network_protocol_version;  // network.protocol.version.

    // ---- Timing (start captured at snapshot creation; end captured at finalize) ----
    std::chrono::steady_clock::time_point start_steady{};
    std::chrono::system_clock::time_point start_system{};

    // ---- Result (written exactly once by finalize-winner) ----
    std::atomic<int>      status_code{0};       // populated by finalizer.
    std::atomic<uint64_t> wire_body_size{0};    // bytes on the wire post-normalize.
    std::string           error_type;           // populated by finalize-winner under finalized CAS.

    // ---- Inbound SERVER span ----
    std::shared_ptr<Span> inbound_span;          // null on DROP / observability-disabled.

    // ---- Idempotent finalize CAS gate ----
    std::atomic<bool> finalized{false};

    // ---- Synchronized link/kill protocol (r63/r65) ----
    mutable std::mutex                       link_mtx;
    std::weak_ptr<UpstreamTransactionLink>   tx_weak;

    // ---- Manager + dispatcher pointers ----
    std::weak_ptr<ObservabilityManager>      manager;
    Dispatcher*                              owning_dispatcher = nullptr;
};

}  // namespace OBSERVABILITY_NAMESPACE
