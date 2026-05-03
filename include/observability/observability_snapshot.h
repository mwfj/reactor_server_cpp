#pragma once

// ObservabilitySnapshot — per-request bookkeeping captured at handler
// dispatch. Carries trace identity + route + timing + manager weak_ptr
// through to FinalizeFromSnapshot, where the request-completion fan-out
// (sync handler return / async-completion / streaming End/Abort /
// middleware-rejection / shutdown kill) lands a single terminal event
// via the `finalized` CAS gate.
//
// Field semantics:
//   finalized            — CAS-from-false-to-true gate. One caller wins;
//                          everyone else no-ops. Guarantees idempotent
//                          Span::End + metric record + inflight_finalizations
//                          decrement.
//   link_mtx + tx_weak   — synchronized link/kill protocol. ProxyTransaction
//                          ::Start writes tx_weak under link_mtx; the
//                          shutdown kill loop reads under the same mutex
//                          and calls tx->MarkKilledForShutdown(). Either
//                          ordering converges — no "linked but not yet
//                          marked" snapshot can exist.
//   manager              — weak_ptr captured at snapshot creation.
//                          Finalize's opening lock() proves the manager
//                          outlived the request; null lock means the
//                          idempotent kill path already ran.
//   inbound_span         — SERVER span allocated by the observability
//                          middleware. Captured here so streaming /
//                          async paths attach child spans without re-
//                          reading a potentially-Reset HttpRequest.
//   owning_dispatcher    — dispatcher that owns the originating
//                          connection. The shutdown kill loop uses it
//                          to choose between inline-on-self-dispatcher
//                          and cross-dispatcher EnQueue.

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
    // Publish the transaction weak_ptr under link_mtx so the kill loop
    // can find and mark it. Either ordering with the kill loop converges
    // — there is no "linked but not yet marked" window.
    void AttachTransaction(std::weak_ptr<UpstreamTransactionLink> tx) {
        std::lock_guard<std::mutex> g(link_mtx);
        tx_weak = std::move(tx);
    }

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

    // ---- Synchronized link/kill protocol ----
    mutable std::mutex                       link_mtx;
    std::weak_ptr<UpstreamTransactionLink>   tx_weak;

    // ---- Manager + dispatcher pointers ----
    std::weak_ptr<ObservabilityManager>      manager;
    Dispatcher*                              owning_dispatcher = nullptr;
};

}  // namespace OBSERVABILITY_NAMESPACE
