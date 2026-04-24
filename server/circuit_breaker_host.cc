#include "circuit_breaker/circuit_breaker_host.h"
#include "dispatcher.h"
#include "log/logger.h"
#include "net/dns_resolver.h"  // FormatAuthority for IPv6 log-label rendering

#include <future>

namespace CIRCUIT_BREAKER_NAMESPACE {

CircuitBreakerHost::CircuitBreakerHost(std::string service_name,
                                        std::string host,
                                        int port,
                                        size_t partition_count,
                                        const CircuitBreakerConfig& config)
    : service_name_(std::move(service_name)),
      host_(std::move(host)),
      port_(port),
      config_(config),
      retry_budget_(std::make_unique<RetryBudget>(
          config.retry_budget_percent,
          config.retry_budget_min_concurrency)) {
    // Clamp partition_count — a zero-partition host would be unusable
    // (no slices to dispatch to). Tests or misuse may pass 0; log and
    // clamp to 1 so the host is at least consistent.
    if (partition_count == 0) {
        logging::Get()->error(
            "CircuitBreakerHost({}, {}:{}) constructed with 0 partitions; "
            "clamping to 1",
            service_name_, host_, port_);
        partition_count = 1;
    }

    slices_.reserve(partition_count);
    for (size_t i = 0; i < partition_count; ++i) {
        // Per-slice label for logs — lets operators grep logs for a
        // specific host:partition pair. Key=value form matches the
        // format documented in circuit_breaker_slice.h:host_label_.
        // Byte-identical to the old `host + ":" + port`
        // form for hostnames / IPv4.
        std::string label = "service=" + service_name_ +
                            " host=" +
                            NET_DNS_NAMESPACE::DnsResolver::FormatAuthority(
                                host_, port_, /*omit_port=*/false) +
                            " partition=" + std::to_string(i);
        slices_.emplace_back(std::make_unique<CircuitBreakerSlice>(
            std::move(label), i, config_));
    }
    logging::Get()->debug(
        "CircuitBreakerHost created service={} host={}:{} partitions={} "
        "enabled={} retry_budget={}%,min={}",
        service_name_, host_, port_, partition_count,
        config_.enabled,
        config_.retry_budget_percent,
        config_.retry_budget_min_concurrency);
}

CircuitBreakerSlice* CircuitBreakerHost::GetSlice(size_t dispatcher_index) {
    if (dispatcher_index >= slices_.size()) return nullptr;
    return slices_[dispatcher_index].get();
}

CircuitBreakerHostSnapshot CircuitBreakerHost::Snapshot() const {
    CircuitBreakerHostSnapshot snap;
    snap.service_name = service_name_;
    snap.host = host_;
    snap.port = port_;
    snap.slices.reserve(slices_.size());

    for (const auto& slice : slices_) {
        CircuitBreakerHostSnapshot::SliceRow row;
        row.dispatcher_index = slice->dispatcher_index();
        row.state = slice->CurrentState();
        row.trips = slice->Trips();
        row.rejected = slice->Rejected();
        row.probe_successes = slice->ProbeSuccesses();
        row.probe_failures = slice->ProbeFailures();

        snap.total_trips += row.trips;
        snap.total_rejected += row.rejected;
        if (row.state == State::OPEN) ++snap.open_partitions;
        else if (row.state == State::HALF_OPEN) ++snap.half_open_partitions;

        snap.slices.push_back(row);
    }

    // Retry budget aggregate (host-level, not per-partition).
    snap.retries_in_flight = retry_budget_->RetriesInFlight();
    snap.retries_rejected = retry_budget_->RetriesRejected();
    snap.in_flight = retry_budget_->InFlight();

    return snap;
}

void CircuitBreakerHost::Reload(
        const std::vector<std::shared_ptr<Dispatcher>>& dispatchers,
        const CircuitBreakerConfig& new_config) {
    // Dispatcher list must match the slice count one-for-one — the
    // slice at index i lives on dispatcher i. A size mismatch is a
    // programming error (topology changed post-construction, which is
    // restart-only); log and bail rather than mis-dispatching.
    if (dispatchers.size() != slices_.size()) {
        logging::Get()->error(
            "CircuitBreakerHost::Reload({}:{}) dispatcher count mismatch: "
            "got {}, expected {} — reload skipped",
            service_name_, host_, dispatchers.size(), slices_.size());
        return;
    }

    // Update host-level retry budget fields immediately — atomic stores,
    // no dispatcher routing needed. RetryBudget::Reload clamps internally.
    retry_budget_->Reload(new_config.retry_budget_percent,
                          new_config.retry_budget_min_concurrency);

    // Apply per-slice Reload on each owning dispatcher. The slice is
    // dispatcher-thread-local for mutation, so the config swap must
    // happen there. Passing slice as raw pointer is safe: slices_ is
    // owned by `this` (the host), which outlives the manager's reload
    // (enforced by CircuitBreakerManager's lifetime).
    //
    // Synchronize: wait for every enqueued slice Reload to actually run
    // before returning. Without this, HttpServer::Reload could return
    // "success" while requests already queued on a dispatcher still run
    // with the OLD enabled/dry_run/thresholds — a SIGHUP flipping a
    // tripped breaker to disabled (or to dry_run) could still emit hard
    // 503s or enforce the old retry budget for a brief window after the
    // operator sees reload-ok. Dispatcher-local inline on the current
    // thread avoids self-deadlock if Reload is ever called from a
    // dispatcher thread.
    std::vector<std::future<void>> pending;
    pending.reserve(slices_.size());
    for (size_t i = 0; i < slices_.size(); ++i) {
        CircuitBreakerSlice* slice = slices_[i].get();
        auto& dispatcher = dispatchers[i];
        if (!dispatcher) {
            logging::Get()->error(
                "CircuitBreakerHost::Reload({}:{}) null dispatcher at index {}",
                service_name_, host_, i);
            continue;
        }
        if (dispatcher->is_on_loop_thread()) {
            // Caller IS this dispatcher — apply inline to preserve
            // dispatcher-thread-local invariant without self-enqueueing
            // (which would only run after this frame returns, defeating
            // the sync contract). No future to wait on for this slice.
            slice->Reload(new_config);
            continue;
        }
        auto promise = std::make_shared<std::promise<void>>();
        pending.push_back(promise->get_future());
        dispatcher->EnQueue([slice, new_config, promise]() {
            slice->Reload(new_config);
            promise->set_value();
        });
    }

    // Bounded wait: slice Reload is trivial (config copy + optional
    // synthetic transition callback), so each dispatcher only needs one
    // event-loop iteration to drain. A 2s ceiling protects callers from
    // a stalled / stopping dispatcher — if the wait times out we log and
    // proceed; the remaining slice(s) will pick up the new config when
    // the queued task eventually runs (via the shared_ptr-captured
    // new_config copy), so we never lose an edit — just delay its visibility.
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(2);
    for (auto& fut : pending) {
        if (fut.wait_until(deadline) != std::future_status::ready) {
            logging::Get()->warn(
                "CircuitBreakerHost::Reload({}:{}) timed out waiting for "
                "slice apply — new config will be applied when the "
                "dispatcher drains", service_name_, host_);
            break;  // No benefit to waiting out the remaining futures
                    // after the first timeout — they share the deadline.
        }
    }

    // Save the new config for future Snapshot() / construction-like
    // operations. Other threads never read config_ directly.
    config_ = new_config;
}

void CircuitBreakerHost::SetTransitionCallbackOnAllSlices(
        StateTransitionCallback cb) {
    for (auto& slice : slices_) {
        // Copy the callback so each slice owns its own std::function.
        // Passing by value into SetTransitionCallback gives each slice
        // an independent copy, avoiding cross-partition std::function
        // data races.
        slice->SetTransitionCallback(cb);
    }
}

}  // namespace CIRCUIT_BREAKER_NAMESPACE
