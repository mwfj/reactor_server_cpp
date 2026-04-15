#pragma once

#include "common.h"
#include "circuit_breaker/circuit_breaker_host.h"
// <memory>, <mutex>, <string>, <unordered_map>, <vector> provided by common.h

class Dispatcher;

namespace CIRCUIT_BREAKER_NAMESPACE {

// Top-level circuit-breaker orchestrator. Mirrors the shape of
// RateLimitManager: one instance lives on HttpServer, built once at
// MarkServerReady, survives for the server's lifetime.
//
// Ownership (per design §3.1):
//   HttpServer
//     ├── upstream_manager_        (declared FIRST, destructs last)
//     └── circuit_breaker_manager_ (declared SECOND, destructs first)
//
//   CircuitBreakerManager
//     └── hosts_: unordered_map<service_name, unique_ptr<CircuitBreakerHost>>
//
// `hosts_` is built once in the constructor — keys are never added or
// removed at runtime (topology is restart-only per the existing
// upstream policy). This makes GetHost lock-free after construction,
// which is critical for the hot path.
//
// Hot-reload: only `circuit_breaker` sub-fields on EXISTING
// upstream services can be live-reloaded. New or removed service names
// log a warn and are skipped — the caller (HttpServer::Reload) still
// fires the "restart required" diagnostic in that case.
class CircuitBreakerManager {
public:
    // Builds one CircuitBreakerHost per upstream in `upstreams` — even
    // when upstreams[i].circuit_breaker.enabled is false — so a later
    // reload that flips enabled to true can take effect without
    // re-wiring transition callbacks (disabled slices hold the callback
    // but never invoke it).
    //
    // `partition_count` must match the server's dispatcher partition
    // count (upstream pool / NetServer worker count). `dispatchers`
    // captures the dispatcher list so Reload can route per-slice work.
    CircuitBreakerManager(
        const std::vector<UpstreamConfig>& upstreams,
        size_t partition_count,
        std::vector<std::shared_ptr<Dispatcher>> dispatchers);

    CircuitBreakerManager(const CircuitBreakerManager&) = delete;
    CircuitBreakerManager& operator=(const CircuitBreakerManager&) = delete;

    // Hot-path lookup — returns nullptr for unknown service names.
    // Thread-safe (post-construction `hosts_` is read-only).
    CircuitBreakerHost* GetHost(const std::string& service_name);
    const CircuitBreakerHost* GetHost(const std::string& service_name) const;

    // Apply breaker-field edits to EXISTING upstream services. Topology
    // changes (new/removed service names) are logged at warn and
    // skipped — HttpServer::Reload is the only layer that warns about
    // topology, and this manager trusts that signal. Serialized by
    // reload_mtx_ so concurrent Reload calls queue cleanly; the hot
    // path does NOT take this lock.
    void Reload(const std::vector<UpstreamConfig>& new_upstreams);

    // Observability — snapshots every host. Safe from any thread.
    std::vector<CircuitBreakerHostSnapshot> SnapshotAll() const;

    // Test/admin helpers.
    size_t host_count() const { return hosts_.size(); }

private:
    // Post-construction read-only — keys and unique_ptr values never
    // change, so lookups don't need a lock.
    std::unordered_map<std::string, std::unique_ptr<CircuitBreakerHost>> hosts_;
    std::vector<std::shared_ptr<Dispatcher>> dispatchers_;

    // Serializes concurrent Reload calls. NOT taken on the hot path.
    mutable std::mutex reload_mtx_;
};

}  // namespace CIRCUIT_BREAKER_NAMESPACE
