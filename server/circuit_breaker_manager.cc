#include "circuit_breaker/circuit_breaker_manager.h"
#include "log/logger.h"
#include <unordered_set>

namespace circuit_breaker {

CircuitBreakerManager::CircuitBreakerManager(
        const std::vector<UpstreamConfig>& upstreams,
        size_t partition_count,
        std::vector<std::shared_ptr<Dispatcher>> dispatchers)
    : dispatchers_(std::move(dispatchers)) {
    // Invariant (production path): slices are indexed by dispatcher,
    // so partition_count must match dispatcher count. Any divergence
    // would cause every subsequent host->Reload() to silently skip
    // (size-mismatch guard in CircuitBreakerHost::Reload) — fail
    // loudly at startup instead of on reload.
    //
    // Exception: pure unit tests that don't exercise Reload pass an
    // empty dispatcher list; skip the check in that case so those
    // tests can continue to allocate slices without wiring up live
    // dispatchers.
    if (!dispatchers_.empty() && partition_count != dispatchers_.size()) {
        logging::Get()->critical(
            "CircuitBreakerManager: partition_count ({}) != dispatcher count "
            "({}) — topology mismatch",
            partition_count, dispatchers_.size());
        throw std::invalid_argument(
            "CircuitBreakerManager: partition_count must equal dispatcher count");
    }

    // Build one Host per upstream regardless of .circuit_breaker.enabled.
    // Disabled hosts still need a live Slice so a later reload can flip
    // them on without re-wiring transition callbacks (design §3.1).
    hosts_.reserve(upstreams.size());
    for (const auto& u : upstreams) {
        if (u.name.empty()) {
            // ConfigLoader::Validate rejects empty names upstream, but
            // defense in depth — skip rather than insert an unreachable
            // host with an empty key that would shadow future lookups.
            logging::Get()->error(
                "CircuitBreakerManager: skipping upstream with empty name");
            continue;
        }
        auto [it, inserted] = hosts_.emplace(
            u.name,
            std::make_unique<CircuitBreakerHost>(
                u.name, u.host, u.port, partition_count, u.circuit_breaker));
        if (!inserted) {
            // Duplicate service name — shouldn't happen (Validate checks
            // uniqueness), but log so the collision is visible rather
            // than silently dropping the second entry.
            logging::Get()->error(
                "CircuitBreakerManager: duplicate upstream name '{}' ignored",
                u.name);
        }
    }
    logging::Get()->info(
        "CircuitBreakerManager initialized hosts={} partitions={}",
        hosts_.size(), partition_count);
}

CircuitBreakerHost* CircuitBreakerManager::GetHost(
        const std::string& service_name) {
    auto it = hosts_.find(service_name);
    return it == hosts_.end() ? nullptr : it->second.get();
}

const CircuitBreakerHost* CircuitBreakerManager::GetHost(
        const std::string& service_name) const {
    auto it = hosts_.find(service_name);
    return it == hosts_.end() ? nullptr : it->second.get();
}

void CircuitBreakerManager::Reload(
        const std::vector<UpstreamConfig>& new_upstreams) {
    // Serialize with any other Reload calls. Hot path doesn't take this.
    std::lock_guard<std::mutex> lk(reload_mtx_);

    // Detect topology changes (added / removed service names) so we can
    // log and skip — the authoritative "restart required" warning lives
    // in HttpServer::Reload; we just honor the "existing hosts only"
    // contract by applying breaker fields to matching names and nothing
    // else.
    std::unordered_set<std::string> new_names;
    new_names.reserve(new_upstreams.size());
    for (const auto& u : new_upstreams) new_names.insert(u.name);

    for (const auto& u : new_upstreams) {
        auto* host = GetHost(u.name);
        if (!host) {
            // New service name — topology change, skip. The outer
            // reload layer warns.
            logging::Get()->warn(
                "CircuitBreakerManager::Reload: new upstream '{}' requires "
                "restart (ignored)",
                u.name);
            continue;
        }
        host->Reload(dispatchers_, u.circuit_breaker);
    }

    // Log removals without touching the hosts (their removal also
    // requires a restart).
    for (const auto& [name, _] : hosts_) {
        if (new_names.find(name) == new_names.end()) {
            logging::Get()->warn(
                "CircuitBreakerManager::Reload: removed upstream '{}' requires "
                "restart (ignored)",
                name);
        }
    }
}

std::vector<CircuitBreakerHostSnapshot>
CircuitBreakerManager::SnapshotAll() const {
    std::vector<CircuitBreakerHostSnapshot> snapshots;
    snapshots.reserve(hosts_.size());
    for (const auto& [_, host] : hosts_) {
        snapshots.push_back(host->Snapshot());
    }
    return snapshots;
}

}  // namespace circuit_breaker
