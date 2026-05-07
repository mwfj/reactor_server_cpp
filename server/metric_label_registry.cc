#include "observability/metric_label_registry.h"

#include "common.h"

namespace OBSERVABILITY_NAMESPACE {

MetricLabelRegistry::MetricLabelRegistry(Catalog catalog) {
    allowed_keys_.reserve(catalog.allowed_keys.size());
    for (auto& k : catalog.allowed_keys) {
        allowed_keys_.insert(k);
        auto state = std::make_unique<PerKeyState>();
        // Apply per-key cap; default to generic when unset.
        auto it = catalog.value_cardinality_caps.find(k);
        state->cap = (it != catalog.value_cardinality_caps.end())
                         ? it->second
                         : kDefaultGenericCap;
        per_key_.emplace(k, std::move(state));
    }
}

bool MetricLabelRegistry::IsKeyAllowed(std::string_view key) const noexcept {
    return allowed_keys_.find(std::string(key)) != allowed_keys_.end();
}

LabelSet MetricLabelRegistry::BuildLabelSet(
    const std::vector<std::pair<std::string, std::string>>& kvs) {
    LabelSet out;
    out.kv.reserve(kvs.size());
    for (const auto& [key, value] : kvs) {
        // Reject keys not in the allowlist — silent drop.
        auto state_it = per_key_.find(key);
        if (state_it == per_key_.end()) continue;
        PerKeyState& s = *state_it->second;

        // Fast path: shared_lock + lookup. Track resolution with an
        // explicit bool — using `emitted.empty()` as a "not yet
        // resolved" sentinel collides with legitimate empty-string
        // label values, forcing them onto the slow path on every
        // call (correctness preserved by the slow path's repeat
        // lookup, but performance regresses for empty-string-valued
        // custom labels).
        std::string emitted;
        bool resolved = false;
        {
            std::shared_lock<std::shared_mutex> g(s.mtx);
            if (s.seen_values.find(value) != s.seen_values.end()) {
                emitted = value;
                resolved = true;
            } else if (s.cap_full.load(std::memory_order_acquire)) {
                // Cap latched and value not seen → overflow.
                emitted = std::string(kOverflowSentinel);
                resolved = true;
            }
        }
        if (!resolved) {
            // Slow path: maybe-insert under unique_lock.
            std::unique_lock<std::shared_mutex> g(s.mtx);
            if (s.seen_values.find(value) != s.seen_values.end()) {
                emitted = value;
            } else if (s.seen_values.size() < s.cap) {
                s.seen_values.insert(value);
                if (s.seen_values.size() >= s.cap) {
                    s.cap_full.store(true, std::memory_order_release);
                }
                emitted = value;
            } else {
                s.cap_full.store(true, std::memory_order_release);
                emitted = std::string(kOverflowSentinel);
            }
        }
        out.kv.emplace_back(key, std::move(emitted));
    }
    out.SortAndHash();
    return out;
}

size_t MetricLabelRegistry::SeenValueCount(std::string_view key) const noexcept {
    auto it = per_key_.find(std::string(key));
    if (it == per_key_.end()) return 0;
    std::shared_lock<std::shared_mutex> g(it->second->mtx);
    return it->second->seen_values.size();
}

}  // namespace OBSERVABILITY_NAMESPACE
