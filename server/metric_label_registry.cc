#include "observability/metric_label_registry.h"

#include "common.h"
#include "log/logger.h"
#include "observability/counter.h"
#include "observability/metrics_catalog.h"
#include "observability/observability_manager.h"

namespace OBSERVABILITY_NAMESPACE {

MetricLabelRegistry::MetricLabelRegistry(Catalog catalog,
                                          ObservabilityManager* manager)
    : manager_(manager) {
    allowed_keys_.reserve(catalog.allowed_keys.size());
    for (auto& k : catalog.allowed_keys) {
        allowed_keys_.insert(k);
        auto state = std::make_unique<PerKeyState>();
        // Apply per-key cap; default to generic when unset. A configured
        // cap of 0 would silently route every observation to
        // `__overflow__` (size<0 is false on the very first insert), so
        // clamp to the default and warn — operators almost always want
        // "unlimited" or a positive bound, not "drop everything".
        auto it = catalog.value_cardinality_caps.find(k);
        if (it != catalog.value_cardinality_caps.end() && it->second > 0) {
            state->cap = it->second;
        } else {
            if (it != catalog.value_cardinality_caps.end()) {
                logging::Get()->warn(
                    "MetricLabelRegistry: cap=0 for key '{}' clamped to "
                    "default {} (cap=0 routes all observations to overflow)",
                    k, kDefaultGenericCap);
            }
            state->cap = kDefaultGenericCap;
        }
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
        bool overflow_event = false;
        {
            std::shared_lock<std::shared_mutex> g(s.mtx);
            if (s.seen_values.find(value) != s.seen_values.end()) {
                emitted = value;
                resolved = true;
            } else if (s.cap_full.load(std::memory_order_acquire)) {
                // Cap latched and value not seen → overflow.
                emitted = std::string(kOverflowSentinel);
                resolved = true;
                overflow_event = true;
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
                overflow_event = true;
            }
        }
        out.kv.emplace_back(key, std::move(emitted));

        // Emit AFTER all locks released. Recursion termination: the
        // overflow counter resolves its own `label_key` label through
        // a MetricLabelRegistry whose allowlist holds a small fixed
        // vocabulary (the union of catalogued label keys); that slot
        // cannot itself overflow under normal operation.
        if (overflow_event && manager_ != nullptr) {
            const auto& cat = manager_->catalog();
            if (cat.reactor_otel_cardinality_overflow != nullptr) {
                cat.reactor_otel_cardinality_overflow->Add(
                    1.0,
                    {{"label_key", key}});
            }
        }
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
