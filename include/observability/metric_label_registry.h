#pragma once

// MetricLabelRegistry — per-instrument allowed-label-key allowlist plus
// per-(instrument, label_key) cardinality cap with `__overflow__` value
// rewrite.
//
// Hot path:
//   1. Caller submits a (label_key, label_value) sequence.
//   2. Registry silently drops keys not in the per-instrument
//      allowlist (drop is not an error — bounded cardinality is the
//      explicit operator contract).
//   3. For each accepted (key, value): if value already in
//      `seen_values[key]` → emit literal value. Else if `cap_full`
//      latched → emit `__overflow__`. Else acquire unique_lock,
//      re-check, insert into seen_values; latch cap_full when size
//      hits cap[k]; emit literal.
//
// Concurrency: shared_lock for steady-state reads; unique_lock fires
// AT MOST cap[k] times per label key per instrument lifetime. After
// cap_full latches, the unique_lock is never taken again for that key.

#include "observability/attr_value.h"

#include <atomic>
#include <cstddef>
#include <memory>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace OBSERVABILITY_NAMESPACE {

class ObservabilityManager;

// Sentinel value emitted when a label key's cardinality cap is reached.
// Operators see this in /metrics + OTLP as a structured overflow signal.
inline constexpr std::string_view kOverflowSentinel = "__overflow__";

// Default per-key cardinality caps used when a Catalog entry omits one.
inline constexpr size_t kDefaultRouteCap   = 256;
inline constexpr size_t kDefaultUrlPathCap = 1000;
inline constexpr size_t kDefaultGenericCap = 256;

class MetricLabelRegistry {
public:
    // Catalog entry. Operators reject labels not in `allowed_keys` and
    // apply per-key caps from `value_cardinality_caps` (defaulting to
    // kDefaultGenericCap when a key is in the allowlist but missing
    // from the cap map).
    struct Catalog {
        std::vector<std::string> allowed_keys;
        std::unordered_map<std::string, size_t> value_cardinality_caps;
    };

    // `manager` is the self-metric escape hatch: when non-null the slow
    // path emits `reactor.otel.cardinality_overflow{label_key=...}`
    // alongside the existing `__overflow__` rewrite so operators see
    // overflow events on /metrics + OTLP. Default null retained for
    // tests that build a raw registry outside the manager.
    explicit MetricLabelRegistry(Catalog catalog,
                                  ObservabilityManager* manager = nullptr);

    // Build a LabelSet from an unsorted sequence of (key, value) pairs.
    // Drops keys not in the allowlist; rewrites values past the cap to
    // `__overflow__`. Result is sorted + hashed and ready for SeriesMap
    // lookup.
    LabelSet BuildLabelSet(
        const std::vector<std::pair<std::string, std::string>>& kvs);

    // Number of distinct values seen so far for a given key. Used by
    // tests + diagnostics; the hot path doesn't need this.
    size_t SeenValueCount(std::string_view key) const noexcept;

    bool IsKeyAllowed(std::string_view key) const noexcept;

private:
    struct PerKeyState {
        size_t                                cap = kDefaultGenericCap;
        std::atomic<bool>                     cap_full{false};
        mutable std::shared_mutex             mtx;
        std::unordered_set<std::string>       seen_values;
    };

    std::unordered_set<std::string>                          allowed_keys_;
    std::unordered_map<std::string, std::unique_ptr<PerKeyState>> per_key_;

    // Raw pointer; manager storage outlives every MetricLabelRegistry
    // (MeterProvider destructs as part of ~ObservabilityManager's body).
    // See batch_span_processor.h::manager() docstring for the SHUTDOWN
    // CAVEAT that applies to any code path consuming manager_->
    // sub-members (catalog, meter_provider, metric_reader) — those may
    // already be destroyed by the time worker drains run.
    // (Today this dtor is default and emits nothing — caveat applies
    // only if a future dtor adds emission paths.)
    ObservabilityManager* manager_ = nullptr;
};

}  // namespace OBSERVABILITY_NAMESPACE
