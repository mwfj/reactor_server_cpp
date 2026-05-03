#pragma once

// AttrValue — tagged-union value type carried by Attribute / Label /
// SpanData / MetricsSnapshot. Mirrors the OTel SDK `AnyValue` shape
// minus the array variants we don't currently emit (we keep arrays
// implementable later; today's exporters only emit scalar types).
//
// `Attribute` is a (key, value) pair carried on Span / Resource /
// InstrumentationScope. `Label` is the metric-side equivalent — a
// (key, value) pair where the value is constrained to small types
// suitable for cardinality-bounded series (no arrays, no large
// strings; the metric label registry enforces this).

#include <cstdint>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace OBSERVABILITY_NAMESPACE {

struct AttrValue {
    using Variant = std::variant<
        std::monostate,        // unset
        bool,
        int64_t,
        double,
        std::string,
        std::vector<bool>,
        std::vector<int64_t>,
        std::vector<double>,
        std::vector<std::string>>;

    Variant value;

    AttrValue() = default;
    AttrValue(bool b)        : value(b) {}
    AttrValue(int v)         : value(static_cast<int64_t>(v)) {}
    AttrValue(int64_t v)     : value(v) {}
    AttrValue(double v)      : value(v) {}
    AttrValue(std::string v) : value(std::move(v)) {}
    AttrValue(const char* v) : value(std::string(v)) {}

    bool IsUnset() const noexcept {
        return std::holds_alternative<std::monostate>(value);
    }
};

struct Attribute {
    std::string key;
    AttrValue   value;

    Attribute() = default;
    Attribute(std::string k, AttrValue v)
        : key(std::move(k)), value(std::move(v)) {}
};

// Metric-label primitive — used by Counter / Histogram instruments.
// Label values are restricted at the registry level to
// strings / bools / int64 / double; we still carry an AttrValue for
// uniformity with span attributes, but instruments reject array
// shapes at record time.
struct Label {
    std::string key;
    AttrValue   value;

    Label() = default;
    Label(std::string k, AttrValue v)
        : key(std::move(k)), value(std::move(v)) {}
};

// LabelSet — ordered collection of labels for one metric record.
// Series identity is the (instrument-name, sorted-label-keys,
// sorted-label-values) tuple. SortAndHash() is called by the
// MetricLabelRegistry pipeline before SeriesMap lookup.
struct LabelSet {
    std::vector<std::pair<std::string, std::string>> kv;
    uint64_t hash = 0;

    // Sort entries by key (canonical ordering) and compute the
    // FNV-1a hash of the sorted key/value sequence. Idempotent.
    void SortAndHash() noexcept;

    bool operator==(const LabelSet& other) const noexcept {
        return kv == other.kv;
    }
};

}  // namespace OBSERVABILITY_NAMESPACE
