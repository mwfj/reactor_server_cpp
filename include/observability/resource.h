#pragma once

// Resource per OTel SDK spec — describes the service / process that
// produced the telemetry. Built once at startup from the
// `service.name` / `service.version` / `service.instance.id` config
// fields plus the standard process / host / sdk attributes; held
// IMMUTABLY for the manager's lifetime — these fields are restart-
// required because mid-flight resource swap would create inconsistent
// traces.

#include "observability/attr_value.h"

#include "../common.h"

namespace OBSERVABILITY_NAMESPACE {

class Resource {
public:
    Resource() = default;
    explicit Resource(std::vector<Attribute> attrs)
        : attributes_(std::move(attrs)) {}

    const std::vector<Attribute>& attributes() const noexcept {
        return attributes_;
    }

    // Append a single attribute. Used at construction time only;
    // Resource is logically immutable post-construction.
    void Append(Attribute a) { attributes_.push_back(std::move(a)); }

    // Look up a single attribute by key. Returns nullptr on miss.
    const Attribute* Find(const std::string& key) const noexcept {
        for (const auto& a : attributes_) {
            if (a.key == key) return &a;
        }
        return nullptr;
    }

private:
    std::vector<Attribute> attributes_;
};

}  // namespace OBSERVABILITY_NAMESPACE
