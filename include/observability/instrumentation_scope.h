#pragma once

// InstrumentationScope per OTel SDK spec — identifies the library /
// component that emitted the telemetry. Carried on every Span and
// Metric record; the OTel collector groups data by (Resource,
// InstrumentationScope) for routing.

#include "observability/attr_value.h"

#include <string>
#include <vector>

namespace OBSERVABILITY_NAMESPACE {

class InstrumentationScope {
public:
    InstrumentationScope() = default;
    InstrumentationScope(std::string name, std::string version = {})
        : name_(std::move(name)), version_(std::move(version)) {}

    const std::string& name() const noexcept { return name_; }
    const std::string& version() const noexcept { return version_; }
    const std::vector<Attribute>& attributes() const noexcept {
        return attributes_;
    }

    void SetAttribute(Attribute a) { attributes_.push_back(std::move(a)); }

private:
    std::string name_;
    std::string version_;
    std::vector<Attribute> attributes_;
};

}  // namespace OBSERVABILITY_NAMESPACE
