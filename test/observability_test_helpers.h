#pragma once

// Shared test fixtures for the observability test suites — keeps
// MakeManager + the boilerplate ObservabilityConfig in one place so
// future signature changes only touch one site.

#include "observability/observability_config.h"
#include "observability/observability_manager.h"
#include "observability/resource.h"
#include "observability/span_processor.h"
#include "observability/trace_id.h"

#include <memory>
#include <string>
#include <vector>

namespace ObservabilityTestHelpers {

inline std::shared_ptr<OBSERVABILITY_NAMESPACE::ObservabilityManager>
MakeManager(std::string service_name = "test",
            uint64_t random_seed = 0xDEADBEEFULL) {
    OBSERVABILITY_NAMESPACE::ObservabilityConfig cfg;
    cfg.enabled = true;
    cfg.metrics.enabled = true;
    cfg.resource.service_name = service_name;
    std::vector<OBSERVABILITY_NAMESPACE::Attribute> attrs;
    attrs.emplace_back(
        "service.name",
        OBSERVABILITY_NAMESPACE::AttrValue(std::move(service_name)));
    return OBSERVABILITY_NAMESPACE::ObservabilityManager::Create(
        std::move(cfg),
        std::make_shared<OBSERVABILITY_NAMESPACE::Resource>(std::move(attrs)),
        std::shared_ptr<OBSERVABILITY_NAMESPACE::SpanProcessor>(
            std::make_shared<OBSERVABILITY_NAMESPACE::NoopSpanProcessor>()),
        std::make_shared<OBSERVABILITY_NAMESPACE::RandomSource>(random_seed));
}

}  // namespace ObservabilityTestHelpers
