#include "observability/propagator.h"

#include <stdexcept>
#include <utility>

namespace OBSERVABILITY_NAMESPACE {

std::shared_ptr<const Propagator> CompositePropagator::Build(
    const std::vector<std::string>& names) {
    if (names.empty()) {
        throw std::invalid_argument(
            "CompositePropagator: at least one propagator required");
    }
    PropagatorList children;
    children.reserve(names.size());
    for (const auto& n : names) {
        if (n == kPropagatorNameW3C) {
            children.emplace_back(std::make_unique<W3CPropagator>());
        } else if (n == kPropagatorNameJaeger) {
            children.emplace_back(std::make_unique<JaegerPropagator>());
        } else {
            throw std::invalid_argument(
                "CompositePropagator: unknown propagator '" + n + "'");
        }
    }
    return std::shared_ptr<const Propagator>(
        new CompositePropagator(std::move(children)));
}

std::optional<SpanContext> CompositePropagator::Extract(
    const HeadersMap& headers) const {
    for (const auto& child : children_) {
        if (auto ctx = child->Extract(headers)) return ctx;
    }
    return std::nullopt;
}

bool CompositePropagator::Inject(const SpanContext& ctx,
                                    HeadersMap& headers) const {
    bool any = false;
    for (const auto& child : children_) {
        if (child->Inject(ctx, headers)) any = true;
    }
    return any;
}

void CompositePropagator::StripOwnedHeaders(HeadersMap& headers) const {
    for (const auto& child : children_) {
        child->StripOwnedHeaders(headers);
    }
}

}  // namespace OBSERVABILITY_NAMESPACE
