#include "observability/propagator.h"

#include <set>
#include <stdexcept>
#include <utility>

namespace OBSERVABILITY_NAMESPACE {

std::shared_ptr<const Propagator> CompositePropagator::Build(
    const std::vector<std::string>& names) {
    if (names.empty()) {
        throw std::invalid_argument(
            "CompositePropagator: at least one propagator required");
    }
    // Reject duplicates. ConfigLoader does the same check, but Build is
    // a public API a programmatic caller can hit without going through
    // the loader. Two children of the same kind would inject identical
    // headers twice and make Extract precedence ambiguous.
    std::set<std::string> seen;
    PropagatorList children;
    children.reserve(names.size());
    for (const auto& n : names) {
        if (!seen.insert(n).second) {
            throw std::invalid_argument(
                "CompositePropagator: duplicate propagator '" + n + "'");
        }
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

bool CompositePropagator::Inject(const SpanContext& ctx,
                                    HeadersVec& headers) const {
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
