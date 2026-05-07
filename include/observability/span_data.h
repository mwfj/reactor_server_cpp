#pragma once

// SpanData — POD snapshot of a finished Span, handed to the
// SpanProcessor (and onward to the SpanExporter). Owning value type:
// holds copies of every string the Span captured so the export pipeline
// can outlive the dispatcher that produced it.

#include "observability/attr_value.h"
#include "observability/instrumentation_scope.h"
#include "observability/span_context.h"
#include "observability/span_kind.h"
#include "observability/span_status.h"

#include "../common.h"
// <chrono>, <memory>, <string>, <vector> via common.h

namespace OBSERVABILITY_NAMESPACE {

class Resource;  // forward decl — pointer member; full type in resource.h

// One event recorded on a Span (e.g. exception, log entry).
struct SpanEvent {
    std::string name;
    std::chrono::system_clock::time_point timestamp{};
    std::vector<Attribute> attributes;
};

// One link to another Span (causal but not parent/child).
struct SpanLink {
    SpanContext context;
    std::vector<Attribute> attributes;
};

struct SpanData {
    SpanContext context;        // (trace_id, span_id, flags, state) for the finished span.
    SpanContext parent_context; // Parent's SpanContext; default-constructed when root.
    bool        has_parent = false;

    std::string  name;
    SpanKind     kind          =          SpanKind::INTERNAL;
    SpanStatusCode status_code =          SpanStatusCode::UNSET;
    std::string  status_description;

    std::chrono::system_clock::time_point start_time_system{};
    std::chrono::system_clock::time_point end_time_system{};
    // Wall-clock duration (end - start). Carried separately so consumers
    // don't need to subtract `system_clock` time_points (which can be
    // adjusted by NTP and produce small negative deltas).
    std::chrono::nanoseconds duration{0};

    std::vector<Attribute> attributes;
    std::vector<SpanEvent> events;
    std::vector<SpanLink>  links;

    // Resource + instrumentation scope shared across every Span emitted
    // by the same TracerProvider. Held by shared_ptr so SpanData copies
    // don't duplicate the (potentially large) Resource attribute list;
    // the provider owns the canonical instances.
    std::shared_ptr<const Resource>             resource;
    std::shared_ptr<const InstrumentationScope> scope;

    // True iff at least one of `attribute_count_overflow`, `event_count_overflow`,
    // or `link_count_overflow` exceeded its respective per-span cap. Lets
    // backends surface a "your traces are losing data" signal.
    bool attributes_truncated = false;
    bool events_truncated     = false;
    bool links_truncated      = false;
};

}  // namespace OBSERVABILITY_NAMESPACE
