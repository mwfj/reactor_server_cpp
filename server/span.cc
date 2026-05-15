#include "observability/span.h"

#include "observability/counter.h"
#include "observability/metrics_catalog.h"
#include "observability/observability_manager.h"
#include "observability/span_processor.h"

namespace OBSERVABILITY_NAMESPACE {

Span::Span(SpanContext context,
           SpanContext parent,
           bool        has_parent,
           std::string name,
           SpanKind    kind,
           std::chrono::system_clock::time_point       start_system,
           std::shared_ptr<const Resource>             resource,
           std::shared_ptr<const InstrumentationScope> scope,
           std::shared_ptr<SpanProcessor>              processor,
           bool                                        record_locally)
    : context_(std::move(context)),
      parent_context_(std::move(parent)),
      has_parent_(has_parent),
      name_(std::move(name)),
      kind_(kind),
      start_system_(start_system),
      resource_(std::move(resource)),
      scope_(std::move(scope)),
      processor_(std::move(processor)),
      record_locally_(record_locally) {}

Span::~Span() {
    // Defensive: if a Span is destroyed without End() / Drop, treat it
    // as End-with-now to avoid silently losing the snapshot. The
    // shutdown kill path calls DropWithoutEnd explicitly, so this
    // branch only hits when a code path drops the shared_ptr without
    // explicit lifecycle management (e.g. an exception thrown across
    // the request handler that bypasses the finalize hook).
    if (!ended_.load(std::memory_order_acquire) &&
        !dropped_.load(std::memory_order_acquire)) {
        try {
            End(std::chrono::system_clock::now());
        } catch (...) {
            // Destructors must not throw. Silently drop; the span is
            // lost in this exceptional path.
        }
    }
}

void Span::UpdateName(std::string name) {
    if (!IsRecording()) return;
    name_ = std::move(name);
}

void Span::SetAttribute(std::string key, AttrValue value) {
    if (!IsRecording()) return;
    // Update-in-place on duplicate key — matches OTel semantics.
    for (auto& a : attributes_) {
        if (a.key == key) {
            a.value = std::move(value);
            return;
        }
    }
    if (attributes_.size() >= kMaxAttributesPerSpan) {
        attributes_truncated_ = true;
        return;
    }
    attributes_.emplace_back(std::move(key), std::move(value));
}

void Span::AddEvent(std::string name,
                     std::chrono::system_clock::time_point ts) {
    AddEvent(std::move(name), {}, ts);
}

void Span::AddEvent(std::string name,
                     std::vector<Attribute> attrs,
                     std::chrono::system_clock::time_point ts) {
    if (!IsRecording()) return;
    if (events_.size() >= kMaxEventsPerSpan) {
        events_truncated_ = true;
        return;
    }
    SpanEvent ev;
    ev.name = std::move(name);
    ev.timestamp = ts;
    ev.attributes = std::move(attrs);
    events_.emplace_back(std::move(ev));
}

void Span::AddLink(SpanLink link) {
    if (!IsRecording()) return;
    if (links_.size() >= kMaxLinksPerSpan) {
        links_truncated_ = true;
        return;
    }
    links_.emplace_back(std::move(link));
}

void Span::SetStatus(SpanStatusCode code, std::string description) {
    if (!IsRecording()) return;
    // Per OTel SDK: once status has been set to OK, ERROR cannot
    // override it. UNSET is overridable by both OK and ERROR.
    if (status_code_ == SpanStatusCode::OK && code == SpanStatusCode::ERROR) {
        return;
    }
    status_code_ = code;
    status_description_ = std::move(description);
}

void Span::RecordException(const std::exception& e) {
    std::vector<Attribute> attrs;
    attrs.reserve(2);
    attrs.emplace_back("exception.type",    AttrValue(std::string("std::exception")));
    attrs.emplace_back("exception.message", AttrValue(std::string(e.what())));
    AddEvent("exception", std::move(attrs));
}

SpanData Span::MakeSnapshot(std::chrono::system_clock::time_point end_system) {
    SpanData d;
    d.context             = context_;
    d.parent_context      = parent_context_;
    d.has_parent          = has_parent_;
    d.name                = std::move(name_);
    d.kind                = kind_;
    d.status_code         = status_code_;
    d.status_description  = std::move(status_description_);
    d.start_time_system   = start_system_;
    d.end_time_system     = end_system;
    d.duration            = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                end_system - start_system_);
    d.attributes          = std::move(attributes_);
    d.events              = std::move(events_);
    d.links               = std::move(links_);
    d.attributes_truncated = attributes_truncated_;
    d.events_truncated     = events_truncated_;
    d.links_truncated      = links_truncated_;
    d.resource = resource_;
    d.scope    = scope_;
    return d;
}

void Span::End(std::chrono::system_clock::time_point end_system) {
    bool expected = false;
    if (!ended_.compare_exchange_strong(expected, true,
                                          std::memory_order_acq_rel)) {
        return;  // already ended; idempotent.
    }
    if (dropped_.load(std::memory_order_acquire)) {
        // DropWithoutEnd raced ahead of us; the processor was torn down
        // and we MUST NOT call OnEnd. The CAS above already published
        // ended_=true so subsequent End() calls also no-op.
        return;
    }
    // Hand the snapshot to the processor. Move semantics — the Span's
    // attribute/event/link vectors are emptied so subsequent reads
    // against this Span (which IsRecording() now reports false for)
    // see clean state.
    if (processor_) {
        processor_->OnEnd(MakeSnapshot(end_system));
    }
}

void Span::DropWithoutEnd() {
    bool expected = false;
    if (!dropped_.compare_exchange_strong(expected, true,
                                            std::memory_order_acq_rel)) {
        return;  // already dropped — second+ caller no-ops.
    }
    // Self-metric: surface unended drops via the dedicated catalog
    // field. Reach the manager through the processor's manager()
    // accessor — Span does NOT carry an ObservabilityManager pointer
    // itself; the SpanProcessor base virtual is the only conduit.
    // Null-safe at every hop: NoopSpanProcessor + InMemorySpanProcessor
    // (no manager wired) return nullptr; the catalog pointer guard
    // covers the cold window during Init() before MetricsCatalog::Build
    // runs.
    auto* mgr = processor_ ? processor_->manager() : nullptr;
    if (mgr != nullptr) {
        const auto& cat = mgr->catalog();
        if (cat.reactor_otel_spans_dropped_unended != nullptr) {
            cat.reactor_otel_spans_dropped_unended->Add(1.0, {});
        }
    }
    // Mutating the vectors / shared_ptrs here would race with a
    // dispatcher thread mid-SetAttribute / AddEvent / End — IsRecording()
    // is necessarily a TOCTOU read against dropped_, so a mutator can
    // be past its IsRecording() check and inside emplace_back() when
    // this CAS publishes. Just mark the span dropped (later mutators
    // bail) and let the destructor reclaim memory when the last
    // shared_ptr is released — bounded by dispatcher stop, which runs
    // after KillOutstandingSnapshots returns.
}

}  // namespace OBSERVABILITY_NAMESPACE
