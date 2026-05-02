#pragma once

// HttpRouter middleware factory that wires the observability pipeline
// into every request. Runs as the FIRST middleware in the chain (per
// OPENTELEMETRY_DESIGN.md §6.1.1: PrependMiddleware order means
// last-prepend-runs-first — observability must be the LAST prepend
// so it executes before auth + rate-limit, and middleware-rejection
// paths can finalize through the populated snapshot).
//
// Constraint surfaced by the live-code survey: HttpRouter allows
// exactly ONE async middleware (auth introspection holds it).
// Observability MUST be sync — it cannot defer or suspend the chain.
// Span finalization happens AT response-completion time via the
// FinalizeFromSnapshot CAS gate, NOT inline in the middleware.

#include "http/http_router.h"
#include "observability/common.h"

#include <memory>

namespace OBSERVABILITY_NAMESPACE {

class ObservabilityManager;

// Build a sync middleware that:
//   1. Calls HttpRouter::ResolveRouteMatch via PopulateRouteParams so
//      `request.route_match` is populated before sampling decisions.
//   2. Allocates a SERVER Span via the manager's TracerProvider with
//      kind=SERVER and parent extracted from inbound `traceparent`
//      (parent extraction lands in task #69 — Propagator).
//   3. Builds an ObservabilitySnapshot, calls
//      ObservabilityManager::RegisterLiveSnapshot, assigns
//      `request.obs_snapshot`.
//   4. Returns true (observability never rejects a request).
//
// On `manager == nullptr`: middleware is a no-op (matches the disabled
// fast-path contract in §14 — the manager is null in the default
// `observability.enabled=false` deployment, so this middleware should
// never be installed in that case; the no-op branch is defensive).
//
// On `manager->TracesEnabled() == false`: snapshot is still built (so
// metrics still record per-route + middleware-rejection paths still
// finalize), but the SpanContext is zero-valued and no Span is
// allocated. Toggle is live-reloadable per §11.2.
HttpRouter::Middleware MakeObservabilityMiddleware(
    std::shared_ptr<ObservabilityManager> manager);

}  // namespace OBSERVABILITY_NAMESPACE
