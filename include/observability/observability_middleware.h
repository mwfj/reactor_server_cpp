#pragma once

// HttpRouter middleware factory that installs the observability
// pipeline. Must be the LAST PrependMiddleware caller so it runs FIRST
// in the chain (PrependMiddleware pushes to the front), executing
// before auth + rate-limit so middleware-rejection paths can still
// finalize through the populated snapshot.
//
// HttpRouter only allows one async middleware (auth introspection),
// so this middleware is sync. Span finalization happens at response-
// completion time via the FinalizeFromSnapshot CAS gate, not inline.

#include "http/http_router.h"
#include "observability/common.h"

#include <memory>

namespace OBSERVABILITY_NAMESPACE {

class ObservabilityManager;

// Build the sync middleware. The closure:
//   1. Resolves the route match so sampling sees the route pattern.
//   2. Allocates a SERVER Span (parent extracted from inbound traceparent).
//   3. Registers the snapshot on the manager and assigns it to the request.
//   4. Returns true; this middleware never rejects.
//
// Manager null   → no-op (defensive; the middleware is normally only
//                  installed when observability.enabled is true).
// Traces off live → snapshot is still built so metrics still record;
//                  the SpanContext is zero-valued and no Span is allocated.
HttpRouter::Middleware MakeObservabilityMiddleware(
    std::shared_ptr<ObservabilityManager> manager);

}  // namespace OBSERVABILITY_NAMESPACE
