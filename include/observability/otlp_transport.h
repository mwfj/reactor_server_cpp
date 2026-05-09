#pragma once

// Build an OtlpHttpExporter::TransportFn that POSTs payloads through an
// auth::UpstreamHttpClient. Used by HttpServer for both the traces-side
// BatchSpanProcessor exporter and the metrics-side PeriodicMetricReader
// exporter (single helper, two callers).
//
// The helper captures `client` as weak_ptr so a mid-flight Export that
// outlives the server short-circuits to kFailedNotRetryable rather than
// dereferencing freed memory. HTTP status codes map to ExportResult per
// OTLP/HTTP guidance: 2xx = kSuccess, 429/503 = kFailedRetryable, all
// others = kFailedNotRetryable.

#include "observability/otlp_http_exporter.h"

#include <memory>

namespace AUTH_NAMESPACE {
class UpstreamHttpClient;
}

namespace OBSERVABILITY_NAMESPACE {

OtlpHttpExporter::TransportFn MakeOtlpTransport(
    std::weak_ptr<AUTH_NAMESPACE::UpstreamHttpClient> client_weak);

}  // namespace OBSERVABILITY_NAMESPACE
