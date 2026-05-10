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

#include "../common.h"

namespace AUTH_NAMESPACE {
class UpstreamHttpClient;
}

namespace OBSERVABILITY_NAMESPACE {

// Round a millisecond timeout up to whole seconds, clamped to a minimum
// of 1. UpstreamHttpClient::Request::timeout_sec is whole seconds and
// only arms SetDeadline when timeout_sec > 0; a naive truncation of
// any sub-second OTLP timeout would silently disable the deadline and
// let fut.get() block indefinitely on a stalled upstream. Exposed for
// direct testing — the lambda captured by MakeOtlpTransport calls this.
int OtlpTimeoutCeilSeconds(std::chrono::milliseconds ms) noexcept;

// Maps an OTLP pool alias (e.g. "otel-collector") to the configured
// upstream hostname (e.g. "otel.svc.cluster.local"). Returning an empty
// string means "use the pool name as the Host header" (the existing
// UpstreamHttpClient default). Without this, vhost-routed or
// strict-Host-validating collectors would reject OTLP requests because
// the Host header would carry the internal alias.
using HostLookupFn = std::function<std::string(const std::string&)>;

OtlpHttpExporter::TransportFn MakeOtlpTransport(
    std::weak_ptr<AUTH_NAMESPACE::UpstreamHttpClient> client_weak,
    HostLookupFn host_lookup = nullptr);

}  // namespace OBSERVABILITY_NAMESPACE
