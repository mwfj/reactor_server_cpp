#pragma once

// OpenTelemetry HTTP semantic-convention attribute keys + reactor.*
// project-namespaced extension keys.
//
// All values are `constexpr string_view` so they participate in
// compile-time deduplication and incur no runtime allocation.
//
// The OTel-spec HTTP semconv catalog uses dotted identifiers. The
// Prometheus exporter translates these to `_`-separated names at
// render time; the OTLP path emits them verbatim.

#include <string_view>

namespace OBSERVABILITY_NAMESPACE {
namespace SEMCONV_NAMESPACE {

// ---- HTTP server semconv (RFC 9112 + OTel HTTP semconv 1.27) ----
inline constexpr std::string_view kHttpRequestMethod      = "http.request.method";
inline constexpr std::string_view kHttpRequestMethodOriginal =
    "http.request.method_original";
inline constexpr std::string_view kHttpResponseStatusCode = "http.response.status_code";
inline constexpr std::string_view kHttpRoute             = "http.route";
inline constexpr std::string_view kHttpServerRequestBodySize =
    "http.server.request.body.size";
inline constexpr std::string_view kHttpServerResponseBodySize =
    "http.server.response.body.size";
inline constexpr std::string_view kHttpRequestResendCount = "http.request.resend_count";

// ---- URL semconv ----
inline constexpr std::string_view kUrlScheme = "url.scheme";
inline constexpr std::string_view kUrlPath   = "url.path";
inline constexpr std::string_view kUrlQuery  = "url.query";
inline constexpr std::string_view kUrlFull   = "url.full";

// ---- Network semconv ----
inline constexpr std::string_view kNetworkProtocolName    = "network.protocol.name";
inline constexpr std::string_view kNetworkProtocolVersion = "network.protocol.version";
inline constexpr std::string_view kNetworkPeerAddress     = "network.peer.address";
inline constexpr std::string_view kNetworkPeerPort        = "network.peer.port";

// ---- Server / client address ----
inline constexpr std::string_view kServerAddress = "server.address";
inline constexpr std::string_view kServerPort    = "server.port";
inline constexpr std::string_view kClientAddress = "client.address";
inline constexpr std::string_view kClientPort    = "client.port";

// ---- Error semconv ----
inline constexpr std::string_view kErrorType = "error.type";

// ---- User-agent ----
inline constexpr std::string_view kUserAgentOriginal = "user_agent.original";

// ---- Service semconv (Resource) ----
inline constexpr std::string_view kServiceName       = "service.name";
inline constexpr std::string_view kServiceVersion    = "service.version";
inline constexpr std::string_view kServiceInstanceId = "service.instance.id";

// ---- Process / SDK semconv (Resource) ----
inline constexpr std::string_view kProcessRuntimeName        = "process.runtime.name";
inline constexpr std::string_view kProcessRuntimeVersion     = "process.runtime.version";
inline constexpr std::string_view kProcessRuntimeDescription = "process.runtime.description";
inline constexpr std::string_view kTelemetrySdkName     = "telemetry.sdk.name";
inline constexpr std::string_view kTelemetrySdkLanguage = "telemetry.sdk.language";
inline constexpr std::string_view kTelemetrySdkVersion  = "telemetry.sdk.version";

// ---- Reactor.* project-namespaced extensions ----
// Auth-overlay outcomes / signals.
inline constexpr std::string_view kReactorAuthOutcome = "reactor.auth.outcome";
inline constexpr std::string_view kReactorAuthIssuer  = "reactor.auth.issuer";
inline constexpr std::string_view kReactorAuthMode    = "reactor.auth.mode";

// Rate-limit decisions.
inline constexpr std::string_view kReactorRateLimitDecision = "reactor.rate_limit.decision";
inline constexpr std::string_view kReactorRateLimitZone     = "reactor.rate_limit.zone";

// Circuit-breaker state transitions / decisions.
inline constexpr std::string_view kReactorCircuitBreakerState    = "reactor.circuit_breaker.state";
inline constexpr std::string_view kReactorCircuitBreakerDecision = "reactor.circuit_breaker.decision";

// Upstream / proxy attempts.
inline constexpr std::string_view kReactorUpstreamPool      = "reactor.upstream.pool";
inline constexpr std::string_view kReactorUpstreamHost      = "reactor.upstream.host";
inline constexpr std::string_view kReactorUpstreamAttempt   = "reactor.upstream.attempt";
inline constexpr std::string_view kReactorUpstreamRetryReason = "reactor.upstream.retry_reason";

// OTLP exporter self-metrics scope / labels.
inline constexpr std::string_view kReactorOtelInstrument  = "reactor.otel.instrument";
inline constexpr std::string_view kReactorOtelDropReason  = "reactor.otel.drop_reason";

}  // namespace SEMCONV_NAMESPACE
}  // namespace OBSERVABILITY_NAMESPACE
