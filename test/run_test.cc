#include "proxy_transaction_internal_test.h"
#include "http_internal_test.h"
#include "http2_internal_test.h"
#include "stress_test.h"
#include "basic_test.h"
#include "race_condition_test.h"
#include "timeout_test.h"
#include "config_test.h"
#include "http_test.h"
#include "websocket_test.h"
#include "tls_test.h"
#include "cli_test.h"
#include "http2_test.h"
#include "route_test.h"
#include "kqueue_test.h"
#include "upstream_pool_test.h"
#include "proxy_test.h"
#include "rate_limit_test.h"
#include "circuit_breaker_test.h"
#include "circuit_breaker_components_test.h"
#include "circuit_breaker_integration_test.h"
#include "circuit_breaker_retry_budget_test.h"
#include "circuit_breaker_wait_queue_drain_test.h"
#include "circuit_breaker_observability_test.h"
#include "circuit_breaker_reload_test.h"
#include "auth_foundation_test.h"
#include "jwt_verifier_test.h"
#include "jwks_cache_test.h"
#include "oidc_discovery_test.h"
#include "header_rewriter_auth_test.h"
#include "auth_manager_test.h"
#include "auth_integration_test.h"
#include "auth_failure_mode_test.h"
#include "auth_reload_test.h"
#include "auth_multi_issuer_test.h"
#include "auth_websocket_upgrade_test.h"
#include "auth_race_test.h"
#include "dns_resolver_test.h"
#include "dual_stack_test.h"
#include "router_async_middleware_test.h"
#include "introspection_cache_test.h"
#include "introspection_client_test.h"
#include "auth_introspection_integration_test.h"
#include "auth_observability_test.h"
#include "observability_foundation_test.h"
#include "observability_tracer_test.h"
#include "observability_metrics_test.h"
#include "observability_manager_test.h"
#include "observability_propagator_test.h"
#include "observability_export_pipeline_test.h"
#include "observability_prometheus_test.h"
#include "observability_e2e_test.h"
#include "test_framework.h"
#include <algorithm>
#include <sys/resource.h>

// Raise fd limit on macOS where the default soft limit is 256.
// 138 tests with concurrent servers can exhaust this quickly.
static void RaiseFdLimit() {
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        if (rl.rlim_cur < 4096) {
            rl.rlim_cur = std::min(rl.rlim_max, (rlim_t)4096);
            setrlimit(RLIMIT_NOFILE, &rl);
        }
    }
}


// Single entry point for the circuit-breaker feature family. Mirrors the
// order operators see when running individual CLI flags, so the umbrella
// invocation (`./test_runner circuit_breaker`) and the full sweep both
// produce stable, predictable output. Sub-suites split because the work
// landed across multiple development phases — they remain ONE feature.
void RunAllCircuitBreakerFamily() {
    CircuitBreakerTests::RunAllTests();
    CircuitBreakerComponentsTests::RunAllTests();
    CircuitBreakerIntegrationTests::RunAllTests();
    CircuitBreakerRetryBudgetTests::RunAllTests();
    CircuitBreakerWaitQueueDrainTests::RunAllTests();
    CircuitBreakerObservabilityTests::RunAllTests();
    CircuitBreakerReloadTests::RunAllTests();
}

// Single entry point for the proxy feature family — internal state-machine
// regressions plus the end-to-end engine tests. Both run the same proxy
// transaction code paths from different angles.
void RunAllProxyFamily() {
    ProxyTransactionInternalTests::RunAllTests();
    ProxyTests::RunAllTests();
}

// Single entry point for the DNS / dual-stack feature family. Same rationale
// as the other family wrappers — DnsResolver primitives + dual-stack
// integration are one feature split across two suites for readability.
void RunAllDnsFamily() {
    DnsResolverTests::RunAllTests();
    DualStackTests::RunAllTests();
}

// Single entry point for the auth feature family. Same rationale as
// RunAllCircuitBreakerFamily — multi-phase development produced multiple
// suites, but they're all the same feature. Order matches a bottom-up
// dependency walk: foundation → primitives → manager → integration →
// failure / reload / multi-issuer / WS / race → introspection → observability.
void RunAllAuthFamily() {
    AuthFoundationTests::RunAllTests();
    JwtVerifierTests::RunAllTests();
    JwksCacheTests::RunAllTests();
    OidcDiscoveryTests::RunAllTests();
    HeaderRewriterAuthTests::RunAllTests();
    AuthManagerTests::RunAllTests();
    AuthIntegrationTests::RunAllTests();
    AuthFailureModeTests::RunAllTests();
    AuthReloadTests::RunAllTests();
    AuthMultiIssuerTests::RunAllTests();
    AuthWebSocketUpgradeTests::RunAllTests();
    AuthRaceTests::RunAllTests();
    RouterAsyncMiddlewareTests::RunAllTests();
    IntrospectionCacheTests::RunAllTests();
    IntrospectionClientTests::RunAllTests();
    AuthIntrospectionIntegrationTests::RunAllTests();
    AuthObservabilityTests::RunAllTests();
}

void RunAllTest(){
    std::cout << "Run All Tests - Test Suite" << std::endl;
    // Run basic functional tests
    BasicTests::RunAllTests();

    // Run stress tests
    StressTests::RunStressTests();

    // Run race condition tests
    RaceConditionTests::RunRaceConditionTests();

    // Run timeout tests
    TimeoutTests::RunAllTests();

    // Run config tests
    ConfigTests::RunAllTests();

    // Run focused internal HTTP/1 streaming regressions
    HttpInternalTests::RunAllTests();

    // Run HTTP tests
    HttpTests::RunAllTests();

    // Run WebSocket tests
    WebSocketTests::RunAllTests();

    // Run TLS tests
    TlsTests::RunAllTests();

    // Run CLI tests
    CliTests::RunAllTests();

    // Run focused internal HTTP/2 regressions
    Http2InternalTests::RunAllTests();

    // Run HTTP/2 tests
    Http2Tests::RunAllTests();

    // Run route trie and router pattern tests
    RouteTests::RunAllTests();

    // Run kqueue platform tests (skipped on Linux)
    KqueueTests::RunAllTests();

    // Run upstream connection pool tests
    UpstreamPoolTests::RunAllTests();

    // Proxy feature family (internal regressions + end-to-end engine).
    RunAllProxyFamily();

    // Run rate limit tests
    RateLimitTests::RunAllTests();

    // Circuit-breaker feature family (umbrella runs every CB sub-suite).
    RunAllCircuitBreakerFamily();

    // Auth feature family (umbrella runs every auth-related sub-suite —
    // foundation, JWT verifier, JWKS cache, OIDC discovery, header
    // rewriter overlay, AuthManager, integration, failure modes, reload,
    // multi-issuer, WebSocket upgrade, race, router async, introspection
    // cache + client + integration, observability).
    RunAllAuthFamily();

    // DNS / dual-stack feature family (transport layer, not inbound auth).
    RunAllDnsFamily();

    // Observability foundation — pure value-type tests (TraceId / SpanId /
    // TraceFlags / TraceState / SpanContext / LabelSet / AttrValue).
    ObservabilityFoundationTests::RunAllTests();

    // Observability tracer / sampler / span lifecycle tests — pure
    // in-process (no I/O); uses InMemorySpanProcessor.
    ObservabilityTracerTests::RunAllTests();

    // Observability metrics tests — Counter / Histogram / Meter /
    // MeterProvider + cardinality registry.
    ObservabilityMetricsTests::RunAllTests();

    // Observability manager + middleware tests — snapshot register-
    // and-count, FinalizeFromSnapshot CAS gate, KillOutstandingSnapshots,
    // Reload live-flag flipping, end-to-end middleware.
    ObservabilityManagerTests::RunAllTests();

    // W3C Trace Context propagator tests — pure value-type tests for
    // traceparent / tracestate parse + serialize + Inject / Extract.
    ObservabilityPropagatorTests::RunAllTests();

    // Export pipeline tests — BatchSpanProcessor (worker thread + queue
    // overflow + shutdown propagation), PeriodicMetricReader (interval
    // worker), OtlpHttpExporter (OTLP/JSON serialization + r84 trio +
    // controlled-merge reload).
    ObservabilityExportPipelineTests::RunAllTests();

    // Prometheus exporter rendering — sanitization, content-type, format
    // selection, counter / gauge / histogram exposition + OpenMetrics.
    ObservabilityPrometheusTests::RunAllTests();

    // Observability end-to-end tests — boot a real HttpServer, install
    // the observability manager + middleware, send TCP-level HTTP
    // requests, assert spans are captured by the InMemorySpanProcessor.
    ObservabilityE2ETests::RunAllTests();

    std::cout << "====================================\n" << std::endl;
}

void PrintUsage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS]" << std::endl;
    std::cout << "\nOptions:" << std::endl;
    std::cout << "  basic,   -b    Run basic functional tests only" << std::endl;
    std::cout << "  stress,  -s    Run stress tests only (100 concurrent clients)" << std::endl;
    std::cout << "  race,    -r    Run race condition tests only" << std::endl;
    std::cout << "  timeout, -t    Run timeout/idle connection tests only" << std::endl;
    std::cout << "  config,  -c    Run configuration tests only" << std::endl;
    std::cout << "  http,    -H    Run HTTP layer tests only" << std::endl;
    std::cout << "  ws,      -w    Run WebSocket layer tests only" << std::endl;
    std::cout << "  tls,     -T    Run TLS/SSL tests only" << std::endl;
    std::cout << "  cli,     -C    Run CLI entry point tests only" << std::endl;
    std::cout << "  http2,   -2    Run HTTP/2 tests only" << std::endl;
    std::cout << "  route,   -R    Run route trie/router pattern tests only" << std::endl;
    std::cout << "  kqueue,   -K    Run kqueue platform tests only (macOS; skipped on Linux)" << std::endl;
    std::cout << "  upstream, -U    Run upstream connection pool tests only" << std::endl;
    std::cout << "  proxy,    -P    Run the full proxy feature family (internal regressions + engine)" << std::endl;
    std::cout << "  rate_limit, -L  Run rate limit tests only" << std::endl;
    std::cout << std::endl;
    std::cout << "  circuit_breaker, -B  Run the full circuit-breaker feature family" << std::endl;
    std::cout << "                       (state machine + components + integration +" << std::endl;
    std::cout << "                        retry budget + drain + observability + reload)" << std::endl;
    std::cout << std::endl;
    std::cout << "  auth,        -A    Run the full auth feature family (umbrella —" << std::endl;
    std::cout << "                     runs every auth-related sub-suite). Use the" << std::endl;
    std::cout << "                     sub-flags below to drill into one aspect." << std::endl;
    std::cout << "  auth_foundation    Auth foundation sub-suite (token_hasher / claims /" << std::endl;
    std::cout << "                     policy matcher / config validation)" << std::endl;
    std::cout << "  jwt,         -J    JWT verifier unit tests" << std::endl;
    std::cout << "  jwks,        -j    JWKS cache unit tests" << std::endl;
    std::cout << "  oidc,        -O    OIDC discovery unit tests" << std::endl;
    std::cout << "  hrauth,      -W    Header rewriter auth overlay tests" << std::endl;
    std::cout << "  auth_mgr,    -M    AuthManager unit tests" << std::endl;
    std::cout << "  auth2,       -V    Auth integration tests (HttpServer + middleware)" << std::endl;
    std::cout << "  auth_fail,   -F    Auth failure mode tests" << std::endl;
    std::cout << "  auth_reload, -X    Auth reload tests" << std::endl;
    std::cout << "  auth_multi,  -I    Auth multi-issuer tests" << std::endl;
    std::cout << "  auth_ws,     -G    Auth WebSocket upgrade tests" << std::endl;
    std::cout << "  auth_race,   -Q    Auth race condition tests" << std::endl;
    std::cout << "  router_async,-N    Router async-middleware tests" << std::endl;
    std::cout << "  introspection_cache, -Y  Introspection cache unit tests" << std::endl;
    std::cout << "  intro_client, -y   Introspection client static-helper + AsyncPendingState tests" << std::endl;
    std::cout << "  auth_intro,  -Z    Introspection integration tests" << std::endl;
    std::cout << "  auth_observability, -o    Auth observability tests" << std::endl;
    std::cout << std::endl;
    std::cout << "  obs_foundation     Observability foundation value-type tests" << std::endl;
    std::cout << "                     (TraceId / SpanId / TraceFlags / TraceState /" << std::endl;
    std::cout << "                      SpanContext / LabelSet / AttrValue)" << std::endl;
    std::cout << "  obs_tracer         Observability tracer / sampler / span lifecycle" << std::endl;
    std::cout << "                     tests (Tracer / TracerProvider / Span / Sampler)" << std::endl;
    std::cout << "  obs_metrics        Observability metrics tests (Counter /" << std::endl;
    std::cout << "                     Histogram / Meter / MeterProvider + cardinality" << std::endl;
    std::cout << "                     registry)" << std::endl;
    std::cout << "  obs_mgr            Observability manager + middleware tests" << std::endl;
    std::cout << "                     (snapshot lifecycle, finalize CAS gate, kill" << std::endl;
    std::cout << "                      loop, Reload, end-to-end middleware)" << std::endl;
    std::cout << "  obs_e2e            Observability end-to-end tests (boot real" << std::endl;
    std::cout << "                     HttpServer, send HTTP requests, verify spans)" << std::endl;
    std::cout << "  obs_propagator     W3C Trace Context propagator tests" << std::endl;
    std::cout << "                     (traceparent / tracestate parse + Inject)" << std::endl;
    std::cout << "  obs_export         Export pipeline tests (BatchSpanProcessor /" << std::endl;
    std::cout << "                     PeriodicMetricReader / OtlpHttpExporter)" << std::endl;
    std::cout << "  obs_prom           PrometheusExporter rendering tests (sanitize," << std::endl;
    std::cout << "                     counter / gauge / histogram exposition, OpenMetrics)" << std::endl;
    std::cout << std::endl;
    std::cout << "  dns,         -D    Run the full DNS / dual-stack feature family" << std::endl;
    std::cout << "                     (DnsResolver primitives + dual-stack integration)" << std::endl;
    std::cout << "  dual_stack         Sub-suite — dual-stack integration only (OS-sensitive)" << std::endl;
    std::cout << "  dns_resolver       Sub-suite — DnsResolver primitives only (timing-sensitive)" << std::endl;
    std::cout << "  help,        -h    Show this help message" << std::endl;
    std::cout << "\nNo arguments: Run all tests (full sweep — every suite above plus the dual_stack and DnsResolver suites)." << std::endl;
}

int main(int argc, char* argv[]) {
    RaiseFdLimit();
    std::cout << "Reactor Network Server - Test Suite" << std::endl;
    std::cout << "====================================\n" << std::endl;

    if(argc == 2){
        std::string mode = argv[1];

        // Run basic functional tests only
        if(mode == "basic" || mode == "-b"){
            BasicTests::RunAllTests();
        // Run stress tests
        }else if(mode == "stress" || mode == "-s"){
            StressTests::RunStressTests();
        // Run race condition tests
        }else if(mode == "race" || mode == "-r"){
            RaceConditionTests::RunRaceConditionTests();
        // Run timeout tests
        }else if(mode == "timeout" || mode == "-t"){
            TimeoutTests::RunAllTests();
        // Run config tests
        }else if(mode == "config" || mode == "-c"){
            ConfigTests::RunAllTests();
        // Run HTTP tests
        }else if(mode == "http" || mode == "-H"){
            HttpInternalTests::RunAllTests();
            HttpTests::RunAllTests();
        // Run WebSocket tests
        }else if(mode == "ws" || mode == "-w"){
            WebSocketTests::RunAllTests();
        // Run TLS tests
        }else if(mode == "tls" || mode == "-T"){
            TlsTests::RunAllTests();
        // Run CLI tests
        }else if(mode == "cli" || mode == "-C"){
            CliTests::RunAllTests();
        // Run HTTP/2 tests
        }else if(mode == "http2" || mode == "-2"){
            Http2InternalTests::RunAllTests();
            Http2Tests::RunAllTests();
        // Run route trie / router pattern tests
        }else if(mode == "route" || mode == "-R"){
            RouteTests::RunAllTests();
        // Run kqueue platform tests
        }else if(mode == "kqueue" || mode == "-K"){
            KqueueTests::RunAllTests();
        // Run upstream connection pool tests
        }else if(mode == "upstream" || mode == "-U"){
            UpstreamPoolTests::RunAllTests();
        // Run the full proxy feature family (internal proxy-transaction
        // regressions + end-to-end proxy engine tests).
        }else if(mode == "proxy" || mode == "-P"){
            RunAllProxyFamily();
        // Run rate limit tests
        }else if(mode == "rate_limit" || mode == "-L"){
            RateLimitTests::RunAllTests();
        // Run the full circuit-breaker feature family — calls every CB
        // sub-suite via RunAllCircuitBreakerFamily(). Sub-suites stay
        // accessible by name through the no-arg full sweep; individual
        // CLI flags for sub-suites are not currently exposed.
        }else if(mode == "circuit_breaker" || mode == "-B"){
            RunAllCircuitBreakerFamily();
        // Run the full auth feature family — calls every auth-related
        // sub-suite via RunAllAuthFamily(). Use the sub-flags below
        // (auth_foundation, jwt, jwks, oidc, hrauth, auth_mgr, auth2,
        // auth_fail, auth_reload, auth_multi, auth_ws, auth_race,
        // router_async, introspection_cache, intro_client, auth_intro,
        // auth_observability) to drill into a specific aspect.
        }else if(mode == "auth" || mode == "-A"){
            RunAllAuthFamily();
        // Run only the auth foundation sub-suite (token_hasher + base64url env
        // auto-detect + scope extractors). Was previously the `auth` flag —
        // the umbrella now lives under `auth`.
        }else if(mode == "auth_foundation"){
            AuthFoundationTests::RunAllTests();
        // Run JWT verifier unit tests
        }else if(mode == "jwt" || mode == "-J"){
            JwtVerifierTests::RunAllTests();
        // Run JWKS cache unit tests
        }else if(mode == "jwks" || mode == "-j"){
            JwksCacheTests::RunAllTests();
        // Run OIDC discovery unit tests
        }else if(mode == "oidc" || mode == "-O"){
            OidcDiscoveryTests::RunAllTests();
        // Run header rewriter auth overlay tests
        }else if(mode == "hrauth" || mode == "-W"){
            HeaderRewriterAuthTests::RunAllTests();
        // Run AuthManager unit tests
        }else if(mode == "auth_mgr" || mode == "-M"){
            AuthManagerTests::RunAllTests();
        // Run auth integration tests (Phase 2)
        }else if(mode == "auth2" || mode == "-V"){
            AuthIntegrationTests::RunAllTests();
        // Run auth failure mode tests
        }else if(mode == "auth_fail" || mode == "-F"){
            AuthFailureModeTests::RunAllTests();
        // Run auth reload tests
        }else if(mode == "auth_reload" || mode == "-X"){
            AuthReloadTests::RunAllTests();
        // Run auth multi-issuer tests
        }else if(mode == "auth_multi" || mode == "-I"){
            AuthMultiIssuerTests::RunAllTests();
        // Run auth WebSocket upgrade tests
        }else if(mode == "auth_ws" || mode == "-G"){
            AuthWebSocketUpgradeTests::RunAllTests();
        // Run auth race condition tests
        }else if(mode == "auth_race" || mode == "-Q"){
            AuthRaceTests::RunAllTests();
        // Run router async-middleware tests (P3-0)
        }else if(mode == "router_async" || mode == "-N"){
            RouterAsyncMiddlewareTests::RunAllTests();
        // Run introspection cache unit tests
        }else if(mode == "introspection_cache" || mode == "-Y"){
            IntrospectionCacheTests::RunAllTests();
        // Run introspection client static-helper + AsyncPendingState unit tests
        }else if(mode == "intro_client" || mode == "-y"){
            IntrospectionClientTests::RunAllTests();
        // Run introspection integration tests
        }else if(mode == "auth_intro" || mode == "-Z"){
            AuthIntrospectionIntegrationTests::RunAllTests();
        // Run the full DNS / dual-stack feature family — DnsResolver
        // primitives + dual-stack integration via RunAllDnsFamily().
        }else if(mode == "dns" || mode == "-D"){
            RunAllDnsFamily();
        // Run only the dual-stack integration sub-suite (sockets / IPv6
        // bind / hostname rejection / Reload integration). OS-sensitive;
        // exercised on the macOS CI subset. The DnsResolver primitives
        // are pure-logic + timing-sensitive — flaky on shared runners,
        // so they live behind the `dns` umbrella for the no-arg full
        // sweep (Linux) and the `dns_resolver` sub-flag for local dev.
        }else if(mode == "dual_stack"){
            DualStackTests::RunAllTests();
        // Run only the DnsResolver primitives sub-suite.
        }else if(mode == "dns_resolver"){
            DnsResolverTests::RunAllTests();
        // Run only TSAN-instrumented dual-stack stop/reload/destruction tests
        }else if(mode == "dual_stack_tsan"){
            DualStackTests::RunTSANTests();
        // Run auth observability tests
        }else if(mode == "auth_observability" || mode == "-o"){
            AuthObservabilityTests::RunAllTests();
        // Run observability foundation value-type tests (TraceId / SpanId /
        // TraceFlags / TraceState / SpanContext / LabelSet / AttrValue).
        }else if(mode == "obs_foundation"){
            ObservabilityFoundationTests::RunAllTests();
        // Run observability tracer / sampler / span lifecycle tests.
        }else if(mode == "obs_tracer"){
            ObservabilityTracerTests::RunAllTests();
        // Run observability metrics tests (Counter / Histogram /
        // Meter / MeterProvider + cardinality registry).
        }else if(mode == "obs_metrics"){
            ObservabilityMetricsTests::RunAllTests();
        // Run observability manager + middleware tests (snapshot
        // lifecycle, FinalizeFromSnapshot CAS gate, kill loop,
        // Reload, middleware end-to-end).
        }else if(mode == "obs_mgr"){
            ObservabilityManagerTests::RunAllTests();
        // Run observability end-to-end tests (boot real HttpServer,
        // install observability manager + middleware, send real HTTP
        // requests, assert spans captured).
        }else if(mode == "obs_e2e"){
            ObservabilityE2ETests::RunAllTests();
        // Run W3C Trace Context propagator tests (traceparent /
        // tracestate parse + serialize + Inject / Extract).
        }else if(mode == "obs_propagator"){
            ObservabilityPropagatorTests::RunAllTests();
        // Run export pipeline tests (BatchSpanProcessor /
        // PeriodicMetricReader / OtlpHttpExporter).
        }else if(mode == "obs_export"){
            ObservabilityExportPipelineTests::RunAllTests();
        // Run PrometheusExporter rendering tests (sanitization,
        // counter / gauge / histogram exposition + OpenMetrics).
        }else if(mode == "obs_prom"){
            ObservabilityPrometheusTests::RunAllTests();
        // Show help
        }else if(mode == "help" || mode == "-h" || mode == "--help"){
            PrintUsage(argv[0]);
            return 0;
        }else{
            std::cout << "Error: Unknown option '" << mode << "'\n" << std::endl;
            PrintUsage(argv[0]);
            return 1;
        }
    }else if(argc > 2){
        std::cout << "Error: Too many arguments\n" << std::endl;
        PrintUsage(argv[0]);
        return 1;
    }else{
        RunAllTest();
    }


    // Print test summary
    TestFramework::PrintResults();

    auto passed_count = std::count_if(TestFramework::results.begin(),
                                      TestFramework::results.end(),
                                      [](const TestFramework::TestResult& r) { return r.passed; });
    return (static_cast<size_t>(passed_count) == TestFramework::results.size()) ? 0 : 1;
}
