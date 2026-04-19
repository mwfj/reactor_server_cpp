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

    // Run focused internal proxy transaction regressions
    ProxyTransactionInternalTests::RunAllTests();

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

    // Run proxy engine tests
    ProxyTests::RunAllTests();

    // Run rate limit tests
    RateLimitTests::RunAllTests();

    // Run circuit breaker tests
    CircuitBreakerTests::RunAllTests();

    // Run circuit-breaker component unit tests (RetryBudget / Host / Manager)
    CircuitBreakerComponentsTests::RunAllTests();

    // Run circuit-breaker integration tests (end-to-end through
    // ProxyTransaction + UpstreamManager + HttpServer)
    CircuitBreakerIntegrationTests::RunAllTests();

    // Run circuit-breaker retry-budget integration tests
    CircuitBreakerRetryBudgetTests::RunAllTests();

    // Run circuit-breaker wait-queue-drain-on-trip tests
    CircuitBreakerWaitQueueDrainTests::RunAllTests();

    // Run circuit-breaker observability tests
    CircuitBreakerObservabilityTests::RunAllTests();

    // Run circuit-breaker hot-reload tests
    CircuitBreakerReloadTests::RunAllTests();

    // Run auth foundation tests (minimal — pins r3/r5 security invariants)
    AuthFoundationTests::RunAllTests();

    // Run JWT verifier unit tests (stateless, no server)
    JwtVerifierTests::RunAllTests();

    // Run JWKS cache unit tests
    JwksCacheTests::RunAllTests();

    // Run OIDC discovery unit tests (no live IdP)
    OidcDiscoveryTests::RunAllTests();

    // Run header rewriter auth overlay tests
    HeaderRewriterAuthTests::RunAllTests();

    // Run AuthManager unit tests (no server)
    AuthManagerTests::RunAllTests();

    // Run auth integration tests (HttpServer + AuthManager middleware)
    AuthIntegrationTests::RunAllTests();

    // Run auth failure mode tests (UNDETERMINED path, stale JWKS)
    AuthFailureModeTests::RunAllTests();

    // Run auth reload tests (Reload API — topology, reloadable fields)
    AuthReloadTests::RunAllTests();

    // Run auth multi-issuer tests (PeekIssuer routing, allowlist enforcement)
    AuthMultiIssuerTests::RunAllTests();

    // Run auth WebSocket upgrade tests
    AuthWebSocketUpgradeTests::RunAllTests();

    // Run auth race condition tests
    AuthRaceTests::RunAllTests();

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
    std::cout << "  proxy,    -P    Run proxy engine tests only" << std::endl;
    std::cout << "  rate_limit, -L  Run rate limit tests only" << std::endl;
    std::cout << "  circuit_breaker, -B  Run circuit-breaker tests only" << std::endl;
    std::cout << "  auth,        -A    Run auth foundation tests only" << std::endl;
    std::cout << "  jwt,         -J    Run JWT verifier unit tests only" << std::endl;
    std::cout << "  jwks,        -j    Run JWKS cache unit tests only" << std::endl;
    std::cout << "  oidc,        -O    Run OIDC discovery unit tests only" << std::endl;
    std::cout << "  hrauth,      -W    Run header rewriter auth overlay tests only" << std::endl;
    std::cout << "  auth_mgr,    -M    Run AuthManager unit tests only" << std::endl;
    std::cout << "  auth2,       -V    Run auth integration tests (Phase 2) only" << std::endl;
    std::cout << "  auth_fail,   -F    Run auth failure mode tests only" << std::endl;
    std::cout << "  auth_reload, -X    Run auth reload tests only" << std::endl;
    std::cout << "  auth_multi,  -I    Run auth multi-issuer tests only" << std::endl;
    std::cout << "  auth_ws,     -G    Run auth WebSocket upgrade tests only" << std::endl;
    std::cout << "  auth_race,   -Q    Run auth race condition tests only" << std::endl;
    std::cout << "  help,        -h    Show this help message" << std::endl;
    std::cout << "\nNo arguments: Run all tests (basic + stress + race + timeout + config + http + ws + tls + cli + http2 + route + kqueue + upstream + proxy + rate_limit + circuit_breaker + auth + auth-phase2)" << std::endl;
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
        // Run proxy engine tests
        }else if(mode == "proxy" || mode == "-P"){
            ProxyTests::RunAllTests();
        // Run rate limit tests
        }else if(mode == "rate_limit" || mode == "-L"){
            RateLimitTests::RunAllTests();
        // Run circuit-breaker tests (unit + components + integration + retry-budget + drain + observability + reload)
        }else if(mode == "circuit_breaker" || mode == "-B"){
            CircuitBreakerTests::RunAllTests();
            CircuitBreakerComponentsTests::RunAllTests();
            CircuitBreakerIntegrationTests::RunAllTests();
            CircuitBreakerRetryBudgetTests::RunAllTests();
            CircuitBreakerWaitQueueDrainTests::RunAllTests();
            CircuitBreakerObservabilityTests::RunAllTests();
            CircuitBreakerReloadTests::RunAllTests();
        // Run auth foundation tests (token_hasher + base64url env auto-detect + scope extractors)
        }else if(mode == "auth" || mode == "-A"){
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
