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

    // Run HTTP tests
    HttpTests::RunAllTests();

    // Run WebSocket tests
    WebSocketTests::RunAllTests();

    // Run TLS tests
    TlsTests::RunAllTests();

    // Run CLI tests
    CliTests::RunAllTests();

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
    std::cout << "  help,     -h    Show this help message" << std::endl;
    std::cout << "\nNo arguments: Run all tests (basic + stress + race + timeout + config + http + ws + tls + cli + http2 + route + kqueue + upstream + proxy + rate_limit)" << std::endl;
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
