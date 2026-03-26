#include "reactor_server.h"
#include "client.h"
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
#include "test_framework.h"
#include <algorithm>


void RunAllTest(){
    std::cout << "Run All Tests - Test Suite" << std::endl;
    // Run basic functional tests
    BasicTests::RunAllTests();

    // Run stress tests
    // Longer delay to ensure ports are released from TIME_WAIT
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    StressTests::RunStressTests();

    // Run race condition tests
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    RaceConditionTests::RunRaceConditionTests();

    // Run timeout tests
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    TimeoutTests::RunAllTests();

    // Run config tests
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    ConfigTests::RunAllTests();

    // Run HTTP tests
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    HttpTests::RunAllTests();

    // Run WebSocket tests
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    WebSocketTests::RunAllTests();

    // Run TLS tests
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    TlsTests::RunAllTests();

    // Run CLI tests
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    CliTests::RunAllTests();

    // Run HTTP/2 tests
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    Http2Tests::RunAllTests();

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
    std::cout << "  help,    -h    Show this help message" << std::endl;
    std::cout << "\nNo arguments: Run all tests (basic + stress + race + timeout + config + http + ws + tls + cli + http2)" << std::endl;
}

int main(int argc, char* argv[]) {
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
