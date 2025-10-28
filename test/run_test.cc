#include "reactor_server.h"
#include "client.h"
#include "stress_test.h"
#include "basic_test.h"
#include "race_condition_test.h"
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


    std::cout << "====================================\n" << std::endl;
}

void PrintUsage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS]" << std::endl;
    std::cout << "\nOptions:" << std::endl;
    std::cout << "  basic,  -b    Run basic functional tests only" << std::endl;
    std::cout << "  stress, -s    Run stress tests only (100 concurrent clients)" << std::endl;
    std::cout << "  race,   -r    Run race condition tests only" << std::endl;
    std::cout << "  help,   -h    Show this help message" << std::endl;
    std::cout << "\nNo arguments: Run all tests (basic + stress + race)" << std::endl;
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
