#include "reactor_server.h"
#include "client.h"
#include "stress_test.h"
#include "basic_test.h"
#include "race_condition_test.h"
#include "test_framework.h"
#include <algorithm>


int main() {
    std::cout << "Reactor Network Server - Test Suite" << std::endl;
    std::cout << "====================================\n" << std::endl;

    // Run basic functional tests
    BasicTests::RunAllTests();

    // Run stress tests (optional - comment out if needed)
    // Longer delay to ensure ports are released from TIME_WAIT
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    StressTests::RunStressTests();

    // Run race condition tests (validates EVENTFD_RACE_CONDITION_FIXES.md)
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    RaceConditionTests::RunRaceConditionTests();

    // Print test summary
    TestFramework::PrintResults();

    auto passed_count = std::count_if(TestFramework::results.begin(),
                                      TestFramework::results.end(),
                                      [](const TestFramework::TestResult& r) { return r.passed; });
    return (static_cast<size_t>(passed_count) == TestFramework::results.size()) ? 0 : 1;
}
