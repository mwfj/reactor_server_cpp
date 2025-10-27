#include "reactor_server.h"
#include "client.h"
#include "race_condition_test.h"
#include "test_framework.h"
#include <algorithm>

int main() {
    std::cout << "Reactor Network Server - Race Condition Test Suite" << std::endl;
    std::cout << "==================================================\n" << std::endl;

    // Run race condition tests only
    RaceConditionTests::RunRaceConditionTests();

    // Print test summary
    TestFramework::PrintResults();

    auto passed_count = std::count_if(TestFramework::results.begin(),
                                      TestFramework::results.end(),
                                      [](const TestFramework::TestResult& r) { return r.passed; });
    return (static_cast<size_t>(passed_count) == TestFramework::results.size()) ? 0 : 1;
}
