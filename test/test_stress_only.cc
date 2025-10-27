#include "reactor_server.h"
#include "client.h"
#include "stress_test.h"
#include "test_framework.h"

int main() {
    std::cout << "Running Stress Test Only" << std::endl;
    std::cout << "========================\n" << std::endl;

    StressTests::RunStressTests();
    TestFramework::PrintResults();

    return (TestFramework::results[0].passed) ? 0 : 1;
}
