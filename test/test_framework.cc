#include "test_framework.h"

// This file provides the single definition for the global 'results' vector
// and function implementations that are declared in test_framework.h.
//
// Why this is necessary:
// - When a global variable is defined in a header file without 'extern',
//   each translation unit (.cc file) that includes it gets its own copy
// - This violates the One Definition Rule (ODR) in C++
// - The linker may fail, or worse, succeed but cause undefined behavior/crashes
//
// By using 'extern' in the header and defining it here in exactly one .cc file,
// we ensure all translation units share the same 'results' vector instance.
//
// Similarly, functions must be declared in the header and defined here (or marked
// as 'inline' in the header) to avoid multiple definition errors when the header
// is included in multiple translation units.

namespace TestFramework {
    // Single definition of the global results vector
    std::vector<TestResult> results;

    // Record a test result
    void RecordTest(const std::string& name, bool passed, const std::string& error) {
        results.push_back({name, passed, error});
    }

    // Print all test results in a formatted summary
    void PrintResults() {
        std::cout << "\n" << std::string(60, '=') << std::endl;
        std::cout << "TEST RESULTS SUMMARY" << std::endl;
        std::cout << std::string(60, '=') << std::endl;

        int passed = 0;
        int failed = 0;

        for (const auto& result : results) {
            std::cout << "[" << (result.passed ? "PASS" : "FAIL") << "] "
                      << result.test_name;
            if (!result.passed && !result.error_message.empty()) {
                std::cout << "\n      Error: " << result.error_message;
            }
            std::cout << std::endl;

            if (result.passed) passed++;
            else failed++;
        }

        std::cout << std::string(60, '-') << std::endl;
        std::cout << "Total: " << results.size() << " | "
                  << "Passed: " << passed << " | "
                  << "Failed: " << failed << std::endl;
        std::cout << std::string(60, '=') << std::endl;
    }
}
