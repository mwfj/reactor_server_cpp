#include "test_framework.h"
#include <map>

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
    void RecordTest(const std::string& name, bool passed, const std::string& error, TestCategory category) {
        results.push_back({name, passed, error, category});
    }

    // Helper function to get category name
    std::string GetCategoryName(TestCategory category) {
        switch(category) {
            case TestCategory::BASIC: return "Basic Tests";
            case TestCategory::STRESS: return "Stress Tests";
            case TestCategory::RACE_CONDITION: return "Race Condition Tests";
            default: return "Other Tests";
        }
    }

    // Print all test results in a formatted, categorized summary
    void PrintResults() {
        if (results.empty()) {
            std::cout << "\nNo test results to display.\n" << std::endl;
            return;
        }

        std::cout << "\n" << std::string(70, '=') << std::endl;
        std::cout << "                    TEST RESULTS SUMMARY" << std::endl;
        std::cout << std::string(70, '=') << std::endl;

        // Count statistics by category
        struct CategoryStats {
            int total = 0;
            int passed = 0;
            int failed = 0;
        };

        std::map<TestCategory, CategoryStats> category_stats;
        int total_passed = 0;
        int total_failed = 0;

        // First pass: collect statistics
        for (const auto& result : results) {
            category_stats[result.category].total++;
            if (result.passed) {
                category_stats[result.category].passed++;
                total_passed++;
            } else {
                category_stats[result.category].failed++;
                total_failed++;
            }
        }

        // Second pass: print by category
        std::vector<TestCategory> categories = {
            TestCategory::BASIC,
            TestCategory::STRESS,
            TestCategory::RACE_CONDITION,
            TestCategory::OTHER
        };

        for (auto category : categories) {
            // Skip categories with no tests
            if (category_stats[category].total == 0) continue;

            std::cout << "\n" << GetCategoryName(category);
            std::cout << " (" << category_stats[category].passed << "/"
                      << category_stats[category].total << " passed)" << std::endl;
            std::cout << std::string(70, '-') << std::endl;

            // Print tests in this category
            for (const auto& result : results) {
                if (result.category != category) continue;

                std::cout << "  [" << (result.passed ? "PASS" : "FAIL") << "] "
                          << result.test_name;

                if (!result.passed && !result.error_message.empty()) {
                    std::cout << "\n        Error: " << result.error_message;
                }
                std::cout << std::endl;
            }
        }

        // Print overall summary
        std::cout << "\n" << std::string(70, '=') << std::endl;
        std::cout << "OVERALL SUMMARY" << std::endl;
        std::cout << std::string(70, '-') << std::endl;

        // Show per-category breakdown
        for (auto category : categories) {
            if (category_stats[category].total == 0) continue;

            double success_rate = (double)category_stats[category].passed / category_stats[category].total * 100.0;
            std::cout << "  " << GetCategoryName(category) << ": "
                      << category_stats[category].passed << "/" << category_stats[category].total
                      << " (" << (int)success_rate << "%)" << std::endl;
        }

        // Calculate overall success rate
        double overall_success_rate = (double)total_passed / results.size() * 100.0;

        std::cout << std::string(70, '-') << std::endl;
        std::cout << "Total Tests: " << results.size() << " | "
                  << "Passed: " << total_passed << " | "
                  << "Failed: " << total_failed << std::endl;
        std::cout << "Success Rate: " << (int)overall_success_rate << "%" << std::endl;
        std::cout << std::string(70, '=') << std::endl;

        // Show final status with emoji-like indicators
        if (total_failed == 0) {
            std::cout << "\n[SUCCESS] All tests passed! " << std::string(3, (char)0x2713) << std::endl;
        } else if (total_passed > total_failed) {
            std::cout << "\n[PARTIAL] " << total_failed << " test(s) failed." << std::endl;
        } else {
            std::cout << "\n[FAILURE] " << total_failed << " test(s) failed." << std::endl;
        }
        std::cout << std::endl;
    }
}
