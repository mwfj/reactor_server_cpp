#pragma once
#include <string>
#include <vector>
#include <iostream>
#include <sstream>
#include <cassert>

// Test result tracking
namespace TestFramework {
    // Test categories for better organization
    enum class TestCategory {
        BASIC,
        STRESS,
        RACE_CONDITION,
        OTHER
    };

    struct TestResult {
        std::string test_name;
        bool passed;
        std::string error_message;
        TestCategory category;
    };

    // IMPORTANT: Use extern to avoid multiple definition errors (ODR violation)
    // When this header is included in multiple translation units, each would get
    // its own copy of 'results' without extern, causing linker errors or undefined behavior.
    // The actual definition is in test_framework.cc
    extern std::vector<TestResult> results;

    // Function declarations (implementations are in test_framework.cc)
    void RecordTest(const std::string& name, bool passed, const std::string& error = "", TestCategory category = TestCategory::OTHER);
    void PrintResults();
}
