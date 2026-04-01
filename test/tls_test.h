#pragma once

#include "test_framework.h"
#include "tls/tls_context.h"
#include "tls/tls_connection.h"
#include <cstdlib>

namespace TlsTests {

    // Generate self-signed cert for testing
    static bool GenerateTestCert() {
        int ret = std::system(
            "openssl req -x509 -newkey rsa:2048 -keyout /tmp/test_key.pem "
            "-out /tmp/test_cert.pem -days 1 -nodes "
            "-subj '/CN=localhost' 2>/dev/null");
        return (ret == 0);
    }

    static void CleanupTestCert() {
        std::remove("/tmp/test_cert.pem");
        std::remove("/tmp/test_key.pem");
    }

    void TestTlsContextCreation() {
        std::cout << "\n[TEST] TLS Context Creation..." << std::endl;
        try {
            if (!GenerateTestCert()) {
                TestFramework::RecordTest("TLS Context Creation", false,
                    "Failed to generate test cert", TestFramework::TestCategory::OTHER);
                return;
            }

            TlsContext ctx("/tmp/test_cert.pem", "/tmp/test_key.pem");
            bool pass = (ctx.GetCtx() != nullptr);

            CleanupTestCert();
            TestFramework::RecordTest("TLS Context Creation", pass,
                pass ? "" : "SSL_CTX is null", TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            CleanupTestCert();
            TestFramework::RecordTest("TLS Context Creation", false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    void TestTlsContextInvalidCert() {
        std::cout << "\n[TEST] TLS Context Invalid Cert..." << std::endl;
        try {
            bool threw = false;
            try {
                TlsContext ctx("/nonexistent/cert.pem", "/nonexistent/key.pem");
            } catch (const std::runtime_error&) {
                threw = true;
            }

            TestFramework::RecordTest("TLS Context Invalid Cert", threw,
                threw ? "" : "Expected exception for invalid cert", TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("TLS Context Invalid Cert", false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    void RunAllTests() {
        std::cout << "\n" << std::string(60, '=') << std::endl;
        std::cout << "TLS/SSL - UNIT TESTS" << std::endl;
        std::cout << std::string(60, '=') << std::endl;

        TestTlsContextCreation();
        TestTlsContextInvalidCert();
    }

}  // namespace TlsTests
