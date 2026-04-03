#pragma once
#include "common.h"
#include "test_server_runner.h"
#include "http_test_client.h"
#include "test_framework.h"
#include <thread>
#include <chrono>

class TimeoutTests {
public:
    static void RunAllTests() {
        std::cout << "\n============================================================" << std::endl;
        std::cout << "TIMEOUT TESTS" << std::endl;
        std::cout << "============================================================\n" << std::endl;

        TestConfigurableTimerParameters();
        TestDefaultTimerParameters();
        TestActiveConnectionsWork();
    }

private:

    // Test 1: Verify server accepts custom timer parameters
    static void TestConfigurableTimerParameters() {
        std::cout << "[TIMEOUT-TEST-1] Configurable Timer Parameters..." << std::endl;

        try {
            // Create server with custom timer: 10 second idle timeout
            auto config = TestHttpClient::MakeTestConfig(10);
            HttpServer server(config);
            TestHttpClient::SetupEchoRoutes(server);
            TestServerRunner<HttpServer> runner(server);
            const int port = runner.GetPort();

            // Send a few messages to verify server works with custom timer config
            for (int i = 0; i < 3; i++) {
                std::string body = "CustomTimer" + std::to_string(i);
                std::string response = TestHttpClient::HttpPost(port, "/echo", body);

                if (!TestHttpClient::HasStatus(response, 200)) {
                    TestFramework::RecordTest("TIMEOUT-1: Custom Timer Config", false,
                        "Request failed", TestFramework::TestCategory::OTHER);
                    return;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }

            std::cout << "[TIMEOUT-TEST-1] PASS: Custom timer parameters accepted" << std::endl;
            TestFramework::RecordTest("TIMEOUT-1: Custom Timer Config", true, "", TestFramework::TestCategory::OTHER);

        } catch (const std::exception& e) {
            std::cout << "[TIMEOUT-TEST-1] FAIL: " << e.what() << std::endl;
            TestFramework::RecordTest("TIMEOUT-1: Custom Timer Config", false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // Test 2: Verify server works with default timer parameters
    static void TestDefaultTimerParameters() {
        std::cout << "[TIMEOUT-TEST-2] Default Timer Parameters..." << std::endl;

        try {
            // Create server with default parameters (300s idle, 30s request)
            HttpServer server("127.0.0.1", 0);
            TestHttpClient::SetupEchoRoutes(server);
            TestServerRunner<HttpServer> runner(server);
            const int port = runner.GetPort();

            // Send messages to verify default timer doesn't interfere
            for (int i = 0; i < 5; i++) {
                std::string body = "DefaultTimer" + std::to_string(i);
                std::string response = TestHttpClient::HttpPost(port, "/echo", body);

                if (!TestHttpClient::HasStatus(response, 200)) {
                    TestFramework::RecordTest("TIMEOUT-2: Default Timer Config", false,
                        "Request failed", TestFramework::TestCategory::OTHER);
                    return;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }

            std::cout << "[TIMEOUT-TEST-2] PASS: Default timer parameters work" << std::endl;
            TestFramework::RecordTest("TIMEOUT-2: Default Timer Config", true, "", TestFramework::TestCategory::OTHER);

        } catch (const std::exception& e) {
            std::cout << "[TIMEOUT-TEST-2] FAIL: " << e.what() << std::endl;
            TestFramework::RecordTest("TIMEOUT-2: Default Timer Config", false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // Test 3: Active connections continue to work (basic functional test)
    static void TestActiveConnectionsWork() {
        std::cout << "[TIMEOUT-TEST-3] Active Connections Functional Test..." << std::endl;

        try {
            // Use moderate timer: 30 second idle timeout
            auto config = TestHttpClient::MakeTestConfig(30);
            HttpServer server(config);
            TestHttpClient::SetupEchoRoutes(server);
            TestServerRunner<HttpServer> runner(server);
            const int port = runner.GetPort();

            // Send 10 sequential messages with small delays
            // This verifies timer doesn't interfere with normal operation
            for (int i = 0; i < 10; i++) {
                std::string body = "Message" + std::to_string(i);
                std::string response = TestHttpClient::HttpPost(port, "/echo", body);

                if (!TestHttpClient::HasStatus(response, 200)) {
                    TestFramework::RecordTest("TIMEOUT-3: Active Connections", false,
                        "Request " + std::to_string(i) + " failed", TestFramework::TestCategory::OTHER);
                    return;
                }

                // 1 second delay - well below any timeout
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }

            std::cout << "[TIMEOUT-TEST-3] PASS: Active connections unaffected by timer" << std::endl;
            TestFramework::RecordTest("TIMEOUT-3: Active Connections", true, "", TestFramework::TestCategory::OTHER);

        } catch (const std::exception& e) {
            std::cout << "[TIMEOUT-TEST-3] FAIL: " << e.what() << std::endl;
            TestFramework::RecordTest("TIMEOUT-3: Active Connections", false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }
};
