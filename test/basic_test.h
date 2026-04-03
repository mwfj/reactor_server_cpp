#pragma once
#include "test_framework.h"
#include "test_server_runner.h"
#include "http_test_client.h"
#include <thread>

// Test namespace for basic functionality tests
namespace BasicTests {

    // Test 1: Single Client Connection
    void TestSingleConnection() {
        std::cout << "\n[TEST] Single Client Connection..." << std::endl;

        try {
            HttpServer server("127.0.0.1", 0);
            TestHttpClient::SetupEchoRoutes(server);
            TestServerRunner<HttpServer> runner(server);

            // Connect and send a simple GET request
            std::string response = TestHttpClient::HttpGet(runner.GetPort(), "/health");

            bool pass = !response.empty() && TestHttpClient::HasStatus(response, 200);
            std::string err = pass ? "" : "No valid response from server";

            TestFramework::RecordTest("Single Client Connection", pass, err, TestFramework::TestCategory::BASIC);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Single Client Connection", false, e.what(), TestFramework::TestCategory::BASIC);
        }
    }

    // Test 2: Echo Functionality
    void TestEchoFunctionality() {
        std::cout << "\n[TEST] Echo Functionality..." << std::endl;

        try {
            HttpServer server("127.0.0.1", 0);
            TestHttpClient::SetupEchoRoutes(server);
            TestServerRunner<HttpServer> runner(server);

            std::string response = TestHttpClient::HttpPost(
                runner.GetPort(), "/echo", "TestMessage");

            bool pass = TestHttpClient::HasStatus(response, 200) &&
                        TestHttpClient::ExtractBody(response) == "TestMessage";
            std::string err = pass ? "" : "Echo mismatch, got: " + TestHttpClient::ExtractBody(response);

            TestFramework::RecordTest("Echo Functionality", pass, err, TestFramework::TestCategory::BASIC);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Echo Functionality", false, e.what(), TestFramework::TestCategory::BASIC);
        }
    }

    // Test 3: Multiple Sequential Connections
    void TestMultipleSequentialConnections() {
        std::cout << "\n[TEST] Multiple Sequential Connections..." << std::endl;

        try {
            HttpServer server("127.0.0.1", 0);
            TestHttpClient::SetupEchoRoutes(server);
            TestServerRunner<HttpServer> runner(server);
            const int port = runner.GetPort();

            const int NUM_CLIENTS = 5;
            for (int i = 0; i < NUM_CLIENTS; i++) {
                std::string body = "Client" + std::to_string(i);
                std::string response = TestHttpClient::HttpPost(port, "/echo", body);

                if (!TestHttpClient::HasStatus(response, 200)) {
                    TestFramework::RecordTest("Multiple Sequential Connections", false,
                        "Request " + std::to_string(i) + " failed", TestFramework::TestCategory::BASIC);
                    return;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }

            TestFramework::RecordTest("Multiple Sequential Connections", true, "", TestFramework::TestCategory::BASIC);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Multiple Sequential Connections", false, e.what(), TestFramework::TestCategory::BASIC);
        }
    }

    // Test 4: Concurrent Connections
    void TestConcurrentConnections() {
        std::cout << "\n[TEST] Concurrent Connections..." << std::endl;

        try {
            HttpServer server("127.0.0.1", 0);
            TestHttpClient::SetupEchoRoutes(server);
            TestServerRunner<HttpServer> runner(server);
            const int port = runner.GetPort();

            const int NUM_CLIENTS = 10;
            std::vector<std::thread> client_threads;
            std::atomic<int> success_count{0};
            std::atomic<int> failure_count{0};

            for (int i = 0; i < NUM_CLIENTS; i++) {
                client_threads.emplace_back([i, port, &success_count, &failure_count]() {
                    try {
                        std::string body = "ConcurrentClient" + std::to_string(i);
                        std::string response = TestHttpClient::HttpPost(port, "/echo", body, 5000);

                        if (TestHttpClient::HasStatus(response, 200)) {
                            success_count++;
                        } else {
                            failure_count++;
                        }
                    } catch (const std::exception& e) {
                        std::cerr << "[TEST] Client " << i << " error: " << e.what() << std::endl;
                        failure_count++;
                    }
                });
            }

            for (auto& t : client_threads) {
                t.join();
            }

            std::cout << "[TEST] All " << NUM_CLIENTS << " concurrent clients completed" << std::endl;
            std::cout << "[TEST] Success: " << success_count << ", Failures: " << failure_count << std::endl;

            bool all_success = (success_count == NUM_CLIENTS && failure_count == 0);
            std::string error_msg = all_success ? "" :
                "Only " + std::to_string(success_count.load()) + "/" + std::to_string(NUM_CLIENTS) + " clients succeeded";
            TestFramework::RecordTest("Concurrent Connections", all_success, error_msg, TestFramework::TestCategory::BASIC);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Concurrent Connections", false, e.what(), TestFramework::TestCategory::BASIC);
        }
    }

    // Test 5: Large Message Transfer
    void TestLargeMessage() {
        std::cout << "\n[TEST] Large Message Transfer..." << std::endl;

        try {
            HttpServer server("127.0.0.1", 0);
            TestHttpClient::SetupEchoRoutes(server);
            TestServerRunner<HttpServer> runner(server);

            // Create a large message (512 bytes)
            std::string large_msg(512, 'A');

            std::string response = TestHttpClient::HttpPost(
                runner.GetPort(), "/echo", large_msg);

            bool pass = TestHttpClient::HasStatus(response, 200) &&
                        TestHttpClient::ExtractBody(response) == large_msg;
            std::string err = pass ? "" : "Large message echo mismatch";

            std::cout << "[TEST] Large message (" << large_msg.size() << " bytes) transferred" << std::endl;

            TestFramework::RecordTest("Large Message Transfer", pass, err, TestFramework::TestCategory::BASIC);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Large Message Transfer", false, e.what(), TestFramework::TestCategory::BASIC);
        }
    }

    // Test 6: Connection and Immediate Disconnect
    void TestQuickDisconnect() {
        std::cout << "\n[TEST] Quick Connection and Disconnect..." << std::endl;

        try {
            HttpServer server("127.0.0.1", 0);
            TestHttpClient::SetupEchoRoutes(server);
            TestServerRunner<HttpServer> runner(server);
            const int port = runner.GetPort();

            for (int i = 0; i < 3; i++) {
                int sockfd = TestHttpClient::ConnectRawSocket(port);
                if (sockfd >= 0) {
                    close(sockfd);  // Immediate disconnect
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }

            std::cout << "[TEST] Quick disconnect test completed" << std::endl;

            TestFramework::RecordTest("Quick Connection and Disconnect", true, "", TestFramework::TestCategory::BASIC);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Quick Connection and Disconnect", false, e.what(), TestFramework::TestCategory::BASIC);
        }
    }

    // Run all tests
    void RunAllTests() {
        std::cout << "\n" << std::string(60, '=') << std::endl;
        std::cout << "BASIC FUNCTIONALITY TESTS" << std::endl;
        std::cout << std::string(60, '=') << std::endl;

        TestSingleConnection();
        TestEchoFunctionality();
        TestMultipleSequentialConnections();
        TestConcurrentConnections();
        TestLargeMessage();
        TestQuickDisconnect();
    }
}
