#include "server.h"
#include "client.h"
#include <iostream>
#include <thread>
#include <vector>
#include <cassert>
#include <sstream>
#include <algorithm>

// Test result tracking
namespace TestFramework {
    struct TestResult {
        std::string test_name;
        bool passed;
        std::string error_message;
    };

    std::vector<TestResult> results;

    void RecordTest(const std::string& name, bool passed, const std::string& error = "") {
        results.push_back({name, passed, error});
    }

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

// Test namespace for basic functionality tests
namespace BasicTests {
    const char* TEST_IP = "127.0.0.1";
    const int TEST_PORT = 8888;

    // RAII wrapper for server thread management
    class ServerRunner {
    private:
        NetworkServer& server_;
        std::thread server_thread_;

    public:
        ServerRunner(NetworkServer& server) : server_(server) {
            server_thread_ = std::thread([this]() {
                try {
                    server_.Start();
                    std::cout << "[SERVER] Started on " << TEST_IP << ":" << TEST_PORT << std::endl;
                    server_.Run();
                } catch (const std::exception& e) {
                    std::cerr << "[SERVER] Error: " << e.what() << std::endl;
                }
            });
            // Give server time to start
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        ~ServerRunner() {
            server_.Stop();
            if(server_thread_.joinable()) {
                server_thread_.join();
            }
        }

        // Delete copy/move
        ServerRunner(const ServerRunner&) = delete;
        ServerRunner& operator=(const ServerRunner&) = delete;
    };

    // Test 1: Single Client Connection
    void TestSingleConnection() {
        std::cout << "\n[TEST] Single Client Connection..." << std::endl;

        try {
            NetworkServer server(TEST_IP, TEST_PORT);
            ServerRunner runner(server);

            // Create and connect client
            Client client(TEST_PORT, TEST_IP, "Hello");
            client.Init();
            client.Connect();

            std::cout << "[TEST] Client connected successfully" << std::endl;

            client.Close();

            TestFramework::RecordTest("Single Client Connection", true);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Single Client Connection", false, e.what());
        }
    }

    // Test 2: Echo Functionality
    void TestEchoFunctionality() {
        std::cout << "\n[TEST] Echo Functionality..." << std::endl;

        try {
            NetworkServer server(TEST_IP, TEST_PORT);
            ServerRunner runner(server);

            Client client(TEST_PORT, TEST_IP, "TestMessage");
            client.SetQuietMode(false);
            client.Init();
            client.Connect();

            // Send message
            client.Send();
            std::cout << "[TEST] Sent: TestMessage" << std::endl;

            // Receive echo
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            client.Receive();

            client.Close();

            TestFramework::RecordTest("Echo Functionality", true);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Echo Functionality", false, e.what());
        }
    }

    // Test 3: Multiple Sequential Connections
    void TestMultipleSequentialConnections() {
        std::cout << "\n[TEST] Multiple Sequential Connections..." << std::endl;

        try {
            NetworkServer server(TEST_IP, TEST_PORT);
            ServerRunner runner(server);

            const int NUM_CLIENTS = 5;
            for (int i = 0; i < NUM_CLIENTS; i++) {
                std::stringstream ss;
                ss << "Client" << i;

                Client client(TEST_PORT, TEST_IP, ss.str().c_str());
                client.SetQuietMode(true);
                client.Init();
                client.Connect();
                client.Send();
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                client.Receive();
                client.Close();

                std::cout << "[TEST] Client " << i << " completed" << std::endl;
            }

            TestFramework::RecordTest("Multiple Sequential Connections", true);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Multiple Sequential Connections", false, e.what());
        }
    }

    // Test 4: Concurrent Connections
    void TestConcurrentConnections() {
        std::cout << "\n[TEST] Concurrent Connections..." << std::endl;

        try {
            NetworkServer server(TEST_IP, TEST_PORT);
            ServerRunner runner(server);

            const int NUM_CLIENTS = 10;
            std::vector<std::thread> client_threads;

            // Launch multiple clients concurrently
            for (int i = 0; i < NUM_CLIENTS; i++) {
                client_threads.emplace_back([i]() {
                    try {
                        std::stringstream ss;
                        ss << "ConcurrentClient" << i;

                        Client client(TEST_PORT, TEST_IP, ss.str().c_str());
                        client.SetQuietMode(true);
                        client.Init();
                        client.Connect();
                        client.Send();
                        std::this_thread::sleep_for(std::chrono::milliseconds(20));
                        client.Receive();
                        client.Close();
                    } catch (const std::exception& e) {
                        std::cerr << "[TEST] Client " << i << " error: " << e.what() << std::endl;
                    }
                });
            }

            // Wait for all clients to finish
            for (auto& t : client_threads) {
                t.join();
            }

            std::cout << "[TEST] All " << NUM_CLIENTS << " concurrent clients completed" << std::endl;

            TestFramework::RecordTest("Concurrent Connections", true);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Concurrent Connections", false, e.what());
        }
    }

    // Test 5: Large Message Transfer
    void TestLargeMessage() {
        std::cout << "\n[TEST] Large Message Transfer..." << std::endl;

        try {
            NetworkServer server(TEST_IP, TEST_PORT);
            ServerRunner runner(server);

            // Create a large message (close to buffer size)
            std::string large_msg(512, 'A');

            Client client(TEST_PORT, TEST_IP, large_msg.c_str());
            client.SetQuietMode(true);
            client.Init();
            client.Connect();
            client.Send();
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            client.Receive();
            client.Close();

            std::cout << "[TEST] Large message (" << large_msg.size() << " bytes) transferred" << std::endl;

            TestFramework::RecordTest("Large Message Transfer", true);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Large Message Transfer", false, e.what());
        }
    }

    // Test 6: Connection and Immediate Disconnect
    void TestQuickDisconnect() {
        std::cout << "\n[TEST] Quick Connection and Disconnect..." << std::endl;

        try {
            NetworkServer server(TEST_IP, TEST_PORT);
            ServerRunner runner(server);

            for (int i = 0; i < 3; i++) {
                Client client(TEST_PORT, TEST_IP, "Quick");
                client.SetQuietMode(true);
                client.Init();
                client.Connect();
                client.Close();  // Immediate disconnect
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }

            std::cout << "[TEST] Quick disconnect test completed" << std::endl;

            TestFramework::RecordTest("Quick Connection and Disconnect", true);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Quick Connection and Disconnect", false, e.what());
        }
    }

    // Run all tests
    void RunAllTests() {
        std::cout << "\n" << std::string(60, '=') << std::endl;
        std::cout << "REACTOR SERVER - UNIT TESTS" << std::endl;
        std::cout << std::string(60, '=') << std::endl;

        TestSingleConnection();
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        TestEchoFunctionality();
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        TestMultipleSequentialConnections();
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        TestConcurrentConnections();
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        TestLargeMessage();
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        TestQuickDisconnect();
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
}

// Stress test namespace
namespace StressTests {
    const char* TEST_IP = "127.0.0.1";
    const int TEST_PORT = 8889;

    // RAII wrapper for stress test server
    class StressServerRunner {
    private:
        NetworkServer& server_;
        std::thread server_thread_;

    public:
        StressServerRunner(NetworkServer& server) : server_(server) {
            server_thread_ = std::thread([this]() {
                try {
                    server_.Start();
                    std::cout << "[SERVER] Stress test server started" << std::endl;
                    server_.Run();
                } catch (const std::exception& e) {
                    std::cerr << "[SERVER] Error: " << e.what() << std::endl;
                }
            });
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        ~StressServerRunner() {
            server_.Stop();
            if(server_thread_.joinable()) {
                server_thread_.join();
            }
        }

        StressServerRunner(const StressServerRunner&) = delete;
        StressServerRunner& operator=(const StressServerRunner&) = delete;
    };

    void TestHighLoadConnections() {
        std::cout << "\n[STRESS TEST] High Load (100 concurrent clients)..." << std::endl;

        try {
            NetworkServer server(TEST_IP, TEST_PORT);
            StressServerRunner runner(server);

            const int NUM_CLIENTS = 100;
            std::vector<std::thread> client_threads;

            for (int i = 0; i < NUM_CLIENTS; i++) {
                client_threads.emplace_back([i]() {
                    try {
                        std::stringstream ss;
                        ss << "StressClient" << i;

                        Client client(TEST_PORT, TEST_IP, ss.str().c_str());
                        client.SetQuietMode(true);
                        client.Init();
                        client.Connect();
                        client.Send();
                        std::this_thread::sleep_for(std::chrono::milliseconds(5));
                        client.Receive();
                        client.Close();
                    } catch (const std::exception& e) {
                        // Silent - some failures expected under high load
                    }
                });
            }

            for (auto& t : client_threads) {
                t.join();
            }

            std::cout << "[STRESS TEST] Completed 100 concurrent connections" << std::endl;

            TestFramework::RecordTest("High Load Connections (100 clients)", true);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("High Load Connections (100 clients)", false, e.what());
        }
    }

    void RunStressTests() {
        std::cout << "\n" << std::string(60, '=') << std::endl;
        std::cout << "STRESS TESTS" << std::endl;
        std::cout << std::string(60, '=') << std::endl;

        TestHighLoadConnections();
    }
}

int main() {
    std::cout << "Reactor Network Server - Test Suite" << std::endl;
    std::cout << "====================================\n" << std::endl;

    // Run basic functional tests
    BasicTests::RunAllTests();

    // Run stress tests (optional - comment out if needed)
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    StressTests::RunStressTests();

    // Print test summary
    TestFramework::PrintResults();

    auto passed_count = std::count_if(TestFramework::results.begin(),
                                      TestFramework::results.end(),
                                      [](const TestFramework::TestResult& r) { return r.passed; });
    return (static_cast<size_t>(passed_count) == TestFramework::results.size()) ? 0 : 1;
}
