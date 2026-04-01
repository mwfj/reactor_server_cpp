#pragma once
#include "test_framework.h"
#include "test_server_runner.h"
#include "reactor_server.h"
#include "client.h"
#include <thread>


// Test namespace for basic functionality tests
namespace BasicTests {
    const char* TEST_IP = "127.0.0.1";

    // Test 1: Single Client Connection
    void TestSingleConnection() {
        std::cout << "\n[TEST] Single Client Connection..." << std::endl;

        try {
            ReactorServer server(TEST_IP, 0);
            TestServerRunner<ReactorServer> runner(server);

            // Create and connect client
            Client client(runner.GetPort(), TEST_IP, "Hello");
            client.Init();
            client.Connect();

            std::cout << "[TEST] Client connected successfully" << std::endl;

            client.Close();

            TestFramework::RecordTest("Single Client Connection", true, "", TestFramework::TestCategory::BASIC);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Single Client Connection", false, e.what(), TestFramework::TestCategory::BASIC);
        }
    }

    // Test 2: Echo Functionality
    void TestEchoFunctionality() {
        std::cout << "\n[TEST] Echo Functionality..." << std::endl;

        try {
            ReactorServer server(TEST_IP, 0);
            TestServerRunner<ReactorServer> runner(server);

            Client client(runner.GetPort(), TEST_IP, "TestMessage");
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

            TestFramework::RecordTest("Echo Functionality", true, "", TestFramework::TestCategory::BASIC);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Echo Functionality", false, e.what(), TestFramework::TestCategory::BASIC);
        }
    }

    // Test 3: Multiple Sequential Connections
    void TestMultipleSequentialConnections() {
        std::cout << "\n[TEST] Multiple Sequential Connections..." << std::endl;

        try {
            ReactorServer server(TEST_IP, 0);
            TestServerRunner<ReactorServer> runner(server);

            const int NUM_CLIENTS = 5;
            for (int i = 0; i < NUM_CLIENTS; i++) {
                std::stringstream ss;
                ss << "Client" << i;

                Client client(runner.GetPort(), TEST_IP, ss.str().c_str());
                client.SetQuietMode(true);
                client.Init();
                client.Connect();
                client.Send();
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                client.Receive();
                client.Close();

                // Give time for server to clean up
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
            ReactorServer server(TEST_IP, 0);
            TestServerRunner<ReactorServer> runner(server);
            const int port = runner.GetPort();

            const int NUM_CLIENTS = 10;
            std::vector<std::thread> client_threads;
            std::atomic<int> success_count{0};
            std::atomic<int> failure_count{0};

            // Launch multiple clients concurrently
            for (int i = 0; i < NUM_CLIENTS; i++) {
                client_threads.emplace_back([i, port, &success_count, &failure_count]() {
                    try {
                        std::stringstream ss;
                        ss << "ConcurrentClient" << i;

                        Client client(port, TEST_IP, ss.str().c_str());
                        client.SetQuietMode(true);
                        client.Init();
                        client.SetReceiveTimeout(5);  // 5 second timeout to prevent hanging
                        client.Connect();
                        std::this_thread::sleep_for(std::chrono::milliseconds(10));  // Reduced from 100ms - acceptor now handles all connections
                        client.Send();
                        client.Receive();  // Block until response arrives (5 second timeout)
                        client.Close();
                        success_count++;  // Only increment if no exception thrown
                    } catch (const std::exception& e) {
                        std::cerr << "[TEST] Client " << i << " error: " << e.what() << std::endl;
                        failure_count++;
                    }
                });
            }

            // Wait for all clients to finish
            for (auto& t : client_threads) {
                t.join();
            }

            std::cout << "[TEST] All " << NUM_CLIENTS << " concurrent clients completed" << std::endl;
            std::cout << "[TEST] Success: " << success_count << ", Failures: " << failure_count << std::endl;

            // FIX: Test now properly tracks success/failure instead of always passing
            // Previously, exceptions were caught and logged but test always recorded as PASS
            // Now, test only passes if ALL clients successfully connect, send, and receive
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
            ReactorServer server(TEST_IP, 0);
            TestServerRunner<ReactorServer> runner(server);

            // Create a large message (close to buffer size)
            std::string large_msg(512, 'A');

            Client client(runner.GetPort(), TEST_IP, large_msg.c_str());
            client.SetQuietMode(true);
            client.Init();
            client.Connect();
            client.Send();
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            client.Receive();
            client.Close();

            std::cout << "[TEST] Large message (" << large_msg.size() << " bytes) transferred" << std::endl;

            TestFramework::RecordTest("Large Message Transfer", true, "", TestFramework::TestCategory::BASIC);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Large Message Transfer", false, e.what(), TestFramework::TestCategory::BASIC);
        }
    }

    // Test 6: Connection and Immediate Disconnect
    void TestQuickDisconnect() {
        std::cout << "\n[TEST] Quick Connection and Disconnect..." << std::endl;

        try {
            ReactorServer server(TEST_IP, 0);
            TestServerRunner<ReactorServer> runner(server);

            for (int i = 0; i < 3; i++) {
                Client client(runner.GetPort(), TEST_IP, "Quick");
                client.SetQuietMode(true);
                client.Init();
                client.Connect();
                client.Close();  // Immediate disconnect
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
        std::cout << "REACTOR SERVER - UNIT TESTS" << std::endl;
        std::cout << std::string(60, '=') << std::endl;

        TestSingleConnection();
        TestEchoFunctionality();
        TestMultipleSequentialConnections();
        TestConcurrentConnections();
        TestLargeMessage();
        TestQuickDisconnect();
    }
}