#pragma once
#include "common.h"
#include "reactor_server.h"
#include "client.h"
#include "test_framework.h"
#include <thread>
#include <chrono>

// RAII helper to start/stop server in background thread
class TimeoutServerRunner {
private:
    ReactorServer& server_;
    std::thread server_thread_;

public:
    TimeoutServerRunner(ReactorServer& server) : server_(server) {
        server_thread_ = std::thread([this]() {
            server_.Start();
        });
        // Give server time to initialize
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    ~TimeoutServerRunner() {
        server_.Stop();
        if (server_thread_.joinable()) {
            server_thread_.join();
        }
    }

    // Delete copy/move
    TimeoutServerRunner(const TimeoutServerRunner&) = delete;
    TimeoutServerRunner& operator=(const TimeoutServerRunner&) = delete;
};

class TimeoutTests {
private:
    static constexpr int BASE_PORT = 10100;

public:
    static void RunAllTests() {
        std::cout << "\n============================================================" << std::endl;
        std::cout << "TIMEOUT TESTS" << std::endl;
        std::cout << "============================================================\n" << std::endl;

        TestConfigurableTimerParameters();
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        TestDefaultTimerParameters();
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        TestActiveConnectionsWork();
    }

private:
    // Test 1: Verify server accepts custom timer parameters
    static void TestConfigurableTimerParameters() {
        std::cout << "[TIMEOUT-TEST-1] Configurable Timer Parameters..." << std::endl;

        try {
            // Create server with custom timer: 5 second check, 10 second timeout
            ReactorServer server("127.0.0.1", BASE_PORT, 5, std::chrono::seconds(10));
            TimeoutServerRunner runner(server);

            // Send a few messages to verify server works with custom timer config
            for (int i = 0; i < 3; i++) {
                std::string msg = "CustomTimer" + std::to_string(i);
                Client client(BASE_PORT, "127.0.0.1", msg.c_str());
                client.SetQuietMode(true);
                client.Init();
                client.Connect();
                client.Send();
                client.Receive();
                client.Close();

                // Small delay to avoid connection reuse issues
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
            // Create server with default timer parameters (60s check, 300s timeout)
            ReactorServer server("127.0.0.1", BASE_PORT + 1);
            TimeoutServerRunner runner(server);

            // Send messages to verify default timer doesn't interfere
            for (int i = 0; i < 5; i++) {
                std::string msg = "DefaultTimer" + std::to_string(i);
                Client client(BASE_PORT + 1, "127.0.0.1", msg.c_str());
                client.SetQuietMode(true);
                client.Init();
                client.Connect();
                client.Send();
                client.Receive();
                client.Close();

                // Small delay between connections
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
            // Use moderate timer: 10 second check, 30 second timeout
            ReactorServer server("127.0.0.1", BASE_PORT + 2, 10, std::chrono::seconds(30));
            TimeoutServerRunner runner(server);

            // Send 10 sequential messages with small delays
            // This verifies timer doesn't interfere with normal operation
            for (int i = 0; i < 10; i++) {
                std::string msg = "Message" + std::to_string(i);
                Client client(BASE_PORT + 2, "127.0.0.1", msg.c_str());
                client.SetQuietMode(true);
                client.Init();
                client.Connect();
                client.Send();
                client.Receive();
                client.Close();

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
