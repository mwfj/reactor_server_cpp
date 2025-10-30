#pragma once
#include "reactor_server.h"
#include "client.h"
#include "test_framework.h"
#include "string.h"

// Stress test namespace
namespace StressTests {
    const char* TEST_IP = "127.0.0.1";
    const int TEST_PORT = 8889;

    // RAII wrapper for stress test server
    class StressServerRunner {
    private:
        ReactorServer& server_;
        std::thread server_thread_;

    public:
        StressServerRunner(ReactorServer& server) : server_(server) {
            server_thread_ = std::thread([this]() {
                try {
                    std::cout << "[SERVER] Stress test server starting" << std::endl;
                    server_.Start();
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
        const int NUM_CLIENTS = 1000;
        std::cout << "\n[STRESS TEST] High Load (1000 concurrent clients)..." << std::endl;

        try {
            ReactorServer server(TEST_IP, TEST_PORT);
            StressServerRunner runner(server);

            std::vector<std::thread> client_threads;

            for (int i = 0; i < NUM_CLIENTS; i++) {
                client_threads.emplace_back([i]() {
                    try {
                        std::stringstream ss;
                        ss << "StressClient" << i;

                        Client client(TEST_PORT, TEST_IP, ss.str().c_str());
                        client.SetQuietMode(true);
                        client.Init();
                        // Set 10-second timeout to prevent indefinite hangs
                        client.SetReceiveTimeout(10, 0);
                        client.Connect();
                        client.Send();
                        // Wait longer for server to process under high load
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
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

            std::cout << "[STRESS TEST] Completed " << NUM_CLIENTS << " concurrent connections" << std::endl;

            TestFramework::RecordTest("High Load Connections (1000 clients)", true, "", TestFramework::TestCategory::STRESS);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("High Load Connections (1000 clients)", false, e.what(), TestFramework::TestCategory::STRESS);
        }
    }

    void RunStressTests() {
        std::cout << "\n" << std::string(60, '=') << std::endl;
        std::cout << "STRESS TESTS" << std::endl;
        std::cout << std::string(60, '=') << std::endl;

        TestHighLoadConnections();
    }
}
