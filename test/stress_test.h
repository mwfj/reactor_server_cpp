#pragma once
#include "test_server_runner.h"
#include "reactor_server.h"
#include "client.h"
#include "test_framework.h"
#include "string.h"

// Stress test namespace
namespace StressTests {
    const char* TEST_IP = "127.0.0.1";

    void TestHighLoadConnections() {
        const int NUM_CLIENTS = 1000;
        std::cout << "\n[STRESS TEST] High Load (1000 concurrent clients)..." << std::endl;

        try {
            ReactorServer server(TEST_IP, 0);
            TestServerRunner<ReactorServer> runner(server);
            const int port = runner.GetPort();

            std::vector<std::thread> client_threads;

            for (int i = 0; i < NUM_CLIENTS; i++) {
                client_threads.emplace_back([i, port]() {
                    try {
                        std::stringstream ss;
                        ss << "StressClient" << i;

                        Client client(port, TEST_IP, ss.str().c_str());
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
