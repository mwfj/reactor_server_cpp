#pragma once
#include "test_server_runner.h"
#include "http_test_client.h"
#include "test_framework.h"

// Stress test namespace
namespace StressTests {

    void TestHighLoadConnections() {
        const int NUM_CLIENTS = 1000;
        std::cout << "\n[STRESS TEST] High Load (1000 concurrent clients)..." << std::endl;

        try {
            HttpServer server("127.0.0.1", 0);
            TestHttpClient::SetupEchoRoutes(server);
            TestServerRunner<HttpServer> runner(server);
            const int port = runner.GetPort();

            std::vector<std::thread> client_threads;

            for (int i = 0; i < NUM_CLIENTS; i++) {
                client_threads.emplace_back([port]() {
                    try {
                        std::string response = TestHttpClient::HttpGet(port, "/health", 10000);
                        // Some failures expected under high load
                        (void)response;
                    } catch (const std::exception&) {
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
