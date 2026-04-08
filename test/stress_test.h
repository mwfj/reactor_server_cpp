#pragma once
#include "test_server_runner.h"
#include "http_test_client.h"
#include "test_framework.h"
#include <cstdlib>

// Stress test namespace
namespace StressTests {

    void TestHighLoadConnections() {
        // CI runners have limited resources (3 vCPU, 7GB RAM on macos-14).
        // Use reduced client count and threshold in CI to avoid false failures
        // while still validating concurrent load handling.
        // macOS CI is particularly constrained — kqueue fd limits and shared
        // runners cause connection failures at 200 clients, so the threshold
        // is set to 85% to avoid flaky failures while still catching real
        // regressions (a broken server scores well below 50%).
        const bool is_ci = (std::getenv("CI") != nullptr);
        const int NUM_CLIENTS = is_ci ? 200 : 1000;
        const double THRESHOLD = is_ci ? 0.85 : 0.95;

        std::cout << "\n[STRESS TEST] High Load (" << NUM_CLIENTS
                  << " concurrent clients" << (is_ci ? ", CI mode" : "") << ")..." << std::endl;

        try {
            HttpServer server("127.0.0.1", 0);
            TestHttpClient::SetupEchoRoutes(server);
            TestServerRunner<HttpServer> runner(server);
            const int port = runner.GetPort();

            std::vector<std::thread> client_threads;
            std::atomic<int> success_count{0};

            for (int i = 0; i < NUM_CLIENTS; i++) {
                client_threads.emplace_back([port, &success_count]() {
                    try {
                        std::string response = TestHttpClient::HttpGet(port, "/health", 10000);
                        if (TestHttpClient::HasStatus(response, 200)) {
                            success_count++;
                        }
                    } catch (const std::exception&) {
                        // Some failures expected under high load
                    }
                });
            }

            for (auto& t : client_threads) {
                t.join();
            }

            double success_rate = static_cast<double>(success_count) / NUM_CLIENTS;
            std::cout << "[STRESS TEST] Completed " << NUM_CLIENTS << " concurrent connections, "
                      << success_count << " succeeded (" << (success_rate * 100) << "%)" << std::endl;

            bool pass = (success_rate > THRESHOLD);
            std::string error_msg = pass ? "" :
                "Only " + std::to_string(success_count.load()) + "/" + std::to_string(NUM_CLIENTS) +
                " requests succeeded (" + std::to_string(static_cast<int>(success_rate * 100)) + "%)";
            TestFramework::RecordTest("High Load Connections (" + std::to_string(NUM_CLIENTS) + " clients)",
                pass, error_msg, TestFramework::TestCategory::STRESS);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("High Load Connections (" + std::to_string(NUM_CLIENTS) + " clients)",
                false, e.what(), TestFramework::TestCategory::STRESS);
        }
    }

    void RunStressTests() {
        std::cout << "\n" << std::string(60, '=') << std::endl;
        std::cout << "STRESS TESTS" << std::endl;
        std::cout << std::string(60, '=') << std::endl;

        TestHighLoadConnections();
    }
}
