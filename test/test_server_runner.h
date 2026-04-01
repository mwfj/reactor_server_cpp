#pragma once

#include "common.h"
#include <thread>
#include <future>
#include <stdexcept>

// RAII wrapper that starts a server in a background thread, waits for the
// ready callback (no sleep), and provides the OS-assigned bound port.
//
// Works with both ReactorServer and HttpServer — any type that exposes:
//   void SetReadyCallback(std::function<void()>)
//   int  GetBoundPort() const
//   void Start()       // blocks in event loop
//   void Stop()
//
// Usage:
//   ReactorServer server("127.0.0.1", 0);     // ephemeral port
//   TestServerRunner<ReactorServer> runner(server);
//   int port = runner.GetPort();
//   // ... test with port ...
//   // ~TestServerRunner calls Stop() + join

template<typename ServerType>
class TestServerRunner {
public:
    TestServerRunner(const TestServerRunner&) = delete;
    TestServerRunner& operator=(const TestServerRunner&) = delete;
    TestServerRunner(TestServerRunner&&) = delete;
    TestServerRunner& operator=(TestServerRunner&&) = delete;

    explicit TestServerRunner(ServerType& server) : server_(server), bound_port_(0) {
        auto shared_promise = std::make_shared<std::promise<int>>();
        auto port_future = shared_promise->get_future();

        // Ready callback fires on the server thread after bind+listen,
        // before the blocking event loop. Sets the promise with the bound port.
        server_.SetReadyCallback([shared_promise, &server]() {
            shared_promise->set_value(server.GetBoundPort());
        });

        // Start server in background. On failure, propagate the exception
        // through the promise so the test thread gets the real error
        // immediately instead of waiting for a timeout.
        server_thread_ = std::thread([&server, shared_promise]() {
            try {
                server.Start();
            } catch (...) {
                // Unblock the test thread with the real error.
                // If the ready callback already set the value (server started
                // but threw later during the event loop), the promise is
                // already satisfied — set_exception throws future_error.
                try {
                    shared_promise->set_exception(std::current_exception());
                } catch (const std::future_error&) {
                    // Promise already satisfied — ignore.
                }
            }
        });

        // Block until ready callback or startup exception.
        // 10-second timeout is a safety net for hangs only — normal startup
        // failures propagate immediately via set_exception.
        auto status = port_future.wait_for(std::chrono::seconds(10));
        if (status == std::future_status::timeout) {
            Cleanup();
            throw std::runtime_error(
                "TestServerRunner: server did not become ready within 10 seconds");
        }

        // future.get() either returns the port or rethrows the server exception.
        try {
            bound_port_ = port_future.get();
        } catch (...) {
            Cleanup();
            throw;
        }

        // Validate the port is usable.
        if (bound_port_ <= 0) {
            Cleanup();
            throw std::runtime_error(
                "TestServerRunner: GetBoundPort() returned " +
                std::to_string(bound_port_) +
                " (getsockname failed or bind did not resolve ephemeral port)");
        }
    }

    ~TestServerRunner() {
        Cleanup();
    }

    int GetPort() const { return bound_port_; }

private:
    ServerType& server_;
    std::thread server_thread_;
    int bound_port_;

    void Cleanup() {
        try { server_.Stop(); } catch (...) {}
        if (server_thread_.joinable()) {
            server_thread_.join();
        }
    }
};
