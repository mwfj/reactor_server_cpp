#pragma once

#include "test_framework.h"
#include "http_test_client.h"
#include "http/http_server.h"
#include "config/server_config.h"

#include <atomic>
#include <chrono>
#include <future>
#include <thread>

// Tests for `HttpServer::ScheduleStopAfterCurrentResponse()` — the helper
// route handlers use to terminate the server after their response leaves
// the wire. The historic Phase 1b deadlock was: a handler calls `Stop()`
// synchronously; `Stop()` enters `WaitForAllAsyncDrain` blocked on the
// in-flight transaction, which IS the calling handler still on the
// dispatcher's call stack. The helper schedules `Stop()` on
// `conn_dispatcher_` so the drain barrier engages on a non-handler thread.
namespace ObservabilitySelfHandlerTests {

namespace {

// Local mini-runner that lets the server thread join naturally after
// the helper-scheduled `Stop()` completes. TestServerRunner's destructor
// calls `Stop()` defensively, which would race the helper's own `Stop()`
// on the conn dispatcher.
struct ManualServerRunner {
    HttpServer& server;
    std::thread thread;
    int port = 0;

    explicit ManualServerRunner(HttpServer& s) : server(s) {
        auto p = std::make_shared<std::promise<int>>();
        auto f = p->get_future();
        server.SetReadyCallback([p, &s]() {
            p->set_value(s.GetBoundPort());
        });
        thread = std::thread([&s, p]() {
            try { s.Start(); }
            catch (...) {
                try { p->set_exception(std::current_exception()); }
                catch (const std::future_error&) {}
            }
        });
        if (f.wait_for(std::chrono::seconds(10)) != std::future_status::ready) {
            throw std::runtime_error(
                "ManualServerRunner: server did not become ready");
        }
        port = f.get();
    }

    ~ManualServerRunner() {
        if (thread.joinable()) {
            try { server.Stop(); } catch (...) {}
            thread.join();
        }
    }
};

}  // namespace

inline void TestStopFromHandlerDoesNotDeadlock() {
    std::cout << "\n[TEST] ScheduleStopAfterCurrentResponse: no deadlock" << std::endl;
    try {
        ServerConfig cfg;
        cfg.bind_host = "127.0.0.1";
        cfg.bind_port = 0;
        cfg.worker_threads = 1;
        cfg.http2.enabled = false;

        HttpServer server(cfg);
        server.Get("/shutdown",
            [&server](const HttpRequest&, HttpResponse& resp) {
                resp.Status(200).Body("ok", "text/plain");
                server.ScheduleStopAfterCurrentResponse();
            });

        ManualServerRunner runner(server);
        auto t0 = std::chrono::steady_clock::now();
        std::string response = TestHttpClient::HttpGet(runner.port, "/shutdown");

        runner.thread.join();
        auto elapsed = std::chrono::steady_clock::now() - t0;

        bool status_ok = TestHttpClient::HasStatus(response, 200);
        bool body_ok = TestHttpClient::ExtractBody(response) == "ok";
        bool fast_enough = elapsed < std::chrono::seconds(5);

        bool pass = status_ok && body_ok && fast_enough;
        std::string err;
        if (!status_ok) err = "expected 200, response: " + response.substr(0, 80);
        else if (!body_ok) err = "body mismatch: " + TestHttpClient::ExtractBody(response);
        else if (!fast_enough) err = "elapsed too long";

        TestFramework::RecordTest(
            "Self-handler shutdown: response delivered + server stops",
            pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "Self-handler shutdown: response delivered + server stops",
            false, e.what());
    }
}

inline void TestStopFromHandlerIdempotent() {
    std::cout << "\n[TEST] ScheduleStopAfterCurrentResponse: idempotent" << std::endl;
    try {
        ServerConfig cfg;
        cfg.bind_host = "127.0.0.1";
        cfg.bind_port = 0;
        cfg.worker_threads = 1;
        cfg.http2.enabled = false;

        HttpServer server(cfg);
        // Handler calls the helper many times — the CAS gate must collapse
        // them into a single deferred Stop(). If it didn't, multiple
        // EnQueue'd Stop() closures would fire concurrently on the conn
        // dispatcher (one shape of the legacy double-Stop bug).
        server.Get("/storm",
            [&server](const HttpRequest&, HttpResponse& resp) {
                resp.Status(200).Body("storm_ok", "text/plain");
                for (int i = 0; i < 8; ++i) {
                    server.ScheduleStopAfterCurrentResponse();
                }
            });

        ManualServerRunner runner(server);
        std::string response = TestHttpClient::HttpGet(runner.port, "/storm");
        runner.thread.join();

        bool ok = TestHttpClient::HasStatus(response, 200) &&
                  TestHttpClient::ExtractBody(response) == "storm_ok";
        TestFramework::RecordTest(
            "Self-handler shutdown: idempotent under repeated calls",
            ok, ok ? "" : "response mismatch: " + response.substr(0, 80));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "Self-handler shutdown: idempotent under repeated calls",
            false, e.what());
    }
}

inline void TestStopFromHandlerWithInflightSibling() {
    std::cout << "\n[TEST] ScheduleStopAfterCurrentResponse: drains sibling" << std::endl;
    try {
        ServerConfig cfg;
        cfg.bind_host = "127.0.0.1";
        cfg.bind_port = 0;
        cfg.worker_threads = 2;
        cfg.http2.enabled = false;

        HttpServer server(cfg);
        std::atomic<bool> slow_started{false};
        std::atomic<bool> slow_finished{false};

        server.Get("/slow",
            [&](const HttpRequest&, HttpResponse& resp) {
                slow_started.store(true);
                std::this_thread::sleep_for(std::chrono::milliseconds(150));
                slow_finished.store(true);
                resp.Status(200).Body("slow_ok", "text/plain");
            });
        server.Get("/shutdown",
            [&server](const HttpRequest&, HttpResponse& resp) {
                resp.Status(200).Body("shutdown_ok", "text/plain");
                server.ScheduleStopAfterCurrentResponse();
            });

        ManualServerRunner runner(server);
        const int port = runner.port;

        // Kick off /slow first; the handler will sleep for 150ms.
        auto slow_fut = std::async(std::launch::async, [port]() {
            return TestHttpClient::HttpGet(port, "/slow", /*timeout_ms=*/4000);
        });
        // Wait until the slow handler is actually running; then trigger shutdown.
        for (int i = 0; i < 50 && !slow_started.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        std::string shutdown_resp = TestHttpClient::HttpGet(port, "/shutdown");
        std::string slow_resp = slow_fut.get();
        runner.thread.join();

        bool shutdown_ok = TestHttpClient::HasStatus(shutdown_resp, 200) &&
                           TestHttpClient::ExtractBody(shutdown_resp) == "shutdown_ok";
        bool slow_ok = TestHttpClient::HasStatus(slow_resp, 200) &&
                       TestHttpClient::ExtractBody(slow_resp) == "slow_ok" &&
                       slow_finished.load();

        bool pass = shutdown_ok && slow_ok;
        std::string err;
        if (!shutdown_ok) err = "shutdown response failed: " + shutdown_resp.substr(0, 80);
        else if (!slow_ok) err = "slow response failed (drain incomplete): " +
                                  slow_resp.substr(0, 80);

        TestFramework::RecordTest(
            "Self-handler shutdown: drain waits for sibling in-flight request",
            pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "Self-handler shutdown: drain waits for sibling in-flight request",
            false, e.what());
    }
}

inline void RunAllTests() {
    TestStopFromHandlerDoesNotDeadlock();
    TestStopFromHandlerIdempotent();
    TestStopFromHandlerWithInflightSibling();
}

}  // namespace ObservabilitySelfHandlerTests
