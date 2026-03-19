#pragma once

#include "test_framework.h"
#include "http/http_parser.h"
#include "http/http_response.h"
#include "http/http_router.h"
#include "http/http_server.h"
#include <string>
#include <thread>
#include <chrono>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>

namespace HttpTests {

    const int TEST_PORT = 10201;

    // === Parser Tests ===

    void TestParseGetRequest() {
        std::cout << "\n[TEST] Parse GET Request..." << std::endl;
        try {
            HttpParser parser;
            std::string raw = "GET /hello?name=world HTTP/1.1\r\n"
                              "Host: localhost\r\n"
                              "Connection: keep-alive\r\n"
                              "\r\n";

            parser.Parse(raw.data(), raw.size());
            const auto& req = parser.GetRequest();

            bool pass = true;
            std::string err;

            if (!req.complete) { pass = false; err += "not complete; "; }
            if (req.method != "GET") { pass = false; err += "method=" + req.method + "; "; }
            if (req.path != "/hello") { pass = false; err += "path=" + req.path + "; "; }
            if (req.query != "name=world") { pass = false; err += "query=" + req.query + "; "; }
            if (req.GetHeader("host") != "localhost") { pass = false; err += "bad host header; "; }
            if (!req.keep_alive) { pass = false; err += "should be keep-alive; "; }
            if (parser.HasError()) { pass = false; err += "parser error: " + parser.GetError() + "; "; }

            TestFramework::RecordTest("Parse GET Request", pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Parse GET Request", false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    void TestParsePostRequest() {
        std::cout << "\n[TEST] Parse POST Request With Body..." << std::endl;
        try {
            HttpParser parser;
            std::string raw = "POST /api/data HTTP/1.1\r\n"
                              "Host: localhost\r\n"
                              "Content-Type: application/json\r\n"
                              "Content-Length: 13\r\n"
                              "\r\n"
                              "{\"key\":\"val\"}";

            parser.Parse(raw.data(), raw.size());
            const auto& req = parser.GetRequest();

            bool pass = true;
            std::string err;

            if (!req.complete) { pass = false; err += "not complete; "; }
            if (req.method != "POST") { pass = false; err += "method=" + req.method + "; "; }
            if (req.path != "/api/data") { pass = false; err += "path=" + req.path + "; "; }
            if (req.body != "{\"key\":\"val\"}") { pass = false; err += "body=" + req.body + "; "; }
            if (req.GetHeader("content-type") != "application/json") { pass = false; err += "bad content-type; "; }

            TestFramework::RecordTest("Parse POST Request With Body", pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Parse POST Request With Body", false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    void TestParseWebSocketUpgrade() {
        std::cout << "\n[TEST] Parse WebSocket Upgrade Request..." << std::endl;
        try {
            HttpParser parser;
            std::string raw = "GET /ws HTTP/1.1\r\n"
                              "Host: localhost\r\n"
                              "Upgrade: websocket\r\n"
                              "Connection: Upgrade\r\n"
                              "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                              "Sec-WebSocket-Version: 13\r\n"
                              "\r\n";

            parser.Parse(raw.data(), raw.size());
            const auto& req = parser.GetRequest();

            bool pass = true;
            std::string err;

            if (!req.complete) { pass = false; err += "not complete; "; }
            if (!req.upgrade) { pass = false; err += "upgrade flag not set; "; }
            if (req.GetHeader("upgrade") != "websocket") { pass = false; err += "bad upgrade header; "; }
            if (req.GetHeader("sec-websocket-key") != "dGhlIHNhbXBsZSBub25jZQ==") { pass = false; err += "bad ws key; "; }

            TestFramework::RecordTest("Parse WebSocket Upgrade Request", pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Parse WebSocket Upgrade Request", false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    void TestParseInvalidRequest() {
        std::cout << "\n[TEST] Parse Invalid Request..." << std::endl;
        try {
            HttpParser parser;
            std::string raw = "INVALID REQUEST DATA\r\n\r\n";

            parser.Parse(raw.data(), raw.size());

            bool pass = parser.HasError();
            TestFramework::RecordTest("Parse Invalid Request", pass,
                pass ? "" : "Expected parser error", TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Parse Invalid Request", false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    void TestParserReset() {
        std::cout << "\n[TEST] Parser Reset (Keep-Alive)..." << std::endl;
        try {
            HttpParser parser;

            // First request
            std::string req1 = "GET /first HTTP/1.1\r\nHost: localhost\r\n\r\n";
            parser.Parse(req1.data(), req1.size());

            bool pass = true;
            std::string err;

            if (!parser.GetRequest().complete) { pass = false; err += "req1 not complete; "; }
            if (parser.GetRequest().path != "/first") { pass = false; err += "req1 path wrong; "; }

            // Reset and parse second request
            parser.Reset();
            std::string req2 = "GET /second HTTP/1.1\r\nHost: localhost\r\n\r\n";
            parser.Parse(req2.data(), req2.size());

            if (!parser.GetRequest().complete) { pass = false; err += "req2 not complete; "; }
            if (parser.GetRequest().path != "/second") { pass = false; err += "req2 path wrong; "; }

            TestFramework::RecordTest("Parser Reset (Keep-Alive)", pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Parser Reset (Keep-Alive)", false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // === Response Tests ===

    void TestResponseSerialize() {
        std::cout << "\n[TEST] Response Serialization..." << std::endl;
        try {
            HttpResponse resp;
            resp.Status(200).Header("X-Custom", "test").Text("Hello");

            std::string wire = resp.Serialize();

            bool pass = true;
            std::string err;

            if (wire.find("HTTP/1.1 200 OK") == std::string::npos) { pass = false; err += "missing status line; "; }
            if (wire.find("Content-Type: text/plain") == std::string::npos) { pass = false; err += "missing content-type; "; }
            if (wire.find("Content-Length: 5") == std::string::npos) { pass = false; err += "missing content-length; "; }
            if (wire.find("X-Custom: test") == std::string::npos) { pass = false; err += "missing custom header; "; }
            if (wire.find("\r\n\r\nHello") == std::string::npos) { pass = false; err += "missing body; "; }

            TestFramework::RecordTest("Response Serialization", pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Response Serialization", false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    void TestResponseFactories() {
        std::cout << "\n[TEST] Response Factory Methods..." << std::endl;
        try {
            bool pass = true;
            std::string err;

            if (HttpResponse::Ok().GetStatusCode() != 200) { pass = false; err += "Ok != 200; "; }
            if (HttpResponse::NotFound().GetStatusCode() != 404) { pass = false; err += "NotFound != 404; "; }
            if (HttpResponse::BadRequest().GetStatusCode() != 400) { pass = false; err += "BadRequest != 400; "; }
            if (HttpResponse::InternalError().GetStatusCode() != 500) { pass = false; err += "InternalError != 500; "; }
            if (HttpResponse::Unauthorized().GetStatusCode() != 401) { pass = false; err += "Unauthorized != 401; "; }
            if (HttpResponse::PayloadTooLarge().GetStatusCode() != 413) { pass = false; err += "PayloadTooLarge != 413; "; }

            TestFramework::RecordTest("Response Factory Methods", pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Response Factory Methods", false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    void TestResponseJson() {
        std::cout << "\n[TEST] Response JSON Helper..." << std::endl;
        try {
            HttpResponse resp;
            resp.Status(200).Json(R"({"ok":true})");

            std::string wire = resp.Serialize();

            bool pass = true;
            std::string err;

            if (wire.find("application/json") == std::string::npos) { pass = false; err += "missing json content-type; "; }
            if (wire.find(R"({"ok":true})") == std::string::npos) { pass = false; err += "missing json body; "; }

            TestFramework::RecordTest("Response JSON Helper", pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Response JSON Helper", false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // === Router Tests ===

    void TestRouterExactMatch() {
        std::cout << "\n[TEST] Router Exact Match..." << std::endl;
        try {
            HttpRouter router;
            bool handler_called = false;

            router.Get("/health", [&](const HttpRequest& req, HttpResponse& res) {
                handler_called = true;
                res.Status(200).Json(R"({"ok":true})");
            });

            HttpRequest req;
            req.method = "GET";
            req.path = "/health";
            HttpResponse res;

            bool found = router.Dispatch(req, res);

            bool pass = found && handler_called && res.GetStatusCode() == 200;
            TestFramework::RecordTest("Router Exact Match", pass,
                pass ? "" : "route not matched or handler not called", TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Router Exact Match", false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    void TestRouterNotFound() {
        std::cout << "\n[TEST] Router 404..." << std::endl;
        try {
            HttpRouter router;
            router.Get("/health", [](const HttpRequest&, HttpResponse& res) {
                res.Status(200);
            });

            HttpRequest req;
            req.method = "GET";
            req.path = "/nonexistent";
            HttpResponse res;

            bool found = router.Dispatch(req, res);

            TestFramework::RecordTest("Router 404", !found, found ? "should not find route" : "", TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Router 404", false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    void TestRouterMethodNotAllowed() {
        std::cout << "\n[TEST] Router 405 Method Not Allowed..." << std::endl;
        try {
            HttpRouter router;
            router.Get("/data", [](const HttpRequest&, HttpResponse& res) { res.Status(200); });

            HttpRequest req;
            req.method = "POST";
            req.path = "/data";
            HttpResponse res;

            bool found = router.Dispatch(req, res);

            bool pass = found && res.GetStatusCode() == 405;
            TestFramework::RecordTest("Router 405 Method Not Allowed", pass,
                pass ? "" : "expected 405", TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Router 405 Method Not Allowed", false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    void TestRouterMiddleware() {
        std::cout << "\n[TEST] Router Middleware..." << std::endl;
        try {
            HttpRouter router;
            int mw_count = 0;

            // Middleware that increments counter
            router.Use([&](const HttpRequest&, HttpResponse&) {
                mw_count++;
                return true;  // continue
            });

            // Middleware that short-circuits for /blocked
            router.Use([&](const HttpRequest& req, HttpResponse& res) {
                if (req.path == "/blocked") {
                    res = HttpResponse::Forbidden();
                    return false;  // stop chain
                }
                mw_count++;
                return true;
            });

            router.Get("/ok", [](const HttpRequest&, HttpResponse& res) { res.Status(200); });

            // Test 1: normal request goes through both middlewares
            {
                HttpRequest req; req.method = "GET"; req.path = "/ok";
                HttpResponse res;
                router.Dispatch(req, res);
            }

            // Test 2: /blocked short-circuits at second middleware
            {
                HttpRequest req; req.method = "GET"; req.path = "/blocked";
                HttpResponse res;
                bool found = router.Dispatch(req, res);
                bool pass = found && res.GetStatusCode() == 403 && mw_count == 3;
                TestFramework::RecordTest("Router Middleware", pass,
                    pass ? "" : "middleware chain failed, mw_count=" + std::to_string(mw_count), TestFramework::TestCategory::OTHER);
            }
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Router Middleware", false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // === Integration Tests ===

    // Helper: connect, send HTTP request, read response.
    // Returns the response string. Uses poll() for reliable non-blocking I/O.
    std::string SendHttpRequest(int port, const std::string& request) {
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) return "";

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");

        if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(sockfd);
            return "";
        }

        // Send the request
        ssize_t sent = send(sockfd, request.data(), request.size(), 0);
        if (sent < 0) {
            close(sockfd);
            return "";
        }

        // Wait for response using poll() - more reliable than SO_RCVTIMEO
        struct pollfd pfd;
        pfd.fd = sockfd;
        pfd.events = POLLIN;

        std::string response;
        char buf[4096];

        // Poll with 3 second total timeout, reading as data becomes available
        int timeout_ms = 3000;
        auto start = std::chrono::steady_clock::now();

        while (true) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();
            int remaining = timeout_ms - static_cast<int>(elapsed);
            if (remaining <= 0) break;

            int ret = poll(&pfd, 1, remaining);
            if (ret > 0 && (pfd.revents & POLLIN)) {
                ssize_t n = recv(sockfd, buf, sizeof(buf) - 1, 0);
                if (n > 0) {
                    response.append(buf, n);
                    // Check if we have a complete HTTP response
                    if (response.find("\r\n\r\n") != std::string::npos) {
                        break;  // Got headers, good enough
                    }
                } else {
                    break;  // Connection closed or error
                }
            } else if (ret == 0) {
                break;  // Timeout
            } else {
                break;  // Error
            }
        }
        close(sockfd);
        return response;
    }

    void TestHttpIntegration() {
        std::cout << "\n[TEST] HTTP Integration (Full Request/Response Cycle)..." << std::endl;
        try {
            HttpServer server("127.0.0.1", TEST_PORT);

            server.Get("/health", [](const HttpRequest& req, HttpResponse& res) {
                res.Status(200).Json(R"({"status":"ok"})");
            });

            server.Post("/echo", [](const HttpRequest& req, HttpResponse& res) {
                res.Status(200).Body(req.body, "text/plain");
            });

            // Start server in background thread
            std::thread server_thread([&server]() {
                try { server.Start(); } catch (...) {}
            });
            // Give server time to start up (thread pool + dispatchers)
            std::this_thread::sleep_for(std::chrono::milliseconds(500));

            bool pass = true;
            std::string err;

            // Use separate connections for each test with sufficient delay
            // to avoid fd-reuse races in the reactor's multi-threaded architecture

            // Test 1: GET /health
            {
                std::string response = SendHttpRequest(TEST_PORT,
                    "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");

                if (response.find("200 OK") == std::string::npos) {
                    pass = false; err += "GET /health: missing 200 OK (got " + std::to_string(response.size()) + " bytes); ";
                }
                if (response.find(R"({"status":"ok"})") == std::string::npos) {
                    pass = false; err += "GET /health: missing JSON body; ";
                }
            }

            // Wait for server to fully process the close of the previous connection
            std::this_thread::sleep_for(std::chrono::milliseconds(200));

            // Test 2: POST /echo with body
            {
                std::string body = "Hello World";
                std::string response = SendHttpRequest(TEST_PORT,
                    "POST /echo HTTP/1.1\r\n"
                    "Host: localhost\r\n"
                    "Content-Length: " + std::to_string(body.size()) + "\r\n"
                    "Connection: close\r\n"
                    "\r\n" + body);

                if (response.find("Hello World") == std::string::npos) {
                    pass = false; err += "POST /echo: missing echoed body (got " + std::to_string(response.size()) + " bytes); ";
                }
            }

            // Wait for server to fully process the close of the previous connection
            std::this_thread::sleep_for(std::chrono::milliseconds(200));

            // Test 3: 404 for unknown path
            {
                std::string response = SendHttpRequest(TEST_PORT,
                    "GET /unknown HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");

                if (response.find("404") == std::string::npos) {
                    pass = false; err += "GET /unknown: expected 404 (got " + std::to_string(response.size()) + " bytes); ";
                }
            }

            server.Stop();
            if (server_thread.joinable()) server_thread.join();

            TestFramework::RecordTest("HTTP Integration", pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("HTTP Integration", false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // Run all HTTP tests
    void RunAllTests() {
        std::cout << "\n" << std::string(60, '=') << std::endl;
        std::cout << "HTTP LAYER - UNIT TESTS" << std::endl;
        std::cout << std::string(60, '=') << std::endl;

        // Parser tests
        TestParseGetRequest();
        TestParsePostRequest();
        TestParseWebSocketUpgrade();
        TestParseInvalidRequest();
        TestParserReset();

        // Response tests
        TestResponseSerialize();
        TestResponseFactories();
        TestResponseJson();

        // Router tests
        TestRouterExactMatch();
        TestRouterNotFound();
        TestRouterMethodNotAllowed();
        TestRouterMiddleware();

        // Integration tests
        TestHttpIntegration();
    }

}  // namespace HttpTests
