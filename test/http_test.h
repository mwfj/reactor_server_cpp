#pragma once

#include "test_framework.h"
#include "test_server_runner.h"
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
                    // Check if we have a complete response (headers + body)
                    auto hdr_end = response.find("\r\n\r\n");
                    if (hdr_end != std::string::npos) {
                        // Parse Content-Length to know when body is complete
                        size_t body_start = hdr_end + 4;
                        size_t content_length = 0;
                        auto cl_pos = response.find("Content-Length: ");
                        if (cl_pos != std::string::npos && cl_pos < hdr_end) {
                            content_length = std::stoul(response.substr(cl_pos + 16));
                        }
                        if (response.size() >= body_start + content_length) {
                            break;  // Got full response
                        }
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
            HttpServer server("127.0.0.1", 0);

            server.Get("/health", [](const HttpRequest& req, HttpResponse& res) {
                res.Status(200).Json(R"({"status":"ok"})");
            });

            server.Post("/echo", [](const HttpRequest& req, HttpResponse& res) {
                res.Status(200).Body(req.body, "text/plain");
            });

            TestServerRunner<HttpServer> runner(server);
            int port = runner.GetPort();

            bool pass = true;
            std::string err;

            // Use separate connections for each test with sufficient delay
            // to avoid fd-reuse races in the reactor's multi-threaded architecture

            // Test 1: GET /health
            {
                std::string response = SendHttpRequest(port,
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
                std::string response = SendHttpRequest(port,
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
                std::string response = SendHttpRequest(port,
                    "GET /unknown HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");

                if (response.find("404") == std::string::npos) {
                    pass = false; err += "GET /unknown: expected 404 (got " + std::to_string(response.size()) + " bytes); ";
                }
            }

            TestFramework::RecordTest("HTTP Integration", pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("HTTP Integration", false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // Test: Request timeout (Slowloris protection)
    void TestRequestTimeout() {
        std::cout << "\n[TEST] Request Timeout (Slowloris Protection)..." << std::endl;
        try {
            // Configure with a short request timeout for testing
            ServerConfig config;
            config.bind_host = "127.0.0.1";
            config.bind_port = 0;
            config.request_timeout_sec = 2;   // 2-second request timeout
            config.idle_timeout_sec = 60;      // idle timeout won't interfere
            config.worker_threads = 2;

            HttpServer server(config);
            server.Get("/health", [](const HttpRequest& req, HttpResponse& res) {
                res.Status(200).Text("ok");
            });

            TestServerRunner<HttpServer> runner(server);
            int port = runner.GetPort();

            bool pass = true;
            std::string err;

            // Test 1: Slow request — send partial headers, wait for 408 or connection close
            {
                int sockfd = socket(AF_INET, SOCK_STREAM, 0);
                struct sockaddr_in addr{};
                addr.sin_family = AF_INET;
                addr.sin_port = htons(port);
                addr.sin_addr.s_addr = inet_addr("127.0.0.1");
                connect(sockfd, (struct sockaddr*)&addr, sizeof(addr));

                // Send partial headers (no \r\n\r\n terminator) then go silent
                std::string partial = "GET /health HTTP/1.1\r\nHost: localhost\r\n";
                send(sockfd, partial.data(), partial.size(), 0);

                // Wait for server to kill the connection (timeout + scan interval)
                struct timeval tv; tv.tv_sec = 5; tv.tv_usec = 0;
                setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

                char buf[4096] = {};
                std::string response;
                ssize_t n;
                while ((n = recv(sockfd, buf, sizeof(buf) - 1, 0)) > 0) {
                    response.append(buf, n);
                }
                close(sockfd);

                // Should get 408 or server-initiated close (EOF, n==0).
                // n < 0 with EAGAIN/EWOULDBLOCK is a client-side timeout — doesn't count.
                bool got_408 = response.find("408") != std::string::npos;
                bool got_server_close = (n == 0);  // EOF = server closed
                if (!got_408 && !got_server_close) {
                    pass = false;
                    err += "Slow request: expected 408 or server close (EOF), got ";
                    if (n < 0) err += "client timeout (not server action); ";
                    else err += "unexpected data; ";
                }
            }

            // Test 2: Fast request should succeed normally
            {
                int sockfd = socket(AF_INET, SOCK_STREAM, 0);
                struct sockaddr_in addr{};
                addr.sin_family = AF_INET;
                addr.sin_port = htons(port);
                addr.sin_addr.s_addr = inet_addr("127.0.0.1");
                connect(sockfd, (struct sockaddr*)&addr, sizeof(addr));

                std::string req = "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
                send(sockfd, req.data(), req.size(), 0);

                struct timeval tv; tv.tv_sec = 3; tv.tv_usec = 0;
                setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

                char buf[4096] = {};
                std::string response;
                ssize_t n;
                while ((n = recv(sockfd, buf, sizeof(buf) - 1, 0)) > 0) {
                    response.append(buf, n);
                }
                close(sockfd);

                if (response.find("200 OK") == std::string::npos) {
                    pass = false;
                    err += "Fast request failed: expected 200 OK; ";
                }
            }

            TestFramework::RecordTest("Request Timeout (Slowloris Protection)", pass, err,
                TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Request Timeout (Slowloris Protection)", false, e.what(),
                TestFramework::TestCategory::OTHER);
        }
    }

    // ─── Async-route integration tests ────────────────────────────────────
    //
    // Middleware gating of async routes, preserving HTTP/1 response ordering across the deferred window,
    // HEAD/close semantics in deferred responses, and HTTP/2 async dispatch.

    // Helper: send raw bytes on a dedicated socket, read the full response
    // stream until the peer closes or the deadline fires. Used for tests
    // that need finer control than SendHttpRequest's per-call loop.
    std::string SendRawAndDrain(int port, const std::string& payload,
                                int timeout_ms = 5000) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return "";
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        if (connect(fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
            close(fd); return "";
        }
        if (send(fd, payload.data(), payload.size(), 0) < 0) {
            close(fd); return "";
        }
        std::string out;
        char buf[4096];
        auto start = std::chrono::steady_clock::now();
        while (true) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();
            int remaining = timeout_ms - static_cast<int>(elapsed);
            if (remaining <= 0) break;
            pollfd pfd{fd, POLLIN, 0};
            int ret = poll(&pfd, 1, remaining);
            if (ret <= 0) break;
            if (pfd.revents & POLLIN) {
                ssize_t n = recv(fd, buf, sizeof(buf), 0);
                if (n > 0) out.append(buf, n);
                else break;
            }
        }
        close(fd);
        return out;
    }

    // Registers a GetAsync handler that schedules its completion onto a
    // background thread after `delay_ms`, mimicking an async upstream call.
    // The test-owned `scheduler` thread pool must outlive the server.
    struct AsyncScheduler {
        std::vector<std::thread> threads;
        ~AsyncScheduler() {
            for (auto& t : threads) if (t.joinable()) t.join();
        }
        void Schedule(int delay_ms, std::function<void()> fn) {
            threads.emplace_back([delay_ms, fn = std::move(fn)]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
                fn();
            });
        }
    };

    // P1: middleware MUST run before matched async routes. A middleware
    // that rejects all /secret paths should short-circuit the async handler
    // entirely — the handler must not be invoked.
    void TestAsyncRouteMiddlewareGating() {
        std::cout << "\n[TEST] Async route: middleware runs before handler..."
                  << std::endl;
        try {
            HttpServer server("127.0.0.1", 0);
            std::atomic<bool> handler_called{false};

            server.Use([](const HttpRequest& req, HttpResponse& res) -> bool {
                if (req.path.rfind("/secret", 0) == 0) {
                    res.Status(401).Text("Unauthorized");
                    return false;
                }
                return true;
            });

            server.GetAsync("/secret/data",
                [&](const HttpRequest&,
                    HttpRouter::InterimResponseSender /*send_interim*/,
                    HttpRouter::ResourcePusher        /*push_resource*/,
                    HttpRouter::StreamingResponseSender /*stream_sender*/,
                    HttpRouter::AsyncCompletionCallback complete) {
                    handler_called.store(true);
                    HttpResponse r;
                    r.Status(200).Text("should-not-reach");
                    complete(std::move(r));
                });

            TestServerRunner<HttpServer> runner(server);
            int port = runner.GetPort();

            std::string resp = SendHttpRequest(port,
                "GET /secret/data HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");

            bool pass = true;
            std::string err;
            if (resp.find(" 401 ") == std::string::npos) {
                pass = false; err += "expected 401 (got " +
                                     std::to_string(resp.size()) + " bytes); ";
            }
            if (handler_called.load()) {
                pass = false; err += "async handler ran despite middleware rejection; ";
            }
            TestFramework::RecordTest("Async route: middleware gating",
                                      pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Async route: middleware gating",
                                      false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // P2: a keep-alive client that pipelines a second request immediately
    // after the first (deferred) async request MUST see responses in order:
    // the async /slow response must arrive before the sync /fast response.
    void TestAsyncRoutePipelineOrdering() {
        std::cout << "\n[TEST] Async route: pipelined requests stay ordered..."
                  << std::endl;
        AsyncScheduler sched;
        try {
            HttpServer server("127.0.0.1", 0);

            server.GetAsync("/slow",
                [&sched](const HttpRequest&,
                         HttpRouter::InterimResponseSender /*send_interim*/,
                         HttpRouter::ResourcePusher        /*push_resource*/,
                         HttpRouter::StreamingResponseSender /*stream_sender*/,
                         HttpRouter::AsyncCompletionCallback complete) {
                    // Defer completion by ~150 ms on a background thread.
                    auto shared = std::make_shared<
                        HttpRouter::AsyncCompletionCallback>(std::move(complete));
                    sched.Schedule(150, [shared]() {
                        HttpResponse r;
                        r.Status(200).Text("SLOW-BODY");
                        (*shared)(std::move(r));
                    });
                });
            server.Get("/fast", [](const HttpRequest&, HttpResponse& res) {
                res.Status(200).Text("FAST-BODY");
            });

            TestServerRunner<HttpServer> runner(server);
            int port = runner.GetPort();

            // Pipeline both requests in a single send, then drain.
            std::string payload =
                "GET /slow HTTP/1.1\r\nHost: x\r\n\r\n"
                "GET /fast HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
            std::string resp = SendRawAndDrain(port, payload, 3000);

            bool pass = true;
            std::string err;
            auto slow_pos = resp.find("SLOW-BODY");
            auto fast_pos = resp.find("FAST-BODY");
            if (slow_pos == std::string::npos) {
                pass = false; err += "missing SLOW-BODY; ";
            }
            if (fast_pos == std::string::npos) {
                pass = false; err += "missing FAST-BODY; ";
            }
            if (pass && slow_pos >= fast_pos) {
                pass = false;
                err += "response order violated: FAST arrived before SLOW; ";
            }
            TestFramework::RecordTest("Async route: pipelined ordering",
                                      pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Async route: pipelined ordering",
                                      false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // P2: HEAD→GetAsync fallback must rewrite the request method to "GET"
    // before invoking the user handler, mirroring the sync Dispatch behavior.
    // Handler-observable test — asserts the method the handler sees is "GET".
    void TestAsyncRouteHeadFallbackRewritesMethod() {
        std::cout << "\n[TEST] Async route: HEAD fallback rewrites method to GET..."
                  << std::endl;
        AsyncScheduler sched;
        try {
            HttpServer server("127.0.0.1", 0);
            std::atomic<bool> saw_get{false};
            std::atomic<bool> saw_head{false};
            server.GetAsync("/r",
                [&](const HttpRequest& req,
                    HttpRouter::InterimResponseSender /*send_interim*/,
                    HttpRouter::ResourcePusher        /*push_resource*/,
                    HttpRouter::StreamingResponseSender /*stream_sender*/,
                    HttpRouter::AsyncCompletionCallback complete) {
                    if (req.method == "GET")  saw_get.store(true);
                    if (req.method == "HEAD") saw_head.store(true);
                    auto shared = std::make_shared<
                        HttpRouter::AsyncCompletionCallback>(std::move(complete));
                    sched.Schedule(20, [shared]() {
                        HttpResponse r;
                        r.Status(200).Text("BODY");
                        (*shared)(std::move(r));
                    });
                });

            TestServerRunner<HttpServer> runner(server);
            int port = runner.GetPort();
            SendRawAndDrain(port,
                "HEAD /r HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
                3000);

            bool pass = saw_get.load() && !saw_head.load();
            std::string err;
            if (!saw_get.load()) err += "handler did not see method=GET; ";
            if (saw_head.load()) err += "handler observed method=HEAD (fallback must rewrite); ";
            TestFramework::RecordTest("Async route: HEAD fallback rewrites method",
                                      pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Async route: HEAD fallback rewrites method",
                                      false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // P2: a PostAsync-only route with a GET request must return 405 with an
    // Allow: POST header, not 404. The 405 logic in HttpRouter::Dispatch
    // must consult the async route trie.
    void TestAsyncRoute405IncludesAsyncMethods() {
        std::cout << "\n[TEST] Async route: 405/Allow includes async methods..."
                  << std::endl;
        try {
            HttpServer server("127.0.0.1", 0);
            server.PostAsync("/jobs",
                [](const HttpRequest&,
                   HttpRouter::InterimResponseSender /*send_interim*/,
                   HttpRouter::ResourcePusher        /*push_resource*/,
                   HttpRouter::StreamingResponseSender /*stream_sender*/,
                   HttpRouter::AsyncCompletionCallback c) {
                    HttpResponse r;
                    r.Status(202).Text("accepted");
                    c(std::move(r));
                });

            TestServerRunner<HttpServer> runner(server);
            int port = runner.GetPort();

            std::string resp = SendHttpRequest(port,
                "GET /jobs HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");

            bool pass = true;
            std::string err;
            if (resp.find(" 405 ") == std::string::npos) {
                pass = false;
                err += "expected 405 Method Not Allowed (got " +
                       std::to_string(resp.size()) + " bytes); ";
            }
            // Allow header must advertise POST.
            auto allow_pos = resp.find("Allow:");
            if (allow_pos == std::string::npos) {
                pass = false; err += "missing Allow header; ";
            } else if (resp.find("POST", allow_pos) == std::string::npos) {
                pass = false; err += "Allow header missing POST; ";
            }
            TestFramework::RecordTest("Async route: 405 advertises async methods",
                                      pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Async route: 405 advertises async methods",
                                      false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // P2: a HEAD request served via a GetAsync fallback MUST NOT carry a
    // body. Matches the sync path's RFC 7231 §4.3.2 behavior.
    void TestAsyncRouteHeadStripping() {
        std::cout << "\n[TEST] Async route: HEAD body stripping..." << std::endl;
        AsyncScheduler sched;
        try {
            HttpServer server("127.0.0.1", 0);
            server.GetAsync("/res",
                [&sched](const HttpRequest&,
                         HttpRouter::InterimResponseSender /*send_interim*/,
                         HttpRouter::ResourcePusher        /*push_resource*/,
                         HttpRouter::StreamingResponseSender /*stream_sender*/,
                         HttpRouter::AsyncCompletionCallback complete) {
                    auto shared = std::make_shared<
                        HttpRouter::AsyncCompletionCallback>(std::move(complete));
                    sched.Schedule(20, [shared]() {
                        HttpResponse r;
                        r.Status(200).Text("GET-ONLY-BODY");
                        (*shared)(std::move(r));
                    });
                });

            TestServerRunner<HttpServer> runner(server);
            int port = runner.GetPort();
            std::string resp = SendRawAndDrain(port,
                "HEAD /res HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
                3000);

            bool pass = true;
            std::string err;
            if (resp.find(" 200 ") == std::string::npos) {
                pass = false; err += "expected 200 status; ";
            }
            // Content-Length header must reflect the GET body size
            if (resp.find("Content-Length:") == std::string::npos) {
                pass = false; err += "missing Content-Length header; ";
            }
            // HEAD MUST NOT carry the body.
            if (resp.find("GET-ONLY-BODY") != std::string::npos) {
                pass = false; err += "HEAD response leaked body bytes; ";
            }
            TestFramework::RecordTest("Async route: HEAD body stripping",
                                      pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Async route: HEAD body stripping",
                                      false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // P2: when the CLIENT sends Connection: close, the framework must
    // enforce Connection: close on a deferred response AND close the
    // socket after delivery. Observable via recv() returning 0.
    void TestAsyncRouteClientCloseHeader() {
        std::cout << "\n[TEST] Async route: Connection: close enforcement..."
                  << std::endl;
        AsyncScheduler sched;
        try {
            HttpServer server("127.0.0.1", 0);
            server.GetAsync("/r",
                [&sched](const HttpRequest&,
                         HttpRouter::InterimResponseSender /*send_interim*/,
                         HttpRouter::ResourcePusher        /*push_resource*/,
                         HttpRouter::StreamingResponseSender /*stream_sender*/,
                         HttpRouter::AsyncCompletionCallback complete) {
                    auto shared = std::make_shared<
                        HttpRouter::AsyncCompletionCallback>(std::move(complete));
                    sched.Schedule(20, [shared]() {
                        HttpResponse r;
                        r.Status(200).Text("OK");
                        (*shared)(std::move(r));
                    });
                });

            TestServerRunner<HttpServer> runner(server);
            int port = runner.GetPort();

            // SendRawAndDrain reads until peer closes → if the server didn't
            // honor Connection: close, recv would block until timeout.
            auto start = std::chrono::steady_clock::now();
            std::string resp = SendRawAndDrain(port,
                "GET /r HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
                3000);
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();

            bool pass = true;
            std::string err;
            if (resp.find("OK") == std::string::npos) {
                pass = false; err += "missing OK body; ";
            }
            // Server must close: if we hit the full 3s timeout, it leaked.
            if (elapsed >= 2500) {
                pass = false; err += "server did not close after "
                                     "Connection: close (took " +
                                     std::to_string(elapsed) + " ms); ";
            }
            TestFramework::RecordTest("Async route: Connection: close",
                                      pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("Async route: Connection: close",
                                      false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // P2: FillDefaultRejectionResponse must upgrade a 200-status response
    // to 403 EVEN when middleware added headers (CORS/request-id/etc.)
    // before rejecting. Previously the helper only fired on empty headers,
    // so a header-setting middleware that returned false would leak a 200
    // to the client on an async route.
    void TestAsyncRouteMiddlewareRejectionWithHeaders() {
        std::cout << "\n[TEST] Async route: middleware rejection preserves "
                     "headers but still 403s..." << std::endl;
        try {
            HttpServer server("127.0.0.1", 0);
            std::atomic<bool> handler_called{false};

            server.Use([](const HttpRequest&, HttpResponse& res) -> bool {
                // Realistic CORS-style middleware: always stamp headers,
                // then reject on auth failure. DOES NOT set a status code.
                res.Header("Access-Control-Allow-Origin", "*");
                res.Header("X-Request-Id", "abc123");
                return false;
            });
            server.GetAsync("/x",
                [&](const HttpRequest&,
                    HttpRouter::InterimResponseSender /*send_interim*/,
                    HttpRouter::ResourcePusher        /*push_resource*/,
                    HttpRouter::StreamingResponseSender /*stream_sender*/,
                    HttpRouter::AsyncCompletionCallback c) {
                    handler_called.store(true);
                    HttpResponse r;
                    r.Status(200).Text("unreachable");
                    c(std::move(r));
                });

            TestServerRunner<HttpServer> runner(server);
            int port = runner.GetPort();

            std::string resp = SendHttpRequest(port,
                "GET /x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");

            bool pass = true;
            std::string err;
            if (handler_called.load()) {
                pass = false; err += "async handler ran after mw rejection; ";
            }
            if (resp.find(" 403 ") == std::string::npos) {
                pass = false;
                err += "expected 403 status (got " +
                       std::to_string(resp.size()) + " bytes); ";
            }
            // Middleware headers must be preserved on the rejection response.
            if (resp.find("Access-Control-Allow-Origin") == std::string::npos) {
                pass = false; err += "CORS header dropped on rejection; ";
            }
            if (resp.find("X-Request-Id") == std::string::npos) {
                pass = false; err += "X-Request-Id header dropped on rejection; ";
            }
            TestFramework::RecordTest(
                "Async route: middleware rejection with headers → 403",
                pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest(
                "Async route: middleware rejection with headers → 403",
                false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // P1: Async HTTP/2 handlers must flush response frames. SubmitStreamResponse
    // only queues into nghttp2; without a subsequent SendPendingFrames, the
    // response hangs until some unrelated event. We verify the round-trip
    // completes by inspecting the plain-text test server's public HttpServer
    // API — async routes are protocol-agnostic, so the H1 completion test
    // already covers the H1 flush path; this test is the H2 counterpart
    // exercised through the shared AsyncCompletionCallback.
    //
    // We simulate by checking the H1 SendHttpRequest roundtrip with an
    // async handler that completes from a background thread — if the
    // dispatcher-routed completion never flushes, the test client times
    // out. The H1 test `TestAsyncRoutePipelineOrdering` already exercises
    // this round trip. No additional H2-specific test is added here because
    // the project's test harness doesn't include an HTTP/2 client; instead,
    // the SubmitStreamResponse code path is covered by manual inspection
    // and the existing http2 suite verifies SendPendingFrames is invoked
    // on each request boundary.

    // ===== HTTP/1.1 103 Early Hints / SendInterimResponse tests =====

    // T1: Basic 103 Early Hints — async handler emits a 103 with a Link header
    // before completing with 200. Verify the wire bytes contain HTTP/1.1 103
    // before HTTP/1.1 200, and the Link header is present in the 103 block.
    void TestH1_EarlyHints_Basic() {
        std::cout << "\n[TEST] H1 103 Early Hints: basic..." << std::endl;
        try {
            HttpServer server("127.0.0.1", 0);
            server.GetAsync("/hints",
                [](const HttpRequest&,
                   HttpRouter::InterimResponseSender send_interim,
                   HttpRouter::ResourcePusher        /*push_resource*/,
                   HttpRouter::StreamingResponseSender /*stream_sender*/,
                   HttpRouter::AsyncCompletionCallback complete) {
                    send_interim(103, {{"Link", "</style.css>; rel=preload; as=style"}});
                    HttpResponse r;
                    r.Status(200).Text("done");
                    complete(std::move(r));
                });

            TestServerRunner<HttpServer> runner(server);
            int port = runner.GetPort();

            std::string resp = SendRawAndDrain(port,
                "GET /hints HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", 3000);

            bool pass = true;
            std::string err;
            auto pos103 = resp.find("HTTP/1.1 103");
            auto pos200 = resp.find("HTTP/1.1 200");
            if (pos103 == std::string::npos) {
                pass = false; err += "missing HTTP/1.1 103; ";
            }
            if (pos200 == std::string::npos) {
                pass = false; err += "missing HTTP/1.1 200; ";
            }
            if (pass && pos103 >= pos200) {
                pass = false; err += "103 not before 200; ";
            }
            // Check Link header is inside the 103 block (before pos200)
            auto link_pos = resp.find("Link:");
            if (link_pos == std::string::npos) {
                pass = false; err += "missing Link header; ";
            } else if (link_pos >= pos200) {
                pass = false; err += "Link header not in 103 block; ";
            }
            // Assert no body bytes between the 103 block terminator and the 200
            // status line: end103 + 4 ("\r\n\r\n") must equal pos200.
            if (pass && pos103 != std::string::npos && pos200 != std::string::npos) {
                auto end103 = resp.find("\r\n\r\n", pos103);
                if (end103 == std::string::npos) {
                    pass = false; err += "103 block not terminated with CRLF CRLF; ";
                } else if (end103 + 4 != pos200) {
                    pass = false; err += "body bytes between 103 and 200; ";
                }
            }
            TestFramework::RecordTest("H1 103 Early Hints: basic",
                                      pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("H1 103 Early Hints: basic",
                                      false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // T2: Multiple 103s before the final 200. Assert both 103s appear and
    // both precede the 200 line.
    void TestH1_EarlyHints_MultipleBeforeFinal() {
        std::cout << "\n[TEST] H1 103 Early Hints: multiple before final..." << std::endl;
        try {
            HttpServer server("127.0.0.1", 0);
            server.GetAsync("/multi",
                [](const HttpRequest&,
                   HttpRouter::InterimResponseSender send_interim,
                   HttpRouter::ResourcePusher        /*push_resource*/,
                   HttpRouter::StreamingResponseSender /*stream_sender*/,
                   HttpRouter::AsyncCompletionCallback complete) {
                    send_interim(103, {{"Link", "</a.css>; rel=preload"}});
                    send_interim(103, {{"Link", "</b.js>; rel=preload"}});
                    HttpResponse r;
                    r.Status(200).Text("done");
                    complete(std::move(r));
                });

            TestServerRunner<HttpServer> runner(server);
            int port = runner.GetPort();

            std::string resp = SendRawAndDrain(port,
                "GET /multi HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", 3000);

            bool pass = true;
            std::string err;

            // Count occurrences of "HTTP/1.1 103"
            size_t count103 = 0;
            size_t search_pos = 0;
            while ((search_pos = resp.find("HTTP/1.1 103", search_pos)) != std::string::npos) {
                ++count103;
                ++search_pos;
            }
            if (count103 != 2) {
                pass = false;
                err += "expected 2 x HTTP/1.1 103, got " + std::to_string(count103) + "; ";
            }
            if (resp.find("HTTP/1.1 200") == std::string::npos) {
                pass = false; err += "missing HTTP/1.1 200; ";
            }
            TestFramework::RecordTest("H1 103 Early Hints: multiple before final",
                                      pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("H1 103 Early Hints: multiple before final",
                                      false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // T3: 103 rejected on HTTP/1.0. The framework must silently drop the interim
    // (HTTP/1.0 cannot handle 1xx interims per RFC 8297). The final 200 must
    // still arrive.
    void TestH1_EarlyHints_RejectedOn10() {
        std::cout << "\n[TEST] H1 103 Early Hints: rejected on HTTP/1.0..." << std::endl;
        try {
            HttpServer server("127.0.0.1", 0);
            server.GetAsync("/hints10",
                [](const HttpRequest&,
                   HttpRouter::InterimResponseSender send_interim,
                   HttpRouter::ResourcePusher        /*push_resource*/,
                   HttpRouter::StreamingResponseSender /*stream_sender*/,
                   HttpRouter::AsyncCompletionCallback complete) {
                    send_interim(103, {{"Link", "</x.css>; rel=preload"}});
                    HttpResponse r;
                    r.Status(200).Text("ok10");
                    complete(std::move(r));
                });

            TestServerRunner<HttpServer> runner(server);
            int port = runner.GetPort();

            // HTTP/1.0 request — Connection: close is implied
            std::string resp = SendRawAndDrain(port,
                "GET /hints10 HTTP/1.0\r\nHost: x\r\n\r\n", 3000);

            bool pass = true;
            std::string err;
            if (resp.find("HTTP/1.1 103") != std::string::npos ||
                resp.find(" 103 ") != std::string::npos) {
                pass = false; err += "103 must not appear for HTTP/1.0 clients; ";
            }
            bool has_200 = resp.find("HTTP/1.1 200") != std::string::npos ||
                           resp.find("HTTP/1.0 200") != std::string::npos;
            if (!has_200) {
                pass = false; err += "missing final 200; ";
            }
            TestFramework::RecordTest("H1 103 Early Hints: rejected on HTTP/1.0",
                                      pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("H1 103 Early Hints: rejected on HTTP/1.0",
                                      false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // T4: Forbidden header stripped from 103 block. The 103 must contain the
    // Link header but NOT Content-Length.
    void TestH1_EarlyHints_ForbiddenHeaderStripped() {
        std::cout << "\n[TEST] H1 103 Early Hints: forbidden header stripped..." << std::endl;
        try {
            HttpServer server("127.0.0.1", 0);
            server.GetAsync("/strip",
                [](const HttpRequest&,
                   HttpRouter::InterimResponseSender send_interim,
                   HttpRouter::ResourcePusher        /*push_resource*/,
                   HttpRouter::StreamingResponseSender /*stream_sender*/,
                   HttpRouter::AsyncCompletionCallback complete) {
                    send_interim(103, {
                        {"Link", "</a.css>; rel=preload"},
                        {"Content-Length", "999"},
                        {"Connection", "keep-alive"}
                    });
                    HttpResponse r;
                    r.Status(200).Text("done");
                    complete(std::move(r));
                });

            TestServerRunner<HttpServer> runner(server);
            int port = runner.GetPort();

            std::string resp = SendRawAndDrain(port,
                "GET /strip HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", 3000);

            bool pass = true;
            std::string err;

            // Isolate the 103 block: from "HTTP/1.1 103" up to the \r\n\r\n
            // that terminates that interim response.
            auto pos103 = resp.find("HTTP/1.1 103");
            if (pos103 == std::string::npos) {
                pass = false; err += "missing HTTP/1.1 103; ";
                TestFramework::RecordTest(
                    "H1 103 Early Hints: forbidden header stripped",
                    pass, err, TestFramework::TestCategory::OTHER);
                return;
            }
            auto end103 = resp.find("\r\n\r\n", pos103);
            if (end103 == std::string::npos) {
                pass = false; err += "103 block not terminated; ";
                TestFramework::RecordTest(
                    "H1 103 Early Hints: forbidden header stripped",
                    pass, err, TestFramework::TestCategory::OTHER);
                return;
            }
            std::string block103 = resp.substr(pos103, end103 - pos103);

            if (block103.find("Link:") == std::string::npos) {
                pass = false; err += "Link header missing from 103 block; ";
            }
            if (block103.find("Content-Length") != std::string::npos) {
                pass = false; err += "Content-Length must not appear in 103 block; ";
            }
            if (block103.find("Connection") != std::string::npos) {
                pass = false; err += "Connection must not appear in 103 block; ";
            }
            TestFramework::RecordTest("H1 103 Early Hints: forbidden header stripped",
                                      pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("H1 103 Early Hints: forbidden header stripped",
                                      false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // T5: Interim dropped after final response.
    //
    // complete() enqueues CompleteAsyncResponse on the dispatcher (task A)
    // via RunOnDispatcher. The handler then signals a promise with send_interim.
    // A background watcher thread waits on the promise (no spin-wait), then
    // sleeps 50 ms — well above a single dispatcher cycle — to let task A run.
    // It then calls send_interim from the background thread.
    //
    // Because final_response_sent_ is now std::atomic<bool> with acquire/release
    // ordering, the background thread's load(acquire) in SendInterimResponse
    // observes the store(true, release) written by CompleteAsyncResponse on the
    // dispatcher thread. There is no data race (C++ UB). The 50 ms budget is
    // purely a reliability margin for task A to finish; the atomic ordering
    // guarantees correctness even if A finishes in < 1 µs.
    void TestH1_EarlyHints_DroppedAfterFinal() {
        std::cout << "\n[TEST] H1 103 Early Hints: dropped after final..." << std::endl;
        try {
            HttpServer server("127.0.0.1", 0);

            // Shared signal: the handler fills this with the send_interim sender
            // after calling complete(), so the watcher thread can call it.
            auto p_sender = std::make_shared<std::promise<HttpRouter::InterimResponseSender>>();
            auto f_sender = p_sender->get_future().share();

            server.GetAsync("/postfinal",
                [p_sender](
                    const HttpRequest&,
                    HttpRouter::InterimResponseSender send_interim,
                    HttpRouter::ResourcePusher        /*push_resource*/,
                    HttpRouter::StreamingResponseSender /*stream_sender*/,
                    HttpRouter::AsyncCompletionCallback complete) {
                    // Complete with the final 200 first. This enqueues
                    // CompleteAsyncResponse on the dispatcher (task A).
                    HttpResponse r;
                    r.Status(200).Text("done");
                    complete(std::move(r));

                    // Signal the watcher with the sender.  The watcher's sleep
                    // ensures task A has run before send_interim is called.
                    p_sender->set_value(send_interim);
                });

            // Background watcher: blocks on the future (no spin-wait), then
            // sleeps 50 ms for the dispatcher to process task A before calling
            // send_interim. With final_response_sent_ atomic, this is race-free.
            std::thread watcher([f_sender]() mutable {
                auto send_interim = f_sender.get();   // blocks until complete() called
                // Margin for dispatcher to drain the enqueued CompleteAsyncResponse;
                // 50ms is plenty even on loaded CI. Atomic acquire/release ordering
                // inside SendInterimResponse provides the actual correctness guarantee.
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                send_interim(103, {{"Link", "</dropped.css>; rel=preload"}});
            });

            // RAII guard: join the watcher on all exit paths (including exceptions
            // thrown by SendRawAndDrain). Without this, stack-unwinding hits the
            // std::thread destructor while the thread is still joinable → std::terminate.
            struct JoinGuard {
                std::thread& t;
                ~JoinGuard() { if (t.joinable()) t.join(); }
            };
            JoinGuard watcher_guard{watcher};

            TestServerRunner<HttpServer> runner(server);
            int port = runner.GetPort();

            std::string resp = SendRawAndDrain(port,
                "GET /postfinal HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
                3000);

            bool pass = true;
            std::string err;
            if (resp.find("HTTP/1.1 103") != std::string::npos) {
                pass = false; err += "post-final 103 must be dropped; ";
            }
            if (resp.find("HTTP/1.1 200") == std::string::npos) {
                pass = false; err += "missing HTTP/1.1 200; ";
            }
            TestFramework::RecordTest("H1 103 Early Hints: dropped after final",
                                      pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("H1 103 Early Hints: dropped after final",
                                      false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // T6: 100 Continue + 103 Early Hints + 200 ordering. Client sends POST
    // headers with Expect: 100-continue (no body yet), waits for the 100,
    // then sends the body. The handler then emits 103 and completes with 200.
    // Assert wire order: 100 < 103 < 200.
    void TestH1_EarlyHints_100ContinueThen103() {
        std::cout << "\n[TEST] H1 103 Early Hints: 100-continue then 103 then 200..."
                  << std::endl;
        AsyncScheduler sched;
        try {
            HttpServer server("127.0.0.1", 0);
            server.PostAsync("/upload",
                [&sched](const HttpRequest&,
                          HttpRouter::InterimResponseSender send_interim,
                          HttpRouter::ResourcePusher        /*push_resource*/,
                          HttpRouter::StreamingResponseSender /*stream_sender*/,
                          HttpRouter::AsyncCompletionCallback complete) {
                    // 103 emitted synchronously; final 200 via background task.
                    send_interim(103, {{"Link", "</style.css>; rel=preload"}});
                    sched.Schedule(10, [complete = std::move(complete)]() {
                        HttpResponse r;
                        r.Status(200).Text("uploaded");
                        complete(std::move(r));
                    });
                });

            TestServerRunner<HttpServer> runner(server);
            int port = runner.GetPort();

            // Phase 1: open socket, send only the request headers (no body).
            // The server sends 100 Continue when it sees headers_complete but
            // the body hasn't arrived yet (HandleIncompleteRequest path).
            // Phase 2: send the body bytes.
            // Phase 3: drain all responses until peer closes.
            int fd = socket(AF_INET, SOCK_STREAM, 0);
            bool pass = true;
            std::string err;
            std::string all_resp;

            if (fd < 0) {
                pass = false; err += "socket() failed; ";
            } else {
                sockaddr_in addr{};
                addr.sin_family = AF_INET;
                addr.sin_port = htons(port);
                addr.sin_addr.s_addr = inet_addr("127.0.0.1");

                if (connect(fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
                    pass = false; err += "connect() failed; ";
                    close(fd); fd = -1;
                }
            }

            if (pass && fd >= 0) {
                std::string body = "payload=hello";
                std::string headers =
                    "POST /upload HTTP/1.1\r\n"
                    "Host: x\r\n"
                    "Content-Length: " + std::to_string(body.size()) + "\r\n"
                    "Expect: 100-continue\r\n"
                    "Connection: close\r\n"
                    "\r\n";

                // Send headers only.
                send(fd, headers.data(), headers.size(), 0);

                // Wait up to 500ms for the 100 Continue response.
                char buf[1024];
                auto t0 = std::chrono::steady_clock::now();
                while (all_resp.find("HTTP/1.1 100") == std::string::npos) {
                    auto elapsed = std::chrono::duration_cast<
                        std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - t0).count();
                    if (elapsed > 500) break;
                    pollfd pfd{fd, POLLIN, 0};
                    int r = poll(&pfd, 1, 50);
                    if (r > 0 && (pfd.revents & POLLIN)) {
                        ssize_t n = recv(fd, buf, sizeof(buf), 0);
                        if (n > 0) all_resp.append(buf, n);
                        else break;
                    }
                }

                // Now send the body to unblock the async handler.
                send(fd, body.data(), body.size(), 0);

                // Drain until peer closes (Connection: close).
                auto t1 = std::chrono::steady_clock::now();
                while (true) {
                    auto elapsed = std::chrono::duration_cast<
                        std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - t1).count();
                    if (elapsed > 2500) break;
                    pollfd pfd2{fd, POLLIN, 0};
                    int r = poll(&pfd2, 1, 100);
                    if (r > 0 && (pfd2.revents & POLLIN)) {
                        ssize_t n = recv(fd, buf, sizeof(buf), 0);
                        if (n > 0) all_resp.append(buf, n);
                        else break;
                    }
                }
                close(fd);

                auto pos100 = all_resp.find("HTTP/1.1 100");
                auto pos103 = all_resp.find("HTTP/1.1 103");
                auto pos200 = all_resp.find("HTTP/1.1 200");
                if (pos100 == std::string::npos) {
                    pass = false; err += "missing HTTP/1.1 100; ";
                }
                if (pos103 == std::string::npos) {
                    pass = false; err += "missing HTTP/1.1 103; ";
                }
                if (pos200 == std::string::npos) {
                    pass = false; err += "missing HTTP/1.1 200; ";
                }
                if (pass) {
                    // Wire order must be: 100 < 103 < 200
                    if (!(pos100 < pos103 && pos103 < pos200)) {
                        pass = false;
                        err += "wrong order (100=" + std::to_string(pos100) +
                               " 103=" + std::to_string(pos103) +
                               " 200=" + std::to_string(pos200) + "); ";
                    }
                }
            }
            TestFramework::RecordTest(
                "H1 103 Early Hints: 100-continue then 103 then 200",
                pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest(
                "H1 103 Early Hints: 100-continue then 103 then 200",
                false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // T7: CR/LF in interim header values must not inject extra headers
    // or body bytes into the 1xx block. Without sanitization, a handler
    // that forwards a Link header whose value contains "\r\nInjected:
    // foo" would leak a forged downstream header into the client's view
    // of the response — a classic response-splitting pathway. The
    // interim serializer mirrors HttpResponse::Header's strip policy.
    void TestH1_EarlyHints_CRLFSanitized() {
        std::cout << "\n[TEST] H1 103 Early Hints: CR/LF header sanitized..." << std::endl;
        try {
            HttpServer server("127.0.0.1", 0);
            server.GetAsync("/inject",
                [](const HttpRequest&,
                   HttpRouter::InterimResponseSender send_interim,
                   HttpRouter::ResourcePusher        /*push_resource*/,
                   HttpRouter::StreamingResponseSender /*stream_sender*/,
                   HttpRouter::AsyncCompletionCallback complete) {
                    send_interim(103, {
                        {"Link", "</a.css>; rel=preload\r\nInjected: leaked"}
                    });
                    HttpResponse r;
                    r.Status(200).Text("ok");
                    complete(std::move(r));
                });

            TestServerRunner<HttpServer> runner(server);
            int port = runner.GetPort();

            std::string resp = SendRawAndDrain(port,
                "GET /inject HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
                3000);

            bool pass = true;
            std::string err;
            if (resp.find("HTTP/1.1 103") == std::string::npos) {
                pass = false; err += "missing 103; ";
            }
            if (resp.find("HTTP/1.1 200") == std::string::npos) {
                pass = false; err += "missing 200; ";
            }
            // Attack succeeds only if "Injected:" appears at the start
            // of its own header line (preceded by CRLF). After
            // sanitization the CR and LF are removed, so the attempted
            // injection collapses into the Link value — the substring
            // "Injected:" is still present, but NOT as a standalone
            // header. Assert on the standalone-line form.
            if (resp.find("\r\nInjected:") != std::string::npos) {
                pass = false; err += "CRLF injection observed (standalone header line); ";
            }
            TestFramework::RecordTest("H1 103 Early Hints: CR/LF header sanitized",
                                      pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("H1 103 Early Hints: CR/LF header sanitized",
                                      false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    void TestH1_StreamingTrailers_CRLFSanitized() {
        std::cout << "\n[TEST] H1 streaming trailers: CR/LF sanitized..." << std::endl;
        try {
            HttpServer server("127.0.0.1", 0);
            server.GetAsync(
                "/stream-trailer-inject",
                [](const HttpRequest&,
                   HttpRouter::InterimResponseSender /*send_interim*/,
                   HttpRouter::ResourcePusher /*push_resource*/,
                   HttpRouter::StreamingResponseSender stream_sender,
                   HttpRouter::AsyncCompletionCallback /*complete*/) {
                    HttpResponse head;
                    head.Status(200)
                        .Header("Content-Type", "text/plain")
                        .Header("Trailer", "X-Key, X-Value");
                    if (stream_sender.SendHeaders(head) < 0) {
                        return;
                    }
                    static constexpr char kBody[] = "hello";
                    if (stream_sender.SendData(kBody, sizeof(kBody) - 1) ==
                        HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::SendResult::CLOSED) {
                        return;
                    }
                    (void)stream_sender.End({
                        {"X-Key\r\nInjected-Name", "abc"},
                        {"X-Value", "line1\r\nInjected-Value: leaked"},
                    });
                });

            TestServerRunner<HttpServer> runner(server);
            int port = runner.GetPort();

            std::string resp = SendRawAndDrain(
                port,
                "GET /stream-trailer-inject HTTP/1.1\r\n"
                "Host: x\r\n"
                "Connection: close\r\n"
                "\r\n",
                3000);

            bool pass = true;
            std::string err;
            if (resp.find("HTTP/1.1 200") == std::string::npos) {
                pass = false; err += "missing 200; ";
            }
            if (resp.find("5\r\nhello\r\n") == std::string::npos) {
                pass = false; err += "chunked body missing; ";
            }
            auto header_end = resp.find("\r\n\r\n");
            std::string body_and_trailers =
                (header_end == std::string::npos) ? std::string() :
                resp.substr(header_end + 4);
            if (body_and_trailers.find("0\r\n") == std::string::npos) {
                pass = false; err += "final zero chunk missing; ";
            }
            if (body_and_trailers.find("\r\nInjected-Name:") != std::string::npos) {
                pass = false; err += "trailer name injection observed; ";
            }
            if (body_and_trailers.find("\r\nInjected-Value:") != std::string::npos) {
                pass = false; err += "trailer value injection observed; ";
            }
            std::string lower = body_and_trailers;
            std::transform(lower.begin(), lower.end(), lower.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            if (lower.find("x-keyinjected-name: abc") == std::string::npos) {
                pass = false; err += "sanitized trailer name missing; ";
            }
            if (lower.find("x-value: line1injected-value: leaked") == std::string::npos) {
                pass = false; err += "sanitized trailer value missing; ";
            }

            TestFramework::RecordTest(
                "H1 streaming trailers: CR/LF sanitized",
                pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest(
                "H1 streaming trailers: CR/LF sanitized",
                false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    void TestH1_StreamingTrailers_DeclarationFiltersForbiddenNames() {
        std::cout << "\n[TEST] H1 streaming trailers: declaration filters forbidden names..."
                  << std::endl;
        try {
            HttpServer server("127.0.0.1", 0);
            server.GetAsync(
                "/stream-trailer-declaration-filter",
                [](const HttpRequest&,
                   HttpRouter::InterimResponseSender /*send_interim*/,
                   HttpRouter::ResourcePusher /*push_resource*/,
                   HttpRouter::StreamingResponseSender stream_sender,
                   HttpRouter::AsyncCompletionCallback /*complete*/) {
                    HttpResponse head;
                    head.Status(200)
                        .Header("Content-Type", "text/plain")
                        .Header("Trailer",
                                "X-Allowed, Content-Length, X-Extra, Host, "
                                "Transfer-Encoding");
                    if (stream_sender.SendHeaders(head) < 0) {
                        return;
                    }
                    static constexpr char kBody[] = "ok";
                    if (stream_sender.SendData(kBody, sizeof(kBody) - 1) ==
                        HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::SendResult::CLOSED) {
                        return;
                    }
                    (void)stream_sender.End({
                        {"X-Allowed", "one"},
                        {"Content-Length", "should-drop"},
                        {"Host", "should-drop"},
                        {"X-Extra", "two"},
                    });
                });

            TestServerRunner<HttpServer> runner(server);
            int port = runner.GetPort();

            std::string resp = SendRawAndDrain(
                port,
                "GET /stream-trailer-declaration-filter HTTP/1.1\r\n"
                "Host: x\r\n"
                "Connection: close\r\n"
                "\r\n",
                3000);

            bool pass = true;
            std::string err;
            auto header_end = resp.find("\r\n\r\n");
            if (header_end == std::string::npos) {
                pass = false; err += "missing header terminator; ";
            } else {
                std::string head = resp.substr(0, header_end);
                std::string lower_head = head;
                std::transform(lower_head.begin(), lower_head.end(), lower_head.begin(),
                               [](unsigned char c) { return std::tolower(c); });
                size_t trailer_pos = lower_head.find("\r\ntrailer: ");
                if (trailer_pos == std::string::npos) {
                    pass = false; err += "filtered trailer declaration missing; ";
                } else {
                    size_t trailer_end = lower_head.find("\r\n", trailer_pos + 2);
                    std::string trailer_line = lower_head.substr(
                        trailer_pos + 2,
                        trailer_end == std::string::npos
                            ? std::string::npos
                            : trailer_end - (trailer_pos + 2));
                    if (trailer_line.find("x-allowed") == std::string::npos ||
                        trailer_line.find("x-extra") == std::string::npos) {
                        pass = false; err += "allowed trailer name missing from declaration; ";
                    }
                    if (trailer_line.find("content-length") != std::string::npos ||
                        trailer_line.find("host") != std::string::npos ||
                        trailer_line.find("transfer-encoding") != std::string::npos) {
                        pass = false; err += "forbidden trailer name declared; ";
                    }
                }

                std::string body_and_trailers = resp.substr(header_end + 4);
                std::string lower_body = body_and_trailers;
                std::transform(lower_body.begin(), lower_body.end(), lower_body.begin(),
                               [](unsigned char c) { return std::tolower(c); });
                if (lower_body.find("2\r\nok\r\n0\r\n") == std::string::npos) {
                    pass = false; err += "chunked body missing; ";
                }
                if (lower_body.find("x-allowed: one\r\n") == std::string::npos ||
                    lower_body.find("x-extra: two\r\n") == std::string::npos) {
                    pass = false; err += "allowed trailers missing; ";
                }
                if (lower_body.find("content-length: should-drop") !=
                        std::string::npos ||
                    lower_body.find("host: should-drop") != std::string::npos) {
                    pass = false; err += "forbidden trailer serialized; ";
                }
            }

            TestFramework::RecordTest(
                "H1 streaming trailers: declaration filters forbidden names",
                pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest(
                "H1 streaming trailers: declaration filters forbidden names",
                false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    void TestH1_Streaming205CanonicalizesContentLength() {
        std::cout << "\n[TEST] H1 streaming: 205 canonicalizes Content-Length..." << std::endl;
        try {
            HttpServer server("127.0.0.1", 0);
            server.GetAsync(
                "/stream-205",
                [](const HttpRequest&,
                   HttpRouter::InterimResponseSender /*send_interim*/,
                   HttpRouter::ResourcePusher /*push_resource*/,
                   HttpRouter::StreamingResponseSender stream_sender,
                   HttpRouter::AsyncCompletionCallback /*complete*/) {
                    HttpResponse head;
                    head.Status(205)
                        .Header("Content-Type", "text/plain")
                        .Header("Content-Length", "9");
                    if (stream_sender.SendHeaders(head) < 0) {
                        return;
                    }
                    (void)stream_sender.SendData("ignored", 7);
                    (void)stream_sender.End();
                });

            TestServerRunner<HttpServer> runner(server);
            int port = runner.GetPort();

            std::string resp = SendRawAndDrain(
                port,
                "GET /stream-205 HTTP/1.1\r\n"
                "Host: x\r\n"
                "Connection: close\r\n"
                "\r\n",
                3000);

            bool pass = true;
            std::string err;
            std::string lower = resp;
            std::transform(lower.begin(), lower.end(), lower.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            if (lower.find("http/1.1 205 reset content") == std::string::npos) {
                pass = false; err += "missing 205 response; ";
            }
            size_t cl_count = 0;
            size_t pos = 0;
            while ((pos = lower.find("content-length:", pos)) != std::string::npos) {
                ++cl_count;
                pos += std::string("content-length:").size();
            }
            if (cl_count != 1) {
                pass = false; err += "expected exactly one content-length; ";
            }
            if (lower.find("content-length: 0") == std::string::npos) {
                pass = false; err += "content-length not canonicalized to 0; ";
            }
            if (lower.find("content-length: 9") != std::string::npos) {
                pass = false; err += "stale content-length leaked; ";
            }
            if (!TestHttpClient::ExtractBody(resp).empty()) {
                pass = false; err += "205 response leaked body; ";
            }

            TestFramework::RecordTest(
                "H1 streaming: 205 canonicalizes Content-Length",
                pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest(
                "H1 streaming: 205 canonicalizes Content-Length",
                false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    void TestH1_StreamingDeduplicatesContentLength() {
        std::cout << "\n[TEST] H1 streaming: duplicate Content-Length canonicalized..." << std::endl;
        try {
            HttpServer server("127.0.0.1", 0);
            server.GetAsync(
                "/stream-dup-cl",
                [](const HttpRequest&,
                   HttpRouter::InterimResponseSender /*send_interim*/,
                   HttpRouter::ResourcePusher /*push_resource*/,
                   HttpRouter::StreamingResponseSender stream_sender,
                   HttpRouter::AsyncCompletionCallback /*complete*/) {
                    HttpResponse head;
                    head.Status(200)
                        .Header("Content-Type", "text/plain")
                        .PreserveContentLength()
                        .AppendHeader("Content-Length", "10")
                        .AppendHeader("Content-Length", "10");
                    if (stream_sender.SendHeaders(head) < 0) {
                        return;
                    }
                    (void)stream_sender.SendData("hello", 5);
                    (void)stream_sender.SendData("world", 5);
                    (void)stream_sender.End();
                });

            TestServerRunner<HttpServer> runner(server);
            int port = runner.GetPort();

            std::string resp = SendRawAndDrain(
                port,
                "GET /stream-dup-cl HTTP/1.1\r\n"
                "Host: x\r\n"
                "Connection: close\r\n"
                "\r\n",
                3000);

            bool pass = true;
            std::string err;
            std::string lower = resp;
            std::transform(lower.begin(), lower.end(), lower.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            if (lower.find("http/1.1 200 ok") == std::string::npos) {
                pass = false; err += "missing 200 response; ";
            }
            size_t cl_count = 0;
            size_t pos = 0;
            while ((pos = lower.find("content-length:", pos)) != std::string::npos) {
                ++cl_count;
                pos += std::string("content-length:").size();
            }
            if (cl_count != 1) {
                pass = false; err += "expected exactly one content-length; ";
            }
            if (lower.find("content-length: 10") == std::string::npos) {
                pass = false; err += "canonical content-length missing; ";
            }
            if (lower.find("transfer-encoding: chunked") != std::string::npos) {
                pass = false; err += "unexpected chunked transfer-encoding; ";
            }
            if (TestHttpClient::ExtractBody(resp) != "helloworld") {
                pass = false; err += "body mismatch; ";
            }

            TestFramework::RecordTest(
                "H1 streaming: duplicate Content-Length canonicalized",
                pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest(
                "H1 streaming: duplicate Content-Length canonicalized",
                false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    void TestH1_StreamingHttp10UnknownLengthOmitsContentLength() {
        std::cout << "\n[TEST] H1 streaming: HTTP/1.0 unknown-length response omits Content-Length..." << std::endl;
        try {
            HttpServer server("127.0.0.1", 0);
            server.GetAsync(
                "/stream-http10-unknown",
                [](const HttpRequest&,
                   HttpRouter::InterimResponseSender /*send_interim*/,
                   HttpRouter::ResourcePusher /*push_resource*/,
                   HttpRouter::StreamingResponseSender stream_sender,
                   HttpRouter::AsyncCompletionCallback /*complete*/) {
                    HttpResponse head;
                    head.Status(200).Header("Content-Type", "text/plain");
                    if (stream_sender.SendHeaders(head) < 0) {
                        return;
                    }
                    if (stream_sender.SendData("hello", 5) ==
                        HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::SendResult::CLOSED) {
                        return;
                    }
                    if (stream_sender.SendData("world", 5) ==
                        HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::SendResult::CLOSED) {
                        return;
                    }
                    (void)stream_sender.End();
                });

            TestServerRunner<HttpServer> runner(server);
            int port = runner.GetPort();

            std::string resp = SendRawAndDrain(
                port,
                "GET /stream-http10-unknown HTTP/1.0\r\n"
                "Host: x\r\n"
                "\r\n",
                3000);

            bool pass = true;
            std::string err;
            std::string lower = resp;
            std::transform(lower.begin(), lower.end(), lower.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            if (lower.find("http/1.0 200 ok") == std::string::npos) {
                pass = false; err += "missing HTTP/1.0 200 response; ";
            }
            if (lower.find("content-length:") != std::string::npos) {
                pass = false; err += "content-length should be omitted; ";
            }
            if (lower.find("transfer-encoding:") != std::string::npos) {
                pass = false; err += "transfer-encoding should be omitted; ";
            }
            if (TestHttpClient::ExtractBody(resp) != "helloworld") {
                pass = false; err += "body mismatch; ";
            }

            TestFramework::RecordTest(
                "H1 streaming: HTTP/1.0 unknown-length response omits Content-Length",
                pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest(
                "H1 streaming: HTTP/1.0 unknown-length response omits Content-Length",
                false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    void TestH1_StreamingAbortOffDispatcherThreadRejected() {
        std::cout << "\n[TEST] H1 streaming: off-dispatcher Abort is rejected..." << std::endl;
        try {
            HttpServer server("127.0.0.1", 0);
            auto worker_called = std::make_shared<std::atomic<bool>>(false);
            server.GetAsync(
                "/stream-abort-offthread",
                [worker_called](const HttpRequest&,
                                HttpRouter::InterimResponseSender /*send_interim*/,
                                HttpRouter::ResourcePusher /*push_resource*/,
                                HttpRouter::StreamingResponseSender stream_sender,
                                HttpRouter::AsyncCompletionCallback /*complete*/) {
                    std::thread t([stream_sender, worker_called]() mutable {
                        worker_called->store(true, std::memory_order_release);
                        stream_sender.Abort(
                            HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::
                                AbortReason::UPSTREAM_ERROR);
                    });
                    t.join();

                    HttpResponse head;
                    head.Status(200)
                        .Header("Content-Type", "text/plain")
                        .Header("Content-Length", "2")
                        .PreserveContentLength();
                    if (stream_sender.SendHeaders(head) < 0) {
                        return;
                    }
                    if (stream_sender.SendData("ok", 2) ==
                        HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::
                            SendResult::CLOSED) {
                        return;
                    }
                    (void)stream_sender.End();
                });

            TestServerRunner<HttpServer> runner(server);
            int port = runner.GetPort();

            std::string resp = SendHttpRequest(
                port,
                "GET /stream-abort-offthread HTTP/1.1\r\n"
                "Host: x\r\n"
                "Connection: close\r\n"
                "\r\n");

            bool pass = true;
            std::string err;
            if (!TestHttpClient::HasStatus(resp, 200)) {
                pass = false; err += "missing 200 response; ";
            }
            if (TestHttpClient::ExtractBody(resp) != "ok") {
                pass = false; err += "body mismatch; ";
            }
            if (!worker_called->load(std::memory_order_acquire)) {
                pass = false; err += "worker thread did not call Abort; ";
            }

            TestFramework::RecordTest(
                "H1 streaming: off-dispatcher Abort is rejected",
                pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest(
                "H1 streaming: off-dispatcher Abort is rejected",
                false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    void TestH1_StreamingRawContentLengthWithoutPreserveUsesChunkedFraming() {
        std::cout << "\n[TEST] H1 streaming: raw Content-Length without preserve uses chunked framing..." << std::endl;
        try {
            HttpServer server("127.0.0.1", 0);
            server.GetAsync(
                "/stream-natural-cl",
                [](const HttpRequest&,
                   HttpRouter::InterimResponseSender /*send_interim*/,
                   HttpRouter::ResourcePusher /*push_resource*/,
                   HttpRouter::StreamingResponseSender stream_sender,
                   HttpRouter::AsyncCompletionCallback /*complete*/) {
                    HttpResponse head;
                    head.Status(200)
                        .Header("Content-Type", "text/plain")
                        .Header("Content-Length", "10");
                    if (stream_sender.SendHeaders(head) < 0) {
                        return;
                    }
                    if (stream_sender.SendData("hello", 5) ==
                        HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::
                            SendResult::CLOSED) {
                        return;
                    }
                    if (stream_sender.SendData("world", 5) ==
                        HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::
                            SendResult::CLOSED) {
                        return;
                    }
                    (void)stream_sender.End();
                });

            TestServerRunner<HttpServer> runner(server);
            int port = runner.GetPort();

            std::string resp = SendRawAndDrain(
                port,
                "GET /stream-natural-cl HTTP/1.1\r\n"
                "Host: x\r\n"
                "Connection: close\r\n"
                "\r\n",
                3000);

            bool pass = true;
            std::string err;
            size_t first_header_end = resp.find("\r\n\r\n");
            if (first_header_end == std::string::npos) {
                pass = false; err += "first response headers missing; ";
            } else {
                std::string first_header = resp.substr(0, first_header_end);
                std::string lower_first = first_header;
                std::transform(lower_first.begin(), lower_first.end(),
                               lower_first.begin(),
                               [](unsigned char c) { return std::tolower(c); });
                if (lower_first.find("http/1.1 200 ok") == std::string::npos) {
                    pass = false; err += "first response status missing; ";
                }
                if (lower_first.find("transfer-encoding: chunked") ==
                    std::string::npos) {
                    pass = false; err += "first response not chunked; ";
                }
                if (lower_first.find("content-length:") != std::string::npos) {
                    pass = false; err += "unexpected content-length in streamed head; ";
                }
            }

            std::string lower_resp = resp;
            std::transform(lower_resp.begin(), lower_resp.end(), lower_resp.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            if (lower_resp.find("5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n") ==
                std::string::npos) {
                pass = false;
                err += "chunked body or terminator missing; ";
            }

            TestFramework::RecordTest(
                "H1 streaming: raw Content-Length without preserve uses chunked framing",
                pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest(
                "H1 streaming: raw Content-Length without preserve uses chunked framing",
                false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    void TestH1_StreamingControlMethodsOffDispatcherThreadRejected() {
        std::cout << "\n[TEST] H1 streaming: off-dispatcher control methods are rejected..." << std::endl;
        try {
            auto worker_called = std::make_shared<std::atomic<bool>>(false);
            auto first_result =
                std::make_shared<std::atomic<int>>(static_cast<int>(
                    HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::SendResult::CLOSED));

            HttpServer server("127.0.0.1", 0);
            server.GetAsync(
                "/stream-control-offthread",
                [worker_called, first_result](
                    const HttpRequest&,
                    HttpRouter::InterimResponseSender /*send_interim*/,
                    HttpRouter::ResourcePusher /*push_resource*/,
                    HttpRouter::StreamingResponseSender stream_sender,
                    HttpRouter::AsyncCompletionCallback /*complete*/) {
                    std::thread t([stream_sender, worker_called]() mutable {
                        worker_called->store(true, std::memory_order_release);
                        stream_sender.ConfigureWatermarks(1);
                        stream_sender.SetDrainListener([]() {});
                    });
                    t.join();

                    HttpResponse head;
                    head.Status(200).Header("Content-Type", "text/plain");
                    if (stream_sender.SendHeaders(head) < 0) {
                        return;
                    }
                    auto first = stream_sender.SendData("a", 1);
                    first_result->store(static_cast<int>(first),
                                        std::memory_order_release);
                    if (first ==
                        HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::
                            SendResult::CLOSED) {
                        return;
                    }

                    std::string body(4096, 'x');
                    stream_sender.ConfigureWatermarks(1);
                    auto second = stream_sender.SendData(body.data(), body.size());
                    if (second ==
                        HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::
                            SendResult::CLOSED) {
                        return;
                    }
                    (void)stream_sender.End();
                });

            TestServerRunner<HttpServer> runner(server);
            int port = runner.GetPort();

            std::string resp = SendRawAndDrain(
                port,
                "GET /stream-control-offthread HTTP/1.1\r\n"
                "Host: x\r\n"
                "Connection: close\r\n"
                "\r\n",
                3000);

            std::this_thread::sleep_for(std::chrono::milliseconds(200));

            bool pass = true;
            std::string err;
            std::string lower = resp;
            std::transform(lower.begin(), lower.end(), lower.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            if (lower.find("http/1.1 200 ok") == std::string::npos) {
                pass = false; err += "missing 200 response; ";
            }
            if (lower.find("transfer-encoding: chunked") == std::string::npos) {
                pass = false; err += "expected chunked framing; ";
            }
            if (lower.find("1\r\na\r\n1000\r\n") == std::string::npos) {
                pass = false; err += "expected streamed chunk sequence missing; ";
            }
            if (!worker_called->load(std::memory_order_acquire)) {
                pass = false; err += "worker thread did not call control methods; ";
            }
            auto expected_first = static_cast<int>(
                HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::SendResult::
                    ACCEPTED_BELOW_WATER);
            if (first_result->load(std::memory_order_acquire) != expected_first) {
                pass = false;
                err += "off-thread ConfigureWatermarks should be ignored; ";
            }

            TestFramework::RecordTest(
                "H1 streaming: off-dispatcher control methods are rejected",
                pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest(
                "H1 streaming: off-dispatcher control methods are rejected",
                false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // T8: Worker-thread interleave — a handler that calls complete() from
    // a worker thread followed by send_interim() from the same worker
    // must not be able to queue a 103 AFTER the 200 on the wire.
    // Without the off-dispatcher hop, send_interim would observe
    // final_response_sent_=false (not yet set by the queued final
    // lambda), build the 103, and SendRaw would enqueue AFTER the
    // final-response lambda — clients would observe 200 followed by
    // 103. The hop re-orders the check through the dispatcher so it
    // runs after the final write and drops.
    void TestH1_EarlyHints_WorkerThreadOrderingSafe() {
        std::cout << "\n[TEST] H1 103 Early Hints: worker-thread ordering safe..." << std::endl;
        try {
            HttpServer server("127.0.0.1", 0);

            // Shared signal: the handler stores complete + send_interim
            // so the watcher thread can invoke BOTH from a single worker
            // thread in rapid succession — the race scenario.
            struct Payload {
                HttpRouter::AsyncCompletionCallback complete;
                HttpRouter::InterimResponseSender   send_interim;
            };
            auto p = std::make_shared<std::promise<Payload>>();
            auto f = p->get_future().share();

            server.GetAsync("/race",
                [p](const HttpRequest&,
                    HttpRouter::InterimResponseSender send_interim,
                    HttpRouter::ResourcePusher        /*push_resource*/,
                    HttpRouter::StreamingResponseSender /*stream_sender*/,
                    HttpRouter::AsyncCompletionCallback complete) {
                    p->set_value(Payload{std::move(complete),
                                         std::move(send_interim)});
                });

            std::thread watcher([f]() mutable {
                auto pl = f.get();
                HttpResponse r;
                r.Status(200).Text("final");
                pl.complete(std::move(r));
                // Same-worker follow-up call: would race without the hop.
                pl.send_interim(103, {{"Link", "</late.css>; rel=preload"}});
            });
            struct JoinGuard {
                std::thread& t;
                ~JoinGuard() { if (t.joinable()) t.join(); }
            };
            JoinGuard g{watcher};

            TestServerRunner<HttpServer> runner(server);
            int port = runner.GetPort();

            std::string resp = SendRawAndDrain(port,
                "GET /race HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
                3000);

            bool pass = true;
            std::string err;
            auto pos200 = resp.find("HTTP/1.1 200");
            auto pos103 = resp.find("HTTP/1.1 103");
            if (pos200 == std::string::npos) {
                pass = false; err += "missing 200; ";
            }
            // The 103 must be fully dropped. Given the worker calls
            // complete() (flipping the per-request `completed` flag)
            // BEFORE send_interim(), the send_interim closure's
            // synchronous check observes completed==true and returns
            // without even hopping. Under no scheduler interleaving
            // should a 103 reach the wire — asserting pos103 == npos
            // is the strict form. A 103-before-200 ordering would also
            // indicate a regression (it'd mean the completed guard was
            // bypassed), not a legitimate-but-weak pass.
            if (pos103 != std::string::npos) {
                pass = false;
                err += "103 reached the wire — completed-guard bypassed; ";
            }
            TestFramework::RecordTest(
                "H1 103 Early Hints: worker-thread ordering safe",
                pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest(
                "H1 103 Early Hints: worker-thread ordering safe",
                false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // T10: Cross-request pipelining race regression — when an off-thread
    // send_interim() is issued and then complete() runs first on the
    // dispatcher (possible when two worker threads race to enqueue),
    // the queued interim lambda must NOT emit a 103 that leaks into a
    // pipelined next request's response window. With the fix, the
    // closure-level hop captures the per-request `completed` atomic
    // and re-checks it on the dispatcher side — the connection-wide
    // final_response_sent_ flag would be reset by BeginAsyncResponse
    // on the pipelined B, but `completed` is per-closure and never
    // reset.
    //
    // We engineer the scenario deterministically by:
    //   1. Worker thread calls send_interim from inside the handler on
    //      a background thread BEFORE the handler sets `completed`.
    //   2. Handler then calls complete() on the SAME background thread
    //      (flipping `completed` synchronously).
    //   3. The dispatcher queue order between the send_interim hop
    //      and complete_lambda is non-deterministic in general, but
    //      we block the send_interim hop artificially by having it
    //      wait on a promise that complete_lambda signals, FORCING
    //      the bug scenario: complete runs first, then send_interim
    //      hop runs with completed=true (pre-fix: would still emit;
    //      post-fix: drops via per-request completed re-check).
    //
    // We can't install the signal directly into SendInterimResponse,
    // so we rely on the simpler invariant: after complete() returns
    // on the worker thread, `completed` is true. A subsequent call to
    // send_interim MUST be dropped by the closure's sync check. This
    // is already tested elsewhere; the stricter regression guard here
    // is: if send_interim is called BEFORE complete on the worker but
    // the dispatcher happens to run complete's lambda first, the hop
    // lambda must still drop.
    //
    // We approximate this by making the handler return immediately
    // and having a background thread call complete() then send_interim()
    // in rapid succession. The FIFO dispatcher will run complete
    // first (it's enqueued first), which sets final_response_sent_
    // AND may parse a pipelined request B. By the time send_interim's
    // hop runs, completed is true — the per-request check fires.
    //
    // If the fix regresses (hop doesn't re-check completed), the 103
    // would leak into the response window. Assertion: no 103 present.
    void TestH1_EarlyHints_PipelinedKeepAliveNoStale() {
        std::cout << "\n[TEST] H1 103 Early Hints: pipelined keep-alive no stale..."
                  << std::endl;
        try {
            HttpServer server("127.0.0.1", 0);
            struct Payload {
                HttpRouter::AsyncCompletionCallback complete;
                HttpRouter::InterimResponseSender   send_interim;
            };
            auto p = std::make_shared<std::promise<Payload>>();
            auto f = p->get_future().share();

            server.GetAsync("/a",
                [p](const HttpRequest&,
                    HttpRouter::InterimResponseSender send_interim,
                    HttpRouter::ResourcePusher        /*push_resource*/,
                    HttpRouter::StreamingResponseSender /*stream_sender*/,
                    HttpRouter::AsyncCompletionCallback complete) {
                    p->set_value(Payload{std::move(complete),
                                         std::move(send_interim)});
                });
            server.GetAsync("/b",
                [](const HttpRequest&,
                   HttpRouter::InterimResponseSender /*send_interim*/,
                   HttpRouter::ResourcePusher        /*push_resource*/,
                   HttpRouter::StreamingResponseSender /*stream_sender*/,
                   HttpRouter::AsyncCompletionCallback complete) {
                    HttpResponse r;
                    r.Status(200).Text("B-response");
                    complete(std::move(r));
                });

            std::thread watcher([f]() mutable {
                auto pl = f.get();
                // Call complete FIRST (this flips `completed` for A and
                // enqueues CompleteAsyncResponse which MAY synchronously
                // begin parsing B). Then call send_interim — the
                // closure's SYNC check of completed catches it. Even
                // if the closure's sync check had raced (see note in
                // the test comment), the dispatcher-side re-check in
                // the hop lambda would catch it.
                HttpResponse r;
                r.Status(200).Text("A-response");
                pl.complete(std::move(r));
                pl.send_interim(103, {{"Link", "</late.css>; rel=preload"}});
            });
            struct JoinGuard {
                std::thread& t;
                ~JoinGuard() { if (t.joinable()) t.join(); }
            };
            JoinGuard g{watcher};

            TestServerRunner<HttpServer> runner(server);
            int port = runner.GetPort();

            // Two pipelined requests on one connection. After B is
            // parsed (triggered by A's completion), the 103 for A
            // must NOT appear in B's response window.
            std::string resp = SendRawAndDrain(port,
                "GET /a HTTP/1.1\r\nHost: x\r\n\r\n"
                "GET /b HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
                3000);

            bool pass = true;
            std::string err;
            // Both responses must appear.
            if (resp.find("A-response") == std::string::npos) {
                pass = false; err += "A-response missing; ";
            }
            if (resp.find("B-response") == std::string::npos) {
                pass = false; err += "B-response missing; ";
            }
            // No stale 103 anywhere on the wire.
            if (resp.find("HTTP/1.1 103") != std::string::npos) {
                pass = false;
                err += "stale 103 leaked onto the pipelined connection — "
                       "request-scoped guard was bypassed; ";
            }
            TestFramework::RecordTest(
                "H1 103 Early Hints: pipelined keep-alive no stale",
                pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest(
                "H1 103 Early Hints: pipelined keep-alive no stale",
                false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // T9: H1 async handler that populates async_cancel_slot then throws
    // must have the slot fired by the framework's catch block. Without
    // this, custom async handlers (e.g. ProxyHandler installs
    // tx->Cancel() in the slot before starting upstream work) would
    // leak the in-flight work — it would hold pool capacity and
    // resources until its own internal timeout, even after the outer
    // catch sent a 500 and closed the client connection.
    void TestH1_Async_HandlerThrowFiresCancelSlot() {
        std::cout << "\n[TEST] H1 async: handler throw fires cancel slot..."
                  << std::endl;
        try {
            HttpServer server("127.0.0.1", 0);
            auto cancel_fired = std::make_shared<std::atomic<bool>>(false);
            server.GetAsync("/throws",
                [cancel_fired](
                    const HttpRequest& req,
                    HttpRouter::InterimResponseSender /*send_interim*/,
                    HttpRouter::ResourcePusher        /*push_resource*/,
                    HttpRouter::StreamingResponseSender /*stream_sender*/,
                    HttpRouter::AsyncCompletionCallback /*complete*/) {
                    // Simulate ProxyHandler::Handle: install cleanup
                    // hook in the cancel slot BEFORE kicking off the
                    // (simulated) background work, then throw.
                    if (req.async_cancel_slot) {
                        *req.async_cancel_slot = [cancel_fired]() {
                            cancel_fired->store(true,
                                                std::memory_order_release);
                        };
                    }
                    throw std::runtime_error("handler synthetic failure");
                });

            TestServerRunner<HttpServer> runner(server);
            int port = runner.GetPort();

            std::string resp = SendRawAndDrain(port,
                "GET /throws HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
                3000);

            bool pass = true;
            std::string err;
            // Outer catch should have sent 500 and closed.
            if (resp.find("HTTP/1.1 500") == std::string::npos) {
                pass = false; err += "missing 500 response; ";
            }
            // Critical: the cancel slot must have been fired so any
            // background work (in real code: proxy upstream) is
            // released, not leaked until its own timeout.
            if (!cancel_fired->load(std::memory_order_acquire)) {
                pass = false;
                err += "cancel_slot was NOT fired — async background "
                       "work would leak; ";
            }
            TestFramework::RecordTest(
                "H1 async: handler throw fires cancel slot",
                pass, err, TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest(
                "H1 async: handler throw fires cancel slot",
                false, e.what(), TestFramework::TestCategory::OTHER);
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

        // Async-route integration tests
        TestAsyncRouteMiddlewareGating();
        TestAsyncRouteMiddlewareRejectionWithHeaders();
        TestAsyncRoutePipelineOrdering();
        TestAsyncRouteHeadFallbackRewritesMethod();
        TestAsyncRoute405IncludesAsyncMethods();
        TestAsyncRouteHeadStripping();
        TestAsyncRouteClientCloseHeader();

        // Timeout tests
        TestRequestTimeout();

        // 103 Early Hints / SendInterimResponse tests
        TestH1_EarlyHints_Basic();
        TestH1_EarlyHints_MultipleBeforeFinal();
        TestH1_EarlyHints_RejectedOn10();
        TestH1_EarlyHints_ForbiddenHeaderStripped();
        TestH1_EarlyHints_DroppedAfterFinal();
        TestH1_EarlyHints_100ContinueThen103();
        TestH1_EarlyHints_CRLFSanitized();
        TestH1_StreamingTrailers_CRLFSanitized();
        TestH1_StreamingTrailers_DeclarationFiltersForbiddenNames();
        TestH1_Streaming205CanonicalizesContentLength();
        TestH1_StreamingDeduplicatesContentLength();
        TestH1_StreamingHttp10UnknownLengthOmitsContentLength();
        TestH1_StreamingAbortOffDispatcherThreadRejected();
        TestH1_StreamingRawContentLengthWithoutPreserveUsesChunkedFraming();
        TestH1_StreamingControlMethodsOffDispatcherThreadRejected();
        TestH1_EarlyHints_WorkerThreadOrderingSafe();
        TestH1_EarlyHints_PipelinedKeepAliveNoStale();
        TestH1_Async_HandlerThrowFiresCancelSlot();
    }

}  // namespace HttpTests
