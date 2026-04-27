#pragma once

// Router phased-dispatch tests — H1 / H2 / WS-upgrade round-trip with
// a no-op async middleware installed (fast-path PASS through).

#include "test_framework.h"
#include "test_server_runner.h"
#include "http_test_client.h"
#include "http/http_server.h"
#include "http/http_router.h"
#include "http/http_request.h"
#include "http/http_response.h"
#include "http/http_status.h"
#include "config/server_config.h"

#include <atomic>
#include <chrono>
#include <cstring>
#include <netinet/in.h>
#include <poll.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

// Pull in the H2 test client (declared in http2_test.h).
#include "http2_test.h"

namespace RouterAsyncMiddlewareTests {

// No-op async middleware — tests install this directly so they don't
// depend on AUTH_NAMESPACE initialization.
inline HttpRouter::AsyncMiddleware NoopAsyncMiddleware() {
    return [](const HttpRequest&, HttpResponse&,
              std::shared_ptr<HttpRouter::AsyncPendingState> state) {
        state->SetSyncResult(HttpRouter::AsyncMiddlewareResult::PASS);
        state->MarkCompletedSync();
    };
}

// Bumped by the registered route on each invocation.
struct InvocationCounter {
    std::atomic<int> count{0};
};

// Test 1: H1 round-trip with no-op async middleware installed.
inline bool TestH1NoAsyncMiddlewareRoundTrip() {
    ServerConfig cfg;
    cfg.bind_host      = "127.0.0.1";
    cfg.bind_port      = 0;
    cfg.worker_threads = 2;

    HttpServer server(cfg);

    InvocationCounter counter;
    server.Get("/router-async/echo",
        [&counter](const HttpRequest&, HttpResponse& res) {
            counter.count.fetch_add(1, std::memory_order_relaxed);
            res.Status(HttpStatus::OK).Text("router-async-h1-ok");
        });

    server.PrependAsyncMiddleware(NoopAsyncMiddleware());

    TestServerRunner<HttpServer> runner(server);
    int port = runner.GetPort();

    std::string resp = TestHttpClient::HttpGet(port, "/router-async/echo", 3000);
    if (resp.empty()) return false;

    if (resp.find("HTTP/1.1 200") != 0) return false;
    if (resp.find("router-async-h1-ok") == std::string::npos) return false;
    if (counter.count.load(std::memory_order_relaxed) != 1) return false;

    return true;
}

// Test 2: H2 (h2c) round-trip with no-op async middleware installed.
inline bool TestH2NoAsyncMiddlewareRoundTrip() {
    ServerConfig cfg;
    cfg.bind_host      = "127.0.0.1";
    cfg.bind_port      = 0;
    cfg.worker_threads = 2;
    cfg.http2.enabled  = true;

    HttpServer server(cfg);

    InvocationCounter counter;
    server.Get("/router-async/echo",
        [&counter](const HttpRequest&, HttpResponse& res) {
            counter.count.fetch_add(1, std::memory_order_relaxed);
            res.Status(HttpStatus::OK).Text("router-async-h2-ok");
        });

    server.PrependAsyncMiddleware(NoopAsyncMiddleware());

    TestServerRunner<HttpServer> runner(server);
    int port = runner.GetPort();

    Http2Tests::Http2TestClient client;
    if (!client.Connect("127.0.0.1", port)) return false;

    auto resp = client.Get("/router-async/echo");
    client.Disconnect();

    if (resp.error)                    return false;
    if (resp.status != 200)            return false;
    if (resp.body.find("router-async-h2-ok") == std::string::npos) return false;
    if (counter.count.load(std::memory_order_relaxed) != 1) return false;

    return true;
}

// Test 3: WS upgrade — drive the handshake by hand, expect 101, then
// echo a single text frame to confirm the upgraded read/write loop.

namespace {

inline int ConnectLocalhost(int port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(static_cast<uint16_t>(port));
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

inline bool SendAllBytes(int fd, const void* buf, size_t len) {
    const char* p = static_cast<const char*>(buf);
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = ::send(fd, p + sent, len - sent, 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return false;
        }
        sent += static_cast<size_t>(n);
    }
    return true;
}

// Read until the HTTP header terminator ("\r\n\r\n"). Returns the full
// header block (no body), or empty string on timeout / error.
inline std::string ReadHttpHeaders(int fd, int timeout_ms = 3000) {
    std::string buf;
    auto deadline = std::chrono::steady_clock::now()
                  + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        pollfd pfd{fd, POLLIN, 0};
        int rc = ::poll(&pfd, 1, 100);
        if (rc < 0) { if (errno == EINTR) continue; return ""; }
        if (rc == 0) continue;
        char c;
        ssize_t n = ::recv(fd, &c, 1, 0);
        if (n <= 0) return "";
        buf += c;
        if (buf.size() >= 4 &&
            buf[buf.size()-4] == '\r' && buf[buf.size()-3] == '\n' &&
            buf[buf.size()-2] == '\r' && buf[buf.size()-1] == '\n') {
            return buf;
        }
    }
    return "";
}

// Read exactly `n` bytes (or fewer on EOF/timeout).
inline std::string ReadExactly(int fd, size_t n, int timeout_ms = 3000) {
    std::string out;
    out.reserve(n);
    auto deadline = std::chrono::steady_clock::now()
                  + std::chrono::milliseconds(timeout_ms);
    while (out.size() < n &&
           std::chrono::steady_clock::now() < deadline) {
        pollfd pfd{fd, POLLIN, 0};
        int rc = ::poll(&pfd, 1, 100);
        if (rc < 0) { if (errno == EINTR) continue; break; }
        if (rc == 0) continue;
        char buf[256];
        size_t want = std::min(sizeof(buf), n - out.size());
        ssize_t got = ::recv(fd, buf, want, 0);
        if (got <= 0) break;
        out.append(buf, static_cast<size_t>(got));
    }
    return out;
}

}  // namespace

inline bool TestWsUpgradeNoAsyncMiddleware() {
    ServerConfig cfg;
    cfg.bind_host      = "127.0.0.1";
    cfg.bind_port      = 0;
    cfg.worker_threads = 2;

    HttpServer server(cfg);

    // WS route that echoes the first text message received.
    server.WebSocket("/router-async/ws",
        [](WebSocketConnection& ws) {
            ws.OnMessage(
                [](WebSocketConnection& w, const std::string& msg, bool) {
                    w.SendText("echo:" + msg);
                });
        });

    server.PrependAsyncMiddleware(NoopAsyncMiddleware());

    TestServerRunner<HttpServer> runner(server);
    int port = runner.GetPort();

    int fd = ConnectLocalhost(port);
    if (fd < 0) return false;
    struct FdGuard { int f; ~FdGuard() { if (f >= 0) ::close(f); } };
    FdGuard g{fd};

    // Send WS upgrade. RFC 6455 §1.3 sample handshake key.
    static const char kClientKey[] = "dGhlIHNhbXBsZSBub25jZQ==";
    std::ostringstream req;
    req << "GET /router-async/ws HTTP/1.1\r\n"
        << "Host: localhost\r\n"
        << "Upgrade: websocket\r\n"
        << "Connection: Upgrade\r\n"
        << "Sec-WebSocket-Key: " << kClientKey << "\r\n"
        << "Sec-WebSocket-Version: 13\r\n"
        << "\r\n";
    std::string upgrade = req.str();
    if (!SendAllBytes(fd, upgrade.data(), upgrade.size())) return false;

    // Read 101 + headers.
    std::string hdrs = ReadHttpHeaders(fd, 3000);
    if (hdrs.empty()) return false;
    if (hdrs.find("HTTP/1.1 101") != 0) return false;

    // Sec-WebSocket-Accept must be present — proves the handshake reached
    // ContinueWsUpgradeAfterAuth and produced a valid 101 body.
    if (hdrs.find("Sec-WebSocket-Accept:") == std::string::npos) return false;

    // Send a WS text frame: "hi" (masked, RFC 6455 §5.3 client-to-server
    // masking required).
    std::string payload = "hi";
    unsigned char mask[4] = {0xAA, 0x55, 0xCC, 0x33};
    std::string frame;
    frame.push_back(static_cast<char>(0x81));   // FIN=1, opcode=text
    frame.push_back(static_cast<char>(0x80 | static_cast<unsigned char>(payload.size())));
    for (int i = 0; i < 4; ++i) frame.push_back(static_cast<char>(mask[i]));
    for (size_t i = 0; i < payload.size(); ++i) {
        frame.push_back(static_cast<char>(
            static_cast<unsigned char>(payload[i]) ^ mask[i % 4]));
    }
    if (!SendAllBytes(fd, frame.data(), frame.size())) return false;

    // Read the echo frame from the server. Server-to-client is unmasked.
    // Expected payload: "echo:hi" (7 bytes), header 0x81, length 0x07.
    std::string head = ReadExactly(fd, 2, 3000);
    if (head.size() != 2) return false;
    unsigned char b0 = static_cast<unsigned char>(head[0]);
    unsigned char b1 = static_cast<unsigned char>(head[1]);
    if (b0 != 0x81) return false;                   // FIN+text
    if ((b1 & 0x80) != 0) return false;             // server must NOT mask
    size_t plen = b1 & 0x7F;
    if (plen != 7) return false;                    // "echo:hi"
    std::string body = ReadExactly(fd, plen, 3000);
    if (body != "echo:hi") return false;

    return true;
}

// ---------------------------------------------------------------------------
// Test runner
// ---------------------------------------------------------------------------

inline void RunOne(const std::string& name, bool(*fn)()) {
    bool ok = false;
    try { ok = fn(); }
    catch (const std::exception& e) {
        TestFramework::RecordTest(name, false, e.what());
        return;
    } catch (...) {
        TestFramework::RecordTest(name, false, "unknown exception");
        return;
    }
    TestFramework::RecordTest(name, ok, ok ? "" : "test returned false");
}

inline void RunAllTests() {
    std::cout << "\n[Suite] RouterAsyncMiddleware (router phased dispatch)" << std::endl;
    RunOne("RouterAsync: H1 sync route round-trips with no-op adapter",
           TestH1NoAsyncMiddlewareRoundTrip);
    RunOne("RouterAsync: H2 sync route round-trips with no-op adapter",
           TestH2NoAsyncMiddlewareRoundTrip);
    RunOne("RouterAsync: WS upgrade handshake completes with no-op adapter",
           TestWsUpgradeNoAsyncMiddleware);
}

}  // namespace RouterAsyncMiddlewareTests
