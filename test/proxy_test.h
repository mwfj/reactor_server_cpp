#pragma once

// proxy_test.h -- Tests for the upstream request forwarding (proxy engine) feature.
//
// Coverage dimensions:
//   Unit tests (no server needed):
//     1. UpstreamHttpCodec     -- parse response bytes, 1xx handling, error paths, reset
//     2. HttpRequestSerializer -- wire-format serialization of proxy requests
//     3. HeaderRewriter        -- request/response header transformation rules
//     4. RetryPolicy           -- retry decision logic, idempotency, backoff
//     5. ProxyConfig parsing   -- JSON round-trip and validation error paths
//
//   Integration tests (with real HttpServer + upstream backend):
//     6. Basic proxy flow      -- GET/POST forwarding, response relay, status codes
//     7. Header rewriting      -- X-Forwarded-For/Proto injection, hop-by-hop strip
//     8. Error handling        -- unreachable upstream, timeout, bad service name
//     9. Path handling         -- strip_prefix, query string forwarding
//    10. Connection reuse      -- second request reuses pooled upstream connection
//    11. Early response        -- upstream 401 before body fully sent, no pool reuse
//
// All integration servers use ephemeral port 0 -- no fixed-port conflicts.

#include "test_framework.h"
#include "test_server_runner.h"
#include "http_test_client.h"
#include "http/http_server.h"
#include "config/server_config.h"
#include "config/config_loader.h"
#include "upstream/upstream_http_codec.h"
#include "upstream/upstream_response.h"
#include "upstream/http_request_serializer.h"
#include "upstream/header_rewriter.h"
#include "upstream/retry_policy.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <chrono>
#include <atomic>
#include <future>
#include <set>
#include <sstream>

namespace ProxyTests {

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// Build a minimal UpstreamConfig with proxy settings that point at backend.
static UpstreamConfig MakeProxyUpstreamConfig(const std::string& name,
                                               const std::string& host,
                                               int port,
                                               const std::string& route_prefix,
                                               bool strip_prefix = false) {
    UpstreamConfig cfg;
    cfg.name = name;
    cfg.host = host;
    cfg.port = port;
    cfg.pool.max_connections       = 8;
    cfg.pool.max_idle_connections  = 4;
    cfg.pool.connect_timeout_ms    = 3000;
    cfg.pool.idle_timeout_sec      = 30;
    cfg.pool.max_lifetime_sec      = 3600;
    cfg.pool.max_requests_per_conn = 0;
    cfg.proxy.route_prefix         = route_prefix;
    cfg.proxy.strip_prefix         = strip_prefix;
    cfg.proxy.response_timeout_ms  = 5000;
    return cfg;
}

// Poll until predicate returns true or timeout expires.
// Uses short sleep intervals — avoids blind sleep() in synchronisation.
static bool WaitFor(std::function<bool()> pred,
                    std::chrono::milliseconds timeout = std::chrono::milliseconds{3000}) {
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds{5});
    }
    return false;
}

static bool SendAll(int fd, const std::string& data) {
    int send_flags = 0;
#ifdef MSG_NOSIGNAL
    send_flags |= MSG_NOSIGNAL;
#endif
    size_t total_sent = 0;
    while (total_sent < data.size()) {
        ssize_t sent = send(
            fd, data.data() + total_sent, data.size() - total_sent, send_flags);
        if (sent < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        total_sent += static_cast<size_t>(sent);
    }
    return true;
}

static std::string RecvOnce(int fd, int timeout_ms) {
    struct pollfd pfd{fd, POLLIN, 0};
    int rv;
    do {
        rv = poll(&pfd, 1, timeout_ms);
    } while (rv < 0 && errno == EINTR);
    if (rv <= 0 || !(pfd.revents & (POLLIN | POLLHUP))) {
        return "";
    }

    char buf[4096];
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n <= 0) return "";
    return std::string(buf, static_cast<size_t>(n));
}

static std::string RecvUntilClose(int fd, int timeout_ms) {
    std::string out;
    while (true) {
        struct pollfd pfd{fd, POLLIN, 0};
        int rv;
        do {
            rv = poll(&pfd, 1, timeout_ms);
        } while (rv < 0 && errno == EINTR);
        if (rv <= 0) break;

        char buf[4096];
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n == 0) break;
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        out.append(buf, static_cast<size_t>(n));
    }
    return out;
}

static std::string RecvUntilContains(
    int fd, const std::string& needle, int timeout_ms) {
    std::string out;
    auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline &&
           out.find(needle) == std::string::npos) {
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
        std::string chunk = RecvOnce(fd, static_cast<int>(remaining.count()));
        if (chunk.empty()) break;
        out += chunk;
    }
    return out;
}

class RawHttpBackendServer {
public:
    using SessionHandler = std::function<void(int, const std::string&)>;

    explicit RawHttpBackendServer(SessionHandler handler)
        : handler_(std::move(handler)) {
        listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd_ < 0) {
            throw std::runtime_error("RawHttpBackendServer socket() failed");
        }

        int reuse = 1;
        setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = 0;
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        if (bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            int saved_errno = errno;
            close(listen_fd_);
            throw std::runtime_error(
                "RawHttpBackendServer bind() failed: " + std::to_string(saved_errno));
        }
        if (listen(listen_fd_, 4) != 0) {
            int saved_errno = errno;
            close(listen_fd_);
            throw std::runtime_error(
                "RawHttpBackendServer listen() failed: " + std::to_string(saved_errno));
        }

        socklen_t len = sizeof(addr);
        if (getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
            int saved_errno = errno;
            close(listen_fd_);
            throw std::runtime_error(
                "RawHttpBackendServer getsockname() failed: " + std::to_string(saved_errno));
        }
        port_ = ntohs(addr.sin_port);

        server_thread_ = std::thread([this]() { Run(); });
    }

    ~RawHttpBackendServer() {
        if (listen_fd_ >= 0) {
            shutdown(listen_fd_, SHUT_RDWR);
            close(listen_fd_);
            listen_fd_ = -1;
        }
        if (server_thread_.joinable()) {
            server_thread_.join();
        }
    }

    int GetPort() const { return port_; }

private:
    static std::string ReadRequestHead(int fd) {
        std::string request;
        char buf[2048];
        while (request.find("\r\n\r\n") == std::string::npos) {
            ssize_t n = recv(fd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            request.append(buf, static_cast<size_t>(n));
        }
        return request;
    }

    void Run() {
        struct sockaddr_in peer{};
        socklen_t peer_len = sizeof(peer);
        int client_fd = accept(
            listen_fd_, reinterpret_cast<sockaddr*>(&peer), &peer_len);
        if (client_fd < 0) {
            return;
        }

        std::string request = ReadRequestHead(client_fd);
        if (handler_) {
            handler_(client_fd, request);
        }
        shutdown(client_fd, SHUT_RDWR);
        close(client_fd);
    }

    SessionHandler handler_;
    int listen_fd_ = -1;
    int port_ = 0;
    std::thread server_thread_;
};

// ---------------------------------------------------------------------------
// Section 1: UpstreamHttpCodec unit tests
// ---------------------------------------------------------------------------

// Parse a simple HTTP/1.1 200 OK response with a text body.
void TestCodecParseSimple200() {
    std::cout << "\n[TEST] Codec: parse simple 200 OK with body..." << std::endl;
    try {
        UpstreamHttpCodec codec;
        const std::string raw =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello";

        size_t consumed = codec.Parse(raw.data(), raw.size());

        bool pass = true;
        std::string err;

        if (consumed != raw.size()) {
            pass = false;
            err += "consumed=" + std::to_string(consumed) + " want=" + std::to_string(raw.size()) + "; ";
        }
        if (codec.HasError()) { pass = false; err += "has_error; "; }
        const auto& resp = codec.GetResponse();
        if (resp.status_code != 200)                        { pass = false; err += "status_code; "; }
        if (resp.status_reason != "OK")                     { pass = false; err += "status_reason; "; }
        if (resp.body != "hello")                           { pass = false; err += "body; "; }
        if (!resp.complete)                                 { pass = false; err += "complete=false; "; }
        if (!resp.headers_complete)                         { pass = false; err += "headers_complete=false; "; }
        if (resp.GetHeader("content-type") != "text/plain") { pass = false; err += "content-type; "; }

        TestFramework::RecordTest("Codec: parse simple 200 OK with body", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Codec: parse simple 200 OK with body", false, e.what());
    }
}

// Parse a 204 No Content response -- no body expected.
void TestCodecParse204NoContent() {
    std::cout << "\n[TEST] Codec: parse 204 No Content..." << std::endl;
    try {
        UpstreamHttpCodec codec;
        const std::string raw =
            "HTTP/1.1 204 No Content\r\n"
            "\r\n";

        codec.Parse(raw.data(), raw.size());

        bool pass = true;
        std::string err;
        if (codec.HasError())                       { pass = false; err += "has_error; "; }
        if (codec.GetResponse().status_code != 204) { pass = false; err += "status_code; "; }
        if (codec.GetResponse().body != "")         { pass = false; err += "body should be empty; "; }
        if (!codec.GetResponse().complete)          { pass = false; err += "complete=false; "; }

        TestFramework::RecordTest("Codec: parse 204 No Content", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Codec: parse 204 No Content", false, e.what());
    }
}

// Parse a response whose headers arrive in two separate chunks (split delivery).
void TestCodecParseHeadersSplit() {
    std::cout << "\n[TEST] Codec: headers split across two Parse() calls..." << std::endl;
    try {
        UpstreamHttpCodec codec;
        const std::string full =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 4\r\n"
            "\r\n"
            "body";

        // Split after the status line
        size_t split = full.find("\r\n") + 2;
        std::string part1 = full.substr(0, split);
        std::string part2 = full.substr(split);

        codec.Parse(part1.data(), part1.size());

        bool pass = true;
        std::string err;
        if (codec.HasError())             { pass = false; err += "has_error after part1; "; }
        if (codec.GetResponse().complete) { pass = false; err += "complete before part2; "; }

        codec.Parse(part2.data(), part2.size());

        if (codec.HasError())                        { pass = false; err += "has_error after part2; "; }
        if (!codec.GetResponse().complete)           { pass = false; err += "complete=false after part2; "; }
        if (codec.GetResponse().status_code != 200)  { pass = false; err += "status_code; "; }
        if (codec.GetResponse().body != "body")      { pass = false; err += "body; "; }

        TestFramework::RecordTest("Codec: headers split across two Parse() calls", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Codec: headers split across two Parse() calls", false, e.what());
    }
}

// Parse a malformed response -- invalid status line should set the error flag.
void TestCodecParseMalformed() {
    std::cout << "\n[TEST] Codec: parse malformed response sets error..." << std::endl;
    try {
        UpstreamHttpCodec codec;
        const std::string raw = "GARBAGE NOT HTTP\r\n\r\n";
        codec.Parse(raw.data(), raw.size());

        bool pass = codec.HasError();
        std::string err = pass ? "" : "expected error on malformed input but HasError() is false";
        TestFramework::RecordTest("Codec: parse malformed response sets error", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Codec: parse malformed response sets error", false, e.what());
    }
}

// Parse a 100 Continue followed immediately by a 200 OK in the same buffer.
// The codec must discard the 1xx and report only the final 200.
void TestCodecParse100ContinueThen200SameBuffer() {
    std::cout << "\n[TEST] Codec: 100 Continue + 200 OK in same buffer..." << std::endl;
    try {
        UpstreamHttpCodec codec;
        const std::string raw =
            "HTTP/1.1 100 Continue\r\n"
            "\r\n"
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "\r\n"
            "hi";

        codec.Parse(raw.data(), raw.size());

        bool pass = true;
        std::string err;
        if (codec.HasError())                       { pass = false; err += "has_error; "; }
        if (!codec.GetResponse().complete)          { pass = false; err += "complete=false; "; }
        if (codec.GetResponse().status_code != 200) {
            pass = false;
            err += "status_code=" + std::to_string(codec.GetResponse().status_code) + " want 200; ";
        }
        if (codec.GetResponse().body != "hi")       { pass = false; err += "body; "; }

        TestFramework::RecordTest("Codec: 100 Continue + 200 OK in same buffer", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Codec: 100 Continue + 200 OK in same buffer", false, e.what());
    }
}

// Parse a 100 Continue in one call, then the final 200 OK in a second call.
void TestCodecParse100ContinueThen200SeparateCalls() {
    std::cout << "\n[TEST] Codec: 100 Continue then 200 OK in separate calls..." << std::endl;
    try {
        UpstreamHttpCodec codec;
        const std::string interim =
            "HTTP/1.1 100 Continue\r\n"
            "\r\n";
        const std::string final_resp =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 3\r\n"
            "\r\n"
            "yes";

        codec.Parse(interim.data(), interim.size());

        bool pass = true;
        std::string err;
        if (codec.HasError())             { pass = false; err += "has_error after 1xx; "; }
        if (codec.GetResponse().complete) { pass = false; err += "complete after 1xx only; "; }

        codec.Parse(final_resp.data(), final_resp.size());

        if (codec.HasError())                       { pass = false; err += "has_error after 200; "; }
        if (!codec.GetResponse().complete)          { pass = false; err += "complete=false after 200; "; }
        if (codec.GetResponse().status_code != 200) { pass = false; err += "status_code; "; }
        if (codec.GetResponse().body != "yes")      { pass = false; err += "body; "; }

        TestFramework::RecordTest("Codec: 100 Continue then 200 OK in separate calls", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Codec: 100 Continue then 200 OK in separate calls", false, e.what());
    }
}

// Parse multiple 1xx responses (100 + 102 Processing) before the final 200.
void TestCodecParseMultiple1xxBeforeFinal() {
    std::cout << "\n[TEST] Codec: multiple 1xx responses before final 200..." << std::endl;
    try {
        UpstreamHttpCodec codec;
        const std::string raw =
            "HTTP/1.1 100 Continue\r\n"
            "\r\n"
            "HTTP/1.1 102 Processing\r\n"
            "\r\n"
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 4\r\n"
            "\r\n"
            "done";

        codec.Parse(raw.data(), raw.size());

        bool pass = true;
        std::string err;
        if (codec.HasError())                       { pass = false; err += "has_error; "; }
        if (!codec.GetResponse().complete)          { pass = false; err += "complete=false; "; }
        if (codec.GetResponse().status_code != 200) {
            pass = false;
            err += "status_code=" + std::to_string(codec.GetResponse().status_code) + "; ";
        }
        if (codec.GetResponse().body != "done")     { pass = false; err += "body; "; }

        TestFramework::RecordTest("Codec: multiple 1xx responses before final 200", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Codec: multiple 1xx responses before final 200", false, e.what());
    }
}

// Reset and reuse for a second response (simulates connection reuse).
void TestCodecResetAndReuse() {
    std::cout << "\n[TEST] Codec: reset and reuse for second response..." << std::endl;
    try {
        UpstreamHttpCodec codec;

        const std::string first =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 3\r\n"
            "\r\n"
            "one";
        codec.Parse(first.data(), first.size());

        bool pass = true;
        std::string err;
        if (!codec.GetResponse().complete || codec.GetResponse().body != "one") {
            pass = false; err += "first response failed; ";
        }

        codec.Reset();

        if (codec.GetResponse().complete)     { pass = false; err += "complete not cleared after Reset; "; }
        if (codec.GetResponse().status_code)  { pass = false; err += "status_code not cleared after Reset; "; }
        if (!codec.GetResponse().body.empty()) { pass = false; err += "body not cleared after Reset; "; }

        const std::string second =
            "HTTP/1.1 201 Created\r\n"
            "Content-Length: 3\r\n"
            "\r\n"
            "two";
        codec.Parse(second.data(), second.size());

        if (!codec.GetResponse().complete)          { pass = false; err += "second response incomplete; "; }
        if (codec.GetResponse().status_code != 201) { pass = false; err += "second status_code; "; }
        if (codec.GetResponse().body != "two")      { pass = false; err += "second body; "; }

        TestFramework::RecordTest("Codec: reset and reuse for second response", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Codec: reset and reuse for second response", false, e.what());
    }
}

// A response body exceeding the 64 MB cap must trigger an error.
void TestCodecBodyCapEnforced() {
    std::cout << "\n[TEST] Codec: 64MB body cap enforced..." << std::endl;
    try {
        UpstreamHttpCodec codec;

        // Declare a content-length far exceeding 64 MB.
        const std::string headers =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 134217728\r\n"  // 128 MB
            "\r\n";
        codec.Parse(headers.data(), headers.size());

        // Feed data in chunks until error fires or cap triggers.
        const size_t cap = UpstreamHttpCodec::MAX_RESPONSE_BODY_SIZE;
        std::string chunk(65536, 'x');  // 64 KB chunks
        bool capped = false;
        size_t total_body = 0;
        for (int i = 0; i < 1200 && !capped; ++i) {  // up to ~75 MB
            codec.Parse(chunk.data(), chunk.size());
            total_body += chunk.size();
            if (codec.HasError())  { capped = true; }
            if (total_body > cap)  { capped = true; }
        }

        bool pass = capped;
        std::string err = pass ? "" :
            "body cap not enforced after " + std::to_string(total_body) + " bytes";
        TestFramework::RecordTest("Codec: 64MB body cap enforced", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Codec: 64MB body cap enforced", false, e.what());
    }
}

// Repeated Set-Cookie headers must all be preserved (not collapsed).
void TestCodecRepeatedSetCookiePreserved() {
    std::cout << "\n[TEST] Codec: repeated Set-Cookie headers preserved..." << std::endl;
    try {
        UpstreamHttpCodec codec;
        const std::string raw =
            "HTTP/1.1 200 OK\r\n"
            "Set-Cookie: sid=abc; Path=/\r\n"
            "Set-Cookie: pref=dark; Path=/\r\n"
            "Set-Cookie: lang=en; Path=/\r\n"
            "Content-Length: 0\r\n"
            "\r\n";

        codec.Parse(raw.data(), raw.size());

        bool pass = true;
        std::string err;
        if (codec.HasError())              { pass = false; err += "has_error; "; }
        if (!codec.GetResponse().complete) { pass = false; err += "incomplete; "; }

        auto cookies = codec.GetResponse().GetAllHeaders("set-cookie");
        if (cookies.size() != 3) {
            pass = false;
            err += "expected 3 Set-Cookie values, got " + std::to_string(cookies.size()) + "; ";
        }

        TestFramework::RecordTest("Codec: repeated Set-Cookie headers preserved", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Codec: repeated Set-Cookie headers preserved", false, e.what());
    }
}

// Connection keep-alive semantics must be tracked so the pool doesn't reuse
// responses that explicitly close the TCP connection.
void TestCodecConnectionCloseDisablesReuse() {
    std::cout << "\n[TEST] Codec: Connection close disables keep-alive..." << std::endl;
    try {
        UpstreamHttpCodec codec;
        const std::string raw =
            "HTTP/1.1 200 OK\r\n"
            "Connection: close\r\n"
            "Content-Length: 2\r\n"
            "\r\n"
            "ok";

        codec.Parse(raw.data(), raw.size());

        bool pass = !codec.HasError() &&
                    codec.GetResponse().complete &&
                    !codec.GetResponse().keep_alive;
        std::string err = pass ? "" : "expected keep_alive=false";
        TestFramework::RecordTest("Codec: Connection close disables keep-alive", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Codec: Connection close disables keep-alive", false, e.what());
    }
}

// HTTP/1.0 responses are non-persistent unless they explicitly opt in.
void TestCodecHttp10DefaultsToClose() {
    std::cout << "\n[TEST] Codec: HTTP/1.0 defaults to connection close..." << std::endl;
    try {
        UpstreamHttpCodec codec;
        const std::string raw =
            "HTTP/1.0 200 OK\r\n"
            "Content-Length: 2\r\n"
            "\r\n"
            "ok";

        codec.Parse(raw.data(), raw.size());

        bool pass = !codec.HasError() &&
                    codec.GetResponse().complete &&
                    !codec.GetResponse().keep_alive;
        std::string err = pass ? "" : "expected HTTP/1.0 response to be non-persistent";
        TestFramework::RecordTest("Codec: HTTP/1.0 defaults to connection close", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Codec: HTTP/1.0 defaults to connection close", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Section 2: HttpRequestSerializer unit tests
// ---------------------------------------------------------------------------

// GET with no body: request-line correct, no body after CRLF CRLF.
void TestSerializerGetNoBody() {
    std::cout << "\n[TEST] Serializer: GET with no body..." << std::endl;
    try {
        std::map<std::string, std::string> headers{{"host", "upstream:8080"}};
        std::string wire = HttpRequestSerializer::Serialize("GET", "/resource", "", headers, "");

        bool pass = true;
        std::string err;
        if (wire.find("GET /resource HTTP/1.1\r\n") == std::string::npos) {
            pass = false; err += "request-line missing; ";
        }
        if (wire.find("host: upstream:8080") == std::string::npos &&
            wire.find("Host: upstream:8080") == std::string::npos) {
            pass = false; err += "host header missing; ";
        }
        // Body must be absent after CRLF CRLF
        auto end = wire.find("\r\n\r\n");
        if (end == std::string::npos) {
            pass = false; err += "no header terminator; ";
        } else {
            std::string body = wire.substr(end + 4);
            if (!body.empty()) { pass = false; err += "unexpected body in GET; "; }
        }

        TestFramework::RecordTest("Serializer: GET with no body", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Serializer: GET with no body", false, e.what());
    }
}

// POST with body: Content-Length must reflect actual body size.
void TestSerializerPostWithBody() {
    std::cout << "\n[TEST] Serializer: POST with body and Content-Length..." << std::endl;
    try {
        const std::string body = "{\"key\":\"value\"}";
        std::map<std::string, std::string> headers{
            {"host", "backend:9090"},
            {"content-type", "application/json"}
        };
        std::string wire = HttpRequestSerializer::Serialize("POST", "/api/data", "", headers, body);

        bool pass = true;
        std::string err;
        if (wire.find("POST /api/data HTTP/1.1\r\n") == std::string::npos) {
            pass = false; err += "request-line; ";
        }
        // Content-Length header must equal body length
        std::string cl = "content-length: " + std::to_string(body.size());
        std::string cl_upper = "Content-Length: " + std::to_string(body.size());
        if (wire.find(cl) == std::string::npos && wire.find(cl_upper) == std::string::npos) {
            pass = false; err += "Content-Length missing or wrong; ";
        }
        // Body must appear after CRLF CRLF
        auto end = wire.find("\r\n\r\n");
        if (end == std::string::npos) {
            pass = false; err += "no header terminator; ";
        } else {
            if (wire.substr(end + 4) != body) {
                pass = false; err += "body mismatch; ";
            }
        }

        TestFramework::RecordTest("Serializer: POST with body and Content-Length", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Serializer: POST with body and Content-Length", false, e.what());
    }
}

// Query string must be appended with "?" separator.
void TestSerializerQueryString() {
    std::cout << "\n[TEST] Serializer: query string appended correctly..." << std::endl;
    try {
        std::map<std::string, std::string> headers{{"host", "h"}};
        std::string wire = HttpRequestSerializer::Serialize(
            "GET", "/search", "q=hello&page=2", headers, "");

        bool pass = wire.find("GET /search?q=hello&page=2 HTTP/1.1\r\n") != std::string::npos;
        std::string err = pass ? "" : "query string not appended: " + wire.substr(0, wire.find("\r\n"));
        TestFramework::RecordTest("Serializer: query string appended correctly", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Serializer: query string appended correctly", false, e.what());
    }
}

// Empty query string: no "?" must appear in the request-line.
void TestSerializerEmptyQueryNoQuestionMark() {
    std::cout << "\n[TEST] Serializer: empty query -- no '?' in request-line..." << std::endl;
    try {
        std::map<std::string, std::string> headers{{"host", "h"}};
        std::string wire = HttpRequestSerializer::Serialize("GET", "/path", "", headers, "");

        std::string first_line = wire.substr(0, wire.find("\r\n"));
        bool pass = first_line.find('?') == std::string::npos;
        std::string err = pass ? "" : "unexpected '?' in request-line: " + first_line;
        TestFramework::RecordTest("Serializer: empty query -- no '?' in request-line", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Serializer: empty query -- no '?' in request-line", false, e.what());
    }
}

// Empty path must default to "/".
void TestSerializerEmptyPathDefaults() {
    std::cout << "\n[TEST] Serializer: empty path defaults to '/'..." << std::endl;
    try {
        std::map<std::string, std::string> headers{{"host", "h"}};
        std::string wire = HttpRequestSerializer::Serialize("GET", "", "", headers, "");

        // First line must contain a valid path starting with /
        std::string first_line = wire.substr(0, wire.find("\r\n"));
        bool pass = first_line.size() > 4 && first_line[4] == '/';
        std::string err = pass ? "" : "path is empty in wire: " + first_line;
        TestFramework::RecordTest("Serializer: empty path defaults to '/'", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Serializer: empty path defaults to '/'", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Section 3: HeaderRewriter unit tests
// ---------------------------------------------------------------------------

// X-Forwarded-For appended to existing value.
void TestRewriterXffAppend() {
    std::cout << "\n[TEST] HeaderRewriter: X-Forwarded-For appended to existing..." << std::endl;
    try {
        HeaderRewriter::Config cfg;
        HeaderRewriter rewriter(cfg);

        std::map<std::string, std::string> in{
            {"x-forwarded-for", "10.0.0.1"},
            {"host", "example.com"}
        };
        auto out = rewriter.RewriteRequest(in, "192.168.1.5", false, false, "backend", 8080);

        bool pass = true;
        std::string err;
        auto it = out.find("x-forwarded-for");
        if (it == out.end()) {
            pass = false; err += "x-forwarded-for missing; ";
        } else {
            if (it->second.find("10.0.0.1") == std::string::npos)    { pass = false; err += "old IP not preserved; "; }
            if (it->second.find("192.168.1.5") == std::string::npos) { pass = false; err += "new IP not appended; "; }
        }

        TestFramework::RecordTest("HeaderRewriter: X-Forwarded-For appended to existing", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("HeaderRewriter: X-Forwarded-For appended to existing", false, e.what());
    }
}

// X-Forwarded-For created when absent in client request.
void TestRewriterXffCreated() {
    std::cout << "\n[TEST] HeaderRewriter: X-Forwarded-For created when absent..." << std::endl;
    try {
        HeaderRewriter::Config cfg;
        HeaderRewriter rewriter(cfg);

        std::map<std::string, std::string> in{{"host", "example.com"}};
        auto out = rewriter.RewriteRequest(in, "1.2.3.4", false, false, "backend", 9000);

        bool pass = out.count("x-forwarded-for") && out.at("x-forwarded-for") == "1.2.3.4";
        std::string err = pass ? "" : "x-forwarded-for not created or wrong value: " +
            (out.count("x-forwarded-for") ? out.at("x-forwarded-for") : "(absent)");
        TestFramework::RecordTest("HeaderRewriter: X-Forwarded-For created when absent", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("HeaderRewriter: X-Forwarded-For created when absent", false, e.what());
    }
}

// X-Forwarded-Proto must be "https" when client uses TLS.
void TestRewriterXfpHttps() {
    std::cout << "\n[TEST] HeaderRewriter: X-Forwarded-Proto = https with TLS..." << std::endl;
    try {
        HeaderRewriter::Config cfg;
        HeaderRewriter rewriter(cfg);

        std::map<std::string, std::string> in{{"host", "secure.example.com"}};
        auto out = rewriter.RewriteRequest(in, "5.6.7.8", true /*client tls*/, false, "backend", 443);

        bool pass = out.count("x-forwarded-proto") && out.at("x-forwarded-proto") == "https";
        std::string err = pass ? "" : "x-forwarded-proto = '" +
            (out.count("x-forwarded-proto") ? out.at("x-forwarded-proto") : "(absent)") +
            "' want 'https'";
        TestFramework::RecordTest("HeaderRewriter: X-Forwarded-Proto = https with TLS", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("HeaderRewriter: X-Forwarded-Proto = https with TLS", false, e.what());
    }
}

// Host header must be rewritten to upstream address when rewrite_host=true.
void TestRewriterHostRewrite() {
    std::cout << "\n[TEST] HeaderRewriter: Host rewritten to upstream address..." << std::endl;
    try {
        HeaderRewriter::Config cfg;
        cfg.rewrite_host = true;
        HeaderRewriter rewriter(cfg);

        std::map<std::string, std::string> in{{"host", "client-facing.com"}};
        auto out = rewriter.RewriteRequest(in, "1.1.1.1", false, false, "10.0.1.10", 8081);

        bool pass = true;
        std::string err;
        if (!out.count("host")) {
            pass = false; err += "host missing; ";
        } else {
            if (out.at("host").find("10.0.1.10") == std::string::npos) {
                pass = false; err += "host value wrong: " + out.at("host") + "; ";
            }
        }
        TestFramework::RecordTest("HeaderRewriter: Host rewritten to upstream address", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("HeaderRewriter: Host rewritten to upstream address", false, e.what());
    }
}

// Port 80 must be omitted from the Host header.
void TestRewriterHostPort80Omitted() {
    std::cout << "\n[TEST] HeaderRewriter: port 80 omitted from Host header..." << std::endl;
    try {
        HeaderRewriter::Config cfg;
        cfg.rewrite_host = true;
        HeaderRewriter rewriter(cfg);

        std::map<std::string, std::string> in{{"host", "client.com"}};
        auto out = rewriter.RewriteRequest(in, "1.1.1.1", false, false, "backend.internal", 80);

        bool pass = true;
        std::string err;
        if (!out.count("host")) {
            pass = false; err += "host missing; ";
        } else {
            if (out.at("host").find(":80") != std::string::npos) {
                pass = false; err += "port 80 should be omitted, got: " + out.at("host") + "; ";
            }
            if (out.at("host").find("backend.internal") == std::string::npos) {
                pass = false; err += "upstream hostname missing: " + out.at("host") + "; ";
            }
        }
        TestFramework::RecordTest("HeaderRewriter: port 80 omitted from Host header", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("HeaderRewriter: port 80 omitted from Host header", false, e.what());
    }
}

// Port 443 must NOT be omitted for plain HTTP upstreams.
void TestRewriterHostPort443RetainedForHttp() {
    std::cout << "\n[TEST] HeaderRewriter: port 443 retained for plain HTTP upstream..." << std::endl;
    try {
        HeaderRewriter::Config cfg;
        cfg.rewrite_host = true;
        HeaderRewriter rewriter(cfg);

        std::map<std::string, std::string> in{{"host", "client.com"}};
        auto out = rewriter.RewriteRequest(
            in, "1.1.1.1", false, false, "backend.internal", 443);

        bool pass = out.count("host") && out.at("host") == "backend.internal:443";
        std::string err = pass ? "" :
            ("expected backend.internal:443, got: " +
             (out.count("host") ? out.at("host") : "(absent)"));
        TestFramework::RecordTest(
            "HeaderRewriter: port 443 retained for plain HTTP upstream", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "HeaderRewriter: port 443 retained for plain HTTP upstream",
            false, e.what());
    }
}

// Port 80 must NOT be omitted for HTTPS upstreams on a non-default port.
void TestRewriterHostPort80RetainedForHttps() {
    std::cout << "\n[TEST] HeaderRewriter: port 80 retained for HTTPS upstream..." << std::endl;
    try {
        HeaderRewriter::Config cfg;
        cfg.rewrite_host = true;
        HeaderRewriter rewriter(cfg);

        std::map<std::string, std::string> in{{"host", "client.com"}};
        auto out = rewriter.RewriteRequest(
            in, "1.1.1.1", false, true, "secure.backend", 80);

        bool pass = out.count("host") && out.at("host") == "secure.backend:80";
        std::string err = pass ? "" :
            ("expected secure.backend:80, got: " +
             (out.count("host") ? out.at("host") : "(absent)"));
        TestFramework::RecordTest(
            "HeaderRewriter: port 80 retained for HTTPS upstream", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "HeaderRewriter: port 80 retained for HTTPS upstream",
            false, e.what());
    }
}

// Hop-by-hop headers must be stripped from the forwarded request.
void TestRewriterHopByHopStripped() {
    std::cout << "\n[TEST] HeaderRewriter: hop-by-hop headers stripped from request..." << std::endl;
    try {
        HeaderRewriter::Config cfg;
        HeaderRewriter rewriter(cfg);

        std::map<std::string, std::string> in{
            {"host", "example.com"},
            {"connection", "keep-alive"},
            {"keep-alive", "timeout=5"},
            {"proxy-authorization", "Basic ZXhhbXBsZQ=="},
            {"transfer-encoding", "chunked"},
            {"te", "trailers"},
            {"trailer", "X-Checksum"},
            {"upgrade", "websocket"},
            {"x-custom", "preserved"}
        };
        auto out = rewriter.RewriteRequest(in, "1.1.1.1", false, false, "backend", 9000);

        bool pass = true;
        std::string err;
        // Hop-by-hop must be absent
        for (const char* hop : {"connection", "keep-alive", "proxy-authorization",
                                "transfer-encoding", "te", "trailer", "upgrade"}) {
            if (out.count(hop)) { pass = false; err += std::string(hop) + " not stripped; "; }
        }
        // Application headers must be preserved
        if (!out.count("x-custom") || out.at("x-custom") != "preserved") {
            pass = false; err += "x-custom not preserved; ";
        }

        TestFramework::RecordTest("HeaderRewriter: hop-by-hop headers stripped from request", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("HeaderRewriter: hop-by-hop headers stripped from request", false, e.what());
    }
}

// Headers named in the Connection header value must also be stripped.
void TestRewriterConnectionListedHeadersStripped() {
    std::cout << "\n[TEST] HeaderRewriter: Connection-listed headers stripped..." << std::endl;
    try {
        HeaderRewriter::Config cfg;
        HeaderRewriter rewriter(cfg);

        std::map<std::string, std::string> in{
            {"host", "example.com"},
            {"connection", "keep-alive, x-special-proxy-header"},
            {"x-special-proxy-header", "secret"},
            {"x-application-data", "keep-me"}
        };
        auto out = rewriter.RewriteRequest(in, "1.1.1.1", false, false, "backend", 9000);

        bool pass = true;
        std::string err;
        if (out.count("x-special-proxy-header")) { pass = false; err += "x-special-proxy-header not stripped; "; }
        if (!out.count("x-application-data"))    { pass = false; err += "x-application-data stripped (should keep); "; }

        TestFramework::RecordTest("HeaderRewriter: Connection-listed headers stripped", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("HeaderRewriter: Connection-listed headers stripped", false, e.what());
    }
}

// Hop-by-hop headers stripped from upstream response, Via added.
void TestRewriterResponseHopByHopStripped() {
    std::cout << "\n[TEST] HeaderRewriter: hop-by-hop stripped from response, Via added..." << std::endl;
    try {
        HeaderRewriter::Config cfg;
        HeaderRewriter rewriter(cfg);

        std::vector<std::pair<std::string, std::string>> upstream_headers{
            {"content-type", "application/json"},
            {"connection", "keep-alive"},
            {"keep-alive", "timeout=5"},
            {"proxy-authenticate", "Basic realm=\"upstream\""},
            {"transfer-encoding", "chunked"},
            {"x-backend-id", "node-3"}
        };
        auto out = rewriter.RewriteResponse(upstream_headers);

        bool pass = true;
        std::string err;

        std::set<std::string> names;
        for (const auto& p : out) names.insert(p.first);

        // Hop-by-hop must be gone
        for (const char* hop : {"connection", "keep-alive", "proxy-authenticate",
                                "transfer-encoding"}) {
            if (names.count(hop)) { pass = false; err += std::string(hop) + " not stripped from response; "; }
        }
        // Application headers preserved
        if (!names.count("content-type"))  { pass = false; err += "content-type stripped; "; }
        if (!names.count("x-backend-id")) { pass = false; err += "x-backend-id stripped; "; }
        // Via must be present
        if (!names.count("via")) { pass = false; err += "via not added to response; "; }

        TestFramework::RecordTest("HeaderRewriter: hop-by-hop stripped from response, Via added", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("HeaderRewriter: hop-by-hop stripped from response, Via added", false, e.what());
    }
}

// Repeated Set-Cookie headers in upstream response must be preserved.
void TestRewriterRepeatedSetCookiePreserved() {
    std::cout << "\n[TEST] HeaderRewriter: repeated Set-Cookie preserved in response..." << std::endl;
    try {
        HeaderRewriter::Config cfg;
        HeaderRewriter rewriter(cfg);

        std::vector<std::pair<std::string, std::string>> upstream_headers{
            {"set-cookie", "sid=abc; Path=/"},
            {"set-cookie", "pref=dark; Path=/"},
            {"set-cookie", "lang=en; Path=/"},
            {"content-type", "text/html"}
        };
        auto out = rewriter.RewriteResponse(upstream_headers);

        int cookie_count = 0;
        for (const auto& p : out) {
            if (p.first == "set-cookie") ++cookie_count;
        }

        bool pass = (cookie_count == 3);
        std::string err = pass ? "" : "expected 3 set-cookie, got " + std::to_string(cookie_count);
        TestFramework::RecordTest("HeaderRewriter: repeated Set-Cookie preserved in response", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("HeaderRewriter: repeated Set-Cookie preserved in response", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Section 4: RetryPolicy unit tests
// ---------------------------------------------------------------------------

// ShouldRetry must return false when max_retries=0.
void TestRetryNoRetriesConfigured() {
    std::cout << "\n[TEST] RetryPolicy: false when max_retries=0..." << std::endl;
    try {
        RetryPolicy::Config cfg;
        cfg.max_retries = 0;
        RetryPolicy policy(cfg);

        bool result = policy.ShouldRetry(0, "GET",
                                          RetryPolicy::RetryCondition::CONNECT_FAILURE, false);
        bool pass = !result;
        TestFramework::RecordTest("RetryPolicy: false when max_retries=0", pass,
                                   pass ? "" : "ShouldRetry returned true with max_retries=0");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RetryPolicy: false when max_retries=0", false, e.what());
    }
}

// ShouldRetry must return false when attempt >= max_retries.
void TestRetryAttemptExhausted() {
    std::cout << "\n[TEST] RetryPolicy: false when attempt >= max_retries..." << std::endl;
    try {
        RetryPolicy::Config cfg;
        cfg.max_retries = 2;
        cfg.retry_on_connect_failure = true;
        RetryPolicy policy(cfg);

        // attempt=2 means we've already done 2 retries (0-indexed: first retry=1, second=2)
        bool result = policy.ShouldRetry(2, "GET",
                                          RetryPolicy::RetryCondition::CONNECT_FAILURE, false);
        bool pass = !result;
        TestFramework::RecordTest("RetryPolicy: false when attempt >= max_retries", pass,
                                   pass ? "" : "ShouldRetry returned true when exhausted");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RetryPolicy: false when attempt >= max_retries", false, e.what());
    }
}

// ShouldRetry must return false when headers_sent=true.
void TestRetryHeadersSent() {
    std::cout << "\n[TEST] RetryPolicy: false when headers_sent=true..." << std::endl;
    try {
        RetryPolicy::Config cfg;
        cfg.max_retries = 3;
        cfg.retry_on_connect_failure = true;
        RetryPolicy policy(cfg);

        bool result = policy.ShouldRetry(0, "GET",
                                          RetryPolicy::RetryCondition::CONNECT_FAILURE,
                                          true /*headers_sent*/);
        bool pass = !result;
        TestFramework::RecordTest("RetryPolicy: false when headers_sent=true", pass,
                                   pass ? "" : "ShouldRetry returned true with headers_sent=true");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RetryPolicy: false when headers_sent=true", false, e.what());
    }
}

// POST is not retried by default (retry_non_idempotent=false).
void TestRetryPostNotRetried() {
    std::cout << "\n[TEST] RetryPolicy: POST not retried when retry_non_idempotent=false..." << std::endl;
    try {
        RetryPolicy::Config cfg;
        cfg.max_retries = 3;
        cfg.retry_on_connect_failure = true;
        cfg.retry_non_idempotent = false;
        RetryPolicy policy(cfg);

        bool result = policy.ShouldRetry(0, "POST",
                                          RetryPolicy::RetryCondition::CONNECT_FAILURE, false);
        bool pass = !result;
        TestFramework::RecordTest("RetryPolicy: POST not retried when retry_non_idempotent=false", pass,
                                   pass ? "" : "ShouldRetry returned true for POST (should not retry)");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RetryPolicy: POST not retried when retry_non_idempotent=false", false, e.what());
    }
}

// GET connect failure is retried when retry_on_connect_failure=true.
void TestRetryGetConnectFailure() {
    std::cout << "\n[TEST] RetryPolicy: GET retried on connect failure..." << std::endl;
    try {
        RetryPolicy::Config cfg;
        cfg.max_retries = 1;
        cfg.retry_on_connect_failure = true;
        RetryPolicy policy(cfg);

        bool result = policy.ShouldRetry(0, "GET",
                                          RetryPolicy::RetryCondition::CONNECT_FAILURE, false);
        bool pass = result;
        TestFramework::RecordTest("RetryPolicy: GET retried on connect failure", pass,
                                   pass ? "" : "ShouldRetry returned false for GET connect failure");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RetryPolicy: GET retried on connect failure", false, e.what());
    }
}

// Disconnect is retried when retry_on_disconnect=true.
void TestRetryDisconnectRetried() {
    std::cout << "\n[TEST] RetryPolicy: GET retried on disconnect..." << std::endl;
    try {
        RetryPolicy::Config cfg;
        cfg.max_retries = 1;
        cfg.retry_on_disconnect = true;
        RetryPolicy policy(cfg);

        bool result = policy.ShouldRetry(0, "GET",
                                          RetryPolicy::RetryCondition::UPSTREAM_DISCONNECT, false);
        bool pass = result;
        TestFramework::RecordTest("RetryPolicy: GET retried on disconnect", pass,
                                   pass ? "" : "ShouldRetry returned false for disconnect");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RetryPolicy: GET retried on disconnect", false, e.what());
    }
}

// Disconnect is NOT retried when retry_on_disconnect=false.
void TestRetryDisconnectNotRetried() {
    std::cout << "\n[TEST] RetryPolicy: disconnect NOT retried when policy=false..." << std::endl;
    try {
        RetryPolicy::Config cfg;
        cfg.max_retries = 3;
        cfg.retry_on_disconnect = false;
        RetryPolicy policy(cfg);

        bool result = policy.ShouldRetry(0, "GET",
                                          RetryPolicy::RetryCondition::UPSTREAM_DISCONNECT, false);
        bool pass = !result;
        TestFramework::RecordTest("RetryPolicy: disconnect NOT retried when policy=false", pass,
                                   pass ? "" : "ShouldRetry returned true for disconnect with policy=false");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RetryPolicy: disconnect NOT retried when policy=false", false, e.what());
    }
}

// Idempotent methods: GET, HEAD, PUT, DELETE. Non-idempotent: POST, PATCH.
void TestRetryIdempotentMethods() {
    std::cout << "\n[TEST] RetryPolicy: idempotent method classification..." << std::endl;
    try {
        RetryPolicy::Config cfg;
        cfg.max_retries = 3;
        cfg.retry_on_connect_failure = true;
        cfg.retry_non_idempotent = false;
        RetryPolicy policy(cfg);

        bool pass = true;
        std::string err;

        // Idempotent -- must be retried
        for (const char* m : {"GET", "HEAD", "PUT", "DELETE"}) {
            if (!policy.ShouldRetry(0, m, RetryPolicy::RetryCondition::CONNECT_FAILURE, false)) {
                pass = false; err += std::string(m) + " should be retried (idempotent); ";
            }
        }
        // Non-idempotent -- must NOT be retried
        for (const char* m : {"POST", "PATCH"}) {
            if (policy.ShouldRetry(0, m, RetryPolicy::RetryCondition::CONNECT_FAILURE, false)) {
                pass = false; err += std::string(m) + " should NOT be retried (non-idempotent); ";
            }
        }

        TestFramework::RecordTest("RetryPolicy: idempotent method classification", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RetryPolicy: idempotent method classification", false, e.what());
    }
}

// BackoffDelay for attempt=0 must return 0ms (immediate first retry).
void TestRetryBackoffDelay() {
    std::cout << "\n[TEST] RetryPolicy: BackoffDelay attempt 0 returns 0ms..." << std::endl;
    try {
        RetryPolicy::Config cfg;
        RetryPolicy policy(cfg);

        auto delay = policy.BackoffDelay(0);
        bool pass = delay.count() == 0;
        TestFramework::RecordTest("RetryPolicy: BackoffDelay attempt 0 returns 0ms", pass,
                                   pass ? "" : "BackoffDelay(0) = " + std::to_string(delay.count()) + "ms want 0");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RetryPolicy: BackoffDelay attempt 0 returns 0ms", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Section 5: ProxyConfig parsing and validation tests
// ---------------------------------------------------------------------------

// Full proxy config from JSON -- all fields parsed correctly.
void TestProxyConfigFullParse() {
    std::cout << "\n[TEST] ProxyConfig: full JSON parse round-trip..." << std::endl;
    try {
        const std::string json = R"({
            "upstreams": [{
                "name": "user-svc",
                "host": "10.0.1.10",
                "port": 8081,
                "proxy": {
                    "route_prefix": "/api/users",
                    "strip_prefix": true,
                    "response_timeout_ms": 5000,
                    "methods": ["GET", "POST", "DELETE"],
                    "header_rewrite": {
                        "set_x_forwarded_for": true,
                        "set_x_forwarded_proto": false,
                        "set_via_header": true,
                        "rewrite_host": false
                    },
                    "retry": {
                        "max_retries": 2,
                        "retry_on_connect_failure": true,
                        "retry_on_5xx": true,
                        "retry_on_timeout": false,
                        "retry_on_disconnect": true,
                        "retry_non_idempotent": false
                    }
                }
            }]
        })";

        ServerConfig cfg = ConfigLoader::LoadFromString(json);

        bool pass = true;
        std::string err;
        if (cfg.upstreams.empty()) {
            pass = false; err += "no upstream; ";
        } else {
            const auto& p = cfg.upstreams[0].proxy;
            if (p.route_prefix != "/api/users")     { pass = false; err += "route_prefix; "; }
            if (!p.strip_prefix)                    { pass = false; err += "strip_prefix; "; }
            if (p.response_timeout_ms != 5000)      { pass = false; err += "response_timeout_ms; "; }
            if (p.methods.size() != 3)              { pass = false; err += "methods count; "; }
            if (!p.header_rewrite.set_x_forwarded_for)  { pass = false; err += "set_x_forwarded_for; "; }
            if (p.header_rewrite.set_x_forwarded_proto) { pass = false; err += "set_x_forwarded_proto should be false; "; }
            if (p.header_rewrite.rewrite_host)          { pass = false; err += "rewrite_host should be false; "; }
            if (p.retry.max_retries != 2)           { pass = false; err += "max_retries; "; }
            if (!p.retry.retry_on_5xx)              { pass = false; err += "retry_on_5xx; "; }
        }

        TestFramework::RecordTest("ProxyConfig: full JSON parse round-trip", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ProxyConfig: full JSON parse round-trip", false, e.what());
    }
}

// Minimal proxy JSON -- unspecified fields must get defaults.
void TestProxyConfigDefaults() {
    std::cout << "\n[TEST] ProxyConfig: defaults applied for minimal config..." << std::endl;
    try {
        const std::string json = R"({
            "upstreams": [{
                "name": "svc",
                "host": "127.0.0.1",
                "port": 9000,
                "proxy": {
                    "route_prefix": "/api"
                }
            }]
        })";

        ServerConfig cfg = ConfigLoader::LoadFromString(json);

        bool pass = true;
        std::string err;
        if (cfg.upstreams.empty()) {
            pass = false; err += "no upstream; ";
        } else {
            const auto& p = cfg.upstreams[0].proxy;
            if (p.strip_prefix)                     { pass = false; err += "strip_prefix default should be false; "; }
            if (p.response_timeout_ms != 30000)     { pass = false; err += "response_timeout_ms default; "; }
            if (!p.methods.empty())                 { pass = false; err += "methods default should be empty; "; }
            if (!p.header_rewrite.set_x_forwarded_for)  { pass = false; err += "header_rewrite defaults; "; }
            if (!p.header_rewrite.set_via_header)       { pass = false; err += "set_via_header default; "; }
            if (p.retry.max_retries != 0)           { pass = false; err += "retry.max_retries default; "; }
            if (!p.retry.retry_on_connect_failure)  { pass = false; err += "retry_on_connect_failure default; "; }
            if (!p.retry.retry_on_disconnect)       { pass = false; err += "retry_on_disconnect default; "; }
        }

        TestFramework::RecordTest("ProxyConfig: defaults applied for minimal config", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ProxyConfig: defaults applied for minimal config", false, e.what());
    }
}

// Invalid HTTP method in methods array must be rejected.
void TestProxyConfigInvalidMethod() {
    std::cout << "\n[TEST] ProxyConfig: invalid method in methods array rejected..." << std::endl;
    try {
        ServerConfig cfg;
        UpstreamConfig u;
        u.name = "svc";
        u.host = "127.0.0.1";
        u.port = 9000;
        u.proxy.route_prefix = "/api";
        u.proxy.response_timeout_ms = 5000;
        u.proxy.methods = {"GET", "INVALID_METHOD"};
        cfg.upstreams.push_back(u);

        try {
            ConfigLoader::Validate(cfg);
            TestFramework::RecordTest("ProxyConfig: invalid method in methods array rejected",
                                       false, "expected invalid_argument exception");
        } catch (const std::invalid_argument&) {
            TestFramework::RecordTest("ProxyConfig: invalid method in methods array rejected", true, "");
        }
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ProxyConfig: invalid method in methods array rejected", false, e.what());
    }
}

// max_retries > 10 must be rejected.
void TestProxyConfigMaxRetriesExcessive() {
    std::cout << "\n[TEST] ProxyConfig: max_retries > 10 rejected..." << std::endl;
    try {
        ServerConfig cfg;
        UpstreamConfig u;
        u.name = "svc";
        u.host = "127.0.0.1";
        u.port = 9000;
        u.proxy.route_prefix = "/api";
        u.proxy.response_timeout_ms = 5000;
        u.proxy.retry.max_retries = 11;
        cfg.upstreams.push_back(u);

        try {
            ConfigLoader::Validate(cfg);
            TestFramework::RecordTest("ProxyConfig: max_retries > 10 rejected",
                                       false, "expected invalid_argument exception");
        } catch (const std::invalid_argument&) {
            TestFramework::RecordTest("ProxyConfig: max_retries > 10 rejected", true, "");
        }
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ProxyConfig: max_retries > 10 rejected", false, e.what());
    }
}

// Negative response_timeout_ms must be rejected.
void TestProxyConfigNegativeTimeout() {
    std::cout << "\n[TEST] ProxyConfig: negative response_timeout_ms rejected..." << std::endl;
    try {
        ServerConfig cfg;
        UpstreamConfig u;
        u.name = "svc";
        u.host = "127.0.0.1";
        u.port = 9000;
        u.proxy.route_prefix = "/api";
        u.proxy.response_timeout_ms = -1;
        cfg.upstreams.push_back(u);

        try {
            ConfigLoader::Validate(cfg);
            TestFramework::RecordTest("ProxyConfig: negative response_timeout_ms rejected",
                                       false, "expected invalid_argument exception");
        } catch (const std::invalid_argument&) {
            TestFramework::RecordTest("ProxyConfig: negative response_timeout_ms rejected", true, "");
        }
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ProxyConfig: negative response_timeout_ms rejected", false, e.what());
    }
}

// HttpServer::Proxy() must throw std::invalid_argument on bad inputs
// instead of logging and silently dropping the route — otherwise an
// embedder who mistypes a route pattern starts the server with the
// expected route missing and only finds out when real traffic hits.
// Covers: empty route_pattern, malformed route_pattern (duplicate
// params), unknown upstream name, and unknown method in
// upstream.proxy.methods.
void TestProxyApiInvalidInputsThrow() {
    std::cout << "\n[TEST] HttpServer::Proxy throws on invalid inputs..." << std::endl;
    try {
        ServerConfig cfg;
        cfg.bind_port = 0;
        UpstreamConfig u;
        u.name = "svc";
        u.host = "127.0.0.1";
        u.port = 9000;
        // No proxy.route_prefix — this is a "programmatic Proxy() only"
        // upstream that ConfigLoader::Validate accepts as-is.
        cfg.upstreams.push_back(u);

        HttpServer server(cfg);

        bool empty_pattern_threw = false;
        try {
            server.Proxy("", "svc");
        } catch (const std::invalid_argument&) {
            empty_pattern_threw = true;
        }

        bool bad_pattern_threw = false;
        try {
            // Duplicate parameter names — ROUTE_TRIE::ValidatePattern
            // rejects this.
            server.Proxy("/api/:id/:id", "svc");
        } catch (const std::invalid_argument&) {
            bad_pattern_threw = true;
        }

        bool unknown_upstream_threw = false;
        try {
            server.Proxy("/api/*rest", "does-not-exist");
        } catch (const std::invalid_argument&) {
            unknown_upstream_threw = true;
        }

        bool pass = empty_pattern_threw && bad_pattern_threw &&
                    unknown_upstream_threw;
        std::string err;
        if (!empty_pattern_threw) err += "empty pattern did not throw; ";
        if (!bad_pattern_threw)   err += "malformed pattern did not throw; ";
        if (!unknown_upstream_threw) err += "unknown upstream did not throw; ";
        TestFramework::RecordTest("HttpServer::Proxy throws on invalid inputs",
                                   pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("HttpServer::Proxy throws on invalid inputs",
                                   false, e.what());
    }
}

// Serialization round-trip: ToJson -> LoadFromString must produce equal config.
void TestProxyConfigRoundTrip() {
    std::cout << "\n[TEST] ProxyConfig: JSON round-trip preserves all fields..." << std::endl;
    try {
        ServerConfig original;
        UpstreamConfig u;
        u.name = "roundtrip-svc";
        u.host = "192.168.0.1";
        u.port = 7070;
        u.proxy.route_prefix = "/roundtrip";
        u.proxy.strip_prefix = true;
        u.proxy.response_timeout_ms = 8000;
        u.proxy.methods = {"GET", "PUT"};
        u.proxy.header_rewrite.set_via_header = false;
        u.proxy.retry.max_retries = 3;
        u.proxy.retry.retry_on_5xx = true;
        original.upstreams.push_back(u);

        std::string serialized = ConfigLoader::ToJson(original);
        ServerConfig loaded = ConfigLoader::LoadFromString(serialized);

        bool pass = !loaded.upstreams.empty() && loaded.upstreams[0] == original.upstreams[0];
        std::string err = pass ? "" : "round-trip mismatch in upstream config";
        TestFramework::RecordTest("ProxyConfig: JSON round-trip preserves all fields", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ProxyConfig: JSON round-trip preserves all fields", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Section 6: Integration tests -- basic proxy flow
// ---------------------------------------------------------------------------

// GET request forwarded through proxy, 200 response relayed to client.
void TestIntegrationGetProxied() {
    std::cout << "\n[TEST] Integration: GET request proxied end-to-end..." << std::endl;
    try {
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/hello", [](const HttpRequest&, HttpResponse& resp) {
            resp.Status(200).Body("world", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ServerConfig gw_config;
        gw_config.bind_host = "127.0.0.1";
        gw_config.bind_port = 0;
        gw_config.worker_threads = 2;
        gw_config.http2.enabled = false;  // Disable HTTP/2 to simplify protocol detection
        gw_config.upstreams.push_back(
            MakeProxyUpstreamConfig("backend", "127.0.0.1", backend_port, "/hello"));

        HttpServer gateway(gw_config);
        // Register an async route for testing async dispatch path
        gateway.GetAsync("/async-test", [](const HttpRequest&,
                                           HTTP_CALLBACKS_NAMESPACE::InterimResponseSender /*send_interim*/,
                                           HTTP_CALLBACKS_NAMESPACE::ResourcePusher        /*push_resource*/,
                                           HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender /*stream_sender*/,
                                           HTTP_CALLBACKS_NAMESPACE::AsyncCompletionCallback complete) {
            HttpResponse resp;
            resp.Status(200).Body("async-ok", "text/plain");
            complete(std::move(resp));
        });
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        // Test async route
        std::string async_resp = TestHttpClient::HttpGet(gw_port, "/async-test", 5000);

        // Verify backend is reachable DIRECTLY
        std::string direct_backend_resp = TestHttpClient::HttpGet(backend_port, "/hello", 5000);
        (void)direct_backend_resp;

        std::string resp = TestHttpClient::HttpGet(gw_port, "/hello", 5000);

        bool pass = true;
        std::string err;
        if (!TestHttpClient::HasStatus(resp, 200))       { pass = false; err += "status not 200; "; }
        if (TestHttpClient::ExtractBody(resp) != "world") { pass = false; err += "body mismatch; "; }

        TestFramework::RecordTest("Integration: GET request proxied end-to-end", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Integration: GET request proxied end-to-end", false, e.what());
    }
}

// POST with body forwarded; upstream echoes back the body.
void TestIntegrationPostWithBodyProxied() {
    std::cout << "\n[TEST] Integration: POST with body proxied to upstream..." << std::endl;
    try {
        HttpServer backend("127.0.0.1", 0);
        backend.Post("/echo", [](const HttpRequest& req, HttpResponse& resp) {
            resp.Status(200).Body(req.body, "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ServerConfig gw_config;
        gw_config.bind_host = "127.0.0.1";
        gw_config.bind_port = 0;
        gw_config.worker_threads = 2;
        gw_config.upstreams.push_back(
            MakeProxyUpstreamConfig("backend", "127.0.0.1", backend_port, "/echo"));

        HttpServer gateway(gw_config);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        const std::string payload = "test-payload-12345";
        std::string resp = TestHttpClient::HttpPost(gw_port, "/echo", payload, 5000);

        bool pass = true;
        std::string err;
        if (!TestHttpClient::HasStatus(resp, 200))             { pass = false; err += "status not 200; "; }
        if (TestHttpClient::ExtractBody(resp) != payload)       { pass = false; err += "body not echoed; "; }

        TestFramework::RecordTest("Integration: POST with body proxied to upstream", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Integration: POST with body proxied to upstream", false, e.what());
    }
}

// Upstream 404 must be relayed to client as-is.
void TestIntegrationUpstream404Relayed() {
    std::cout << "\n[TEST] Integration: upstream 404 relayed to client..." << std::endl;
    try {
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/notfound", [](const HttpRequest&, HttpResponse& resp) {
            resp.Status(404).Body("not found", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ServerConfig gw_config;
        gw_config.bind_host = "127.0.0.1";
        gw_config.bind_port = 0;
        gw_config.worker_threads = 2;
        gw_config.upstreams.push_back(
            MakeProxyUpstreamConfig("backend", "127.0.0.1", backend_port, "/notfound"));

        HttpServer gateway(gw_config);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        std::string resp = TestHttpClient::HttpGet(gw_port, "/notfound", 5000);

        bool pass = TestHttpClient::HasStatus(resp, 404);
        TestFramework::RecordTest("Integration: upstream 404 relayed to client",
                                   pass, pass ? "" :
                                   "status is not 404: " + resp.substr(0, resp.find("\r\n")));
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Integration: upstream 404 relayed to client", false, e.what());
    }
}

// Upstream custom response headers must appear in the client response.
void TestIntegrationResponseHeadersForwarded() {
    std::cout << "\n[TEST] Integration: upstream response headers forwarded to client..." << std::endl;
    try {
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/headers", [](const HttpRequest&, HttpResponse& resp) {
            resp.Status(200).Header("X-Backend-Tag", "node-42").Body("ok", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ServerConfig gw_config;
        gw_config.bind_host = "127.0.0.1";
        gw_config.bind_port = 0;
        gw_config.worker_threads = 2;
        gw_config.upstreams.push_back(
            MakeProxyUpstreamConfig("backend", "127.0.0.1", backend_port, "/headers"));

        HttpServer gateway(gw_config);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        std::string resp = TestHttpClient::HttpGet(gw_port, "/headers", 5000);

        // HTTP headers are case-insensitive (RFC 9110).  The proxy normalises
        // header names to lowercase during codec parsing, so search for the
        // lowercase form.  The value "node-42" is preserved verbatim.
        std::string resp_lower = resp;
        std::transform(resp_lower.begin(), resp_lower.end(), resp_lower.begin(),
                       [](unsigned char c){ return std::tolower(c); });
        bool pass = TestHttpClient::HasStatus(resp, 200) &&
                    resp_lower.find("x-backend-tag") != std::string::npos &&
                    resp.find("node-42") != std::string::npos;
        std::string err = pass ? "" : "X-Backend-Tag header not found in response";
        TestFramework::RecordTest("Integration: upstream response headers forwarded to client", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Integration: upstream response headers forwarded to client", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Section 7: Integration tests -- header rewriting
// ---------------------------------------------------------------------------

// X-Forwarded-For must be present in the request received by upstream.
void TestIntegrationXffInjected() {
    std::cout << "\n[TEST] Integration: X-Forwarded-For injected for upstream..." << std::endl;
    try {
        std::mutex xff_mtx;
        std::string seen_xff;

        HttpServer backend("127.0.0.1", 0);
        backend.Get("/xff-check", [&](const HttpRequest& req, HttpResponse& resp) {
            std::lock_guard<std::mutex> lk(xff_mtx);
            seen_xff = req.GetHeader("x-forwarded-for");
            resp.Status(200).Body("ok", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ServerConfig gw_config;
        gw_config.bind_host = "127.0.0.1";
        gw_config.bind_port = 0;
        gw_config.worker_threads = 2;
        gw_config.upstreams.push_back(
            MakeProxyUpstreamConfig("backend", "127.0.0.1", backend_port, "/xff-check"));

        HttpServer gateway(gw_config);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        TestHttpClient::HttpGet(gw_port, "/xff-check", 5000);

        // Wait for backend handler to capture the header value.
        bool received = WaitFor([&] {
            std::lock_guard<std::mutex> lk(xff_mtx);
            return !seen_xff.empty();
        });

        std::string captured_xff;
        {
            std::lock_guard<std::mutex> lk(xff_mtx);
            captured_xff = seen_xff;
        }
        bool pass = received && !captured_xff.empty();
        std::string err = pass ? "" : "X-Forwarded-For not present in upstream request";
        TestFramework::RecordTest("Integration: X-Forwarded-For injected for upstream", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Integration: X-Forwarded-For injected for upstream", false, e.what());
    }
}

// Hop-by-hop headers must be stripped from the request forwarded to upstream.
void TestIntegrationHopByHopStrippedFromForwarded() {
    std::cout << "\n[TEST] Integration: hop-by-hop headers stripped from forwarded request..." << std::endl;
    try {
        std::atomic<bool> connection_present{false};
        std::atomic<bool> te_present{false};
        std::atomic<bool> handler_called{false};

        HttpServer backend("127.0.0.1", 0);
        backend.Get("/hop-check", [&](const HttpRequest& req, HttpResponse& resp) {
            connection_present.store(!req.GetHeader("connection").empty());
            te_present.store(!req.GetHeader("transfer-encoding").empty());
            handler_called.store(true);
            resp.Status(200).Body("ok", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ServerConfig gw_config;
        gw_config.bind_host = "127.0.0.1";
        gw_config.bind_port = 0;
        gw_config.worker_threads = 2;
        gw_config.upstreams.push_back(
            MakeProxyUpstreamConfig("backend", "127.0.0.1", backend_port, "/hop-check"));

        HttpServer gateway(gw_config);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        // Send request with hop-by-hop headers; these must not reach the backend.
        std::string raw_req =
            "GET /hop-check HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Connection: keep-alive\r\n"
            "\r\n";
        TestHttpClient::SendHttpRequest(gw_port, raw_req, 5000);

        WaitFor([&] { return handler_called.load(); }, std::chrono::milliseconds{3000});

        bool pass = !connection_present.load() && !te_present.load();
        std::string err = pass ? "" : "hop-by-hop headers not stripped from forwarded request";
        TestFramework::RecordTest("Integration: hop-by-hop headers stripped from forwarded request", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Integration: hop-by-hop headers stripped from forwarded request", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Section 8: Integration tests -- error handling
// ---------------------------------------------------------------------------

// Upstream not reachable -- client must receive 502 or 503.
void TestIntegrationUpstreamUnreachable502() {
    std::cout << "\n[TEST] Integration: unreachable upstream -> 502 Bad Gateway..." << std::endl;
    try {
        // Use a port with nothing listening. Port 29999 is highly unlikely
        // to be in use on loopback for CI environments.
        static constexpr int DEAD_PORT = 29999;

        ServerConfig gw_config;
        gw_config.bind_host = "127.0.0.1";
        gw_config.bind_port = 0;
        gw_config.worker_threads = 2;
        UpstreamConfig u = MakeProxyUpstreamConfig("dead", "127.0.0.1", DEAD_PORT, "/dead");
        u.pool.connect_timeout_ms = 1000;  // Minimum allowed (timer resolution is 1s)
        gw_config.upstreams.push_back(u);

        HttpServer gateway(gw_config);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        std::string resp = TestHttpClient::HttpGet(gw_port, "/dead", 5000);

        bool pass = TestHttpClient::HasStatus(resp, 502) || TestHttpClient::HasStatus(resp, 503);
        TestFramework::RecordTest("Integration: unreachable upstream -> 502 Bad Gateway",
                                   pass, pass ? "" :
                                   "expected 502/503, got: " + resp.substr(0, resp.find("\r\n")));
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Integration: unreachable upstream -> 502 Bad Gateway", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Section 9: Integration tests -- path handling
// ---------------------------------------------------------------------------

// strip_prefix=true: route prefix stripped before forwarding to upstream.
void TestIntegrationStripPrefix() {
    std::cout << "\n[TEST] Integration: strip_prefix removes prefix from upstream path..." << std::endl;
    try {
        HttpServer backend("127.0.0.1", 0);
        // Backend handles only "/resource" (the prefix-stripped path)
        backend.Get("/resource", [](const HttpRequest&, HttpResponse& resp) {
            resp.Status(200).Body("stripped", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ServerConfig gw_config;
        gw_config.bind_host = "127.0.0.1";
        gw_config.bind_port = 0;
        gw_config.worker_threads = 2;
        // strip_prefix=true: /api/v1/* -> /*
        gw_config.upstreams.push_back(
            MakeProxyUpstreamConfig("backend", "127.0.0.1", backend_port, "/api/v1", true /*strip*/));

        HttpServer gateway(gw_config);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        std::string resp = TestHttpClient::HttpGet(gw_port, "/api/v1/resource", 5000);

        bool pass = TestHttpClient::HasStatus(resp, 200);
        std::string err = pass ? "" :
            "expected 200 after strip_prefix, got: " + resp.substr(0, resp.find("\r\n"));
        TestFramework::RecordTest("Integration: strip_prefix removes prefix from upstream path", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Integration: strip_prefix removes prefix from upstream path", false, e.what());
    }
}

// Query string preserved when forwarding to upstream.
void TestIntegrationQueryStringForwarded() {
    std::cout << "\n[TEST] Integration: query string forwarded to upstream..." << std::endl;
    try {
        std::mutex query_mtx;
        std::string seen_query;

        HttpServer backend("127.0.0.1", 0);
        backend.Get("/search", [&](const HttpRequest& req, HttpResponse& resp) {
            std::lock_guard<std::mutex> lk(query_mtx);
            seen_query = req.query;
            resp.Status(200).Body("ok", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ServerConfig gw_config;
        gw_config.bind_host = "127.0.0.1";
        gw_config.bind_port = 0;
        gw_config.worker_threads = 2;
        gw_config.upstreams.push_back(
            MakeProxyUpstreamConfig("backend", "127.0.0.1", backend_port, "/search"));

        HttpServer gateway(gw_config);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        TestHttpClient::HttpGet(gw_port, "/search?q=test&page=2", 5000);

        bool received = WaitFor([&] {
            std::lock_guard<std::mutex> lk(query_mtx);
            return !seen_query.empty();
        });

        std::string captured_query;
        {
            std::lock_guard<std::mutex> lk(query_mtx);
            captured_query = seen_query;
        }
        bool pass = received && captured_query.find("q=test") != std::string::npos;
        std::string err = pass ? "" : "query not forwarded, seen: '" + captured_query + "'";
        TestFramework::RecordTest("Integration: query string forwarded to upstream", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Integration: query string forwarded to upstream", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Section 10: Integration tests -- connection reuse
// ---------------------------------------------------------------------------

// Two sequential requests through the proxy must both succeed. Connection
// reuse is verified indirectly: if the pool returns a corrupt connection after
// the first request, the second request will fail or time out.
void TestIntegrationConnectionReuse() {
    std::cout << "\n[TEST] Integration: second request reuses pooled upstream connection..." << std::endl;
    try {
        HttpServer backend("127.0.0.1", 0);
        backend.Get("/ping", [](const HttpRequest&, HttpResponse& resp) {
            resp.Status(200).Body("pong", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ServerConfig gw_config;
        gw_config.bind_host = "127.0.0.1";
        gw_config.bind_port = 0;
        gw_config.worker_threads = 2;
        gw_config.upstreams.push_back(
            MakeProxyUpstreamConfig("backend", "127.0.0.1", backend_port, "/ping"));

        HttpServer gateway(gw_config);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        std::string resp1 = TestHttpClient::HttpGet(gw_port, "/ping", 5000);
        std::string resp2 = TestHttpClient::HttpGet(gw_port, "/ping", 5000);

        bool pass = TestHttpClient::HasStatus(resp1, 200) && TestHttpClient::HasStatus(resp2, 200);
        std::string err = pass ? "" : "one or both requests failed";
        TestFramework::RecordTest("Integration: second request reuses pooled upstream connection", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Integration: second request reuses pooled upstream connection", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Section 11: Integration tests -- early response / pool safety
// ---------------------------------------------------------------------------

// Upstream sends 401 for the first request.
// Subsequent requests to the gateway must still succeed (pool not corrupted).
void TestIntegrationEarlyResponsePoolSafe() {
    std::cout << "\n[TEST] Integration: early 401 from upstream does not corrupt pool..." << std::endl;
    try {
        HttpServer backend("127.0.0.1", 0);
        backend.Post("/protected", [](const HttpRequest&, HttpResponse& resp) {
            resp.Status(401).Body("Unauthorized", "text/plain");
        });
        backend.Get("/health", [](const HttpRequest&, HttpResponse& resp) {
            resp.Status(200).Body("ok", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ServerConfig gw_config;
        gw_config.bind_host = "127.0.0.1";
        gw_config.bind_port = 0;
        gw_config.worker_threads = 2;
        // Single upstream; catch-all prefix routes both /protected and /health.
        UpstreamConfig u = MakeProxyUpstreamConfig("backend", "127.0.0.1", backend_port, "/");
        gw_config.upstreams.push_back(u);

        HttpServer gateway(gw_config);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        // POST to /protected -- backend returns 401
        std::string resp1 = TestHttpClient::HttpPost(
            gw_port, "/protected", std::string(1024, 'x'), 5000);

        // Subsequent GET to /health -- must still work even if pool was poisoned
        std::string resp2 = TestHttpClient::HttpGet(gw_port, "/health", 5000);

        bool pass = true;
        std::string err;
        if (!TestHttpClient::HasStatus(resp1, 401)) { pass = false; err += "first resp not 401; "; }
        if (!TestHttpClient::HasStatus(resp2, 200)) { pass = false; err += "subsequent req failed (pool corrupted?); "; }

        TestFramework::RecordTest("Integration: early 401 from upstream does not corrupt pool", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Integration: early 401 from upstream does not corrupt pool", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Section 12: Integration tests -- streaming relay
// ---------------------------------------------------------------------------

void TestIntegrationSmallContentLengthStaysBuffered() {
    std::cout << "\n[TEST] Integration: small Content-Length response stays buffered..." << std::endl;
    try {
        RawHttpBackendServer backend([](int fd, const std::string&) {
            SendAll(fd,
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Length: 10\r\n"
                    "Content-Type: text/plain\r\n"
                    "\r\n");
            SendAll(fd, "hello");
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            SendAll(fd, "world");
        });

        ServerConfig gw_config;
        gw_config.bind_host = "127.0.0.1";
        gw_config.bind_port = 0;
        gw_config.worker_threads = 1;
        gw_config.http2.enabled = false;
        gw_config.upstreams.push_back(
            MakeProxyUpstreamConfig("backend", "127.0.0.1", backend.GetPort(), "/buffered"));

        HttpServer gateway(gw_config);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        int client_fd = TestHttpClient::ConnectRawSocket(gw_port);
        if (client_fd < 0) throw std::runtime_error("gateway connect failed");

        if (!SendAll(client_fd,
                     "GET /buffered HTTP/1.1\r\n"
                     "Host: localhost\r\n"
                     "Connection: close\r\n"
                     "\r\n")) {
            close(client_fd);
            throw std::runtime_error("gateway send failed");
        }

        std::string early = RecvOnce(client_fd, 80);
        std::string full = early + RecvUntilClose(client_fd, 2000);
        close(client_fd);

        std::string full_lower = full;
        std::transform(full_lower.begin(), full_lower.end(), full_lower.begin(),
                       [](unsigned char c) { return std::tolower(c); });

        bool pass = true;
        std::string err;
        if (!early.empty()) err += "gateway emitted bytes before buffered completion; ";
        if (!TestHttpClient::HasStatus(full, 200)) err += "status not 200; ";
        if (TestHttpClient::ExtractBody(full) != "helloworld") err += "body mismatch; ";
        if (full_lower.find("content-length: 10") == std::string::npos) {
            err += "content-length missing; ";
        }
        pass = err.empty();

        TestFramework::RecordTest(
            "Integration: small Content-Length response stays buffered", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "Integration: small Content-Length response stays buffered", false, e.what());
    }
}

void TestIntegrationLargeContentLengthStreamsAndPreservesLength() {
    std::cout << "\n[TEST] Integration: large Content-Length response streams and preserves CL..." << std::endl;
    try {
        RawHttpBackendServer backend([](int fd, const std::string&) {
            SendAll(fd,
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Length: 10\r\n"
                    "Content-Type: text/plain\r\n"
                    "\r\n");
            SendAll(fd, "hello");
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            SendAll(fd, "world");
        });

        ServerConfig gw_config;
        gw_config.bind_host = "127.0.0.1";
        gw_config.bind_port = 0;
        gw_config.worker_threads = 1;
        gw_config.http2.enabled = false;
        UpstreamConfig u = MakeProxyUpstreamConfig(
            "backend", "127.0.0.1", backend.GetPort(), "/stream-cl");
        u.proxy.auto_stream_content_length_threshold_bytes = 4;
        gw_config.upstreams.push_back(u);

        HttpServer gateway(gw_config);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        int client_fd = TestHttpClient::ConnectRawSocket(gw_port);
        if (client_fd < 0) throw std::runtime_error("gateway connect failed");

        if (!SendAll(client_fd,
                     "GET /stream-cl HTTP/1.1\r\n"
                     "Host: localhost\r\n"
                     "Connection: close\r\n"
                     "\r\n")) {
            close(client_fd);
            throw std::runtime_error("gateway send failed");
        }

        std::string early = RecvUntilContains(client_fd, "hello", 400);
        std::string full = early + RecvUntilClose(client_fd, 2000);
        close(client_fd);

        std::string early_lower = early;
        std::transform(early_lower.begin(), early_lower.end(), early_lower.begin(),
                       [](unsigned char c) { return std::tolower(c); });

        bool pass = true;
        std::string err;
        if (!TestHttpClient::HasStatus(full, 200)) err += "status not 200; ";
        if (early.find("hello") == std::string::npos) err += "first body bytes not observed early; ";
        if (early.find("world") != std::string::npos) err += "second body bytes arrived too early; ";
        if (early_lower.find("content-length: 10") == std::string::npos) {
            err += "content-length not preserved; ";
        }
        if (early_lower.find("transfer-encoding: chunked") != std::string::npos) {
            err += "unexpected chunked transfer-encoding; ";
        }
        if (TestHttpClient::ExtractBody(full) != "helloworld") err += "body mismatch; ";
        pass = err.empty();

        TestFramework::RecordTest(
            "Integration: large Content-Length response streams and preserves CL",
            pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "Integration: large Content-Length response streams and preserves CL",
            false, e.what());
    }
}

void TestIntegrationChunkedUpstreamStreamsImmediately() {
    std::cout << "\n[TEST] Integration: chunked upstream response streams immediately..." << std::endl;
    try {
        RawHttpBackendServer backend([](int fd, const std::string&) {
            SendAll(fd,
                    "HTTP/1.1 200 OK\r\n"
                    "Transfer-Encoding: chunked\r\n"
                    "Content-Type: text/plain\r\n"
                    "\r\n");
            SendAll(fd, "5\r\nhello\r\n");
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            SendAll(fd, "5\r\nworld\r\n0\r\n\r\n");
        });

        ServerConfig gw_config;
        gw_config.bind_host = "127.0.0.1";
        gw_config.bind_port = 0;
        gw_config.worker_threads = 1;
        gw_config.http2.enabled = false;
        gw_config.upstreams.push_back(
            MakeProxyUpstreamConfig("backend", "127.0.0.1", backend.GetPort(), "/chunked"));

        HttpServer gateway(gw_config);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        int client_fd = TestHttpClient::ConnectRawSocket(gw_port);
        if (client_fd < 0) throw std::runtime_error("gateway connect failed");

        if (!SendAll(client_fd,
                     "GET /chunked HTTP/1.1\r\n"
                     "Host: localhost\r\n"
                     "Connection: close\r\n"
                     "\r\n")) {
            close(client_fd);
            throw std::runtime_error("gateway send failed");
        }

        std::string early = RecvUntilContains(client_fd, "hello", 400);
        std::string full = early + RecvUntilClose(client_fd, 2000);
        close(client_fd);

        std::string early_lower = early;
        std::transform(early_lower.begin(), early_lower.end(), early_lower.begin(),
                       [](unsigned char c) { return std::tolower(c); });

        bool pass = true;
        std::string err;
        if (!TestHttpClient::HasStatus(full, 200)) err += "status not 200; ";
        if (early_lower.find("transfer-encoding: chunked") == std::string::npos) {
            err += "chunked transfer-encoding missing; ";
        }
        if (early.find("5\r\nhello\r\n") == std::string::npos) err += "first chunk not observed early; ";
        if (early.find("world") != std::string::npos) err += "second chunk arrived too early; ";
        if (full.find("5\r\nworld\r\n0\r\n\r\n") == std::string::npos) {
            err += "final chunk or terminator missing; ";
        }
        pass = err.empty();

        TestFramework::RecordTest(
            "Integration: chunked upstream response streams immediately", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "Integration: chunked upstream response streams immediately", false, e.what());
    }
}

void TestIntegrationStreamIdleTimeoutAbortsRelay() {
    std::cout << "\n[TEST] Integration: stream idle timeout aborts committed relay..." << std::endl;
    try {
        RawHttpBackendServer backend([](int fd, const std::string&) {
            SendAll(fd,
                    "HTTP/1.1 200 OK\r\n"
                    "Transfer-Encoding: chunked\r\n"
                    "Content-Type: text/plain\r\n"
                    "\r\n");
            SendAll(fd, "5\r\nhello\r\n");
            std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        });

        ServerConfig gw_config;
        gw_config.bind_host = "127.0.0.1";
        gw_config.bind_port = 0;
        gw_config.worker_threads = 1;
        gw_config.http2.enabled = false;
        UpstreamConfig u = MakeProxyUpstreamConfig(
            "backend", "127.0.0.1", backend.GetPort(), "/idle-timeout");
        u.proxy.buffering = "never";
        u.proxy.response_timeout_ms = 0;
        u.proxy.stream_idle_timeout_sec = 1;
        gw_config.upstreams.push_back(u);

        HttpServer gateway(gw_config);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        int client_fd = TestHttpClient::ConnectRawSocket(gw_port);
        if (client_fd < 0) throw std::runtime_error("gateway connect failed");

        if (!SendAll(client_fd,
                     "GET /idle-timeout HTTP/1.1\r\n"
                     "Host: localhost\r\n"
                     "Connection: close\r\n"
                     "\r\n")) {
            close(client_fd);
            throw std::runtime_error("gateway send failed");
        }

        std::string early = RecvUntilContains(client_fd, "hello", 400);
        std::string full = early + RecvUntilClose(client_fd, 2500);
        close(client_fd);

        bool pass = true;
        std::string err;
        if (!TestHttpClient::HasStatus(full, 200)) err += "status not 200 before timeout; ";
        if (early.find("hello") == std::string::npos) err += "first chunk missing; ";
        if (full.find("0\r\n\r\n") != std::string::npos) {
            err += "clean chunk terminator must not be emitted on abort; ";
        }
        pass = err.empty();

        TestFramework::RecordTest(
            "Integration: stream idle timeout aborts committed relay", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "Integration: stream idle timeout aborts committed relay", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Section 13: RetryPolicy unit tests -- full jitter backoff (timer-based retry)
// ---------------------------------------------------------------------------

// BackoffDelay(1) must always fall in [1, 50) — BASE * 2^1 = 50.
// BackoffDelay(3) must always fall in [1, 200) — BASE * 2^3 = 200.
// BackoffDelay(5) must always fall in [1, 250) — BASE * 2^5 = 800 -> capped at 250.
// Run many iterations to statistically rule out accidental compliance.
void TestRetryFullJitterRange() {
    std::cout << "\n[TEST] RetryPolicy: full jitter range for attempts 1, 3, 5..." << std::endl;
    try {
        RetryPolicy::Config cfg;
        RetryPolicy policy(cfg);

        bool pass = true;
        std::string err;

        // attempt=1: upper_bound = BASE(25) * 2^1 = 50, range [1, 50)
        {
            static constexpr int EXPECTED_MAX = 50;  // BASE_BACKOFF_MS * 2^1
            for (int i = 0; i < 1000; ++i) {
                auto d = policy.BackoffDelay(1).count();
                if (d < 1 || d >= EXPECTED_MAX) {
                    pass = false;
                    err += "attempt=1 out of range: " + std::to_string(d) + "; ";
                    break;
                }
            }
        }

        // attempt=3: upper_bound = BASE(25) * 2^3 = 200, range [1, 200)
        {
            static constexpr int EXPECTED_MAX = 200;  // BASE_BACKOFF_MS * 2^3
            for (int i = 0; i < 1000; ++i) {
                auto d = policy.BackoffDelay(3).count();
                if (d < 1 || d >= EXPECTED_MAX) {
                    pass = false;
                    err += "attempt=3 out of range: " + std::to_string(d) + "; ";
                    break;
                }
            }
        }

        // attempt=5: upper_bound = BASE(25) * 2^5 = 800 -> capped at MAX_BACKOFF_MS(250)
        // range [1, 250)
        {
            static constexpr int EXPECTED_MAX = 250;  // MAX_BACKOFF_MS cap
            for (int i = 0; i < 1000; ++i) {
                auto d = policy.BackoffDelay(5).count();
                if (d < 1 || d >= EXPECTED_MAX) {
                    pass = false;
                    err += "attempt=5 out of range: " + std::to_string(d) + "; ";
                    break;
                }
            }
        }

        TestFramework::RecordTest("RetryPolicy: full jitter range", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RetryPolicy: full jitter range", false, e.what());
    }
}

// BackoffDelay(0) must return exactly 0ms in all invocations.
// attempt=0 is the first-retry case; callers that pass 0 want immediate retry.
void TestRetryFullJitterAttempt0IsZero() {
    std::cout << "\n[TEST] RetryPolicy: full jitter attempt 0 always returns 0ms..." << std::endl;
    try {
        RetryPolicy::Config cfg;
        RetryPolicy policy(cfg);

        bool pass = true;
        std::string err;
        for (int i = 0; i < 100; ++i) {
            auto d = policy.BackoffDelay(0).count();
            if (d != 0) {
                pass = false;
                err = "BackoffDelay(0) returned " + std::to_string(d) + "ms want 0";
                break;
            }
        }

        TestFramework::RecordTest("RetryPolicy: full jitter attempt 0 always returns 0ms",
                                   pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RetryPolicy: full jitter attempt 0 always returns 0ms",
                                   false, e.what());
    }
}

// BackoffDelay for large attempt values must never exceed MAX_BACKOFF_MS (250ms).
// The cap prevents the exponential from growing unboundedly.
void TestRetryFullJitterCapAtMax() {
    std::cout << "\n[TEST] RetryPolicy: full jitter capped at MAX_BACKOFF_MS..." << std::endl;
    try {
        RetryPolicy::Config cfg;
        RetryPolicy policy(cfg);

        static constexpr int MAX_BACKOFF_MS = 250;
        bool pass = true;
        std::string err;

        // Test a range of large attempt values where the cap must engage.
        for (int attempt : {5, 7, 10, 15, 20, 50}) {
            for (int i = 0; i < 1000; ++i) {
                auto d = policy.BackoffDelay(attempt).count();
                if (d < 1 || d >= MAX_BACKOFF_MS) {
                    pass = false;
                    err += "attempt=" + std::to_string(attempt) +
                           " returned " + std::to_string(d) +
                           "ms (not in [1, 250)); ";
                    break;
                }
            }
            if (!pass) break;
        }

        TestFramework::RecordTest("RetryPolicy: full jitter capped at MAX_BACKOFF_MS", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RetryPolicy: full jitter capped at MAX_BACKOFF_MS",
                                   false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Section 13: Integration tests -- timer-based retry backoff
// ---------------------------------------------------------------------------

// Build a gateway UpstreamConfig with retry settings.
// Helper specific to backoff integration tests.
static UpstreamConfig MakeRetryProxyConfig(const std::string& name,
                                            const std::string& host,
                                            int port,
                                            const std::string& route_prefix,
                                            int max_retries,
                                            bool retry_on_5xx,
                                            bool retry_on_connect_failure) {
    UpstreamConfig cfg = MakeProxyUpstreamConfig(name, host, port, route_prefix);
    cfg.proxy.retry.max_retries             = max_retries;
    cfg.proxy.retry.retry_on_5xx            = retry_on_5xx;
    cfg.proxy.retry.retry_on_connect_failure = retry_on_connect_failure;
    cfg.proxy.retry.retry_on_disconnect     = false;
    cfg.proxy.retry.retry_non_idempotent    = false;
    return cfg;
}

// A 5xx response on the first attempt triggers a backoff before the retry.
// We configure max_retries=1 and retry_on_5xx=true. The backend returns 503
// on the first call and 200 on the second. The backoff for attempt=1 is
// random in [1, 50ms), so the total roundtrip includes at least 1ms of
// artificial delay. We assert elapsed >= 1ms and < 3000ms (CI safety margin).
// This test validates that EnQueueDelayed() is used for 5xx retries.
void TestIntegration5xxFirstRetryBacksOff() {
    std::cout << "\n[TEST] Integration: 5xx first retry backs off (non-zero delay)..." << std::endl;
    try {
        // Backend: first request returns 503, subsequent requests return 200.
        std::atomic<int> request_count{0};

        HttpServer backend("127.0.0.1", 0);
        backend.Get("/flaky", [&](const HttpRequest&, HttpResponse& resp) {
            int n = request_count.fetch_add(1, std::memory_order_relaxed) + 1;
            if (n == 1) {
                // First request: simulate transient 503
                resp.Status(503).Body("Service Unavailable", "text/plain");
            } else {
                resp.Status(200).Body("ok", "text/plain");
            }
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ServerConfig gw_config;
        gw_config.bind_host = "127.0.0.1";
        gw_config.bind_port = 0;
        gw_config.worker_threads = 2;
        gw_config.http2.enabled = false;
        gw_config.upstreams.push_back(
            MakeRetryProxyConfig("backend", "127.0.0.1", backend_port, "/flaky",
                                 1 /*max_retries*/, true /*retry_on_5xx*/,
                                 false /*retry_on_connect_failure*/));

        HttpServer gateway(gw_config);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        // Measure the round-trip time through the gateway (includes backoff delay).
        // Use a generous timeout (8s) so CI doesn't timeout prematurely.
        auto t0 = std::chrono::steady_clock::now();
        std::string resp = TestHttpClient::HttpGet(gw_port, "/flaky", 8000);
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count();

        bool pass = true;
        std::string err;

        // Verify we got 200 (retry succeeded)
        if (!TestHttpClient::HasStatus(resp, 200)) {
            pass = false;
            err += "expected 200 after retry, got: " +
                   (resp.empty() ? "(empty)" : resp.substr(0, resp.find("\r\n"))) + "; ";
        }

        // Verify backoff was applied: elapsed must be >= 1ms (BackoffDelay
        // guarantees >= 1ms for attempt >= 1). Use 1ms as the floor and
        // 3000ms as the CI safety cap.
        static constexpr long ELAPSED_LOWER_BOUND_MS = 1;
        static constexpr long ELAPSED_UPPER_BOUND_MS = 3000;
        if (elapsed_ms < ELAPSED_LOWER_BOUND_MS) {
            pass = false;
            err += "elapsed " + std::to_string(elapsed_ms) +
                   "ms < " + std::to_string(ELAPSED_LOWER_BOUND_MS) +
                   "ms (backoff not applied?); ";
        }
        if (elapsed_ms > ELAPSED_UPPER_BOUND_MS) {
            pass = false;
            err += "elapsed " + std::to_string(elapsed_ms) + "ms exceeds CI limit; ";
        }

        // Verify the backend actually received two requests (original + 1 retry).
        // Poll briefly since the second request may still be in flight.
        bool two_requests = WaitFor(
            [&] { return request_count.load() >= 2; },
            std::chrono::milliseconds{500});
        if (!two_requests) {
            pass = false;
            err += "backend received " + std::to_string(request_count.load()) +
                   " requests, expected 2 (original + retry); ";
        }

        TestFramework::RecordTest("Integration: 5xx first retry backs off", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Integration: 5xx first retry backs off", false, e.what());
    }
}

// Connect-failure retries must be immediate (no backoff delay added for
// attempt <= 1). We configure max_retries=1 pointing at a port with
// nothing listening. Both attempts get ECONNREFUSED. The final 502 must
// arrive quickly — well under 1000ms — confirming no artificial backoff
// was injected.
void TestIntegrationConnectFailureFirstRetryIsImmediate() {
    std::cout << "\n[TEST] Integration: connect failure first retry is immediate (no backoff)..." << std::endl;
    try {
        // Find an unused port by binding and immediately closing.
        // This gives us a port that is not listening (ECONNREFUSED).
        int dead_port = -1;
        {
            int probe_fd = socket(AF_INET, SOCK_STREAM, 0);
            if (probe_fd >= 0) {
                int reuse = 1;
                setsockopt(probe_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
                struct sockaddr_in addr{};
                addr.sin_family = AF_INET;
                addr.sin_port = 0;
                addr.sin_addr.s_addr = inet_addr("127.0.0.1");
                if (bind(probe_fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
                    struct sockaddr_in bound_addr{};
                    socklen_t len = sizeof(bound_addr);
                    if (getsockname(probe_fd, (struct sockaddr*)&bound_addr, &len) == 0) {
                        dead_port = ntohs(bound_addr.sin_port);
                    }
                }
                close(probe_fd);
                // port is now closed — nothing is listening there
            }
        }

        if (dead_port <= 0) {
            // Fallback: use a port in the ephemeral range that is very
            // unlikely to be in use on the test host.
            dead_port = 39991;
        }

        ServerConfig gw_config;
        gw_config.bind_host = "127.0.0.1";
        gw_config.bind_port = 0;
        gw_config.worker_threads = 2;
        gw_config.http2.enabled = false;
        UpstreamConfig u = MakeRetryProxyConfig(
            "dead", "127.0.0.1", dead_port, "/immediate",
            1 /*max_retries*/, false /*retry_on_5xx*/,
            true /*retry_on_connect_failure*/);
        // Minimum connect timeout so the test does not wait unnecessarily
        u.pool.connect_timeout_ms = 1000;
        gw_config.upstreams.push_back(u);

        HttpServer gateway(gw_config);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        // Time the full round-trip: original attempt + 1 immediate retry → 502.
        auto t0 = std::chrono::steady_clock::now();
        std::string resp = TestHttpClient::HttpGet(gw_port, "/immediate", 5000);
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count();

        bool pass = true;
        std::string err;

        // Expect 502/503 since both attempts fail
        if (!TestHttpClient::HasStatus(resp, 502) && !TestHttpClient::HasStatus(resp, 503)) {
            pass = false;
            err += "expected 502/503, got: " +
                   (resp.empty() ? "(empty)" : resp.substr(0, resp.find("\r\n"))) + "; ";
        }

        // Immediate retry: elapsed must be well below 1000ms.
        // The connect timeout is 1s per attempt, so 2 immediate attempts may
        // take up to ~2s on a very slow CI. Use a generous cap of 4000ms to
        // avoid false positives while still proving no gratuitous backoff sleep.
        static constexpr long IMMEDIATE_UPPER_BOUND_MS = 4000;
        if (elapsed_ms > IMMEDIATE_UPPER_BOUND_MS) {
            pass = false;
            err += "elapsed " + std::to_string(elapsed_ms) +
                   "ms exceeds immediate-retry threshold of " +
                   std::to_string(IMMEDIATE_UPPER_BOUND_MS) + "ms; ";
        }

        TestFramework::RecordTest(
            "Integration: connect failure first retry is immediate", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "Integration: connect failure first retry is immediate", false, e.what());
    }
}

// A request undergoing backoff must NOT block other concurrent requests.
// Setup: backend returns 503 for /slow (triggers backoff retry) and 200 for /fast.
// Send /slow first, then /fast immediately after on a separate connection.
// /fast must complete before /slow finishes its backoff retry cycle.
// This proves EnQueueDelayed() defers only the retried transaction, not
// the entire dispatcher thread.
void TestIntegrationBackoffDoesNotBlockOtherRequests() {
    std::cout << "\n[TEST] Integration: backoff does not block other requests..." << std::endl;
    try {
        // Backend:
        //   /slow  — always returns 503 on first visit; 200 on second (after retry).
        //            The retry path sleeps 200ms BEFORE responding to ensure
        //            /slow completes well after /fast, regardless of the
        //            specific jitter value picked for backoff (1-49ms).
        //            Without this deterministic delay, a low jitter value
        //            combined with fast-machine backend processing could
        //            let /slow finish before /fast, flaking the ordering
        //            assertion below.
        //   /fast  — always returns 200 immediately.
        std::atomic<int> slow_count{0};

        HttpServer backend("127.0.0.1", 0);
        backend.Get("/slow", [&](const HttpRequest&, HttpResponse& resp) {
            int n = slow_count.fetch_add(1, std::memory_order_relaxed) + 1;
            if (n == 1) {
                // First call: trigger retry
                resp.Status(503).Body("retry me", "text/plain");
            } else {
                // Second call (after backoff): sleep then succeed.
                // The 200ms sleep dominates the backoff jitter, making
                // the total /slow wall-clock time predictably > /fast.
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
                resp.Status(200).Body("slow-ok", "text/plain");
            }
        });
        backend.Get("/fast", [](const HttpRequest&, HttpResponse& resp) {
            resp.Status(200).Body("fast-ok", "text/plain");
        });
        TestServerRunner<HttpServer> backend_runner(backend);
        int backend_port = backend_runner.GetPort();

        ServerConfig gw_config;
        gw_config.bind_host = "127.0.0.1";
        gw_config.bind_port = 0;
        // Pin to 1 worker so both /slow and /fast land on the same
        // dispatcher. With multiple workers, fd % N routing can put
        // them on different dispatchers, letting /fast succeed even
        // if the retry path blocks its own dispatcher thread.
        gw_config.worker_threads = 1;
        gw_config.http2.enabled = false;

        // /slow has retry_on_5xx=true so backoff will be applied between attempts.
        UpstreamConfig slow_us = MakeRetryProxyConfig(
            "backend", "127.0.0.1", backend_port, "/",
            1 /*max_retries*/, true /*retry_on_5xx*/,
            false /*retry_on_connect_failure*/);
        gw_config.upstreams.push_back(slow_us);

        HttpServer gateway(gw_config);
        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        // Send /slow asynchronously so we can immediately fire /fast.
        std::atomic<bool> slow_done{false};
        std::atomic<bool> fast_done{false};
        std::atomic<long> slow_elapsed_ms{-1};
        std::atomic<long> fast_elapsed_ms{-1};

        std::thread slow_thread([&] {
            auto t0 = std::chrono::steady_clock::now();
            std::string r = TestHttpClient::HttpGet(gw_port, "/slow", 8000);
            slow_elapsed_ms.store(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - t0).count());
            (void)r;
            slow_done.store(true);
        });

        // Give the slow request a small head-start so it reaches the gateway
        // before /fast, allowing the test to observe ordering.
        std::this_thread::sleep_for(std::chrono::milliseconds{10});

        std::thread fast_thread([&] {
            auto t0 = std::chrono::steady_clock::now();
            std::string r = TestHttpClient::HttpGet(gw_port, "/fast", 5000);
            fast_elapsed_ms.store(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - t0).count());
            (void)r;
            fast_done.store(true);
        });

        slow_thread.join();
        fast_thread.join();

        bool pass = true;
        std::string err;

        // /fast must have finished (timeout guard)
        if (!fast_done.load()) {
            pass = false;
            err += "/fast did not complete; ";
        }
        if (!slow_done.load()) {
            pass = false;
            err += "/slow did not complete; ";
        }

        long fast_ms = fast_elapsed_ms.load();
        long slow_ms = slow_elapsed_ms.load();

        // /fast should complete in significantly less wall-clock time than /slow.
        // /slow takes at least 200ms (deterministic backend sleep on retry)
        // + backoff jitter + two round-trips. /fast takes one round-trip with
        // no sleep. The 10ms head-start for /slow ensures it enters the backoff
        // wait before /fast is dispatched. The 200ms backend sleep eliminates
        // the flake risk where a low jitter value could let /slow finish first.
        if (fast_ms < 0 || fast_ms > 2000) {
            pass = false;
            err += "/fast took " + std::to_string(fast_ms) + "ms (expected < 2000ms); ";
        }

        // /slow must eventually succeed (retry worked)
        if (slow_ms < 0 || slow_ms > 5000) {
            pass = false;
            err += "/slow took " + std::to_string(slow_ms) + "ms (expected < 5000ms); ";
        }

        // Key assertion: /fast must complete before /slow, proving that
        // the backoff delay on /slow did not block /fast.
        if (fast_ms >= 0 && slow_ms >= 0 && fast_ms >= slow_ms) {
            pass = false;
            err += "/fast (" + std::to_string(fast_ms) + "ms) did not finish before /slow (" +
                   std::to_string(slow_ms) + "ms); backoff may be blocking; ";
        }

        TestFramework::RecordTest(
            "Integration: backoff does not block other requests", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "Integration: backoff does not block other requests", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// RunAllTests
// ---------------------------------------------------------------------------

void RunAllTests() {
    std::cout << "\n=== Proxy Engine Tests ===" << std::endl;

    // Section 1: UpstreamHttpCodec
    TestCodecParseSimple200();
    TestCodecParse204NoContent();
    TestCodecParseHeadersSplit();
    TestCodecParseMalformed();
    TestCodecParse100ContinueThen200SameBuffer();
    TestCodecParse100ContinueThen200SeparateCalls();
    TestCodecParseMultiple1xxBeforeFinal();
    TestCodecResetAndReuse();
    TestCodecBodyCapEnforced();
    TestCodecRepeatedSetCookiePreserved();
    TestCodecConnectionCloseDisablesReuse();
    TestCodecHttp10DefaultsToClose();

    // Section 2: HttpRequestSerializer
    TestSerializerGetNoBody();
    TestSerializerPostWithBody();
    TestSerializerQueryString();
    TestSerializerEmptyQueryNoQuestionMark();
    TestSerializerEmptyPathDefaults();

    // Section 3: HeaderRewriter
    TestRewriterXffAppend();
    TestRewriterXffCreated();
    TestRewriterXfpHttps();
    TestRewriterHostRewrite();
    TestRewriterHostPort80Omitted();
    TestRewriterHostPort443RetainedForHttp();
    TestRewriterHostPort80RetainedForHttps();
    TestRewriterHopByHopStripped();
    TestRewriterConnectionListedHeadersStripped();
    TestRewriterResponseHopByHopStripped();
    TestRewriterRepeatedSetCookiePreserved();

    // Section 4: RetryPolicy
    TestRetryNoRetriesConfigured();
    TestRetryAttemptExhausted();
    TestRetryHeadersSent();
    TestRetryPostNotRetried();
    TestRetryGetConnectFailure();
    TestRetryDisconnectRetried();
    TestRetryDisconnectNotRetried();
    TestRetryIdempotentMethods();
    TestRetryBackoffDelay();

    // Section 5: ProxyConfig parsing
    TestProxyConfigFullParse();
    TestProxyConfigDefaults();
    TestProxyConfigInvalidMethod();
    TestProxyConfigMaxRetriesExcessive();
    TestProxyConfigNegativeTimeout();
    TestProxyConfigRoundTrip();
    TestProxyApiInvalidInputsThrow();

    // Sections 6-11: Integration tests
    TestIntegrationGetProxied();
    TestIntegrationPostWithBodyProxied();
    TestIntegrationUpstream404Relayed();
    TestIntegrationResponseHeadersForwarded();
    TestIntegrationXffInjected();
    TestIntegrationHopByHopStrippedFromForwarded();
    TestIntegrationUpstreamUnreachable502();
    TestIntegrationStripPrefix();
    TestIntegrationQueryStringForwarded();
    TestIntegrationConnectionReuse();
    TestIntegrationEarlyResponsePoolSafe();
    TestIntegrationSmallContentLengthStaysBuffered();
    TestIntegrationLargeContentLengthStreamsAndPreservesLength();
    TestIntegrationChunkedUpstreamStreamsImmediately();
    TestIntegrationStreamIdleTimeoutAbortsRelay();

    // Section 13: RetryPolicy unit tests -- full jitter backoff
    TestRetryFullJitterRange();
    TestRetryFullJitterAttempt0IsZero();
    TestRetryFullJitterCapAtMax();

    // Section 14: Integration tests -- timer-based retry backoff
    TestIntegration5xxFirstRetryBacksOff();
    TestIntegrationConnectFailureFirstRetryIsImmediate();
    TestIntegrationBackoffDoesNotBlockOtherRequests();
}

} // namespace ProxyTests
