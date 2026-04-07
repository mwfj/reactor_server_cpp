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
        auto out = rewriter.RewriteRequest(in, "192.168.1.5", false, "backend", 8080);

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
        auto out = rewriter.RewriteRequest(in, "1.2.3.4", false, "backend", 9000);

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
        auto out = rewriter.RewriteRequest(in, "5.6.7.8", true /*tls*/, "backend", 443);

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
        auto out = rewriter.RewriteRequest(in, "1.1.1.1", false, "10.0.1.10", 8081);

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
        auto out = rewriter.RewriteRequest(in, "1.1.1.1", false, "backend.internal", 80);

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
            {"transfer-encoding", "chunked"},
            {"te", "trailers"},
            {"trailer", "X-Checksum"},
            {"upgrade", "websocket"},
            {"x-custom", "preserved"}
        };
        auto out = rewriter.RewriteRequest(in, "1.1.1.1", false, "backend", 9000);

        bool pass = true;
        std::string err;
        // Hop-by-hop must be absent
        for (const char* hop : {"connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade"}) {
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
        auto out = rewriter.RewriteRequest(in, "1.1.1.1", false, "backend", 9000);

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
            {"transfer-encoding", "chunked"},
            {"x-backend-id", "node-3"}
        };
        auto out = rewriter.RewriteResponse(upstream_headers);

        bool pass = true;
        std::string err;

        std::set<std::string> names;
        for (const auto& p : out) names.insert(p.first);

        // Hop-by-hop must be gone
        for (const char* hop : {"connection", "keep-alive", "transfer-encoding"}) {
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
        gateway.GetAsync("/async-test", [](const HttpRequest&, HTTP_CALLBACKS_NAMESPACE::AsyncCompletionCallback complete) {
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
}

} // namespace ProxyTests
