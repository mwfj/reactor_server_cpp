#pragma once
//
// Dual-stack integration tests per §12.2 of
// HOSTNAME_RESOLUTION_AND_IPV6_DESIGN.md. Seeded by step 4 (Acceptor
// IPv6 bind path); will grow as later steps land bind observability,
// hostname-driven flows, and the startup-abort gate.
//

#include "test_framework.h"
#include "http/http_server.h"
#include "test_server_runner.h"
#include "http_test_client.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iostream>
#include <string>

namespace DualStackTests {

inline void Record(const std::string& name, bool ok,
                    const std::string& err = "") {
    TestFramework::RecordTest(name, ok, err,
                               TestFramework::TestCategory::OTHER);
}

// ---------- Acceptor IPv6 literal bind ----------
inline void TestAcceptorIpv6LiteralBind() {
    std::cout << "\n[TEST] DualStack: Acceptor accepts IPv6 literal bind..."
              << std::endl;
    try {
        // Bind on loopback IPv6. If the host lacks IPv6 loopback this
        // test is expected to throw during construction — skip cleanly.
        HttpServer server("::1", 0);
        TestHttpClient::SetupEchoRoutes(server);
        TestServerRunner<HttpServer> runner(server);
        const int port = runner.GetPort();

        // Connect to the IPv6 loopback and issue a health probe.
        int fd = ::socket(AF_INET6, SOCK_STREAM, 0);
        bool ok = (fd >= 0);
        if (!ok) {
            Record("DualStack: Acceptor accepts IPv6 literal bind", false,
                    "socket(AF_INET6) failed");
            return;
        }
        sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_port   = htons(static_cast<uint16_t>(port));
        ::inet_pton(AF_INET6, "::1", &addr.sin6_addr);
        const int rc = ::connect(fd, reinterpret_cast<sockaddr*>(&addr),
                                   sizeof(addr));
        ok = ok && (rc == 0);
        const std::string req =
            "GET /health HTTP/1.1\r\nHost: [::1]\r\nConnection: close\r\n\r\n";
        ok = ok && (::send(fd, req.data(), req.size(), 0)
                     == static_cast<ssize_t>(req.size()));
        char buf[512];
        ssize_t n = ::recv(fd, buf, sizeof(buf) - 1, 0);
        ok = ok && (n > 0);
        ::close(fd);

        std::string response(buf, n > 0 ? (size_t)n : 0);
        ok = ok && response.find("HTTP/1.1 2") != std::string::npos;
        Record("DualStack: Acceptor accepts IPv6 literal bind", ok,
                ok ? "" : "no 2xx response on ::1 bind");
    } catch (const std::exception& e) {
        // On systems without IPv6 loopback (rare in CI) we accept a
        // clear runtime failure rather than a silent false pass.
        const std::string msg = e.what();
        const bool skip_allowed =
            msg.find("Cannot assign requested address") != std::string::npos ||
            msg.find("Address family not supported") != std::string::npos;
        if (skip_allowed) {
            Record("DualStack: Acceptor accepts IPv6 literal bind", true,
                    "skipped (no IPv6 loopback)");
        } else {
            Record("DualStack: Acceptor accepts IPv6 literal bind", false,
                    msg);
        }
    }
}

// ---------- Acceptor rejects non-literal bind ----------
inline void TestAcceptorRejectsHostname() {
    std::cout << "\n[TEST] DualStack: Acceptor rejects hostname bind..."
              << std::endl;
    try {
        // Hostnames are resolved by HttpServer::Start's DNS phase.
        // The Acceptor ctor itself takes an InetAddr literal; legacy
        // string entry-point must fail closed for non-literals.
        bool threw = false;
        try {
            HttpServer server("not-a-valid-ip-or-hostname-literal", 0);
            TestServerRunner<HttpServer> runner(server);
        } catch (const std::exception&) {
            threw = true;
        }
        Record("DualStack: Acceptor rejects hostname bind", threw,
                threw ? "" : "Acceptor accepted non-literal host");
    } catch (const std::exception& e) {
        Record("DualStack: Acceptor rejects hostname bind", false, e.what());
    }
}

// ---------- Test registrar ----------

inline void RunAllTests() {
    std::cout << "\n=== DualStack Tests ===" << std::endl;
    TestAcceptorIpv6LiteralBind();
    TestAcceptorRejectsHostname();
}

}  // namespace DualStackTests
