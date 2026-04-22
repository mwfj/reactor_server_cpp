#pragma once
//
// Dual-stack integration tests per §12.2 of
// HOSTNAME_RESOLUTION_AND_IPV6_DESIGN.md. Seeded by step 4 (Acceptor
// IPv6 bind path); will grow as later steps land bind observability,
// hostname-driven flows, and the startup-abort gate.
//

#include "test_framework.h"
#include "http/http_server.h"
#include "socket_handler.h"
#include "inet_addr.h"
#include "upstream/header_rewriter.h"   // P1 IPv6 Host-header regression test
#include "test_server_runner.h"
#include "http_test_client.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>

#include <atomic>
#include <chrono>
#include <future>
#include <iostream>
#include <string>
#include <thread>

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

// ---------- Outbound IPv6 primitive (pool partition path) ----------
//
// Pin the review-round fix that threads the resolved family into
// PoolPartition::CreateNewConnection. Previously the pool called the
// zero-arg CreateClientSocket() which defaulted to AF_INET; this test
// exercises the corrected primitives: InetAddr("::1", port) drives
// family detection, CreateClientSocket(AF_INET6) produces a matching
// socket, and ::connect on the InetAddr's sockaddr succeeds.
//
// We cannot easily drive PoolPartition::CreateNewConnection directly
// without standing up a full UpstreamManager/HostPool; step 9 will add
// that end-to-end path. For now this microtest covers the exact
// OS-level primitives the pool path uses.
inline void TestOutboundIpv6LiteralConnectPrimitives() {
    std::cout << "\n[TEST] DualStack: outbound IPv6 literal connect primitives..."
              << std::endl;
    try {
        // ---- Listener on ::1:0 ----
        int listen_fd = ::socket(AF_INET6, SOCK_STREAM, 0);
        if (listen_fd < 0) {
            // Host lacks IPv6 — the same accept-it-as-skipped pattern
            // used by the Acceptor bind test above.
            Record("DualStack: outbound IPv6 literal connect primitives",
                    true, "skipped (no IPv6 loopback)");
            return;
        }
        int on = 1;
        ::setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
        ::setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

        sockaddr_in6 sa{};
        sa.sin6_family = AF_INET6;
        sa.sin6_port   = htons(0);
        ::inet_pton(AF_INET6, "::1", &sa.sin6_addr);
        if (::bind(listen_fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) < 0) {
            ::close(listen_fd);
            Record("DualStack: outbound IPv6 literal connect primitives",
                    true, "skipped (no IPv6 loopback bind)");
            return;
        }
        if (::listen(listen_fd, 4) < 0) {
            ::close(listen_fd);
            Record("DualStack: outbound IPv6 literal connect primitives",
                    false, "listen() failed");
            return;
        }
        sockaddr_in6 bound{};
        socklen_t bound_len = sizeof(bound);
        ::getsockname(listen_fd, reinterpret_cast<sockaddr*>(&bound), &bound_len);
        const uint16_t bound_port = ntohs(bound.sin6_port);

        // Accept on a worker and signal completion via a promise/future
        // so we can wait for it EXPLICITLY before closing the listener.
        // The previous atomic-flag pattern had a race: closing listen_fd
        // while the thread was still in accept() would kick the thread
        // out with EBADF and the flag would never get set, causing a
        // flaky failure under load.
        std::promise<bool> accept_signal;
        auto accept_future = accept_signal.get_future();
        std::thread acceptor([&]() {
            sockaddr_in6 peer{};
            socklen_t peer_len = sizeof(peer);
            int cfd = ::accept(listen_fd, reinterpret_cast<sockaddr*>(&peer),
                                 &peer_len);
            accept_signal.set_value(cfd >= 0);
            if (cfd >= 0) ::close(cfd);
        });

        // ---- Client: EXACT primitives PoolPartition::CreateNewConnection
        //      uses post-fix ----
        InetAddr upstream_addr("::1", bound_port);
        bool ok = upstream_addr.is_valid();
        ok = ok && (upstream_addr.family() == InetAddr::Family::kIPv6);

        const sa_family_t family =
            (upstream_addr.family() == InetAddr::Family::kIPv6)
                ? AF_INET6 : AF_INET;
        ok = ok && (family == AF_INET6);

        int cfd = SocketHandler::CreateClientSocket(family);
        ok = ok && (cfd >= 0);

        const int rc = ::connect(cfd, upstream_addr.Addr(), upstream_addr.Len());
        // Non-blocking connect on loopback typically returns 0; some
        // kernels return -1 with errno=EINPROGRESS. EAFNOSUPPORT would
        // be the pre-fix failure mode (family mismatch between socket
        // and sockaddr). Reject that explicitly.
        const int connect_errno = errno;
        const bool connect_ok = (rc == 0) ||
                                (rc == -1 && connect_errno == EINPROGRESS);
        ok = ok && connect_ok;
        if (!connect_ok) {
            // Surface the pre-fix failure signal loudly.
            Record("DualStack: outbound IPv6 literal connect primitives",
                    false,
                    std::string("connect returned ") + std::to_string(rc) +
                    " errno=" + std::to_string(connect_errno) +
                    " (" + std::strerror(connect_errno) + ") — "
                    "EAFNOSUPPORT indicates the regression this test pins");
            if (cfd >= 0) ::close(cfd);
            ::close(listen_fd);
            acceptor.join();
            return;
        }

        // Wait for writability / the acceptor thread.
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(cfd, &wfds);
        timeval tv{};
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        int sel = ::select(cfd + 1, nullptr, &wfds, nullptr, &tv);
        ok = ok && (sel > 0);

        // SO_ERROR must be zero — otherwise connect failed asynchronously.
        int so_err = 0;
        socklen_t so_err_len = sizeof(so_err);
        ::getsockopt(cfd, SOL_SOCKET, SO_ERROR, &so_err, &so_err_len);
        ok = ok && (so_err == 0);

        // Wait up to 2 s for the acceptor thread to signal — must
        // happen BEFORE we close listen_fd so the blocking accept()
        // returns a real connection rather than EBADF. Without this
        // sync the test was flaky under load.
        bool accept_ok = false;
        if (accept_future.wait_for(std::chrono::seconds(2))
            == std::future_status::ready) {
            accept_ok = accept_future.get();
        }

        // Cleanup (ordering doesn't matter now — accept has signalled).
        ::close(cfd);
        ::close(listen_fd);
        acceptor.join();

        ok = ok && accept_ok;
        Record("DualStack: outbound IPv6 literal connect primitives", ok);
    } catch (const std::exception& e) {
        Record("DualStack: outbound IPv6 literal connect primitives",
                false, e.what());
    }
}

// ---------- PoolPartition's invalid-upstream guard ----------
//
// Pin that the post-fix invalid-literal path still fails cleanly (no
// fd leak, no crash) — the fix moved the parse ABOVE the socket creation,
// changing the failure-mode sequence from "create fd, parse, close fd"
// to "parse, fail, return" which is cheaper AND avoids the fd-churn
// class of TOCTOU.
inline void TestOutboundRejectsInvalidUpstreamLiteral() {
    std::cout << "\n[TEST] DualStack: outbound rejects invalid upstream literal..."
              << std::endl;
    try {
        // Validate the fix's parse-first guard using InetAddr directly
        // (mirrors the PoolPartition path without requiring a pool).
        InetAddr a("not-a-literal", 80);
        bool ok = !a.is_valid();
        InetAddr b("[::1]", 80);           // bracketed — also rejected per §5.1
        ok = ok && !b.is_valid();
        InetAddr c("example.com", 80);     // hostname — rejected; step 9 takes it
        ok = ok && !c.is_valid();
        // Control: bare literals still parse.
        InetAddr d("127.0.0.1", 80);
        ok = ok && d.is_valid() && d.family() == InetAddr::Family::kIPv4;
        InetAddr e("::1", 80);
        ok = ok && e.is_valid() && e.family() == InetAddr::Family::kIPv6;
        Record("DualStack: outbound rejects invalid upstream literal", ok);
    } catch (const std::exception& ex) {
        Record("DualStack: outbound rejects invalid upstream literal",
                false, ex.what());
    }
}

// ---------- HeaderRewriter Host-header format (P1 review-round preview) ----------
//
// Pin the step-7 preview fix: HeaderRewriter::RewriteRequest must emit
// RFC 3986 §3.2.2 authority — `[ipv6]:port` / `[ipv6]` for IPv6, bare
// for hostnames and IPv4. Previously emitted `::1:8080` which breaks
// backends. Exercises the code path the step-9 outbound IPv6 fix
// actually uses when the proxy forwards to an IPv6 upstream.
inline void TestHeaderRewriterIpv6HostAuthority() {
    std::cout << "\n[TEST] DualStack: HeaderRewriter brackets IPv6 Host authority..."
              << std::endl;
    try {
        HeaderRewriter::Config cfg;
        cfg.rewrite_host = true;
        HeaderRewriter rewriter(cfg);

        // IPv6 upstream, non-well-known port → "[::1]:8080"
        std::map<std::string, std::string> in1{{"host", "client.example"}};
        auto out1 = rewriter.RewriteRequest(
            in1, "10.0.0.5",                 // downstream peer
            false,                           // downstream_tls
            false,                           // upstream_tls
            "::1", 8080,                     // upstream host / port
            {});                             // sni_hostname
        bool ok = out1["host"] == "[::1]:8080";

        // IPv6 upstream on HTTP default port (80) → "[::1]" (port omitted)
        std::map<std::string, std::string> in2{{"host", "client.example"}};
        auto out2 = rewriter.RewriteRequest(
            in2, "10.0.0.5", false, false, "::1", 80, {});
        ok = ok && out2["host"] == "[::1]";

        // IPv6 upstream on HTTPS default port (443) with upstream_tls:
        // port omitted.
        std::map<std::string, std::string> in3{{"host", "client.example"}};
        auto out3 = rewriter.RewriteRequest(
            in3, "10.0.0.5", false, true, "::1", 443, {});
        ok = ok && out3["host"] == "[::1]";

        // Full IPv6 address, non-default port.
        std::map<std::string, std::string> in4{{"host", "client.example"}};
        auto out4 = rewriter.RewriteRequest(
            in4, "10.0.0.5", false, false, "2001:db8::1", 9000, {});
        ok = ok && out4["host"] == "[2001:db8::1]:9000";

        // Controls: IPv4 and hostname paths must produce identical output
        // to the pre-fix construction (bare, no brackets).
        std::map<std::string, std::string> in5{{"host", "c"}};
        auto out5 = rewriter.RewriteRequest(
            in5, "10.0.0.5", false, false, "127.0.0.1", 8080, {});
        ok = ok && out5["host"] == "127.0.0.1:8080";

        std::map<std::string, std::string> in6{{"host", "c"}};
        auto out6 = rewriter.RewriteRequest(
            in6, "10.0.0.5", false, false, "backend.example.com", 8080, {});
        ok = ok && out6["host"] == "backend.example.com:8080";

        std::map<std::string, std::string> in7{{"host", "c"}};
        auto out7 = rewriter.RewriteRequest(
            in7, "10.0.0.5", false, false, "backend.example.com", 80, {});
        ok = ok && out7["host"] == "backend.example.com";

        Record("DualStack: HeaderRewriter brackets IPv6 Host authority", ok,
                "out1=" + out1["host"] +
                " out2=" + out2["host"] +
                " out3=" + out3["host"] +
                " out4=" + out4["host"] +
                " out5=" + out5["host"] +
                " out6=" + out6["host"] +
                " out7=" + out7["host"]);
    } catch (const std::exception& e) {
        Record("DualStack: HeaderRewriter brackets IPv6 Host authority",
                false, e.what());
    }
}

// ---------- Test registrar ----------

inline void RunAllTests() {
    std::cout << "\n=== DualStack Tests ===" << std::endl;
    TestAcceptorIpv6LiteralBind();
    TestAcceptorRejectsHostname();
    TestOutboundIpv6LiteralConnectPrimitives();
    TestOutboundRejectsInvalidUpstreamLiteral();
    TestHeaderRewriterIpv6HostAuthority();
}

}  // namespace DualStackTests
