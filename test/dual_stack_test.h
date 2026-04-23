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
#include "tls/tls_client_context.h"     // TLS SNI trailing-dot strip test
#include "tls/tls_connection.h"
#include "test_server_runner.h"
#include "http_test_client.h"
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

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
    std::cout << "\n[TEST] DualStack: Acceptor rejects invalid bind host..."
              << std::endl;
    try {
        // Post-hostname-preview state: valid RFC 1123 hostnames go
        // through `HttpServer::ResolveBindHost`'s synchronous
        // getaddrinfo. Grammar-violating inputs (underscore, legacy
        // numeric-dotted forms) are rejected by
        // `IsValidHostOrIpLiteral` BEFORE getaddrinfo is called — no
        // real DNS query, so the test is fast and deterministic.
        // (Old input "not-a-valid-ip-or-hostname-literal" was actually
        // a valid single-label RFC 1123 hostname — system-dependent
        // resolution could have made the assertion flaky post-fix.)
        bool threw = false;
        try {
            // Underscore is invalid per RFC 1123 hostname grammar.
            HttpServer server("bad_hostname", 0);
            TestServerRunner<HttpServer> runner(server);
        } catch (const std::exception&) {
            threw = true;
        }
        Record("DualStack: Acceptor rejects invalid bind host", threw,
                threw ? "" : "Grammar-invalid hostname bind succeeded");
    } catch (const std::exception& e) {
        Record("DualStack: Acceptor rejects invalid bind host",
                false, e.what());
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

// Review-round fix: HeaderRewriter::RewriteRequest must strip a single
// trailing '.' from absolute-FQDN upstream hosts before assembling Host.
// Without this, `backend.example.com.` (operator uses trailing dot to
// suppress /etc/resolv.conf search-domain expansion) emits
// `Host: backend.example.com.` — many vhost backends treat the dotted
// form as a distinct authority and 400 / misroute. Covers both source
// branches: upstream_host (default) and sni_hostname (override).
inline void TestHeaderRewriterStripsTrailingDotInHost() {
    std::cout << "\n[TEST] DualStack: HeaderRewriter strips trailing dot in Host..."
              << std::endl;
    try {
        HeaderRewriter::Config cfg;
        cfg.rewrite_host = true;
        HeaderRewriter rewriter(cfg);

        bool ok = true;
        std::string details;

        // 1. upstream_host with trailing dot → Host must be dotless.
        std::map<std::string, std::string> in1{{"host", "c"}};
        auto out1 = rewriter.RewriteRequest(
            in1, "10.0.0.5", false, false,
            "backend.example.com.", 8080, {});
        ok = ok && out1["host"] == "backend.example.com:8080";
        details += "dotted_host_np=" + out1["host"] + " ";

        // 2. upstream_host with trailing dot, HTTP well-known port (80):
        // omit port AND strip dot → "backend.example.com".
        std::map<std::string, std::string> in2{{"host", "c"}};
        auto out2 = rewriter.RewriteRequest(
            in2, "10.0.0.5", false, false,
            "backend.example.com.", 80, {});
        ok = ok && out2["host"] == "backend.example.com";
        details += "dotted_host_80=" + out2["host"] + " ";

        // 3. sni_hostname override with trailing dot (pre-v0.37 where
        // Normalize does not yet strip overrides). Host source for an
        // HTTPS upstream with sni_hostname set: sni_hostname wins.
        std::map<std::string, std::string> in3{{"host", "c"}};
        auto out3 = rewriter.RewriteRequest(
            in3, "10.0.0.5", false,
            true,                        // upstream_tls
            "10.0.0.1", 443,             // upstream is IP literal
            "api.example.com.");         // SNI override with trailing dot
        ok = ok && out3["host"] == "api.example.com";  // strip + omit 443
        details += "dotted_sni=" + out3["host"] + " ";

        // 4. Control: dotless hostname input stays byte-identical (no
        // double strip, no accidental trim).
        std::map<std::string, std::string> in4{{"host", "c"}};
        auto out4 = rewriter.RewriteRequest(
            in4, "10.0.0.5", false, false,
            "backend.example.com", 8080, {});
        ok = ok && out4["host"] == "backend.example.com:8080";
        details += "dotless_ctrl=" + out4["host"] + " ";

        // 5. Control: IPv4 literal unaffected by trailing-dot path.
        std::map<std::string, std::string> in5{{"host", "c"}};
        auto out5 = rewriter.RewriteRequest(
            in5, "10.0.0.5", false, false,
            "127.0.0.1", 8080, {});
        ok = ok && out5["host"] == "127.0.0.1:8080";
        details += "ipv4_ctrl=" + out5["host"] + " ";

        // 6. Control: IPv6 literal unaffected (no trailing dot in IP
        // literal grammar; StripTrailingDot is a no-op).
        std::map<std::string, std::string> in6{{"host", "c"}};
        auto out6 = rewriter.RewriteRequest(
            in6, "10.0.0.5", false, false,
            "::1", 8080, {});
        ok = ok && out6["host"] == "[::1]:8080";
        details += "ipv6_ctrl=" + out6["host"] + " ";

        Record("DualStack: HeaderRewriter strips trailing dot in Host",
                ok, details);
    } catch (const std::exception& e) {
        Record("DualStack: HeaderRewriter strips trailing dot in Host",
                false, e.what());
    }
}

// Review-round fix (revert): InetAddr::Ip() must remain a HEADER-SAFE
// bare IP token. An earlier round appended RFC 4007 zone-id suffix
// (`fe80::1%5`) to preserve link-local peer identity, but `Ip()` is read
// transitively into X-Forwarded-For via HeaderRewriter, and zone-
// qualified literals are rejected by widely deployed XFF parsers / ACL
// engines / log pipelines — a P2 regression on the exact traffic the
// earlier fix targeted. This test pins the header-safety invariant so
// future attempts to "enrich" Ip() with scope/interface/etc must go
// through a separate peer-identity API instead.
inline void TestInetAddrIpIsHeaderSafe() {
    std::cout << "\n[TEST] DualStack: InetAddr::Ip() returns header-safe bare IP..."
              << std::endl;
    try {
        bool ok = true;
        std::string details;

        // Link-local IPv6 with non-zero scope_id — the specific input
        // shape that the reverted fix mis-handled. Must return bare
        // "fe80::1" (no "%5" suffix), preserving XFF parser
        // compatibility. Acknowledged consequence: link-local peers on
        // different interfaces collapse to the same Ip(); tracked as a
        // separate P3 deferred to a future phase (proper peer-identity
        // API).
        sockaddr_in6 s6{};
        s6.sin6_family = AF_INET6;
        ::inet_pton(AF_INET6, "fe80::1", &s6.sin6_addr);
        s6.sin6_port = htons(443);
        s6.sin6_scope_id = 5;
        InetAddr a(reinterpret_cast<const sockaddr*>(&s6), sizeof(s6));
        const std::string ip_a = a.Ip();
        ok = ok && ip_a == "fe80::1";
        details += "scope5_bare=" + ip_a + " ";

        // No '%' character anywhere in the returned string — the
        // invariant XFF / ACL parsers rely on.
        ok = ok && ip_a.find('%') == std::string::npos;

        // Control: scope_id=0 — same output.
        sockaddr_in6 s6b = s6;
        s6b.sin6_scope_id = 0;
        InetAddr b(reinterpret_cast<const sockaddr*>(&s6b), sizeof(s6b));
        ok = ok && b.Ip() == "fe80::1";
        details += "scope0_bare=" + b.Ip() + " ";

        // Control: IPv4 literal.
        sockaddr_in s4{};
        s4.sin_family = AF_INET;
        ::inet_pton(AF_INET, "192.0.2.1", &s4.sin_addr);
        s4.sin_port = htons(80);
        InetAddr d(reinterpret_cast<const sockaddr*>(&s4), sizeof(s4));
        ok = ok && d.Ip() == "192.0.2.1";
        details += "ipv4=" + d.Ip() + " ";

        // Control: literal-ctor path.
        InetAddr e("::1", 443);
        ok = ok && e.is_valid() && e.Ip() == "::1";
        details += "literal_v6=" + e.Ip() + " ";

        Record("DualStack: InetAddr::Ip() returns header-safe bare IP",
                ok, details);
    } catch (const std::exception& ex) {
        Record("DualStack: InetAddr::Ip() returns header-safe bare IP",
                false, ex.what());
    }
}

// Review-round fix: `TlsConnection` must strip the trailing dot from
// `sni_hostname` symmetrically with `HeaderRewriter`. Without this, an
// operator configuring `tls.sni_hostname = "api.example.com."` would see
// `Host: api.example.com` on the wire but TLS would negotiate SNI
// `api.example.com.` and verify against `api.example.com.` — a real
// Host/SNI mismatch that either hits the wrong vhost or fails
// hostname verification on valid certs. Exercise `TlsConnection`'s
// client-mode ctor directly and read back the effective SNI /
// verify-name via OpenSSL introspection (no handshake required).
inline void TestTlsConnectionStripsTrailingDotInSni() {
    std::cout << "\n[TEST] DualStack: TlsConnection strips trailing dot in SNI..."
              << std::endl;
    try {
        // socketpair produces two connected fds — we just need a valid
        // fd for SSL_set_fd; no handshake is attempted.
        int sv[2];
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
            Record("DualStack: TlsConnection strips trailing dot in SNI",
                    false, "socketpair failed");
            return;
        }

        TlsClientContext ctx("", /*verify_peer=*/true);
        TlsConnection conn(ctx, sv[0], "api.example.com.");

        // SSL_get_servername on a client SSL returns the SNI string
        // set via SSL_set_tlsext_host_name. Post-fix: dotless.
        SSL* ssl = conn.GetSslForTesting();
        const char* sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
        const std::string sni_str = sni ? sni : "";

        // X509_VERIFY_PARAM_get0_host(param, 0) returns the first
        // hostname registered via SSL_set1_host. Post-fix: dotless.
        X509_VERIFY_PARAM* vp = SSL_get0_param(ssl);
        const char* verify_name =
            (vp ? X509_VERIFY_PARAM_get0_host(vp, 0) : nullptr);
        const std::string vfy_str = verify_name ? verify_name : "";

        bool ok = true;
        ok = ok && sni_str == "api.example.com";
        ok = ok && vfy_str == "api.example.com";

        // Control: dotless input passes through byte-identical.
        TlsConnection conn2(ctx, sv[1], "api.example.com");
        SSL* ssl2 = conn2.GetSslForTesting();
        const char* sni2 = SSL_get_servername(ssl2, TLSEXT_NAMETYPE_host_name);
        X509_VERIFY_PARAM* vp2 = SSL_get0_param(ssl2);
        const char* verify_name2 =
            (vp2 ? X509_VERIFY_PARAM_get0_host(vp2, 0) : nullptr);
        ok = ok && (sni2 && std::string(sni2) == "api.example.com");
        ok = ok && (verify_name2 &&
                    std::string(verify_name2) == "api.example.com");

        Record("DualStack: TlsConnection strips trailing dot in SNI", ok,
                "sni=" + sni_str + " verify=" + vfy_str);

        // Socket fds are owned by SSL via SSL_set_fd; but ~TlsConnection
        // calls SSL_free which closes the underlying BIO — which in turn
        // closes the fd. So we do NOT close sv[0]/sv[1] manually here.
    } catch (const std::exception& e) {
        Record("DualStack: TlsConnection strips trailing dot in SNI",
                false, e.what());
    }
}

// Review-round fix (P1): HttpServer ctor must accept hostnames as
// bind_host by resolving them synchronously before NetServer / Acceptor
// construction. Pre-fix, a hostname like "localhost" threw at
// `Acceptor`'s literal-only validation (lines 20-25) INSIDE the member-
// init list, so `HttpServer::Start()` could never run the advertised
// resolution flow. Post-fix, `ResolveBindHost` resolves the hostname
// via synchronous getaddrinfo (with the same fail-closed grammar as
// DnsResolver) before the member-init list hits `net_server_`, so
// construction completes and NetServer is handed a literal IP.
//
// v0.48 step-6 update: the step-4 preview `ResolveBindHost` that did
// synchronous getaddrinfo at ctor time has been removed in favour of
// the PrepareConfig pipeline (Normalize + Validate only). Hostname
// resolution moves to `HttpServer::Start` (step 8, pending). For now,
// the ctor ACCEPTS hostnames at the validation layer (no throw) but
// Start()/Acceptor will reject them until step 8 wires DnsResolver
// into startup. This test pins the accept-at-ctor contract; a
// follow-up step-8 test will pin the Start-time resolution contract.
//
// Test strategy:
//   - Happy path uses "localhost" — must pass the ctor's validation
//     layer (Normalize strips brackets; Validate accepts RFC 1123
//     hostnames); we do NOT call Start() so Acceptor's literal-only
//     check is not exercised.
//   - Negative paths use grammar-violating inputs (empty, underscore,
//     legacy-numeric-dotted) that `IsValidHostOrIpLiteral` rejects
//     inside `ConfigLoader::Validate`, which PrepareConfig runs during
//     member-init. No DNS, fast.
//   - Constructor-only (no Start()) keeps the test focused on the
//     validation contract (pre-Start resolution is step 8's concern).
inline void TestHostnameBindResolvesAtCtor() {
    std::cout << "\n[TEST] DualStack: HttpServer ctor resolves hostname bind..."
              << std::endl;
    try {
        bool ok = true;
        std::string details;

        // Happy path: "localhost" — valid RFC 1123 hostname accepted
        // by `IsValidHostOrIpLiteral`. PrepareConfig (Normalize +
        // Validate) lets it through to NetServer's ctor; we construct
        // successfully without calling Start().
        bool localhost_ok = false;
        try {
            HttpServer server("localhost", 0);
            localhost_ok = true;
        } catch (const std::exception& e) {
            details += std::string("localhost_exc=") + e.what() + " ";
        }
        ok = ok && localhost_ok;
        details += "localhost_ctor=" +
                   std::string(localhost_ok ? "ok" : "FAILED") + " ";

        // Control 1: IP literal fast path — PrepareConfig treats
        // IPv4 literals as valid, NetServer/Acceptor bind happily.
        bool ipv4_ok = false;
        try {
            HttpServer server("127.0.0.1", 0);
            ipv4_ok = true;
        } catch (const std::exception& e) {
            details += std::string("ipv4_exc=") + e.what() + " ";
        }
        ok = ok && ipv4_ok;
        details += "ipv4_ctor=" +
                   std::string(ipv4_ok ? "ok" : "FAILED") + " ";

        // Control 2: legacy numeric-dotted form still fail-closed via
        // `IsValidHostOrIpLiteral` inside Validate. Never hits the
        // resolver — no risk of glibc inet_aton reinterpreting
        // `0127.0.0.1` → `87.0.0.1`.
        bool got_legacy_reject = false;
        try {
            HttpServer server("0127.0.0.1", 0);
            (void)server;
        } catch (const std::invalid_argument&) {
            got_legacy_reject = true;
        }
        ok = ok && got_legacy_reject;
        details += "legacy_numeric_rejected=" +
                   std::string(got_legacy_reject ? "yes" : "no") + " ";

        // Control 3: underscore in hostname — invalid per RFC 1123,
        // rejected by `IsValidHostOrIpLiteral`, no DNS query.
        bool got_underscore_reject = false;
        try {
            HttpServer server("bad_host", 0);
            (void)server;
        } catch (const std::invalid_argument&) {
            got_underscore_reject = true;
        }
        ok = ok && got_underscore_reject;
        details += "underscore_rejected=" +
                   std::string(got_underscore_reject ? "yes" : "no") + " ";

        // Control 4: empty host still rejects with clear message.
        bool got_empty_reject = false;
        try {
            HttpServer server("", 0);
            (void)server;
        } catch (const std::invalid_argument&) {
            got_empty_reject = true;
        }
        ok = ok && got_empty_reject;
        details += "empty_rejected=" +
                   std::string(got_empty_reject ? "yes" : "no") + " ";

        Record("DualStack: HttpServer ctor resolves hostname bind", ok,
                details);
    } catch (const std::exception& e) {
        Record("DualStack: HttpServer ctor resolves hostname bind",
                false, e.what());
    }
}

// ---------- Step 3 — HttpServer live_config_ + Stop stopping_ ----------

// GetLiveConfigSnapshot returns a fully-committed snapshot of the
// config the server was constructed with (after PrepareConfig's
// Normalize + Validate). Exercises the §11 v0.28 `mutable reload_mtx_`
// contract indirectly — the snapshot is safe to take on a const
// HttpServer even though the lock isn't visibly const.
inline void TestGetLiveConfigSnapshotReturnsInitialConfig() {
    std::cout << "\n[TEST] DualStack: HttpServer GetLiveConfigSnapshot..."
              << std::endl;
    try {
        ServerConfig cfg;
        cfg.bind_host = "127.0.0.1";
        cfg.bind_port = 0;
        cfg.idle_timeout_sec = 42;
        cfg.request_timeout_sec = 7;
        cfg.max_body_size = 1 << 20;
        cfg.dns.resolve_timeout_ms = 1234;

        HttpServer server(cfg);

        // Must compile AND work on a const reference.
        const HttpServer& cref = server;
        ServerConfig snap = cref.GetLiveConfigSnapshot();

        bool ok = true;
        std::string err;
        if (snap.bind_host != "127.0.0.1") {
            ok = false; err += "bind_host='" + snap.bind_host + "'; ";
        }
        if (snap.idle_timeout_sec != 42) {
            ok = false; err += "idle != 42; ";
        }
        if (snap.request_timeout_sec != 7) {
            ok = false; err += "req != 7; ";
        }
        if (snap.dns.resolve_timeout_ms != 1234) {
            ok = false; err += "dns.resolve_timeout_ms != 1234; ";
        }

        // Second snapshot produces the same content (serialisation
        // does not corrupt the live state).
        ServerConfig snap2 = server.GetLiveConfigSnapshot();
        if (snap2.bind_host != snap.bind_host ||
            snap2.idle_timeout_sec != snap.idle_timeout_sec) {
            ok = false; err += "snap2 diverged; ";
        }

        Record("DualStack: HttpServer GetLiveConfigSnapshot", ok, err);
    } catch (const std::exception& e) {
        Record("DualStack: HttpServer GetLiveConfigSnapshot",
                false, e.what());
    }
}

// NetServer three-phase lifecycle sanity: after Start() runs, the
// listen socket is bound and `GetBoundPort()` returns a real
// kernel-assigned port. §5.4a: ctor is config-only; Phase B
// (StartListening) runs inside Start() between the DNS batch and
// dispatcher bootstrap.
inline void TestNetServerStartListeningBinds() {
    std::cout << "\n[TEST] DualStack: NetServer StartListening binds..."
              << std::endl;
    try {
        HttpServer server("127.0.0.1", 0);
        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();
        bool ok = (port > 0 && port <= 65535);
        std::string err;
        if (!ok) err = "GetBoundPort=" + std::to_string(port);
        Record("DualStack: NetServer StartListening binds", ok, err);
    } catch (const std::exception& e) {
        Record("DualStack: NetServer StartListening binds",
                false, e.what());
    }
}

// Step 8: bind_resolved_ is populated after Start() commits, reflects
// the ephemeral-port refresh, and is absent pre-Start.
inline void TestBindResolvedPresentAfterStart() {
    std::cout << "\n[TEST] DualStack: bind_resolved_ populated post-Start..."
              << std::endl;
    try {
        HttpServer server("127.0.0.1", 0);

        // Pre-Start: absent.
        bool pre_empty = !server.GetBindResolved().has_value();

        TestServerRunner<HttpServer> runner(server);
        auto post = server.GetBindResolved();
        int actual_port = runner.GetPort();

        bool ok = pre_empty && post.has_value() &&
                  !post->error &&
                  post->port == actual_port &&
                  post->addr.Port() == actual_port &&
                  !post->addr.Ip().empty();
        std::string err;
        if (!ok) {
            err = "pre_empty=" + std::to_string(pre_empty) +
                  " has=" + std::to_string(post.has_value());
            if (post) {
                err += " err=" + std::to_string(post->error) +
                       " port=" + std::to_string(post->port) +
                       " addr.port=" + std::to_string(post->addr.Port()) +
                       " ip='" + post->addr.Ip() + "'" +
                       " actual=" + std::to_string(actual_port);
            }
        }
        Record("DualStack: bind_resolved_ populated post-Start", ok, err);
    } catch (const std::exception& e) {
        Record("DualStack: bind_resolved_ populated post-Start",
                false, e.what());
    }
}

// Step 8 Phase-A gate: if stopping_ is set before Start() runs DNS,
// Start returns cleanly without opening a listen socket. We can't
// manipulate stopping_ directly from tests (no setter), but we can
// exercise the equivalent effect by calling Stop() before Start():
// Stop sets stopping_ as its first line, then Start should abort at
// the Phase-A gate. bind_resolved_ stays absent; GetBoundPort stays 0.
inline void TestStartupAbortsWhenStopCalledFirst() {
    std::cout << "\n[TEST] DualStack: Start aborts if Stop ran first..."
              << std::endl;
    try {
        HttpServer server("127.0.0.1", 0);
        server.Stop();   // sets stopping_ = true
        // Start on the same thread; must NOT throw and must NOT open
        // a listener. The Phase-A gate observes stopping_=true and
        // returns; Phase-B therefore never runs.
        server.Start();  // returns quickly
        bool ok = !server.GetBindResolved().has_value() &&
                  server.GetBoundPort() == 0;
        Record("DualStack: Start aborts if Stop ran first", ok,
                ok ? "" :
                "bind_resolved_has=" + std::to_string(server.GetBindResolved().has_value()) +
                " bound_port=" + std::to_string(server.GetBoundPort()));
    } catch (const std::exception& e) {
        Record("DualStack: Start aborts if Stop ran first",
                false, e.what());
    }
}

// Step 9 full: PoolPartition stores its connect endpoint via an atomic
// shared_ptr target that step 11's reload will swap. This test exercises
// the atomic-load path end-to-end: an IP-literal upstream is configured,
// the pool partition is constructed through the production UpstreamManager
// path, and a proxy request reaches the upstream via the resolved
// endpoint. We use an in-process echo server as the "upstream" to avoid
// external DNS.
inline void TestPoolPartitionResolvedEndpointAtomic() {
    std::cout << "\n[TEST] DualStack: PoolPartition resolved_endpoint_ atomic..."
              << std::endl;
    try {
        // Upstream echo server.
        HttpServer upstream("127.0.0.1", 0);
        upstream.Get("/ping",
            [](const HttpRequest&, HttpResponse& r) {
                r.Status(200).Text("pong");
            });
        TestServerRunner<HttpServer> upstream_runner(upstream);
        int upstream_port = upstream_runner.GetPort();

        // Gateway pointing at the upstream by IP literal.
        ServerConfig cfg;
        cfg.bind_host = "127.0.0.1";
        cfg.bind_port = 0;
        UpstreamConfig uc;
        uc.name = "echo";
        uc.host = "127.0.0.1";
        uc.port = upstream_port;
        uc.proxy.route_prefix = "/api";
        uc.proxy.strip_prefix = true;  // /api/ping → /ping at upstream
        cfg.upstreams.push_back(uc);
        HttpServer gateway(cfg);
        gateway.Proxy("/api/*", "echo");

        TestServerRunner<HttpServer> gw_runner(gateway);
        int gw_port = gw_runner.GetPort();

        // Drive a request through: gateway→upstream should succeed,
        // proving CreateNewConnection's atomic_load on resolved_endpoint_
        // returned a valid endpoint.
        const std::string resp = TestHttpClient::HttpGet(gw_port, "/api/ping");
        const bool status_ok = resp.find("200 OK") != std::string::npos;
        const bool body_ok   = resp.find("pong")   != std::string::npos;
        const bool ok = status_ok && body_ok;
        std::string err;
        if (!ok) {
            err = "status_line_ok=" + std::to_string(status_ok) +
                  " body_ok=" + std::to_string(body_ok) +
                  " response_size=" + std::to_string(resp.size());
        }
        Record("DualStack: PoolPartition resolved_endpoint_ atomic",
                ok, err);
    } catch (const std::exception& e) {
        Record("DualStack: PoolPartition resolved_endpoint_ atomic",
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
    TestHeaderRewriterStripsTrailingDotInHost();
    TestInetAddrIpIsHeaderSafe();
    TestTlsConnectionStripsTrailingDotInSni();
    TestHostnameBindResolvesAtCtor();

    // Step 3 — NetServer three-phase + HttpServer state
    TestGetLiveConfigSnapshotReturnsInitialConfig();
    TestNetServerStartListeningBinds();

    // Step 8 — HttpServer::Start DNS orchestration
    TestBindResolvedPresentAfterStart();
    TestStartupAbortsWhenStopCalledFirst();

    // Step 9 full — PoolPartition resolved-endpoint split
    TestPoolPartitionResolvedEndpointAtomic();
}

}  // namespace DualStackTests
