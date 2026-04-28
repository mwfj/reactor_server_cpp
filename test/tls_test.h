#pragma once

#include "test_framework.h"
#include "tls/tls_context.h"
#include "tls/tls_client_context.h"
#include "tls/tls_connection.h"
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>
#include <sys/socket.h>
#include <cstdlib>

namespace TlsTests {

    // Generate self-signed cert for testing
    static bool GenerateTestCert() {
        int ret = std::system(
            "openssl req -x509 -newkey rsa:2048 -keyout /tmp/test_key.pem "
            "-out /tmp/test_cert.pem -days 1 -nodes "
            "-subj '/CN=localhost' 2>/dev/null");
        return (ret == 0);
    }

    static void CleanupTestCert() {
        std::remove("/tmp/test_cert.pem");
        std::remove("/tmp/test_key.pem");
    }

    void TestTlsContextCreation() {
        std::cout << "\n[TEST] TLS Context Creation..." << std::endl;
        try {
            if (!GenerateTestCert()) {
                TestFramework::RecordTest("TLS Context Creation", false,
                    "Failed to generate test cert", TestFramework::TestCategory::OTHER);
                return;
            }

            TlsContext ctx("/tmp/test_cert.pem", "/tmp/test_key.pem");
            bool pass = (ctx.GetCtx() != nullptr);

            CleanupTestCert();
            TestFramework::RecordTest("TLS Context Creation", pass,
                pass ? "" : "SSL_CTX is null", TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            CleanupTestCert();
            TestFramework::RecordTest("TLS Context Creation", false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    void TestTlsContextInvalidCert() {
        std::cout << "\n[TEST] TLS Context Invalid Cert..." << std::endl;
        try {
            bool threw = false;
            try {
                TlsContext ctx("/nonexistent/cert.pem", "/nonexistent/key.pem");
            } catch (const std::runtime_error&) {
                threw = true;
            }

            TestFramework::RecordTest("TLS Context Invalid Cert", threw,
                threw ? "" : "Expected exception for invalid cert", TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest("TLS Context Invalid Cert", false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // When upstream.host is a hostname and no tls.sni_hostname override is
    // set, PoolPartition passes the stripped hostname as the effective SNI
    // to TlsConnection (StripTrailingDot applied at computation time). This
    // test verifies that TlsConnection installs both the SNI extension
    // (SSL_set_tlsext_host_name) and the verify-name (SSL_set1_host) when
    // a non-empty sni_hostname is provided.
    // Effective-SNI rule: hostname host + verify_peer=true + empty
    // sni_hostname override → effective SNI = u.host (dotless).
    void TestSniRuleHostnameFallback() {
        std::cout << "\n[TEST] TLS SNI rule: hostname fallback sets SNI and verify name..."
                  << std::endl;
        try {
            // socketpair gives a valid fd without a real network handshake.
            int sv[2];
            if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
                TestFramework::RecordTest(
                    "TLS SNI rule: hostname fallback sets SNI and verify name",
                    false, "socketpair failed", TestFramework::TestCategory::OTHER);
                return;
            }

            // verify_peer=true: PoolPartition would strip any trailing dot and
            // pass the dotless hostname as effective SNI to TlsConnection.
            TlsClientContext ctx("", /*verify_peer=*/true);
            TlsConnection conn(ctx, sv[0], "api.example.com");

            SSL* ssl = conn.GetSslForTesting();
            const char* raw_sni =
                SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
            const std::string sni_str = raw_sni ? raw_sni : "";

            X509_VERIFY_PARAM* vp = SSL_get0_param(ssl);
            const char* raw_vfy =
                (vp ? X509_VERIFY_PARAM_get0_host(vp, 0) : nullptr);
            const std::string vfy_str = raw_vfy ? raw_vfy : "";

            // Both SNI extension and verify-name must equal the dotless hostname.
            bool ok = (sni_str == "api.example.com") &&
                      (vfy_str == "api.example.com");

            // sv[0] is owned by the SSL object via SSL_set_fd; SSL_free (called
            // by ~TlsConnection) closes it. Close sv[1] manually.
            ::close(sv[1]);
            TestFramework::RecordTest(
                "TLS SNI rule: hostname fallback sets SNI and verify name", ok,
                ok ? "" : "sni='" + sni_str + "' verify='" + vfy_str + "'",
                TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest(
                "TLS SNI rule: hostname fallback sets SNI and verify name",
                false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // When upstream.host is an IPv4 literal and no tls.sni_hostname override is
    // set, PoolPartition leaves effective_sni empty. TlsConnection receives ""
    // and must NOT call SSL_set_tlsext_host_name, so SSL_get_servername returns
    // nullptr (no SNI extension on the wire).
    // Effective-SNI rule: IPv4 literal host + verify_peer=false + empty
    // sni_hostname → effective SNI omitted. RFC 6066 §3 forbids IP literals
    // in SNI.
    void TestSniRuleIpv4LiteralNoFallback() {
        std::cout << "\n[TEST] TLS SNI rule: IPv4 literal suppresses SNI extension..."
                  << std::endl;
        try {
            int sv[2];
            if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
                TestFramework::RecordTest(
                    "TLS SNI rule: IPv4 literal suppresses SNI extension",
                    false, "socketpair failed", TestFramework::TestCategory::OTHER);
                return;
            }

            // PoolPartition passes "" as effective_sni for an IP-literal host.
            TlsClientContext ctx("", /*verify_peer=*/false);
            TlsConnection conn(ctx, sv[0], /*sni_hostname=*/"");

            SSL* ssl = conn.GetSslForTesting();
            const char* raw_sni =
                SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

            bool ok = (raw_sni == nullptr);
            ::close(sv[1]);
            TestFramework::RecordTest(
                "TLS SNI rule: IPv4 literal suppresses SNI extension", ok,
                ok ? "" : std::string("unexpected SNI='") + raw_sni + "'",
                TestFramework::TestCategory::OTHER);
        } catch (const std::exception& e) {
            TestFramework::RecordTest(
                "TLS SNI rule: IPv4 literal suppresses SNI extension",
                false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // IPv6 literals (bare "::1" or bracketed "[::1]") follow the same rule as
    // IPv4: PoolPartition leaves effective_sni empty. ConfigLoader::Normalize
    // strips brackets before the config reaches UpstreamManager, so by the
    // time TlsConnection is constructed the effective_sni is always "".
    // Both bare and bracketed paths therefore produce the same TlsConnection
    // behaviour (sni_hostname=""). This test exercises that path twice.
    // Effective-SNI rule: IPv6 literal host + any verify_peer + empty
    // sni_hostname → effective SNI omitted. RFC 6066 §3 forbids IP literals
    // in SNI.
    void TestSniRuleIpv6LiteralNoFallback() {
        std::cout << "\n[TEST] TLS SNI rule: IPv6 literal suppresses SNI extension..."
                  << std::endl;
        try {
            // Sub-case A: bare IPv6 literal path — PoolPartition passes "".
            {
                int sv[2];
                if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
                    TestFramework::RecordTest(
                        "TLS SNI rule: IPv6 literal suppresses SNI extension",
                        false, "socketpair failed (bare)", TestFramework::TestCategory::OTHER);
                    return;
                }

                TlsClientContext ctx("", /*verify_peer=*/false);
                TlsConnection conn(ctx, sv[0], "");

                SSL* ssl = conn.GetSslForTesting();
                const char* raw_sni =
                    SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

                if (raw_sni != nullptr) {
                    ::close(sv[1]);
                    TestFramework::RecordTest(
                        "TLS SNI rule: IPv6 literal suppresses SNI extension",
                        false,
                        std::string("bare-IPv6 path: unexpected SNI='") +
                            raw_sni + "'",
                        TestFramework::TestCategory::OTHER);
                    return;
                }
                ::close(sv[1]);
            }

            // Sub-case B: bracketed form — Normalize strips brackets and
            // IsIpLiteral returns true on the bare "::1", so PoolPartition
            // also passes "". The TlsConnection side is identical to A.
            {
                int sv[2];
                if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
                    TestFramework::RecordTest(
                        "TLS SNI rule: IPv6 literal suppresses SNI extension",
                        false, "socketpair failed (bracketed)", TestFramework::TestCategory::OTHER);
                    return;
                }

                TlsClientContext ctx("", /*verify_peer=*/false);
                TlsConnection conn(ctx, sv[0], "");

                SSL* ssl = conn.GetSslForTesting();
                const char* raw_sni =
                    SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

                bool ok = (raw_sni == nullptr);
                ::close(sv[1]);
                TestFramework::RecordTest(
                    "TLS SNI rule: IPv6 literal suppresses SNI extension", ok,
                    ok ? ""
                       : std::string("bracketed-IPv6 path: unexpected SNI='")
                             + raw_sni + "'",
                    TestFramework::TestCategory::OTHER);
            }
        } catch (const std::exception& e) {
            TestFramework::RecordTest(
                "TLS SNI rule: IPv6 literal suppresses SNI extension",
                false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    // When tls.sni_hostname is set explicitly it wins regardless of
    // upstream.host type (hostname or IP literal) and verify_peer value.
    // Sub-case 1: IP-literal host + explicit sni_hostname → SNI = sni_hostname.
    // Sub-case 2: explicit sni_hostname with a trailing dot → TlsConnection
    //   strips the dot (ConfigLoader::Normalize already strips at config-load
    //   time; TlsConnection's strip is defence-in-depth for callers that
    //   bypass Normalize, e.g. direct construction in tests).
    // Effective-SNI rule: any host + sni_hostname set → effective SNI =
    // sni_hostname (dotless). Also validates the trailing-dot strip.
    void TestSniRuleExplicitOverridesAlways() {
        std::cout << "\n[TEST] TLS SNI rule: explicit sni_hostname overrides host type..."
                  << std::endl;
        try {
            // Sub-case 1: IP-literal upstream with explicit SNI override.
            {
                int sv[2];
                if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
                    TestFramework::RecordTest(
                        "TLS SNI rule: explicit sni_hostname overrides host type",
                        false, "socketpair failed (sub1)", TestFramework::TestCategory::OTHER);
                    return;
                }

                TlsClientContext ctx("", /*verify_peer=*/false);
                TlsConnection conn(ctx, sv[0], "api.example.com");

                SSL* ssl = conn.GetSslForTesting();
                const char* raw_sni =
                    SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
                const std::string sni_str = raw_sni ? raw_sni : "";

                if (sni_str != "api.example.com") {
                    ::close(sv[1]);
                    TestFramework::RecordTest(
                        "TLS SNI rule: explicit sni_hostname overrides host type",
                        false,
                        "sub1 (IP+override): expected 'api.example.com', got '" +
                            sni_str + "'",
                        TestFramework::TestCategory::OTHER);
                    return;
                }
                ::close(sv[1]);
            }

            // Sub-case 2: explicit sni_hostname with a trailing dot —
            // TlsConnection strips it before calling SSL_set_tlsext_host_name.
            {
                int sv[2];
                if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
                    TestFramework::RecordTest(
                        "TLS SNI rule: explicit sni_hostname overrides host type",
                        false, "socketpair failed (sub2)", TestFramework::TestCategory::OTHER);
                    return;
                }

                TlsClientContext ctx("", /*verify_peer=*/false);
                // Trailing dot — TlsConnection must strip before the SSL call.
                TlsConnection conn(ctx, sv[0], "api.example.com.");

                SSL* ssl = conn.GetSslForTesting();
                const char* raw_sni =
                    SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
                const std::string sni_str = raw_sni ? raw_sni : "";

                bool ok = (sni_str == "api.example.com");
                ::close(sv[1]);
                TestFramework::RecordTest(
                    "TLS SNI rule: explicit sni_hostname overrides host type", ok,
                    ok ? ""
                       : "sub2 (override+trailing-dot): expected 'api.example.com'"
                         ", got '" + sni_str + "'",
                    TestFramework::TestCategory::OTHER);
            }
        } catch (const std::exception& e) {
            TestFramework::RecordTest(
                "TLS SNI rule: explicit sni_hostname overrides host type",
                false, e.what(), TestFramework::TestCategory::OTHER);
        }
    }

    void RunAllTests() {
        std::cout << "\n" << std::string(60, '=') << std::endl;
        std::cout << "TLS/SSL - UNIT TESTS" << std::endl;
        std::cout << std::string(60, '=') << std::endl;

        TestTlsContextCreation();
        TestTlsContextInvalidCert();
        TestSniRuleHostnameFallback();
        TestSniRuleIpv4LiteralNoFallback();
        TestSniRuleIpv6LiteralNoFallback();
        TestSniRuleExplicitOverridesAlways();
    }

}  // namespace TlsTests
