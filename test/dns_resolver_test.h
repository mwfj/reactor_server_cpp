#pragma once
//
// DnsResolver unit tests per §12.6 of HOSTNAME_RESOLUTION_AND_IPV6_DESIGN.md.
// Covers literal short-circuit, first-hostname lazy pool spawn, ResolveMany
// deadline bounding, per-instance isolation, detach-not-join teardown,
// and the static pure helpers.
//

#include "test_framework.h"
#include "net/dns_resolver.h"

#include <netdb.h>   // EAI_* constants used in assertions

#include <atomic>
#include <limits>     // std::numeric_limits
#include <chrono>
#include <condition_variable>
#include <future>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace DnsResolverTests {

using DNS_NAMESPACE::DnsConfig;
using DNS_NAMESPACE::DnsResolver;
using DNS_NAMESPACE::LookupFamily;
using DNS_NAMESPACE::ResolvedEndpoint;
using DNS_NAMESPACE::ResolveRequest;

// ---------- Shared helpers ----------

inline DnsConfig MakeFastConfig(int max_inflight = 2) {
    DnsConfig c;
    c.lookup_family         = LookupFamily::kV4Preferred;
    c.resolve_timeout_ms    = 500;
    c.overall_timeout_ms    = 1500;
    c.stale_on_error        = true;
    c.resolver_max_inflight = max_inflight;
    return c;
}

inline ResolveRequest MakeReq(const std::string& host, int port,
                               std::chrono::milliseconds timeout =
                                   std::chrono::milliseconds(500)) {
    ResolveRequest r;
    r.host    = host;
    r.port    = port;
    r.family  = LookupFamily::kV4Preferred;
    r.timeout = timeout;
    r.tag     = host;
    return r;
}

inline void Record(const std::string& name, bool ok,
                    const std::string& err = "") {
    TestFramework::RecordTest(name, ok, err,
                               TestFramework::TestCategory::OTHER);
}

// ---------- Static-helper tests ----------

inline void TestIsValidHostOrIpLiteral() {
    std::cout << "\n[TEST] DnsResolver: IsValidHostOrIpLiteral..." << std::endl;
    try {
        bool ok = true;
        // Accept IPv4 / IPv6 / hostnames (incl. trailing dot).
        ok = ok && DnsResolver::IsValidHostOrIpLiteral("127.0.0.1");
        ok = ok && DnsResolver::IsValidHostOrIpLiteral("0.0.0.0");
        ok = ok && DnsResolver::IsValidHostOrIpLiteral("::1");
        ok = ok && DnsResolver::IsValidHostOrIpLiteral("2001:db8::1");
        ok = ok && DnsResolver::IsValidHostOrIpLiteral("localhost");
        ok = ok && DnsResolver::IsValidHostOrIpLiteral("backend.ns.svc.cluster.local");
        ok = ok && DnsResolver::IsValidHostOrIpLiteral("backend.ns.svc.cluster.local.");
        // A label with a hyphen counts as "has letter or hyphen" per the
        // review-round tightening — safe because inet_aton rejects
        // strings containing '-'.
        ok = ok && DnsResolver::IsValidHostOrIpLiteral("1-2");
        // Reject bracketed IPv6 (Normalize strips brackets BEFORE validation).
        ok = ok && !DnsResolver::IsValidHostOrIpLiteral("[::1]");
        // Reject malformed.
        ok = ok && !DnsResolver::IsValidHostOrIpLiteral("");
        ok = ok && !DnsResolver::IsValidHostOrIpLiteral(".");
        ok = ok && !DnsResolver::IsValidHostOrIpLiteral("host..");
        ok = ok && !DnsResolver::IsValidHostOrIpLiteral(".leading");
        ok = ok && !DnsResolver::IsValidHostOrIpLiteral("-start");
        ok = ok && !DnsResolver::IsValidHostOrIpLiteral("end-");
        ok = ok && !DnsResolver::IsValidHostOrIpLiteral("1");       // pure integer
        ok = ok && !DnsResolver::IsValidHostOrIpLiteral("12345");
        Record("DnsResolver: IsValidHostOrIpLiteral", ok);
    } catch (const std::exception& e) {
        Record("DnsResolver: IsValidHostOrIpLiteral", false, e.what());
    }
}

// Review-round: legacy numeric-dotted forms must NOT pass through to
// getaddrinfo where glibc / BSD's NSS layer would reinterpret them via
// inet_aton (classful / octal numeric parsing). These strings are not
// strict dotted-quad IPv4 literals (inet_pton rejects them), and they
// used to fall through to hostname validation. With the tightened
// "must have letter or hyphen" rule, they now reject at validation
// time, fail-closed before reaching the DNS layer.
inline void TestIsValidHostOrIpLiteralRejectsLegacyNumericForms() {
    std::cout << "\n[TEST] DnsResolver: IsValidHostOrIpLiteral rejects legacy numeric forms..."
              << std::endl;
    try {
        bool ok = true;
        // inet_aton-style reinterpretations that must be blocked:
        //   "1.2.3"        → 1.2.0.3   (classful 3-part)
        //   "1.2"          → 1.0.0.2   (classful 2-part)
        //   "0127.0.0.1"   → 87.0.0.1  (octal first octet)
        //   "1.1.1.1.1"    → not a valid IPv4 but some libcs may still
        //                    try to interpret via gethostbyname legacy.
        //   "12.345.67"    → 3-part with out-of-range middle — libc may
        //                    still reinterpret via numeric path.
        ok = ok && !DnsResolver::IsValidHostOrIpLiteral("1.2.3");
        ok = ok && !DnsResolver::IsValidHostOrIpLiteral("1.2");
        ok = ok && !DnsResolver::IsValidHostOrIpLiteral("0127.0.0.1");
        ok = ok && !DnsResolver::IsValidHostOrIpLiteral("1.1.1.1.1");
        ok = ok && !DnsResolver::IsValidHostOrIpLiteral("12.345.67");
        // Trailing-dot forms of the same (FQDN notation over numeric).
        ok = ok && !DnsResolver::IsValidHostOrIpLiteral("1.2.3.");
        ok = ok && !DnsResolver::IsValidHostOrIpLiteral("0127.0.0.1.");

        // Control: genuine strict IPv4 literals still accept.
        ok = ok && DnsResolver::IsValidHostOrIpLiteral("127.0.0.1");
        ok = ok && DnsResolver::IsValidHostOrIpLiteral("1.2.3.4");
        // Control: hostnames that happen to start with digits still
        // accept (a letter elsewhere in the string distinguishes them
        // from numeric forms).
        ok = ok && DnsResolver::IsValidHostOrIpLiteral("1.example.com");
        ok = ok && DnsResolver::IsValidHostOrIpLiteral("1.2.example");
        ok = ok && DnsResolver::IsValidHostOrIpLiteral("3com.com");

        Record("DnsResolver: IsValidHostOrIpLiteral rejects legacy numeric forms",
                ok);
    } catch (const std::exception& e) {
        Record("DnsResolver: IsValidHostOrIpLiteral rejects legacy numeric forms",
                false, e.what());
    }
}

inline void TestFormatAuthority() {
    std::cout << "\n[TEST] DnsResolver: FormatAuthority..." << std::endl;
    try {
        bool ok = true;
        ok = ok && DnsResolver::FormatAuthority("127.0.0.1", 8080) == "127.0.0.1:8080";
        ok = ok && DnsResolver::FormatAuthority("::1", 8080)       == "[::1]:8080";
        ok = ok && DnsResolver::FormatAuthority("example.com", 443) == "example.com:443";
        ok = ok && DnsResolver::FormatAuthority("2001:db8::1", 8080) == "[2001:db8::1]:8080";
        // omit_port variant for SNI-like callers.
        ok = ok && DnsResolver::FormatAuthority("example.com", 443, true) == "example.com";
        ok = ok && DnsResolver::FormatAuthority("::1", 443, true) == "[::1]";
        Record("DnsResolver: FormatAuthority", ok);
    } catch (const std::exception& e) {
        Record("DnsResolver: FormatAuthority", false, e.what());
    }
}

inline void TestStripTrailingDot() {
    std::cout << "\n[TEST] DnsResolver: StripTrailingDot..." << std::endl;
    try {
        bool ok = true;
        ok = ok && DnsResolver::StripTrailingDot("example.com.") == "example.com";
        ok = ok && DnsResolver::StripTrailingDot("example.com")  == "example.com";
        ok = ok && DnsResolver::StripTrailingDot("").empty();
        ok = ok && DnsResolver::StripTrailingDot("x..") == "x.";
        Record("DnsResolver: StripTrailingDot", ok);
    } catch (const std::exception& e) {
        Record("DnsResolver: StripTrailingDot", false, e.what());
    }
}

inline void TestNormalizeHostToBare() {
    std::cout << "\n[TEST] DnsResolver: NormalizeHostToBare..." << std::endl;
    try {
        std::string out;
        bool ok = true;
        ok = ok && DnsResolver::NormalizeHostToBare("127.0.0.1", &out) && out == "127.0.0.1";
        ok = ok && DnsResolver::NormalizeHostToBare("[::1]", &out)      && out == "::1";
        ok = ok && DnsResolver::NormalizeHostToBare("[2001:db8::1]", &out)
                 && out == "2001:db8::1";
        ok = ok && DnsResolver::NormalizeHostToBare("example.com", &out)
                 && out == "example.com";
        // Malformed bracket forms reject.
        ok = ok && !DnsResolver::NormalizeHostToBare("[::1", &out);
        ok = ok && !DnsResolver::NormalizeHostToBare("[::1]:80", &out);
        ok = ok && !DnsResolver::NormalizeHostToBare("[notanip]", &out);
        // Review-round: brackets are RFC 3986 §3.2.2 IPv6-only. IPv4
        // literals inside brackets are malformed operator input and
        // must reject — previously accepted via the permissive
        // ParseLiteral helper.
        ok = ok && !DnsResolver::NormalizeHostToBare("[127.0.0.1]", &out);
        ok = ok && !DnsResolver::NormalizeHostToBare("[0.0.0.0]", &out);
        ok = ok && !DnsResolver::NormalizeHostToBare("[192.168.1.1]", &out);
        Record("DnsResolver: NormalizeHostToBare", ok);
    } catch (const std::exception& e) {
        Record("DnsResolver: NormalizeHostToBare", false, e.what());
    }
}

inline void TestParseLookupFamily() {
    std::cout << "\n[TEST] DnsResolver: ParseLookupFamily..." << std::endl;
    try {
        bool ok = true;
        ok = ok && DNS_NAMESPACE::ParseLookupFamily("v4_only")      == LookupFamily::kV4Only;
        ok = ok && DNS_NAMESPACE::ParseLookupFamily("v6_only")      == LookupFamily::kV6Only;
        ok = ok && DNS_NAMESPACE::ParseLookupFamily("v4_preferred") == LookupFamily::kV4Preferred;
        ok = ok && DNS_NAMESPACE::ParseLookupFamily("v6_preferred") == LookupFamily::kV6Preferred;
        bool threw = false;
        try { (void)DNS_NAMESPACE::ParseLookupFamily("bogus"); }
        catch (const std::invalid_argument&) { threw = true; }
        ok = ok && threw;
        Record("DnsResolver: ParseLookupFamily", ok);
    } catch (const std::exception& e) {
        Record("DnsResolver: ParseLookupFamily", false, e.what());
    }
}

// ---------- Literal short-circuit: pool stays dormant ----------

inline void TestLiteralOnlyConfigSpawnsNoWorkers() {
    std::cout << "\n[TEST] DnsResolver: Literal-only config never spawns workers..." << std::endl;
    try {
        DnsResolver resolver(MakeFastConfig(8));
        std::atomic<int> seam_calls{0};
        resolver.SetResolverForTesting([&](const ResolveRequest& req) {
            seam_calls.fetch_add(1);
            ResolvedEndpoint r;
            r.host = req.host; r.port = req.port; r.tag = req.tag;
            r.error = true;
            r.error_code = EAI_NONAME;
            r.error_message = "seam should not fire for literal";
            return r;
        });
        auto fut = resolver.ResolveAsync(MakeReq("127.0.0.1", 8080));
        bool ok = fut.wait_for(std::chrono::milliseconds(50))
                    == std::future_status::ready;
        auto ep = fut.get();
        ok = ok && !ep.error;
        ok = ok && ep.addr.Ip() == "127.0.0.1";
        ok = ok && ep.addr.Port() == 8080;
        ok = ok && seam_calls.load() == 0;
        Record("DnsResolver: Literal-only config never spawns workers", ok);
    } catch (const std::exception& e) {
        Record("DnsResolver: Literal-only config never spawns workers",
                false, e.what());
    }
}

inline void TestLiteralIPv6ShortCircuit() {
    std::cout << "\n[TEST] DnsResolver: Literal IPv6 short-circuit..." << std::endl;
    try {
        DnsResolver resolver(MakeFastConfig(2));
        auto fut = resolver.ResolveAsync(MakeReq("::1", 9000));
        bool ok = fut.wait_for(std::chrono::milliseconds(50))
                    == std::future_status::ready;
        auto ep = fut.get();
        ok = ok && !ep.error;
        ok = ok && ep.addr.family() == InetAddr::Family::kIPv6;
        ok = ok && ep.addr.Ip() == "::1";
        ok = ok && ep.addr.Port() == 9000;
        Record("DnsResolver: Literal IPv6 short-circuit", ok);
    } catch (const std::exception& e) {
        Record("DnsResolver: Literal IPv6 short-circuit", false, e.what());
    }
}

// ---------- First hostname triggers the pool ----------

inline void TestFirstHostnameTriggersPool() {
    std::cout << "\n[TEST] DnsResolver: First hostname triggers pool..." << std::endl;
    try {
        DnsResolver resolver(MakeFastConfig(2));
        std::atomic<int> seam_calls{0};
        resolver.SetResolverForTesting([&](const ResolveRequest& req) {
            seam_calls.fetch_add(1);
            ResolvedEndpoint r;
            r.host = req.host; r.port = req.port; r.tag = req.tag;
            r.addr = InetAddr("10.0.0.7", req.port);
            r.resolved_at = std::chrono::steady_clock::now();
            return r;
        });
        auto fut = resolver.ResolveAsync(MakeReq("some.host", 8080));
        bool ok = fut.wait_for(std::chrono::milliseconds(500))
                    == std::future_status::ready;
        auto ep = fut.get();
        ok = ok && !ep.error;
        ok = ok && seam_calls.load() == 1;
        ok = ok && ep.addr.Ip() == "10.0.0.7";
        Record("DnsResolver: First hostname triggers pool", ok);
    } catch (const std::exception& e) {
        Record("DnsResolver: First hostname triggers pool", false, e.what());
    }
}

// ---------- ResolveMany enforces the batch ceiling ----------

inline void TestResolveManyDeadlineBounded() {
    std::cout << "\n[TEST] DnsResolver: ResolveMany overall-timeout bounded..." << std::endl;
    try {
        DnsResolver resolver(MakeFastConfig(2));
        resolver.SetResolverForTesting([](const ResolveRequest& req) {
            ResolvedEndpoint r;
            r.host = req.host; r.port = req.port; r.tag = req.tag;
            if (req.host == "slow.host") {
                std::this_thread::sleep_for(std::chrono::milliseconds(300));
            }
            r.addr = InetAddr("10.0.0.1", req.port);
            r.resolved_at = std::chrono::steady_clock::now();
            return r;
        });

        std::vector<ResolveRequest> batch;
        batch.push_back(MakeReq("fast.host", 80, std::chrono::milliseconds(100)));
        batch.push_back(MakeReq("slow.host", 80, std::chrono::milliseconds(100)));

        const auto start = std::chrono::steady_clock::now();
        auto out = resolver.ResolveMany(std::move(batch),
                                         std::chrono::milliseconds(400));
        const auto elapsed_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();

        bool ok = out.size() == 2;
        ok = ok && !out[0].error;
        ok = ok && out[1].error;
        ok = ok && out[1].error_code == EAI_AGAIN;
        // Must complete within ~400ms — the batch ceiling — not compound
        // per-entry timeouts.
        ok = ok && elapsed_ms < 500;
        Record("DnsResolver: ResolveMany overall-timeout bounded", ok);
    } catch (const std::exception& e) {
        Record("DnsResolver: ResolveMany overall-timeout bounded",
                false, e.what());
    }
}

// ---------- Per-instance isolation ----------

inline void TestTwoResolversAreIndependent() {
    std::cout << "\n[TEST] DnsResolver: Two resolvers are independent..." << std::endl;
    try {
        DnsResolver a(MakeFastConfig(1));
        DnsResolver b(MakeFastConfig(1));
        a.SetResolverForTesting([](const ResolveRequest& req) {
            ResolvedEndpoint r;
            r.host = req.host; r.port = req.port; r.tag = req.tag;
            r.addr = InetAddr("10.0.0.1", req.port);
            return r;
        });
        b.SetResolverForTesting([](const ResolveRequest& req) {
            ResolvedEndpoint r;
            r.host = req.host; r.port = req.port; r.tag = req.tag;
            r.addr = InetAddr("10.0.0.2", req.port);
            return r;
        });
        auto fa = a.ResolveAsync(MakeReq("host.a", 80));
        auto fb = b.ResolveAsync(MakeReq("host.b", 80));
        bool ok = fa.wait_for(std::chrono::milliseconds(500))
                    == std::future_status::ready;
        ok = ok && fb.wait_for(std::chrono::milliseconds(500))
                    == std::future_status::ready;
        ok = ok && fa.get().addr.Ip() == "10.0.0.1";
        ok = ok && fb.get().addr.Ip() == "10.0.0.2";
        Record("DnsResolver: Two resolvers are independent", ok);
    } catch (const std::exception& e) {
        Record("DnsResolver: Two resolvers are independent",
                false, e.what());
    }
}

// ---------- Detach-not-join shutdown ----------

inline void TestShutdownDetachesWorkers() {
    std::cout << "\n[TEST] DnsResolver: Shutdown detaches workers..." << std::endl;
    try {
        struct Gate {
            std::mutex m;
            std::condition_variable cv;
            bool release = false;
        };
        auto gate = std::make_shared<Gate>();

        auto mock = [gate](const ResolveRequest& req) -> ResolvedEndpoint {
            std::unique_lock<std::mutex> lk(gate->m);
            gate->cv.wait(lk, [&] { return gate->release; });
            ResolvedEndpoint r;
            r.host = req.host; r.port = req.port; r.tag = req.tag;
            r.addr = InetAddr("10.0.0.1", req.port);
            return r;
        };

        std::future<ResolvedEndpoint> in_flight;
        std::future<ResolvedEndpoint> queued;
        std::chrono::steady_clock::duration dtor_latency{0};
        {
            DnsResolver resolver(MakeFastConfig(1));
            resolver.SetResolverForTesting(mock);
            in_flight = resolver.ResolveAsync(MakeReq("wedge.a", 80,
                std::chrono::milliseconds(50)));
            std::this_thread::sleep_for(std::chrono::milliseconds(30));
            queued = resolver.ResolveAsync(MakeReq("wedge.b", 80,
                std::chrono::milliseconds(50)));
            const auto t0 = std::chrono::steady_clock::now();
            // Scope end: dtor runs here.
            // Record the time after scope exit via a move-capture trick.
            (void)t0;
        }
        // We can't time around a scope exit cleanly without extra scaffolding,
        // so the assertion is "queued future was woken with a shutdown error".
        bool ok = queued.wait_for(std::chrono::milliseconds(100))
                    == std::future_status::ready;
        auto q = queued.get();
        ok = ok && q.error;

        // Release the wedged worker so its 256 KB stack can drain (otherwise
        // ASAN would flag it; on a healthy run the detached worker exits
        // cleanly after the notify below).
        {
            std::lock_guard<std::mutex> lk(gate->m);
            gate->release = true;
        }
        gate->cv.notify_all();
        (void)in_flight.wait_for(std::chrono::milliseconds(500));
        (void)dtor_latency;

        Record("DnsResolver: Shutdown detaches workers", ok);
    } catch (const std::exception& e) {
        Record("DnsResolver: Shutdown detaches workers",
                false, e.what());
    }
}

// ---------- P1: zero ResolveRequest.timeout falls back to config ----------

inline void TestResolveRequestZeroTimeoutUsesConfig() {
    std::cout << "\n[TEST] DnsResolver: zero ResolveRequest.timeout uses config..."
              << std::endl;
    try {
        // Config says resolve_timeout_ms=40 and overall_timeout_ms=400.
        // Caller hands ResolveMany a request with timeout=0 (sentinel).
        // Mock sleeps 150ms — longer than the config's per-entry budget,
        // shorter than the overall. Expect timeout via config-derived
        // per-entry deadline (~40ms), NOT via the batch ceiling.
        DnsConfig c = MakeFastConfig(1);
        c.resolve_timeout_ms = 40;
        c.overall_timeout_ms = 400;
        DnsResolver resolver(c);
        resolver.SetResolverForTesting([](const ResolveRequest& req) {
            std::this_thread::sleep_for(std::chrono::milliseconds(150));
            ResolvedEndpoint r;
            r.host = req.host; r.port = req.port; r.tag = req.tag;
            r.addr = InetAddr("10.0.0.1", req.port);
            return r;
        });

        ResolveRequest req;
        req.host = "some.host";
        req.port = 80;
        req.family = LookupFamily::kV4Preferred;
        // req.timeout left at struct default (0ms sentinel — P1 fix).
        req.tag = "test";

        std::vector<ResolveRequest> batch;
        batch.push_back(req);
        const auto start = std::chrono::steady_clock::now();
        auto out = resolver.ResolveMany(std::move(batch),
                                         std::chrono::milliseconds(400));
        const auto elapsed_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();

        bool ok = out.size() == 1;
        ok = ok && out[0].error;
        ok = ok && out[0].error_code == EAI_AGAIN;
        // Config per-entry was 40ms; allow slack for scheduler but well
        // under the 150ms mock sleep (which would fire if the sentinel
        // failed to substitute and some hardcoded path took over).
        ok = ok && elapsed_ms < 120;
        Record("DnsResolver: zero ResolveRequest.timeout uses config", ok,
                "elapsed=" + std::to_string(elapsed_ms) + "ms");
    } catch (const std::exception& e) {
        Record("DnsResolver: zero ResolveRequest.timeout uses config",
                false, e.what());
    }
}

// ---------- P1: one-arg ResolveMany uses config overall_timeout_ms ----------

inline void TestResolveManyOneArgUsesConfigOverallTimeout() {
    std::cout << "\n[TEST] DnsResolver: one-arg ResolveMany uses config overall..."
              << std::endl;
    try {
        // Config says overall_timeout_ms=80. Single request with a
        // per-entry timeout of 300ms — but the BATCH should time out at
        // ~80ms because the one-arg form picks up config.overall.
        DnsConfig c = MakeFastConfig(1);
        c.resolve_timeout_ms = 300;
        c.overall_timeout_ms = 80;
        DnsResolver resolver(c);
        resolver.SetResolverForTesting([](const ResolveRequest& req) {
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            ResolvedEndpoint r;
            r.host = req.host; r.port = req.port; r.tag = req.tag;
            r.addr = InetAddr("10.0.0.1", req.port);
            return r;
        });

        std::vector<ResolveRequest> batch;
        batch.push_back(MakeReq("some.host", 80,
                                  std::chrono::milliseconds(300)));

        const auto start = std::chrono::steady_clock::now();
        auto out = resolver.ResolveMany(std::move(batch));   // one-arg form
        const auto elapsed_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();

        bool ok = out.size() == 1;
        ok = ok && out[0].error;
        ok = ok && out[0].error_code == EAI_AGAIN;
        // Config overall was 80ms; tolerate scheduler slack up to 160ms.
        ok = ok && elapsed_ms < 160;
        Record("DnsResolver: one-arg ResolveMany uses config overall", ok,
                "elapsed=" + std::to_string(elapsed_ms) + "ms");
    } catch (const std::exception& e) {
        Record("DnsResolver: one-arg ResolveMany uses config overall",
                false, e.what());
    }
}

// ---------- P2: per-entry deadline anchored at dispatch ----------

inline void TestResolveManyPerEntryDeadlineFromDispatch() {
    std::cout << "\n[TEST] DnsResolver: per-entry deadline from dispatch..."
              << std::endl;
    try {
        // One worker, two requests with 100ms per-entry timeout. Mock
        // sleeps 80ms per resolve. Overall budget 400ms.
        //
        // Timeline with fix:
        //   T=0     Dispatch A, B. Per-entry deadlines anchored at T=0:
        //           A_deadline=100ms, B_deadline=100ms.
        //   T=~0    Worker picks up A, sleeps 80ms.
        //   T=80    A returns. ResolveMany loop consumes A's future (ok).
        //           Worker picks up B, sleeps 80ms.
        //   T=80    Loop reaches B. Wait for min(B_deadline, batch) - now
        //           = min(100, 400) - 80 = 20ms.
        //   T=100   Wait times out. B → EAI_AGAIN.
        //
        // Timeline WITHOUT fix (the bug):
        //   T=80    Loop reaches B; recompute B_deadline = now + 100
        //           = 180ms (RESET). Wait 100ms.
        //   T=160   Worker returns B successfully; loop observes READY.
        //           elapsed ≈ 160ms, B.error == false → WRONG.
        DnsConfig c = MakeFastConfig(1);   // single worker
        DnsResolver resolver(c);
        resolver.SetResolverForTesting([](const ResolveRequest& req) {
            std::this_thread::sleep_for(std::chrono::milliseconds(80));
            ResolvedEndpoint r;
            r.host = req.host; r.port = req.port; r.tag = req.tag;
            r.addr = InetAddr("10.0.0.1", req.port);
            r.resolved_at = std::chrono::steady_clock::now();
            return r;
        });

        std::vector<ResolveRequest> batch;
        batch.push_back(MakeReq("host.a", 80, std::chrono::milliseconds(100)));
        batch.push_back(MakeReq("host.b", 80, std::chrono::milliseconds(100)));
        const auto start = std::chrono::steady_clock::now();
        auto out = resolver.ResolveMany(std::move(batch),
                                         std::chrono::milliseconds(400));
        const auto elapsed_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();

        bool ok = out.size() == 2;
        ok = ok && !out[0].error;                   // A succeeded at T≈80.
        ok = ok && out[1].error;                    // B timed out.
        ok = ok && out[1].error_code == EAI_AGAIN;
        // Fix puts elapsed at ~100ms. Bug would produce ~160ms. Allow
        // generous scheduler slack (< 140) — still < bug's 160.
        ok = ok && elapsed_ms < 140;
        Record("DnsResolver: per-entry deadline anchored at dispatch", ok,
                "elapsed=" + std::to_string(elapsed_ms) + "ms "
                "(fix: ~100ms, bug: ~160ms)");
    } catch (const std::exception& e) {
        Record("DnsResolver: per-entry deadline anchored at dispatch",
                false, e.what());
    }
}

// ---------- Review-round P2: lookup_family sentinel → config ----------

inline void TestResolveRequestUnsetFamilyUsesConfig() {
    std::cout << "\n[TEST] DnsResolver: unset ResolveRequest.family uses config..."
              << std::endl;
    try {
        // Config policy says v6_only. Caller leaves ResolveRequest.family
        // at the struct default (kUnset). Mock records whatever family
        // it receives. Expect the mock to observe v6_only — proving the
        // sentinel substitution replaced kUnset with config_.lookup_family.
        DnsConfig c = MakeFastConfig(1);
        c.lookup_family = LookupFamily::kV6Only;
        DnsResolver resolver(c);

        std::atomic<int> observed_family{-1};
        resolver.SetResolverForTesting([&](const ResolveRequest& req) {
            observed_family.store(static_cast<int>(req.family));
            ResolvedEndpoint r;
            r.host = req.host; r.port = req.port; r.tag = req.tag;
            // We only care about the family the resolver saw — any
            // non-error return is fine.
            r.addr = InetAddr("::1", req.port);
            return r;
        });

        ResolveRequest req;
        req.host = "some.host";
        req.port = 80;
        // req.family left at struct default (kUnset — the sentinel).
        req.timeout = std::chrono::milliseconds(200);
        req.tag = "test";

        auto fut = resolver.ResolveAsync(std::move(req));
        bool ok = fut.wait_for(std::chrono::milliseconds(500))
                    == std::future_status::ready;
        (void)fut.get();   // drain so the worker doesn't leak.
        ok = ok && observed_family.load()
                    == static_cast<int>(LookupFamily::kV6Only);
        Record("DnsResolver: unset ResolveRequest.family uses config", ok,
                "observed_family=" + std::to_string(observed_family.load()) +
                " (expected " + std::to_string(
                    static_cast<int>(LookupFamily::kV6Only)) + ")");
    } catch (const std::exception& e) {
        Record("DnsResolver: unset ResolveRequest.family uses config",
                false, e.what());
    }
}

// ---------- Review-round P2: per-request family override beats config ----------

inline void TestResolveRequestExplicitFamilyOverridesConfig() {
    std::cout << "\n[TEST] DnsResolver: explicit ResolveRequest.family overrides config..."
              << std::endl;
    try {
        // Config policy says v4_preferred. Caller explicitly sets family
        // to kV6Only. The explicit value must win — sentinel substitution
        // must not clobber a real caller-supplied value.
        DnsConfig c = MakeFastConfig(1);
        c.lookup_family = LookupFamily::kV4Preferred;
        DnsResolver resolver(c);

        std::atomic<int> observed_family{-1};
        resolver.SetResolverForTesting([&](const ResolveRequest& req) {
            observed_family.store(static_cast<int>(req.family));
            ResolvedEndpoint r;
            r.host = req.host; r.port = req.port; r.tag = req.tag;
            r.addr = InetAddr("::1", req.port);
            return r;
        });

        ResolveRequest req;
        req.host = "some.host";
        req.port = 80;
        req.family = LookupFamily::kV6Only;   // explicit caller override
        req.timeout = std::chrono::milliseconds(200);
        req.tag = "test";

        auto fut = resolver.ResolveAsync(std::move(req));
        bool ok = fut.wait_for(std::chrono::milliseconds(500))
                    == std::future_status::ready;
        (void)fut.get();
        ok = ok && observed_family.load()
                    == static_cast<int>(LookupFamily::kV6Only);
        Record("DnsResolver: explicit family overrides config", ok,
                "observed_family=" + std::to_string(observed_family.load()));
    } catch (const std::exception& e) {
        Record("DnsResolver: explicit family overrides config",
                false, e.what());
    }
}

// ---------- Review-round P2: ParseHostPort rejects non-IP in brackets ----------

inline void TestParseHostPortRejectsNonIpBrackets() {
    std::cout << "\n[TEST] DnsResolver: ParseHostPort rejects non-IPv6 brackets..."
              << std::endl;
    try {
        std::string host;
        int port = -1;
        bool ok = true;

        // Must REJECT: bracketed hostname (RFC 3986 violation).
        ok = ok && !DnsResolver::ParseHostPort("[example.com]", &host, &port);
        ok = ok && !DnsResolver::ParseHostPort("[example.com]:443", &host, &port);
        ok = ok && !DnsResolver::ParseHostPort("[notanip]", &host, &port);
        ok = ok && !DnsResolver::ParseHostPort("[not-an-ip]:8080", &host, &port);
        ok = ok && !DnsResolver::ParseHostPort("[]", &host, &port);

        // Must REJECT: bracketed IPv4 literal (RFC 3986 §3.2.2 reserves
        // brackets for IPv6 / IPvFuture only). Review-round fix — the
        // previous round's ParseLiteral-based check accepted these.
        ok = ok && !DnsResolver::ParseHostPort("[127.0.0.1]", &host, &port);
        ok = ok && !DnsResolver::ParseHostPort("[127.0.0.1]:443", &host, &port);
        ok = ok && !DnsResolver::ParseHostPort("[0.0.0.0]:8080", &host, &port);
        ok = ok && !DnsResolver::ParseHostPort("[192.168.1.1]", &host, &port);

        // Malformed bracketed forms that were already rejected — pin
        // the pre-existing behavior here too.
        ok = ok && !DnsResolver::ParseHostPort("[::1", &host, &port);
        ok = ok && !DnsResolver::ParseHostPort("[::1]extra", &host, &port);
        ok = ok && !DnsResolver::ParseHostPort("[::1]x80", &host, &port);

        // Must ACCEPT: genuine IPv6 literals in brackets.
        host.clear(); port = -1;
        ok = ok && DnsResolver::ParseHostPort("[::1]", &host, &port)
                 && host == "::1" && port == 0;
        host.clear(); port = -1;
        ok = ok && DnsResolver::ParseHostPort("[::1]:443", &host, &port)
                 && host == "::1" && port == 443;
        host.clear(); port = -1;
        ok = ok && DnsResolver::ParseHostPort("[2001:db8::1]:8080", &host, &port)
                 && host == "2001:db8::1" && port == 8080;

        // Bare forms unaffected by the bracketed-path fix.
        host.clear(); port = -1;
        ok = ok && DnsResolver::ParseHostPort("example.com", &host, &port)
                 && host == "example.com" && port == 0;
        host.clear(); port = -1;
        ok = ok && DnsResolver::ParseHostPort("example.com:443", &host, &port)
                 && host == "example.com" && port == 443;
        host.clear(); port = -1;
        ok = ok && DnsResolver::ParseHostPort("127.0.0.1:80", &host, &port)
                 && host == "127.0.0.1" && port == 80;

        Record("DnsResolver: ParseHostPort rejects non-IPv6 brackets", ok);
    } catch (const std::exception& e) {
        Record("DnsResolver: ParseHostPort rejects non-IPv6 brackets",
                false, e.what());
    }
}

// ---------- Review-round: ctor rejects non-positive resolver_max_inflight ----------

inline void TestDnsResolverCtorRejectsNonPositiveInflight() {
    std::cout << "\n[TEST] DnsResolver: ctor rejects non-positive resolver_max_inflight..."
              << std::endl;
    try {
        bool threw_on_zero = false;
        try {
            DnsConfig c = MakeFastConfig(0);     // zero workers = silent hang
            DnsResolver r(c);
            (void)r;
        } catch (const std::invalid_argument&) {
            threw_on_zero = true;
        }

        bool threw_on_negative_one = false;
        try {
            DnsConfig c = MakeFastConfig(-1);    // cast to SIZE_MAX in reserve
            DnsResolver r(c);
            (void)r;
        } catch (const std::invalid_argument&) {
            threw_on_negative_one = true;
        }

        bool threw_on_int_min = false;
        try {
            DnsConfig c = MakeFastConfig(std::numeric_limits<int>::min());
            DnsResolver r(c);
            (void)r;
        } catch (const std::invalid_argument&) {
            threw_on_int_min = true;
        }

        // Control: positive value still accepts.
        bool accepts_positive = false;
        try {
            DnsConfig c = MakeFastConfig(1);
            DnsResolver r(c);
            accepts_positive = true;
        } catch (...) {
            accepts_positive = false;
        }

        bool ok = threw_on_zero && threw_on_negative_one
                   && threw_on_int_min && accepts_positive;
        Record("DnsResolver: ctor rejects non-positive resolver_max_inflight",
                ok,
                "threw_on_zero=" + std::to_string(threw_on_zero) +
                " threw_on_-1=" + std::to_string(threw_on_negative_one) +
                " threw_on_INT_MIN=" + std::to_string(threw_on_int_min) +
                " accepts_1=" + std::to_string(accepts_positive));
    } catch (const std::exception& e) {
        Record("DnsResolver: ctor rejects non-positive resolver_max_inflight",
                false, e.what());
    }
}

// ---------- Review-round: queued items expire while workers are wedged ----------

inline void TestQueuedItemExpiresDuringWorkerStall() {
    std::cout << "\n[TEST] DnsResolver: queued items expire during worker stall..."
              << std::endl;
    try {
        // Scenario: every worker is wedged in the seam callable on a
        // shared gate. A submitted item sits in the queue past its
        // deadline — no worker can pop it. Pre-fix: item's future
        // never becomes ready until we either release the gate or
        // destroy the resolver. Post-fix: a subsequent ResolveAsync
        // call triggers a front-sweep that evicts the expired item
        // with EAI_AGAIN "queue-time exceeded".
        struct Gate {
            std::mutex m;
            std::condition_variable cv;
            bool release = false;
        };
        auto gate = std::make_shared<Gate>();

        DnsResolver resolver(MakeFastConfig(1));   // 1 worker
        resolver.SetResolverForTesting([gate](const ResolveRequest& req) {
            // Wedge the single worker on the gate. Until release,
            // the worker cannot pop further items from the queue.
            std::unique_lock<std::mutex> lk(gate->m);
            gate->cv.wait(lk, [&] { return gate->release; });
            ResolvedEndpoint r;
            r.host = req.host; r.port = req.port; r.tag = req.tag;
            r.addr = InetAddr("10.0.0.1", req.port);
            return r;
        });

        // A: picked up by the worker and wedges on the gate.
        auto fut_a = resolver.ResolveAsync(
            MakeReq("host.a", 80, std::chrono::milliseconds(500)));
        // Give the worker a moment to dequeue A and park on the gate.
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        // B: submitted behind A with a SHORT timeout. No worker is
        // available to pop it — it sits in the queue.
        auto fut_b = resolver.ResolveAsync(
            MakeReq("host.b", 80, std::chrono::milliseconds(30)));

        // Wait for B to become ready. Post-reaper: the reaper thread
        // fires the timeout at B's deadline (~30ms), so the future
        // transitions to READY without requiring a follow-up
        // submission. (The earlier version of this test submitted a
        // follow-up request to trigger the submission-side sweep, and
        // asserted that B was NOT ready before that submission. That
        // assertion no longer holds under the reaper, which closes the
        // "future never becomes ready at timeout" API-contract hole;
        // see TestQueuedItemExpiresWithoutFollowUpSubmission for the
        // focused reaper test.) We still submit a follow-up request
        // afterwards to exercise the submission-side sweep as a
        // defense-in-depth path, but the correctness bar is simply
        // that B gets EAI_AGAIN with the queue-time-exceeded marker.
        const bool ready =
            fut_b.wait_for(std::chrono::milliseconds(200))
                == std::future_status::ready;
        ResolvedEndpoint result_b;
        if (ready) result_b = fut_b.get();

        // Exercise the submission-side sweep as a defense-in-depth
        // path (harmless; B is already evicted by the reaper).
        auto fut_c = resolver.ResolveAsync(
            MakeReq("host.c", 80, std::chrono::milliseconds(500)));

        // Cleanup: release the gate so the wedged worker completes A
        // (and pops/processes C). Drain both futures so ASAN/leak
        // detectors see a clean teardown.
        {
            std::lock_guard<std::mutex> lk(gate->m);
            gate->release = true;
        }
        gate->cv.notify_all();
        (void)fut_a.wait_for(std::chrono::milliseconds(500));
        (void)fut_c.wait_for(std::chrono::milliseconds(500));

        bool ok = ready;
        ok = ok && result_b.error;
        ok = ok && result_b.error_code == EAI_AGAIN;
        ok = ok && result_b.error_message.find("queue-time exceeded")
                    != std::string::npos;
        Record("DnsResolver: queued item expires during worker stall", ok,
                "ready=" + std::to_string(ready) +
                " err=" + std::to_string(result_b.error_code));
    } catch (const std::exception& e) {
        Record("DnsResolver: queued item expires during worker stall",
                false, e.what());
    }
}

// ---------- Review-round: non-saturated mixed-timeout queue ALSO expires ----------

inline void TestNonSaturatedMixedTimeoutQueueExpires() {
    std::cout << "\n[TEST] DnsResolver: non-saturated mixed-timeout queue expires..."
              << std::endl;
    try {
        // Reviewer scenario: queue is [5s_item, 30ms_item]. The
        // front-only sweep stops at the live 5s head; the saturation-
        // gated full sweep does not fire because queue size (2) is
        // nowhere near max (10000). Under a stalled-worker condition
        // this left the 30ms caller's future pending indefinitely,
        // breaking the per-request deadline contract.
        //
        // With the round-3 fix (full sweep on every submission, not
        // gated on saturation), the 30ms item is evicted the next
        // time any caller submits a resolve.
        struct Gate {
            std::mutex m;
            std::condition_variable cv;
            bool release = false;
        };
        auto gate = std::make_shared<Gate>();

        DnsResolver resolver(MakeFastConfig(1));   // single worker
        resolver.SetResolverForTesting([gate](const ResolveRequest& req) {
            std::unique_lock<std::mutex> lk(gate->m);
            gate->cv.wait(lk, [&] { return gate->release; });
            ResolvedEndpoint r;
            r.host = req.host; r.port = req.port; r.tag = req.tag;
            r.addr = InetAddr("10.0.0.1", req.port);
            return r;
        });

        // A: picked up by the worker, wedges on the gate.
        auto fut_a = resolver.ResolveAsync(
            MakeReq("host.a", 80, std::chrono::milliseconds(5000)));
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        // B_long: queued, LONG (5s) deadline. Will block any front-only
        // sweep — its deadline is far in the future.
        auto fut_b_long = resolver.ResolveAsync(
            MakeReq("host.b_long", 80, std::chrono::milliseconds(5000)));

        // C: queued behind B_long with SHORT (30ms) deadline. Queue is
        // now [B_long, C] — size 2, nowhere near max=10000 saturation.
        auto fut_c = resolver.ResolveAsync(
            MakeReq("host.c", 80, std::chrono::milliseconds(30)));

        // Wait for C to become ready. Post-reaper: the reaper fires
        // at C's deadline (~30ms) independently of any follow-up
        // submission, so the future transitions to READY directly.
        // (The earlier version of this test relied on a follow-up
        // submission to trigger the submission-side full sweep — that
        // path still works as defense-in-depth, but the correctness
        // bar is just that C gets EAI_AGAIN with the queue-time-
        // exceeded marker, however it reaches that state. The focused
        // reaper test is TestQueuedItemExpiresWithoutFollowUpSubmission.)
        const bool c_ready =
            fut_c.wait_for(std::chrono::milliseconds(200))
                == std::future_status::ready;
        ResolvedEndpoint res_c;
        if (c_ready) res_c = fut_c.get();

        // Also exercise the submission-side full sweep as defense-
        // in-depth. Harmless since C has already been evicted by the
        // reaper at ~30ms; this just demonstrates the mechanism is
        // still reachable and non-saturated.
        auto fut_d = resolver.ResolveAsync(
            MakeReq("host.d", 80, std::chrono::milliseconds(5000)));

        // Cleanup.
        {
            std::lock_guard<std::mutex> lk(gate->m);
            gate->release = true;
        }
        gate->cv.notify_all();
        (void)fut_a.wait_for(std::chrono::milliseconds(500));
        (void)fut_b_long.wait_for(std::chrono::milliseconds(500));
        (void)fut_d.wait_for(std::chrono::milliseconds(500));

        bool ok = c_ready;
        ok = ok && res_c.error;
        ok = ok && res_c.error_code == EAI_AGAIN;
        ok = ok && res_c.error_message.find("queue-time exceeded")
                    != std::string::npos;
        Record("DnsResolver: non-saturated mixed-timeout queue expires",
                ok,
                "c_ready=" + std::to_string(c_ready) +
                " err=" + std::to_string(res_c.error_code));
    } catch (const std::exception& e) {
        Record("DnsResolver: non-saturated mixed-timeout queue expires",
                false, e.what());
    }
}

// ---------- Review-round: full sweep at saturation catches non-monotone expiry ----------

inline void TestMixedTimeoutSaturationTriggersFullSweep() {
    std::cout << "\n[TEST] DnsResolver: mixed-timeout saturation triggers full sweep..."
              << std::endl;
    try {
        // Scenario the reviewer described: queue is AT capacity with a
        // mixed-deadline mix where the FRONT is not yet expired but the
        // body IS. Front-only sweep can't evict anything (front is
        // live); without the full-sweep-at-saturation fix, fresh
        // submissions would hit spurious "resolver saturated" even
        // though most queued work is long dead.
        //
        // Uses the test-only SetMaxQueuedItemsForTesting hook so we can
        // exercise the saturation path at 4-item cap instead of
        // production's 10000.
        struct Gate {
            std::mutex m;
            std::condition_variable cv;
            bool release = false;
        };
        auto gate = std::make_shared<Gate>();

        DnsResolver resolver(MakeFastConfig(1));   // single worker
        resolver.SetMaxQueuedItemsForTesting(4);   // small cap for test

        resolver.SetResolverForTesting([gate](const ResolveRequest& req) {
            std::unique_lock<std::mutex> lk(gate->m);
            gate->cv.wait(lk, [&] { return gate->release; });
            ResolvedEndpoint r;
            r.host = req.host; r.port = req.port; r.tag = req.tag;
            r.addr = InetAddr("10.0.0.1", req.port);
            return r;
        });

        // A: picked up by the single worker, wedges on the gate.
        auto fut_a = resolver.ResolveAsync(
            MakeReq("host.a", 80, std::chrono::milliseconds(5000)));
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        // B_long: FRONT of queue, long timeout. Front-only sweep cannot
        // evict B_long — if the fix were front-only the saturation
        // check below would still reject fresh traffic.
        auto fut_b_long = resolver.ResolveAsync(
            MakeReq("host.b_long", 80, std::chrono::milliseconds(5000)));

        // Fill to cap with SHORT-timeout stragglers.
        auto fut_c = resolver.ResolveAsync(
            MakeReq("host.c", 80, std::chrono::milliseconds(30)));
        auto fut_d = resolver.ResolveAsync(
            MakeReq("host.d", 80, std::chrono::milliseconds(30)));
        auto fut_e = resolver.ResolveAsync(
            MakeReq("host.e", 80, std::chrono::milliseconds(30)));

        // Queue is now at the test cap: [B_long (5s), C (30ms),
        // D (30ms), E (30ms)] — 4 items, max=4.

        // Wait past the short-timeout deadlines. B_long stays live.
        std::this_thread::sleep_for(std::chrono::milliseconds(80));

        // F: fresh submission. Flow under the fix:
        //   - ResolveAsync acquires state_->mtx.
        //   - Front-sweep: B_long is live → stop (no evictions).
        //   - Saturation check: queue.size()==4 >= max==4 → enter
        //     full-sweep branch.
        //   - Full sweep: walk queue; C/D/E are expired → set_value
        //     EAI_AGAIN, remove; B_long stays.
        //   - queue.size()==1 < 4 → push F. F is queued, NOT rejected.
        auto fut_f = resolver.ResolveAsync(
            MakeReq("host.f", 80, std::chrono::milliseconds(5000)));

        // F must be queued (future PENDING), not synchronously rejected
        // with EAI_AGAIN "resolver saturated". If the full-sweep fix
        // were absent, the call would have returned an immediate-ready
        // saturated error future.
        const bool f_queued =
            fut_f.wait_for(std::chrono::milliseconds(10))
                != std::future_status::ready;

        // Release gate so the wedged worker drains A, then B_long, F.
        {
            std::lock_guard<std::mutex> lk(gate->m);
            gate->release = true;
        }
        gate->cv.notify_all();

        // Wait for F to complete (drains entire queue once gate released).
        const bool f_completes =
            fut_f.wait_for(std::chrono::milliseconds(1000))
                == std::future_status::ready;
        ResolvedEndpoint res_f;
        if (f_completes) res_f = fut_f.get();

        // Verify C/D/E were evicted with the queue-time timeout marker.
        auto check_expired = [](std::future<ResolvedEndpoint>& fut) {
            if (fut.wait_for(std::chrono::milliseconds(50))
                    != std::future_status::ready) return false;
            auto r = fut.get();
            return r.error && r.error_code == EAI_AGAIN &&
                   r.error_message.find("queue-time exceeded") !=
                       std::string::npos;
        };
        const bool c_evicted = check_expired(fut_c);
        const bool d_evicted = check_expired(fut_d);
        const bool e_evicted = check_expired(fut_e);

        // A and B_long must have succeeded (worker drained them after
        // gate release).
        (void)fut_a.wait_for(std::chrono::milliseconds(500));
        (void)fut_b_long.wait_for(std::chrono::milliseconds(500));

        bool ok = f_queued;
        ok = ok && f_completes;
        ok = ok && !res_f.error;          // F succeeded, not saturated
        ok = ok && c_evicted;
        ok = ok && d_evicted;
        ok = ok && e_evicted;
        Record("DnsResolver: mixed-timeout saturation triggers full sweep",
                ok,
                "f_queued=" + std::to_string(f_queued) +
                " f_completes=" + std::to_string(f_completes) +
                " f_err=" + std::to_string(res_f.error_code) +
                " c_evicted=" + std::to_string(c_evicted) +
                " d_evicted=" + std::to_string(d_evicted) +
                " e_evicted=" + std::to_string(e_evicted));
    } catch (const std::exception& e) {
        Record("DnsResolver: mixed-timeout saturation triggers full sweep",
                false, e.what());
    }
}

// ---------- Review-round: ParseHostPort rejects malformed port tokens ----------

inline void TestParseHostPortRejectsMalformedPort() {
    std::cout << "\n[TEST] DnsResolver: ParseHostPort rejects malformed port..."
              << std::endl;
    try {
        std::string host;
        int port = -1;
        bool ok = true;

        // Trailing non-digit junk after the port. std::stoi would have
        // accepted these and returned only the leading digits.
        ok = ok && !DnsResolver::ParseHostPort("[::1]:443junk", &host, &port);
        ok = ok && !DnsResolver::ParseHostPort("example.com:443junk", &host, &port);
        ok = ok && !DnsResolver::ParseHostPort("127.0.0.1:80abc", &host, &port);
        ok = ok && !DnsResolver::ParseHostPort("host:8080xyz", &host, &port);

        // Negative sign — std::stoi would have returned -1, passing into
        // InetAddr's uint16_t port (silently becoming 65535).
        ok = ok && !DnsResolver::ParseHostPort("example.com:-1", &host, &port);
        ok = ok && !DnsResolver::ParseHostPort("[::1]:-80", &host, &port);
        ok = ok && !DnsResolver::ParseHostPort("host:-443", &host, &port);

        // Out of uint16_t range. std::stoi would have returned the
        // full value, later truncated into 16-bit port storage
        // (silently targeting the wrong port).
        ok = ok && !DnsResolver::ParseHostPort("example.com:65536", &host, &port);
        ok = ok && !DnsResolver::ParseHostPort("example.com:70000", &host, &port);
        ok = ok && !DnsResolver::ParseHostPort("[::1]:100000", &host, &port);
        ok = ok && !DnsResolver::ParseHostPort("host:999999", &host, &port);

        // Empty host (":80" had port=80 host="" previously).
        ok = ok && !DnsResolver::ParseHostPort(":80", &host, &port);
        ok = ok && !DnsResolver::ParseHostPort(":", &host, &port);

        // Leading zero beyond single "0" — strict parse rejects to
        // avoid ambiguity with any downstream octal-aware tooling.
        ok = ok && !DnsResolver::ParseHostPort("example.com:01", &host, &port);
        ok = ok && !DnsResolver::ParseHostPort("example.com:080", &host, &port);
        ok = ok && !DnsResolver::ParseHostPort("[::1]:00443", &host, &port);

        // Whitespace and sign chars.
        ok = ok && !DnsResolver::ParseHostPort("example.com:+80", &host, &port);
        ok = ok && !DnsResolver::ParseHostPort("example.com: 80", &host, &port);
        ok = ok && !DnsResolver::ParseHostPort("example.com:80 ", &host, &port);

        // Empty port (":"-terminated host).
        ok = ok && !DnsResolver::ParseHostPort("example.com:", &host, &port);
        ok = ok && !DnsResolver::ParseHostPort("[::1]:", &host, &port);

        // Must ACCEPT: valid forms at the uint16_t boundaries.
        host.clear(); port = -1;
        ok = ok && DnsResolver::ParseHostPort("example.com:0", &host, &port)
                 && host == "example.com" && port == 0;
        host.clear(); port = -1;
        ok = ok && DnsResolver::ParseHostPort("example.com:65535", &host, &port)
                 && host == "example.com" && port == 65535;
        host.clear(); port = -1;
        ok = ok && DnsResolver::ParseHostPort("[::1]:65535", &host, &port)
                 && host == "::1" && port == 65535;
        host.clear(); port = -1;
        ok = ok && DnsResolver::ParseHostPort("[::1]:0", &host, &port)
                 && host == "::1" && port == 0;
        host.clear(); port = -1;
        ok = ok && DnsResolver::ParseHostPort("127.0.0.1:80", &host, &port)
                 && host == "127.0.0.1" && port == 80;

        Record("DnsResolver: ParseHostPort rejects malformed port", ok);
    } catch (const std::exception& e) {
        Record("DnsResolver: ParseHostPort rejects malformed port",
                false, e.what());
    }
}

// ---------- Review-round: ResolveAsync rejects invalid hosts before queuing ----------

inline void TestResolveAsyncRejectsInvalidHostBeforeQueue() {
    std::cout << "\n[TEST] DnsResolver: ResolveAsync rejects invalid host before queue..."
              << std::endl;
    try {
        // The guard sits BEFORE EnsurePoolStarted, so a literal-only
        // server that only ever submits invalid hostnames should NEVER
        // spawn a worker. Instrument the seam to count invocations — if
        // the guard misbehaves and a request slips through to the pool,
        // the seam will fire. We expect zero fires because (a) invalid
        // hostnames fail at the guard with a ready error future, and
        // (b) valid IP literals short-circuit on the literal path.
        DnsResolver resolver(MakeFastConfig(2));
        std::atomic<int> seam_calls{0};
        resolver.SetResolverForTesting([&](const ResolveRequest& req) {
            seam_calls.fetch_add(1);
            ResolvedEndpoint r;
            r.host = req.host; r.port = req.port; r.tag = req.tag;
            r.addr = InetAddr("10.0.0.1", req.port);
            return r;
        });

        // Must REJECT: legacy numeric-dotted forms the validator
        // rejects but that libc would reinterpret via inet_aton.
        auto fut_1 = resolver.ResolveAsync(MakeReq("1.2.3", 80));
        auto fut_2 = resolver.ResolveAsync(MakeReq("0127.0.0.1", 80));
        auto fut_3 = resolver.ResolveAsync(MakeReq("1.2", 80));
        // Must REJECT: obviously-malformed hostnames.
        auto fut_4 = resolver.ResolveAsync(MakeReq("host..bad", 80));
        auto fut_5 = resolver.ResolveAsync(MakeReq(".leading", 80));
        auto fut_6 = resolver.ResolveAsync(MakeReq("end-", 80));
        auto fut_7 = resolver.ResolveAsync(MakeReq("-start", 80));
        auto fut_8 = resolver.ResolveAsync(MakeReq("", 80));
        // Must REJECT: bracketed forms (caller should have Normalize'd
        // before reaching here).
        auto fut_9 = resolver.ResolveAsync(MakeReq("[::1]", 80));

        auto check_rejected = [](std::future<ResolvedEndpoint>& f) {
            if (f.wait_for(std::chrono::milliseconds(50))
                    != std::future_status::ready) return false;
            auto r = f.get();
            return r.error && r.error_code == EAI_NONAME;
        };
        bool ok = true;
        ok = ok && check_rejected(fut_1);
        ok = ok && check_rejected(fut_2);
        ok = ok && check_rejected(fut_3);
        ok = ok && check_rejected(fut_4);
        ok = ok && check_rejected(fut_5);
        ok = ok && check_rejected(fut_6);
        ok = ok && check_rejected(fut_7);
        ok = ok && check_rejected(fut_8);
        ok = ok && check_rejected(fut_9);

        // Control: valid IPv4 literal short-circuits without seam call.
        auto fut_ok_literal = resolver.ResolveAsync(MakeReq("127.0.0.1", 80));
        ok = ok && fut_ok_literal.wait_for(std::chrono::milliseconds(50))
                    == std::future_status::ready;
        auto res_lit = fut_ok_literal.get();
        ok = ok && !res_lit.error;

        // Control: valid hostname goes through the pool (seam fires).
        auto fut_ok_host = resolver.ResolveAsync(MakeReq("example.com", 80));
        ok = ok && fut_ok_host.wait_for(std::chrono::milliseconds(500))
                    == std::future_status::ready;
        auto res_host = fut_ok_host.get();
        ok = ok && !res_host.error;

        // The seam should have fired ONCE for example.com. The 9
        // invalid-host requests all failed at the guard, never reaching
        // the pool — proving the runtime path is consistent with the
        // validator AND that kMaxQueuedItems slots are not consumed by
        // invalid requests under pathological inputs.
        ok = ok && seam_calls.load() == 1;

        Record("DnsResolver: ResolveAsync rejects invalid host before queue",
                ok,
                "seam_calls=" + std::to_string(seam_calls.load()) +
                " (expected 1 for example.com only)");
    } catch (const std::exception& e) {
        Record("DnsResolver: ResolveAsync rejects invalid host before queue",
                false, e.what());
    }
}

// ---------- Review-round: ParseHostPort validates host token ----------

inline void TestParseHostPortValidatesHostToken() {
    std::cout << "\n[TEST] DnsResolver: ParseHostPort validates host token..."
              << std::endl;
    try {
        std::string host;
        int port = -1;
        bool ok = true;

        // Must REJECT: host that fails hostname grammar, with a port.
        ok = ok && !DnsResolver::ParseHostPort("host..bad:80", &host, &port);
        ok = ok && !DnsResolver::ParseHostPort(".leading:443", &host, &port);
        ok = ok && !DnsResolver::ParseHostPort("-start:80", &host, &port);
        ok = ok && !DnsResolver::ParseHostPort("end-:80", &host, &port);

        // Must REJECT: legacy numeric-dotted forms, with a port.
        ok = ok && !DnsResolver::ParseHostPort("0127.0.0.1:80", &host, &port);
        ok = ok && !DnsResolver::ParseHostPort("1.2.3:443", &host, &port);
        ok = ok && !DnsResolver::ParseHostPort("1.2:80", &host, &port);
        ok = ok && !DnsResolver::ParseHostPort("12.345.67:80", &host, &port);

        // Must REJECT: same forms WITHOUT a port (bare fallback branch
        // previously skipped host validation too).
        ok = ok && !DnsResolver::ParseHostPort("host..bad", &host, &port);
        ok = ok && !DnsResolver::ParseHostPort("0127.0.0.1", &host, &port);
        ok = ok && !DnsResolver::ParseHostPort("1.2.3", &host, &port);
        ok = ok && !DnsResolver::ParseHostPort("-start", &host, &port);

        // Must ACCEPT: genuinely valid forms still round-trip cleanly.
        host.clear(); port = -1;
        ok = ok && DnsResolver::ParseHostPort("example.com", &host, &port)
                 && host == "example.com" && port == 0;
        host.clear(); port = -1;
        ok = ok && DnsResolver::ParseHostPort("example.com:443", &host, &port)
                 && host == "example.com" && port == 443;
        host.clear(); port = -1;
        ok = ok && DnsResolver::ParseHostPort("127.0.0.1", &host, &port)
                 && host == "127.0.0.1" && port == 0;
        host.clear(); port = -1;
        ok = ok && DnsResolver::ParseHostPort("127.0.0.1:80", &host, &port)
                 && host == "127.0.0.1" && port == 80;
        host.clear(); port = -1;
        ok = ok && DnsResolver::ParseHostPort("[::1]:443", &host, &port)
                 && host == "::1" && port == 443;
        host.clear(); port = -1;
        ok = ok && DnsResolver::ParseHostPort("::1", &host, &port)
                 && host == "::1" && port == 0;
        // Trailing-dot FQDN form is a legitimate hostname.
        host.clear(); port = -1;
        ok = ok && DnsResolver::ParseHostPort("example.com.:443", &host, &port)
                 && host == "example.com." && port == 443;

        Record("DnsResolver: ParseHostPort validates host token", ok);
    } catch (const std::exception& e) {
        Record("DnsResolver: ParseHostPort validates host token",
                false, e.what());
    }
}

// ---------- Review-round: future becomes ready at timeout without follow-up traffic ----------

inline void TestQueuedItemExpiresWithoutFollowUpSubmission() {
    std::cout << "\n[TEST] DnsResolver: queued item expires without follow-up submission..."
              << std::endl;
    try {
        // Reviewer scenario: cap=1, first request wedges the single
        // worker, second request has a 50ms timeout, NO third submission
        // arrives. Previously the second future stayed pending forever
        // because neither expiry path fired (submission-side sweep
        // needs a follow-up call; worker-side check needs the worker
        // to pop the item). The new reaper thread sleeps on
        // cv.wait_until(earliest_deadline), wakes at 50ms, evicts the
        // expired item, and set_values the promise. Caller's future
        // transitions to READY at ~50ms — the contract ResolveAsync
        // was always supposed to provide.
        struct Gate {
            std::mutex m;
            std::condition_variable cv;
            bool release = false;
        };
        auto gate = std::make_shared<Gate>();

        DnsResolver resolver(MakeFastConfig(1));   // cap = 1 worker
        resolver.SetResolverForTesting([gate](const ResolveRequest& req) {
            std::unique_lock<std::mutex> lk(gate->m);
            gate->cv.wait(lk, [&] { return gate->release; });
            ResolvedEndpoint r;
            r.host = req.host; r.port = req.port; r.tag = req.tag;
            r.addr = InetAddr("10.0.0.1", req.port);
            return r;
        });

        // A: picked up by the single worker, wedges on the gate.
        auto fut_a = resolver.ResolveAsync(
            MakeReq("wedge", 80, std::chrono::milliseconds(5000)));
        // Give the worker a moment to dequeue A and park on the gate.
        std::this_thread::sleep_for(std::chrono::milliseconds(30));

        // B: queued with a 50ms deadline. No worker available to pop.
        // No follow-up submission planned. The reaper MUST fire the
        // timeout.
        const auto t_submit = std::chrono::steady_clock::now();
        auto fut_b = resolver.ResolveAsync(
            MakeReq("target", 80, std::chrono::milliseconds(50)));

        // Wait up to 250ms for the future to become READY (not just for
        // our local wait_for to timeout, which is the pre-fix behaviour).
        // If the reaper is working, elapsed should be ~50ms.
        const bool ready =
            fut_b.wait_for(std::chrono::milliseconds(250))
                == std::future_status::ready;
        const auto elapsed_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - t_submit).count();

        ResolvedEndpoint res_b;
        if (ready) res_b = fut_b.get();

        // Cleanup: release the gate so the wedged worker finishes A.
        {
            std::lock_guard<std::mutex> lk(gate->m);
            gate->release = true;
        }
        gate->cv.notify_all();
        (void)fut_a.wait_for(std::chrono::milliseconds(500));

        bool ok = ready;
        ok = ok && res_b.error;
        ok = ok && res_b.error_code == EAI_AGAIN;
        ok = ok && res_b.error_message.find("queue-time exceeded")
                    != std::string::npos;
        // Sanity bounds. Elapsed should be at least ~40 ms (not
        // instantaneous — would indicate something expired pre-deadline)
        // and well under 200 ms (catches the pre-fix "never ready"
        // bug where wait_for itself times out and elapsed ≈ 250).
        ok = ok && elapsed_ms >= 40;
        ok = ok && elapsed_ms < 200;
        Record("DnsResolver: queued item expires without follow-up submission",
                ok,
                "ready=" + std::to_string(ready) +
                " elapsed_ms=" + std::to_string(elapsed_ms) +
                " err=" + std::to_string(res_b.error_code));
    } catch (const std::exception& e) {
        Record("DnsResolver: queued item expires without follow-up submission",
                false, e.what());
    }
}

// ---------- Review-round: reaper expires in-flight items ----------

inline void TestInFlightItemExpiresAtDeadline() {
    std::cout << "\n[TEST] DnsResolver: in-flight item expires at deadline..."
              << std::endl;
    try {
        // Reviewer scenario: the request has been POPPED from state->queue
        // by a worker and is now in-flight (blocked in DoBlockingResolve /
        // test seam). Previously the reaper only scanned state->queue so
        // the in-flight item's future stayed pending until the blocking
        // call returned. Post-fix: shared_ptr<WorkItem> + state->in_flight
        // list + `done` flag let the reaper race the worker on set_value,
        // so the future transitions to READY at the caller's deadline
        // even while the worker's DoBlockingResolve is still blocked.
        //
        // Setup: cap=1, single worker. Submit ONE request with a 50ms
        // timeout. Worker picks it up and wedges in the seam. No other
        // item ever arrives. The reaper MUST fire the timeout at ~50ms.
        struct Gate {
            std::mutex m;
            std::condition_variable cv;
            bool release = false;
        };
        auto gate = std::make_shared<Gate>();

        DnsResolver resolver(MakeFastConfig(1));   // cap=1 worker
        resolver.SetResolverForTesting([gate](const ResolveRequest& req) {
            // Wedge in the seam — this models getaddrinfo being stuck.
            // The item has been popped from state->queue by the worker;
            // it is now held on the worker's stack (in in_flight list).
            std::unique_lock<std::mutex> lk(gate->m);
            gate->cv.wait(lk, [&] { return gate->release; });
            ResolvedEndpoint r;
            r.host = req.host; r.port = req.port; r.tag = req.tag;
            r.addr = InetAddr("10.0.0.1", req.port);
            return r;
        });

        const auto t_submit = std::chrono::steady_clock::now();
        auto fut = resolver.ResolveAsync(
            MakeReq("wedged-target", 80, std::chrono::milliseconds(50)));

        // Future must become READY at ~50ms via the reaper expiring the
        // in-flight item. Without the fix, wait_for(250ms) would time
        // out because the seam is still wedged and no one can reach
        // the item.
        const bool ready = fut.wait_for(std::chrono::milliseconds(250))
                            == std::future_status::ready;
        const auto elapsed_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - t_submit).count();

        ResolvedEndpoint res;
        if (ready) res = fut.get();

        // Cleanup: release gate so the wedged worker eventually exits.
        // Its Phase-3 completion will see `done=true` (reaper already
        // flipped it) and skip set_value + skip in_flight.erase (reaper
        // did both). No double-set, no UB.
        {
            std::lock_guard<std::mutex> lk(gate->m);
            gate->release = true;
        }
        gate->cv.notify_all();

        bool ok = ready;
        ok = ok && res.error;
        ok = ok && res.error_code == EAI_AGAIN;
        ok = ok && res.error_message.find("queue-time exceeded")
                    != std::string::npos;
        // Elapsed bounds. Lower bound catches "instantly ready" regressions
        // (would mean the deadline didn't actually fire via reaper);
        // upper bound catches the pre-fix "never ready" hang.
        ok = ok && elapsed_ms >= 40;
        ok = ok && elapsed_ms < 200;
        Record("DnsResolver: in-flight item expires at deadline", ok,
                "ready=" + std::to_string(ready) +
                " elapsed_ms=" + std::to_string(elapsed_ms) +
                " err=" + std::to_string(res.error_code));
    } catch (const std::exception& e) {
        Record("DnsResolver: in-flight item expires at deadline",
                false, e.what());
    }
}

// ---------- Queue-time deadline short-circuit ----------

inline void TestQueueTimeDeadlineShortCircuits() {
    std::cout << "\n[TEST] DnsResolver: Queue-time deadline short-circuits..." << std::endl;
    try {
        DnsResolver resolver(MakeFastConfig(1));
        resolver.SetResolverForTesting([](const ResolveRequest& req) {
            std::this_thread::sleep_for(std::chrono::milliseconds(80));
            ResolvedEndpoint r;
            r.host = req.host; r.port = req.port; r.tag = req.tag;
            r.addr = InetAddr("10.0.0.1", req.port);
            return r;
        });
        auto blocker = resolver.ResolveAsync(MakeReq("wedge", 80,
            std::chrono::milliseconds(200)));
        auto shorty = resolver.ResolveAsync(MakeReq("shorty", 80,
            std::chrono::milliseconds(1)));
        bool ok = shorty.wait_for(std::chrono::milliseconds(200))
                    == std::future_status::ready;
        auto r = shorty.get();
        ok = ok && r.error;
        ok = ok && r.error_code == EAI_AGAIN;
        (void)blocker.wait_for(std::chrono::milliseconds(300));
        Record("DnsResolver: Queue-time deadline short-circuits", ok);
    } catch (const std::exception& e) {
        Record("DnsResolver: Queue-time deadline short-circuits",
                false, e.what());
    }
}

// ---------- Test registrar ----------

inline void RunAllTests() {
    std::cout << "\n=== DnsResolver Tests ===" << std::endl;
    TestIsValidHostOrIpLiteral();
    TestFormatAuthority();
    TestStripTrailingDot();
    TestNormalizeHostToBare();
    TestParseLookupFamily();
    TestLiteralOnlyConfigSpawnsNoWorkers();
    TestLiteralIPv6ShortCircuit();
    TestFirstHostnameTriggersPool();
    TestResolveManyDeadlineBounded();
    TestTwoResolversAreIndependent();
    TestShutdownDetachesWorkers();
    TestResolveRequestZeroTimeoutUsesConfig();
    TestResolveManyOneArgUsesConfigOverallTimeout();
    TestResolveManyPerEntryDeadlineFromDispatch();
    TestResolveRequestUnsetFamilyUsesConfig();
    TestResolveRequestExplicitFamilyOverridesConfig();
    TestParseHostPortRejectsNonIpBrackets();
    TestDnsResolverCtorRejectsNonPositiveInflight();
    TestQueuedItemExpiresDuringWorkerStall();
    TestNonSaturatedMixedTimeoutQueueExpires();
    TestMixedTimeoutSaturationTriggersFullSweep();
    TestIsValidHostOrIpLiteralRejectsLegacyNumericForms();
    TestParseHostPortRejectsMalformedPort();
    TestResolveAsyncRejectsInvalidHostBeforeQueue();
    TestParseHostPortValidatesHostToken();
    TestQueuedItemExpiresWithoutFollowUpSubmission();
    TestInFlightItemExpiresAtDeadline();
    TestQueueTimeDeadlineShortCircuits();
}

}  // namespace DnsResolverTests
