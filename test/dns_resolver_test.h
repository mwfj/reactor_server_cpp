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
#include <chrono>
#include <condition_variable>
#include <future>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace DnsResolverTests {

using net_dns::DnsConfig;
using net_dns::DnsResolver;
using net_dns::LookupFamily;
using net_dns::ResolvedEndpoint;
using net_dns::ResolveRequest;

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
        Record("DnsResolver: NormalizeHostToBare", ok);
    } catch (const std::exception& e) {
        Record("DnsResolver: NormalizeHostToBare", false, e.what());
    }
}

inline void TestParseLookupFamily() {
    std::cout << "\n[TEST] DnsResolver: ParseLookupFamily..." << std::endl;
    try {
        bool ok = true;
        ok = ok && net_dns::ParseLookupFamily("v4_only")      == LookupFamily::kV4Only;
        ok = ok && net_dns::ParseLookupFamily("v6_only")      == LookupFamily::kV6Only;
        ok = ok && net_dns::ParseLookupFamily("v4_preferred") == LookupFamily::kV4Preferred;
        ok = ok && net_dns::ParseLookupFamily("v6_preferred") == LookupFamily::kV6Preferred;
        bool threw = false;
        try { (void)net_dns::ParseLookupFamily("bogus"); }
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
    TestQueueTimeDeadlineShortCircuits();
}

}  // namespace DnsResolverTests
