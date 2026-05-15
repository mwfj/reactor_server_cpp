#pragma once

// Middleware-layer observability emission tests — DNS resolver + rate
// limiter + circuit breaker.
//
// Coverage:
//   * reactor.dns.resolves{outcome}
//       outcome ∈ {success, cache_hit, nxdomain, timeout, servfail, other_error}
//       — DnsResolver::ResolveAsync literal + non-literal paths,
//         submission-side sweep, worker / reaper / saturation.
//   * reactor.rate_limit.decisions{zone, decision}
//       decision ∈ {admit, reject, dry_run_reject}
//       — RateLimitManager::Check per-zone decision emit.
//   * reactor.rate_limit.tokens{zone}
//       — Histogram of bucket level after every decision (admit + reject).
//   * reactor.circuit_breaker.state{service, state}
//       state ∈ {closed, open, half_open}
//       — Per-slice baseline emit at CircuitBreakerHost construction;
//         +1/-1 pairs at every transition.
//   * reactor.circuit_breaker.transitions{service, from, to, trigger}
//       — Counter bumped once per transition. Composed into the
//         HttpServer-installed callback that already drives the
//         wait-queue drain.
//   * reactor.circuit_breaker.rejected{service, reason}
//       reason ∈ {open, open_dry_run, half_open_full,
//                 half_open_recovery_failing}
//       — Slice-level test sketches the emit via the slice's RejectReason
//         vocabulary directly; production emit lives in
//         ProxyTransaction::ConsultBreaker.

#include "test_framework.h"
#include "auth/auth_config.h"
#include "auth/auth_manager.h"
#include "auth/auth_metrics.h"
#include "auth/auth_result.h"
#include "net/dns_resolver.h"
#include "rate_limit/rate_limiter.h"
#include "config/server_config.h"
#include "circuit_breaker/circuit_breaker_manager.h"
#include "circuit_breaker/circuit_breaker_host.h"
#include "circuit_breaker/circuit_breaker_slice.h"
#include "circuit_breaker/circuit_breaker_state.h"
#include "http/http_request.h"
#include "http/http_response.h"
#include "observability/counter.h"
#include "observability/histogram.h"
#include "observability/meter_provider.h"
#include "observability/metrics_catalog.h"
#include "observability/metrics_snapshot.h"
#include "observability/observability_config.h"
#include "observability/observability_manager.h"
#include "observability/resource.h"
#include "observability/sampler.h"
#include "observability/span_processor.h"

#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace ObservabilityMiddlewareMetricsTests {

using NET_DNS_NAMESPACE::DnsResolver;
using NET_DNS_NAMESPACE::DnsConfig;
using NET_DNS_NAMESPACE::ResolveRequest;
using NET_DNS_NAMESPACE::ResolvedEndpoint;
using NET_DNS_NAMESPACE::LookupFamily;
using OBSERVABILITY_NAMESPACE::CounterPoint;
using OBSERVABILITY_NAMESPACE::HistogramPoint;
using OBSERVABILITY_NAMESPACE::InMemorySpanProcessor;
using OBSERVABILITY_NAMESPACE::InstrumentSnapshot;
using OBSERVABILITY_NAMESPACE::MetricsSnapshot;
using OBSERVABILITY_NAMESPACE::ObservabilityConfig;
using OBSERVABILITY_NAMESPACE::ObservabilityManager;
using OBSERVABILITY_NAMESPACE::RandomSource;
using OBSERVABILITY_NAMESPACE::Resource;
using OBSERVABILITY_NAMESPACE::SamplerType;

namespace {

// ---------------------------------------------------------------------
// Fixture — minimal ObservabilityManager backed by InMemorySpanProcessor.
// Mirrors the pattern used by observability_catalog_test.h /
// observability_pool_gauges_test.h.
// ---------------------------------------------------------------------
struct MiddlewareFixture {
    std::shared_ptr<InMemorySpanProcessor> processor =
        std::make_shared<InMemorySpanProcessor>();
    std::shared_ptr<ObservabilityManager> manager;

    explicit MiddlewareFixture() {
        ObservabilityConfig cfg;
        cfg.enabled               = true;
        cfg.traces.enabled        = true;
        cfg.metrics.enabled       = true;
        cfg.traces.sampler.type   = SamplerType::AlwaysOn;
        cfg.resource.service_name = "obs-middleware-test";
        manager = ObservabilityManager::Create(
            std::move(cfg),
            std::make_shared<Resource>(),
            processor,
            std::make_shared<RandomSource>(0xD15D15FEULL));
    }
};

// ---------------------------------------------------------------------
// Counter / Histogram snapshot helpers.
// ---------------------------------------------------------------------

// Sum every Counter point on `name` whose labels contain `(k=v)`. UpDown
// and Counter share the CounterPoint shape so the same helper covers both.
double SumCounterByLabel(const MetricsSnapshot& snap,
                          const std::string& name,
                          const std::string& k,
                          const std::string& v) {
    double total = 0;
    for (const auto& inst : snap.instruments) {
        if (inst.name != name) continue;
        for (const auto& p : inst.counter_points) {
            for (const auto& [pk, pv] : p.labels.kv) {
                if (pk == k && pv == v) { total += p.value; break; }
            }
        }
    }
    return total;
}

// Sum every Counter point whose labels contain BOTH (k1=v1) AND (k2=v2).
double SumCounterByTwoLabels(const MetricsSnapshot& snap,
                              const std::string& name,
                              const std::string& k1, const std::string& v1,
                              const std::string& k2, const std::string& v2) {
    double total = 0;
    for (const auto& inst : snap.instruments) {
        if (inst.name != name) continue;
        for (const auto& p : inst.counter_points) {
            bool m1 = false, m2 = false;
            for (const auto& [pk, pv] : p.labels.kv) {
                if (pk == k1 && pv == v1) m1 = true;
                if (pk == k2 && pv == v2) m2 = true;
            }
            if (m1 && m2) total += p.value;
        }
    }
    return total;
}

// Sum every histogram point's `count` on `name` whose labels contain
// `(k=v)`. Used to assert tokens histograms recorded a sample per zone.
uint64_t HistogramCountByLabel(const MetricsSnapshot& snap,
                                const std::string& name,
                                const std::string& k,
                                const std::string& v) {
    uint64_t total = 0;
    for (const auto& inst : snap.instruments) {
        if (inst.name != name) continue;
        for (const auto& p : inst.histogram_points) {
            for (const auto& [pk, pv] : p.labels.kv) {
                if (pk == k && pv == v) { total += p.count; break; }
            }
        }
    }
    return total;
}

// Synchronously resolve a host through DnsResolver, blocking on the
// returned future up to `timeout_ms`. Wraps the future-wait so individual
// tests don't repeat the boilerplate.
ResolvedEndpoint ResolveSync(DnsResolver& resolver,
                             const std::string& host,
                             int port = 80,
                             int timeout_ms = 3000) {
    ResolveRequest req;
    req.host = host;
    req.port = port;
    req.timeout = std::chrono::milliseconds(timeout_ms);
    auto fut = resolver.ResolveAsync(req);
    if (fut.wait_for(std::chrono::milliseconds(timeout_ms + 500))
            == std::future_status::ready) {
        return fut.get();
    }
    ResolvedEndpoint out;
    out.host = host;
    out.port = port;
    out.error = true;
    out.error_message = "test wait timeout";
    return out;
}

HttpRequest MakeRequest(const std::string& method,
                        const std::string& path,
                        const std::string& client_ip = "10.0.0.42") {
    HttpRequest req;
    req.method    = method;
    req.path      = path;
    req.client_ip = client_ip;
    req.complete  = true;
    return req;
}

}  // namespace

// ---------------------------------------------------------------------
// DNS — `success` outcome
//
// A literal IP that succeeds the inet_pton parse short-circuits in
// ResolveAsync without spawning the worker pool. By contract that path
// emits `cache_hit`. To exercise the `success` outcome we route through
// the test seam so the worker code path runs without dependence on the
// host's DNS resolver.
// ---------------------------------------------------------------------
inline void TestDnsSuccessOutcome() {
    const char* TAG = "ObsMW DNS: success outcome from worker path";
    try {
        MiddlewareFixture fix;
        DnsConfig cfg;
        cfg.lookup_family = LookupFamily::kV4Only;
        cfg.resolve_timeout_ms = 1000;
        DnsResolver resolver(cfg);
        resolver.SetObservabilityManager(fix.manager.get());

        // Test seam returns a synthetic success — the resolver wires
        // every gai_result == 0 to "success" via OutcomeForGaiError.
        resolver.SetResolverForTesting(
            [](const ResolveRequest& req) -> ResolvedEndpoint {
                ResolvedEndpoint out;
                out.host = req.host;
                out.port = req.port;
                out.tag  = req.tag;
                out.resolved_at = std::chrono::steady_clock::now();
                out.addr = InetAddr("127.0.0.1", req.port);
                return out;  // error = false → success
            });

        auto res = ResolveSync(resolver, "example.invalid", 80);
        bool resolve_ok = !res.error;

        auto snap = fix.manager->meter_provider()->Snapshot();
        double success_count = SumCounterByLabel(
            snap, "reactor.dns.resolves", "outcome", "success");

        bool pass = resolve_ok && success_count >= 1.0;
        std::string err;
        if (!resolve_ok) err = "test seam should yield success";
        else if (success_count < 1.0)
            err = "expected >=1 success increment, got "
                  + std::to_string(success_count);
        TestFramework::RecordTest(TAG, pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// DNS — `cache_hit` outcome (literal short-circuit)
// ---------------------------------------------------------------------
inline void TestDnsCacheHitOutcome() {
    const char* TAG = "ObsMW DNS: cache_hit outcome on literal short-circuit";
    try {
        MiddlewareFixture fix;
        DnsConfig cfg;
        cfg.lookup_family = LookupFamily::kV4Only;
        DnsResolver resolver(cfg);
        resolver.SetObservabilityManager(fix.manager.get());

        // Two literal resolves — both take the literal short-circuit
        // path and emit `cache_hit`.
        auto r1 = ResolveSync(resolver, "127.0.0.1", 8080);
        auto r2 = ResolveSync(resolver, "127.0.0.1", 8080);
        bool resolves_ok = !r1.error && !r2.error;

        auto snap = fix.manager->meter_provider()->Snapshot();
        double cache_hits = SumCounterByLabel(
            snap, "reactor.dns.resolves", "outcome", "cache_hit");

        bool pass = resolves_ok && cache_hits >= 2.0;
        std::string err;
        if (!resolves_ok) err = "literal resolves must succeed";
        else if (cache_hits < 2.0)
            err = "expected >=2 cache_hit increments, got "
                  + std::to_string(cache_hits);
        TestFramework::RecordTest(TAG, pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// DNS — `nxdomain` outcome
//
// Drive via the test seam returning EAI_NONAME so the test is hermetic
// — no dependency on the host's negative-cache behavior.
// ---------------------------------------------------------------------
inline void TestDnsNxDomainOutcome() {
    const char* TAG = "ObsMW DNS: nxdomain outcome";
    try {
        MiddlewareFixture fix;
        DnsConfig cfg;
        cfg.lookup_family = LookupFamily::kV4Only;
        DnsResolver resolver(cfg);
        resolver.SetObservabilityManager(fix.manager.get());

        resolver.SetResolverForTesting(
            [](const ResolveRequest& req) -> ResolvedEndpoint {
                ResolvedEndpoint out;
                out.host = req.host;
                out.port = req.port;
                out.error = true;
                out.error_code = EAI_NONAME;
                out.error_message = "synthetic nxdomain";
                return out;
            });

        auto res = ResolveSync(resolver, "missing.host.invalid", 80);
        bool got_error = res.error && res.error_code == EAI_NONAME;

        auto snap = fix.manager->meter_provider()->Snapshot();
        double nx_count = SumCounterByLabel(
            snap, "reactor.dns.resolves", "outcome", "nxdomain");

        bool pass = got_error && nx_count >= 1.0;
        std::string err;
        if (!got_error) err = "seam should yield EAI_NONAME";
        else if (nx_count < 1.0)
            err = "expected >=1 nxdomain increment, got "
                  + std::to_string(nx_count);
        TestFramework::RecordTest(TAG, pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// DNS — `servfail` + `other_error` outcomes via seam-returned gai codes.
// ---------------------------------------------------------------------
inline void TestDnsServfailAndOtherErrorOutcome() {
    const char* TAG = "ObsMW DNS: servfail + other_error outcomes";
    try {
        MiddlewareFixture fix;
        DnsConfig cfg;
        cfg.lookup_family = LookupFamily::kV4Only;
        DnsResolver resolver(cfg);
        resolver.SetObservabilityManager(fix.manager.get());

        // First seam: EAI_FAIL → servfail.
        resolver.SetResolverForTesting(
            [](const ResolveRequest& req) -> ResolvedEndpoint {
                ResolvedEndpoint out;
                out.host = req.host;
                out.error = true;
                out.error_code = EAI_FAIL;
                out.error_message = "synthetic servfail";
                return out;
            });
        (void)ResolveSync(resolver, "fail.example.invalid", 80);

        // Second seam: a non-mapped gai_result → other_error. We use
        // EAI_BADFLAGS which is neither NONAME/AGAIN/FAIL so the
        // classifier routes it to other_error.
        resolver.SetResolverForTesting(
            [](const ResolveRequest& req) -> ResolvedEndpoint {
                ResolvedEndpoint out;
                out.host = req.host;
                out.error = true;
                out.error_code = EAI_BADFLAGS;
                out.error_message = "synthetic badflags";
                return out;
            });
        (void)ResolveSync(resolver, "badflags.example.invalid", 80);

        auto snap = fix.manager->meter_provider()->Snapshot();
        double servfail = SumCounterByLabel(
            snap, "reactor.dns.resolves", "outcome", "servfail");
        double other = SumCounterByLabel(
            snap, "reactor.dns.resolves", "outcome", "other_error");

        bool pass = servfail >= 1.0 && other >= 1.0;
        std::string err;
        if (servfail < 1.0)
            err = "expected servfail>=1, got " + std::to_string(servfail);
        else if (other < 1.0)
            err = "expected other_error>=1, got " + std::to_string(other);
        TestFramework::RecordTest(TAG, pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// DNS — null-manager safety. Calling ResolveAsync without ever wiring an
// ObservabilityManager must NOT crash and must NOT emit any series.
// Ratchet for the SHUTDOWN CAVEAT path documented on the setter.
// ---------------------------------------------------------------------
inline void TestDnsNullManagerSafe() {
    const char* TAG = "ObsMW DNS: null obs_manager_ is safe (no crash, no series)";
    try {
        MiddlewareFixture fix;  // create a manager, but do NOT wire it
        DnsConfig cfg;
        cfg.lookup_family = LookupFamily::kV4Only;
        DnsResolver resolver(cfg);
        // Deliberately skip SetObservabilityManager — emit branches must
        // short-circuit and the resolve must still complete normally.

        auto res = ResolveSync(resolver, "127.0.0.1", 9090);
        bool resolve_ok = !res.error;

        auto snap = fix.manager->meter_provider()->Snapshot();
        // Manager is alive but never wired → no series should exist on
        // its catalog for reactor.dns.resolves (the resolver could not
        // reach this manager).
        double total = 0;
        for (const auto& inst : snap.instruments) {
            if (inst.name == "reactor.dns.resolves") {
                for (const auto& p : inst.counter_points) total += p.value;
            }
        }
        bool pass = resolve_ok && total == 0.0;
        std::string err;
        if (!resolve_ok) err = "resolve should succeed without obs wired";
        else if (total != 0.0)
            err = "unexpected series count " + std::to_string(total);
        TestFramework::RecordTest(TAG, pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Rate-limit — admit decision
// ---------------------------------------------------------------------
inline void TestRateLimitAdmitMetric() {
    const char* TAG = "ObsMW RL: admit decision emits {zone=z1, decision=admit}";
    try {
        MiddlewareFixture fix;

        RateLimitConfig cfg;
        cfg.enabled = true;
        cfg.dry_run = false;
        cfg.include_headers = true;
        RateLimitZoneConfig z;
        z.name     = "z1";
        z.rate     = 100.0;
        z.capacity = 100;
        z.key_type = "client_ip";
        cfg.zones.push_back(z);

        RateLimitManager rl(cfg);
        rl.SetObservabilityManager(fix.manager.get());

        HttpRequest req = MakeRequest("GET", "/a");
        HttpResponse resp;
        bool admitted = rl.Check(req, resp);

        auto snap = fix.manager->meter_provider()->Snapshot();
        double admit_count = SumCounterByTwoLabels(
            snap, "reactor.rate_limit.decisions",
            "zone", "z1", "decision", "admit");

        bool pass = admitted && admit_count >= 1.0;
        std::string err;
        if (!admitted) err = "first request should admit";
        else if (admit_count < 1.0)
            err = "expected admit>=1, got " + std::to_string(admit_count);
        TestFramework::RecordTest(TAG, pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Rate-limit — reject decision (exceed capacity)
// ---------------------------------------------------------------------
inline void TestRateLimitRejectMetric() {
    const char* TAG = "ObsMW RL: reject decision emits {zone=z1, decision=reject}";
    try {
        MiddlewareFixture fix;

        RateLimitConfig cfg;
        cfg.enabled = true;
        cfg.dry_run = false;
        cfg.include_headers = true;
        RateLimitZoneConfig z;
        z.name     = "z1";
        z.rate     = 1.0;      // very slow refill
        z.capacity = 2;        // burst of 2 → 3rd req must reject
        z.key_type = "client_ip";
        cfg.zones.push_back(z);

        RateLimitManager rl(cfg);
        rl.SetObservabilityManager(fix.manager.get());

        bool reject_observed = false;
        for (int i = 0; i < 5; ++i) {
            HttpRequest req = MakeRequest("GET", "/a", "10.0.0.99");
            HttpResponse resp;
            bool admitted = rl.Check(req, resp);
            if (!admitted) reject_observed = true;
        }

        auto snap = fix.manager->meter_provider()->Snapshot();
        double reject_count = SumCounterByTwoLabels(
            snap, "reactor.rate_limit.decisions",
            "zone", "z1", "decision", "reject");
        double admit_count = SumCounterByTwoLabels(
            snap, "reactor.rate_limit.decisions",
            "zone", "z1", "decision", "admit");

        bool pass = reject_observed && reject_count >= 1.0 && admit_count >= 1.0;
        std::string err;
        if (!reject_observed) err = "at least one Check() should reject";
        else if (reject_count < 1.0)
            err = "expected reject>=1, got " + std::to_string(reject_count);
        else if (admit_count < 1.0)
            err = "expected admit>=1 (first requests in burst), got "
                  + std::to_string(admit_count);
        TestFramework::RecordTest(TAG, pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Rate-limit — dry-run reject is labelled `dry_run_reject`, not `reject`.
// ---------------------------------------------------------------------
inline void TestRateLimitDryRunRejectMetric() {
    const char* TAG = "ObsMW RL: dry_run flip labels decision dry_run_reject";
    try {
        MiddlewareFixture fix;

        RateLimitConfig cfg;
        cfg.enabled = true;
        cfg.dry_run = true;    // shadow mode
        cfg.include_headers = true;
        RateLimitZoneConfig z;
        z.name     = "shadow";
        z.rate     = 1.0;
        z.capacity = 1;        // 2nd req trips
        z.key_type = "client_ip";
        cfg.zones.push_back(z);

        RateLimitManager rl(cfg);
        rl.SetObservabilityManager(fix.manager.get());

        for (int i = 0; i < 4; ++i) {
            HttpRequest req = MakeRequest("GET", "/p", "10.0.0.7");
            HttpResponse resp;
            // Check() returns false in dry-run as well — middleware does
            // the let-through. We are testing the metric label here.
            rl.Check(req, resp);
        }

        auto snap = fix.manager->meter_provider()->Snapshot();
        double dry_count = SumCounterByTwoLabels(
            snap, "reactor.rate_limit.decisions",
            "zone", "shadow", "decision", "dry_run_reject");
        double real_reject_count = SumCounterByTwoLabels(
            snap, "reactor.rate_limit.decisions",
            "zone", "shadow", "decision", "reject");

        bool pass = dry_count >= 1.0 && real_reject_count == 0.0;
        std::string err;
        if (dry_count < 1.0)
            err = "expected dry_run_reject>=1, got " + std::to_string(dry_count);
        else if (real_reject_count != 0.0)
            err = "dry-run must NOT emit 'reject' label; got "
                  + std::to_string(real_reject_count);
        TestFramework::RecordTest(TAG, pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Rate-limit — tokens histogram records a sample on every decision.
// ---------------------------------------------------------------------
inline void TestRateLimitTokensHistogram() {
    const char* TAG = "ObsMW RL: tokens histogram records samples per zone";
    try {
        MiddlewareFixture fix;

        RateLimitConfig cfg;
        cfg.enabled = true;
        cfg.dry_run = false;
        cfg.include_headers = true;
        RateLimitZoneConfig z;
        z.name     = "hist_zone";
        z.rate     = 100.0;
        z.capacity = 100;
        z.key_type = "client_ip";
        cfg.zones.push_back(z);

        RateLimitManager rl(cfg);
        rl.SetObservabilityManager(fix.manager.get());

        for (int i = 0; i < 5; ++i) {
            HttpRequest req = MakeRequest("GET", "/h", "10.0.0.42");
            HttpResponse resp;
            rl.Check(req, resp);
        }

        auto snap = fix.manager->meter_provider()->Snapshot();
        uint64_t samples = HistogramCountByLabel(
            snap, "reactor.rate_limit.tokens", "zone", "hist_zone");

        bool pass = samples >= 5;
        std::string err;
        if (samples < 5)
            err = "expected >=5 histogram samples, got "
                  + std::to_string(samples);
        TestFramework::RecordTest(TAG, pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Rate-limit — disabled fast path must NOT emit decisions or histogram.
// `enabled=false` short-circuits Check() in the prepended middleware
// (HttpServer::MarkServerReady), so Check() is never invoked. We verify
// here that even when Check() runs explicitly with no zones, no series
// surface — guards against the empty-config emit regression.
// ---------------------------------------------------------------------
inline void TestRateLimitNoZonesNoEmit() {
    const char* TAG = "ObsMW RL: empty zone list yields zero decisions";
    try {
        MiddlewareFixture fix;

        RateLimitConfig cfg;
        cfg.enabled = true;       // master switch on
        cfg.dry_run = false;
        cfg.include_headers = true;
        // zones intentionally empty

        RateLimitManager rl(cfg);
        rl.SetObservabilityManager(fix.manager.get());

        HttpRequest req = MakeRequest("GET", "/x");
        HttpResponse resp;
        bool admitted = rl.Check(req, resp);

        auto snap = fix.manager->meter_provider()->Snapshot();
        double total_decisions = 0;
        for (const auto& inst : snap.instruments) {
            if (inst.name == "reactor.rate_limit.decisions") {
                for (const auto& p : inst.counter_points)
                    total_decisions += p.value;
            }
        }
        uint64_t total_samples = 0;
        for (const auto& inst : snap.instruments) {
            if (inst.name == "reactor.rate_limit.tokens") {
                for (const auto& p : inst.histogram_points)
                    total_samples += p.count;
            }
        }

        bool pass = admitted && total_decisions == 0.0 && total_samples == 0;
        std::string err;
        if (!admitted) err = "empty-zone Check must admit";
        else if (total_decisions != 0.0)
            err = "no zone → no decision; got " + std::to_string(total_decisions);
        else if (total_samples != 0)
            err = "no zone → no tokens; got " + std::to_string(total_samples);
        TestFramework::RecordTest(TAG, pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Rate-limit — null-manager safety. Mirror of the DNS guard.
// ---------------------------------------------------------------------
inline void TestRateLimitNullManagerSafe() {
    const char* TAG = "ObsMW RL: null obs_manager_ is safe (no crash, no series)";
    try {
        MiddlewareFixture fix;

        RateLimitConfig cfg;
        cfg.enabled = true;
        cfg.dry_run = false;
        cfg.include_headers = true;
        RateLimitZoneConfig z;
        z.name = "z1"; z.rate = 100.0; z.capacity = 100; z.key_type = "client_ip";
        cfg.zones.push_back(z);

        RateLimitManager rl(cfg);
        // No SetObservabilityManager call — defaults to nullptr.

        HttpRequest req = MakeRequest("GET", "/n");
        HttpResponse resp;
        bool admitted = rl.Check(req, resp);

        auto snap = fix.manager->meter_provider()->Snapshot();
        double total = 0;
        for (const auto& inst : snap.instruments) {
            if (inst.name == "reactor.rate_limit.decisions") {
                for (const auto& p : inst.counter_points) total += p.value;
            }
        }
        bool pass = admitted && total == 0.0;
        std::string err;
        if (!admitted) err = "Check must admit without obs wired";
        else if (total != 0.0)
            err = "series count must be 0; got " + std::to_string(total);
        TestFramework::RecordTest(TAG, pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Circuit Breaker — baseline gauge emit
//
// Constructing a CircuitBreakerManager with N partitions per host wires
// each slice to emit +1 on reactor.circuit_breaker.state{state=closed}
// at construction. With N=4 dispatchers and 1 host we expect 4 samples
// summed across the {service=X, state=closed} series.
// ---------------------------------------------------------------------
inline void TestCircuitBreakerBaselineGauge() {
    const char* TAG = "ObsMW CB: baseline state{closed} gauge +N per host";
    try {
        MiddlewareFixture fix;

        UpstreamConfig u;
        u.name = "svcA";
        u.host = "127.0.0.1";
        u.port = 8080;
        u.circuit_breaker.enabled = true;

        const size_t partition_count = 4;
        CIRCUIT_BREAKER_NAMESPACE::CircuitBreakerManager cbm(
            {u}, partition_count,
            /*dispatchers=*/{},
            fix.manager.get());

        auto snap = fix.manager->meter_provider()->Snapshot();
        double closed = SumCounterByTwoLabels(
            snap, "reactor.circuit_breaker.state",
            "service", "svcA", "state", "closed");

        bool pass = closed == static_cast<double>(partition_count);
        std::string err;
        if (!pass) {
            err = "expected baseline closed=" +
                  std::to_string(partition_count) + ", got " +
                  std::to_string(closed);
        }
        TestFramework::RecordTest(TAG, pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Circuit Breaker — transition gauge + counter
//
// Forcing a CLOSED→OPEN trip via 5 consecutive failures must emit a
// matching pair on the gauge ({closed:-1, open:+1}) and bump the
// transitions counter by exactly 1.
// ---------------------------------------------------------------------
inline void TestCircuitBreakerTransition() {
    const char* TAG = "ObsMW CB: CLOSED->OPEN emits gauge pair + transitions++";
    try {
        MiddlewareFixture fix;

        UpstreamConfig u;
        u.name = "svcT";
        u.host = "127.0.0.1";
        u.port = 8080;
        u.circuit_breaker.enabled = true;
        u.circuit_breaker.consecutive_failure_threshold = 5;
        u.circuit_breaker.minimum_volume = 1000;  // disable rate trip
        u.circuit_breaker.base_open_duration_ms = 5000;

        const size_t partition_count = 1;
        CIRCUIT_BREAKER_NAMESPACE::CircuitBreakerManager cbm(
            {u}, partition_count,
            /*dispatchers=*/{},
            fix.manager.get());

        auto* host = cbm.GetHost("svcT");
        auto* slice = host->GetSlice(0);

        // Install the same composed callback shape used by HttpServer.
        auto* obs_mgr = fix.manager.get();
        slice->SetTransitionCallback(
            [obs_mgr](CIRCUIT_BREAKER_NAMESPACE::State old_s,
                      CIRCUIT_BREAKER_NAMESPACE::State new_s,
                      const char* trigger) {
                const auto& cat = obs_mgr->catalog();
                const char* old_label =
                    CIRCUIT_BREAKER_NAMESPACE::StateName(old_s);
                const char* new_label =
                    CIRCUIT_BREAKER_NAMESPACE::StateName(new_s);
                if (cat.reactor_circuit_breaker_state != nullptr
                        && old_s != new_s) {
                    cat.reactor_circuit_breaker_state->Add(
                        -1.0,
                        {{"service", "svcT"}, {"state", old_label}});
                    cat.reactor_circuit_breaker_state->Add(
                        +1.0,
                        {{"service", "svcT"}, {"state", new_label}});
                }
                if (cat.reactor_circuit_breaker_transitions != nullptr) {
                    cat.reactor_circuit_breaker_transitions->Add(
                        1.0,
                        {{"service", "svcT"},
                         {"from", old_label},
                         {"to", new_label},
                         {"trigger",
                          trigger != nullptr ? trigger : "unknown"}});
                }
            });

        // Drive 5 consecutive failures → CLOSED->OPEN trip on
        // trigger=consecutive.
        for (int i = 0; i < 5; ++i) {
            slice->ReportFailure(
                CIRCUIT_BREAKER_NAMESPACE::FailureKind::RESPONSE_5XX,
                /*probe=*/false,
                slice->CurrentGenerationForTesting());
        }

        auto snap = fix.manager->meter_provider()->Snapshot();
        double closed_after = SumCounterByTwoLabels(
            snap, "reactor.circuit_breaker.state",
            "service", "svcT", "state", "closed");
        double open_after = SumCounterByTwoLabels(
            snap, "reactor.circuit_breaker.state",
            "service", "svcT", "state", "open");
        double transitions = SumCounterByTwoLabels(
            snap, "reactor.circuit_breaker.transitions",
            "service", "svcT", "from", "closed");

        // Baseline +1 on closed minus the transition -1 = 0.
        // Transition +1 on open = 1. Transitions counter = 1.
        bool pass = closed_after == 0.0 &&
                    open_after == 1.0 &&
                    transitions == 1.0 &&
                    slice->CurrentState() ==
                        CIRCUIT_BREAKER_NAMESPACE::State::OPEN;
        std::string err;
        if (!pass) {
            err = "closed_after=" + std::to_string(closed_after) +
                  " open_after=" + std::to_string(open_after) +
                  " transitions=" + std::to_string(transitions);
        }
        TestFramework::RecordTest(TAG, pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Circuit Breaker — rejected counter via the slice's RejectReason
// vocabulary.
//
// The proxy-side emit is exercised end-to-end in proxy integration
// tests; here we sketch the emit directly against the catalog using the
// same reason-string lookup the proxy uses so the closed-set vocabulary
// stays anchored to a test.
// ---------------------------------------------------------------------
inline void TestCircuitBreakerRejectedCounter() {
    const char* TAG = "ObsMW CB: rejected{reason=open} bumps on OPEN reject";
    try {
        MiddlewareFixture fix;

        UpstreamConfig u;
        u.name = "svcR";
        u.host = "127.0.0.1";
        u.port = 8080;
        u.circuit_breaker.enabled = true;
        u.circuit_breaker.consecutive_failure_threshold = 5;
        u.circuit_breaker.minimum_volume = 1000;
        u.circuit_breaker.base_open_duration_ms = 60000;  // stay OPEN

        const size_t partition_count = 1;
        CIRCUIT_BREAKER_NAMESPACE::CircuitBreakerManager cbm(
            {u}, partition_count,
            /*dispatchers=*/{},
            fix.manager.get());
        auto* slice = cbm.GetHost("svcR")->GetSlice(0);

        // Trip into OPEN.
        for (int i = 0; i < 5; ++i) {
            slice->ReportFailure(
                CIRCUIT_BREAKER_NAMESPACE::FailureKind::RESPONSE_5XX,
                /*probe=*/false,
                slice->CurrentGenerationForTesting());
        }

        // Reject via TryAcquire → matches the proxy-side reject-emit.
        auto a = slice->TryAcquire();
        const auto& cat = fix.manager->catalog();
        // Replicate the proxy emit-site mapping.
        const char* rl = nullptr;
        switch (a.reject_reason) {
            case CIRCUIT_BREAKER_NAMESPACE::RejectReason::OPEN:
                rl = "open"; break;
            case CIRCUIT_BREAKER_NAMESPACE::RejectReason::OPEN_DRYRUN:
                rl = "open_dry_run"; break;
            case CIRCUIT_BREAKER_NAMESPACE::RejectReason::HALF_OPEN_FULL:
                rl = "half_open_full"; break;
            case CIRCUIT_BREAKER_NAMESPACE::RejectReason::HALF_OPEN_RECOVERY_FAILING:
                rl = "half_open_recovery_failing"; break;
            case CIRCUIT_BREAKER_NAMESPACE::RejectReason::NONE:
                break;
        }
        if (rl != nullptr && cat.reactor_circuit_breaker_rejected != nullptr) {
            cat.reactor_circuit_breaker_rejected->Add(
                1.0, {{"service", "svcR"}, {"reason", rl}});
        }

        auto snap = fix.manager->meter_provider()->Snapshot();
        double open_rej = SumCounterByTwoLabels(
            snap, "reactor.circuit_breaker.rejected",
            "service", "svcR", "reason", "open");

        bool pass =
            a.decision == CIRCUIT_BREAKER_NAMESPACE::Decision::REJECTED_OPEN &&
            a.reject_reason ==
                CIRCUIT_BREAKER_NAMESPACE::RejectReason::OPEN &&
            open_rej >= 1.0;
        std::string err;
        if (a.decision != CIRCUIT_BREAKER_NAMESPACE::Decision::REJECTED_OPEN) {
            err = "expected REJECTED_OPEN";
        } else if (a.reject_reason !=
                   CIRCUIT_BREAKER_NAMESPACE::RejectReason::OPEN) {
            err = "expected RejectReason::OPEN";
        } else if (open_rej < 1.0) {
            err = "expected rejected{reason=open}>=1, got " +
                  std::to_string(open_rej);
        }
        TestFramework::RecordTest(TAG, pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Circuit Breaker — dry-run reject stamps reason=open_dry_run.
// ---------------------------------------------------------------------
inline void TestCircuitBreakerDryRunRejectedCounter() {
    const char* TAG = "ObsMW CB: dry-run reject stamps reason=open_dry_run";
    try {
        MiddlewareFixture fix;

        UpstreamConfig u;
        u.name = "svcD";
        u.host = "127.0.0.1";
        u.port = 8080;
        u.circuit_breaker.enabled = true;
        u.circuit_breaker.dry_run = true;
        u.circuit_breaker.consecutive_failure_threshold = 5;
        u.circuit_breaker.minimum_volume = 1000;
        u.circuit_breaker.base_open_duration_ms = 60000;

        const size_t partition_count = 1;
        CIRCUIT_BREAKER_NAMESPACE::CircuitBreakerManager cbm(
            {u}, partition_count,
            /*dispatchers=*/{},
            fix.manager.get());
        auto* slice = cbm.GetHost("svcD")->GetSlice(0);

        for (int i = 0; i < 5; ++i) {
            slice->ReportFailure(
                CIRCUIT_BREAKER_NAMESPACE::FailureKind::RESPONSE_5XX,
                /*probe=*/false,
                slice->CurrentGenerationForTesting());
        }
        auto a = slice->TryAcquire();
        bool reason_ok =
            a.reject_reason ==
                CIRCUIT_BREAKER_NAMESPACE::RejectReason::OPEN_DRYRUN;
        const auto& cat = fix.manager->catalog();
        if (reason_ok && cat.reactor_circuit_breaker_rejected != nullptr) {
            cat.reactor_circuit_breaker_rejected->Add(
                1.0, {{"service", "svcD"}, {"reason", "open_dry_run"}});
        }

        auto snap = fix.manager->meter_provider()->Snapshot();
        double dry = SumCounterByTwoLabels(
            snap, "reactor.circuit_breaker.rejected",
            "service", "svcD", "reason", "open_dry_run");

        bool pass =
            a.decision ==
                CIRCUIT_BREAKER_NAMESPACE::Decision::REJECTED_OPEN_DRYRUN &&
            reason_ok && dry >= 1.0;
        std::string err;
        if (!pass) {
            err = "decision=" + std::to_string(static_cast<int>(a.decision)) +
                  " reject_reason=" +
                  std::to_string(static_cast<int>(a.reject_reason)) +
                  " dry=" + std::to_string(dry);
        }
        TestFramework::RecordTest(TAG, pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Circuit Breaker — null manager safe path. Constructing without an
// observability manager must emit nothing and must not crash.
// ---------------------------------------------------------------------
inline void TestCircuitBreakerNullManagerSafe() {
    const char* TAG = "ObsMW CB: null manager skips emit (safe)";
    try {
        // Manager wired here only to inspect the metric snapshot; we
        // pass nullptr to CircuitBreakerManager so no emit fires.
        MiddlewareFixture fix;

        UpstreamConfig u;
        u.name = "svcN";
        u.host = "127.0.0.1";
        u.port = 8080;
        u.circuit_breaker.enabled = true;

        const size_t partition_count = 2;
        CIRCUIT_BREAKER_NAMESPACE::CircuitBreakerManager cbm(
            {u}, partition_count,
            /*dispatchers=*/{},
            /*obs_manager=*/nullptr);

        auto snap = fix.manager->meter_provider()->Snapshot();
        double closed = SumCounterByTwoLabels(
            snap, "reactor.circuit_breaker.state",
            "service", "svcN", "state", "closed");

        bool pass = closed == 0.0 && cbm.GetHost("svcN") != nullptr;
        std::string err;
        if (closed != 0.0) {
            err = "expected no emit, got closed=" + std::to_string(closed);
        }
        TestFramework::RecordTest(TAG, pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

inline void TestCircuitBreakerMetrics() {
    TestCircuitBreakerBaselineGauge();
    TestCircuitBreakerTransition();
    TestCircuitBreakerRejectedCounter();
    TestCircuitBreakerDryRunRejectedCounter();
    TestCircuitBreakerNullManagerSafe();
}

// ---------------------------------------------------------------------
// Auth — StripReasonTail unit tests
// ---------------------------------------------------------------------
inline void TestAuthStripReasonTail() {
    const char* TAG = "ObsMW Auth: StripReasonTail handles colon + whitespace";
    try {
        using AUTH_NAMESPACE::StripReasonTail;
        bool pass = true;
        std::string err;

        auto check = [&](std::string_view in, std::string_view want) {
            if (!pass) return;
            std::string got = StripReasonTail(in);
            if (got != want) {
                pass = false;
                err = "StripReasonTail(\"" + std::string(in) + "\") = \""
                      + got + "\", want \"" + std::string(want) + "\"";
            }
        };

        check("", "");
        check("x", "x");
        check("x:", "x");
        check("x: y", "x");
        check("x :y", "x");        // whitespace before colon trimmed
        check("x \t:y", "x");      // tab+space trimmed
        check("jwt_verify_failed: invalid signature, key not found",
              "jwt_verify_failed");
        check("introspection_error:502", "introspection_error");
        check("expired_token", "expired_token");
        check("only_one:two:three", "only_one");  // splits on FIRST colon

        TestFramework::RecordTest(TAG, pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Auth — CanonicalReasonLabel unit tests
// ---------------------------------------------------------------------
inline void TestAuthCanonicalReasonLabel() {
    const char* TAG = "ObsMW Auth: CanonicalReasonLabel maps to closed vocab";
    try {
        using AUTH_NAMESPACE::CanonicalReasonLabel;
        bool pass = true;
        std::string err;

        auto check = [&](std::string_view in, const char* want) {
            if (!pass) return;
            const char* got = CanonicalReasonLabel(in);
            if (std::string(got) != want) {
                pass = false;
                err = "CanonicalReasonLabel(\"" + std::string(in)
                      + "\") = \"" + got + "\", want \"" + want + "\"";
            }
        };

        // Identity round-trip — every canonical vocab entry maps to itself.
        check("missing_token",          "missing_token");
        check("expired_token",          "expired_token");
        check("malformed_token",        "malformed_token");
        check("signature_invalid",      "signature_invalid");
        check("jwt_verify_failed",      "jwt_verify_failed");
        check("aud_mismatch",           "aud_mismatch");
        check("iss_mismatch",           "iss_mismatch");
        check("introspection_inactive", "introspection_inactive");
        check("introspection_error",    "introspection_error");
        check("policy_denied",          "policy_denied");
        check("cache_miss_no_issuer",   "cache_miss_no_issuer");

        // Legacy verifier translations.
        check("issuer_mismatch",     "iss_mismatch");
        check("audience_mismatch",   "aud_mismatch");
        check("token_expired_or_nbf","expired_token");
        check("decode_failed",       "malformed_token");
        check("verify_failed",       "jwt_verify_failed");
        check("missing_required_claim","policy_denied");
        check("insufficient_scope",  "policy_denied");

        // Unknown / empty / arbitrary → "other".
        check("",                    "other");
        check("totally_unknown",     "other");
        check("some weird tag",      "other");

        TestFramework::RecordTest(TAG, pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Auth fixture helper — construct an AuthManager wired to a fixture's
// ObservabilityManager. No dispatchers/upstream needed for direct
// RecordVerdict tests.
// ---------------------------------------------------------------------
namespace {

inline std::unique_ptr<AUTH_NAMESPACE::AuthManager> MakeAuthManager(
        MiddlewareFixture& fix) {
    AUTH_NAMESPACE::AuthConfig cfg;
    cfg.enabled = true;
    return std::make_unique<AUTH_NAMESPACE::AuthManager>(
        cfg,
        /*upstream_manager=*/nullptr,
        /*dispatchers=*/std::vector<std::shared_ptr<Dispatcher>>{},
        /*obs_manager=*/fix.manager.get());
}

inline std::unique_ptr<AUTH_NAMESPACE::AuthManager> MakeAuthManagerNullObs() {
    AUTH_NAMESPACE::AuthConfig cfg;
    cfg.enabled = true;
    return std::make_unique<AUTH_NAMESPACE::AuthManager>(
        cfg,
        /*upstream_manager=*/nullptr,
        /*dispatchers=*/std::vector<std::shared_ptr<Dispatcher>>{},
        /*obs_manager=*/nullptr);
}

}  // namespace

// ---------------------------------------------------------------------
// Auth — ALLOW emits reactor.auth.requests{outcome=allow, reason=ok}
// ---------------------------------------------------------------------
inline void TestAuthAllowEmit() {
    const char* TAG = "ObsMW Auth: ALLOW emits {outcome=allow, issuer=..., reason=ok}";
    try {
        MiddlewareFixture fix;
        auto mgr = MakeAuthManager(fix);

        HttpResponse resp;
        mgr->RecordVerdict(resp, AUTH_NAMESPACE::VerifyOutcome::ALLOW,
                           "acme",
                           "policy-a",
                           AUTH_NAMESPACE::AuthCache::None,
                           std::nullopt,
                           std::string_view{});

        auto snap = fix.manager->meter_provider()->Snapshot();
        // Count points with (outcome=allow, issuer=acme, reason=ok).
        double count = 0;
        for (const auto& inst : snap.instruments) {
            if (inst.name != "reactor.auth.requests") continue;
            for (const auto& p : inst.counter_points) {
                bool ok = false, allow = false, acme = false;
                for (const auto& [k, v] : p.labels.kv) {
                    if (k == "outcome" && v == "allow")  allow = true;
                    if (k == "issuer"  && v == "acme")   acme  = true;
                    if (k == "reason"  && v == "ok")     ok    = true;
                }
                if (ok && allow && acme) count += p.value;
            }
        }
        bool pass = count >= 1.0;
        std::string err;
        if (!pass) err = "expected allow+acme+ok>=1, got "
                         + std::to_string(count);
        TestFramework::RecordTest(TAG, pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Auth — DENY with canonical reason passes through verbatim.
// ---------------------------------------------------------------------
inline void TestAuthDenyCanonicalReason() {
    const char* TAG = "ObsMW Auth: DENY {reason=missing_token} round-trips";
    try {
        MiddlewareFixture fix;
        auto mgr = MakeAuthManager(fix);

        HttpResponse resp;
        mgr->RecordVerdict(resp, AUTH_NAMESPACE::VerifyOutcome::DENY_401,
                           "acme", "policy-a",
                           AUTH_NAMESPACE::AuthCache::None,
                           std::nullopt,
                           std::string_view{"missing_token"});

        auto snap = fix.manager->meter_provider()->Snapshot();
        double count = SumCounterByTwoLabels(
            snap, "reactor.auth.requests",
            "outcome", "deny", "reason", "missing_token");
        bool pass = count >= 1.0;
        std::string err;
        if (!pass) err = "expected deny+missing_token>=1, got "
                         + std::to_string(count);
        TestFramework::RecordTest(TAG, pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Auth — DENY with empty issuer surfaces as "<unknown>". Reason with
// tail strips correctly before label emit.
// ---------------------------------------------------------------------
inline void TestAuthDenyEmptyIssuerAndTail() {
    const char* TAG = "ObsMW Auth: DENY empty issuer => <unknown> + tail stripped";
    try {
        MiddlewareFixture fix;
        auto mgr = MakeAuthManager(fix);

        HttpResponse resp;
        mgr->RecordVerdict(resp, AUTH_NAMESPACE::VerifyOutcome::DENY_401,
                           /*issuer=*/std::string{},
                           "policy-a",
                           AUTH_NAMESPACE::AuthCache::None,
                           std::nullopt,
                           std::string_view{
                               "jwt_verify_failed:invalid signature, key not found"});

        auto snap = fix.manager->meter_provider()->Snapshot();
        // Expect (outcome=deny, issuer=<unknown>, reason=jwt_verify_failed).
        double count = 0;
        for (const auto& inst : snap.instruments) {
            if (inst.name != "reactor.auth.requests") continue;
            for (const auto& p : inst.counter_points) {
                bool deny = false, unk = false, jvf = false;
                for (const auto& [k, v] : p.labels.kv) {
                    if (k == "outcome" && v == "deny")              deny = true;
                    if (k == "issuer"  && v == "<unknown>")          unk  = true;
                    if (k == "reason"  && v == "jwt_verify_failed")  jvf  = true;
                }
                if (deny && unk && jvf) count += p.value;
            }
        }
        bool pass = count >= 1.0;
        std::string err;
        if (!pass) err = "expected deny+<unknown>+jwt_verify_failed>=1, got "
                         + std::to_string(count);
        TestFramework::RecordTest(TAG, pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Auth — Unknown reason (outside closed vocab) collapses to "other".
// ---------------------------------------------------------------------
inline void TestAuthDenyUnknownReasonCollapsesToOther() {
    const char* TAG = "ObsMW Auth: DENY unknown reason => reason=other";
    try {
        MiddlewareFixture fix;
        auto mgr = MakeAuthManager(fix);

        HttpResponse resp;
        mgr->RecordVerdict(resp, AUTH_NAMESPACE::VerifyOutcome::DENY_401,
                           "acme", "policy-a",
                           AUTH_NAMESPACE::AuthCache::None,
                           std::nullopt,
                           std::string_view{"weirdness:tail bits"});

        auto snap = fix.manager->meter_provider()->Snapshot();
        double count = SumCounterByTwoLabels(
            snap, "reactor.auth.requests",
            "outcome", "deny", "reason", "other");
        bool pass = count >= 1.0;
        std::string err;
        if (!pass) err = "expected deny+other>=1, got " + std::to_string(count);
        TestFramework::RecordTest(TAG, pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Auth — UNDETERMINED emits with outcome=undetermined.
// ---------------------------------------------------------------------
inline void TestAuthUndeterminedEmit() {
    const char* TAG = "ObsMW Auth: UNDETERMINED emits outcome=undetermined";
    try {
        MiddlewareFixture fix;
        auto mgr = MakeAuthManager(fix);

        HttpResponse resp;
        mgr->RecordVerdict(resp, AUTH_NAMESPACE::VerifyOutcome::UNDETERMINED,
                           "acme", "policy-a",
                           AUTH_NAMESPACE::AuthCache::None,
                           std::nullopt,
                           std::string_view{"introspection_error:502"});

        auto snap = fix.manager->meter_provider()->Snapshot();
        double count = SumCounterByTwoLabels(
            snap, "reactor.auth.requests",
            "outcome", "undetermined", "reason", "introspection_error");
        bool pass = count >= 1.0;
        std::string err;
        if (!pass) err = "expected undetermined+introspection_error>=1, got "
                         + std::to_string(count);
        TestFramework::RecordTest(TAG, pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Auth — Null obs_manager is safe (no crash, no emit).
// ---------------------------------------------------------------------
inline void TestAuthNullManagerSafe() {
    const char* TAG = "ObsMW Auth: null obs_manager => no crash, no emit";
    try {
        auto mgr = MakeAuthManagerNullObs();

        HttpResponse resp;
        // Drive every outcome path; none should crash with null obs_manager.
        mgr->RecordVerdict(resp, AUTH_NAMESPACE::VerifyOutcome::ALLOW,
                           "acme", "policy-a", AUTH_NAMESPACE::AuthCache::None);
        mgr->RecordVerdict(resp, AUTH_NAMESPACE::VerifyOutcome::DENY_401,
                           "acme", "policy-a", AUTH_NAMESPACE::AuthCache::None,
                           std::nullopt, std::string_view{"missing_token"});
        mgr->RecordVerdict(resp, AUTH_NAMESPACE::VerifyOutcome::UNDETERMINED,
                           "acme", "policy-a", AUTH_NAMESPACE::AuthCache::None,
                           std::nullopt, std::string_view{"introspection_error"});
        // Also test EmitCacheLookup is safe with null manager (private impl
        // shouldn't reach the catalog at all).
        mgr->EmitCacheLookup("hit", "acme");
        mgr->EmitCacheLookup("miss", "acme");

        // If we reach here without crashing, the test passes.
        TestFramework::RecordTest(TAG, true, "",
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// Auth — EmitCacheLookup emits each closed-vocab outcome at the right
// site. Drives the helper directly since the cache-hit / miss /
// stale_serve / refresh_fail call sites are deep inside the
// introspection-async path; exercising them via integration tests
// requires standing up an IdP, which is out of scope here.
// ---------------------------------------------------------------------
inline void TestAuthCacheLookupOutcomes() {
    const char* TAG = "ObsMW Auth: EmitCacheLookup hit/miss/stale_serve/refresh_fail";
    try {
        MiddlewareFixture fix;
        auto mgr = MakeAuthManager(fix);

        mgr->EmitCacheLookup("hit",          "acme");
        mgr->EmitCacheLookup("miss",         "acme");
        mgr->EmitCacheLookup("stale_serve",  "acme");
        mgr->EmitCacheLookup("refresh_fail", "acme");
        // Empty issuer should surface as <unknown>.
        mgr->EmitCacheLookup("miss",         std::string{});

        auto snap = fix.manager->meter_provider()->Snapshot();
        auto count = [&](const std::string& outcome,
                         const std::string& issuer) -> double {
            return SumCounterByTwoLabels(
                snap, "reactor.auth.cache.lookups",
                "outcome", outcome, "issuer", issuer);
        };

        bool pass = count("hit",          "acme") >= 1.0
                 && count("miss",         "acme") >= 1.0
                 && count("stale_serve",  "acme") >= 1.0
                 && count("refresh_fail", "acme") >= 1.0
                 && count("miss",         "<unknown>") >= 1.0;
        std::string err = pass ? "" : "one or more outcomes did not emit "
                                       "the expected count";
        TestFramework::RecordTest(TAG, pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ---------------------------------------------------------------------
// JWKS — The fetcher's terminal closures emit
// reactor.auth.jwks.refreshes{issuer, outcome}. We exercise the parse-
// failure path by feeding a malformed body through ParseAndConvert via
// the public StartFetch / Issue path is heavyweight (needs an UpstreamHttpClient
// + dispatchers). Instead, drive the metric directly via the catalog to
// validate the catalog wiring; deep integration coverage lives in the
// auth_jwks_test suite.
// ---------------------------------------------------------------------
inline void TestAuthJwksRefreshesCatalogWired() {
    const char* TAG = "ObsMW Auth: reactor.auth.jwks.refreshes catalog wired";
    try {
        MiddlewareFixture fix;
        const auto& cat = fix.manager->catalog();
        bool pass = cat.reactor_auth_jwks_refreshes != nullptr;
        std::string err;
        if (!pass) {
            err = "reactor_auth_jwks_refreshes is null — catalog must "
                  "construct the counter at boot";
        } else {
            // Drive a synthetic emit so the test would detect a counter
            // accidentally renamed without updating the catalog.
            cat.reactor_auth_jwks_refreshes->Add(
                1.0,
                {{"issuer", "acme"},
                 {"outcome", "success"}});
            auto snap = fix.manager->meter_provider()->Snapshot();
            double count = SumCounterByTwoLabels(
                snap, "reactor.auth.jwks.refreshes",
                "issuer", "acme", "outcome", "success");
            if (count < 1.0) {
                pass = false;
                err = "expected jwks_refreshes{success}>=1, got "
                      + std::to_string(count);
            }
        }
        TestFramework::RecordTest(TAG, pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

inline void TestAuthMetrics() {
    TestAuthStripReasonTail();
    TestAuthCanonicalReasonLabel();
    TestAuthAllowEmit();
    TestAuthDenyCanonicalReason();
    TestAuthDenyEmptyIssuerAndTail();
    TestAuthDenyUnknownReasonCollapsesToOther();
    TestAuthUndeterminedEmit();
    TestAuthNullManagerSafe();
    TestAuthCacheLookupOutcomes();
    TestAuthJwksRefreshesCatalogWired();
}

inline void RunAllTests() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "MIDDLEWARE METRICS TESTS — DNS + Rate-Limit + CB + Auth"
              << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    TestDnsSuccessOutcome();
    TestDnsCacheHitOutcome();
    TestDnsNxDomainOutcome();
    TestDnsServfailAndOtherErrorOutcome();
    TestDnsNullManagerSafe();

    TestRateLimitAdmitMetric();
    TestRateLimitRejectMetric();
    TestRateLimitDryRunRejectMetric();
    TestRateLimitTokensHistogram();
    TestRateLimitNoZonesNoEmit();
    TestRateLimitNullManagerSafe();

    TestCircuitBreakerMetrics();

    TestAuthMetrics();
}

}  // namespace ObservabilityMiddlewareMetricsTests
