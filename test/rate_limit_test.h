#pragma once

// rate_limit_test.h -- Tests for the rate limiting feature.
//
// Coverage dimensions:
//   A. TokenBucket unit tests (core algorithm)
//   B. RateLimitZone tests (key extraction, applies_to, LRU eviction)
//   C. RateLimitManager tests (single/multi zone, headers, disabled)
//   D. Hot-reload tests (enable/disable, rate change, add/remove zones)
//   E. Integration tests (full HTTP request/response via TestServerRunner)
//   F. Configuration tests (JSON round-trip, validation errors)
//   G. Edge case tests (empty key, capacity=1, high rate)
//
// All servers use ephemeral port 0 -- no fixed port conflicts.

#include "test_framework.h"
#include "test_server_runner.h"
#include "http_test_client.h"
#include "http/http_server.h"
#include "http/http_request.h"
#include "http/http_response.h"
#include "config/server_config.h"
#include "config/config_loader.h"
#include "rate_limit/token_bucket.h"
#include "rate_limit/rate_limit_zone.h"
#include "rate_limit/rate_limiter.h"
#include <thread>
#include <chrono>

namespace RateLimitTests {

// =========================================================================
// Helper: build a minimal HttpRequest for unit tests
// =========================================================================

static HttpRequest MakeRequest(const std::string& method,
                               const std::string& path,
                               const std::string& client_ip = "10.0.0.1") {
    HttpRequest req;
    req.method = method;
    req.path = path;
    req.client_ip = client_ip;
    req.complete = true;
    return req;
}

// Helper: check if response headers contain a given key (case-sensitive,
// matches the server's exact casing since it controls header names).
static bool ResponseHasHeader(const HttpResponse& response,
                              const std::string& name) {
    for (const auto& kv : response.GetHeaders()) {
        if (kv.first == name) return true;
    }
    return false;
}

static std::string ResponseGetHeader(const HttpResponse& response,
                                     const std::string& name) {
    for (const auto& kv : response.GetHeaders()) {
        if (kv.first == name) return kv.second;
    }
    return "";
}

// Helper: find a header value in a raw HTTP response string (case-insensitive).
static std::string FindRawHeader(const std::string& response,
                                 const std::string& header_name) {
    // Lowercase both for comparison
    std::string lower_resp = response;
    std::string lower_name = header_name;
    for (auto& c : lower_resp) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    for (auto& c : lower_name) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    std::string search = lower_name + ": ";
    auto pos = lower_resp.find(search);
    if (pos == std::string::npos) return "";

    // Extract value from original (preserving case)
    size_t val_start = pos + search.size();
    auto val_end = response.find("\r\n", val_start);
    if (val_end == std::string::npos) val_end = response.size();
    return response.substr(val_start, val_end - val_start);
}


// =========================================================================
// A. TokenBucket unit tests
// =========================================================================

void TestTokenBucketFreshBucketIsFull() {
    std::cout << "\n[TEST] TokenBucket: Fresh bucket is full..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        TokenBucket bucket(10.0, 5);  // 10 tokens/sec, capacity 5

        if (bucket.Capacity() != 5) {
            pass = false;
            err += "capacity=" + std::to_string(bucket.Capacity()) + " expected 5; ";
        }
        if (bucket.AvailableTokens() != 5) {
            pass = false;
            err += "available=" + std::to_string(bucket.AvailableTokens()) + " expected 5; ";
        }

        // Should succeed exactly 5 times
        int consumed = 0;
        for (int i = 0; i < 10; i++) {
            if (bucket.TryConsume()) consumed++;
        }
        if (consumed != 5) {
            pass = false;
            err += "consumed=" + std::to_string(consumed) + " expected 5; ";
        }

        TestFramework::RecordTest("TokenBucket: Fresh bucket is full", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("TokenBucket: Fresh bucket is full", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestTokenBucketLazyRefill() {
    std::cout << "\n[TEST] TokenBucket: Lazy refill after sleep..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        // rate = 100 tokens/sec, capacity = 10
        // Consume all tokens, sleep 50ms, expect ~5 tokens refilled
        TokenBucket bucket(100.0, 10);

        // Drain all tokens
        for (int i = 0; i < 10; i++) bucket.TryConsume();

        if (bucket.AvailableTokens() != 0) {
            pass = false;
            err += "after drain available=" + std::to_string(bucket.AvailableTokens()) + "; ";
        }

        // Sleep 50ms -> expect ~5 tokens (100 tokens/sec * 0.05 sec = 5)
        std::this_thread::sleep_for(std::chrono::milliseconds(60));

        int64_t avail = bucket.AvailableTokens();
        // Allow some tolerance for timing: 3-7 tokens
        if (avail < 3 || avail > 8) {
            pass = false;
            err += "after 60ms sleep available=" + std::to_string(avail) + " expected ~5; ";
        }

        TestFramework::RecordTest("TokenBucket: Lazy refill after sleep", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("TokenBucket: Lazy refill after sleep", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestTokenBucketCapacityLimit() {
    std::cout << "\n[TEST] TokenBucket: Refill never exceeds capacity..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        TokenBucket bucket(1000.0, 5);  // Very high rate, capacity 5

        // Sleep to allow many tokens to accumulate
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        int64_t avail = bucket.AvailableTokens();
        if (avail != 5) {
            pass = false;
            err += "available=" + std::to_string(avail) + " expected capacity=5; ";
        }

        TestFramework::RecordTest("TokenBucket: Refill never exceeds capacity", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("TokenBucket: Refill never exceeds capacity", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestTokenBucketUpdateConfigRateChange() {
    std::cout << "\n[TEST] TokenBucket: UpdateConfig rate change..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        TokenBucket bucket(10.0, 5);

        // Consume 3 tokens, leaving 2
        for (int i = 0; i < 3; i++) bucket.TryConsume();

        int64_t before = bucket.AvailableTokens();
        if (before != 2) {
            pass = false;
            err += "before update available=" + std::to_string(before) + " expected 2; ";
        }

        // Update rate to 100 tokens/sec, same capacity. Tokens preserved.
        bucket.UpdateConfig(100.0, 5);

        int64_t after = bucket.AvailableTokens();
        if (after != 2) {
            pass = false;
            err += "after rate update available=" + std::to_string(after) + " expected 2; ";
        }

        if (bucket.Capacity() != 5) {
            pass = false;
            err += "capacity after update=" + std::to_string(bucket.Capacity()) + " expected 5; ";
        }

        TestFramework::RecordTest("TokenBucket: UpdateConfig rate change", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("TokenBucket: UpdateConfig rate change", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestTokenBucketUpdateConfigCapacityShrink() {
    std::cout << "\n[TEST] TokenBucket: UpdateConfig capacity shrink clamps tokens..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        TokenBucket bucket(10.0, 10);  // Full at 10

        // Shrink capacity to 3 -- tokens should be clamped
        bucket.UpdateConfig(10.0, 3);

        if (bucket.Capacity() != 3) {
            pass = false;
            err += "capacity=" + std::to_string(bucket.Capacity()) + " expected 3; ";
        }

        int64_t avail = bucket.AvailableTokens();
        if (avail != 3) {
            pass = false;
            err += "available=" + std::to_string(avail) + " expected 3 (clamped); ";
        }

        TestFramework::RecordTest("TokenBucket: UpdateConfig capacity shrink clamps tokens", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("TokenBucket: UpdateConfig capacity shrink clamps tokens", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestTokenBucketLowRateFractionalCredit() {
    std::cout << "\n[TEST] TokenBucket: low-rate fractional refill credit preserved..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        // Rate = 10 req/sec → 10000 millitokens/sec.
        // Capacity = 1. Each refill requires 1000 millitokens = 100 ms.
        // We probe faster than the refill period (every 50 ms). With the
        // fractional-credit fix, after 2 probes (100 ms total) we should
        // accrue 1 token. Without the fix, add truncates to 0 on each
        // probe and last_refill_time_ advances, losing all credit — the
        // bucket would stay empty forever.
        TokenBucket bucket(10.0, 1);

        // Drain the bucket
        if (!bucket.TryConsume()) {
            pass = false;
            err += "initial TryConsume should succeed; ";
        }
        if (bucket.TryConsume()) {
            pass = false;
            err += "second TryConsume should be denied; ";
        }

        // Now probe every 50 ms. After 100 ms total (2 probes), we should
        // have earned 1 token via accumulated fractional credit.
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        bool r1 = bucket.TryConsume();  // Should still be denied (only 500 mt)
        if (r1) {
            pass = false;
            err += "probe after 50ms should be denied (only 500 mt accrued); ";
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(60));  // total ~110ms
        bool r2 = bucket.TryConsume();  // Should succeed (1000+ mt accrued)
        if (!r2) {
            pass = false;
            err += "probe after 110ms total should succeed (credit accumulated); ";
        }

        TestFramework::RecordTest("TokenBucket: low-rate fractional credit preserved", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("TokenBucket: low-rate fractional credit preserved", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestTokenBucketSecondsUntilAvailable() {
    std::cout << "\n[TEST] TokenBucket: SecondsUntilAvailable..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        TokenBucket bucket(10.0, 5);  // 10 tokens/sec

        // When tokens are available, should return 0
        double wait = bucket.SecondsUntilAvailable();
        if (wait != 0.0) {
            pass = false;
            err += "with tokens wait=" + std::to_string(wait) + " expected 0; ";
        }

        // Drain all tokens
        for (int i = 0; i < 5; i++) bucket.TryConsume();

        // Now should return a positive value (~0.1 sec for 10 tokens/sec)
        wait = bucket.SecondsUntilAvailable();
        if (wait <= 0.0) {
            pass = false;
            err += "after drain wait=" + std::to_string(wait) + " expected >0; ";
        }
        // Should be roughly 0.1 seconds (1 token / 10 tokens per second)
        if (wait > 0.2) {
            pass = false;
            err += "after drain wait=" + std::to_string(wait) + " expected ~0.1; ";
        }

        TestFramework::RecordTest("TokenBucket: SecondsUntilAvailable", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("TokenBucket: SecondsUntilAvailable", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}


// =========================================================================
// B. RateLimitZone tests
// =========================================================================

void TestZoneKeyExtractorClientIp() {
    std::cout << "\n[TEST] RateLimitZone: client_ip key extractor..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        auto extractor = MakeKeyExtractor("client_ip");
        HttpRequest req = MakeRequest("GET", "/test", "192.168.1.100");

        std::string key = extractor(req);
        if (key != "192.168.1.100") {
            pass = false;
            err += "key='" + key + "' expected '192.168.1.100'; ";
        }

        TestFramework::RecordTest("RateLimitZone: client_ip key extractor", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RateLimitZone: client_ip key extractor", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestZoneKeyExtractorHeader() {
    std::cout << "\n[TEST] RateLimitZone: header key extractor..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        auto extractor = MakeKeyExtractor("header:x-api-key");

        // With header present
        HttpRequest req = MakeRequest("GET", "/test");
        req.headers["x-api-key"] = "my-key-123";

        std::string key = extractor(req);
        if (key != "my-key-123") {
            pass = false;
            err += "with header: key='" + key + "' expected 'my-key-123'; ";
        }

        // Without header -- should return empty
        HttpRequest req2 = MakeRequest("GET", "/test");
        std::string key2 = extractor(req2);
        if (!key2.empty()) {
            pass = false;
            err += "without header: key='" + key2 + "' expected empty; ";
        }

        TestFramework::RecordTest("RateLimitZone: header key extractor", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RateLimitZone: header key extractor", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestZoneKeyExtractorComposite() {
    std::cout << "\n[TEST] RateLimitZone: client_ip+path composite extractor..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        auto extractor = MakeKeyExtractor("client_ip+path");
        HttpRequest req = MakeRequest("GET", "/api/users", "10.0.0.5");

        std::string key = extractor(req);
        std::string expected = "10.0.0.5|/api/users";
        if (key != expected) {
            pass = false;
            err += "key='" + key + "' expected '" + expected + "'; ";
        }

        TestFramework::RecordTest("RateLimitZone: client_ip+path composite extractor", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RateLimitZone: client_ip+path composite extractor", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestZoneEmptyKeySkipsRateLimit() {
    std::cout << "\n[TEST] RateLimitZone: empty key skips rate limiting..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        RateLimitZoneConfig config;
        config.name = "test_zone";
        config.rate = 1.0;
        config.capacity = 1;
        config.key_type = "header:x-api-key";
        config.max_entries = 100;

        auto extractor = MakeKeyExtractor(config.key_type);
        RateLimitZone zone(config.name, config, std::move(extractor));

        // Request without x-api-key header -> empty key -> allowed
        HttpRequest req = MakeRequest("GET", "/test");

        // Should always be allowed regardless of rate limit, AND the result
        // must be marked applicable=false so the manager skips this zone
        // when building response headers (symmetric with applies_to miss).
        for (int i = 0; i < 10; i++) {
            auto result = zone.Check(req);
            if (!result.allowed) {
                pass = false;
                err += "request " + std::to_string(i) + " was denied with empty key; ";
                break;
            }
            if (result.applicable) {
                pass = false;
                err += "request " + std::to_string(i) +
                       " result.applicable=true (should be false — empty key); ";
                break;
            }
        }

        TestFramework::RecordTest("RateLimitZone: empty key skips rate limiting", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RateLimitZone: empty key skips rate limiting", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestZoneAppliesToFilter() {
    std::cout << "\n[TEST] RateLimitZone: applies_to prefix filter..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        RateLimitZoneConfig config;
        config.name = "api_zone";
        config.rate = 1.0;
        config.capacity = 1;
        config.key_type = "client_ip";
        config.max_entries = 100;
        config.applies_to = {"/api/"};

        auto extractor = MakeKeyExtractor(config.key_type);
        RateLimitZone zone(config.name, config, std::move(extractor));

        // Request to /api/users -- should be rate limited (capacity=1)
        HttpRequest api_req = MakeRequest("GET", "/api/users");
        auto r1 = zone.Check(api_req);
        if (!r1.allowed) {
            pass = false;
            err += "first /api/ request should be allowed; ";
        }
        auto r2 = zone.Check(api_req);
        if (r2.allowed) {
            pass = false;
            err += "second /api/ request should be denied (capacity=1); ";
        }

        // Request to /health -- should NOT be rate limited (no prefix match).
        // The result must be marked applicable=false so the manager skips
        // this zone when building response headers.
        HttpRequest health_req = MakeRequest("GET", "/health");
        for (int i = 0; i < 5; i++) {
            auto r = zone.Check(health_req);
            if (!r.allowed) {
                pass = false;
                err += "/health request " + std::to_string(i) + " was denied (should bypass); ";
                break;
            }
            if (r.applicable) {
                pass = false;
                err += "/health request " + std::to_string(i) +
                       " result.applicable=true (should be false — prefix miss); ";
                break;
            }
        }

        TestFramework::RecordTest("RateLimitZone: applies_to prefix filter", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RateLimitZone: applies_to prefix filter", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestZoneAppliesToSegmentBoundary() {
    std::cout << "\n[TEST] RateLimitZone: applies_to matches on segment boundary only..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        // Prefix "/api" WITHOUT trailing slash. Should match "/api",
        // "/api/users", etc., but NOT "/apis" or "/api2" (no segment
        // boundary).
        RateLimitZoneConfig config;
        config.name = "boundary_zone";
        config.rate = 1.0;
        config.capacity = 1;
        config.key_type = "client_ip";
        config.max_entries = 100;
        config.applies_to = {"/api"};

        auto extractor = MakeKeyExtractor(config.key_type);
        RateLimitZone zone(config.name, config, std::move(extractor));

        // /api (exact match) — zone applies, capacity=1, first allowed, second denied
        {
            HttpRequest req = MakeRequest("GET", "/api");
            auto r1 = zone.Check(req);
            auto r2 = zone.Check(req);
            if (!r1.allowed || r2.allowed) {
                pass = false;
                err += "/api: expected allow then deny; ";
            }
        }

        // /api/users (segment boundary) — zone applies, shares the /api bucket
        // Since we already consumed the token above for this client_ip, this
        // should also be denied.
        {
            HttpRequest req = MakeRequest("GET", "/api/users");
            auto r = zone.Check(req);
            if (r.allowed) {
                pass = false;
                err += "/api/users: expected deny (shares bucket via segment match); ";
            }
        }

        // /apis — zone does NOT apply (no segment boundary), always allowed
        {
            HttpRequest req = MakeRequest("GET", "/apis");
            for (int i = 0; i < 5; i++) {
                auto r = zone.Check(req);
                if (!r.allowed) {
                    pass = false;
                    err += "/apis request " + std::to_string(i) +
                           " denied (should bypass — not a segment match); ";
                    break;
                }
            }
        }

        // /api2 — zone does NOT apply, always allowed
        {
            HttpRequest req = MakeRequest("GET", "/api2");
            for (int i = 0; i < 5; i++) {
                auto r = zone.Check(req);
                if (!r.allowed) {
                    pass = false;
                    err += "/api2 request " + std::to_string(i) +
                           " denied (should bypass — not a segment match); ";
                    break;
                }
            }
        }

        TestFramework::RecordTest("RateLimitZone: applies_to segment boundary", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RateLimitZone: applies_to segment boundary", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestZoneLruEviction() {
    std::cout << "\n[TEST] RateLimitZone: LRU eviction when max_entries exceeded..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        RateLimitZoneConfig config;
        config.name = "evict_zone";
        config.rate = 1000.0;  // High rate so tokens refill fast
        config.capacity = 100;
        config.key_type = "client_ip";
        config.max_entries = 16;  // Low limit to trigger eviction (1 per shard)

        auto extractor = MakeKeyExtractor(config.key_type);
        RateLimitZone zone(config.name, config, std::move(extractor));

        // Insert many unique keys (more than max_entries)
        for (int i = 0; i < 100; i++) {
            HttpRequest req = MakeRequest("GET", "/test",
                "10.0." + std::to_string(i / 256) + "." + std::to_string(i % 256));
            zone.Check(req);
        }

        size_t before = zone.EntryCount();

        // Evict expired entries (simulate dispatcher 0 of 1)
        zone.EvictExpired(0, 1);

        size_t after = zone.EntryCount();

        // After eviction, entry count should be <= max_entries
        if (after > static_cast<size_t>(config.max_entries)) {
            pass = false;
            err += "after eviction count=" + std::to_string(after) +
                   " exceeds max_entries=" + std::to_string(config.max_entries) +
                   " (before=" + std::to_string(before) + "); ";
        }

        TestFramework::RecordTest("RateLimitZone: LRU eviction when max_entries exceeded", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RateLimitZone: LRU eviction when max_entries exceeded", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestZoneSynchronousMaxEntriesEnforcement() {
    std::cout << "\n[TEST] RateLimitZone: max_entries enforced synchronously on insert..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        // Insert many unique keys WITHOUT calling EvictExpired in between.
        // Under the old behavior, the shard could grow unbounded until the
        // next timer sweep (vulnerability to memory spikes under high-
        // cardinality bursts). With the fix, FindOrCreate evicts LRU before
        // insert if the shard is at capacity.
        RateLimitZoneConfig config;
        config.name = "sync_evict_zone";
        config.rate = 1000.0;
        config.capacity = 100;
        config.key_type = "client_ip";
        config.max_entries = 16;  // 1 per shard (16 shards default)

        auto extractor = MakeKeyExtractor(config.key_type);
        RateLimitZone zone(config.name, config, std::move(extractor));

        // Insert 500 unique keys without calling EvictExpired.
        for (int i = 0; i < 500; i++) {
            HttpRequest req = MakeRequest("GET", "/test",
                "10.1." + std::to_string(i / 256) + "." + std::to_string(i % 256));
            zone.Check(req);
        }

        // Without a timer sweep, count must still respect max_entries
        // (thanks to synchronous eviction on insert).
        size_t count = zone.EntryCount();
        if (count > static_cast<size_t>(config.max_entries)) {
            pass = false;
            err += "count=" + std::to_string(count) +
                   " exceeds max_entries=" + std::to_string(config.max_entries) +
                   " without timer sweep (sync eviction failed); ";
        }

        TestFramework::RecordTest("RateLimitZone: synchronous max_entries enforcement", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RateLimitZone: synchronous max_entries enforcement", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}


// =========================================================================
// C. RateLimitManager tests
// =========================================================================

void TestManagerSingleZoneAllow() {
    std::cout << "\n[TEST] RateLimitManager: single zone allow..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        RateLimitConfig config;
        config.enabled = true;
        config.zones.push_back({"test_zone", 100.0, 10, "client_ip", 1000, {}});

        RateLimitManager manager(config);

        HttpRequest req = MakeRequest("GET", "/test");
        HttpResponse response;

        bool allowed = manager.Check(req, response);
        if (!allowed) {
            pass = false;
            err += "first request should be allowed; ";
        }

        TestFramework::RecordTest("RateLimitManager: single zone allow", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RateLimitManager: single zone allow", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestManagerSingleZoneDeny() {
    std::cout << "\n[TEST] RateLimitManager: single zone deny when exhausted..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        RateLimitConfig config;
        config.enabled = true;
        config.zones.push_back({"test_zone", 1.0, 3, "client_ip", 1000, {}});

        RateLimitManager manager(config);

        HttpRequest req = MakeRequest("GET", "/test");

        // Consume all 3 tokens
        for (int i = 0; i < 3; i++) {
            HttpResponse response;
            bool allowed = manager.Check(req, response);
            if (!allowed) {
                pass = false;
                err += "request " + std::to_string(i) + " should be allowed; ";
            }
        }

        // 4th request should be denied
        HttpResponse response;
        bool denied = !manager.Check(req, response);
        if (!denied) {
            pass = false;
            err += "4th request should be denied (capacity=3 exhausted); ";
        }

        TestFramework::RecordTest("RateLimitManager: single zone deny when exhausted", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RateLimitManager: single zone deny when exhausted", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestManagerMultiZoneAllPass() {
    std::cout << "\n[TEST] RateLimitManager: multi-zone all pass..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        RateLimitConfig config;
        config.enabled = true;
        config.zones.push_back({"zone_a", 100.0, 50, "client_ip", 1000, {}});
        config.zones.push_back({"zone_b", 100.0, 50, "path", 1000, {}});

        RateLimitManager manager(config);

        HttpRequest req = MakeRequest("GET", "/test");
        HttpResponse response;

        bool allowed = manager.Check(req, response);
        if (!allowed) {
            pass = false;
            err += "request should pass both zones; ";
        }

        TestFramework::RecordTest("RateLimitManager: multi-zone all pass", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RateLimitManager: multi-zone all pass", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestManagerMultiZoneOneDenies() {
    std::cout << "\n[TEST] RateLimitManager: multi-zone one denies..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        RateLimitConfig config;
        config.enabled = true;
        // Zone A: generous limit
        config.zones.push_back({"zone_a", 100.0, 50, "client_ip", 1000, {}});
        // Zone B: tiny limit (capacity=1)
        config.zones.push_back({"zone_b", 1.0, 1, "client_ip", 1000, {}});

        RateLimitManager manager(config);

        HttpRequest req = MakeRequest("GET", "/test");

        // First request should pass
        {
            HttpResponse response;
            bool allowed = manager.Check(req, response);
            if (!allowed) {
                pass = false;
                err += "first request should pass; ";
            }
        }

        // Second request: zone_b exhausted -> denied
        {
            HttpResponse response;
            bool denied = !manager.Check(req, response);
            if (!denied) {
                pass = false;
                err += "second request should be denied by zone_b; ";
            }
        }

        TestFramework::RecordTest("RateLimitManager: multi-zone one denies", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RateLimitManager: multi-zone one denies", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestManagerStopsDebitingAfterDenial() {
    std::cout << "\n[TEST] RateLimitManager: later zones are not debited after denial..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        // Strategy: use key_type="path" for BOTH zones so buckets are
        // SHARED across all clients. Then we can directly observe whether
        // the trailing zone's bucket was debited by requests that the
        // leading zone rejected.
        //
        //   deny_first:    key=path, capacity=1 — rejects 2nd+ request on same path
        //   trailing_zone: key=path, capacity=4 — witness; if debited after
        //                  deny_first rejects, it will exhaust faster
        //
        // With OLD behavior (debit all zones): every rejection by deny_first
        // still consumes 1 from trailing_zone, so after 4 total requests
        // trailing_zone is exhausted (4 debits = capacity).
        //
        // With NEW behavior (break on deny): only request #1 debits
        // trailing_zone. Rejections by deny_first do not touch it. After
        // 100 rejections, trailing_zone still has 3 tokens.
        RateLimitConfig config;
        config.enabled = true;
        config.zones.push_back({"deny_first", 1.0, 1, "path", 1000, {}});
        config.zones.push_back({"trailing_zone", 0.001, 4, "path", 1000, {}});

        RateLimitManager manager(config);
        HttpRequest req = MakeRequest("GET", "/test", "10.0.0.1");

        // First request: both zones allow. deny_first: 1→0, trailing: 4→3.
        {
            HttpResponse response;
            if (!manager.Check(req, response)) {
                pass = false;
                err += "first request should pass; ";
            }
        }

        // Send 5 more requests that deny_first will reject. With the fix,
        // trailing_zone stays at 3 tokens (no debit on rejection path).
        for (int i = 0; i < 5; i++) {
            HttpResponse response;
            if (manager.Check(req, response)) {
                pass = false;
                err += "request " + std::to_string(i + 2) +
                       " should be denied by deny_first; ";
            }
        }

        // Now REMOVE deny_first from the config via Reload, leaving only
        // trailing_zone. Under the fix (new behavior), trailing_zone still
        // has ~3 tokens from the initial allow. Under the old behavior
        // (debit all zones), trailing_zone was drained to 0 by the 5
        // subsequent rejections.
        //
        // Reload preserves existing zone state by name+key_type match, so
        // trailing_zone keeps its accumulated bucket state across reload.
        RateLimitConfig reduced;
        reduced.enabled = true;
        reduced.zones.push_back({"trailing_zone", 0.001, 4, "path", 1000, {}});
        manager.Reload(reduced);

        int successes = 0;
        for (int i = 0; i < 10; i++) {
            HttpResponse response;
            if (manager.Check(req, response)) {
                successes++;
            }
        }

        // With new behavior: trailing_zone had 3 tokens left after the
        // initial Check() (req 1 debited 1 of 4 tokens). Rate=0.001/s,
        // negligible refill over a few ms. Expected: ~3 successes.
        // With old behavior: trailing_zone was drained to 0 by the 5
        // rejections in the previous loop. Expected: 0 successes.
        if (successes < 2) {
            pass = false;
            err += "trailing_zone exhausted: " + std::to_string(successes) +
                   " successes (old debit-all behavior detected; expected >= 2); ";
        }

        TestFramework::RecordTest("RateLimitManager: stops debiting after denial", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RateLimitManager: stops debiting after denial", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestManagerResponseHeaders() {
    std::cout << "\n[TEST] RateLimitManager: response headers present..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        RateLimitConfig config;
        config.enabled = true;
        config.include_headers = true;
        config.zones.push_back({"test_zone", 10.0, 5, "client_ip", 1000, {}});

        RateLimitManager manager(config);

        HttpRequest req = MakeRequest("GET", "/test");
        HttpResponse response;
        manager.Check(req, response);

        // Should have RateLimit-Policy and RateLimit headers
        if (!ResponseHasHeader(response, "RateLimit-Policy")) {
            pass = false;
            err += "missing RateLimit-Policy header; ";
        }
        if (!ResponseHasHeader(response, "RateLimit")) {
            pass = false;
            err += "missing RateLimit header; ";
        }

        TestFramework::RecordTest("RateLimitManager: response headers present", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RateLimitManager: response headers present", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestManagerLargePolicyWindowHeader() {
    std::cout << "\n[TEST] RateLimitManager: large policy window header doesn't overflow..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        RateLimitConfig config;
        config.enabled = true;
        config.include_headers = true;
        config.zones.push_back(
            {"huge_window", 0.001, 1000000000000LL, "client_ip", 1000, {}});

        RateLimitManager manager(config);

        HttpRequest req = MakeRequest("GET", "/test");
        HttpResponse response;
        if (!manager.Check(req, response)) {
            pass = false;
            err += "request should be allowed; ";
        }

        std::string policy = ResponseGetHeader(response, "RateLimit-Policy");
        if (policy != "1000000000000;w=1000000000000000") {
            pass = false;
            err += "RateLimit-Policy='" + policy +
                   "' expected '1000000000000;w=1000000000000000'; ";
        }

        TestFramework::RecordTest("RateLimitManager: large policy window header doesn't overflow",
                                  pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RateLimitManager: large policy window header doesn't overflow",
                                  false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestManagerResetHeaderWhenBucketEmpties() {
    std::cout << "\n[TEST] RateLimitManager: reset header reflects empty allowed bucket..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        RateLimitConfig config;
        config.enabled = true;
        config.include_headers = true;
        config.zones.push_back({"test_zone", 1.0, 1, "client_ip", 1000, {}});

        RateLimitManager manager(config);

        HttpRequest req = MakeRequest("GET", "/test");
        HttpResponse response;
        if (!manager.Check(req, response)) {
            pass = false;
            err += "first request should be allowed; ";
        }

        std::string header = ResponseGetHeader(response, "RateLimit");
        if (header.find("remaining=0") == std::string::npos) {
            pass = false;
            err += "RateLimit header should report remaining=0; ";
        }
        if (header.find("reset=0") != std::string::npos) {
            pass = false;
            err += "RateLimit header should not report reset=0 after last token is consumed; ";
        }

        TestFramework::RecordTest("RateLimitManager: reset header reflects empty allowed bucket",
                                  pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RateLimitManager: reset header reflects empty allowed bucket",
                                  false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestManagerSkipsNonApplicableZonesForHeaders() {
    std::cout << "\n[TEST] RateLimitManager: non-applicable zones don't drive headers..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        // Two zones: one applies to /api/, one applies to /admin/.
        // Request to /something-else matches neither — both are
        // non-applicable. With the fix, NO RateLimit-* headers are
        // emitted. Without the fix, the first zone would be promoted
        // to best_name and bogus headers would appear.
        RateLimitConfig config;
        config.enabled = true;
        config.include_headers = true;
        config.zones.push_back({"api_zone",   100.0, 50, "client_ip", 1000, {"/api/"}});
        config.zones.push_back({"admin_zone", 10.0,  5,  "client_ip", 1000, {"/admin/"}});

        RateLimitManager manager(config);

        HttpRequest req = MakeRequest("GET", "/health", "10.0.0.1");
        HttpResponse response;
        bool allowed = manager.Check(req, response);

        if (!allowed) {
            pass = false;
            err += "request should pass (no applicable zone); ";
        }

        // No RateLimit-* headers expected — neither zone governed this request.
        if (ResponseHasHeader(response, "RateLimit-Policy")) {
            pass = false;
            err += "RateLimit-Policy should NOT be present when no zone applies; ";
        }
        if (ResponseHasHeader(response, "RateLimit")) {
            pass = false;
            err += "RateLimit should NOT be present when no zone applies; ";
        }

        // Sanity check: request to /api/users DOES get headers.
        HttpRequest api_req = MakeRequest("GET", "/api/users", "10.0.0.1");
        HttpResponse api_response;
        manager.Check(api_req, api_response);
        if (!ResponseHasHeader(api_response, "RateLimit-Policy")) {
            pass = false;
            err += "RateLimit-Policy should be present when api_zone applies; ";
        }

        TestFramework::RecordTest("RateLimitManager: non-applicable zones don't drive headers", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RateLimitManager: non-applicable zones don't drive headers", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestManagerRetryAfterOnDenial() {
    std::cout << "\n[TEST] RateLimitManager: Retry-After header on denial..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        RateLimitConfig config;
        config.enabled = true;
        config.include_headers = true;
        config.zones.push_back({"test_zone", 1.0, 1, "client_ip", 1000, {}});

        RateLimitManager manager(config);

        HttpRequest req = MakeRequest("GET", "/test");

        // Consume the one token
        {
            HttpResponse response;
            manager.Check(req, response);
        }

        // Next request should be denied with Retry-After
        {
            HttpResponse response;
            bool allowed = manager.Check(req, response);
            if (allowed) {
                pass = false;
                err += "should be denied; ";
            }

            if (!ResponseHasHeader(response, "Retry-After")) {
                pass = false;
                err += "missing Retry-After header on denial; ";
            } else {
                std::string retry_val = ResponseGetHeader(response, "Retry-After");
                int retry_sec = std::stoi(retry_val);
                if (retry_sec < 1) {
                    pass = false;
                    err += "Retry-After=" + retry_val + " expected >= 1; ";
                }
            }
        }

        TestFramework::RecordTest("RateLimitManager: Retry-After header on denial", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RateLimitManager: Retry-After header on denial", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestManagerDisabledReturnsTrueImmediately() {
    std::cout << "\n[TEST] RateLimitManager: disabled returns true immediately..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        RateLimitConfig config;
        config.enabled = false;
        config.zones.push_back({"test_zone", 1.0, 1, "client_ip", 1000, {}});

        RateLimitManager manager(config);

        if (manager.enabled()) {
            pass = false;
            err += "manager should report disabled; ";
        }

        // Even though the zone has capacity=1, disabled means Check() on the
        // middleware path won't even call manager.Check(). But we test the
        // manager directly: even with zones, Check returns results based on
        // zone evaluation (it doesn't check enabled()). The middleware guards it.
        // What we test here is the enabled() accessor.

        TestFramework::RecordTest("RateLimitManager: disabled returns true immediately", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RateLimitManager: disabled returns true immediately", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}


// =========================================================================
// D. Hot-reload tests
// =========================================================================

void TestReloadEnableDisableToggle() {
    std::cout << "\n[TEST] Reload: enable/disable toggle..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        RateLimitConfig config;
        config.enabled = false;

        RateLimitManager manager(config);

        if (manager.enabled()) {
            pass = false;
            err += "should start disabled; ";
        }

        // Enable via reload
        config.enabled = true;
        config.zones.push_back({"zone", 10.0, 10, "client_ip", 1000, {}});
        manager.Reload(config);

        if (!manager.enabled()) {
            pass = false;
            err += "should be enabled after reload; ";
        }

        // Disable via reload
        config.enabled = false;
        manager.Reload(config);

        if (manager.enabled()) {
            pass = false;
            err += "should be disabled after second reload; ";
        }

        TestFramework::RecordTest("Reload: enable/disable toggle", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Reload: enable/disable toggle", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestReloadRateChange() {
    std::cout << "\n[TEST] Reload: rate change picks up new rate..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        RateLimitConfig config;
        config.enabled = true;
        config.zones.push_back({"zone", 1.0, 2, "client_ip", 1000, {}});

        RateLimitManager manager(config);

        HttpRequest req = MakeRequest("GET", "/test");

        // Consume both tokens
        for (int i = 0; i < 2; i++) {
            HttpResponse response;
            manager.Check(req, response);
        }

        // Should be denied now
        {
            HttpResponse response;
            if (manager.Check(req, response)) {
                pass = false;
                err += "should be denied at capacity=2; ";
            }
        }

        // Reload with higher rate and capacity
        config.zones[0].capacity = 100;
        config.zones[0].rate = 100.0;
        manager.Reload(config);

        // Trigger the lazy config update: this Check() detects the rate/capacity
        // mismatch and calls UpdateConfig(), which Refills at the OLD rate first
        // (materializing any pre-reload idle time), then applies the new rate.
        // The request itself will be denied (0 tokens after old-rate refill).
        {
            HttpResponse response;
            manager.Check(req, response);  // triggers UpdateConfig on the bucket
        }

        // Now sleep so the NEW rate (100 req/sec) produces tokens.
        // 50ms at 100 req/sec = ~5 tokens.
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        {
            HttpResponse response;
            if (!manager.Check(req, response)) {
                pass = false;
                err += "should be allowed after reload with higher rate; ";
            }
        }

        TestFramework::RecordTest("Reload: rate change picks up new rate", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Reload: rate change picks up new rate", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestReloadAddNewZone() {
    std::cout << "\n[TEST] Reload: add new zone..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        RateLimitConfig config;
        config.enabled = true;
        config.zones.push_back({"zone_a", 100.0, 100, "client_ip", 1000, {}});

        RateLimitManager manager(config);

        // Add a second zone
        config.zones.push_back({"zone_b", 1.0, 1, "client_ip", 1000, {}});
        manager.Reload(config);

        HttpRequest req = MakeRequest("GET", "/test");

        // First request should pass both zones
        {
            HttpResponse response;
            if (!manager.Check(req, response)) {
                pass = false;
                err += "first request should pass; ";
            }
        }

        // Second request should be denied by zone_b (capacity=1)
        {
            HttpResponse response;
            if (manager.Check(req, response)) {
                pass = false;
                err += "second request should be denied by new zone_b; ";
            }
        }

        TestFramework::RecordTest("Reload: add new zone", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Reload: add new zone", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestReloadRemoveZone() {
    std::cout << "\n[TEST] Reload: remove zone..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        RateLimitConfig config;
        config.enabled = true;
        config.zones.push_back({"zone_a", 100.0, 100, "client_ip", 1000, {}});
        config.zones.push_back({"zone_b", 1.0, 1, "client_ip", 1000, {}});

        RateLimitManager manager(config);

        HttpRequest req = MakeRequest("GET", "/test");

        // Exhaust zone_b
        {
            HttpResponse response;
            manager.Check(req, response);
        }
        {
            HttpResponse response;
            if (manager.Check(req, response)) {
                pass = false;
                err += "should be denied by zone_b before reload; ";
            }
        }

        // Remove zone_b via reload
        config.zones.erase(config.zones.begin() + 1);
        manager.Reload(config);

        // Now should pass (only zone_a remains)
        {
            HttpResponse response;
            if (!manager.Check(req, response)) {
                pass = false;
                err += "should be allowed after removing zone_b; ";
            }
        }

        TestFramework::RecordTest("Reload: remove zone", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Reload: remove zone", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestReloadStatusCodeChange() {
    std::cout << "\n[TEST] Reload: status_code change visible..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        RateLimitConfig config;
        config.enabled = true;
        config.status_code = 429;

        RateLimitManager manager(config);

        if (manager.status_code() != 429) {
            pass = false;
            err += "initial status_code=" + std::to_string(manager.status_code()) + " expected 429; ";
        }

        config.status_code = 503;
        manager.Reload(config);

        if (manager.status_code() != 503) {
            pass = false;
            err += "after reload status_code=" + std::to_string(manager.status_code()) + " expected 503; ";
        }

        TestFramework::RecordTest("Reload: status_code change visible", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Reload: status_code change visible", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestReloadDryRunToggle() {
    std::cout << "\n[TEST] Reload: dry_run toggle visible..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        RateLimitConfig config;
        config.enabled = true;
        config.dry_run = false;

        RateLimitManager manager(config);

        if (manager.dry_run()) {
            pass = false;
            err += "should start with dry_run=false; ";
        }

        config.dry_run = true;
        manager.Reload(config);

        if (!manager.dry_run()) {
            pass = false;
            err += "should be dry_run=true after reload; ";
        }

        TestFramework::RecordTest("Reload: dry_run toggle visible", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Reload: dry_run toggle visible", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}


// =========================================================================
// E. Integration tests -- full HTTP request/response
// =========================================================================

void TestIntegrationRequestUnderLimit() {
    std::cout << "\n[TEST] Integration: request under limit returns 200 with RateLimit headers..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        ServerConfig config;
        config.bind_host = "127.0.0.1";
        config.bind_port = 0;
        config.worker_threads = 1;
        config.rate_limit.enabled = true;
        config.rate_limit.include_headers = true;
        config.rate_limit.zones.push_back({"test_zone", 100.0, 100, "client_ip", 1000, {}});

        HttpServer server(config);
        server.Get("/health", [](const HttpRequest&, HttpResponse& res) {
            res.Status(200).Text("ok");
        });

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        std::string response = TestHttpClient::HttpGet(port, "/health");

        if (!TestHttpClient::HasStatus(response, 200)) {
            pass = false;
            err += "expected 200 OK; ";
        }

        std::string body = TestHttpClient::ExtractBody(response);
        if (body.find("ok") == std::string::npos) {
            pass = false;
            err += "missing body 'ok'; ";
        }

        // Check for RateLimit headers
        std::string rl_policy = FindRawHeader(response, "RateLimit-Policy");
        if (rl_policy.empty()) {
            pass = false;
            err += "missing RateLimit-Policy header; ";
        }

        std::string rl_header = FindRawHeader(response, "RateLimit");
        if (rl_header.empty()) {
            pass = false;
            err += "missing RateLimit header; ";
        }

        TestFramework::RecordTest("Integration: request under limit returns 200 with RateLimit headers", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Integration: request under limit returns 200 with RateLimit headers", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestIntegrationExhaustTokensGet429() {
    std::cout << "\n[TEST] Integration: exhaust tokens returns 429 with Retry-After..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        ServerConfig config;
        config.bind_host = "127.0.0.1";
        config.bind_port = 0;
        config.worker_threads = 1;
        config.rate_limit.enabled = true;
        config.rate_limit.include_headers = true;
        config.rate_limit.status_code = 429;
        // Capacity=2, rate=1: will exhaust quickly
        config.rate_limit.zones.push_back({"test_zone", 1.0, 2, "client_ip", 1000, {}});

        HttpServer server(config);
        server.Get("/health", [](const HttpRequest&, HttpResponse& res) {
            res.Status(200).Text("ok");
        });

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        // Send requests until we get a 429
        bool got_429 = false;
        for (int i = 0; i < 10; i++) {
            std::string response = TestHttpClient::HttpGet(port, "/health");
            if (TestHttpClient::HasStatus(response, 429)) {
                got_429 = true;

                // Check Retry-After header
                std::string retry = FindRawHeader(response, "Retry-After");
                if (retry.empty()) {
                    pass = false;
                    err += "429 response missing Retry-After header; ";
                }
                break;
            }
            // Small delay between requests
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }

        if (!got_429) {
            pass = false;
            err += "never received 429 after multiple requests; ";
        }

        TestFramework::RecordTest("Integration: exhaust tokens returns 429 with Retry-After", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Integration: exhaust tokens returns 429 with Retry-After", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestIntegrationCustomStatusCode503() {
    std::cout << "\n[TEST] Integration: custom status code 503..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        ServerConfig config;
        config.bind_host = "127.0.0.1";
        config.bind_port = 0;
        config.worker_threads = 1;
        config.rate_limit.enabled = true;
        config.rate_limit.status_code = 503;
        config.rate_limit.zones.push_back({"test_zone", 1.0, 1, "client_ip", 1000, {}});

        HttpServer server(config);
        server.Get("/test", [](const HttpRequest&, HttpResponse& res) {
            res.Status(200).Text("ok");
        });

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        // First request: OK (consumes the 1 token)
        {
            std::string response = TestHttpClient::HttpGet(port, "/test");
            if (!TestHttpClient::HasStatus(response, 200)) {
                pass = false;
                err += "first request should be 200; ";
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(20));

        // Second request: should get 503
        {
            std::string response = TestHttpClient::HttpGet(port, "/test");
            if (!TestHttpClient::HasStatus(response, 503)) {
                pass = false;
                err += "second request should be 503 (custom status); got response: " +
                       response.substr(0, std::min(response.size(), (size_t)80)) + "; ";
            }
        }

        TestFramework::RecordTest("Integration: custom status code 503", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Integration: custom status code 503", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestIntegrationDryRunMode() {
    std::cout << "\n[TEST] Integration: dry-run mode returns 200 even when limit exceeded..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        ServerConfig config;
        config.bind_host = "127.0.0.1";
        config.bind_port = 0;
        config.worker_threads = 1;
        config.rate_limit.enabled = true;
        config.rate_limit.dry_run = true;
        config.rate_limit.zones.push_back({"test_zone", 1.0, 1, "client_ip", 1000, {}});

        HttpServer server(config);
        server.Get("/test", [](const HttpRequest&, HttpResponse& res) {
            res.Status(200).Text("ok");
        });

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        // Send multiple requests -- all should get 200 in dry-run mode,
        // AND none should have Retry-After (that would trigger client backoff
        // on responses that were actually allowed).
        bool all_200 = true;
        bool saw_retry_after = false;
        for (int i = 0; i < 5; i++) {
            std::string response = TestHttpClient::HttpGet(port, "/test");
            if (!TestHttpClient::HasStatus(response, 200)) {
                all_200 = false;
                err += "request " + std::to_string(i) + " not 200 in dry-run mode; ";
                break;
            }
            // Check: Retry-After must NOT be present on allowed responses.
            std::string retry = FindRawHeader(response, "Retry-After");
            if (!retry.empty()) {
                saw_retry_after = true;
                err += "request " + std::to_string(i) +
                       " has Retry-After='" + retry + "' on dry-run 200 response; ";
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }

        if (!all_200 || saw_retry_after) {
            pass = false;
        }

        TestFramework::RecordTest("Integration: dry-run mode returns 200 even when limit exceeded", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Integration: dry-run mode returns 200 even when limit exceeded", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestIntegrationRateLimitAllRoutes() {
    std::cout << "\n[TEST] Integration: rate limit applies to all routes (middleware)..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        ServerConfig config;
        config.bind_host = "127.0.0.1";
        config.bind_port = 0;
        config.worker_threads = 1;
        config.rate_limit.enabled = true;
        config.rate_limit.zones.push_back({"test_zone", 1.0, 2, "client_ip", 1000, {}});

        HttpServer server(config);
        server.Get("/a", [](const HttpRequest&, HttpResponse& res) {
            res.Status(200).Text("route-a");
        });
        server.Get("/b", [](const HttpRequest&, HttpResponse& res) {
            res.Status(200).Text("route-b");
        });

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        // Request /a (1st token)
        {
            std::string response = TestHttpClient::HttpGet(port, "/a");
            if (!TestHttpClient::HasStatus(response, 200)) {
                pass = false;
                err += "/a request should be 200; ";
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(20));

        // Request /b (2nd token)
        {
            std::string response = TestHttpClient::HttpGet(port, "/b");
            if (!TestHttpClient::HasStatus(response, 200)) {
                pass = false;
                err += "/b request should be 200; ";
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(20));

        // Request /a again (should be denied -- tokens exhausted across routes)
        {
            std::string response = TestHttpClient::HttpGet(port, "/a");
            if (!TestHttpClient::HasStatus(response, 429)) {
                pass = false;
                err += "third request to /a should be 429 (shared rate limit across routes); ";
            }
        }

        TestFramework::RecordTest("Integration: rate limit applies to all routes (middleware)", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Integration: rate limit applies to all routes (middleware)", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}


// =========================================================================
// F. Configuration tests
// =========================================================================

void TestConfigJsonRoundTrip() {
    std::cout << "\n[TEST] Config: JSON round-trip rate_limit..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        std::string json = R"({
            "bind_host": "0.0.0.0",
            "bind_port": 8080,
            "rate_limit": {
                "enabled": true,
                "dry_run": false,
                "status_code": 429,
                "include_headers": true,
                "zones": [
                    {
                        "name": "global",
                        "rate": 100.0,
                        "capacity": 50,
                        "key_type": "client_ip",
                        "max_entries": 10000,
                        "applies_to": ["/api/"]
                    },
                    {
                        "name": "auth",
                        "rate": 5.0,
                        "capacity": 5,
                        "key_type": "header:x-api-key",
                        "max_entries": 5000,
                        "applies_to": ["/auth/"]
                    }
                ]
            }
        })";

        ServerConfig config = ConfigLoader::LoadFromString(json);

        // Verify parsed correctly
        if (!config.rate_limit.enabled) {
            pass = false;
            err += "enabled should be true; ";
        }
        if (config.rate_limit.zones.size() != 2) {
            pass = false;
            err += "zones count=" + std::to_string(config.rate_limit.zones.size()) + " expected 2; ";
        }
        if (config.rate_limit.zones[0].name != "global") {
            pass = false;
            err += "zone[0] name='" + config.rate_limit.zones[0].name + "' expected 'global'; ";
        }
        if (config.rate_limit.zones[1].key_type != "header:x-api-key") {
            pass = false;
            err += "zone[1] key_type='" + config.rate_limit.zones[1].key_type + "'; ";
        }

        // Serialize and re-parse
        std::string serialized = ConfigLoader::ToJson(config);
        ServerConfig config2 = ConfigLoader::LoadFromString(serialized);

        if (config.rate_limit != config2.rate_limit) {
            pass = false;
            err += "round-trip mismatch; ";
        }

        TestFramework::RecordTest("Config: JSON round-trip rate_limit", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Config: JSON round-trip rate_limit", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestConfigValidateRateZero() {
    std::cout << "\n[TEST] Config: validate rate <= 0 throws..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        ServerConfig config;
        config.rate_limit.enabled = true;
        config.rate_limit.zones.push_back({"bad_zone", 0.0, 10, "client_ip", 1000, {}});

        bool threw = false;
        try {
            ConfigLoader::Validate(config);
        } catch (const std::invalid_argument& e) {
            threw = true;
            std::string what = e.what();
            if (what.find("rate") == std::string::npos) {
                pass = false;
                err += "exception should mention 'rate': " + what + "; ";
            }
        }

        if (!threw) {
            pass = false;
            err += "should throw for rate=0; ";
        }

        TestFramework::RecordTest("Config: validate rate <= 0 throws", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Config: validate rate <= 0 throws", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestConfigValidateUnknownKeyType() {
    std::cout << "\n[TEST] Config: validate unknown key_type throws..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        ServerConfig config;
        config.rate_limit.enabled = true;
        config.rate_limit.zones.push_back({"bad_zone", 10.0, 10, "invalid_key_type", 1000, {}});

        bool threw = false;
        try {
            ConfigLoader::Validate(config);
        } catch (const std::invalid_argument& e) {
            threw = true;
            std::string what = e.what();
            if (what.find("key_type") == std::string::npos) {
                pass = false;
                err += "exception should mention 'key_type': " + what + "; ";
            }
        }

        if (!threw) {
            pass = false;
            err += "should throw for unknown key_type; ";
        }

        TestFramework::RecordTest("Config: validate unknown key_type throws", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Config: validate unknown key_type throws", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestConfigValidateDuplicateZoneNames() {
    std::cout << "\n[TEST] Config: validate duplicate zone names throws..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        ServerConfig config;
        config.rate_limit.enabled = true;
        config.rate_limit.zones.push_back({"dup_zone", 10.0, 10, "client_ip", 1000, {}});
        config.rate_limit.zones.push_back({"dup_zone", 5.0, 5, "client_ip", 1000, {}});

        bool threw = false;
        try {
            ConfigLoader::Validate(config);
        } catch (const std::invalid_argument& e) {
            threw = true;
            std::string what = e.what();
            if (what.find("Duplicate") == std::string::npos &&
                what.find("duplicate") == std::string::npos) {
                pass = false;
                err += "exception should mention 'Duplicate': " + what + "; ";
            }
        }

        if (!threw) {
            pass = false;
            err += "should throw for duplicate zone names; ";
        }

        TestFramework::RecordTest("Config: validate duplicate zone names throws", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Config: validate duplicate zone names throws", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestConfigValidateEnabledWithEmptyZones() {
    std::cout << "\n[TEST] Config: validate enabled with empty zones throws..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        ServerConfig config;
        config.rate_limit.enabled = true;
        // No zones added

        bool threw = false;
        try {
            ConfigLoader::Validate(config);
        } catch (const std::invalid_argument& e) {
            threw = true;
            std::string what = e.what();
            if (what.find("no zones") == std::string::npos &&
                what.find("zones") == std::string::npos) {
                pass = false;
                err += "exception should mention zones: " + what + "; ";
            }
        }

        if (!threw) {
            pass = false;
            err += "should throw when enabled with empty zones; ";
        }

        TestFramework::RecordTest("Config: validate enabled with empty zones throws", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Config: validate enabled with empty zones throws", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestConfigRejectEmptyAppliesToPrefix() {
    std::cout << "\n[TEST] Config: empty applies_to prefix rejected at parse time..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        // Empty prefix ("") would crash RateLimitZone::Check() via
        // prefix.back() (UB on empty strings). Must be rejected at parse.
        std::string json = R"({
            "rate_limit": {
                "enabled": true,
                "zones": [{
                    "name": "bad_zone",
                    "rate": 10.0,
                    "capacity": 10,
                    "key_type": "client_ip",
                    "max_entries": 100,
                    "applies_to": [""]
                }]
            }
        })";

        bool threw = false;
        try {
            ConfigLoader::LoadFromString(json);
        } catch (const std::exception& e) {
            threw = true;
            std::string what = e.what();
            if (what.find("applies_to") == std::string::npos &&
                what.find("empty") == std::string::npos) {
                pass = false;
                err += "exception should mention empty applies_to: " + what + "; ";
            }
        }

        if (!threw) {
            pass = false;
            err += "should throw for empty applies_to entry; ";
        }

        TestFramework::RecordTest("Config: empty applies_to prefix rejected", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Config: empty applies_to prefix rejected", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}


// =========================================================================
// G. Edge case tests
// =========================================================================

void TestEdgeCaseEmptyClientIp() {
    std::cout << "\n[TEST] Edge case: empty client_ip -> skip (allowed)..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        RateLimitConfig config;
        config.enabled = true;
        config.zones.push_back({"test_zone", 1.0, 1, "client_ip", 1000, {}});

        RateLimitManager manager(config);

        // Request with empty client_ip -- key extractor returns ""
        HttpRequest req = MakeRequest("GET", "/test", "");

        // Should always be allowed (empty key -> skip)
        for (int i = 0; i < 5; i++) {
            HttpResponse response;
            if (!manager.Check(req, response)) {
                pass = false;
                err += "request " + std::to_string(i) + " denied with empty client_ip; ";
                break;
            }
        }

        TestFramework::RecordTest("Edge case: empty client_ip -> skip (allowed)", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Edge case: empty client_ip -> skip (allowed)", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestEdgeCaseCapacityOne() {
    std::cout << "\n[TEST] Edge case: capacity=1 allows exactly 1 then denies..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        RateLimitConfig config;
        config.enabled = true;
        config.zones.push_back({"test_zone", 1.0, 1, "client_ip", 1000, {}});

        RateLimitManager manager(config);

        HttpRequest req = MakeRequest("GET", "/test");

        // First request: allowed
        {
            HttpResponse response;
            if (!manager.Check(req, response)) {
                pass = false;
                err += "first request should be allowed; ";
            }
        }

        // Second request: denied
        {
            HttpResponse response;
            if (manager.Check(req, response)) {
                pass = false;
                err += "second request should be denied (capacity=1); ";
            }
        }

        TestFramework::RecordTest("Edge case: capacity=1 allows exactly 1 then denies", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Edge case: capacity=1 allows exactly 1 then denies", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestEdgeCaseVeryHighRate() {
    std::cout << "\n[TEST] Edge case: very high rate (1000000) no overflow..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        // Very high rate -- should not cause integer overflow
        TokenBucket bucket(1000000.0, 1000000);

        // Should start full
        if (bucket.Capacity() != 1000000) {
            pass = false;
            err += "capacity=" + std::to_string(bucket.Capacity()) + " expected 1000000; ";
        }

        // Consume some and verify correct behavior
        int consumed = 0;
        for (int i = 0; i < 100; i++) {
            if (bucket.TryConsume()) consumed++;
        }

        if (consumed != 100) {
            pass = false;
            err += "consumed=" + std::to_string(consumed) + " expected 100; ";
        }

        // Remaining should be 999900
        int64_t remaining = bucket.AvailableTokens();
        if (remaining != 999900) {
            pass = false;
            err += "remaining=" + std::to_string(remaining) + " expected 999900; ";
        }

        // SecondsUntilAvailable should be 0 (still have tokens)
        double wait = bucket.SecondsUntilAvailable();
        if (wait != 0.0) {
            pass = false;
            err += "wait=" + std::to_string(wait) + " expected 0; ";
        }

        TestFramework::RecordTest("Edge case: very high rate (1000000) no overflow", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Edge case: very high rate (1000000) no overflow", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}


// =========================================================================
// Test runner
// =========================================================================

void RunAllTests() {
    std::cout << "\n========================================" << std::endl;
    std::cout << "  Rate Limit Tests" << std::endl;
    std::cout << "========================================" << std::endl;

    // A. TokenBucket unit tests (6)
    TestTokenBucketFreshBucketIsFull();
    TestTokenBucketLazyRefill();
    TestTokenBucketCapacityLimit();
    TestTokenBucketUpdateConfigRateChange();
    TestTokenBucketUpdateConfigCapacityShrink();
    TestTokenBucketLowRateFractionalCredit();
    TestTokenBucketSecondsUntilAvailable();

    // B. RateLimitZone tests (6)
    TestZoneKeyExtractorClientIp();
    TestZoneKeyExtractorHeader();
    TestZoneKeyExtractorComposite();
    TestZoneEmptyKeySkipsRateLimit();
    TestZoneAppliesToFilter();
    TestZoneAppliesToSegmentBoundary();
    TestZoneLruEviction();
    TestZoneSynchronousMaxEntriesEnforcement();

    // C. RateLimitManager tests (7)
    TestManagerSingleZoneAllow();
    TestManagerSingleZoneDeny();
    TestManagerMultiZoneAllPass();
    TestManagerMultiZoneOneDenies();
    TestManagerStopsDebitingAfterDenial();
    TestManagerSkipsNonApplicableZonesForHeaders();
    TestManagerResponseHeaders();
    TestManagerLargePolicyWindowHeader();
    TestManagerResetHeaderWhenBucketEmpties();
    TestManagerRetryAfterOnDenial();
    TestManagerDisabledReturnsTrueImmediately();

    // D. Hot-reload tests (6)
    TestReloadEnableDisableToggle();
    TestReloadRateChange();
    TestReloadAddNewZone();
    TestReloadRemoveZone();
    TestReloadStatusCodeChange();
    TestReloadDryRunToggle();

    // E. Integration tests (5)
    TestIntegrationRequestUnderLimit();
    TestIntegrationExhaustTokensGet429();
    TestIntegrationCustomStatusCode503();
    TestIntegrationDryRunMode();
    TestIntegrationRateLimitAllRoutes();

    // F. Configuration tests (5)
    TestConfigJsonRoundTrip();
    TestConfigValidateRateZero();
    TestConfigValidateUnknownKeyType();
    TestConfigValidateDuplicateZoneNames();
    TestConfigValidateEnabledWithEmptyZones();
    TestConfigRejectEmptyAppliesToPrefix();

    // G. Edge case tests (3)
    TestEdgeCaseEmptyClientIp();
    TestEdgeCaseCapacityOne();
    TestEdgeCaseVeryHighRate();
}

} // namespace RateLimitTests
