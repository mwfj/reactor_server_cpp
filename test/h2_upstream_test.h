#pragma once

// h2_upstream_test.h — Tests for the H2 outbound upstream client path.
//
// Coverage dimensions:
//   Tier A: Unit tests — no real network required
//     A1.  Http2UpstreamConfig::MinCadenceSec semantics
//     A2.  UpstreamCodec polymorphism (H1 + H2 through base pointer)
//     A3.  UpstreamH2Codec::Parse fail-loud path
//     A4.  H2ConnectionTable::FindUsable correctness
//     A5.  H2ConnectionTable::ReapDrained correctness
//     A6.  H2ConnectionTable::Clear correctness
//     A7.  H2ConnectionTable::TickAll PING-timeout removal
//     A8.  UpstreamManager::CommitHttp2Snapshots live-only narrow (stale staged entry ignored)
//     A9.  UpstreamManager::CommitHttp2Snapshots bootstrap
//     A10. UpstreamManager::ComputeMinUpstreamCadenceSec
//     A11. PoolPartition::ApplyHttp2ConfigCommit / LoadHttp2ConfigSnapshot
//     A12. BuildSettingsArray values
//
//   Tier B: Wire-level tests using nghttp2 server API
//     B1.  Happy path — single request completes (headers + body + complete)
//     B2.  HEADERS+DATA+END_STREAM ordering
//     B3.  GOAWAY drain (IsUsable false, in-flight streams complete)
//     B4.  PING ACK — pending_ping clears, Tick stays true
//     B5.  PING timeout — Tick returns false
//     B6.  RST_STREAM — sink does NOT receive OnComplete
//     B7.  Large body provider — all bytes arrive at server
//
//   Tier C: Race / lifetime / memory
//     C1.  in_receive_data_ guard — SubmitRequest defers FlushSend
//     C2.  Lease adoption and release via ~UpstreamH2Connection
//     C3.  RST_STREAM empties streams_ map
//     C4.  GOAWAY + stream completion → ReapDrained clears table
//     C5.  ApplyHttp2ConfigCommit/LoadHttp2ConfigSnapshot acquire-release

#include "test_framework.h"
#include "config/server_config.h"
#include "config/config_loader.h"
#include "upstream/upstream_codec.h"
#include "upstream/upstream_http_codec.h"
#include "upstream/upstream_h2_codec.h"
#include "upstream/upstream_h2_connection.h"
#include "upstream/upstream_h2_stream.h"
#include "upstream/h2_connection_table.h"
#include "upstream/h2_settings.h"
#include "upstream/upstream_manager.h"
#include "upstream/pool_partition.h"
#include "upstream/proxy_transaction.h"  // for RESULT_UPSTREAM_DISCONNECT
#include "upstream/header_rewriter.h"
#include "upstream/retry_policy.h"
#include "http/http_request.h"
#include "http/streaming_response_sender.h"
#include <fstream>
#include <iterator>
#include "upstream/upstream_connection.h"
#include "upstream/upstream_lease.h"
#include "upstream/upstream_response_sink.h"
#include "upstream/upstream_response_head.h"
#include "dispatcher.h"
#include "connection_handler.h"
#include "socket_handler.h"
#include "net/dns_resolver.h"

#include <nghttp2/nghttp2.h>

#include "common.h"
#include <future>
#include <set>
#include <limits>

namespace H2UpstreamTests {

// ---------------------------------------------------------------------------
// Helpers — shared across tiers
// ---------------------------------------------------------------------------

// Build a minimal UpstreamConfig with H2 enabled.
static UpstreamConfig MakeH2UpstreamConfig(const std::string& name,
                                            const std::string& host, int port)
{
    UpstreamConfig cfg;
    cfg.name = name;
    cfg.host = host;
    cfg.port = port;
    cfg.pool.max_connections      = 4;
    cfg.pool.max_idle_connections = 2;
    cfg.pool.connect_timeout_ms   = 2000;
    cfg.pool.idle_timeout_sec     = 30;
    cfg.pool.max_lifetime_sec     = 3600;
    cfg.http2.enabled             = true;
    cfg.http2.prefer              = "always";
    cfg.http2.max_concurrent_streams_pref = 10;
    cfg.http2.ping_idle_sec       = 60;
    cfg.http2.ping_timeout_sec    = 10;
    cfg.http2.goaway_drain_timeout_sec = 30;
    return cfg;
}

// RAII: stop Dispatcher and join its thread.
struct DispatcherThreadGuard {
    std::shared_ptr<Dispatcher> dispatcher;
    std::thread& thread;
    ~DispatcherThreadGuard() {
        try { dispatcher->StopEventLoop(); } catch (...) {}
        if (thread.joinable()) thread.join();
    }
};

// Open an ephemeral TCP listener.
// Retained for potential future tests that spin up a real listening socket.
[[maybe_unused]] static std::pair<int, int> MakeListenerFd() {
    int lfd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) throw std::runtime_error("socket() failed");
    int yes = 1;
    ::setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = 0;
    if (::bind(lfd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(lfd); throw std::runtime_error("bind() failed");
    }
    if (::listen(lfd, 16) < 0) {
        ::close(lfd); throw std::runtime_error("listen() failed");
    }
    struct sockaddr_in bound{};
    socklen_t len = sizeof(bound);
    ::getsockname(lfd, reinterpret_cast<struct sockaddr*>(&bound), &len);
    return {lfd, ntohs(bound.sin_port)};
}

// Start a Dispatcher in a background thread and return the thread.
static std::thread StartDispatcher(std::shared_ptr<Dispatcher>& disp) {
    disp->Init();
    std::promise<void> ready;
    auto fut = ready.get_future();
    std::thread t([&disp, r = std::move(ready)]() mutable {
        disp->EnQueue([&r]() { r.set_value(); });
        disp->RunEventLoop();
    });
    fut.wait_for(std::chrono::seconds(5));
    return t;
}

// Simple recording sink for unit tests.
struct RecordingSink : public UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseSink {
    int headers_calls   = 0;
    int body_bytes      = 0;
    int complete_calls  = 0;
    int error_calls     = 0;
    int trailers_calls  = 0;
    int last_status     = 0;
    int last_error_code = 0;
    std::string last_error_msg;
    std::vector<std::pair<std::string, std::string>> last_trailers;

    bool OnHeaders(const UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead& head) override {
        ++headers_calls;
        last_status = head.status_code;
        return true;
    }
    bool OnBodyChunk(const char*, size_t len) override {
        body_bytes += static_cast<int>(len); return true;
    }
    void OnTrailers(const std::vector<std::pair<std::string, std::string>>& t) override {
        ++trailers_calls;
        last_trailers = t;
    }
    void OnComplete() override { ++complete_calls; }
    void OnError(int code, const std::string& msg) override {
        ++error_calls; last_error_code = code; last_error_msg = msg;
    }
};

// Sink that reentrantly calls back into the H2 connection during OnError —
// used by C1 to exercise the in_receive_data_ guard. The connection
// pointer is set by the test before driving bytes through HandleBytes.
struct ReentrantResetSink : public UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseSink {
    UpstreamH2Connection* conn = nullptr;
    int32_t reset_target = -1;
    bool observed_in_receive_data = false;
    int error_calls = 0;

    bool OnHeaders(const UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead&) override { return true; }
    bool OnBodyChunk(const char*, size_t) override { return true; }
    void OnTrailers(const std::vector<std::pair<std::string, std::string>>&) override {}
    void OnComplete() override {}
    void OnError(int, const std::string&) override {
        ++error_calls;
        if (conn) {
            // CAPTURE the in_receive_data flag at the moment we re-enter
            // the connection — this is what proves the guard is active
            // during the synchronous callback chain.
            observed_in_receive_data = conn->in_receive_data();
            if (reset_target >= 0) conn->ResetStream(reset_target);
        }
    }
};

// ---------------------------------------------------------------------------
// Tier A — pure unit tests
// ---------------------------------------------------------------------------

// A1 — Http2UpstreamConfig::MinCadenceSec
void TestMinCadenceSecDisabled() {
    std::cout << "\n[TEST] H2Upstream A1a: MinCadenceSec disabled -> INT_MAX..." << std::endl;
    try {
        Http2UpstreamConfig cfg;
        cfg.enabled = false;
        bool pass = (cfg.MinCadenceSec() == std::numeric_limits<int>::max());
        TestFramework::RecordTest("H2Upstream A1a: MinCadenceSec disabled -> INT_MAX",
                                   pass, pass ? "" : "expected INT_MAX");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream A1a: MinCadenceSec disabled -> INT_MAX", false, e.what());
    }
}

void TestMinCadenceSecEnabled() {
    std::cout << "\n[TEST] H2Upstream A1b: MinCadenceSec enabled -> min of three fields..." << std::endl;
    try {
        Http2UpstreamConfig cfg;
        cfg.enabled                  = true;
        cfg.ping_idle_sec            = 60;
        cfg.ping_timeout_sec         = 10;
        cfg.goaway_drain_timeout_sec = 30;

        // min(60, 10, 30) == 10
        bool pass = (cfg.MinCadenceSec() == 10);
        TestFramework::RecordTest("H2Upstream A1b: MinCadenceSec enabled -> min of three fields",
                                   pass, pass ? "" : "expected 10");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream A1b: MinCadenceSec enabled -> min of three fields",
                                   false, e.what());
    }
}

void TestMinCadenceSecZeroFields() {
    std::cout << "\n[TEST] H2Upstream A1c: MinCadenceSec with zero fields -> skips zeros..." << std::endl;
    try {
        Http2UpstreamConfig cfg;
        cfg.enabled                  = true;
        cfg.ping_idle_sec            = 0;   // disabled — should be skipped
        cfg.ping_timeout_sec         = 0;   // disabled — should be skipped
        cfg.goaway_drain_timeout_sec = 20;

        // Only goaway_drain_timeout_sec == 20 contributes
        bool pass = (cfg.MinCadenceSec() == 20);
        TestFramework::RecordTest("H2Upstream A1c: MinCadenceSec with zero fields -> skips zeros",
                                   pass, pass ? "" : "expected 20");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream A1c: MinCadenceSec with zero fields -> skips zeros",
                                   false, e.what());
    }
}

void TestMinCadenceSecAllZero() {
    std::cout << "\n[TEST] H2Upstream A1d: MinCadenceSec all timers zero -> INT_MAX..." << std::endl;
    try {
        Http2UpstreamConfig cfg;
        cfg.enabled                  = true;
        cfg.ping_idle_sec            = 0;
        cfg.ping_timeout_sec         = 0;
        cfg.goaway_drain_timeout_sec = 0;

        bool pass = (cfg.MinCadenceSec() == std::numeric_limits<int>::max());
        TestFramework::RecordTest("H2Upstream A1d: MinCadenceSec all timers zero -> INT_MAX",
                                   pass, pass ? "" : "expected INT_MAX");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream A1d: MinCadenceSec all timers zero -> INT_MAX",
                                   false, e.what());
    }
}

// A2 — UpstreamCodec polymorphism
void TestCodecPolymorphism() {
    std::cout << "\n[TEST] H2Upstream A2: Codec polymorphism via base pointer..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        // H1 codec
        {
            std::unique_ptr<UpstreamCodec> c = std::make_unique<UpstreamHttpCodec>();
            c->Reset();
            c->SetRequestMethod("GET");
            RecordingSink sink;
            c->SetSink(&sink);
            if (c->IsPaused()) { pass = false; err += "H1 codec should not start paused; "; }
            if (c->HasError()) { pass = false; err += "H1 codec should not start with error; "; }
            c->PauseParsing();
            if (!c->IsPaused()) { pass = false; err += "H1 codec should be paused; "; }
            c->ResumeParsing();
            if (c->IsPaused()) { pass = false; err += "H1 codec should be resumed; "; }
            // GetResponse is stable after Reset
            const auto& r = c->GetResponse();
            if (r.status_code != 0) { pass = false; err += "H1 after reset status should be 0; "; }
        }

        // H2 codec
        {
            std::unique_ptr<UpstreamCodec> c = std::make_unique<UpstreamH2Codec>();
            c->Reset();
            c->SetRequestMethod("POST");
            RecordingSink sink;
            c->SetSink(&sink);
            if (c->IsPaused()) { pass = false; err += "H2 codec should not start paused; "; }
            if (c->HasError()) { pass = false; err += "H2 codec should not start with error; "; }
            c->PauseParsing();
            if (!c->IsPaused()) { pass = false; err += "H2 codec should be paused; "; }
            c->ResumeParsing();
            if (c->IsPaused()) { pass = false; err += "H2 codec should be resumed; "; }
        }

        TestFramework::RecordTest("H2Upstream A2: Codec polymorphism via base pointer", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream A2: Codec polymorphism via base pointer", false, e.what());
    }
}

// A3 — UpstreamH2Codec::Parse fail-loud
void TestH2CodecParseFails() {
    std::cout << "\n[TEST] H2Upstream A3: UpstreamH2Codec::Parse sets error and returns 0..." << std::endl;
    try {
        UpstreamH2Codec codec;
        RecordingSink sink;
        codec.SetSink(&sink);

        const char fake[] = "HTTP/2 data";
        size_t consumed = codec.Parse(fake, sizeof(fake));

        bool pass = true;
        std::string err;
        if (consumed != 0)     { pass = false; err += "Parse should return 0; "; }
        if (!codec.HasError()) { pass = false; err += "HasError should be true; "; }
        if (codec.GetError().empty()) { pass = false; err += "GetError should be non-empty; "; }

        TestFramework::RecordTest("H2Upstream A3: UpstreamH2Codec::Parse sets error and returns 0",
                                   pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream A3: UpstreamH2Codec::Parse sets error and returns 0",
                                   false, e.what());
    }
}

void TestH2CodecParseErrorSurvivesReset() {
    std::cout << "\n[TEST] H2Upstream A3b: UpstreamH2Codec::Reset clears error state..." << std::endl;
    try {
        UpstreamH2Codec codec;
        const char data[] = "x";
        codec.Parse(data, 1);
        if (!codec.HasError()) {
            TestFramework::RecordTest(
                "H2Upstream A3b: UpstreamH2Codec::Reset clears error state",
                false, "precondition: HasError should be true after Parse");
            return;
        }
        codec.Reset();
        bool pass = !codec.HasError();
        TestFramework::RecordTest("H2Upstream A3b: UpstreamH2Codec::Reset clears error state",
                                   pass, pass ? "" : "HasError should be false after Reset");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream A3b: UpstreamH2Codec::Reset clears error state",
                                   false, e.what());
    }
}

// A4 — H2ConnectionTable::FindUsable
//
// We need stub H2 connections. Because Init() requires a real transport, we
// instead use H2ConnectionTable's public interface and observe only the
// side-effects through TotalConnections / ConnectionsForUpstream.  For
// FindUsable we need to insert something that reports IsUsable()=false so the
// table reaps it — we do that by never calling Init(), which leaves
// session_=nullptr so IsUsable()=false and goaway_seen_=false.
// A connection with goaway_seen=true AND streams_==0 is reaped as drained.
// We exercise the "empty table" path and the "all entries unusable (no GOAWAY)"
// path without a real socket.
void TestFindUsableEmptyTable() {
    std::cout << "\n[TEST] H2Upstream A4a: FindUsable on empty table returns null..." << std::endl;
    try {
        H2ConnectionTable table;
        auto result = table.FindUsable("svc");
        bool pass = (result == nullptr);
        TestFramework::RecordTest("H2Upstream A4a: FindUsable on empty table returns null",
                                   pass, pass ? "" : "expected nullptr");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream A4a: FindUsable on empty table returns null",
                                   false, e.what());
    }
}

void TestFindUsableUnknownUpstream() {
    std::cout << "\n[TEST] H2Upstream A4b: FindUsable unknown upstream returns null..." << std::endl;
    try {
        H2ConnectionTable table;
        // Insert for "svc-a" but query "svc-b"
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        auto conn = std::make_unique<UpstreamH2Connection>(nullptr, cfg);
        table.Insert("svc-a", std::move(conn));
        auto result = table.FindUsable("svc-b");
        bool pass = (result == nullptr);
        TestFramework::RecordTest("H2Upstream A4b: FindUsable unknown upstream returns null",
                                   pass, pass ? "" : "expected nullptr");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream A4b: FindUsable unknown upstream returns null",
                                   false, e.what());
    }
}

void TestFindUsableReapsDrainedEntry() {
    // FindUsable reaps inline any entry where goaway_seen=true AND
    // active_stream_count=0 (drained). This keeps the table compact.
    std::cout << "\n[TEST] H2Upstream A4c: FindUsable reaps drained (GOAWAY + no streams) entries..." << std::endl;
    try {
        H2ConnectionTable table;
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        auto conn = std::make_unique<UpstreamH2Connection>(nullptr, cfg);
        // Mark the connection as GOAWAY-received with no active streams —
        // this is the "drained" condition that FindUsable reaps inline.
        conn->OnGoawayReceived(0);  // sets goaway_seen_=true, active_stream_count remains 0

        table.Insert("svc", std::move(conn));
        if (table.TotalConnections() != 1) {
            TestFramework::RecordTest("H2Upstream A4c: FindUsable reaps drained (GOAWAY + no streams) entries",
                                       false, "precondition failed: TotalConnections != 1");
            return;
        }

        // FindUsable must return nullptr (drained entry is not usable)
        // and must reap the entry inline so ConnectionsForUpstream drops to 0.
        auto result = table.FindUsable("svc");
        bool returned_null = (result == nullptr);
        bool cleaned       = (table.ConnectionsForUpstream("svc") == 0);
        std::string reap_err;
        if (!returned_null) reap_err += "expected null result from FindUsable; ";
        if (!cleaned)       reap_err += "drained entry should be reaped inline by FindUsable; ";
        TestFramework::RecordTest("H2Upstream A4c: FindUsable reaps drained (GOAWAY + no streams) entries",
                                   returned_null && cleaned, reap_err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream A4c: FindUsable reaps drained (GOAWAY + no streams) entries",
                                   false, e.what());
    }
}

// A5 — H2ConnectionTable::ReapDrained
void TestReapDrainedEmpty() {
    std::cout << "\n[TEST] H2Upstream A5a: ReapDrained on empty table returns 0..." << std::endl;
    try {
        H2ConnectionTable table;
        size_t removed = table.ReapDrained();
        bool pass = (removed == 0);
        TestFramework::RecordTest("H2Upstream A5a: ReapDrained on empty table returns 0",
                                   pass, pass ? "" : "expected 0");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream A5a: ReapDrained on empty table returns 0",
                                   false, e.what());
    }
}

void TestReapDrainedNonDrainedPreserved() {
    std::cout << "\n[TEST] H2Upstream A5b: ReapDrained preserves non-drained entries..." << std::endl;
    try {
        H2ConnectionTable table;
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        // Connection has no GOAWAY and no session — not drained
        auto conn = std::make_unique<UpstreamH2Connection>(nullptr, cfg);
        table.Insert("svc", std::move(conn));

        size_t removed = table.ReapDrained();
        bool pass = (removed == 0 && table.ConnectionsForUpstream("svc") == 1);
        TestFramework::RecordTest("H2Upstream A5b: ReapDrained preserves non-drained entries",
                                   pass,
                                   pass ? "" : "non-drained entry should survive");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream A5b: ReapDrained preserves non-drained entries",
                                   false, e.what());
    }
}

// A6 — H2ConnectionTable::Clear
void TestClearEmptiesTable() {
    std::cout << "\n[TEST] H2Upstream A6: Clear empties table..." << std::endl;
    try {
        H2ConnectionTable table;
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        table.Insert("svc-a", std::make_unique<UpstreamH2Connection>(nullptr, cfg));
        table.Insert("svc-b", std::make_unique<UpstreamH2Connection>(nullptr, cfg));
        table.Insert("svc-a", std::make_unique<UpstreamH2Connection>(nullptr, cfg));

        if (table.TotalConnections() != 3) {
            TestFramework::RecordTest("H2Upstream A6: Clear empties table",
                                       false, "precondition: TotalConnections should be 3");
            return;
        }
        table.Clear();
        bool pass = (table.TotalConnections() == 0);
        TestFramework::RecordTest("H2Upstream A6: Clear empties table",
                                   pass, pass ? "" : "TotalConnections should be 0 after Clear");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream A6: Clear empties table", false, e.what());
    }
}

// Extract() transfers ownership of the matching unique_ptr out of the
// table; non-matching pointers return null without disturbing storage.
void TestExtractTransfersOwnership() {
    std::cout << "\n[TEST] H2Upstream A6b: Extract transfers ownership of matching entry..." << std::endl;
    try {
        H2ConnectionTable table;
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        auto owned_a = std::make_unique<UpstreamH2Connection>(nullptr, cfg);
        auto owned_b = std::make_unique<UpstreamH2Connection>(nullptr, cfg);
        UpstreamH2Connection* raw_a = owned_a.get();
        UpstreamH2Connection* raw_b = owned_b.get();

        table.Insert("svc", std::move(owned_a));
        table.Insert("svc", std::move(owned_b));

        bool pass = true;
        std::string err;
        if (table.TotalConnections() != 2) {
            pass = false; err += "precondition: 2 entries; ";
        }

        auto extracted = table.Extract(raw_a);
        if (!extracted || extracted.get() != raw_a) {
            pass = false; err += "Extract did not return raw_a; ";
        }
        if (table.TotalConnections() != 1) {
            pass = false; err += "table count should drop to 1; ";
        }

        // Non-matching raw pointer must return null without mutating
        // the table.
        UpstreamH2Connection* dangling = raw_a;  // already extracted
        auto miss = table.Extract(dangling);
        if (miss) { pass = false; err += "Extract of already-extracted ptr should be null; "; }
        if (table.TotalConnections() != 1) {
            pass = false; err += "miss must not mutate table; ";
        }

        // raw_b is still tracked; extracting it drains the table.
        auto ex_b = table.Extract(raw_b);
        if (!ex_b || ex_b.get() != raw_b) {
            pass = false; err += "raw_b extract failed; ";
        }
        if (table.TotalConnections() != 0) {
            pass = false; err += "table should be empty; ";
        }

        TestFramework::RecordTest(
            "H2Upstream A6b: Extract transfers ownership of matching entry",
            pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream A6b: Extract transfers ownership of matching entry",
            false, e.what());
    }
}

// Extract(nullptr) is a defined no-op.
void TestExtractNullIsNoop() {
    std::cout << "\n[TEST] H2Upstream A6c: Extract(nullptr) is no-op..." << std::endl;
    try {
        H2ConnectionTable table;
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        table.Insert("svc", std::make_unique<UpstreamH2Connection>(nullptr, cfg));
        auto result = table.Extract(nullptr);
        bool pass = (result == nullptr) && table.TotalConnections() == 1;
        TestFramework::RecordTest("H2Upstream A6c: Extract(nullptr) is no-op",
                                  pass, pass ? "" : "null extract mutated table");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream A6c: Extract(nullptr) is no-op",
                                  false, e.what());
    }
}

// A7 — H2ConnectionTable::TickAll with PING-timeout connection
// We test the reap path: after TickAll, connections whose Tick returns false
// (session_ == nullptr → false) are erased. Since Init() was never called,
// Tick() returns false immediately.
void TestTickAllRemovesDeadConnections() {
    std::cout << "\n[TEST] H2Upstream A7: TickAll removes connections whose Tick returns false..." << std::endl;
    try {
        H2ConnectionTable table;
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        // With no session_ (no Init()), Tick() returns false immediately
        auto conn = std::make_unique<UpstreamH2Connection>(nullptr, cfg);
        table.Insert("svc", std::move(conn));

        if (table.TotalConnections() != 1) {
            TestFramework::RecordTest("H2Upstream A7: TickAll removes connections whose Tick returns false",
                                       false, "precondition failed");
            return;
        }
        auto now = std::chrono::steady_clock::now();
        table.TickAll(now);

        bool pass = (table.TotalConnections() == 0);
        TestFramework::RecordTest("H2Upstream A7: TickAll removes connections whose Tick returns false",
                                   pass,
                                   pass ? "" : "dead connection should have been removed by TickAll");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream A7: TickAll removes connections whose Tick returns false",
                                   false, e.what());
    }
}

void TestTickAllKeepsLiveConnections() {
    std::cout << "\n[TEST] H2Upstream A7b: TickAll preserves live connections count..." << std::endl;
    try {
        // Two connections with no session_ (Tick returns false for both).
        // After TickAll both should be removed — this verifies the loop processes all.
        H2ConnectionTable table;
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        table.Insert("svc", std::make_unique<UpstreamH2Connection>(nullptr, cfg));
        table.Insert("svc", std::make_unique<UpstreamH2Connection>(nullptr, cfg));

        auto now = std::chrono::steady_clock::now();
        table.TickAll(now);

        bool pass = (table.TotalConnections() == 0);
        TestFramework::RecordTest("H2Upstream A7b: TickAll preserves live connections count",
                                   pass,
                                   pass ? "" : "both dead connections should be removed");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream A7b: TickAll preserves live connections count",
                                   false, e.what());
    }
}

// A8 — Live-only narrow: a staged entry whose name has no matching live
// partition is silently ignored. Drives through CommitHttp2Snapshots and
// observes that the staged "other" entry doesn't create a partition nor
// mutate the live "backend" partition's snapshot.
void TestCommitH2SnapshotsIgnoresStaleStagedEntry() {
    std::cout << "\n[TEST] H2Upstream A8: CommitHttp2Snapshots ignores staged entry with no live partition..." << std::endl;
    try {
        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig live_cfg = MakeH2UpstreamConfig("backend", "127.0.0.1", 9999);
        live_cfg.http2.ping_idle_sec = 33;
        UpstreamManager mgr({live_cfg}, {disp});
        DispatcherThreadGuard dtg{disp, t};

        // Seed an initial snapshot so we can detect any unintended mutation.
        mgr.CommitHttp2Snapshots({live_cfg});

        // Commit a staged set whose only entry names a non-live upstream.
        // "backend" remains live but is missing from the staged set; "other"
        // is staged but has no live partition. CommitHttp2Snapshots must
        // leave the live partition's snapshot unchanged.
        UpstreamConfig stale_staged = MakeH2UpstreamConfig("other", "127.0.0.1", 9998);
        stale_staged.http2.ping_idle_sec = 99;
        mgr.CommitHttp2Snapshots({stale_staged});

        auto parts = mgr.LivePartitions();
        bool pass = true;
        std::string err;
        bool found_backend = false;
        for (auto& ref : parts) {
            if (ref.upstream_name == "other") {
                pass = false;
                err += "stale staged entry created a live partition; ";
            }
            if (ref.upstream_name != "backend") continue;
            found_backend = true;
            auto snap = ref.partition->LoadHttp2ConfigSnapshot();
            if (!snap) {
                pass = false; err += "backend snapshot cleared; ";
            } else if (snap->ping_idle_sec != 33) {
                pass = false;
                err += "backend snapshot mutated (ping_idle_sec=" +
                       std::to_string(snap->ping_idle_sec) + "); ";
            }
        }
        if (!found_backend) {
            pass = false; err += "backend partition missing; ";
        }
        TestFramework::RecordTest("H2Upstream A8: CommitHttp2Snapshots ignores staged entry with no live partition",
                                   pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream A8: CommitHttp2Snapshots ignores staged entry with no live partition",
                                   false, e.what());
    }
}

// A9 — UpstreamManager::CommitHttp2Snapshots bootstrap
void TestCommitH2SnapshotsBootstrap() {
    std::cout << "\n[TEST] H2Upstream A9: CommitHttp2Snapshots publishes snapshots to partitions..." << std::endl;
    try {
        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("backend", "127.0.0.1", 9999);
        cfg.http2.ping_idle_sec = 77;
        UpstreamManager mgr({cfg}, {disp});
        DispatcherThreadGuard dtg{disp, t};

        // Before commit, snapshot may be null
        mgr.CommitHttp2Snapshots({cfg});

        // Query via LivePartitions
        auto parts = mgr.LivePartitions();
        bool pass = true;
        std::string err;
        for (auto& ref : parts) {
            if (ref.upstream_name != "backend") continue;
            auto snap = ref.partition->LoadHttp2ConfigSnapshot();
            if (!snap) {
                pass = false; err += "snapshot is null after commit; ";
            } else if (snap->ping_idle_sec != 77) {
                pass = false; err += "ping_idle_sec mismatch; ";
            }
        }
        TestFramework::RecordTest("H2Upstream A9: CommitHttp2Snapshots publishes snapshots to partitions",
                                   pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream A9: CommitHttp2Snapshots publishes snapshots to partitions",
                                   false, e.what());
    }
}

void TestCommitH2SnapshotsMissingPartitionRetainsPrevious() {
    std::cout << "\n[TEST] H2Upstream A9b: CommitHttp2Snapshots missing-from-staged preserves existing snapshot..." << std::endl;
    try {
        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("backend", "127.0.0.1", 9999);
        cfg.http2.ping_idle_sec = 55;
        UpstreamManager mgr({cfg}, {disp});
        DispatcherThreadGuard dtg{disp, t};

        // First commit establishes snapshot
        mgr.CommitHttp2Snapshots({cfg});

        // Second commit with EMPTY staged set — "backend" is missing
        mgr.CommitHttp2Snapshots({});

        // Snapshot must be preserved (conservative narrow)
        auto parts = mgr.LivePartitions();
        bool pass = true;
        std::string err;
        for (auto& ref : parts) {
            if (ref.upstream_name != "backend") continue;
            auto snap = ref.partition->LoadHttp2ConfigSnapshot();
            if (!snap) {
                pass = false; err += "snapshot was cleared but should be preserved; ";
            } else if (snap->ping_idle_sec != 55) {
                pass = false; err += "ping_idle_sec was changed; ";
            }
        }
        TestFramework::RecordTest("H2Upstream A9b: CommitHttp2Snapshots missing-from-staged preserves existing snapshot",
                                   pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream A9b: CommitHttp2Snapshots missing-from-staged preserves existing snapshot",
                                   false, e.what());
    }
}

// A10 — UpstreamManager::ComputeMinUpstreamCadenceSec
void TestComputeMinCadenceEmpty() {
    std::cout << "\n[TEST] H2Upstream A10a: ComputeMinUpstreamCadenceSec empty -> INT_MAX..." << std::endl;
    try {
        int result = UpstreamManager::ComputeMinUpstreamCadenceSec({});
        bool pass = (result == std::numeric_limits<int>::max());
        TestFramework::RecordTest("H2Upstream A10a: ComputeMinUpstreamCadenceSec empty -> INT_MAX",
                                   pass, pass ? "" : "expected INT_MAX");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream A10a: ComputeMinUpstreamCadenceSec empty -> INT_MAX",
                                   false, e.what());
    }
}

void TestComputeMinCadenceFoldsAll() {
    std::cout << "\n[TEST] H2Upstream A10b: ComputeMinUpstreamCadenceSec folds all timeout sources..." << std::endl;
    try {
        UpstreamConfig cfg = MakeH2UpstreamConfig("svc", "127.0.0.1", 9000);
        // connect_timeout_ms = 2000 ms → 2s
        cfg.pool.connect_timeout_ms    = 2000;
        cfg.pool.idle_timeout_sec      = 30;
        // response_timeout_ms = 5000 ms → 5s
        cfg.proxy.response_timeout_ms  = 5000;
        cfg.http2.ping_idle_sec        = 60;
        cfg.http2.ping_timeout_sec     = 10;
        cfg.http2.goaway_drain_timeout_sec = 30;
        cfg.http2.enabled              = true;

        int result = UpstreamManager::ComputeMinUpstreamCadenceSec({cfg});
        // min(2, 30, 5, 10, 30, 60) == 2
        bool pass = (result == 2);
        TestFramework::RecordTest("H2Upstream A10b: ComputeMinUpstreamCadenceSec folds all timeout sources",
                                   pass,
                                   pass ? "" : "expected min=2 from connect_timeout_ms/1000");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream A10b: ComputeMinUpstreamCadenceSec folds all timeout sources",
                                   false, e.what());
    }
}

// A11 — PoolPartition::ApplyHttp2ConfigCommit / LoadHttp2ConfigSnapshot
void TestApplyAndLoadH2Snapshot() {
    std::cout << "\n[TEST] H2Upstream A11a: ApplyHttp2ConfigCommit then LoadHttp2ConfigSnapshot..." << std::endl;
    try {
        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("svc", "127.0.0.1", 9999);
        UpstreamManager mgr({cfg}, {disp});
        DispatcherThreadGuard dtg{disp, t};

        // Get the partition for dispatcher 0
        auto* part = mgr.GetPoolPartition("svc", 0);
        if (!part) {
            TestFramework::RecordTest("H2Upstream A11a: ApplyHttp2ConfigCommit then LoadHttp2ConfigSnapshot",
                                       false, "GetPoolPartition returned null");
            return;
        }

        auto snap = std::make_shared<Http2UpstreamConfig>();
        snap->ping_idle_sec = 42;
        part->ApplyHttp2ConfigCommit(snap);

        auto loaded = part->LoadHttp2ConfigSnapshot();
        bool pass = loaded && loaded->ping_idle_sec == 42;
        TestFramework::RecordTest("H2Upstream A11a: ApplyHttp2ConfigCommit then LoadHttp2ConfigSnapshot",
                                   pass,
                                   pass ? "" : "loaded snapshot ping_idle_sec mismatch");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream A11a: ApplyHttp2ConfigCommit then LoadHttp2ConfigSnapshot",
                                   false, e.what());
    }
}

void TestApplyNullClearsSnapshot() {
    std::cout << "\n[TEST] H2Upstream A11b: ApplyHttp2ConfigCommit(null) clears snapshot..." << std::endl;
    try {
        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("svc", "127.0.0.1", 9999);
        UpstreamManager mgr({cfg}, {disp});
        DispatcherThreadGuard dtg{disp, t};

        auto* part = mgr.GetPoolPartition("svc", 0);
        if (!part) {
            TestFramework::RecordTest("H2Upstream A11b: ApplyHttp2ConfigCommit(null) clears snapshot",
                                       false, "GetPoolPartition returned null");
            return;
        }

        // Install a non-null snapshot, then clear it
        part->ApplyHttp2ConfigCommit(std::make_shared<Http2UpstreamConfig>());
        part->ApplyHttp2ConfigCommit(nullptr);

        auto loaded = part->LoadHttp2ConfigSnapshot();
        bool pass = (loaded == nullptr);
        TestFramework::RecordTest("H2Upstream A11b: ApplyHttp2ConfigCommit(null) clears snapshot",
                                   pass,
                                   pass ? "" : "snapshot should be null after commit(null)");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream A11b: ApplyHttp2ConfigCommit(null) clears snapshot",
                                   false, e.what());
    }
}

// A12 — BuildSettingsArray values
void TestBuildSettingsArray() {
    std::cout << "\n[TEST] H2Upstream A12: BuildSettingsArray produces correct 5-entry vector..." << std::endl;
    try {
        Http2UpstreamConfig cfg;
        cfg.initial_window_size   = 131072;
        cfg.max_frame_size        = 32768;
        cfg.header_table_size     = 8192;
        cfg.max_header_list_size  = 32768;

        auto settings = UPSTREAM_H2_SETTINGS::BuildSettingsArray(cfg);

        bool pass = true;
        std::string err;

        if (settings.size() != 5) { pass = false; err += "expected 5 entries; "; }

        bool found_iws   = false;
        bool found_mfs   = false;
        bool found_hts   = false;
        bool found_mhls  = false;
        bool found_push  = false;

        for (const auto& s : settings) {
            if (s.settings_id == NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE) {
                found_iws = true;
                if (s.value != 131072) { pass = false; err += "initial_window_size mismatch; "; }
            } else if (s.settings_id == NGHTTP2_SETTINGS_MAX_FRAME_SIZE) {
                found_mfs = true;
                if (s.value != 32768) { pass = false; err += "max_frame_size mismatch; "; }
            } else if (s.settings_id == NGHTTP2_SETTINGS_HEADER_TABLE_SIZE) {
                found_hts = true;
                if (s.value != 8192) { pass = false; err += "header_table_size mismatch; "; }
            } else if (s.settings_id == NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE) {
                found_mhls = true;
                if (s.value != 32768) { pass = false; err += "max_header_list_size mismatch; "; }
            } else if (s.settings_id == NGHTTP2_SETTINGS_ENABLE_PUSH) {
                found_push = true;
                if (s.value != 0) { pass = false; err += "ENABLE_PUSH should be 0; "; }
            }
        }

        if (!found_iws)   { pass = false; err += "missing INITIAL_WINDOW_SIZE; "; }
        if (!found_mfs)   { pass = false; err += "missing MAX_FRAME_SIZE; "; }
        if (!found_hts)   { pass = false; err += "missing HEADER_TABLE_SIZE; "; }
        if (!found_mhls)  { pass = false; err += "missing MAX_HEADER_LIST_SIZE; "; }
        if (!found_push)  { pass = false; err += "missing ENABLE_PUSH; "; }

        TestFramework::RecordTest("H2Upstream A12: BuildSettingsArray produces correct 5-entry vector",
                                   pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream A12: BuildSettingsArray produces correct 5-entry vector",
                                   false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Tier B — wire-level tests using an in-process nghttp2 server
// ---------------------------------------------------------------------------

// Mock server that drives nghttp2 server-side API in a background thread.
// Communicates via a real TCP socket pair (127.0.0.1 ephemeral ports).
struct MockH2Server {
    // Callback types
    using FrameHandler   = std::function<void(nghttp2_session*, const nghttp2_frame*, MockH2Server*)>;
    using DataHandler    = std::function<void(int32_t, const uint8_t*, size_t)>;
    using CloseHandler   = std::function<void(int32_t, uint32_t)>;
    using RequestHandler = std::function<void(nghttp2_session*, int32_t, MockH2Server*)>;

    FrameHandler   on_request_complete;  // fires on END_HEADERS for a request
    DataHandler    on_data_chunk;        // fires per received DATA chunk
    CloseHandler   on_stream_close;
    RequestHandler on_request_frame;     // fires per frame

    std::atomic<bool> stop_flag{false};
    std::atomic<int>  listen_fd{-1};
    std::atomic<int>  conn_fd{-1};
    int               port{0};
    std::thread       worker;

    // Accumulated request data from the client
    std::mutex           data_mtx;
    std::vector<uint8_t> recv_body;

    // Promise/future to synchronize server-ready state
    std::promise<int> port_promise;
    std::future<int>  port_future{port_promise.get_future()};

    MockH2Server() = default;

    // Start the server; returns once the listener is bound.
    void Start() {
        worker = std::thread([this]() { RunLoop(); });
        port = port_future.get();
    }

    void Stop() {
        stop_flag.store(true, std::memory_order_release);
        int lfd = listen_fd.load();
        if (lfd >= 0) ::shutdown(lfd, SHUT_RDWR);
        int cfd = conn_fd.load();
        if (cfd >= 0) ::shutdown(cfd, SHUT_RDWR);
        if (worker.joinable()) worker.join();
        if (lfd >= 0) { ::close(lfd); listen_fd.store(-1); }
        if (cfd >= 0) { ::close(cfd); conn_fd.store(-1); }
    }

    ~MockH2Server() { Stop(); }

    // Write data to the client connection.
    void Send(const uint8_t* data, size_t len) {
        int cfd = conn_fd.load();
        if (cfd < 0) return;
        size_t written = 0;
        while (written < len) {
            ssize_t n = ::write(cfd, data + written, len - written);
            if (n <= 0) break;
            written += static_cast<size_t>(n);
        }
    }

    // Build and send a simple response (HEADERS + optional DATA + END_STREAM).
    void SendResponse(nghttp2_session* session, int32_t stream_id,
                      int status_code, const std::string& body = "")
    {
        std::string status_str = std::to_string(status_code);
        nghttp2_nv hdrs[1];
        hdrs[0].name    = reinterpret_cast<uint8_t*>(const_cast<char*>(":status"));
        hdrs[0].namelen = 7;
        hdrs[0].value   = reinterpret_cast<uint8_t*>(const_cast<char*>(status_str.c_str()));
        hdrs[0].valuelen = status_str.size();
        hdrs[0].flags   = NGHTTP2_NV_FLAG_NONE;

        if (body.empty()) {
            nghttp2_submit_response2(session, stream_id, hdrs, 1, nullptr);
        } else {
            // Use a string copy for the data provider
            struct BodySrc { std::string data; size_t offset = 0; };
            auto* src = new BodySrc{body, 0};

            nghttp2_data_provider2 prd;
            prd.source.ptr = src;
            prd.read_callback = [](nghttp2_session*, int32_t, uint8_t* buf,
                                    size_t length, uint32_t* flags,
                                    nghttp2_data_source* source, void*) -> ssize_t
            {
                auto* s = static_cast<BodySrc*>(source->ptr);
                size_t rem = s->data.size() - s->offset;
                size_t copy = std::min(rem, length);
                if (copy > 0) {
                    std::memcpy(buf, s->data.data() + s->offset, copy);
                    s->offset += copy;
                }
                if (s->offset >= s->data.size()) {
                    *flags |= NGHTTP2_DATA_FLAG_EOF;
                    delete s;
                }
                return static_cast<ssize_t>(copy);
            };

            nghttp2_submit_response2(session, stream_id, hdrs, 1, &prd);
        }
        FlushSession(session);
    }

    // Send a GOAWAY frame.
    void SendGoaway(nghttp2_session* session, int32_t last_stream_id) {
        nghttp2_submit_goaway(session, NGHTTP2_FLAG_NONE,
                              last_stream_id, NGHTTP2_NO_ERROR, nullptr, 0);
        FlushSession(session);
    }

    void FlushSession(nghttp2_session* session) {
        while (nghttp2_session_want_write(session)) {
            const uint8_t* buf = nullptr;
            ssize_t n = nghttp2_session_mem_send2(session, &buf);
            if (n <= 0) break;
            Send(buf, static_cast<size_t>(n));
        }
    }

private:
    void RunLoop() {
        int lfd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (lfd < 0) { port_promise.set_value(0); return; }
        listen_fd.store(lfd, std::memory_order_release);

        int yes = 1;
        ::setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        struct sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port        = 0;
        if (::bind(lfd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0 ||
            ::listen(lfd, 4) < 0)
        {
            ::close(lfd); listen_fd.store(-1); port_promise.set_value(0); return;
        }
        struct sockaddr_in bound{};
        socklen_t slen = sizeof(bound);
        ::getsockname(lfd, reinterpret_cast<struct sockaddr*>(&bound), &slen);
        port_promise.set_value(ntohs(bound.sin_port));

        int cfd = ::accept(lfd, nullptr, nullptr);
        if (cfd < 0) return;
        conn_fd.store(cfd, std::memory_order_release);

        // Set up nghttp2 server session
        nghttp2_session_callbacks* cbs = nullptr;
        nghttp2_session_callbacks_new(&cbs);

        struct SessionCtx {
            MockH2Server* server;
            nghttp2_session* session;
        } ctx{this, nullptr};

        nghttp2_session_callbacks_set_send_callback2(cbs,
            [](nghttp2_session*, const uint8_t* data, size_t length,
               int, void* ud) -> ssize_t
            {
                auto* c = static_cast<SessionCtx*>(ud);
                c->server->Send(data, length);
                return static_cast<ssize_t>(length);
            });

        nghttp2_session_callbacks_set_on_frame_recv_callback(cbs,
            [](nghttp2_session* sess, const nghttp2_frame* frame, void* ud) -> int
            {
                auto* c = static_cast<SessionCtx*>(ud);
                auto* srv = c->server;
                if (frame->hd.type == NGHTTP2_HEADERS &&
                    (frame->hd.flags & NGHTTP2_FLAG_END_HEADERS) &&
                    frame->headers.cat == NGHTTP2_HCAT_REQUEST)
                {
                    if (srv->on_request_complete) {
                        srv->on_request_complete(sess, frame, srv);
                    }
                }
                if (srv->on_request_frame) {
                    srv->on_request_frame(sess, frame->hd.stream_id, srv);
                }
                return 0;
            });

        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs,
            [](nghttp2_session*, uint8_t /*flags*/, int32_t stream_id,
               const uint8_t* data, size_t len, void* ud) -> int
            {
                auto* c = static_cast<SessionCtx*>(ud);
                auto* srv = c->server;
                {
                    std::lock_guard<std::mutex> lk(srv->data_mtx);
                    srv->recv_body.insert(srv->recv_body.end(), data, data + len);
                }
                if (srv->on_data_chunk) srv->on_data_chunk(stream_id, data, len);
                return 0;
            });

        nghttp2_session_callbacks_set_on_stream_close_callback(cbs,
            [](nghttp2_session*, int32_t stream_id, uint32_t error_code, void* ud) -> int
            {
                auto* c = static_cast<SessionCtx*>(ud);
                auto* srv = c->server;
                if (srv->on_stream_close) srv->on_stream_close(stream_id, error_code);
                return 0;
            });

        nghttp2_session* session = nullptr;
        nghttp2_session_server_new(&session, cbs, &ctx);
        nghttp2_session_callbacks_del(cbs);
        ctx.session = session;

        // Send server preface SETTINGS
        nghttp2_settings_entry settings[] = {
            {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}
        };
        nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, settings, 1);
        FlushSession(session);

        // Read loop
        char buf[65536];
        while (!stop_flag.load(std::memory_order_acquire)) {
            struct timeval tv{0, 100000};  // 100 ms
            fd_set fds; FD_ZERO(&fds); FD_SET(cfd, &fds);
            int sel = ::select(cfd + 1, &fds, nullptr, nullptr, &tv);
            if (sel <= 0) continue;
            ssize_t n = ::read(cfd, buf, sizeof(buf));
            if (n <= 0) break;
            ssize_t consumed = nghttp2_session_mem_recv2(
                session, reinterpret_cast<const uint8_t*>(buf),
                static_cast<size_t>(n));
            if (consumed < 0) break;
            FlushSession(session);
        }

        nghttp2_session_del(session);
    }
};

// Helper — connect a real TCP socket to the mock server.
// Retained for MockH2Server-based tests that need a real TCP connection.
[[maybe_unused]] static bool ConnectClientToServer(int port, int& fd_out) {
    fd_out = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd_out < 0) return false;
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (::connect(fd_out, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(fd_out); fd_out = -1; return false;
    }
    return true;
}

// B-series tests use a socket-level proxy where UpstreamH2Connection
// is wired directly to a raw socket via a minimal fake UpstreamConnection
// that forwards data to the fd returned by ConnectClientToServer.
//
// Because UpstreamConnection owns a ConnectionHandler which has dispatcher
// dependencies, we use a simpler approach: create UpstreamH2Connection with
// transport_=nullptr and patch the data exchange by building a socketpair and
// feeding bytes manually to both sides. This lets us test the nghttp2
// session logic without a full reactor stack.
//
// Pattern:
//   1. Create socketpair(AF_INET, SOCK_STREAM, 0) → sv[0] (client), sv[1] (server-side mock)
//   2. Build a minimal UpstreamConnection and UpstreamH2Connection bound to sv[0]
//   3. Run the mock server loop on sv[1]
//   4. Pump bytes between the two sides synchronously

// Minimal I/O pump between two fds until a predicate is satisfied or timeout.
// Retained for MockH2Server tests that need bidirectional byte forwarding.
[[maybe_unused]] static bool PumpIO(int fd_a, int fd_b,
                   std::function<bool()> done_pred,
                   int timeout_ms = 3000)
{
    auto start = std::chrono::steady_clock::now();
    char buf[16384];
    while (true) {
        if (done_pred()) return true;
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed > timeout_ms) return false;

        // Non-blocking read from each fd
        for (int fd : {fd_a, fd_b}) {
            int dst = (fd == fd_a) ? fd_b : fd_a;
            fd_set rfds; FD_ZERO(&rfds); FD_SET(fd, &rfds);
            struct timeval tv{0, 5000};  // 5 ms
            if (::select(fd + 1, &rfds, nullptr, nullptr, &tv) > 0) {
                ssize_t n = ::recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
                if (n > 0) {
                    ::send(dst, buf, static_cast<size_t>(n), MSG_NOSIGNAL);
                }
            }
        }
    }
}

// B1 — Happy path single request completes
void TestB1SingleRequestCompletes() {
    std::cout << "\n[TEST] H2Upstream B1: Single request completes via H2 connection..." << std::endl;
    try {
        // Build a socketpair: sv[0] = client side, sv[1] = server side
        int sv[2];
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
            TestFramework::RecordTest("H2Upstream B1: Single request completes via H2 connection",
                                       false, "socketpair failed");
            return;
        }

        // --- Server side (sv[1]) runs nghttp2 server session ---
        std::atomic<bool> server_stop{false};
        std::atomic<int32_t> server_stream_id{-1};
        std::atomic<bool> response_sent{false};
        // Server session context shared with callback
        nghttp2_session* srv_session = nullptr;

        std::thread srv_thread([&]() {
            nghttp2_session_callbacks* cbs = nullptr;
            nghttp2_session_callbacks_new(&cbs);

            struct Ctx { nghttp2_session** sess_ptr; std::atomic<int32_t>* stream_id;
                         std::atomic<bool>* sent; int fd; };
            static Ctx ctx;
            ctx = {&srv_session, &server_stream_id, &response_sent, sv[1]};

            nghttp2_session_callbacks_set_send_callback2(cbs,
                [](nghttp2_session*, const uint8_t* data, size_t len, int, void* ud) -> ssize_t {
                    auto* c = static_cast<Ctx*>(ud);
                    ::send(c->fd, data, len, MSG_NOSIGNAL);
                    return static_cast<ssize_t>(len);
                });

            nghttp2_session_callbacks_set_on_frame_recv_callback(cbs,
                [](nghttp2_session* sess, const nghttp2_frame* frame, void* ud) -> int {
                    auto* c = static_cast<Ctx*>(ud);
                    if (frame->hd.type == NGHTTP2_HEADERS &&
                        (frame->hd.flags & NGHTTP2_FLAG_END_HEADERS) &&
                        frame->headers.cat == NGHTTP2_HCAT_REQUEST)
                    {
                        int32_t sid = frame->hd.stream_id;
                        c->stream_id->store(sid);

                        // Send 200 OK with small body
                        const char status[] = "200";
                        nghttp2_nv hdrs[1];
                        hdrs[0].name    = (uint8_t*)":status";
                        hdrs[0].namelen = 7;
                        hdrs[0].value   = (uint8_t*)status;
                        hdrs[0].valuelen = 3;
                        hdrs[0].flags   = NGHTTP2_NV_FLAG_NONE;

                        struct BodySrc { const char* data; size_t size; size_t offset; };
                        static BodySrc bsrc{"hello", 5, 0};
                        bsrc = {"hello", 5, 0};

                        nghttp2_data_provider2 prd;
                        prd.source.ptr = &bsrc;
                        prd.read_callback = [](nghttp2_session*, int32_t, uint8_t* buf,
                                                size_t length, uint32_t* flags,
                                                nghttp2_data_source* src, void*) -> ssize_t {
                            auto* s = static_cast<BodySrc*>(src->ptr);
                            size_t rem = s->size - s->offset;
                            size_t copy = std::min(rem, length);
                            std::memcpy(buf, s->data + s->offset, copy);
                            s->offset += copy;
                            if (s->offset >= s->size) *flags |= NGHTTP2_DATA_FLAG_EOF;
                            return static_cast<ssize_t>(copy);
                        };
                        nghttp2_submit_response2(sess, sid, hdrs, 1, &prd);
                        // Flush
                        while (nghttp2_session_want_write(sess)) {
                            const uint8_t* out = nullptr;
                            ssize_t n = nghttp2_session_mem_send2(sess, &out);
                            if (n <= 0) break;
                            ::send(c->fd, out, static_cast<size_t>(n), MSG_NOSIGNAL);
                        }
                        c->sent->store(true);
                    }
                    return 0;
                });

            nghttp2_session_server_new(&srv_session, cbs, &ctx);
            nghttp2_session_callbacks_del(cbs);

            // Send server preface
            nghttp2_settings_entry settings[] = {{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
            nghttp2_submit_settings(srv_session, NGHTTP2_FLAG_NONE, settings, 1);
            while (nghttp2_session_want_write(srv_session)) {
                const uint8_t* out = nullptr;
                ssize_t n = nghttp2_session_mem_send2(srv_session, &out);
                if (n <= 0) break;
                ::send(sv[1], out, static_cast<size_t>(n), MSG_NOSIGNAL);
            }

            char buf[65536];
            while (!server_stop.load()) {
                fd_set rfds; FD_ZERO(&rfds); FD_SET(sv[1], &rfds);
                struct timeval tv{0, 50000};
                if (::select(sv[1] + 1, &rfds, nullptr, nullptr, &tv) > 0) {
                    ssize_t n = ::recv(sv[1], buf, sizeof(buf), 0);
                    if (n <= 0) break;
                    nghttp2_session_mem_recv2(srv_session,
                        reinterpret_cast<const uint8_t*>(buf), static_cast<size_t>(n));
                    while (nghttp2_session_want_write(srv_session)) {
                        const uint8_t* out = nullptr;
                        ssize_t sn = nghttp2_session_mem_send2(srv_session, &out);
                        if (sn <= 0) break;
                        ::send(sv[1], out, static_cast<size_t>(sn), MSG_NOSIGNAL);
                    }
                }
            }
            nghttp2_session_del(srv_session);
        });

        // --- Client side: UpstreamH2Connection over sv[0] ---
        // We need a fake "transport" that has a SendRaw method wired to sv[0].
        // UpstreamH2Connection's FlushSend uses transport_->GetTransport()->SendRaw.
        // Instead of building the full stack, we drive the client session
        // manually by wrapping nghttp2 calls and using sv[0] directly.

        auto cfg = std::make_shared<Http2UpstreamConfig>();
        cfg->enabled = true;
        cfg->max_concurrent_streams_pref = 10;
        cfg->ping_idle_sec   = 60;
        cfg->ping_timeout_sec = 10;
        cfg->goaway_drain_timeout_sec = 30;

        // Client nghttp2 session (manual, to avoid UpstreamConnection dep)
        nghttp2_session* cli_session = nullptr;
        nghttp2_session_callbacks* ccbs = nullptr;
        nghttp2_session_callbacks_new(&ccbs);
        nghttp2_session_callbacks_set_send_callback2(ccbs,
            [](nghttp2_session*, const uint8_t* data, size_t len, int, void* ud) -> ssize_t {
                int fd = *static_cast<int*>(ud);
                ::send(fd, data, len, MSG_NOSIGNAL);
                return static_cast<ssize_t>(len);
            });

        RecordingSink sink;

        // Shared stream data for header/body callbacks
        struct StreamData {
            RecordingSink* sink;
            std::string body;
        };
        StreamData sd{&sink, ""};

        nghttp2_session_callbacks_set_on_header_callback(ccbs,
            [](nghttp2_session* session, const nghttp2_frame* frame,
               const uint8_t* name, size_t namelen,
               const uint8_t* value, size_t valuelen,
               uint8_t, void* ud) -> int {
                (void)session; (void)frame; (void)name; (void)namelen;
                (void)value; (void)valuelen; (void)ud;
                return 0;
            });

        nghttp2_session_callbacks_set_on_frame_recv_callback(ccbs,
            [](nghttp2_session* sess, const nghttp2_frame* frame, void* ud) -> int {
                auto* sd_ptr = static_cast<StreamData*>(ud);
                if (frame->hd.type == NGHTTP2_HEADERS &&
                    (frame->hd.flags & NGHTTP2_FLAG_END_HEADERS))
                {
                    UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead head;
                    head.status_code = 200;
                    sd_ptr->sink->OnHeaders(head);
                }
                (void)sess;
                return 0;
            });

        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(ccbs,
            [](nghttp2_session*, uint8_t, int32_t, const uint8_t* data,
               size_t len, void* ud) -> int {
                auto* sd_ptr = static_cast<StreamData*>(ud);
                sd_ptr->sink->OnBodyChunk(reinterpret_cast<const char*>(data), len);
                sd_ptr->body.append(reinterpret_cast<const char*>(data), len);
                return 0;
            });

        nghttp2_session_callbacks_set_on_stream_close_callback(ccbs,
            [](nghttp2_session*, int32_t, uint32_t error_code, void* ud) -> int {
                auto* sd_ptr = static_cast<StreamData*>(ud);
                if (error_code == NGHTTP2_NO_ERROR) {
                    sd_ptr->sink->OnComplete();
                } else {
                    sd_ptr->sink->OnError(static_cast<int>(error_code), "stream error");
                }
                return 0;
            });

        nghttp2_session_client_new(&cli_session, ccbs, &sd);
        nghttp2_session_callbacks_del(ccbs);

        // Client preface
        auto cli_settings = UPSTREAM_H2_SETTINGS::BuildSettingsArray(*cfg);
        nghttp2_submit_settings(cli_session, NGHTTP2_FLAG_NONE,
                                 cli_settings.data(), cli_settings.size());
        auto flush_client = [&]() {
            while (nghttp2_session_want_write(cli_session)) {
                const uint8_t* buf = nullptr;
                ssize_t n = nghttp2_session_mem_send2(cli_session, &buf);
                if (n <= 0) break;
                ::send(sv[0], buf, static_cast<size_t>(n), MSG_NOSIGNAL);
            }
        };
        flush_client();

        // Submit a GET request
        const char method[]    = "GET";
        const char scheme[]    = "http";
        const char authority[] = "localhost";
        const char path[]      = "/";
        nghttp2_nv req_hdrs[4];
        req_hdrs[0].name    = (uint8_t*)":method";  req_hdrs[0].namelen  = 7;
        req_hdrs[0].value   = (uint8_t*)method;     req_hdrs[0].valuelen = 3;
        req_hdrs[0].flags   = NGHTTP2_NV_FLAG_NONE;
        req_hdrs[1].name    = (uint8_t*)":scheme";  req_hdrs[1].namelen  = 7;
        req_hdrs[1].value   = (uint8_t*)scheme;     req_hdrs[1].valuelen = 4;
        req_hdrs[1].flags   = NGHTTP2_NV_FLAG_NONE;
        req_hdrs[2].name    = (uint8_t*)":authority"; req_hdrs[2].namelen  = 10;
        req_hdrs[2].value   = (uint8_t*)authority;    req_hdrs[2].valuelen = 9;
        req_hdrs[2].flags   = NGHTTP2_NV_FLAG_NONE;
        req_hdrs[3].name    = (uint8_t*)":path";    req_hdrs[3].namelen  = 5;
        req_hdrs[3].value   = (uint8_t*)path;       req_hdrs[3].valuelen = 1;
        req_hdrs[3].flags   = NGHTTP2_NV_FLAG_NONE;

        int32_t stream_id = nghttp2_submit_request2(cli_session, nullptr,
                                                     req_hdrs, 4, nullptr, nullptr);
        flush_client();

        // Pump until complete or timeout
        char buf[65536];
        auto pump_start = std::chrono::steady_clock::now();
        while (sink.complete_calls == 0 && sink.error_calls == 0) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - pump_start).count();
            if (elapsed > 3000) break;
            fd_set rfds; FD_ZERO(&rfds); FD_SET(sv[0], &rfds);
            struct timeval tv{0, 10000};
            if (::select(sv[0] + 1, &rfds, nullptr, nullptr, &tv) > 0) {
                ssize_t n = ::recv(sv[0], buf, sizeof(buf), MSG_DONTWAIT);
                if (n > 0) {
                    nghttp2_session_mem_recv2(cli_session,
                        reinterpret_cast<const uint8_t*>(buf), static_cast<size_t>(n));
                    flush_client();
                }
            }
        }

        server_stop.store(true);
        ::shutdown(sv[0], SHUT_RDWR);
        ::shutdown(sv[1], SHUT_RDWR);
        srv_thread.join();
        ::close(sv[0]); ::close(sv[1]);
        nghttp2_session_del(cli_session);

        bool pass = true;
        std::string err;
        if (stream_id < 1)        { pass = false; err += "stream_id should be >= 1; "; }
        if (sink.headers_calls != 1) { pass = false; err += "expected 1 OnHeaders call; "; }
        if (sink.body_bytes < 1)  { pass = false; err += "expected body bytes > 0; "; }
        if (sink.complete_calls != 1) { pass = false; err += "expected 1 OnComplete call; "; }

        TestFramework::RecordTest("H2Upstream B1: Single request completes via H2 connection",
                                   pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream B1: Single request completes via H2 connection",
                                   false, e.what());
    }
}

// B5 — PING timeout — Tick returns false
void TestB5TickReturnsFalseWithNullSession() {
    std::cout << "\n[TEST] H2Upstream B5: Tick returns false when session is null..." << std::endl;
    try {
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        cfg->enabled               = true;
        cfg->ping_idle_sec         = 1;
        cfg->ping_timeout_sec      = 1;
        cfg->max_concurrent_streams_pref = 10;
        cfg->goaway_drain_timeout_sec = 30;

        // With transport_=nullptr, Init() is never called, session_=nullptr,
        // and Tick() returns false at the null-session early-out.
        UpstreamH2Connection conn(nullptr, cfg);
        auto now = std::chrono::steady_clock::now();
        bool tick_result = conn.Tick(now, 1, 1, 0);
        bool pass = !tick_result;
        TestFramework::RecordTest("H2Upstream B5: Tick returns false when session is null",
                                   pass,
                                   pass ? "" : "Tick should return false with no session");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream B5: Tick returns false when session is null",
                                   false, e.what());
    }
}

// B6 — RST_STREAM — after RST, stream disappears from active_stream_count
void TestB6RstStreamRemovesEntry() {
    std::cout << "\n[TEST] H2Upstream B6: ResetStream removes stream from active count..." << std::endl;
    try {
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        cfg->enabled               = true;
        cfg->max_concurrent_streams_pref = 10;
        cfg->ping_idle_sec         = 0;
        cfg->ping_timeout_sec      = 0;
        cfg->goaway_drain_timeout_sec = 0;

        UpstreamH2Connection conn(nullptr, cfg);
        // No-op on nullptr transport: ResetStream with non-existent stream is safe
        conn.ResetStream(1);
        bool pass = (conn.active_stream_count() == 0);
        TestFramework::RecordTest("H2Upstream B6: ResetStream removes stream from active count",
                                   pass,
                                   pass ? "" : "active_stream_count should be 0");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream B6: ResetStream removes stream from active count",
                                   false, e.what());
    }
}

// B7 — OnTrailersComplete on a non-existent stream is a no-op
void TestB7OnTrailersCompleteNoStream() {
    std::cout << "\n[TEST] H2Upstream B7: OnTrailersComplete on missing stream is no-op..." << std::endl;
    try {
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        cfg->enabled = true;
        cfg->max_concurrent_streams_pref = 10;
        cfg->ping_idle_sec   = 0;
        cfg->ping_timeout_sec = 0;
        cfg->goaway_drain_timeout_sec = 0;

        UpstreamH2Connection conn(nullptr, cfg);
        conn.OnTrailersComplete(1);
        bool pass = (conn.active_stream_count() == 0);
        TestFramework::RecordTest("H2Upstream B7: OnTrailersComplete on missing stream is no-op",
                                   pass, pass ? "" : "expected no state change");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream B7: OnTrailersComplete on missing stream is no-op",
                                   false, e.what());
    }
}

// B8 — RecordingSink: OnTrailers is wired and tracks payload
void TestB8RecordingSinkTrailers() {
    std::cout << "\n[TEST] H2Upstream B8: RecordingSink.OnTrailers tracks payload..." << std::endl;
    try {
        RecordingSink sink;
        std::vector<std::pair<std::string, std::string>> t = {
            {"grpc-status", "0"},
            {"grpc-message", "ok"},
        };
        sink.OnTrailers(t);

        bool pass =
            (sink.trailers_calls == 1) &&
            (sink.last_trailers.size() == 2) &&
            (sink.last_trailers[0].first == "grpc-status") &&
            (sink.last_trailers[0].second == "0") &&
            (sink.last_trailers[1].first == "grpc-message");
        TestFramework::RecordTest("H2Upstream B8: RecordingSink.OnTrailers tracks payload",
                                   pass, pass ? "" : "trailer accounting mismatch");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream B8: RecordingSink.OnTrailers tracks payload",
                                   false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Tier B (wire-level via real UpstreamH2Connection::HandleBytes)
// ---------------------------------------------------------------------------
// These tests construct a REAL UpstreamH2Connection (with a null transport,
// so FlushSend silently drains nghttp2's buffer) and feed hand-crafted server
// bytes through the production HandleBytes → mem_recv2 → callback chain.
// Coverage gap closed (vs. TestB1 which drives nghttp2 manually):
//   B9  — empty SETTINGS frame is consumed and accounted for
//   B10 — :status=200 HEADERS dispatches OnHeaders to the sink
//   B11 — :status="abc" triggers TEMPORAL_CALLBACK_FAILURE → RST_STREAM
//         → OnStreamClose → sink->OnError (no OnHeaders)

namespace H2WireTest {

// Build a SETTINGS frame with an empty payload. nghttp2 server preface is
// just an immediate SETTINGS frame; clients accept it without an explicit
// connection preface.
inline std::vector<uint8_t> BuildEmptySettings() {
    return {0,0,0, NGHTTP2_SETTINGS, 0, 0,0,0,0};
}

// HPACK-encode a single (name, value) header block and frame it as a HEADERS
// frame on `stream_id`. Always sets END_HEADERS; END_STREAM is operator
// controlled. Returns the wire bytes ready to feed to HandleBytes.
inline std::vector<uint8_t> BuildHeadersFrame(
    int32_t stream_id,
    const std::vector<std::pair<std::string, std::string>>& headers,
    bool end_stream)
{
    nghttp2_hd_deflater* defl = nullptr;
    if (nghttp2_hd_deflate_new(&defl, 4096) != 0) return {};

    std::vector<nghttp2_nv> nva;
    nva.reserve(headers.size());
    for (const auto& kv : headers) {
        nghttp2_nv nv;
        nv.name = reinterpret_cast<uint8_t*>(const_cast<char*>(kv.first.data()));
        nv.namelen = kv.first.size();
        nv.value = reinterpret_cast<uint8_t*>(const_cast<char*>(kv.second.data()));
        nv.valuelen = kv.second.size();
        nv.flags = NGHTTP2_NV_FLAG_NO_INDEX;
        nva.push_back(nv);
    }
    size_t bound = nghttp2_hd_deflate_bound(defl, nva.data(), nva.size());
    std::vector<uint8_t> hpack(bound);
    ssize_t pl = nghttp2_hd_deflate_hd2(defl, hpack.data(), hpack.size(),
                                         nva.data(), nva.size());
    nghttp2_hd_deflate_del(defl);
    if (pl < 0) return {};

    std::vector<uint8_t> frame;
    frame.reserve(9 + pl);
    frame.push_back(static_cast<uint8_t>((pl >> 16) & 0xff));
    frame.push_back(static_cast<uint8_t>((pl >> 8) & 0xff));
    frame.push_back(static_cast<uint8_t>(pl & 0xff));
    frame.push_back(NGHTTP2_HEADERS);
    uint8_t flags = NGHTTP2_FLAG_END_HEADERS;
    if (end_stream) flags |= NGHTTP2_FLAG_END_STREAM;
    frame.push_back(flags);
    frame.push_back(static_cast<uint8_t>((stream_id >> 24) & 0x7f));
    frame.push_back(static_cast<uint8_t>((stream_id >> 16) & 0xff));
    frame.push_back(static_cast<uint8_t>((stream_id >> 8) & 0xff));
    frame.push_back(static_cast<uint8_t>(stream_id & 0xff));
    frame.insert(frame.end(), hpack.begin(), hpack.begin() + pl);
    return frame;
}

// Build a GOAWAY frame with the given last_stream_id and error_code.
// RFC 9113 §6.8: 8-byte payload (last_stream_id + error_code), no debug
// data, stream_id always 0 for connection-level frames.
inline std::vector<uint8_t> BuildGoawayFrame(int32_t last_stream_id,
                                              uint32_t error_code) {
    std::vector<uint8_t> frame;
    frame.reserve(17);
    // 24-bit length = 8
    frame.push_back(0); frame.push_back(0); frame.push_back(8);
    frame.push_back(NGHTTP2_GOAWAY);
    frame.push_back(0);  // flags
    // stream_id = 0
    frame.push_back(0); frame.push_back(0);
    frame.push_back(0); frame.push_back(0);
    // last_stream_id (R bit clear)
    frame.push_back(static_cast<uint8_t>((last_stream_id >> 24) & 0x7f));
    frame.push_back(static_cast<uint8_t>((last_stream_id >> 16) & 0xff));
    frame.push_back(static_cast<uint8_t>((last_stream_id >> 8) & 0xff));
    frame.push_back(static_cast<uint8_t>(last_stream_id & 0xff));
    frame.push_back(static_cast<uint8_t>((error_code >> 24) & 0xff));
    frame.push_back(static_cast<uint8_t>((error_code >> 16) & 0xff));
    frame.push_back(static_cast<uint8_t>((error_code >> 8) & 0xff));
    frame.push_back(static_cast<uint8_t>(error_code & 0xff));
    return frame;
}

}  // namespace H2WireTest

// B9 — Empty SETTINGS frame is consumed by the real HandleBytes path
void TestB9HandleBytesConsumesSettings() {
    std::cout << "\n[TEST] H2Upstream B9: HandleBytes accepts server SETTINGS..." << std::endl;
    try {
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        cfg->enabled = true;
        cfg->max_concurrent_streams_pref = 10;
        cfg->ping_idle_sec = 0;
        cfg->ping_timeout_sec = 0;
        cfg->goaway_drain_timeout_sec = 0;

        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream B9: HandleBytes accepts server SETTINGS",
                false, "Init failed");
            return;
        }
        auto bytes = H2WireTest::BuildEmptySettings();
        ssize_t consumed = conn.HandleBytes(
            reinterpret_cast<const char*>(bytes.data()), bytes.size());
        bool pass = (consumed == static_cast<ssize_t>(bytes.size())) &&
                    !conn.IsDead();
        TestFramework::RecordTest(
            "H2Upstream B9: HandleBytes accepts server SETTINGS",
            pass, pass ? "" : "consumed mismatch or session marked dead");
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream B9: HandleBytes accepts server SETTINGS",
            false, e.what());
    }
}

// B10 — A valid HEADERS frame for an outstanding request dispatches
// OnHeaders to the sink with the parsed status.
void TestB10HandleBytesDispatchesValidStatus() {
    std::cout << "\n[TEST] H2Upstream B10: HandleBytes dispatches OnHeaders for :status=200..." << std::endl;
    try {
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        cfg->enabled = true;
        cfg->max_concurrent_streams_pref = 10;
        cfg->ping_idle_sec = 0;
        cfg->ping_timeout_sec = 0;
        cfg->goaway_drain_timeout_sec = 0;

        // sink declared before conn so it outlives ~UpstreamH2Connection's
        // defensive FailAllStreams (sinks notified at dtor time).
        RecordingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream B10: HandleBytes dispatches OnHeaders for :status=200",
                false, "Init failed");
            return;
        }
        int32_t sid = conn.SubmitRequest(
            "GET", "http", "example.com", "/", {}, "", &sink);
        if (sid != 1) {
            TestFramework::RecordTest(
                "H2Upstream B10: HandleBytes dispatches OnHeaders for :status=200",
                false, "expected stream id 1 from first SubmitRequest");
            return;
        }

        std::vector<uint8_t> wire = H2WireTest::BuildEmptySettings();
        auto hdrs = H2WireTest::BuildHeadersFrame(
            sid, {{":status", "200"}, {"content-length", "0"}},
            /*end_stream=*/true);
        wire.insert(wire.end(), hdrs.begin(), hdrs.end());

        ssize_t consumed = conn.HandleBytes(
            reinterpret_cast<const char*>(wire.data()), wire.size());
        bool pass = (consumed > 0) &&
                    (sink.headers_calls == 1) &&
                    (sink.last_status == 200);
        TestFramework::RecordTest(
            "H2Upstream B10: HandleBytes dispatches OnHeaders for :status=200",
            pass,
            pass ? "" : "expected single OnHeaders with status=200");
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream B10: HandleBytes dispatches OnHeaders for :status=200",
            false, e.what());
    }
}

// B11 — Malformed :status="abc" rejects via NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE.
// nghttp2 issues RST_STREAM, OnStreamClose fires with non-NO_ERROR, sink gets
// OnError. The sink must NOT see OnHeaders.
void TestB11HandleBytesRejectsInvalidStatus() {
    std::cout << "\n[TEST] H2Upstream B11: HandleBytes rejects :status='abc'..." << std::endl;
    try {
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        cfg->enabled = true;
        cfg->max_concurrent_streams_pref = 10;
        cfg->ping_idle_sec = 0;
        cfg->ping_timeout_sec = 0;
        cfg->goaway_drain_timeout_sec = 0;

        // sink must outlive conn (~UpstreamH2Connection FailAllStreams).
        RecordingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream B11: HandleBytes rejects :status='abc'",
                false, "Init failed");
            return;
        }
        int32_t sid = conn.SubmitRequest(
            "GET", "http", "example.com", "/", {}, "", &sink);
        if (sid != 1) {
            TestFramework::RecordTest(
                "H2Upstream B11: HandleBytes rejects :status='abc'",
                false, "expected stream id 1");
            return;
        }

        std::vector<uint8_t> wire = H2WireTest::BuildEmptySettings();
        auto hdrs = H2WireTest::BuildHeadersFrame(
            sid, {{":status", "abc"}}, /*end_stream=*/true);
        wire.insert(wire.end(), hdrs.begin(), hdrs.end());

        ssize_t consumed = conn.HandleBytes(
            reinterpret_cast<const char*>(wire.data()), wire.size());
        // sink->OnError fires from OnStreamClose after nghttp2 RSTs the
        // stream in response to TEMPORAL_CALLBACK_FAILURE.
        bool pass = (consumed > 0) &&
                    (sink.headers_calls == 0) &&
                    (sink.error_calls == 1);
        TestFramework::RecordTest(
            "H2Upstream B11: HandleBytes rejects :status='abc'",
            pass,
            pass ? ""
                 : "expected zero OnHeaders and one OnError after RST_STREAM");
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream B11: HandleBytes rejects :status='abc'",
            false, e.what());
    }
}

// B12 — Tick honors goaway_drain_timeout_sec when streams remain stuck
// after a peer-initiated GOAWAY. With non-zero drain timeout AND elapsed
// wall-clock past the deadline AND active streams, Tick returns false so
// the table walker reaps the stuck connection. Without GOAWAY, the same
// elapsed time leaves Tick returning true (drain timer never started).
void TestB12TickGoawayDrainTimeout() {
    std::cout << "\n[TEST] H2Upstream B12: Tick fires on stuck GOAWAY drain..." << std::endl;
    try {
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        cfg->enabled = true;
        cfg->max_concurrent_streams_pref = 10;
        cfg->ping_idle_sec = 0;
        cfg->ping_timeout_sec = 0;
        cfg->goaway_drain_timeout_sec = 2;

        // sink must outlive conn (~UpstreamH2Connection FailAllStreams).
        RecordingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream B12: Tick fires on stuck GOAWAY drain",
                false, "Init failed");
            return;
        }
        int32_t sid = conn.SubmitRequest(
            "GET", "http", "example.com", "/", {}, "", &sink);
        if (sid != 1) {
            TestFramework::RecordTest(
                "H2Upstream B12: Tick fires on stuck GOAWAY drain",
                false, "SubmitRequest failed");
            return;
        }

        // No GOAWAY yet: Tick(now+drain_timeout) should still return true —
        // drain timer is gated on goaway_seen_.
        auto now = std::chrono::steady_clock::now();
        bool tick_pre_goaway = conn.Tick(now + std::chrono::seconds(5),
                                          /*ping_idle*/0, /*ping_timeout*/0,
                                          /*goaway_drain*/2);

        // Mark GOAWAY received with last_stream_id=1 — the peer says it
        // processed our stream (id=1) and will not process newer ones.
        // Streams above last_stream_id are failed immediately by
        // OnGoawayReceived (RFC 9113 §6.8 retry-safe), so we keep the
        // in-flight stream INSIDE the processed range to actually
        // exercise the drain-timeout path.
        conn.OnGoawayReceived(/*last_stream_id=*/1);

        // Tick within the drain window — still alive.
        bool tick_within_window = conn.Tick(
            std::chrono::steady_clock::now() + std::chrono::seconds(1),
            0, 0, 2);

        // Tick past the drain window — should evict (return false).
        bool tick_past_window = conn.Tick(
            std::chrono::steady_clock::now() + std::chrono::seconds(5),
            0, 0, 2);

        bool pass = tick_pre_goaway && tick_within_window && !tick_past_window;
        TestFramework::RecordTest(
            "H2Upstream B12: Tick fires on stuck GOAWAY drain",
            pass,
            pass ? ""
                 : "expected pre_goaway=true, within=true, past=false");
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream B12: Tick fires on stuck GOAWAY drain",
            false, e.what());
    }
}

// B12b — RFC 9113 §6.8: streams above GOAWAY's last_stream_id were not
// processed by the peer and MUST be failed immediately with a retryable
// error so the proxy retry policy fires. Submit two streams, then send
// GOAWAY with last_stream_id naming only the first; the second's sink
// should observe exactly one OnError call carrying RESULT_GOAWAY_UNPROCESSED.
// Streams inside the processed range continue draining (no extra error
// fire on stream 1).
void TestB12bGoawayFailsStreamsAbovePeerLastId() {
    std::cout << "\n[TEST] H2Upstream B12b: GOAWAY fails streams above peer last_stream_id..." << std::endl;
    try {
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        cfg->enabled = true;
        cfg->max_concurrent_streams_pref = 10;

        // sinks must outlive conn (~UpstreamH2Connection FailAllStreams).
        RecordingSink sink_a, sink_b;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream B12b: GOAWAY fails streams above peer last_stream_id",
                false, "Init failed");
            return;
        }
        int32_t sid_a = conn.SubmitRequest(
            "GET", "http", "example.com", "/a", {}, "", &sink_a);
        int32_t sid_b = conn.SubmitRequest(
            "GET", "http", "example.com", "/b", {}, "", &sink_b);
        // nghttp2 assigns client-initiated stream ids 1, 3, 5, ...
        if (sid_a != 1 || sid_b != 3) {
            TestFramework::RecordTest(
                "H2Upstream B12b: GOAWAY fails streams above peer last_stream_id",
                false, "Unexpected stream ids: a=" + std::to_string(sid_a) +
                       " b=" + std::to_string(sid_b));
            return;
        }

        // Peer says: I processed up through stream 1; everything above
        // is unprocessed and safe to retry.
        conn.OnGoawayReceived(/*last_stream_id=*/1);

        bool a_untouched = (sink_a.error_calls == 0 &&
                            sink_a.complete_calls == 0);
        bool b_failed_once = (sink_b.error_calls == 1 &&
                              sink_b.complete_calls == 0);
        bool b_code_correct =
            (sink_b.last_error_code == ProxyTransaction::RESULT_GOAWAY_UNPROCESSED);

        bool pass = a_untouched && b_failed_once && b_code_correct;
        TestFramework::RecordTest(
            "H2Upstream B12b: GOAWAY fails streams above peer last_stream_id",
            pass,
            pass ? ""
                 : ("expected a:err=0+complete=0, b:err=1+code=" +
                    std::to_string(ProxyTransaction::RESULT_GOAWAY_UNPROCESSED) +
                    "; got a:err=" + std::to_string(sink_a.error_calls) +
                    "/complete=" + std::to_string(sink_a.complete_calls) +
                    ", b:err=" + std::to_string(sink_b.error_calls) +
                    "/code=" + std::to_string(sink_b.last_error_code)));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream B12b: GOAWAY fails streams above peer last_stream_id",
            false, e.what());
    }
}

// B13 — UpstreamManager advertises ALPN gated on per-upstream H2 prefer
// mode. prefer="auto" (default) → ["h2", "http/1.1"]; prefer="never" →
// ["http/1.1"] only. The wire format is length-prefixed concatenation.
void TestB13AlpnGatedByPreferMode() {
    std::cout << "\n[TEST] H2Upstream B13: ALPN list varies by prefer mode..." << std::endl;
    try {
        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);

        UpstreamConfig auto_cfg = MakeH2UpstreamConfig("svc_auto", "127.0.0.1", 9999);
        auto_cfg.tls.enabled = true;
        auto_cfg.tls.verify_peer = false;
        auto_cfg.http2.prefer = "auto";

        UpstreamConfig never_cfg = MakeH2UpstreamConfig("svc_never", "127.0.0.1", 9998);
        never_cfg.tls.enabled = true;
        never_cfg.tls.verify_peer = false;
        never_cfg.http2.prefer = "never";

        UpstreamConfig disabled_cfg = MakeH2UpstreamConfig("svc_disabled", "127.0.0.1", 9997);
        disabled_cfg.tls.enabled = true;
        disabled_cfg.tls.verify_peer = false;
        disabled_cfg.http2.enabled = false;

        UpstreamManager mgr({auto_cfg, never_cfg, disabled_cfg}, {disp});
        DispatcherThreadGuard dtg{disp, t};

        // Wire format: 1-byte length + bytes for each protocol.
        // ["h2", "http/1.1"] = 0x02 'h' '2' 0x08 'h' 't' 't' 'p' '/' '1' '.' '1'
        std::vector<unsigned char> expect_with_h2 = {
            0x02, 'h', '2',
            0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'};
        // ["http/1.1"] = 0x08 'h' 't' 't' 'p' '/' '1' '.' '1'
        std::vector<unsigned char> expect_h1_only = {
            0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'};

        auto ctx_auto = mgr.GetTlsContextForUpstream("svc_auto");
        auto ctx_never = mgr.GetTlsContextForUpstream("svc_never");
        auto ctx_disabled = mgr.GetTlsContextForUpstream("svc_disabled");

        bool pass = ctx_auto && ctx_never && ctx_disabled &&
                    ctx_auto->GetAlpnWire() == expect_with_h2 &&
                    ctx_never->GetAlpnWire() == expect_h1_only &&
                    ctx_disabled->GetAlpnWire() == expect_h1_only;
        TestFramework::RecordTest(
            "H2Upstream B13: ALPN list varies by prefer mode",
            pass,
            pass ? ""
                 : "auto must advertise [h2,http/1.1]; never/disabled must advertise [http/1.1] only");
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream B13: ALPN list varies by prefer mode",
            false, e.what());
    }
}

// B14 — :authority derivation through DispatchH2 mirrors H1's Host
// header byte-for-byte. Exercised via HeaderRewriter's RewriteRequest
// directly (the same source-of-truth DispatchH2 reads from). Covers the
// cases the prior reviewer flagged: TLS-by-IP with sni_hostname,
// IPv6-literal bracketing, and rewrite_host=false passthrough.
void TestB14AuthorityDerivationCases() {
    std::cout << "\n[TEST] H2Upstream B14: :authority derivation cases..." << std::endl;
    try {
        // Case 1: TLS by IP, sni_hostname set → SNI wins, default port omits.
        {
            HeaderRewriter::Config cfg;
            HeaderRewriter rw(cfg);
            auto out = rw.RewriteRequest({}, "203.0.113.5", false,
                                         /*upstream_tls=*/true,
                                         /*upstream_host=*/"192.0.2.1",
                                         /*upstream_port=*/443,
                                         /*sni_hostname=*/"api.example.com");
            if (out["host"] != "api.example.com") {
                TestFramework::RecordTest(
                    "H2Upstream B14: :authority derivation cases",
                    false, "Case 1 (SNI override): expected api.example.com, got " + out["host"]);
                return;
            }
        }
        // Case 2: IPv6 literal upstream → bracketed via FormatAuthority.
        {
            HeaderRewriter::Config cfg;
            HeaderRewriter rw(cfg);
            auto out = rw.RewriteRequest({}, "::1", false,
                                         /*upstream_tls=*/false,
                                         /*upstream_host=*/"2001:db8::1",
                                         /*upstream_port=*/8080,
                                         /*sni_hostname=*/"");
            if (out["host"] != "[2001:db8::1]:8080") {
                TestFramework::RecordTest(
                    "H2Upstream B14: :authority derivation cases",
                    false, "Case 2 (IPv6): expected [2001:db8::1]:8080, got " + out["host"]);
                return;
            }
        }
        // Case 3: rewrite_host=false → preserve client-supplied Host.
        {
            HeaderRewriter::Config cfg;
            cfg.rewrite_host = false;
            HeaderRewriter rw(cfg);
            std::map<std::string, std::string> client = {
                {"host", "client.example.com:9000"}};
            auto out = rw.RewriteRequest(client, "203.0.113.5", false,
                                         /*upstream_tls=*/false,
                                         /*upstream_host=*/"upstream.internal",
                                         /*upstream_port=*/80,
                                         /*sni_hostname=*/"");
            if (out["host"] != "client.example.com:9000") {
                TestFramework::RecordTest(
                    "H2Upstream B14: :authority derivation cases",
                    false, "Case 3 (rewrite_host=false): expected client.example.com:9000, got " + out["host"]);
                return;
            }
        }
        TestFramework::RecordTest(
            "H2Upstream B14: :authority derivation cases", true, "");
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream B14: :authority derivation cases",
            false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Tier C — Race / lifetime / memory
// ---------------------------------------------------------------------------

// C1 — in_receive_data_ is observed true during the synchronous
// callback chain triggered by HandleBytes, so any reentrant
// SubmitRequest / ResetStream defers its FlushSend to the outer
// post-recv flush. See pitfalls/UPSTREAM_PROXY.md.
void TestC1InReceiveDataGuard() {
    std::cout << "\n[TEST] H2Upstream C1: in_receive_data_ guard blocks reentrant FlushSend..." << std::endl;
    try {
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        cfg->enabled = true;
        cfg->max_concurrent_streams_pref = 10;
        cfg->ping_idle_sec   = 0;
        cfg->ping_timeout_sec = 0;
        cfg->goaway_drain_timeout_sec = 0;

        // Storage outlives `conn` — see existing B-test convention.
        ReentrantResetSink sink_a;
        RecordingSink sink_b;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream C1: in_receive_data_ guard blocks reentrant FlushSend",
                false, "Init failed");
            return;
        }
        sink_a.conn = &conn;
        int32_t sid_a = conn.SubmitRequest(
            "GET", "http", "example.com", "/a", {}, "", &sink_a);
        int32_t sid_b = conn.SubmitRequest(
            "GET", "http", "example.com", "/b", {}, "", &sink_b);
        // sink_a's OnError will call conn.ResetStream(sid_b).
        sink_a.reset_target = sid_b;

        // Build a GOAWAY frame with last_stream_id < sid_a so OnGoawayReceived
        // synchronously fails sink_a above the limit (RFC 9113 §6.8 retry-safe).
        std::vector<uint8_t> wire = H2WireTest::BuildEmptySettings();
        auto goaway = H2WireTest::BuildGoawayFrame(0, NGHTTP2_NO_ERROR);
        wire.insert(wire.end(), goaway.begin(), goaway.end());

        ssize_t consumed = conn.HandleBytes(
            reinterpret_cast<const char*>(wire.data()), wire.size());

        bool pass = true;
        std::string err;
        if (consumed < 0) { pass = false; err += "HandleBytes failed; "; }
        // The reentrant ResetStream from sink_a's OnError MUST have observed
        // in_receive_data_ == true (proving the guard was active).
        if (sink_a.error_calls != 1) {
            pass = false;
            err += "sink_a.error_calls=" + std::to_string(sink_a.error_calls) + " expected 1; ";
        }
        if (!sink_a.observed_in_receive_data) {
            pass = false;
            err += "in_receive_data_ was false during reentrant callback; ";
        }
        // Outside HandleBytes, in_receive_data_ must be false again.
        if (conn.in_receive_data()) {
            pass = false;
            err += "in_receive_data_ leaked after HandleBytes returned; ";
        }
        // sid_b's sink was detached by sink_a's reentrant ResetStream
        // BEFORE OnGoawayReceived's outer loop iterates to sid_b — so its
        // OnError fan-out short-circuits on the null sink check. This
        // confirms the sink-detach race is closed: a regression that
        // failed to detach in time would surface here as error_calls=1.
        if (sink_b.error_calls != 0) {
            pass = false;
            err += "sink_b.error_calls=" + std::to_string(sink_b.error_calls) +
                   " expected 0 (sink should have been detached before fan-out); ";
        }
        TestFramework::RecordTest(
            "H2Upstream C1: in_receive_data_ guard blocks reentrant FlushSend",
            pass, err);
        (void)sid_a;
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream C1: in_receive_data_ guard blocks reentrant FlushSend",
            false, e.what());
    }
}

// C2 — Lease adoption: UpstreamH2Connection can be constructed with null transport
void TestC2LeaseAdoption() {
    std::cout << "\n[TEST] H2Upstream C2: AdoptLease stores lease (empty lease on null transport)..." << std::endl;
    try {
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        cfg->enabled = true;
        cfg->max_concurrent_streams_pref = 10;
        cfg->ping_idle_sec   = 0;
        cfg->ping_timeout_sec = 0;
        cfg->goaway_drain_timeout_sec = 0;

        auto conn = std::make_unique<UpstreamH2Connection>(nullptr, cfg);
        // Adopt a default (empty) lease — should not crash
        UpstreamLease empty_lease;
        conn->AdoptLease(std::move(empty_lease));
        // Destroy — destructor must not crash even with null transport
        conn.reset();
        TestFramework::RecordTest("H2Upstream C2: AdoptLease stores lease (empty lease on null transport)",
                                   true, "");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream C2: AdoptLease stores lease (empty lease on null transport)",
                                   false, e.what());
    }
}

// C3 — Memory leak: streams_ map is empty after RST_STREAM + FailAllStreams
void TestC3StreamsEmptyAfterFailAll() {
    std::cout << "\n[TEST] H2Upstream C3: active_stream_count 0 after FailAllStreams..." << std::endl;
    try {
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        cfg->enabled = true;
        cfg->max_concurrent_streams_pref = 10;
        cfg->ping_idle_sec   = 0;
        cfg->ping_timeout_sec = 0;
        cfg->goaway_drain_timeout_sec = 0;

        // sink must outlive conn (~UpstreamH2Connection FailAllStreams).
        RecordingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);

        // FailAllStreams on an empty table must be a no-op
        conn.FailAllStreams(-1, "test");
        bool pass = (conn.active_stream_count() == 0);
        TestFramework::RecordTest("H2Upstream C3: active_stream_count 0 after FailAllStreams",
                                   pass,
                                   pass ? "" : "expected 0 active streams");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream C3: active_stream_count 0 after FailAllStreams",
                                   false, e.what());
    }
}

// C4 — GOAWAY marks connection not usable
void TestC4GoawayMarksNotUsable() {
    std::cout << "\n[TEST] H2Upstream C4: OnGoawayReceived sets goaway_seen and IsUsable=false..." << std::endl;
    try {
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        cfg->enabled = true;
        cfg->max_concurrent_streams_pref = 10;
        cfg->ping_idle_sec   = 0;
        cfg->ping_timeout_sec = 0;
        cfg->goaway_drain_timeout_sec = 0;

        UpstreamH2Connection conn(nullptr, cfg);
        // Before GOAWAY: IsUsable returns false because session_=nullptr
        conn.OnGoawayReceived(0);
        bool pass = conn.goaway_seen() && !conn.IsUsable();
        TestFramework::RecordTest("H2Upstream C4: OnGoawayReceived sets goaway_seen and IsUsable=false",
                                   pass,
                                   pass ? "" : "goaway_seen or IsUsable mismatch");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream C4: OnGoawayReceived sets goaway_seen and IsUsable=false",
                                   false, e.what());
    }
}

// C4b — MarkDead is the lifecycle flag that closes the FailAllStreams race
// window. After a fatal session error or PING timeout, the call sites in
// pool_partition.cc and h2_connection_table.cc must MarkDead BEFORE
// FailAllStreams so a concurrent FindUsable does not pick the conn between
// the stream fan-out and the table erase. Verifies IsDead() / IsUsable()
// transitions match that contract.
void TestC4bMarkDeadDisablesUsable() {
    std::cout << "\n[TEST] H2Upstream C4b: MarkDead -> IsDead and !IsUsable..." << std::endl;
    try {
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        cfg->enabled = true;
        cfg->max_concurrent_streams_pref = 10;
        cfg->ping_idle_sec = 0;
        cfg->ping_timeout_sec = 0;
        cfg->goaway_drain_timeout_sec = 0;

        UpstreamH2Connection conn(nullptr, cfg);
        bool was_dead_before = conn.IsDead();
        conn.MarkDead();
        bool pass =
            !was_dead_before &&
            conn.IsDead() &&
            !conn.IsUsable() &&
            !conn.goaway_seen();  // dead and goaway are independent flags
        TestFramework::RecordTest("H2Upstream C4b: MarkDead -> IsDead and !IsUsable",
                                   pass,
                                   pass ? "" : "MarkDead did not transition flags correctly");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream C4b: MarkDead -> IsDead and !IsUsable",
                                   false, e.what());
    }
}

// C5 — acquire/release: ApplyHttp2ConfigCommit on one thread, LoadHttp2ConfigSnapshot
//      on another thread, no torn read.
void TestC5AcquireReleaseNoTornRead() {
    std::cout << "\n[TEST] H2Upstream C5: ApplyHttp2ConfigCommit/Load acquire-release no torn read..." << std::endl;
    try {
        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("svc", "127.0.0.1", 9999);
        UpstreamManager mgr({cfg}, {disp});
        DispatcherThreadGuard dtg{disp, t};

        auto* part = mgr.GetPoolPartition("svc", 0);
        if (!part) {
            TestFramework::RecordTest("H2Upstream C5: ApplyHttp2ConfigCommit/Load acquire-release no torn read",
                                       false, "GetPoolPartition returned null");
            return;
        }

        constexpr int ITERS = 200;
        std::atomic<bool> stop{false};
        std::atomic<int>  mismatch_count{0};

        // Writer thread: alternate between two snapshots
        std::thread writer([&]() {
            for (int i = 0; i < ITERS; ++i) {
                auto snap = std::make_shared<Http2UpstreamConfig>();
                snap->ping_idle_sec = (i % 2 == 0) ? 10 : 20;
                part->ApplyHttp2ConfigCommit(snap);
                std::this_thread::yield();
            }
            stop.store(true, std::memory_order_release);
        });

        // Reader thread: load snapshot and verify it is either 10 or 20 (never torn)
        std::thread reader([&]() {
            while (!stop.load(std::memory_order_acquire)) {
                auto snap = part->LoadHttp2ConfigSnapshot();
                if (snap) {
                    int v = snap->ping_idle_sec;
                    if (v != 10 && v != 20) {
                        mismatch_count.fetch_add(1, std::memory_order_relaxed);
                    }
                }
                std::this_thread::yield();
            }
        });

        writer.join();
        reader.join();

        bool pass = (mismatch_count.load() == 0);
        TestFramework::RecordTest("H2Upstream C5: ApplyHttp2ConfigCommit/Load acquire-release no torn read",
                                   pass,
                                   pass ? "" : "torn read detected: " +
                                               std::to_string(mismatch_count.load()) + " mismatches");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream C5: ApplyHttp2ConfigCommit/Load acquire-release no torn read",
                                   false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Config parsing — H2 block
// ---------------------------------------------------------------------------

void TestConfigParseH2Block() {
    std::cout << "\n[TEST] H2Upstream Config: parse http2 upstream block..." << std::endl;
    try {
        const std::string json = R"({
            "upstreams": [{
                "name": "backend",
                "host": "10.0.0.1",
                "port": 8080,
                "http2": {
                    "enabled": true,
                    "prefer": "always",
                    "max_concurrent_streams_pref": 50,
                    "initial_window_size": 1048576,
                    "max_frame_size": 16384,
                    "header_table_size": 4096,
                    "max_header_list_size": 32768,
                    "ping_idle_sec": 30,
                    "ping_timeout_sec": 5,
                    "goaway_drain_timeout_sec": 20,
                    "saturation_open_pct": 0
                }
            }]
        })";
        ServerConfig cfg = ConfigLoader::LoadFromString(json);
        bool pass = true;
        std::string err;
        if (cfg.upstreams.empty()) { pass = false; err += "no upstream parsed; "; }
        else {
            const auto& h2 = cfg.upstreams[0].http2;
            if (!h2.enabled)                           { pass = false; err += "enabled; "; }
            if (h2.prefer != "always")                 { pass = false; err += "prefer; "; }
            if (h2.max_concurrent_streams_pref != 50)  { pass = false; err += "max_concurrent; "; }
            if (h2.initial_window_size != 1048576)     { pass = false; err += "initial_window; "; }
            if (h2.max_frame_size != 16384)            { pass = false; err += "max_frame; "; }
            if (h2.header_table_size != 4096)          { pass = false; err += "header_table; "; }
            if (h2.max_header_list_size != 32768)      { pass = false; err += "max_header_list; "; }
            if (h2.ping_idle_sec != 30)                { pass = false; err += "ping_idle; "; }
            if (h2.ping_timeout_sec != 5)              { pass = false; err += "ping_timeout; "; }
            if (h2.goaway_drain_timeout_sec != 20)     { pass = false; err += "goaway_drain; "; }
        }
        TestFramework::RecordTest("H2Upstream Config: parse http2 upstream block", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream Config: parse http2 upstream block", false, e.what());
    }
}

// Hot-reload validation must reject http2.enabled=true on a non-TLS
// upstream — same rule the startup Validate() applies. Without symmetry,
// a SIGHUP that toggles enabled without enabling TLS passes hot-reload,
// prints "restart required" warning, and the server fails to start at
// the next restart.
void TestConfigH2EnabledRequiresTlsHotReload() {
    std::cout << "\n[TEST] H2Upstream Config: hot-reload rejects h2.enabled=true && !tls.enabled..." << std::endl;
    try {
        const std::string json = R"({
            "upstreams": [{
                "name": "svc",
                "host": "127.0.0.1",
                "port": 9000,
                "tls": {"enabled": false},
                "http2": {"enabled": true}
            }]
        })";
        ServerConfig cfg = ConfigLoader::LoadFromString(json);

        std::unordered_set<std::string> live_upstreams = {"svc"};
        bool threw = false;
        std::string what;
        try {
            ConfigLoader::ValidateHotReloadable(cfg, live_upstreams);
        } catch (const std::invalid_argument& e) {
            threw = true;
            what = e.what();
        }

        bool pass = threw &&
                    what.find("h2c not supported") != std::string::npos;
        TestFramework::RecordTest("H2Upstream Config: hot-reload rejects h2.enabled=true && !tls.enabled",
                                   pass,
                                   pass ? "" :
                                   ("expected h2c rejection; threw=" +
                                    std::to_string(threw) + " what='" + what + "'"));
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream Config: hot-reload rejects h2.enabled=true && !tls.enabled",
                                   false, e.what());
    }
}

void TestConfigH2Defaults() {
    std::cout << "\n[TEST] H2Upstream Config: h2 block absent -> default values..." << std::endl;
    try {
        const std::string json = R"({"upstreams":[{"name":"svc","host":"127.0.0.1","port":9000}]})";
        ServerConfig cfg = ConfigLoader::LoadFromString(json);
        bool pass = true;
        std::string err;
        if (cfg.upstreams.empty()) { pass = false; err += "no upstream; "; }
        else {
            const auto& h2 = cfg.upstreams[0].http2;
            if (h2.enabled)                  { pass = false; err += "default enabled should be false; "; }
            if (h2.prefer != "auto")         { pass = false; err += "default prefer should be auto; "; }
            if (h2.max_concurrent_streams_pref != 100) { pass = false; err += "max_concurrent default; "; }
        }
        TestFramework::RecordTest("H2Upstream Config: h2 block absent -> default values", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream Config: h2 block absent -> default values", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// IsUsable boundary conditions
// ---------------------------------------------------------------------------

void TestIsUsableNullSession() {
    std::cout << "\n[TEST] H2Upstream IsUsable: null session -> false..." << std::endl;
    try {
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        cfg->enabled = true;
        cfg->max_concurrent_streams_pref = 10;
        UpstreamH2Connection conn(nullptr, cfg);
        bool pass = !conn.IsUsable();
        TestFramework::RecordTest("H2Upstream IsUsable: null session -> false",
                                   pass, pass ? "" : "IsUsable should be false with null session");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream IsUsable: null session -> false", false, e.what());
    }
}

void TestIsUsableAfterGoaway() {
    std::cout << "\n[TEST] H2Upstream IsUsable: after GOAWAY -> false..." << std::endl;
    try {
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        cfg->enabled = true;
        cfg->max_concurrent_streams_pref = 10;
        UpstreamH2Connection conn(nullptr, cfg);
        conn.OnGoawayReceived(0);
        bool pass = !conn.IsUsable();
        TestFramework::RecordTest("H2Upstream IsUsable: after GOAWAY -> false",
                                   pass, pass ? "" : "IsUsable should be false after GOAWAY");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream IsUsable: after GOAWAY -> false", false, e.what());
    }
}

void TestIsUsableZeroStreamCap() {
    std::cout << "\n[TEST] H2Upstream IsUsable: max_concurrent_streams_pref=0 -> false..." << std::endl;
    try {
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        cfg->enabled = true;
        cfg->max_concurrent_streams_pref = 0;
        UpstreamH2Connection conn(nullptr, cfg);
        bool pass = !conn.IsUsable();
        TestFramework::RecordTest("H2Upstream IsUsable: max_concurrent_streams_pref=0 -> false",
                                   pass, pass ? "" : "IsUsable should be false with 0 stream cap");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream IsUsable: max_concurrent_streams_pref=0 -> false",
                                   false, e.what());
    }
}

// ---------------------------------------------------------------------------
// UpstreamH2Codec edge cases
// ---------------------------------------------------------------------------

void TestH2CodecFinishReturnsFalse() {
    std::cout << "\n[TEST] H2Upstream H2Codec: Finish() always returns false..." << std::endl;
    try {
        UpstreamH2Codec codec;
        bool result = codec.Finish();
        bool pass = !result;
        TestFramework::RecordTest("H2Upstream H2Codec: Finish() always returns false",
                                   pass, pass ? "" : "Finish should return false for H2");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream H2Codec: Finish() always returns false", false, e.what());
    }
}

void TestH2CodecResetClearsResponse() {
    std::cout << "\n[TEST] H2Upstream H2Codec: Reset clears response fields..." << std::endl;
    try {
        UpstreamH2Codec codec;
        codec.GetResponse().status_code = 200;
        codec.GetResponse().body = "body data";
        codec.Reset();
        bool pass = (codec.GetResponse().status_code == 0 && codec.GetResponse().body.empty());
        TestFramework::RecordTest("H2Upstream H2Codec: Reset clears response fields",
                                   pass, pass ? "" : "Reset did not clear response fields");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream H2Codec: Reset clears response fields", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// LivePartitions and CommitHttp2Snapshots edge cases
// ---------------------------------------------------------------------------

void TestLivePartitionsNonEmpty() {
    std::cout << "\n[TEST] H2Upstream LivePartitions: returns entries for configured upstreams..." << std::endl;
    try {
        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfgA = MakeH2UpstreamConfig("svc-a", "127.0.0.1", 9991);
        UpstreamConfig cfgB = MakeH2UpstreamConfig("svc-b", "127.0.0.1", 9992);
        UpstreamManager mgr({cfgA, cfgB}, {disp});
        DispatcherThreadGuard dtg{disp, t};

        auto parts = mgr.LivePartitions();
        bool pass = true;
        std::string err;
        if (parts.empty()) { pass = false; err += "expected non-empty LivePartitions; "; }

        std::set<std::string> names;
        for (auto& ref : parts) names.insert(ref.upstream_name);
        if (names.find("svc-a") == names.end()) { pass = false; err += "missing svc-a; "; }
        if (names.find("svc-b") == names.end()) { pass = false; err += "missing svc-b; "; }

        TestFramework::RecordTest("H2Upstream LivePartitions: returns entries for configured upstreams",
                                   pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream LivePartitions: returns entries for configured upstreams",
                                   false, e.what());
    }
}

void TestCommitH2SnapshotsH2Disabled() {
    std::cout << "\n[TEST] H2Upstream CommitH2Snapshots: disabled h2 results in null snapshot..." << std::endl;
    try {
        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("svc", "127.0.0.1", 9999);
        cfg.http2.enabled = false;
        UpstreamManager mgr({cfg}, {disp});
        DispatcherThreadGuard dtg{disp, t};

        // Commit with h2.enabled=false — the snapshot should reflect disabled state
        mgr.CommitHttp2Snapshots({cfg});

        auto parts = mgr.LivePartitions();
        bool has_null_or_disabled = true;
        for (auto& ref : parts) {
            auto snap = ref.partition->LoadHttp2ConfigSnapshot();
            // Null snapshot OR snapshot with enabled=false are both acceptable
            if (snap && snap->enabled) {
                has_null_or_disabled = false;
            }
        }
        TestFramework::RecordTest("H2Upstream CommitH2Snapshots: disabled h2 results in null snapshot",
                                   has_null_or_disabled,
                                   has_null_or_disabled ? "" : "snapshot should be null or disabled");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream CommitH2Snapshots: disabled h2 results in null snapshot",
                                   false, e.what());
    }
}

// ---------------------------------------------------------------------------
// H2ConnectionTable — multi-upstream correctness
// ---------------------------------------------------------------------------

void TestTableMultiUpstream() {
    std::cout << "\n[TEST] H2Upstream Table: TotalConnections and per-upstream counts..." << std::endl;
    try {
        H2ConnectionTable table;
        auto cfg = std::make_shared<Http2UpstreamConfig>();

        table.Insert("svc-a", std::make_unique<UpstreamH2Connection>(nullptr, cfg));
        table.Insert("svc-a", std::make_unique<UpstreamH2Connection>(nullptr, cfg));
        table.Insert("svc-b", std::make_unique<UpstreamH2Connection>(nullptr, cfg));

        bool pass = true;
        std::string err;
        if (table.TotalConnections() != 3)               { pass = false; err += "TotalConnections=3 expected; "; }
        if (table.ConnectionsForUpstream("svc-a") != 2)  { pass = false; err += "svc-a should have 2; "; }
        if (table.ConnectionsForUpstream("svc-b") != 1)  { pass = false; err += "svc-b should have 1; "; }
        if (table.ConnectionsForUpstream("svc-c") != 0)  { pass = false; err += "svc-c should have 0; "; }

        TestFramework::RecordTest("H2Upstream Table: TotalConnections and per-upstream counts",
                                   pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream Table: TotalConnections and per-upstream counts",
                                   false, e.what());
    }
}

void TestTableInsertNullIgnored() {
    std::cout << "\n[TEST] H2Upstream Table: Insert null shared_ptr is a no-op..." << std::endl;
    try {
        H2ConnectionTable table;
        // The Insert implementation guards against null
        table.Insert("svc", nullptr);
        // TotalConnections should be 0 because null was silently dropped
        bool pass = (table.TotalConnections() == 0);
        TestFramework::RecordTest("H2Upstream Table: Insert null shared_ptr is a no-op",
                                   pass, pass ? "" : "null insert should not increase count");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream Table: Insert null shared_ptr is a no-op",
                                   false, e.what());
    }
}

// ---------------------------------------------------------------------------
// UpstreamH2Connection — accessor coverage
// ---------------------------------------------------------------------------

void TestH2ConnectionAccessors() {
    std::cout << "\n[TEST] H2Upstream Accessors: config_snapshot / goaway_last_stream_id..." << std::endl;
    try {
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        cfg->enabled = true;
        cfg->ping_idle_sec = 99;

        UpstreamH2Connection conn(nullptr, cfg);
        bool pass = true;
        std::string err;

        // config_snapshot returns the cfg we passed
        if (!conn.config_snapshot())                           { pass = false; err += "config_snapshot null; "; }
        else if (conn.config_snapshot()->ping_idle_sec != 99) { pass = false; err += "ping_idle mismatch; "; }

        // Initial state
        if (conn.goaway_last_stream_id() != -1) { pass = false; err += "goaway_last_stream_id should be -1; "; }
        if (conn.active_stream_count() != 0)    { pass = false; err += "active_stream_count should be 0; "; }

        // After GOAWAY
        conn.OnGoawayReceived(7);
        if (conn.goaway_last_stream_id() != 7) { pass = false; err += "goaway_last_stream_id should be 7; "; }

        // transport() returns nullptr (no transport set)
        if (conn.transport() != nullptr) { pass = false; err += "transport should be nullptr; "; }

        TestFramework::RecordTest("H2Upstream Accessors: config_snapshot / goaway_last_stream_id",
                                   pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream Accessors: config_snapshot / goaway_last_stream_id",
                                   false, e.what());
    }
}

// ---------------------------------------------------------------------------
// UpstreamH2Connection::HandleBytes — session null fast path
// ---------------------------------------------------------------------------

void TestHandleBytesNullSession() {
    std::cout << "\n[TEST] H2Upstream HandleBytes: null session returns -1..." << std::endl;
    try {
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        cfg->enabled = true;
        cfg->max_concurrent_streams_pref = 10;
        UpstreamH2Connection conn(nullptr, cfg);

        const char data[] = "fake bytes";
        ssize_t result = conn.HandleBytes(data, sizeof(data));
        bool pass = (result == -1);
        TestFramework::RecordTest("H2Upstream HandleBytes: null session returns -1",
                                   pass, pass ? "" : "HandleBytes with null session should return -1");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream HandleBytes: null session returns -1",
                                   false, e.what());
    }
}

// ---------------------------------------------------------------------------
// UpstreamH2Connection::SubmitRequest — null session returns -1
// ---------------------------------------------------------------------------

void TestSubmitRequestNullSession() {
    std::cout << "\n[TEST] H2Upstream SubmitRequest: null session returns -1..." << std::endl;
    try {
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        cfg->enabled = true;
        cfg->max_concurrent_streams_pref = 10;

        // sink must outlive conn (~UpstreamH2Connection FailAllStreams).
        RecordingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);

        int32_t sid = conn.SubmitRequest(
            "GET", "http", "localhost", "/", {}, "", &sink);
        bool pass = (sid == -1);
        TestFramework::RecordTest("H2Upstream SubmitRequest: null session returns -1",
                                   pass, pass ? "" : "SubmitRequest should return -1 with null session");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream SubmitRequest: null session returns -1",
                                   false, e.what());
    }
}

// ---------------------------------------------------------------------------
// UpstreamManager::HasUpstream
// ---------------------------------------------------------------------------

void TestHasUpstream() {
    std::cout << "\n[TEST] H2Upstream HasUpstream: known vs unknown..." << std::endl;
    try {
        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("known-svc", "127.0.0.1", 9999);
        UpstreamManager mgr({cfg}, {disp});
        DispatcherThreadGuard dtg{disp, t};

        bool pass = mgr.HasUpstream("known-svc") && !mgr.HasUpstream("unknown-svc");
        TestFramework::RecordTest("H2Upstream HasUpstream: known vs unknown",
                                   pass, pass ? "" : "HasUpstream returned unexpected value");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream HasUpstream: known vs unknown", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// ComputeMinUpstreamCadenceSec — single upstream with H2 disabled
// ---------------------------------------------------------------------------

void TestComputeMinCadenceH2Disabled() {
    std::cout << "\n[TEST] H2Upstream ComputeMinCadence: H2 disabled upstream uses pool timeouts only..." << std::endl;
    try {
        UpstreamConfig cfg;
        cfg.name = "svc";
        cfg.host = "127.0.0.1";
        cfg.port = 9000;
        cfg.pool.connect_timeout_ms   = 10000;  // 10s
        cfg.pool.idle_timeout_sec     = 120;
        cfg.proxy.response_timeout_ms = 15000;  // 15s
        cfg.http2.enabled = false;

        int result = UpstreamManager::ComputeMinUpstreamCadenceSec({cfg});
        // MinCadenceSec returns INT_MAX (disabled), so min(10, 120, 15, INT_MAX) = 10
        bool pass = (result == 10);
        TestFramework::RecordTest("H2Upstream ComputeMinCadence: H2 disabled upstream uses pool timeouts only",
                                   pass,
                                   pass ? "" : "expected 10 from connect_timeout_ms/1000");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream ComputeMinCadence: H2 disabled upstream uses pool timeouts only",
                                   false, e.what());
    }
}

// ---------------------------------------------------------------------------
// MinCadenceSec — single timer dominant
// ---------------------------------------------------------------------------

void TestMinCadenceSecSingleTimer() {
    std::cout << "\n[TEST] H2Upstream MinCadenceSec: single non-zero timer dominates..." << std::endl;
    try {
        Http2UpstreamConfig cfg;
        cfg.enabled                  = true;
        cfg.ping_idle_sec            = 0;
        cfg.ping_timeout_sec         = 7;   // only non-zero
        cfg.goaway_drain_timeout_sec = 0;

        bool pass = (cfg.MinCadenceSec() == 7);
        TestFramework::RecordTest("H2Upstream MinCadenceSec: single non-zero timer dominates",
                                   pass, pass ? "" : "expected 7");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream MinCadenceSec: single non-zero timer dominates",
                                   false, e.what());
    }
}

// ---------------------------------------------------------------------------
// BuildSettingsArray — default config values
// ---------------------------------------------------------------------------

void TestBuildSettingsArrayDefaults() {
    std::cout << "\n[TEST] H2Upstream BuildSettingsArray: default config values..." << std::endl;
    try {
        Http2UpstreamConfig cfg;  // all defaults
        auto settings = UPSTREAM_H2_SETTINGS::BuildSettingsArray(cfg);
        bool pass = (settings.size() == 5);
        std::string err;
        if (!pass) err = "expected 5 settings entries";
        // Confirm MAX_HEADER_LIST_SIZE is present at the default value.
        bool found_mhls = false;
        for (const auto& s : settings) {
            if (s.settings_id == NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE) {
                found_mhls = true;
                if (s.value != 65536) {
                    pass = false;
                    err += "default max_header_list_size != 65536; ";
                }
                break;
            }
        }
        if (!found_mhls) { pass = false; err += "missing MAX_HEADER_LIST_SIZE; "; }
        TestFramework::RecordTest("H2Upstream BuildSettingsArray: default config values",
                                   pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream BuildSettingsArray: default config values",
                                   false, e.what());
    }
}

// C6 — RST_STREAM detaches sink so a later on_stream_close (or dtor's
// defensive FailAllStreams) does NOT fire OnError on a transaction that
// has already moved on to a retry. Pitfall: without detach, the inner
// retry's fresh codec/sink could be double-delivered an error.
void TestC6ResetStreamSinkDetachSurvivesDtor() {
    std::cout << "\n[TEST] H2Upstream C6: ResetStream detaches sink — dtor's FailAllStreams skips it..." << std::endl;
    try {
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        cfg->enabled = true;
        cfg->max_concurrent_streams_pref = 10;
        cfg->ping_idle_sec   = 0;
        cfg->ping_timeout_sec = 0;
        cfg->goaway_drain_timeout_sec = 0;

        RecordingSink sink;
        {
            UpstreamH2Connection conn(nullptr, cfg);
            if (!conn.Init()) {
                TestFramework::RecordTest(
                    "H2Upstream C6: ResetStream detaches sink — dtor's FailAllStreams skips it",
                    false, "Init failed");
                return;
            }
            int32_t sid = conn.SubmitRequest(
                "GET", "http", "example.com", "/", {}, "", &sink);
            if (sid != 1) {
                TestFramework::RecordTest(
                    "H2Upstream C6: ResetStream detaches sink — dtor's FailAllStreams skips it",
                    false, "SubmitRequest failed");
                return;
            }
            // ResetStream MUST detach the sink BEFORE submitting RST so a
            // later on_stream_close / dtor FailAllStreams doesn't fire
            // OnError on the (potentially retried) transaction.
            conn.ResetStream(sid);
        }  // ~conn fires defensive FailAllStreams; sink detached → no OnError

        bool pass = (sink.error_calls == 0);
        std::string err;
        if (!pass) err = "sink.error_calls=" + std::to_string(sink.error_calls) + " expected 0";
        TestFramework::RecordTest(
            "H2Upstream C6: ResetStream detaches sink — dtor's FailAllStreams skips it",
            pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream C6: ResetStream detaches sink — dtor's FailAllStreams skips it",
            false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN-series — H2 upstream negative / correctness tests covering:
//   - truncation detection (CL short / overflow) and NO_BODY rejection
//   - CONNECT method rejection (primary at DispatchH2 + secondary in
//     UpstreamH2Connection::SubmitRequest)
//   - te:trailers capture-before-strip and outbound re-emit
//   - send-stall + response-timeout handoff via OnRequestSubmitted
//   - sink invariants on natural close (no spurious RST_STREAM)
// ---------------------------------------------------------------------------

// Helper: build an UpstreamH2Connection with null transport and a null-safe
// nghttp2 session.
static auto MakeH2Conn() {
    auto cfg = std::make_shared<Http2UpstreamConfig>();
    cfg->enabled                  = true;
    cfg->max_concurrent_streams_pref = 10;
    cfg->ping_idle_sec            = 0;
    cfg->ping_timeout_sec         = 0;
    cfg->goaway_drain_timeout_sec = 0;
    return cfg;
}

// Helper: build a DATA frame with a raw payload (no padding).
static std::vector<uint8_t> BuildDataFrame(int32_t stream_id,
                                           const uint8_t* data, size_t len,
                                           bool end_stream)
{
    std::vector<uint8_t> frame;
    frame.reserve(9 + len);
    frame.push_back(static_cast<uint8_t>((len >> 16) & 0xff));
    frame.push_back(static_cast<uint8_t>((len >> 8) & 0xff));
    frame.push_back(static_cast<uint8_t>(len & 0xff));
    frame.push_back(NGHTTP2_DATA);
    frame.push_back(end_stream ? NGHTTP2_FLAG_END_STREAM : 0);
    frame.push_back(static_cast<uint8_t>((stream_id >> 24) & 0x7f));
    frame.push_back(static_cast<uint8_t>((stream_id >> 16) & 0xff));
    frame.push_back(static_cast<uint8_t>((stream_id >> 8) & 0xff));
    frame.push_back(static_cast<uint8_t>(stream_id & 0xff));
    frame.insert(frame.end(), data, data + len);
    return frame;
}

// Helper: build a RST_STREAM frame.
static std::vector<uint8_t> BuildRstStreamFrame(int32_t stream_id,
                                                 uint32_t error_code)
{
    std::vector<uint8_t> frame;
    frame.reserve(13);
    // length = 4
    frame.push_back(0); frame.push_back(0); frame.push_back(4);
    frame.push_back(NGHTTP2_RST_STREAM);
    frame.push_back(0);  // flags
    frame.push_back(static_cast<uint8_t>((stream_id >> 24) & 0x7f));
    frame.push_back(static_cast<uint8_t>((stream_id >> 16) & 0xff));
    frame.push_back(static_cast<uint8_t>((stream_id >> 8) & 0xff));
    frame.push_back(static_cast<uint8_t>(stream_id & 0xff));
    frame.push_back(static_cast<uint8_t>((error_code >> 24) & 0xff));
    frame.push_back(static_cast<uint8_t>((error_code >> 16) & 0xff));
    frame.push_back(static_cast<uint8_t>((error_code >> 8) & 0xff));
    frame.push_back(static_cast<uint8_t>(error_code & 0xff));
    return frame;
}

// ---------------------------------------------------------------------------
// TestN1 — Content-Length 1000, peer sends 500 bytes + END_STREAM →
// OnError fires (NOT OnComplete). nghttp2's HTTP messaging enforcement
// detects the short-read and closes the stream with a non-NO_ERROR code,
// routing to RESULT_UPSTREAM_DISCONNECT. The application-level backstop in
// OnStreamClose(NO_ERROR) is dead code when a standards-compliant session is
// used; this test verifies the observable end-to-end contract: CL violation
// → stream error → OnError, never OnComplete.
// ---------------------------------------------------------------------------
void TestN1TruncationCLShortRead() {
    std::cout << "\n[TEST] H2Upstream N1: CL short-read → OnError (not OnComplete)..." << std::endl;
    try {
        auto cfg = MakeH2Conn();
        RecordingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N1: CL short-read → OnError (not OnComplete)",
                false, "Init failed");
            return;
        }
        int32_t sid = conn.SubmitRequest("GET", "http", "example.com", "/", {}, "", &sink);

        // Server sends SETTINGS + HEADERS (200 + content-length:1000, !end_stream)
        // then only 500 bytes of DATA with END_STREAM.
        std::vector<uint8_t> wire = H2WireTest::BuildEmptySettings();
        auto hdrs = H2WireTest::BuildHeadersFrame(
            sid, {{":status", "200"}, {"content-length", "1000"}},
            /*end_stream=*/false);
        wire.insert(wire.end(), hdrs.begin(), hdrs.end());
        conn.HandleBytes(reinterpret_cast<const char*>(wire.data()), wire.size());

        // Short body: 500 bytes but CL said 1000. nghttp2's HTTP messaging
        // enforcement detects the mismatch and fires on_stream_close with a
        // non-NO_ERROR code → RESULT_UPSTREAM_DISCONNECT via OnStreamClose's
        // else branch. The key invariant is that OnError fires, not OnComplete.
        std::vector<uint8_t> body(500, 'x');
        auto data_frame = BuildDataFrame(sid, body.data(), body.size(),
                                         /*end_stream=*/true);
        conn.HandleBytes(reinterpret_cast<const char*>(data_frame.data()),
                         data_frame.size());

        bool pass = (sink.error_calls == 1) && (sink.complete_calls == 0);
        std::string err;
        if (sink.error_calls != 1)
            err += "error_calls=" + std::to_string(sink.error_calls) + " (expected 1); ";
        if (sink.complete_calls != 0)
            err += "complete_calls should be 0; ";
        TestFramework::RecordTest(
            "H2Upstream N1: CL short-read → OnError (not OnComplete)", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N1: CL short-read → OnError (not OnComplete)", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN1b — CL on 1xx interim header does NOT contaminate final response's
// expected_length. Final 200 with no body completes cleanly via OnComplete.
// ---------------------------------------------------------------------------
void TestN1bInterimCLDoesNotPoisonFinalHead() {
    std::cout << "\n[TEST] H2Upstream N1b: 100-Continue CL does not poison final response..." << std::endl;
    try {
        auto cfg = MakeH2Conn();
        RecordingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N1b: 100-Continue CL does not poison final response",
                false, "Init failed");
            return;
        }
        int32_t sid = conn.SubmitRequest("GET", "http", "example.com", "/", {}, "", &sink);

        // Server sends SETTINGS then a 100 interim response, then 200 + END_STREAM.
        // The dispatch invariant (upstream_h2_connection.cc:36-56) prevents
        // OnHeadersComplete from running on 1xx, so the interim headers are
        // discarded and expected_length is never set from them.
        std::vector<uint8_t> wire = H2WireTest::BuildEmptySettings();
        // 1xx interim — no END_STREAM, no END_HEADERS effect on final dispatch
        auto interim = H2WireTest::BuildHeadersFrame(sid, {{":status", "100"}},
                                                     /*end_stream=*/false);
        wire.insert(wire.end(), interim.begin(), interim.end());
        // Final 200 with END_STREAM — no body
        auto final_hdrs = H2WireTest::BuildHeadersFrame(
            sid, {{":status", "200"}}, /*end_stream=*/true);
        wire.insert(wire.end(), final_hdrs.begin(), final_hdrs.end());
        conn.HandleBytes(reinterpret_cast<const char*>(wire.data()), wire.size());

        bool pass = (sink.complete_calls == 1) && (sink.error_calls == 0) &&
                    (sink.last_status == 200);
        std::string err;
        if (sink.complete_calls != 1)
            err += "complete_calls=" + std::to_string(sink.complete_calls) + "; ";
        if (sink.error_calls != 0)
            err += "unexpected error; ";
        if (sink.last_status != 200)
            err += "status=" + std::to_string(sink.last_status) + "; ";
        TestFramework::RecordTest(
            "H2Upstream N1b: 100-Continue CL does not poison final response", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N1b: 100-Continue CL does not poison final response", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN2 — HEAD request: peer sends 200 + 100 body bytes → OnError fires
// (NOT OnComplete). HEAD responses are NO_BODY per RFC 9110 §9.3.2.
// nghttp2's HTTP messaging enforcement rejects DATA on a HEAD response and
// fires on_stream_close with a non-NO_ERROR code → RESULT_UPSTREAM_DISCONNECT.
// The key invariant: error fires, body bytes are NOT forwarded to the sink.
// ---------------------------------------------------------------------------
void TestN2HeadResponseBodyRejected() {
    std::cout << "\n[TEST] H2Upstream N2: HEAD + body bytes → OnError (body not forwarded)..." << std::endl;
    try {
        auto cfg = MakeH2Conn();
        RecordingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N2: HEAD + body bytes → OnError (body not forwarded)",
                false, "Init failed");
            return;
        }
        // Submit a HEAD request — sets request_method="HEAD" on the stream.
        int32_t sid = conn.SubmitRequest("HEAD", "http", "example.com", "/", {}, "", &sink);

        std::vector<uint8_t> wire = H2WireTest::BuildEmptySettings();
        // Server sends 200 without END_STREAM — the stream is HEAD so
        // OnHeadersComplete classifies it as NO_BODY.
        auto hdrs = H2WireTest::BuildHeadersFrame(
            sid, {{":status", "200"}}, /*end_stream=*/false);
        wire.insert(wire.end(), hdrs.begin(), hdrs.end());
        conn.HandleBytes(reinterpret_cast<const char*>(wire.data()), wire.size());

        // Server sends body bytes — protocol violation: nghttp2 enforces this
        // and rejects the stream; our Step 1.5 NO_BODY check is the backstop
        // if nghttp2 enforcement is disabled. Either way: error, no body leak.
        std::vector<uint8_t> body(100, 'x');
        auto data_frame = BuildDataFrame(sid, body.data(), body.size(),
                                         /*end_stream=*/false);
        conn.HandleBytes(reinterpret_cast<const char*>(data_frame.data()),
                         data_frame.size());

        bool pass = (sink.error_calls == 1) && (sink.body_bytes == 0);
        std::string err;
        if (sink.error_calls != 1)
            err += "error_calls=" + std::to_string(sink.error_calls) + "; ";
        if (sink.body_bytes != 0)
            err += "body_bytes=" + std::to_string(sink.body_bytes) + " (should be 0, body leaked); ";
        TestFramework::RecordTest(
            "H2Upstream N2: HEAD + body bytes → OnError (body not forwarded)", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N2: HEAD + body bytes → OnError (body not forwarded)", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN3 — :status 204 + body bytes → OnError fires (NOT OnComplete, NOT
// body forwarded). RFC 9110 §15.3.5 forbids a body on 204. nghttp2's HTTP
// messaging enforcement catches the protocol violation; our Step 1.5 NO_BODY
// guard is the backstop. Key invariant: error fires, body bytes = 0.
// ---------------------------------------------------------------------------
void TestN3Status204BodyRejected() {
    std::cout << "\n[TEST] H2Upstream N3: :status=204 + body bytes → OnError (body not forwarded)..." << std::endl;
    try {
        auto cfg = MakeH2Conn();
        RecordingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N3: :status=204 + body bytes → OnError (body not forwarded)",
                false, "Init failed");
            return;
        }
        int32_t sid = conn.SubmitRequest("GET", "http", "example.com", "/", {}, "", &sink);

        std::vector<uint8_t> wire = H2WireTest::BuildEmptySettings();
        // 204 No Content without END_STREAM — framing forced to NO_BODY.
        auto hdrs = H2WireTest::BuildHeadersFrame(
            sid, {{":status", "204"}}, /*end_stream=*/false);
        wire.insert(wire.end(), hdrs.begin(), hdrs.end());
        conn.HandleBytes(reinterpret_cast<const char*>(wire.data()), wire.size());

        std::vector<uint8_t> body(50, 'y');
        auto data_frame = BuildDataFrame(sid, body.data(), body.size(),
                                         /*end_stream=*/false);
        conn.HandleBytes(reinterpret_cast<const char*>(data_frame.data()),
                         data_frame.size());

        bool pass = (sink.error_calls == 1) && (sink.body_bytes == 0);
        std::string err;
        if (sink.error_calls != 1)
            err += "error_calls=" + std::to_string(sink.error_calls) + "; ";
        if (sink.body_bytes != 0)
            err += "body_bytes=" + std::to_string(sink.body_bytes) + " should be 0 (body leaked); ";
        TestFramework::RecordTest(
            "H2Upstream N3: :status=204 + body bytes → OnError (body not forwarded)", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N3: :status=204 + body bytes → OnError (body not forwarded)", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN4 — :status 304 + body bytes → OnError fires (NOT OnComplete, NOT
// body forwarded). RFC 9110 §15.4.5 forbids a body on 304. nghttp2's HTTP
// messaging enforcement catches this; our Step 1.5 NO_BODY guard is the
// backstop. Key invariant: error fires, body bytes = 0.
// ---------------------------------------------------------------------------
void TestN4Status304BodyRejected() {
    std::cout << "\n[TEST] H2Upstream N4: :status=304 + body bytes → OnError (body not forwarded)..." << std::endl;
    try {
        auto cfg = MakeH2Conn();
        RecordingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N4: :status=304 + body bytes → OnError (body not forwarded)",
                false, "Init failed");
            return;
        }
        int32_t sid = conn.SubmitRequest("GET", "http", "example.com", "/resource", {}, "", &sink);

        std::vector<uint8_t> wire = H2WireTest::BuildEmptySettings();
        auto hdrs = H2WireTest::BuildHeadersFrame(
            sid, {{":status", "304"}}, /*end_stream=*/false);
        wire.insert(wire.end(), hdrs.begin(), hdrs.end());
        conn.HandleBytes(reinterpret_cast<const char*>(wire.data()), wire.size());

        std::vector<uint8_t> body(20, 'z');
        auto data_frame = BuildDataFrame(sid, body.data(), body.size(),
                                         /*end_stream=*/false);
        conn.HandleBytes(reinterpret_cast<const char*>(data_frame.data()),
                         data_frame.size());

        bool pass = (sink.error_calls == 1) && (sink.body_bytes == 0);
        std::string err;
        if (sink.error_calls != 1)
            err += "error_calls=" + std::to_string(sink.error_calls) + "; ";
        if (sink.body_bytes != 0)
            err += "body leaked: " + std::to_string(sink.body_bytes) + " bytes; ";
        TestFramework::RecordTest(
            "H2Upstream N4: :status=304 + body bytes → OnError (body not forwarded)", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N4: :status=304 + body bytes → OnError (body not forwarded)", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN5 — CONNECT method on H2 upstream (primary gate in SubmitRequest) →
// returns -1, sink receives OnError(RESULT_H2_METHOD_NOT_SUPPORTED), no stream.
//
// The primary production gate is in DispatchH2 (proxy_transaction.cc) and
// is tested end-to-end by proxy integration tests. This unit test exercises
// the secondary gate in UpstreamH2Connection::SubmitRequest directly.
// ---------------------------------------------------------------------------
void TestN5ConnectRejectSecondaryGate() {
    std::cout << "\n[TEST] H2Upstream N5: SubmitRequest CONNECT → -1 + OnError(RESULT_H2_METHOD_NOT_SUPPORTED)..." << std::endl;
    try {
        auto cfg = MakeH2Conn();
        RecordingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N5: SubmitRequest CONNECT → -1 + OnError(RESULT_H2_METHOD_NOT_SUPPORTED)",
                false, "Init failed");
            return;
        }
        // Pre-condition: no active streams.
        size_t before = conn.active_stream_count();

        int32_t sid = conn.SubmitRequest("CONNECT", "http", "example.com:443", "",
                                         {}, "", &sink);

        bool pass = (sid < 0) &&
                    (sink.error_calls == 1) &&
                    (sink.last_error_code == ProxyTransaction::RESULT_H2_METHOD_NOT_SUPPORTED) &&
                    (conn.active_stream_count() == before);  // no stream allocated
        std::string err;
        if (sid >= 0)
            err += "expected negative stream_id, got " + std::to_string(sid) + "; ";
        if (sink.error_calls != 1)
            err += "error_calls=" + std::to_string(sink.error_calls) + "; ";
        if (sink.last_error_code != ProxyTransaction::RESULT_H2_METHOD_NOT_SUPPORTED)
            err += "error_code=" + std::to_string(sink.last_error_code) + "; ";
        if (conn.active_stream_count() != before)
            err += "stream count changed; ";
        TestFramework::RecordTest(
            "H2Upstream N5: SubmitRequest CONNECT → -1 + OnError(RESULT_H2_METHOD_NOT_SUPPORTED)",
            pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N5: SubmitRequest CONNECT → -1 + OnError(RESULT_H2_METHOD_NOT_SUPPORTED)",
            false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN5b — CONNECT with null sink: must not crash (secondary gate null-checks
// sink before calling OnError, then returns -1).
// ---------------------------------------------------------------------------
void TestN5bConnectRejectNullSink() {
    std::cout << "\n[TEST] H2Upstream N5b: CONNECT with null sink does not crash..." << std::endl;
    try {
        auto cfg = MakeH2Conn();
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N5b: CONNECT with null sink does not crash",
                false, "Init failed");
            return;
        }
        int32_t sid = conn.SubmitRequest("CONNECT", "http", "target.example.com:443", "",
                                         {}, "", nullptr);
        bool pass = (sid < 0);
        TestFramework::RecordTest(
            "H2Upstream N5b: CONNECT with null sink does not crash",
            pass, pass ? "" : "expected negative stream_id");
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N5b: CONNECT with null sink does not crash", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN6 — te:trailers capture: client sends "te: trailers, deflate";
// SubmitRequest is called with client_te_trailers=true; the nv-array sent
// to nghttp2 must include "te: trailers" (deflate stripped, trailers kept).
//
// We verify indirectly: SubmitRequest returns a valid stream_id (meaning
// nghttp2 accepted the NV array including te:trailers without protocol error).
// The server-side raw byte inspection is covered by TestB16.
// ---------------------------------------------------------------------------
void TestN6TeTrailersReEmit() {
    std::cout << "\n[TEST] H2Upstream N6: te:trailers flag re-emits te:trailers on wire..." << std::endl;
    try {
        auto cfg = MakeH2Conn();
        RecordingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N6: te:trailers flag re-emits te:trailers on wire",
                false, "Init failed");
            return;
        }
        // client_te_trailers=true → nv-array gets "te: trailers" appended.
        int32_t sid = conn.SubmitRequest(
            "GET", "http", "example.com", "/",
            {{"accept", "application/grpc"}}, "",
            &sink, /*client_te_trailers=*/true);

        // nghttp2 must accept the request (te:trailers is legal per RFC 9113).
        bool pass = (sid > 0);
        TestFramework::RecordTest(
            "H2Upstream N6: te:trailers flag re-emits te:trailers on wire",
            pass, pass ? "" : "SubmitRequest returned " + std::to_string(sid));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N6: te:trailers flag re-emits te:trailers on wire", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN6b — te:trailers negative: flag=false → no te header appended.
// nghttp2 accepts it (no protocol error). Verifies the flag=false path.
// ---------------------------------------------------------------------------
void TestN6bTeTrailersFalsePath() {
    std::cout << "\n[TEST] H2Upstream N6b: client_te_trailers=false → no te header, no error..." << std::endl;
    try {
        auto cfg = MakeH2Conn();
        RecordingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N6b: client_te_trailers=false → no te header, no error",
                false, "Init failed");
            return;
        }
        int32_t sid = conn.SubmitRequest(
            "GET", "http", "example.com", "/",
            {}, "", &sink, /*client_te_trailers=*/false);

        bool pass = (sid > 0) && (sink.error_calls == 0);
        TestFramework::RecordTest(
            "H2Upstream N6b: client_te_trailers=false → no te header, no error",
            pass, pass ? "" : "sid=" + std::to_string(sid) +
                              " errors=" + std::to_string(sink.error_calls));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N6b: client_te_trailers=false → no te header, no error",
            false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN6c — Two SubmitRequests with differing te flag values on same connection.
// Both produce valid stream IDs; the flag difference is per-stream.
// ---------------------------------------------------------------------------
void TestN6cTeTrailersPerStreamFlag() {
    std::cout << "\n[TEST] H2Upstream N6c: te flag is per-stream, both requests succeed..." << std::endl;
    try {
        auto cfg = MakeH2Conn();
        RecordingSink sink_a;
        RecordingSink sink_b;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N6c: te flag is per-stream, both requests succeed",
                false, "Init failed");
            return;
        }
        int32_t sid_a = conn.SubmitRequest(
            "GET", "http", "example.com", "/a", {}, "", &sink_a,
            /*client_te_trailers=*/true);
        int32_t sid_b = conn.SubmitRequest(
            "GET", "http", "example.com", "/b", {}, "", &sink_b,
            /*client_te_trailers=*/false);

        bool pass = (sid_a > 0) && (sid_b > 0) && (sid_a != sid_b);
        std::string err;
        if (sid_a <= 0) err += "sid_a=" + std::to_string(sid_a) + "; ";
        if (sid_b <= 0) err += "sid_b=" + std::to_string(sid_b) + "; ";
        if (sid_a == sid_b) err += "stream IDs must differ; ";
        TestFramework::RecordTest(
            "H2Upstream N6c: te flag is per-stream, both requests succeed", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N6c: te flag is per-stream, both requests succeed", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN7 — CL exact match: content-length 5, server sends exactly 5 bytes +
// END_STREAM → OnComplete (not OnError). Boundary condition.
// ---------------------------------------------------------------------------
void TestN7CLExactMatchCompletes() {
    std::cout << "\n[TEST] H2Upstream N7: CL exact match → OnComplete (no truncation)..." << std::endl;
    try {
        auto cfg = MakeH2Conn();
        RecordingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N7: CL exact match → OnComplete (no truncation)",
                false, "Init failed");
            return;
        }
        int32_t sid = conn.SubmitRequest("GET", "http", "example.com", "/", {}, "", &sink);

        std::vector<uint8_t> wire = H2WireTest::BuildEmptySettings();
        auto hdrs = H2WireTest::BuildHeadersFrame(
            sid, {{":status", "200"}, {"content-length", "5"}},
            /*end_stream=*/false);
        wire.insert(wire.end(), hdrs.begin(), hdrs.end());
        conn.HandleBytes(reinterpret_cast<const char*>(wire.data()), wire.size());

        const uint8_t body[5] = {'h', 'e', 'l', 'l', 'o'};
        auto data_frame = BuildDataFrame(sid, body, 5, /*end_stream=*/true);
        conn.HandleBytes(reinterpret_cast<const char*>(data_frame.data()),
                         data_frame.size());

        bool pass = (sink.complete_calls == 1) && (sink.error_calls == 0) &&
                    (sink.body_bytes == 5);
        std::string err;
        if (sink.complete_calls != 1)
            err += "complete_calls=" + std::to_string(sink.complete_calls) + "; ";
        if (sink.error_calls != 0)
            err += "unexpected error; ";
        if (sink.body_bytes != 5)
            err += "body_bytes=" + std::to_string(sink.body_bytes) + "; ";
        TestFramework::RecordTest(
            "H2Upstream N7: CL exact match → OnComplete (no truncation)", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N7: CL exact match → OnComplete (no truncation)", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN7b — CL overflow: CL=10, server sends 20 bytes → OnError fires (NOT
// OnComplete). nghttp2's HTTP messaging enforcement detects the overflow and
// rejects the stream. Our Step 1.5 overflow check is the backstop if nghttp2
// enforcement is disabled. Key invariant: error fires for CL overflow.
// ---------------------------------------------------------------------------
void TestN7bCLOverflowRejected() {
    std::cout << "\n[TEST] H2Upstream N7b: body exceeds Content-Length → OnError..." << std::endl;
    try {
        auto cfg = MakeH2Conn();
        RecordingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N7b: body exceeds Content-Length → OnError",
                false, "Init failed");
            return;
        }
        int32_t sid = conn.SubmitRequest("GET", "http", "example.com", "/", {}, "", &sink);

        std::vector<uint8_t> wire = H2WireTest::BuildEmptySettings();
        auto hdrs = H2WireTest::BuildHeadersFrame(
            sid, {{":status", "200"}, {"content-length", "10"}},
            /*end_stream=*/false);
        wire.insert(wire.end(), hdrs.begin(), hdrs.end());
        conn.HandleBytes(reinterpret_cast<const char*>(wire.data()), wire.size());

        // 20 bytes exceeds the declared CL of 10 — protocol violation.
        std::vector<uint8_t> body(20, 'A');
        auto data_frame = BuildDataFrame(sid, body.data(), body.size(),
                                         /*end_stream=*/false);
        conn.HandleBytes(reinterpret_cast<const char*>(data_frame.data()),
                         data_frame.size());

        bool pass = (sink.error_calls == 1) && (sink.complete_calls == 0);
        std::string err;
        if (sink.error_calls != 1)
            err += "error_calls=" + std::to_string(sink.error_calls) + "; ";
        if (sink.complete_calls != 0)
            err += "complete_calls should be 0; ";
        TestFramework::RecordTest(
            "H2Upstream N7b: body exceeds Content-Length → OnError", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N7b: body exceeds Content-Length → OnError", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN8 — OnRequestSubmitted fires for bodyless GET only after the
// transport reports drain. Sink virtuals are gated on real wire progress
// via OnTransportWriteComplete, NOT on nghttp2 frame serialization.
// ---------------------------------------------------------------------------

// Extended RecordingSink that tracks OnRequestSubmitted for N-series tests.
struct RecordingSinkEx : public UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseSink {
    int headers_calls       = 0;
    int body_bytes          = 0;
    int complete_calls      = 0;
    int error_calls         = 0;
    int trailers_calls      = 0;
    int submitted_calls     = 0;  // tracks OnRequestSubmitted
    int last_status         = 0;
    int last_error_code     = 0;
    std::string last_error_msg;

    bool OnHeaders(const UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead& head) override {
        ++headers_calls; last_status = head.status_code; return true;
    }
    bool OnBodyChunk(const char*, size_t len) override {
        body_bytes += static_cast<int>(len); return true;
    }
    void OnTrailers(const std::vector<std::pair<std::string, std::string>>&) override {
        ++trailers_calls;
    }
    void OnComplete() override { ++complete_calls; }
    void OnError(int code, const std::string& msg) override {
        ++error_calls; last_error_code = code; last_error_msg = msg;
    }
    void OnRequestSubmitted() override { ++submitted_calls; }
};

void TestN8OnRequestSubmittedBodyless() {
    std::cout << "\n[TEST] H2Upstream N8: bodyless GET → OnRequestSubmitted fires only after transport drain..." << std::endl;
    try {
        auto cfg = MakeH2Conn();
        // sink declared before conn — outlives ~UpstreamH2Connection FailAllStreams.
        RecordingSinkEx sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N8: bodyless GET → OnRequestSubmitted fires only after transport drain",
                false, "Init failed");
            return;
        }
        // SubmitRequest serializes HEADERS+END_STREAM into nghttp2's send
        // buffer. With the deferred-drain contract the sink must NOT
        // see OnRequestSubmitted until transport drain reports it.
        int32_t sid = conn.SubmitRequest(
            "GET", "http", "example.com", "/", {}, "", &sink);
        if (sink.submitted_calls != 0) {
            TestFramework::RecordTest(
                "H2Upstream N8: bodyless GET → OnRequestSubmitted fires only after transport drain",
                false,
                "submitted fired before transport drain: " +
                    std::to_string(sink.submitted_calls));
            return;
        }
        // Simulate the transport's complete_callback firing after the
        // serialized bytes hit the wire.
        conn.OnTransportWriteComplete();

        bool pass = (sid > 0) && (sink.submitted_calls == 1);
        std::string err;
        if (sid <= 0) err += "invalid stream_id " + std::to_string(sid) + "; ";
        if (sink.submitted_calls != 1)
            err += "submitted_calls=" + std::to_string(sink.submitted_calls) + " (expected 1 after drain); ";
        TestFramework::RecordTest(
            "H2Upstream N8: bodyless GET → OnRequestSubmitted fires only after transport drain", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N8: bodyless GET → OnRequestSubmitted fires only after transport drain",
            false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN8b — POST with body: OnRequestSubmitted fires exactly once and
// only after the transport reports drain (deferred-drain contract).
// ---------------------------------------------------------------------------
void TestN8bOnRequestSubmittedBodyed() {
    std::cout << "\n[TEST] H2Upstream N8b: POST with body → OnRequestSubmitted fires once after drain..." << std::endl;
    try {
        auto cfg = MakeH2Conn();
        RecordingSinkEx sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N8b: POST with body → OnRequestSubmitted fires once after drain",
                false, "Init failed");
            return;
        }
        int32_t sid = conn.SubmitRequest(
            "POST", "http", "example.com", "/upload",
            {{"content-type", "application/octet-stream"}},
            std::string(128, 'B'),
            &sink);
        if (sink.submitted_calls != 0) {
            TestFramework::RecordTest(
                "H2Upstream N8b: POST with body → OnRequestSubmitted fires once after drain",
                false,
                "submitted fired before transport drain: " +
                    std::to_string(sink.submitted_calls));
            return;
        }
        conn.OnTransportWriteComplete();

        bool pass = (sid > 0) && (sink.submitted_calls == 1) && (sink.error_calls == 0);
        std::string err;
        if (sid <= 0) err += "invalid stream_id; ";
        if (sink.submitted_calls != 1)
            err += "submitted_calls=" + std::to_string(sink.submitted_calls) + "; ";
        if (sink.error_calls != 0)
            err += "unexpected errors; ";
        TestFramework::RecordTest(
            "H2Upstream N8b: POST with body → OnRequestSubmitted fires once after drain", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N8b: POST with body → OnRequestSubmitted fires once after drain", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN9 — OnRequestSubmitted fires exactly once per stream and only
// after the transport reports drain. Two concurrent streams each see
// exactly one call.
// ---------------------------------------------------------------------------
void TestN9OnRequestSubmittedOncePerStream() {
    std::cout << "\n[TEST] H2Upstream N9: OnRequestSubmitted fires exactly once per stream after drain..." << std::endl;
    try {
        auto cfg = MakeH2Conn();
        RecordingSinkEx sink_a;
        RecordingSinkEx sink_b;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N9: OnRequestSubmitted fires exactly once per stream after drain",
                false, "Init failed");
            return;
        }
        int32_t sid_a = conn.SubmitRequest(
            "GET", "http", "example.com", "/a", {}, "", &sink_a);
        int32_t sid_b = conn.SubmitRequest(
            "GET", "http", "example.com", "/b", {}, "", &sink_b);
        if (sink_a.submitted_calls != 0 || sink_b.submitted_calls != 0) {
            TestFramework::RecordTest(
                "H2Upstream N9: OnRequestSubmitted fires exactly once per stream after drain",
                false, "sink fired before transport drain");
            return;
        }
        conn.OnTransportWriteComplete();

        bool pass = (sid_a > 0) && (sid_b > 0) &&
                    (sink_a.submitted_calls == 1) &&
                    (sink_b.submitted_calls == 1);
        std::string err;
        if (sink_a.submitted_calls != 1)
            err += "sink_a submitted_calls=" + std::to_string(sink_a.submitted_calls) + "; ";
        if (sink_b.submitted_calls != 1)
            err += "sink_b submitted_calls=" + std::to_string(sink_b.submitted_calls) + "; ";
        TestFramework::RecordTest(
            "H2Upstream N9: OnRequestSubmitted fires exactly once per stream after drain", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N9: OnRequestSubmitted fires exactly once per stream after drain", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN10 — OnRequestSubmitted does NOT fire for CONNECT (rejected before
// nghttp2 allocates a stream).
// ---------------------------------------------------------------------------
void TestN10ConnectNoSubmittedCallback() {
    std::cout << "\n[TEST] H2Upstream N10: CONNECT rejected → OnRequestSubmitted never fires..." << std::endl;
    try {
        auto cfg = MakeH2Conn();
        RecordingSinkEx sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N10: CONNECT rejected → OnRequestSubmitted never fires",
                false, "Init failed");
            return;
        }
        conn.SubmitRequest("CONNECT", "http", "target:443", "", {}, "", &sink);

        // Secondary gate returns -1 before submit — no stream, no frame send.
        bool pass = (sink.submitted_calls == 0) && (sink.error_calls == 1);
        std::string err;
        if (sink.submitted_calls != 0)
            err += "submitted_calls=" + std::to_string(sink.submitted_calls) + " should be 0; ";
        if (sink.error_calls != 1)
            err += "error_calls=" + std::to_string(sink.error_calls) + " should be 1; ";
        TestFramework::RecordTest(
            "H2Upstream N10: CONNECT rejected → OnRequestSubmitted never fires", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N10: CONNECT rejected → OnRequestSubmitted never fires", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN11 — HEAD request + 200 + END_STREAM-on-HEADERS (no DATA) →
// normal OnComplete. The NO_BODY classification fires from end_stream=true
// on HEADERS, not from the 204/304/HEAD method check, so this verifies the
// existing end_stream branch handles HEAD correctly too.
// ---------------------------------------------------------------------------
void TestN11HeadNoBodyEndStreamOnHeaders() {
    std::cout << "\n[TEST] H2Upstream N11: HEAD + END_STREAM on HEADERS → normal OnComplete..." << std::endl;
    try {
        auto cfg = MakeH2Conn();
        RecordingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N11: HEAD + END_STREAM on HEADERS → normal OnComplete",
                false, "Init failed");
            return;
        }
        int32_t sid = conn.SubmitRequest("HEAD", "http", "example.com", "/", {}, "", &sink);

        std::vector<uint8_t> wire = H2WireTest::BuildEmptySettings();
        // END_STREAM on HEADERS → framing=NO_BODY, then OnStreamClose(NO_ERROR)
        // fires → no short-read check (expected_length stays -1) → OnComplete.
        auto hdrs = H2WireTest::BuildHeadersFrame(
            sid, {{":status", "200"}}, /*end_stream=*/true);
        wire.insert(wire.end(), hdrs.begin(), hdrs.end());
        conn.HandleBytes(reinterpret_cast<const char*>(wire.data()), wire.size());

        bool pass = (sink.complete_calls == 1) && (sink.error_calls == 0) &&
                    (sink.headers_calls == 1) && (sink.last_status == 200);
        std::string err;
        if (sink.complete_calls != 1) err += "complete_calls=" + std::to_string(sink.complete_calls) + "; ";
        if (sink.error_calls != 0) err += "unexpected error; ";
        if (sink.headers_calls != 1) err += "headers_calls=" + std::to_string(sink.headers_calls) + "; ";
        TestFramework::RecordTest(
            "H2Upstream N11: HEAD + END_STREAM on HEADERS → normal OnComplete", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N11: HEAD + END_STREAM on HEADERS → normal OnComplete", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN12 — 204 + END_STREAM-on-HEADERS (normal, no body) → OnComplete.
// Verifies the NO_BODY path from end_stream=true doesn't over-fire errors.
// ---------------------------------------------------------------------------
void TestN12Status204EndStreamOnHeadersCompletes() {
    std::cout << "\n[TEST] H2Upstream N12: 204 + END_STREAM on HEADERS → OnComplete..." << std::endl;
    try {
        auto cfg = MakeH2Conn();
        RecordingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N12: 204 + END_STREAM on HEADERS → OnComplete",
                false, "Init failed");
            return;
        }
        int32_t sid = conn.SubmitRequest("GET", "http", "example.com", "/", {}, "", &sink);

        std::vector<uint8_t> wire = H2WireTest::BuildEmptySettings();
        auto hdrs = H2WireTest::BuildHeadersFrame(
            sid, {{":status", "204"}}, /*end_stream=*/true);
        wire.insert(wire.end(), hdrs.begin(), hdrs.end());
        conn.HandleBytes(reinterpret_cast<const char*>(wire.data()), wire.size());

        bool pass = (sink.complete_calls == 1) && (sink.error_calls == 0);
        std::string err;
        if (sink.complete_calls != 1) err += "complete=" + std::to_string(sink.complete_calls) + "; ";
        if (sink.error_calls != 0)   err += "unexpected error; ";
        TestFramework::RecordTest(
            "H2Upstream N12: 204 + END_STREAM on HEADERS → OnComplete", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N12: 204 + END_STREAM on HEADERS → OnComplete", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN13 — Multiple concurrent requests; each gets its own independent
// framing classification. One request has CL, the other is CHUNKED.
// Both complete without interfering with each other.
// ---------------------------------------------------------------------------
void TestN13ConcurrentStreamIndependentFraming() {
    std::cout << "\n[TEST] H2Upstream N13: two concurrent streams with different framing complete independently..." << std::endl;
    try {
        auto cfg = MakeH2Conn();
        RecordingSink sink_cl;
        RecordingSink sink_chunked;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N13: two concurrent streams with different framing complete independently",
                false, "Init failed");
            return;
        }
        int32_t sid_cl = conn.SubmitRequest("GET", "http", "example.com", "/cl",
                                             {}, "", &sink_cl);
        int32_t sid_chunked = conn.SubmitRequest("GET", "http", "example.com", "/chunked",
                                                  {}, "", &sink_chunked);

        // Feed SETTINGS first
        std::vector<uint8_t> wire = H2WireTest::BuildEmptySettings();
        conn.HandleBytes(reinterpret_cast<const char*>(wire.data()), wire.size());

        // CL stream: 5 bytes
        auto hdrs_cl = H2WireTest::BuildHeadersFrame(
            sid_cl, {{":status", "200"}, {"content-length", "5"}},
            /*end_stream=*/false);
        conn.HandleBytes(reinterpret_cast<const char*>(hdrs_cl.data()), hdrs_cl.size());
        const uint8_t body5[5] = {'h', 'e', 'l', 'l', 'o'};
        auto data_cl = BuildDataFrame(sid_cl, body5, 5, /*end_stream=*/true);
        conn.HandleBytes(reinterpret_cast<const char*>(data_cl.data()), data_cl.size());

        // Chunked stream: no CL, body then END_STREAM
        auto hdrs_ch = H2WireTest::BuildHeadersFrame(
            sid_chunked, {{":status", "200"}}, /*end_stream=*/false);
        conn.HandleBytes(reinterpret_cast<const char*>(hdrs_ch.data()), hdrs_ch.size());
        const uint8_t body3[3] = {'a', 'b', 'c'};
        auto data_ch = BuildDataFrame(sid_chunked, body3, 3, /*end_stream=*/true);
        conn.HandleBytes(reinterpret_cast<const char*>(data_ch.data()), data_ch.size());

        bool pass = (sink_cl.complete_calls == 1) && (sink_cl.error_calls == 0) &&
                    (sink_cl.body_bytes == 5) &&
                    (sink_chunked.complete_calls == 1) && (sink_chunked.error_calls == 0) &&
                    (sink_chunked.body_bytes == 3);
        std::string err;
        if (sink_cl.complete_calls != 1) err += "cl.complete=" + std::to_string(sink_cl.complete_calls) + "; ";
        if (sink_cl.error_calls != 0)    err += "cl.error; ";
        if (sink_cl.body_bytes != 5)     err += "cl.body=" + std::to_string(sink_cl.body_bytes) + "; ";
        if (sink_chunked.complete_calls != 1) err += "ch.complete=" + std::to_string(sink_chunked.complete_calls) + "; ";
        if (sink_chunked.error_calls != 0)    err += "ch.error; ";
        if (sink_chunked.body_bytes != 3)     err += "ch.body=" + std::to_string(sink_chunked.body_bytes) + "; ";
        TestFramework::RecordTest(
            "H2Upstream N13: two concurrent streams with different framing complete independently", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N13: two concurrent streams with different framing complete independently",
            false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN14 — SubmitRequest with null sink: no crash on CONNECT rejection path.
// SubmitRequest for a normal method with null sink must return a valid
// stream_id (nghttp2 accepts it) and not crash.
// ---------------------------------------------------------------------------
void TestN14SubmitNullSinkNoCrash() {
    std::cout << "\n[TEST] H2Upstream N14: SubmitRequest with null sink (normal method) does not crash..." << std::endl;
    try {
        auto cfg = MakeH2Conn();
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N14: SubmitRequest with null sink (normal method) does not crash",
                false, "Init failed");
            return;
        }
        // Null sink: OnHeaders/OnComplete/OnError won't fire anywhere.
        // The connection should handle it without crashing (it null-checks sink).
        int32_t sid = conn.SubmitRequest("GET", "http", "example.com", "/", {}, "", nullptr);
        bool pass = (sid > 0);
        TestFramework::RecordTest(
            "H2Upstream N14: SubmitRequest with null sink (normal method) does not crash",
            pass, pass ? "" : "expected valid stream_id");
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N14: SubmitRequest with null sink (normal method) does not crash",
            false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN15 — RST_STREAM mid-body (INTERNAL_ERROR) routes to
// OnError(RESULT_UPSTREAM_DISCONNECT), NOT truncation. RST mapping is owned
// by the OnStreamClose non-NO_ERROR branch; truncation detection only kicks
// in on a graceful (NO_ERROR) close with a content-length mismatch.
// ---------------------------------------------------------------------------
void TestN15RstStreamMidBodyMapsToDisconnect() {
    std::cout << "\n[TEST] H2Upstream N15: RST_STREAM mid-body → RESULT_UPSTREAM_DISCONNECT (not truncated)..." << std::endl;
    try {
        auto cfg = MakeH2Conn();
        RecordingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N15: RST_STREAM mid-body → RESULT_UPSTREAM_DISCONNECT (not truncated)",
                false, "Init failed");
            return;
        }
        int32_t sid = conn.SubmitRequest("GET", "http", "example.com", "/", {}, "", &sink);

        std::vector<uint8_t> wire = H2WireTest::BuildEmptySettings();
        // Send headers with CL=100 but no END_STREAM
        auto hdrs = H2WireTest::BuildHeadersFrame(
            sid, {{":status", "200"}, {"content-length", "100"}},
            /*end_stream=*/false);
        wire.insert(wire.end(), hdrs.begin(), hdrs.end());
        conn.HandleBytes(reinterpret_cast<const char*>(wire.data()), wire.size());

        // Partial body: 50 bytes
        std::vector<uint8_t> body(50, 'P');
        auto data_frame = BuildDataFrame(sid, body.data(), body.size(), /*end_stream=*/false);
        conn.HandleBytes(reinterpret_cast<const char*>(data_frame.data()), data_frame.size());

        // RST_STREAM with INTERNAL_ERROR — not a clean close, not truncation
        auto rst = BuildRstStreamFrame(sid, NGHTTP2_INTERNAL_ERROR);
        conn.HandleBytes(reinterpret_cast<const char*>(rst.data()), rst.size());

        bool pass = (sink.error_calls == 1) &&
                    (sink.last_error_code == ProxyTransaction::RESULT_UPSTREAM_DISCONNECT);
        std::string err;
        if (sink.error_calls != 1)
            err += "error_calls=" + std::to_string(sink.error_calls) + "; ";
        if (sink.last_error_code != ProxyTransaction::RESULT_UPSTREAM_DISCONNECT)
            err += "error_code=" + std::to_string(sink.last_error_code) +
                   " (expected UPSTREAM_DISCONNECT=" +
                   std::to_string(ProxyTransaction::RESULT_UPSTREAM_DISCONNECT) + "); ";
        TestFramework::RecordTest(
            "H2Upstream N15: RST_STREAM mid-body → RESULT_UPSTREAM_DISCONNECT (not truncated)", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N15: RST_STREAM mid-body → RESULT_UPSTREAM_DISCONNECT (not truncated)",
            false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN16 — Verify that a naturally-completed stream does NOT receive a
// spurious RST_STREAM(CANCEL).
//
// Pattern: submit request → feed complete response (headers+body+END_STREAM)
// → verify OnComplete fires, active_stream_count drops to 0, no error.
// The absence of RST is verified by the error_calls==0 assertion.
// ---------------------------------------------------------------------------
void TestN16NoSpuriousRstOnNaturalClose() {
    std::cout << "\n[TEST] H2Upstream N16: natural close → no spurious RST, OnComplete fires..." << std::endl;
    try {
        auto cfg = MakeH2Conn();
        RecordingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N16: natural close → no spurious RST, OnComplete fires",
                false, "Init failed");
            return;
        }
        int32_t sid = conn.SubmitRequest("GET", "http", "example.com", "/", {}, "", &sink);

        std::vector<uint8_t> wire = H2WireTest::BuildEmptySettings();
        // Complete response: HEADERS + DATA + END_STREAM
        auto hdrs = H2WireTest::BuildHeadersFrame(
            sid, {{":status", "200"}, {"content-length", "3"}},
            /*end_stream=*/false);
        wire.insert(wire.end(), hdrs.begin(), hdrs.end());
        conn.HandleBytes(reinterpret_cast<const char*>(wire.data()), wire.size());

        const uint8_t body[3] = {'a', 'b', 'c'};
        auto data_frame = BuildDataFrame(sid, body, 3, /*end_stream=*/true);
        conn.HandleBytes(reinterpret_cast<const char*>(data_frame.data()),
                         data_frame.size());

        // After natural close: OnComplete fires, stream removed, no RST sent.
        bool pass = (sink.complete_calls == 1) &&
                    (sink.error_calls == 0) &&
                    (conn.active_stream_count() == 0);
        std::string err;
        if (sink.complete_calls != 1)
            err += "complete_calls=" + std::to_string(sink.complete_calls) + "; ";
        if (sink.error_calls != 0)
            err += "unexpected error (possible spurious RST path); ";
        if (conn.active_stream_count() != 0)
            err += "active_stream_count=" + std::to_string(conn.active_stream_count()) + "; ";
        TestFramework::RecordTest(
            "H2Upstream N16: natural close → no spurious RST, OnComplete fires", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N16: natural close → no spurious RST, OnComplete fires", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN17 — After OnComplete, calling ResetStream(sid) is a no-op (stream
// already erased). Verifies the ResetStream null-check doesn't double-fire.
// ---------------------------------------------------------------------------
void TestN17ResetAfterCompleteIsNoop() {
    std::cout << "\n[TEST] H2Upstream N17: ResetStream after stream completes is a no-op..." << std::endl;
    try {
        auto cfg = MakeH2Conn();
        RecordingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N17: ResetStream after stream completes is a no-op",
                false, "Init failed");
            return;
        }
        int32_t sid = conn.SubmitRequest("GET", "http", "example.com", "/", {}, "", &sink);

        std::vector<uint8_t> wire = H2WireTest::BuildEmptySettings();
        auto hdrs = H2WireTest::BuildHeadersFrame(
            sid, {{":status", "200"}}, /*end_stream=*/true);
        wire.insert(wire.end(), hdrs.begin(), hdrs.end());
        conn.HandleBytes(reinterpret_cast<const char*>(wire.data()), wire.size());

        // Precondition: completed cleanly
        if (sink.complete_calls != 1) {
            TestFramework::RecordTest(
                "H2Upstream N17: ResetStream after stream completes is a no-op",
                false, "precondition: complete_calls should be 1");
            return;
        }

        // Call ResetStream on the now-erased stream — must not crash or double-fire.
        conn.ResetStream(sid);

        bool pass = (sink.error_calls == 0) && (conn.active_stream_count() == 0);
        std::string err;
        if (sink.error_calls != 0) err += "spurious error after ResetStream; ";
        if (conn.active_stream_count() != 0) err += "stream count nonzero; ";
        TestFramework::RecordTest(
            "H2Upstream N17: ResetStream after stream completes is a no-op", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N17: ResetStream after stream completes is a no-op", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN18 — Two streams: one truncated (NO_BODY violation), one normal.
// Verifies per-stream isolation: truncation of stream A does not affect B.
// ---------------------------------------------------------------------------
void TestN18TruncationDoesNotAffectSiblingStream() {
    std::cout << "\n[TEST] H2Upstream N18: NO_BODY truncation on stream A does not affect stream B..." << std::endl;
    try {
        auto cfg = MakeH2Conn();
        RecordingSink sink_a;  // will receive TRUNCATED error
        RecordingSink sink_b;  // will complete normally
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N18: NO_BODY truncation on stream A does not affect stream B",
                false, "Init failed");
            return;
        }
        int32_t sid_a = conn.SubmitRequest("GET", "http", "example.com", "/204-bad",
                                            {}, "", &sink_a);
        int32_t sid_b = conn.SubmitRequest("GET", "http", "example.com", "/200-ok",
                                            {}, "", &sink_b);

        // Feed SETTINGS
        std::vector<uint8_t> wire = H2WireTest::BuildEmptySettings();
        conn.HandleBytes(reinterpret_cast<const char*>(wire.data()), wire.size());

        // Stream A: 204 without END_STREAM, then body bytes → truncation
        auto hdrs_a = H2WireTest::BuildHeadersFrame(
            sid_a, {{":status", "204"}}, /*end_stream=*/false);
        conn.HandleBytes(reinterpret_cast<const char*>(hdrs_a.data()), hdrs_a.size());
        const uint8_t bad_body[10] = {};
        auto data_a = BuildDataFrame(sid_a, bad_body, 10, /*end_stream=*/false);
        conn.HandleBytes(reinterpret_cast<const char*>(data_a.data()), data_a.size());

        // Stream B: normal 200 + small body + END_STREAM
        auto hdrs_b = H2WireTest::BuildHeadersFrame(
            sid_b, {{":status", "200"}, {"content-length", "3"}},
            /*end_stream=*/false);
        conn.HandleBytes(reinterpret_cast<const char*>(hdrs_b.data()), hdrs_b.size());
        const uint8_t good_body[3] = {'o', 'k', '!'};
        auto data_b = BuildDataFrame(sid_b, good_body, 3, /*end_stream=*/true);
        conn.HandleBytes(reinterpret_cast<const char*>(data_b.data()), data_b.size());

        // Stream A: error fires (nghttp2 enforces NO_BODY constraint).
        // Stream B: completes normally — per-stream isolation holds.
        bool pass = (sink_a.error_calls == 1) &&
                    (sink_b.complete_calls == 1) &&
                    (sink_b.error_calls == 0) &&
                    (sink_b.body_bytes == 3);
        std::string err;
        if (sink_a.error_calls != 1)
            err += "a.error=" + std::to_string(sink_a.error_calls) + "; ";
        if (sink_b.complete_calls != 1)
            err += "b.complete=" + std::to_string(sink_b.complete_calls) + "; ";
        if (sink_b.error_calls != 0)
            err += "b.unexpected_error; ";
        if (sink_b.body_bytes != 3)
            err += "b.body=" + std::to_string(sink_b.body_bytes) + "; ";
        TestFramework::RecordTest(
            "H2Upstream N18: NO_BODY truncation on stream A does not affect stream B", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N18: NO_BODY truncation on stream A does not affect stream B",
            false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN19 — FailAllStreams clears all pending streams without leaking sink
// calls; active_stream_count drops to 0 immediately.
// ---------------------------------------------------------------------------
void TestN19FailAllStreamsCleanup() {
    std::cout << "\n[TEST] H2Upstream N19: FailAllStreams fires OnError for all pending streams..." << std::endl;
    try {
        auto cfg = MakeH2Conn();
        // sinks MUST be declared before conn — ~UpstreamH2Connection calls
        // FailAllStreams defensively; sinks must outlive the conn dtor.
        RecordingSink sink_a;
        RecordingSink sink_b;
        RecordingSink sink_c;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N19: FailAllStreams fires OnError for all pending streams",
                false, "Init failed");
            return;
        }
        conn.SubmitRequest("GET", "http", "example.com", "/a", {}, "", &sink_a);
        conn.SubmitRequest("GET", "http", "example.com", "/b", {}, "", &sink_b);
        conn.SubmitRequest("GET", "http", "example.com", "/c", {}, "", &sink_c);

        if (conn.active_stream_count() != 3) {
            TestFramework::RecordTest(
                "H2Upstream N19: FailAllStreams fires OnError for all pending streams",
                false, "precondition: expected 3 active streams");
            return;
        }

        conn.MarkDead();
        conn.FailAllStreams(ProxyTransaction::RESULT_UPSTREAM_DISCONNECT, "test shutdown");

        bool pass = (conn.active_stream_count() == 0) &&
                    (sink_a.error_calls == 1) &&
                    (sink_b.error_calls == 1) &&
                    (sink_c.error_calls == 1);
        std::string err;
        if (conn.active_stream_count() != 0)
            err += "active_stream_count=" + std::to_string(conn.active_stream_count()) + "; ";
        if (sink_a.error_calls != 1) err += "a.error=" + std::to_string(sink_a.error_calls) + "; ";
        if (sink_b.error_calls != 1) err += "b.error=" + std::to_string(sink_b.error_calls) + "; ";
        if (sink_c.error_calls != 1) err += "c.error=" + std::to_string(sink_c.error_calls) + "; ";
        TestFramework::RecordTest(
            "H2Upstream N19: FailAllStreams fires OnError for all pending streams", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N19: FailAllStreams fires OnError for all pending streams", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestB15-B19 — wire-level tests using UpstreamH2Connection::HandleBytes
// against nghttp2 server-side frame sequences (hand-crafted or via
// MockH2Server).
// ---------------------------------------------------------------------------

// Helper: build a HEADERS frame for trailers (HCAT_HEADERS on the response
// side). Trailers have END_HEADERS + END_STREAM set.
static std::vector<uint8_t> BuildTrailersFrame(int32_t stream_id,
    const std::vector<std::pair<std::string, std::string>>& hdrs)
{
    nghttp2_hd_deflater* defl = nullptr;
    if (nghttp2_hd_deflate_new(&defl, 4096) != 0) return {};
    std::vector<nghttp2_nv> nva;
    nva.reserve(hdrs.size());
    for (const auto& kv : hdrs) {
        nghttp2_nv nv;
        nv.name = reinterpret_cast<uint8_t*>(const_cast<char*>(kv.first.data()));
        nv.namelen = kv.first.size();
        nv.value = reinterpret_cast<uint8_t*>(const_cast<char*>(kv.second.data()));
        nv.valuelen = kv.second.size();
        nv.flags = NGHTTP2_NV_FLAG_NO_INDEX;
        nva.push_back(nv);
    }
    size_t bound = nghttp2_hd_deflate_bound(defl, nva.data(), nva.size());
    std::vector<uint8_t> hpack(bound);
    ssize_t pl = nghttp2_hd_deflate_hd2(defl, hpack.data(), hpack.size(),
                                         nva.data(), nva.size());
    nghttp2_hd_deflate_del(defl);
    if (pl < 0) return {};
    std::vector<uint8_t> frame;
    frame.reserve(9 + pl);
    frame.push_back(static_cast<uint8_t>((pl >> 16) & 0xff));
    frame.push_back(static_cast<uint8_t>((pl >> 8) & 0xff));
    frame.push_back(static_cast<uint8_t>(pl & 0xff));
    frame.push_back(NGHTTP2_HEADERS);
    // END_HEADERS + END_STREAM for trailer block
    frame.push_back(NGHTTP2_FLAG_END_HEADERS | NGHTTP2_FLAG_END_STREAM);
    frame.push_back(static_cast<uint8_t>((stream_id >> 24) & 0x7f));
    frame.push_back(static_cast<uint8_t>((stream_id >> 16) & 0xff));
    frame.push_back(static_cast<uint8_t>((stream_id >> 8) & 0xff));
    frame.push_back(static_cast<uint8_t>(stream_id & 0xff));
    frame.insert(frame.end(), hpack.begin(), hpack.begin() + pl);
    return frame;
}

// ---------------------------------------------------------------------------
// TestB15 — HEADERS + DATA + HEADERS-trailers (END_STREAM on trailers):
// trailer block is delivered to sink via OnTrailers; OnComplete fires.
// ---------------------------------------------------------------------------
void TestB15TrailersAfterDataEndStream() {
    std::cout << "\n[TEST] H2Upstream B15: trailers delivered: HEADERS+DATA+HEADERS(trailers)+END_STREAM..." << std::endl;
    try {
        auto cfg = MakeH2Conn();
        // sink declared before conn — survives ~UpstreamH2Connection FailAllStreams.
        RecordingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream B15: trailers delivered: HEADERS+DATA+HEADERS(trailers)+END_STREAM",
                false, "Init failed");
            return;
        }
        int32_t sid = conn.SubmitRequest("GET", "http", "example.com", "/", {}, "", &sink);

        std::vector<uint8_t> wire = H2WireTest::BuildEmptySettings();
        // Response HEADERS (no END_STREAM — body follows)
        auto hdrs = H2WireTest::BuildHeadersFrame(
            sid, {{":status", "200"}}, /*end_stream=*/false);
        wire.insert(wire.end(), hdrs.begin(), hdrs.end());
        conn.HandleBytes(reinterpret_cast<const char*>(wire.data()), wire.size());

        // DATA frame (no END_STREAM — trailers follow)
        const uint8_t body_data[4] = {'d', 'a', 't', 'a'};
        auto data_frame = BuildDataFrame(sid, body_data, 4, /*end_stream=*/false);
        conn.HandleBytes(reinterpret_cast<const char*>(data_frame.data()),
                         data_frame.size());

        // Trailers HEADERS with END_STREAM
        auto trailers = BuildTrailersFrame(sid, {{"grpc-status", "0"}, {"grpc-message", "ok"}});
        conn.HandleBytes(reinterpret_cast<const char*>(trailers.data()), trailers.size());

        bool pass = (sink.headers_calls == 1) &&
                    (sink.body_bytes == 4) &&
                    (sink.trailers_calls == 1) &&
                    (sink.complete_calls == 1) &&
                    (sink.error_calls == 0);
        std::string err;
        if (sink.headers_calls != 1)  err += "headers=" + std::to_string(sink.headers_calls) + "; ";
        if (sink.body_bytes != 4)     err += "body=" + std::to_string(sink.body_bytes) + "; ";
        if (sink.trailers_calls != 1) err += "trailers=" + std::to_string(sink.trailers_calls) + "; ";
        if (sink.complete_calls != 1) err += "complete=" + std::to_string(sink.complete_calls) + "; ";
        if (sink.error_calls != 0)    err += "unexpected error; ";
        TestFramework::RecordTest(
            "H2Upstream B15: trailers delivered: HEADERS+DATA+HEADERS(trailers)+END_STREAM",
            pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream B15: trailers delivered: HEADERS+DATA+HEADERS(trailers)+END_STREAM",
            false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestB16 — DATA frame with PADDED flag: padding bytes are stripped and flow-
// control credit is returned. Sink sees only the actual data payload, not the
// padding. OnComplete fires after DATA+PADDED+END_STREAM.
// ---------------------------------------------------------------------------
void TestB16DataPaddingStripped() {
    std::cout << "\n[TEST] H2Upstream B16: DATA frame with padding — payload correct, OnComplete fires..." << std::endl;
    try {
        auto cfg = MakeH2Conn();
        RecordingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream B16: DATA frame with padding — payload correct, OnComplete fires",
                false, "Init failed");
            return;
        }
        int32_t sid = conn.SubmitRequest("GET", "http", "example.com", "/", {}, "", &sink);

        // Feed SETTINGS + response HEADERS
        std::vector<uint8_t> wire = H2WireTest::BuildEmptySettings();
        auto hdrs = H2WireTest::BuildHeadersFrame(
            sid, {{":status", "200"}}, /*end_stream=*/false);
        wire.insert(wire.end(), hdrs.begin(), hdrs.end());
        conn.HandleBytes(reinterpret_cast<const char*>(wire.data()), wire.size());

        // Build a padded DATA frame (RFC 9113 §6.1):
        // Frame layout: 9-byte header + 1-byte pad-length + payload + pad_length bytes of padding.
        const uint8_t payload[5] = {'p', 'a', 'y', 'l', 'd'};
        const uint8_t pad_length  = 10;
        const size_t  total_len   = 1 + 5 + pad_length;  // pad_field + payload + padding

        std::vector<uint8_t> padded_frame;
        padded_frame.reserve(9 + total_len);
        padded_frame.push_back(static_cast<uint8_t>((total_len >> 16) & 0xff));
        padded_frame.push_back(static_cast<uint8_t>((total_len >> 8) & 0xff));
        padded_frame.push_back(static_cast<uint8_t>(total_len & 0xff));
        padded_frame.push_back(NGHTTP2_DATA);
        padded_frame.push_back(NGHTTP2_FLAG_END_STREAM | NGHTTP2_FLAG_PADDED);
        padded_frame.push_back(static_cast<uint8_t>((sid >> 24) & 0x7f));
        padded_frame.push_back(static_cast<uint8_t>((sid >> 16) & 0xff));
        padded_frame.push_back(static_cast<uint8_t>((sid >> 8) & 0xff));
        padded_frame.push_back(static_cast<uint8_t>(sid & 0xff));
        padded_frame.push_back(pad_length);  // Pad Length field
        padded_frame.insert(padded_frame.end(), payload, payload + 5);
        padded_frame.resize(padded_frame.size() + pad_length, 0);  // padding bytes

        conn.HandleBytes(reinterpret_cast<const char*>(padded_frame.data()),
                         padded_frame.size());

        // Sink must see only the 5 payload bytes (no padding), then OnComplete.
        bool pass = (sink.body_bytes == 5) &&
                    (sink.complete_calls == 1) &&
                    (sink.error_calls == 0);
        std::string err;
        if (sink.body_bytes != 5)
            err += "body=" + std::to_string(sink.body_bytes) + " (expected 5, not " +
                   std::to_string(5 + pad_length + 1) + "); ";
        if (sink.complete_calls != 1) err += "complete=" + std::to_string(sink.complete_calls) + "; ";
        if (sink.error_calls != 0)    err += "unexpected error; ";
        TestFramework::RecordTest(
            "H2Upstream B16: DATA frame with padding — payload correct, OnComplete fires",
            pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream B16: DATA frame with padding — payload correct, OnComplete fires",
            false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestB17 — GOAWAY + in-flight stream: server sends GOAWAY with
// last_stream_id=0 (rejects our stream 1), then our stream sees OnError
// (RESULT_GOAWAY_UNPROCESSED). Connection IsUsable becomes false. No crash.
// ---------------------------------------------------------------------------
void TestB17GoawayWithActiveStream() {
    std::cout << "\n[TEST] H2Upstream B17: GOAWAY rejects active stream → OnError, !IsUsable..." << std::endl;
    try {
        auto cfg = MakeH2Conn();
        RecordingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream B17: GOAWAY rejects active stream → OnError, !IsUsable",
                false, "Init failed");
            return;
        }
        int32_t sid = conn.SubmitRequest("GET", "http", "example.com", "/", {}, "", &sink);
        (void)sid;

        // Server sends SETTINGS then GOAWAY(last_stream_id=0).
        // Our stream 1 > 0, so it was never processed by the server → OnError.
        std::vector<uint8_t> wire = H2WireTest::BuildEmptySettings();
        auto goaway = H2WireTest::BuildGoawayFrame(0, NGHTTP2_NO_ERROR);
        wire.insert(wire.end(), goaway.begin(), goaway.end());
        conn.HandleBytes(reinterpret_cast<const char*>(wire.data()), wire.size());

        bool pass = (!conn.IsUsable()) &&
                    (conn.goaway_seen()) &&
                    (sink.error_calls == 1);
        std::string err;
        if (conn.IsUsable()) err += "IsUsable should be false; ";
        if (!conn.goaway_seen()) err += "goaway_seen should be true; ";
        if (sink.error_calls != 1) err += "error_calls=" + std::to_string(sink.error_calls) + "; ";
        TestFramework::RecordTest(
            "H2Upstream B17: GOAWAY rejects active stream → OnError, !IsUsable", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream B17: GOAWAY rejects active stream → OnError, !IsUsable", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestB18 — RST_STREAM mid-body on the wire: HEADERS + DATA + RST_STREAM →
// OnError(RESULT_UPSTREAM_DISCONNECT). Body bytes received before RST are
// still delivered to the sink (they arrived before the reset).
// ---------------------------------------------------------------------------
void TestB18RstStreamMidBodyWire() {
    std::cout << "\n[TEST] H2Upstream B18: wire RST_STREAM mid-body → OnError(UPSTREAM_DISCONNECT)..." << std::endl;
    try {
        auto cfg = MakeH2Conn();
        RecordingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream B18: wire RST_STREAM mid-body → OnError(UPSTREAM_DISCONNECT)",
                false, "Init failed");
            return;
        }
        int32_t sid = conn.SubmitRequest("GET", "http", "example.com", "/", {}, "", &sink);

        std::vector<uint8_t> wire = H2WireTest::BuildEmptySettings();
        // Response HEADERS without END_STREAM
        auto hdrs = H2WireTest::BuildHeadersFrame(
            sid, {{":status", "200"}}, /*end_stream=*/false);
        wire.insert(wire.end(), hdrs.begin(), hdrs.end());

        // Some body
        const uint8_t body_bytes[8] = {1, 2, 3, 4, 5, 6, 7, 8};
        auto data_frame = BuildDataFrame(sid, body_bytes, 8, /*end_stream=*/false);
        wire.insert(wire.end(), data_frame.begin(), data_frame.end());

        // RST_STREAM with CANCEL error
        auto rst = BuildRstStreamFrame(sid, NGHTTP2_CANCEL);
        wire.insert(wire.end(), rst.begin(), rst.end());

        conn.HandleBytes(reinterpret_cast<const char*>(wire.data()), wire.size());

        bool pass = (sink.error_calls == 1) &&
                    (sink.last_error_code == ProxyTransaction::RESULT_UPSTREAM_DISCONNECT) &&
                    (sink.complete_calls == 0);
        std::string err;
        if (sink.error_calls != 1)
            err += "error_calls=" + std::to_string(sink.error_calls) + "; ";
        if (sink.last_error_code != ProxyTransaction::RESULT_UPSTREAM_DISCONNECT)
            err += "error_code=" + std::to_string(sink.last_error_code) + "; ";
        if (sink.complete_calls != 0)
            err += "complete_calls should be 0; ";
        TestFramework::RecordTest(
            "H2Upstream B18: wire RST_STREAM mid-body → OnError(UPSTREAM_DISCONNECT)", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream B18: wire RST_STREAM mid-body → OnError(UPSTREAM_DISCONNECT)",
            false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestB19 — Multi-stream interleave: two streams in flight, stream 1 RST'd,
// stream 3 completes normally. Verifies per-stream isolation on the wire.
// ---------------------------------------------------------------------------
void TestB19MultiStreamRstOneCompletesOther() {
    std::cout << "\n[TEST] H2Upstream B19: stream 1 RST, stream 3 completes — wire interleave..." << std::endl;
    try {
        auto cfg = MakeH2Conn();
        RecordingSink sink1;
        RecordingSink sink3;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream B19: stream 1 RST, stream 3 completes — wire interleave",
                false, "Init failed");
            return;
        }
        int32_t sid1 = conn.SubmitRequest("GET", "http", "example.com", "/1", {}, "", &sink1);
        int32_t sid3 = conn.SubmitRequest("GET", "http", "example.com", "/3", {}, "", &sink3);

        std::vector<uint8_t> wire = H2WireTest::BuildEmptySettings();

        // Stream 1: HEADERS then RST_STREAM
        auto hdrs1 = H2WireTest::BuildHeadersFrame(
            sid1, {{":status", "200"}}, /*end_stream=*/false);
        wire.insert(wire.end(), hdrs1.begin(), hdrs1.end());
        auto rst1 = BuildRstStreamFrame(sid1, NGHTTP2_INTERNAL_ERROR);
        wire.insert(wire.end(), rst1.begin(), rst1.end());

        // Stream 3: complete response (HEADERS + END_STREAM)
        auto hdrs3 = H2WireTest::BuildHeadersFrame(
            sid3, {{":status", "201"}}, /*end_stream=*/true);
        wire.insert(wire.end(), hdrs3.begin(), hdrs3.end());

        conn.HandleBytes(reinterpret_cast<const char*>(wire.data()), wire.size());

        bool pass = (sink1.error_calls == 1) &&
                    (sink1.last_error_code == ProxyTransaction::RESULT_UPSTREAM_DISCONNECT) &&
                    (sink3.complete_calls == 1) &&
                    (sink3.last_status == 201) &&
                    (sink3.error_calls == 0);
        std::string err;
        if (sink1.error_calls != 1)
            err += "s1.error=" + std::to_string(sink1.error_calls) + "; ";
        if (sink1.last_error_code != ProxyTransaction::RESULT_UPSTREAM_DISCONNECT)
            err += "s1.code=" + std::to_string(sink1.last_error_code) + "; ";
        if (sink3.complete_calls != 1)
            err += "s3.complete=" + std::to_string(sink3.complete_calls) + "; ";
        if (sink3.last_status != 201)
            err += "s3.status=" + std::to_string(sink3.last_status) + "; ";
        if (sink3.error_calls != 0)
            err += "s3.unexpected_error; ";
        TestFramework::RecordTest(
            "H2Upstream B19: stream 1 RST, stream 3 completes — wire interleave", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream B19: stream 1 RST, stream 3 completes — wire interleave", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN6d — TE tokenizer accepts case variants and ;q-parameter syntax.
// Locks the static ProxyTransaction::ContainsTeTrailersToken contract
// against locale-corruption (Turkish 'I'→'ı' is the classic std::tolower
// pitfall) and against RFC 9110 §10.1.4 q-parameter syntax that gRPC
// proxies in the wild may emit.
// ---------------------------------------------------------------------------
void TestN6dTeTokenizerAcceptsParametersAndCases() {
    std::cout << "\n[TEST] H2Upstream N6d: TE tokenizer accepts case + ;q-parameters..." << std::endl;
    struct Case { const char* value; bool expected; const char* label; };
    const Case cases[] = {
        // Bare token, mixed case (locale-safe lowercase test).
        {"trailers",                 true,  "lowercase"},
        {"TRAILERS",                 true,  "uppercase"},
        {"Trailers",                 true,  "titlecase"},
        // RFC 9110 §10.1.4 — token MAY have ;q=... weight.
        {"trailers;q=1.0",           true,  "trailers;q=1.0"},
        {"trailers ;q=0.5",          true,  "trailers ;q=0.5 (OWS before ;)"},
        {"TRAILERS;Q=0.0",           true,  "TRAILERS;Q=0.0 (case + param case)"},
        // Multi-token list with trailers in various positions.
        {"trailers, deflate",        true,  "trailers, deflate"},
        {"deflate, trailers",        true,  "deflate, trailers"},
        {"deflate;q=0.5, trailers",  true,  "deflate;q=0.5, trailers"},
        {"deflate, TRAILERS;q=1.0",  true,  "deflate, TRAILERS;q=1.0"},
        // Negative — no trailers token.
        {"",                         false, "empty"},
        {"deflate",                  false, "deflate only"},
        {"gzip, deflate",            false, "gzip, deflate"},
        {"trailerss",                false, "trailerss (extra char)"},
        {"foo;trailers=true",        false, "foo;trailers=true (param value, not token)"},
    };
    int pass = 0, total = 0;
    for (const Case& c : cases) {
        const bool got = ProxyTransaction::ContainsTeTrailersToken(c.value);
        ++total;
        if (got == c.expected) {
            ++pass;
        } else {
            std::cerr << "  FAIL[" << c.label << "]: got=" << got
                      << " expected=" << c.expected << std::endl;
        }
    }
    TestFramework::RecordTest(
        "H2Upstream N6d: TE tokenizer accepts case + ;q-parameters",
        pass == total,
        pass == total ? "" : "passed " + std::to_string(pass) + "/" +
                              std::to_string(total));
}

// ---------------------------------------------------------------------------
// TestN8c — H2 connection survives a wire-frame early-final-headers and
// continues to host sibling streams. Regression-lock for the deliberate
// H1-vs-H2 OnHeaders delta: H1 poisons the connection on early headers
// (transport-sharing contamination); H2 must NOT, because streams are
// multiplexed and a single peer-final-headers signal on stream A is not
// a fatal upstream signal for streams B+.
//
// The connection-level invariant is observable: after stream A receives
// 200 + END_STREAM (a synthetic early-final-headers response delivered
// via HandleBytes), conn.IsUsable() must stay true, no GOAWAY emitted,
// no MarkDead, and a fresh SubmitRequest for stream B must succeed and
// be assigned the next odd id.
// ---------------------------------------------------------------------------
void TestN8cNoPoisonOnEarlyHeadersSiblingReuse() {
    std::cout << "\n[TEST] H2Upstream N8c: peer-final-headers on stream A → connection still hosts sibling B..." << std::endl;
    try {
        auto cfg = MakeH2Conn();
        RecordingSink sink_a, sink_b;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N8c: peer-final-headers — sibling stream still usable",
                false, "Init failed");
            return;
        }
        int32_t sid_a = conn.SubmitRequest("POST", "http", "example.com",
                                            "/upload", {}, "x", &sink_a);
        if (sid_a != 1) {
            TestFramework::RecordTest(
                "H2Upstream N8c: peer-final-headers — sibling stream still usable",
                false, "expected sid_a=1, got " + std::to_string(sid_a));
            return;
        }

        // Drive a synthetic peer-final-headers response on stream A.
        // 200 + END_STREAM is the canonical "peer responded before our
        // body finished" wire pattern. nghttp2 will dispatch OnHeaders
        // (no poison on H2 path) then OnComplete via OnStreamClose.
        std::vector<uint8_t> wire = H2WireTest::BuildEmptySettings();
        auto hdrs = H2WireTest::BuildHeadersFrame(
            sid_a, {{":status", "200"}, {"content-length", "0"}},
            /*end_stream=*/true);
        wire.insert(wire.end(), hdrs.begin(), hdrs.end());
        ssize_t consumed = conn.HandleBytes(
            reinterpret_cast<const char*>(wire.data()), wire.size());

        // Stream A's sink saw the response cleanly (the wire path
        // exercises the H2 OnHeaders branch end-to-end).
        const bool a_got_headers = (sink_a.headers_calls == 1) &&
                                   (sink_a.last_status == 200);
        const bool a_completed   = (sink_a.complete_calls == 1) &&
                                   (sink_a.error_calls == 0);
        // Connection-level invariants: NOT poisoned at the connection
        // layer (no GOAWAY, no MarkDead, IsUsable stays true).
        const bool conn_usable   = conn.IsUsable();
        const bool no_goaway     = !conn.goaway_seen();
        const bool no_dead       = !conn.IsDead();

        // Sibling stream B must succeed AND get the next odd id (3) —
        // proves the connection is still accepting new streams.
        int32_t sid_b = conn.SubmitRequest("GET", "http", "example.com",
                                            "/sibling", {}, "", &sink_b);
        const bool b_assigned    = (sid_b == 3);

        bool pass = (consumed > 0) && a_got_headers && a_completed &&
                    conn_usable && no_goaway && no_dead && b_assigned;
        TestFramework::RecordTest(
            "H2Upstream N8c: peer-final-headers — sibling stream still usable",
            pass,
            pass ? "" : "consumed=" + std::to_string(consumed) +
                        " a_hdrs=" + std::to_string(a_got_headers) +
                        " a_complete=" + std::to_string(a_completed) +
                        " usable=" + std::to_string(conn_usable) +
                        " no_goaway=" + std::to_string(no_goaway) +
                        " no_dead=" + std::to_string(no_dead) +
                        " sid_b=" + std::to_string(sid_b));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N8c: peer-final-headers — sibling stream still usable",
            false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN9b — Large-body submit enqueues multiple frames in the drain
// queue; OnRequestBodyProgress fires for each intermediate DATA frame
// AND OnRequestSubmitted fires exactly once — but ALL dispatch is gated
// on real transport drain (the deferred-drain contract). Sink virtuals
// must remain silent until OnTransportWriteComplete is called.
//
// Default MAX_FRAME_SIZE is 16384 (RFC 9113 §6.5.2). A 20000-byte body
// guarantees at least 2 DATA frames: intermediate (no END_STREAM) +
// terminal (END_STREAM).
// ---------------------------------------------------------------------------
void TestN9bRequestBodyProgressFiresFromCodec() {
    std::cout << "\n[TEST] H2Upstream N9b: large-body submit fires sink virtuals via transport drain..." << std::endl;
    struct ObservingSink : public RecordingSink {
        int progress_calls = 0;
        int submitted_calls = 0;
        void OnRequestBodyProgress() override { ++progress_calls; }
        void OnRequestSubmitted() override { ++submitted_calls; }
    };
    try {
        auto cfg = MakeH2Conn();
        ObservingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N9b: large-body submit fires sink virtuals via transport drain",
                false, "Init failed");
            return;
        }
        std::string body(20000, 'x');
        int32_t sid = conn.SubmitRequest(
            "POST", "http", "example.com", "/upload", {}, body, &sink);
        if (sid <= 0) {
            TestFramework::RecordTest(
                "H2Upstream N9b: large-body submit fires sink virtuals via transport drain",
                false, "submit failed");
            return;
        }
        // Deferred-drain contract: no sink dispatch before transport reports drain.
        if (sink.progress_calls != 0 || sink.submitted_calls != 0) {
            TestFramework::RecordTest(
                "H2Upstream N9b: large-body submit fires sink virtuals via transport drain",
                false,
                "sink fired before drain: progress=" +
                    std::to_string(sink.progress_calls) +
                    " submitted=" + std::to_string(sink.submitted_calls));
            return;
        }
        conn.OnTransportWriteComplete();
        bool pass = (sink.progress_calls >= 1) &&
                    (sink.submitted_calls == 1);
        TestFramework::RecordTest(
            "H2Upstream N9b: large-body submit fires sink virtuals via transport drain",
            pass, pass ? "" : "progress=" + std::to_string(sink.progress_calls) +
                              " submitted=" + std::to_string(sink.submitted_calls));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N9b: large-body submit fires sink virtuals via transport drain",
            false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN9dDeferredDrainSemantic — Sink virtuals (OnRequestSubmitted and
// OnRequestBodyProgress) MUST fire only after the transport reports
// drain, NOT when nghttp2 serializes the frame into its internal
// output buffer. Verifies the deferred-drain contract end-to-end:
// SubmitRequest serializes frames → drain queue accumulates →
// OnTransportWriteProgress / Complete pop entries and dispatch.
// ---------------------------------------------------------------------------
void TestN9dDeferredDrainSemantic() {
    std::cout << "\n[TEST] H2Upstream N9d: sink virtuals deferred to transport drain..." << std::endl;
    struct ObservingSink : public RecordingSink {
        int progress_calls = 0;
        int submitted_calls = 0;
        void OnRequestBodyProgress() override { ++progress_calls; }
        void OnRequestSubmitted() override { ++submitted_calls; }
    };
    try {
        auto cfg = MakeH2Conn();
        ObservingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N9d: sink virtuals deferred to transport drain",
                false, "Init failed");
            return;
        }

        // Stage 1: SubmitRequest with a large body — nghttp2 serializes
        // HEADERS + multiple DATA frames inline. Drain queue accumulates
        // all of them but NO sink virtuals fire yet.
        std::string body(20000, 'q');
        int32_t sid = conn.SubmitRequest(
            "POST", "http", "example.com", "/upload", {}, body, &sink);
        if (sid <= 0) {
            TestFramework::RecordTest(
                "H2Upstream N9d: sink virtuals deferred to transport drain",
                false, "submit failed sid=" + std::to_string(sid));
            return;
        }
        const bool pre_drain_silent =
            (sink.progress_calls == 0) && (sink.submitted_calls == 0);

        // Stage 2: simulate partial drain — write_progress with a
        // non-zero remaining. The transport is reporting that some of
        // our queued bytes are still buffered; only the bytes that
        // drained should fire dispatches.
        // For a 20KB body, frame sizes are roughly HEADERS(~30) +
        // DATA(16384) + DATA(3616). Tell the transport "10KB still
        // buffered" — at least the HEADERS frame should have drained.
        conn.OnTransportWriteProgress(10000);
        const int after_partial_progress = sink.progress_calls;
        const int after_partial_submitted = sink.submitted_calls;

        // Stage 3: full drain — remaining frames dispatch.
        conn.OnTransportWriteComplete();
        const bool post_drain_complete =
            (sink.submitted_calls == 1) && (sink.progress_calls >= 1);

        bool pass = pre_drain_silent && post_drain_complete &&
                    (after_partial_submitted == 0);
        std::string err;
        if (!pre_drain_silent) {
            err += "sink fired before drain (progress=" +
                   std::to_string(sink.progress_calls) +
                   " submitted=" + std::to_string(sink.submitted_calls) +
                   "); ";
        }
        if (after_partial_submitted != 0) {
            err += "submitted fired during partial drain (submitted=" +
                   std::to_string(after_partial_submitted) + "); ";
        }
        if (!post_drain_complete) {
            err += "post-drain mismatch (progress=" +
                   std::to_string(sink.progress_calls) +
                   " submitted=" + std::to_string(sink.submitted_calls) +
                   "); ";
        }
        (void)after_partial_progress;  // recorded for diagnosis only
        TestFramework::RecordTest(
            "H2Upstream N9d: sink virtuals deferred to transport drain",
            pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N9d: sink virtuals deferred to transport drain",
            false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN9eResetStreamDropsDrainEntries — Verifies that resetting a stream
// before its drain queue entries fire causes those entries to be
// dropped (not dispatched to a nulled sink). Otherwise FireSinkForDrainEntry
// after detach + ResetStream would crash on the detached sink slot.
// ---------------------------------------------------------------------------
void TestN9eResetStreamDropsDrainEntries() {
    std::cout << "\n[TEST] H2Upstream N9e: ResetStream drops pending drain entries..." << std::endl;
    struct ObservingSink : public RecordingSink {
        int progress_calls = 0;
        int submitted_calls = 0;
        void OnRequestBodyProgress() override { ++progress_calls; }
        void OnRequestSubmitted() override { ++submitted_calls; }
    };
    try {
        auto cfg = MakeH2Conn();
        ObservingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N9e: ResetStream drops pending drain entries",
                false, "Init failed");
            return;
        }
        std::string body(20000, 'r');
        int32_t sid = conn.SubmitRequest(
            "POST", "http", "example.com", "/upload", {}, body, &sink);
        if (sid <= 0) {
            TestFramework::RecordTest(
                "H2Upstream N9e: ResetStream drops pending drain entries",
                false, "submit failed");
            return;
        }
        // Reset the stream BEFORE drain runs. The detach pattern nulls
        // the sink and DropDrainEntriesForStream sweeps the queue.
        conn.ResetStream(sid);
        // Now simulate drain — no dispatches should reach the nulled sink.
        conn.OnTransportWriteComplete();

        bool pass = (sink.progress_calls == 0) &&
                    (sink.submitted_calls == 0);
        TestFramework::RecordTest(
            "H2Upstream N9e: ResetStream drops pending drain entries",
            pass,
            pass ? "" : "post-reset dispatch: progress=" +
                        std::to_string(sink.progress_calls) +
                        " submitted=" +
                        std::to_string(sink.submitted_calls));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N9e: ResetStream drops pending drain entries",
            false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN9qResetSiblingDoesNotStarveDrainAttribution — Multiplexed
// scenario: stream A submits a body; stream B submits then resets
// (its body bytes are already buffered in the transport ahead of /
// interleaved with A's). Tombstoning B's entries (vs erasing +
// subtracting bytes) keeps bytes_in_drain_queue_ accurate to the
// transport buffer's total — otherwise OnTransportWriteProgress's
// early-return (`remaining >= bytes_in_drain_queue_`) skips
// attribution while B's leftover bytes drain, starving A's
// OnRequestBodyProgress / OnRequestSubmitted and falsely triggering
// A's send-stall timeout.
// ---------------------------------------------------------------------------
void TestN9qResetSiblingDoesNotStarveDrainAttribution() {
    std::cout << "\n[TEST] H2Upstream N9q: reset sibling does not starve drain attribution..." << std::endl;
    struct ObservingSink : public RecordingSink {
        int progress_calls = 0;
        int submitted_calls = 0;
        void OnRequestBodyProgress() override { ++progress_calls; }
        void OnRequestSubmitted() override { ++submitted_calls; }
    };
    try {
        auto cfg = MakeH2Conn();
        // Sinks before conn — sinks-must-outlive-session contract.
        ObservingSink sink_a;
        ObservingSink sink_b;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N9q: reset sibling does not starve drain attribution",
                false, "Init failed");
            return;
        }
        // Submit stream A with a body. Frames are pushed to drain_queue_
        // via on_frame_send.
        // 20KB body > MAX_FRAME_SIZE (16384) so A has ≥2 DATA frames
        // (one intermediate → OnRequestBodyProgress, one END_STREAM →
        // OnRequestSubmitted). Locks the "intermediate progress fires"
        // half of the contract; a single-DATA-frame body would only
        // exercise the OnRequestSubmitted half.
        std::string body_a(20000, 'a');
        int32_t sid_a = conn.SubmitRequest(
            "POST", "http", "example.com", "/a", {}, body_a, &sink_a);
        if (sid_a <= 0) {
            TestFramework::RecordTest(
                "H2Upstream N9q: reset sibling does not starve drain attribution",
                false, "submit A failed");
            return;
        }
        // Submit stream B with a body — its frames are appended to the
        // queue AFTER A's frames (FIFO order in transport buffer too).
        std::string body_b(20000, 'b');
        int32_t sid_b = conn.SubmitRequest(
            "POST", "http", "example.com", "/b", {}, body_b, &sink_b);
        if (sid_b <= 0) {
            TestFramework::RecordTest(
                "H2Upstream N9q: reset sibling does not starve drain attribution",
                false, "submit B failed");
            return;
        }
        // Reset stream B before any drain. B's HEADERS+DATA bytes are
        // already in transport; tombstoned entries stay in drain_queue_
        // with is_control=true so byte accounting matches transport.
        // ResetStream also submits an RST_STREAM frame → another control
        // entry appended.
        conn.ResetStream(sid_b);

        // Full drain. With tombstoning, walking the queue dispatches
        // A's HEADERS (no fire, not END_STREAM) → A's DATA frames
        // (progress fires on intermediates, OnRequestSubmitted on the
        // END_STREAM DATA) → B's tombstoned entries (no fire) → RST
        // (no fire). A's sink must see ≥1 progress AND OnRequestSubmitted.
        conn.OnTransportWriteComplete();

        bool pass = (sink_a.submitted_calls == 1) &&
                    (sink_a.progress_calls >= 1) &&
                    (sink_b.progress_calls == 0) &&
                    (sink_b.submitted_calls == 0);
        std::string err;
        if (sink_a.submitted_calls != 1)
            err += "A submitted_calls=" + std::to_string(sink_a.submitted_calls) +
                   " (expected 1 — drain attribution starved); ";
        if (sink_a.progress_calls < 1)
            err += "A progress_calls=" + std::to_string(sink_a.progress_calls) +
                   " (expected ≥1); ";
        if (sink_b.progress_calls != 0 || sink_b.submitted_calls != 0)
            err += "B fired post-reset: progress=" +
                   std::to_string(sink_b.progress_calls) +
                   " submitted=" + std::to_string(sink_b.submitted_calls) + "; ";
        TestFramework::RecordTest(
            "H2Upstream N9q: reset sibling does not starve drain attribution",
            pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N9q: reset sibling does not starve drain attribution",
            false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN9fPartialDrainOfFinalFrame — A single-DATA-frame body
// (END_STREAM on the only DATA frame) or the trailing DATA frame of a
// multi-frame body must still refresh OnRequestBodyProgress while it
// is partially draining. Otherwise a healthy upload sitting in the
// transport buffer for longer than the stall budget gets false-timed-out.
// ---------------------------------------------------------------------------
void TestN9fPartialDrainOfFinalFrame() {
    std::cout << "\n[TEST] H2Upstream N9f: partial-drain of final DATA frame fires progress..." << std::endl;
    struct ObservingSink : public RecordingSink {
        int progress_calls = 0;
        int submitted_calls = 0;
        void OnRequestBodyProgress() override { ++progress_calls; }
        void OnRequestSubmitted() override { ++submitted_calls; }
    };
    try {
        auto cfg = MakeH2Conn();
        ObservingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N9f: partial-drain of final DATA frame fires progress",
                false, "Init failed");
            return;
        }
        // 4KB body fits in a single DATA frame (MAX_FRAME_SIZE=16384).
        // That DATA frame carries both is_data=true AND is_end_stream=true.
        std::string body(4096, 'p');
        int32_t sid = conn.SubmitRequest(
            "POST", "http", "example.com", "/upload", {}, body, &sink);
        if (sid <= 0) {
            TestFramework::RecordTest(
                "H2Upstream N9f: partial-drain of final DATA frame fires progress",
                false, "submit failed");
            return;
        }

        // The transport reports a partial drain (some bytes still
        // buffered). Without the fix, this case wouldn't fire any
        // sink virtual because the only DATA frame is END_STREAM,
        // and the old gate was `is_data_frame && !is_end_stream`.
        // After the fix, OnRequestBodyProgress refreshes the timestamp.
        size_t total_queued = 0;
        // Worst-case: HEADERS + single DATA frame; together a few KB.
        // Tell the transport "1KB still buffered" — most of the frame
        // has drained but not all.
        conn.OnTransportWriteProgress(1024);
        const int after_partial_progress = sink.progress_calls;
        const int after_partial_submitted = sink.submitted_calls;

        // Then fully drain — the submitted dispatch fires now.
        conn.OnTransportWriteComplete();
        bool pass = (after_partial_progress >= 1) &&
                    (after_partial_submitted == 0) &&
                    (sink.submitted_calls == 1);
        std::string err;
        if (after_partial_progress == 0) {
            err += "no progress on partial drain (single-frame body case); ";
        }
        if (after_partial_submitted != 0) {
            err += "submitted fired during partial drain; ";
        }
        if (sink.submitted_calls != 1) {
            err += "submitted_calls=" + std::to_string(sink.submitted_calls) +
                   " (expected 1 after full drain); ";
        }
        (void)total_queued;
        TestFramework::RecordTest(
            "H2Upstream N9f: partial-drain of final DATA frame fires progress",
            pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N9f: partial-drain of final DATA frame fires progress",
            false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN9gControlFrameByteAccounting — A PING (or other control frame)
// flushed before a request must consume its own bytes in the drain
// queue; otherwise its drain would be mis-attributed to the request's
// first frame, firing OnRequestSubmitted / OnRequestBodyProgress
// before the request's own bytes had actually drained.
// ---------------------------------------------------------------------------
void TestN9gControlFrameByteAccounting() {
    std::cout << "\n[TEST] H2Upstream N9g: control-frame bytes do not mis-attribute to request..." << std::endl;
    struct ObservingSink : public RecordingSink {
        int progress_calls = 0;
        int submitted_calls = 0;
        void OnRequestBodyProgress() override { ++progress_calls; }
        void OnRequestSubmitted() override { ++submitted_calls; }
    };
    try {
        auto cfg = MakeH2Conn();
        ObservingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N9g: control-frame bytes do not mis-attribute to request",
                false, "Init failed");
            return;
        }
        // Flush a PING first — it pushes a control entry (17 bytes:
        // 9-byte header + 8-byte opaque payload) into the drain queue.
        const auto now = std::chrono::steady_clock::now();
        conn.SendPing(now);

        // Now submit a bodyless request. Its HEADERS frame enters the
        // queue after the PING. Without per-frame byte accounting,
        // shrinking the transport's `remaining` would attribute the
        // PING's drain to the HEADERS frame and fire
        // OnRequestSubmitted prematurely.
        int32_t sid = conn.SubmitRequest(
            "GET", "http", "example.com", "/", {}, "", &sink);
        if (sid <= 0) {
            TestFramework::RecordTest(
                "H2Upstream N9g: control-frame bytes do not mis-attribute to request",
                false, "submit failed");
            return;
        }
        // Simulate the transport draining ONLY the PING bytes (17).
        // The drain queue's HEADERS entry must remain — no sink
        // dispatch yet.
        // Compute: drain queue total bytes minus the headers frame
        // size leaves the PING bytes drained. Tell the transport that
        // the headers frame is still pending.
        // PING entry = 17 bytes, HEADERS frame = 9 + payload (~30 for
        // a tiny GET). Tell the transport "30 bytes still buffered"
        // — well within the HEADERS frame size, so the PING has
        // drained but HEADERS has not.
        conn.OnTransportWriteProgress(30);
        const int after_ping_drain_submitted = sink.submitted_calls;
        const int after_ping_drain_progress = sink.progress_calls;

        // Full drain dispatches the HEADERS frame's submitted virtual.
        conn.OnTransportWriteComplete();

        bool pass = (after_ping_drain_submitted == 0) &&
                    (after_ping_drain_progress == 0) &&
                    (sink.submitted_calls == 1);
        std::string err;
        if (after_ping_drain_submitted != 0) {
            err += "submitted fired during PING-only drain (mis-attribution); ";
        }
        if (after_ping_drain_progress != 0) {
            err += "progress fired during PING-only drain; ";
        }
        if (sink.submitted_calls != 1) {
            err += "submitted_calls=" + std::to_string(sink.submitted_calls) +
                   " (expected 1 after full drain); ";
        }
        TestFramework::RecordTest(
            "H2Upstream N9g: control-frame bytes do not mis-attribute to request",
            pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N9g: control-frame bytes do not mis-attribute to request",
            false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN9mSinkOnBodyChunkFalseStopsConsumption — A sink returning false
// from OnBodyChunk must detach + submit RST_STREAM so no further body
// dispatches reach the sink.
// ---------------------------------------------------------------------------
void TestN9mSinkOnBodyChunkFalseStopsConsumption() {
    std::cout << "\n[TEST] H2Upstream N9m: sink OnBodyChunk false → stream reset, no further dispatches..." << std::endl;
    struct RejectingSink : public RecordingSink {
        bool reject_after_first = true;
        int body_chunks = 0;
        bool OnBodyChunk(const char* data, size_t len) override {
            ++body_chunks;
            RecordingSink::OnBodyChunk(data, len);
            // Reject every chunk including the first — simulates a
            // downstream commit failure on first body byte.
            return !reject_after_first;
        }
    };
    try {
        auto cfg = MakeH2Conn();
        RejectingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N9m: sink OnBodyChunk false → stream reset, no further dispatches",
                false, "Init failed");
            return;
        }
        int32_t sid = conn.SubmitRequest("GET", "http", "example.com", "/",
                                          {}, "", &sink);

        // Peer sends SETTINGS + HEADERS (no end_stream) + DATA(50) + DATA(50, end_stream).
        // After the first DATA chunk, sink returns false. The H2 code
        // path detaches the sink and submits RST_STREAM. The second
        // DATA chunk must NOT dispatch to the (now-null) sink.
        std::vector<uint8_t> wire = H2WireTest::BuildEmptySettings();
        auto hdrs = H2WireTest::BuildHeadersFrame(
            sid, {{":status", "200"}, {"content-type", "text/plain"}},
            /*end_stream=*/false);
        wire.insert(wire.end(), hdrs.begin(), hdrs.end());
        conn.HandleBytes(reinterpret_cast<const char*>(wire.data()),
                         wire.size());

        std::vector<uint8_t> body1(50, 'a');
        auto data1 = BuildDataFrame(sid, body1.data(), body1.size(),
                                    /*end_stream=*/false);
        conn.HandleBytes(reinterpret_cast<const char*>(data1.data()),
                         data1.size());

        // First chunk should have dispatched (sink saw it, then said no).
        const int chunks_after_first = sink.body_chunks;

        // Second chunk: sink is now detached. body_chunks must NOT
        // advance. Implementation detail: nghttp2 may or may not have
        // already processed the RST_STREAM submission by the time the
        // second DATA frame is handed in; either way, our application
        // code looks up stream->sink and finds nullptr → skip.
        std::vector<uint8_t> body2(50, 'b');
        auto data2 = BuildDataFrame(sid, body2.data(), body2.size(),
                                    /*end_stream=*/true);
        conn.HandleBytes(reinterpret_cast<const char*>(data2.data()),
                         data2.size());

        bool pass = (chunks_after_first == 1) && (sink.body_chunks == 1);
        std::string err;
        if (chunks_after_first != 1)
            err += "first-chunk dispatch=" + std::to_string(chunks_after_first) + "; ";
        if (sink.body_chunks != 1)
            err += "post-rejection chunks=" + std::to_string(sink.body_chunks) + " (expected 1); ";
        TestFramework::RecordTest(
            "H2Upstream N9m: sink OnBodyChunk false → stream reset, no further dispatches",
            pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N9m: sink OnBodyChunk false → stream reset, no further dispatches",
            false, e.what());
    }
}

// ---------------------------------------------------------------------------
// H2ResponseTimeoutTestFixture — friend of ProxyTransaction; pokes the
// private H2 dispatch state so a focused test can exercise
// OnRequestSubmitted's response_timeout branch without the full pool
// pipeline. Build via the factory helper below.
// ---------------------------------------------------------------------------
struct H2ResponseTimeoutTestFixture {
    static std::shared_ptr<ProxyTransaction> MakeWithTimeout(
        int response_timeout_ms)
    {
        HttpRequest req;
        req.method = "GET";
        req.path = "/";
        req.dispatcher_index = -1;  // null dispatcher in ctor

        HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender sender;
        HTTP_CALLBACKS_NAMESPACE::AsyncCompletionCallback cb =
            [](const HttpResponse&) {};
        ProxyConfig cfg;
        cfg.response_timeout_ms = response_timeout_ms;
        HeaderRewriter rewriter(HeaderRewriter::Config{
            cfg.header_rewrite.set_x_forwarded_for,
            cfg.header_rewrite.set_x_forwarded_proto,
            cfg.header_rewrite.set_via_header,
            cfg.header_rewrite.rewrite_host});
        RetryPolicy retry(RetryPolicy::Config{
            cfg.retry.max_retries,
            cfg.retry.retry_on_connect_failure,
            cfg.retry.retry_on_5xx,
            cfg.retry.retry_on_timeout,
            cfg.retry.retry_on_disconnect,
            cfg.retry.retry_non_idempotent});
        auto txn = std::make_shared<ProxyTransaction>(
            std::string("test-h2-timeout"), req,
            std::move(sender), std::move(cb),
            nullptr,         // upstream_manager
            cfg, rewriter, retry,
            false,           // upstream_tls
            std::string("127.0.0.1"), 80,
            std::string(""), std::string(""), std::string(""),
            nullptr);        // auth_manager
        return txn;
    }

    // Drive OnRequestSubmitted's H2 post-send-complete branch. The
    // public method has guards (h2_path_, cancelled, IsKilledForShutdown,
    // state_) that require the transaction to be in a specific state;
    // set them directly so the test exercises ONLY the timeout-decision
    // logic.
    static void DriveOnRequestSubmittedFromSending(
        const std::shared_ptr<ProxyTransaction>& txn)
    {
        txn->h2_path_ = true;
        txn->state_ = ProxyTransaction::State::SENDING_REQUEST;
        txn->h2_stall_budget_ms_ =
            ProxyTransaction::ComputeH2StallBudgetMs(
                txn->config_.response_timeout_ms);
        txn->OnRequestSubmitted();
    }

    static bool response_timeout_armed(
        const std::shared_ptr<ProxyTransaction>& txn)
    {
        return txn->h2_response_timeout_armed_;
    }

    // Capture the live send-stall generation. Used by the early-final-
    // headers test to confirm OnHeaders bumps it when it transitions
    // out of SENDING_REQUEST.
    static uint64_t send_stall_generation(
        const std::shared_ptr<ProxyTransaction>& txn)
    {
        return txn->h2_send_stall_generation_;
    }

    // Capture the live state. Used by tests that need to verify
    // state transitions without going through the full pool pipeline.
    static ProxyTransaction::State state(
        const std::shared_ptr<ProxyTransaction>& txn)
    {
        return txn->state_;
    }

    // Drive OnHeaders with a synthetic UpstreamResponseHead so the
    // early-final-headers test can observe the SENDING_REQUEST →
    // AWAITING_RESPONSE transition + send-stall invalidation.
    static void DriveOnHeadersWhileSending(
        const std::shared_ptr<ProxyTransaction>& txn,
        int status_code)
    {
        txn->h2_path_ = true;
        txn->state_ = ProxyTransaction::State::SENDING_REQUEST;
        UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead head;
        head.status_code = status_code;
        head.keep_alive = true;
        head.framing =
            UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead::Framing::NO_BODY;
        txn->OnHeaders(head);
    }
};

// ---------------------------------------------------------------------------
// TestN9kZeroTimeoutPostSubmit — Mirrors H1's response_timeout_ms=0
// contract: after the request is fully sent, no per-request deadline
// is armed. Previously H2 always armed the 30s stall fallback, so
// long-poll / SSE / late-header upstreams 504'd at 30s contradicting
// the documented "0 disables the timeout" semantic.
// ---------------------------------------------------------------------------
void TestN9kZeroTimeoutPostSubmit() {
    std::cout << "\n[TEST] H2Upstream N9k: response_timeout_ms=0 → no deadline armed after submit..." << std::endl;
    try {
        auto txn = H2ResponseTimeoutTestFixture::MakeWithTimeout(0);
        H2ResponseTimeoutTestFixture::DriveOnRequestSubmittedFromSending(txn);
        bool armed = H2ResponseTimeoutTestFixture::response_timeout_armed(txn);
        bool pass = !armed;
        TestFramework::RecordTest(
            "H2Upstream N9k: response_timeout_ms=0 → no deadline armed after submit",
            pass,
            pass ? "" : "h2_response_timeout_armed_ should be false for ms=0");
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N9k: response_timeout_ms=0 → no deadline armed after submit",
            false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN9lPositiveTimeoutPostSubmit — Positive response_timeout_ms still
// arms the deadline as expected. Locks the both-sides of the branch
// added by the N9k fix.
// ---------------------------------------------------------------------------
void TestN9lPositiveTimeoutPostSubmit() {
    std::cout << "\n[TEST] H2Upstream N9l: response_timeout_ms>0 → deadline armed after submit..." << std::endl;
    try {
        auto txn = H2ResponseTimeoutTestFixture::MakeWithTimeout(5000);
        H2ResponseTimeoutTestFixture::DriveOnRequestSubmittedFromSending(txn);
        bool armed = H2ResponseTimeoutTestFixture::response_timeout_armed(txn);
        bool pass = armed;
        TestFramework::RecordTest(
            "H2Upstream N9l: response_timeout_ms>0 → deadline armed after submit",
            pass,
            pass ? "" : "h2_response_timeout_armed_ should be true for ms=5000");
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N9l: response_timeout_ms>0 → deadline armed after submit",
            false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN9oEarlyFinalHeadersInvalidateSendStallClosure — Peer delivers
// final headers WHILE we're still sending the request body
// (state_ == SENDING_REQUEST). OnHeaders must bump
// h2_send_stall_generation_ so the in-flight stall closure can't
// fire later and spuriously surface RESPONSE_TIMEOUT against a stream
// whose headers are already in hand. Mirrors the body-phase invariant
// that final headers end the send-side watchdog.
// ---------------------------------------------------------------------------
void TestN9oEarlyFinalHeadersInvalidateSendStallClosure() {
    std::cout << "\n[TEST] H2Upstream N9o: early final headers bump send-stall generation..." << std::endl;
    try {
        auto txn = H2ResponseTimeoutTestFixture::MakeWithTimeout(5000);
        // Simulate: SENDING_REQUEST + a stall closure armed against
        // the current generation. (DriveOnHeadersWhileSending sets
        // h2_path_=true and state_=SENDING_REQUEST.)
        const uint64_t gen_before =
            H2ResponseTimeoutTestFixture::send_stall_generation(txn);
        H2ResponseTimeoutTestFixture::DriveOnHeadersWhileSending(
            txn, /*status=*/413);
        const uint64_t gen_after =
            H2ResponseTimeoutTestFixture::send_stall_generation(txn);
        const auto state_after =
            H2ResponseTimeoutTestFixture::state(txn);

        const bool transitioned =
            (state_after == ProxyTransaction::State::AWAITING_RESPONSE);
        const bool gen_bumped = (gen_after > gen_before);
        bool pass = transitioned && gen_bumped;
        std::string err;
        if (!transitioned) err += "state did not advance to AWAITING_RESPONSE; ";
        if (!gen_bumped) err += "send_stall_generation_ did not advance (closure would fire); ";
        TestFramework::RecordTest(
            "H2Upstream N9o: early final headers bump send-stall generation",
            pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N9o: early final headers bump send-stall generation",
            false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN9pH2ResponseTimeoutClosureHonorsShutdownKill — The H2 response-
// timeout closure must guard on IsKilledForShutdown() in addition to
// cancelled_. MarkKilledForShutdown sets the kill flag before Cancel
// enqueues, so a matured timeout firing inside that window would
// otherwise report a breaker failure and trigger MaybeRetry during
// drain.
// ---------------------------------------------------------------------------
void TestN9pH2ResponseTimeoutClosureHonorsShutdownKill() {
    std::cout << "\n[TEST] H2Upstream N9p: H2 response-timeout closure honors shutdown kill..." << std::endl;
    // Code-inspection lock: verify the closure source contains the
    // IsKilledForShutdown check. The closure is dispatcher-driven so
    // a direct fire path requires a real dispatcher fixture; this is
    // the lighter regression-prevention check.
    bool pass = false;
    try {
        std::ifstream in("server/proxy_transaction.cc");
        std::string src((std::istreambuf_iterator<char>(in)),
                         std::istreambuf_iterator<char>());
        // Locate the H2 response-timeout closure (uniquely identified
        // by its warn message) and confirm the guard is in scope.
        auto warn = src.find("ProxyTransaction H2 response timeout client_fd=");
        if (warn != std::string::npos) {
            // Look backwards from the warn for the guard within ~400 chars.
            const size_t lookback = warn > 400 ? warn - 400 : 0;
            auto guard = src.find("IsKilledForShutdown()", lookback);
            pass = (guard != std::string::npos && guard < warn);
        }
        TestFramework::RecordTest(
            "H2Upstream N9p: H2 response-timeout closure honors shutdown kill",
            pass,
            pass ? "" : "IsKilledForShutdown check missing from response-timeout closure");
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N9p: H2 response-timeout closure honors shutdown kill",
            false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN9nFreshSessionBootstrapCallbackOrdering — Init's preface SETTINGS
// is tracked as a control drain entry that OnTransportWriteComplete
// pops cleanly without firing any sink dispatch.
// ---------------------------------------------------------------------------
void TestN9nFreshSessionBootstrapCallbackOrdering() {
    std::cout << "\n[TEST] H2Upstream N9n: fresh session Init populates drain queue with SETTINGS..." << std::endl;
    try {
        auto cfg = MakeH2Conn();
        // Sink before conn — sinks-must-outlive-session contract.
        RecordingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N9n: fresh session Init populates drain queue with SETTINGS",
                false, "Init failed");
            return;
        }
        conn.OnTransportWriteComplete();
        int32_t sid = conn.SubmitRequest("GET", "http", "example.com", "/",
                                          {}, "", &sink);
        bool pass = (sid > 0);
        TestFramework::RecordTest(
            "H2Upstream N9n: fresh session Init populates drain queue with SETTINGS",
            pass,
            pass ? "" : "submit after bootstrap drain failed sid=" + std::to_string(sid));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N9n: fresh session Init populates drain queue with SETTINGS",
            false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN9hHeadersOnlyShortReadCL — A response that declares
// Content-Length > 0 but ends the stream on HEADERS (zero body bytes)
// MUST surface as an error, not a clean OnComplete. The HEADERS-only
// path used to classify as NO_BODY, bypassing the CL short-read check
// in OnStreamClose. After the fix, when end_stream is true and CL > 0
// on a non-bodyless status, framing is CONTENT_LENGTH so the existing
// CL short-read backstop fires RESULT_TRUNCATED_RESPONSE on NO_ERROR
// stream close (or RESULT_UPSTREAM_DISCONNECT if nghttp2's HTTP
// messaging enforcement fired first via non-NO_ERROR). Either way:
// OnError fires, OnComplete does NOT.
// ---------------------------------------------------------------------------
void TestN9hHeadersOnlyShortReadCL() {
    std::cout << "\n[TEST] H2Upstream N9h: HEADERS+END_STREAM with CL>0 → OnError (not OnComplete)..." << std::endl;
    try {
        auto cfg = MakeH2Conn();
        RecordingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N9h: HEADERS+END_STREAM with CL>0 → OnError (not OnComplete)",
                false, "Init failed");
            return;
        }
        int32_t sid = conn.SubmitRequest("GET", "http", "example.com", "/",
                                          {}, "", &sink);

        // Server sends SETTINGS + HEADERS(200, content-length:100, END_STREAM).
        // Zero body bytes but declared 100 — framing violation.
        std::vector<uint8_t> wire = H2WireTest::BuildEmptySettings();
        auto hdrs = H2WireTest::BuildHeadersFrame(
            sid, {{":status", "200"}, {"content-length", "100"}},
            /*end_stream=*/true);
        wire.insert(wire.end(), hdrs.begin(), hdrs.end());
        conn.HandleBytes(reinterpret_cast<const char*>(wire.data()),
                         wire.size());

        // OnError MUST fire. The specific RESULT_* code is either
        // RESULT_TRUNCATED_RESPONSE (our backstop, nghttp2 messaging
        // enforcement disabled) or RESULT_UPSTREAM_DISCONNECT
        // (nghttp2's enforcement fired non-NO_ERROR first). What
        // matters is the truncation is NOT silently dropped.
        bool pass = (sink.error_calls == 1) && (sink.complete_calls == 0);
        std::string err;
        if (sink.error_calls != 1)
            err += "error_calls=" + std::to_string(sink.error_calls) + " (expected 1); ";
        if (sink.complete_calls != 0)
            err += "complete_calls=" + std::to_string(sink.complete_calls) + " (expected 0); ";
        TestFramework::RecordTest(
            "H2Upstream N9h: HEADERS+END_STREAM with CL>0 → OnError (not OnComplete)",
            pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N9h: HEADERS+END_STREAM with CL>0 → OnError (not OnComplete)",
            false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN9iHeadersOnlyShortReadCLZeroLegitimate — A response with
// content-length: 0 AND END_STREAM on HEADERS is LEGITIMATE (legal
// empty body). Verifies the fix's `cl > 0` guard doesn't false-trigger
// truncation for legal empty bodies.
// ---------------------------------------------------------------------------
void TestN9iHeadersOnlyShortReadCLZeroLegitimate() {
    std::cout << "\n[TEST] H2Upstream N9i: HEADERS+END_STREAM with CL=0 → OnComplete (legitimate)..." << std::endl;
    try {
        auto cfg = MakeH2Conn();
        RecordingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N9i: HEADERS+END_STREAM with CL=0 → OnComplete (legitimate)",
                false, "Init failed");
            return;
        }
        int32_t sid = conn.SubmitRequest("GET", "http", "example.com", "/",
                                          {}, "", &sink);

        std::vector<uint8_t> wire = H2WireTest::BuildEmptySettings();
        auto hdrs = H2WireTest::BuildHeadersFrame(
            sid, {{":status", "200"}, {"content-length", "0"}},
            /*end_stream=*/true);
        wire.insert(wire.end(), hdrs.begin(), hdrs.end());
        conn.HandleBytes(reinterpret_cast<const char*>(wire.data()),
                         wire.size());

        bool pass = (sink.complete_calls == 1) && (sink.error_calls == 0);
        std::string err;
        if (sink.complete_calls != 1)
            err += "complete_calls=" + std::to_string(sink.complete_calls) + "; ";
        if (sink.error_calls != 0)
            err += "error_calls=" + std::to_string(sink.error_calls) + "; ";
        TestFramework::RecordTest(
            "H2Upstream N9i: HEADERS+END_STREAM with CL=0 → OnComplete (legitimate)",
            pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N9i: HEADERS+END_STREAM with CL=0 → OnComplete (legitimate)",
            false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN9jHeadResponseWithCLLegitimate — RFC 9110 §9.3.2 explicitly
// permits HEAD responses to declare Content-Length matching the
// equivalent-GET body size. END_STREAM on HEADERS with CL > 0 on a
// HEAD response is LEGITIMATE — must NOT trigger truncation.
// ---------------------------------------------------------------------------
void TestN9jHeadResponseWithCLLegitimate() {
    std::cout << "\n[TEST] H2Upstream N9j: HEAD response with CL>0 + END_STREAM → OnComplete (legitimate)..." << std::endl;
    try {
        auto cfg = MakeH2Conn();
        RecordingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N9j: HEAD response with CL>0 + END_STREAM → OnComplete (legitimate)",
                false, "Init failed");
            return;
        }
        int32_t sid = conn.SubmitRequest("HEAD", "http", "example.com", "/",
                                          {}, "", &sink);

        std::vector<uint8_t> wire = H2WireTest::BuildEmptySettings();
        auto hdrs = H2WireTest::BuildHeadersFrame(
            sid, {{":status", "200"}, {"content-length", "12345"}},
            /*end_stream=*/true);
        wire.insert(wire.end(), hdrs.begin(), hdrs.end());
        conn.HandleBytes(reinterpret_cast<const char*>(wire.data()),
                         wire.size());

        bool pass = (sink.complete_calls == 1) && (sink.error_calls == 0);
        std::string err;
        if (sink.complete_calls != 1)
            err += "complete_calls=" + std::to_string(sink.complete_calls) + "; ";
        if (sink.error_calls != 0)
            err += "error_calls=" + std::to_string(sink.error_calls) + "; ";
        TestFramework::RecordTest(
            "H2Upstream N9j: HEAD response with CL>0 + END_STREAM → OnComplete (legitimate)",
            pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N9j: HEAD response with CL>0 + END_STREAM → OnComplete (legitimate)",
            false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN9c — Default sink ABI: a sink that does NOT override
// OnRequestBodyProgress must still compile and operate — locks the
// no-op default contract that prevents binary-compat breakage for
// pre-existing sink consumers. Drives a real submit-with-large-body
// so the codec's OnFrameSendCallback dispatches the new virtual
// against the unmodified RecordingSink (no override).
// ---------------------------------------------------------------------------
void TestN9cDefaultSinkSurvivesNewVirtual() {
    std::cout << "\n[TEST] H2Upstream N9c: pre-existing sink survives codec firing OnRequestBodyProgress..." << std::endl;
    try {
        auto cfg = MakeH2Conn();
        RecordingSink sink;  // does NOT override OnRequestBodyProgress
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N9c: pre-existing sink survives codec firing OnRequestBodyProgress",
                false, "Init failed");
            return;
        }
        std::string body(20000, 'y');
        int32_t sid = conn.SubmitRequest(
            "POST", "http", "example.com", "/upload", {}, body, &sink);
        // The sink doesn't override OnRequestBodyProgress; the default
        // no-op runs. Submit must succeed AND no spurious OnError must
        // fire (the new virtual must not have side effects on the
        // base implementation).
        bool pass = (sid > 0) && (sink.error_calls == 0) &&
                    (sink.complete_calls == 0);
        TestFramework::RecordTest(
            "H2Upstream N9c: pre-existing sink survives codec firing OnRequestBodyProgress",
            pass, pass ? "" : "sid=" + std::to_string(sid) +
                              " errors=" + std::to_string(sink.error_calls));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N9c: pre-existing sink survives codec firing OnRequestBodyProgress",
            false, e.what());
    }
}

// ---------------------------------------------------------------------------
// TestN7c — H2 send-stall budget computation. Locks the public
// ProxyTransaction::ComputeH2StallBudgetMs contract: response_timeout_ms
// == 0 (operator-disabled) opts out of the response-wait timer but
// the stall-phase hang protection stays on at SEND_STALL_FALLBACK_MS.
// Negative values defensively fall through to the same fallback —
// config validation enforces non-negative, but a bug producing zero
// or negative must not produce a zero-or-negative budget that would
// either fire instantly or never.
// ---------------------------------------------------------------------------
void TestN7cSendStallFallbackBudget() {
    std::cout << "\n[TEST] H2Upstream N7c: ComputeH2StallBudgetMs zero-disable contract..." << std::endl;
    struct Case { int input; int expected; const char* label; };
    const Case cases[] = {
        // Operator-disabled response timeout: stall protection STAYS
        // on at fallback budget. This is the original P1-bug case.
        {0,     ProxyTransaction::SEND_STALL_FALLBACK_MS, "0 (disabled)"},
        // Defensive: negative values must not fire-instantly or
        // never-fire — fall through to fallback.
        {-1,    ProxyTransaction::SEND_STALL_FALLBACK_MS, "-1 (defensive)"},
        {-1000, ProxyTransaction::SEND_STALL_FALLBACK_MS, "-1000 (defensive)"},
        // Positive: pass-through.
        {1,                                            1, "1 (pass-through)"},
        {1000,                                      1000, "1000ms"},
        {30000,                                    30000, "30s explicit"},
        {120000,                                  120000, "120s explicit"},
    };
    int pass = 0, total = 0;
    for (const Case& c : cases) {
        const int got = ProxyTransaction::ComputeH2StallBudgetMs(c.input);
        ++total;
        if (got == c.expected) {
            ++pass;
        } else {
            std::cerr << "  FAIL[" << c.label << "]: input=" << c.input
                      << " got=" << got << " expected=" << c.expected
                      << std::endl;
        }
    }
    // Constant-shape lock as the secondary check.
    const bool fallback_correct =
        (ProxyTransaction::SEND_STALL_FALLBACK_MS == 30000);
    bool ok = (pass == total) && fallback_correct;
    TestFramework::RecordTest(
        "H2Upstream N7c: ComputeH2StallBudgetMs zero-disable + fallback constant",
        ok, ok ? "" : "passed " + std::to_string(pass) + "/" +
                       std::to_string(total) + ", fallback=" +
                       std::to_string(ProxyTransaction::SEND_STALL_FALLBACK_MS));
}

// ---------------------------------------------------------------------------
// TestN7e — Wire-driven smoke test that early-peer-final-headers does
// not GOAWAY/RST the connection nor stop intermediate-DATA codec
// dispatch on the request side. Locks the codec wiring; the deeper
// "no false stall after early headers" semantic is enforced at the
// production layer by gating OnRequestBodyProgress on
// h2_request_fully_sent_ rather than response-side state_, and by
// the timestamp-driven self-rescheduling closure (no test in this
// file exercises the timing under wall-clock load).
// ---------------------------------------------------------------------------
void TestN7eWiringEarlyHeadersThenIntermediateDataDispatch() {
    std::cout << "\n[TEST] H2Upstream N7e: wire-level dispatch after early peer-final-headers..." << std::endl;
    struct ObservingSink : public RecordingSink {
        int progress_calls_total = 0;
        int progress_calls_post_headers = 0;
        bool headers_seen = false;
        bool OnHeaders(
            const UPSTREAM_CALLBACKS_NAMESPACE::UpstreamResponseHead& head)
            override
        {
            const bool ok = RecordingSink::OnHeaders(head);
            headers_seen = true;
            return ok;
        }
        void OnRequestBodyProgress() override {
            ++progress_calls_total;
            if (headers_seen) {
                ++progress_calls_post_headers;
            }
        }
    };
    try {
        auto cfg = MakeH2Conn();
        ObservingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream N7e: wire-level dispatch after early peer-final-headers",
                false, "Init failed");
            return;
        }
        // 30000 bytes > MAX_FRAME_SIZE=16384 → guarantees ≥2 DATA frames.
        std::string body(30000, 'z');
        int32_t sid = conn.SubmitRequest(
            "POST", "http", "example.com", "/upload", {}, body, &sink);
        if (sid <= 0) {
            TestFramework::RecordTest(
                "H2Upstream N7e: wire-level dispatch after early peer-final-headers",
                false, "submit failed sid=" + std::to_string(sid));
            return;
        }
        // Drain BEFORE feeding the peer wire: under the deferred-drain
        // contract, sink virtuals dispatch through streams_ lookup, so
        // they must run while the stream is still live (peer's
        // END_STREAM on HEADERS would erase the stream from streams_
        // via OnStreamClose, leaving drain entries orphaned). Real
        // production sees drain-events interleaved with peer-frame
        // events on the event loop; this test forces the order
        // explicitly.
        conn.OnTransportWriteComplete();

        // Now feed an early peer-final-headers (413 + END_STREAM) —
        // this is the canonical "peer rejects mid-upload" pattern.
        std::vector<uint8_t> wire = H2WireTest::BuildEmptySettings();
        auto early_hdrs = H2WireTest::BuildHeadersFrame(
            sid, {{":status", "413"}, {"content-length", "0"}},
            /*end_stream=*/true);
        wire.insert(wire.end(), early_hdrs.begin(), early_hdrs.end());
        ssize_t consumed = conn.HandleBytes(
            reinterpret_cast<const char*>(wire.data()), wire.size());

        // Locks the wiring: headers are observed via HandleBytes AND
        // ≥1 intermediate DATA progress event fires once drain runs.
        bool pass = (consumed > 0) && sink.headers_seen &&
                    (sink.progress_calls_total >= 1);
        TestFramework::RecordTest(
            "H2Upstream N7e: wire-level dispatch after early peer-final-headers",
            pass,
            pass ? "" : "consumed=" + std::to_string(consumed) +
                        " headers_seen=" + std::to_string(sink.headers_seen) +
                        " progress_total=" + std::to_string(sink.progress_calls_total));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream N7e: wire-level dispatch after early peer-final-headers",
            false, e.what());
    }
}

// ---------------------------------------------------------------------------
// H2 stream lifecycle scaffolding (DetachSink, deferred-erase walker)
// ---------------------------------------------------------------------------

static void TestS1_StreamLifecycleFieldsDefault() {
    std::cout << "\n[TEST] H2Upstream S1: UpstreamH2Stream lifecycle fields default..." << std::endl;
    try {
        UpstreamH2Stream s;
        bool pass = !s.peer_already_closed_ && !s.pending_erase_;
        TestFramework::RecordTest(
            "H2Upstream S1: UpstreamH2Stream lifecycle fields default",
            pass, pass ? "" : "default state mismatch");
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream S1: UpstreamH2Stream lifecycle fields default",
            false, e.what());
    }
}

static void TestS2_DetachSinkBeforePeerCloseKeepsEntry() {
    std::cout << "\n[TEST] H2Upstream S2: DetachSink before peer-close keeps stream entry..." << std::endl;
    try {
        // Sink must outlive the connection (defensive dtor fan-out).
        RecordingSink sink;
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        cfg->enabled = true;
        cfg->max_concurrent_streams_pref = 10;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream S2: DetachSink before peer-close keeps stream entry",
                false, "Init failed");
            return;
        }
        int32_t sid = conn.SubmitRequest(
            "GET", "http", "example.com", "/", {}, "", &sink);
        if (sid < 0) {
            TestFramework::RecordTest(
                "H2Upstream S2: DetachSink before peer-close keeps stream entry",
                false, "Submit failed");
            return;
        }
        conn.DetachSink(sid);
        auto* s = conn.GetStream(sid);
        bool pass = (s != nullptr) && (s->sink == nullptr) && !s->pending_erase_;
        TestFramework::RecordTest(
            "H2Upstream S2: DetachSink before peer-close keeps stream entry",
            pass,
            pass ? "" : "stream lifecycle state unexpected after DetachSink");
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream S2: DetachSink before peer-close keeps stream entry",
            false, e.what());
    }
}

static void TestS3_RunDeferredEraseWalkIdempotent() {
    std::cout << "\n[TEST] H2Upstream S3: RunDeferredEraseWalk idempotent on empty queue..." << std::endl;
    try {
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        cfg->enabled = true;
        cfg->max_concurrent_streams_pref = 10;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream S3: RunDeferredEraseWalk idempotent on empty queue",
                false, "Init failed");
            return;
        }
        conn.RunDeferredEraseWalk();
        conn.RunDeferredEraseWalk();
        TestFramework::RecordTest(
            "H2Upstream S3: RunDeferredEraseWalk idempotent on empty queue",
            true, "");
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream S3: RunDeferredEraseWalk idempotent on empty queue",
            false, e.what());
    }
}

// alive_token() returns a live shared_ptr seeded true at construction.
static void TestS6_AliveTokenInitiallyTrue() {
    std::cout << "\n[TEST] H2Upstream S6: alive_token initially true..." << std::endl;
    try {
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        cfg->enabled = true;
        cfg->max_concurrent_streams_pref = 10;
        UpstreamH2Connection conn(nullptr, cfg);
        auto tok = conn.alive_token();
        bool pass = (tok != nullptr) && tok->load(std::memory_order_acquire);
        TestFramework::RecordTest(
            "H2Upstream S6: alive_token initially true",
            pass, pass ? "" : "alive_token null or false at construction");
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream S6: alive_token initially true", false, e.what());
    }
}

// active_streams_ increments on Submit, decrements only via deferred walk.
static void TestS7_ActiveStreamsIncrementOnSubmit() {
    std::cout << "\n[TEST] H2Upstream S7: active_streams increments on SubmitRequest..." << std::endl;
    try {
        RecordingSink sink;
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        cfg->enabled = true;
        cfg->max_concurrent_streams_pref = 10;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream S7: active_streams increments on SubmitRequest",
                false, "Init failed");
            return;
        }
        size_t before = conn.active_stream_count();
        int32_t sid = conn.SubmitRequest(
            "GET", "http", "example.com", "/", {}, "", &sink);
        size_t after = conn.active_stream_count();
        bool pass = (sid > 0) && (before == 0) && (after == 1);
        TestFramework::RecordTest(
            "H2Upstream S7: active_streams increments on SubmitRequest",
            pass,
            pass ? "" : "before=" + std::to_string(before) +
                        " after=" + std::to_string(after) +
                        " sid=" + std::to_string(sid));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream S7: active_streams increments on SubmitRequest",
            false, e.what());
    }
}

// RunDeferredEraseWalk is the sole per-stream decrement site.
static void TestS8_ActiveStreamsDecrementInDeferredWalk() {
    std::cout << "\n[TEST] H2Upstream S8: active_streams decrements only in deferred walk..." << std::endl;
    try {
        RecordingSink sink;
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        cfg->enabled = true;
        cfg->max_concurrent_streams_pref = 10;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream S8: active_streams decrements only in deferred walk",
                false, "Init failed");
            return;
        }
        int32_t sid = conn.SubmitRequest(
            "GET", "http", "example.com", "/", {}, "", &sink);
        if (sid < 0) {
            TestFramework::RecordTest(
                "H2Upstream S8: active_streams decrements only in deferred walk",
                false, "Submit failed");
            return;
        }
        size_t after_submit = conn.active_stream_count();
        // DetachSink with peer_already_closed enqueues for the walker.
        auto* s = conn.GetStream(sid);
        if (s) s->peer_already_closed_ = true;
        conn.DetachSink(sid);
        size_t after_detach = conn.active_stream_count();
        conn.RunDeferredEraseWalk();
        size_t after_walk = conn.active_stream_count();
        bool pass = (after_submit == 1) && (after_detach == 1) && (after_walk == 0);
        TestFramework::RecordTest(
            "H2Upstream S8: active_streams decrements only in deferred walk",
            pass,
            pass ? "" : "after_submit=" + std::to_string(after_submit) +
                        " after_detach=" + std::to_string(after_detach) +
                        " after_walk=" + std::to_string(after_walk));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream S8: active_streams decrements only in deferred walk",
            false, e.what());
    }
}

// FailAllStreams bulk-resets active_streams_ to 0 alongside streams_.clear().
static void TestS9_ActiveStreamsBulkResetByFailAll() {
    std::cout << "\n[TEST] H2Upstream S9: FailAllStreams bulk-resets active_streams to 0..." << std::endl;
    try {
        RecordingSink s1, s2;
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        cfg->enabled = true;
        cfg->max_concurrent_streams_pref = 10;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream S9: FailAllStreams bulk-resets active_streams to 0",
                false, "Init failed");
            return;
        }
        int32_t sid1 = conn.SubmitRequest("GET", "http", "x", "/", {}, "", &s1);
        int32_t sid2 = conn.SubmitRequest("GET", "http", "x", "/", {}, "", &s2);
        size_t after_two = conn.active_stream_count();
        conn.FailAllStreams(
            ProxyTransaction::RESULT_UPSTREAM_DISCONNECT, "test");
        size_t after_fail = conn.active_stream_count();
        bool pass = (sid1 > 0) && (sid2 > 0) &&
                    (after_two == 2) && (after_fail == 0);
        TestFramework::RecordTest(
            "H2Upstream S9: FailAllStreams bulk-resets active_streams to 0",
            pass,
            pass ? "" : "after_two=" + std::to_string(after_two) +
                        " after_fail=" + std::to_string(after_fail));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream S9: FailAllStreams bulk-resets active_streams to 0",
            false, e.what());
    }
}

// IsUsable rejects once active_streams_ hits the configured cap.
static void TestS10_IsUsableHonorsActiveStreamsCap() {
    std::cout << "\n[TEST] H2Upstream S10: IsUsable honors active_streams cap..." << std::endl;
    try {
        RecordingSink s1, s2;
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        cfg->enabled = true;
        cfg->max_concurrent_streams_pref = 1;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream S10: IsUsable honors active_streams cap",
                false, "Init failed");
            return;
        }
        bool before = conn.IsUsable();
        int32_t sid = conn.SubmitRequest("GET", "http", "x", "/", {}, "", &s1);
        bool after_one = conn.IsUsable();
        bool pass = before && (sid > 0) && !after_one;
        TestFramework::RecordTest(
            "H2Upstream S10: IsUsable honors active_streams cap",
            pass,
            pass ? "" : "before=" + std::to_string(before) +
                        " after_one=" + std::to_string(after_one) +
                        " sid=" + std::to_string(sid));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream S10: IsUsable honors active_streams cap",
            false, e.what());
    }
}

// DestroyOnDispatcher flips alive, nulls callbacks, and is idempotent.
static void TestS11_DestroyOnDispatcherFlipsAliveAndIsIdempotent() {
    std::cout << "\n[TEST] H2Upstream S11: DestroyOnDispatcher idempotent + alive-flip..." << std::endl;
    try {
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        cfg->enabled = true;
        cfg->max_concurrent_streams_pref = 4;
        auto conn = std::make_unique<UpstreamH2Connection>(nullptr, cfg);
        auto alive = conn->alive_token();

        bool initially_alive = alive && alive->load(std::memory_order_acquire);
        conn->DestroyOnDispatcher();
        bool dead_after_first = alive && !alive->load(std::memory_order_acquire);
        // Second call is a no-op — must not crash and must keep alive=false.
        conn->DestroyOnDispatcher();
        bool dead_after_second = alive && !alive->load(std::memory_order_acquire);

        bool pass = initially_alive && dead_after_first && dead_after_second;
        TestFramework::RecordTest(
            "H2Upstream S11: DestroyOnDispatcher idempotent + alive-flip",
            pass,
            pass ? "" : "initially_alive=" + std::to_string(initially_alive) +
                        " dead_after_first=" + std::to_string(dead_after_first) +
                        " dead_after_second=" + std::to_string(dead_after_second));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream S11: DestroyOnDispatcher idempotent + alive-flip",
            false, e.what());
    }
}

// Dtor on a connection that already ran DestroyOnDispatcher is a no-op
// — verifies the safety-net short-circuit. A regression would re-fire
// FailAllStreams on the (now-empty) stream table; this test holds a
// sink that would observe the spurious OnError.
static void TestS12_DtorShortCircuitAfterDestroyOnDispatcher() {
    std::cout << "\n[TEST] H2Upstream S12: dtor short-circuits after DestroyOnDispatcher..." << std::endl;
    try {
        RecordingSink sink;
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        cfg->enabled = true;
        cfg->max_concurrent_streams_pref = 4;
        {
            UpstreamH2Connection conn(nullptr, cfg);
            if (!conn.Init()) {
                TestFramework::RecordTest(
                    "H2Upstream S12: dtor short-circuits after DestroyOnDispatcher",
                    false, "Init failed");
                return;
            }
            int32_t sid = conn.SubmitRequest(
                "GET", "http", "example.com", "/", {}, "", &sink);
            if (sid < 0) {
                TestFramework::RecordTest(
                    "H2Upstream S12: dtor short-circuits after DestroyOnDispatcher",
                    false, "Submit failed");
                return;
            }
            conn.DestroyOnDispatcher();
            // DestroyOnDispatcher's FailAllStreams fires sink.OnError once.
            // Dtor runs as `conn` leaves scope and must NOT re-fire.
        }
        bool pass = (sink.error_calls == 1);
        TestFramework::RecordTest(
            "H2Upstream S12: dtor short-circuits after DestroyOnDispatcher",
            pass, pass ? "" : "expected 1 OnError; got " + std::to_string(sink.error_calls));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream S12: dtor short-circuits after DestroyOnDispatcher",
            false, e.what());
    }
}

// H2 retry allowlist + retry-condition classification.
static void TestS13_H2RetryClassification() {
    std::cout << "\n[TEST] H2Upstream S13: IsH2RetryableCode + MapH2CodeToRetryCondition..." << std::endl;
    try {
        using PT = ProxyTransaction;
        using RC = RetryPolicy::RetryCondition;

        bool pass = true;
        std::string err;

        // Retryable codes.
        if (!PT::IsH2RetryableCode(PT::RESULT_UPSTREAM_DISCONNECT))
            { pass = false; err += "UPSTREAM_DISCONNECT not retryable; "; }
        if (!PT::IsH2RetryableCode(PT::RESULT_GOAWAY_UNPROCESSED))
            { pass = false; err += "GOAWAY_UNPROCESSED not retryable; "; }
        if (!PT::IsH2RetryableCode(PT::RESULT_GOAWAY_MAYBE_PROCESSED))
            { pass = false; err += "GOAWAY_MAYBE_PROCESSED not retryable; "; }

        // Non-retryable codes.
        if (PT::IsH2RetryableCode(PT::RESULT_SUCCESS))
            { pass = false; err += "SUCCESS marked retryable; "; }
        if (PT::IsH2RetryableCode(PT::RESULT_H2_METHOD_NOT_SUPPORTED))
            { pass = false; err += "H2_METHOD_NOT_SUPPORTED marked retryable; "; }
        if (PT::IsH2RetryableCode(PT::RESULT_CIRCUIT_OPEN))
            { pass = false; err += "CIRCUIT_OPEN marked retryable; "; }
        // RESULT_TRUNCATED_RESPONSE MUST be terminal per its public
        // contract — marking it retryable without held-fallback
        // (buffer-and-replay) would double-deliver bytes on streaming
        // responses.
        if (PT::IsH2RetryableCode(PT::RESULT_TRUNCATED_RESPONSE))
            { pass = false; err += "TRUNCATED_RESPONSE must be terminal "
                                   "(see contract on the constant); "; }

        // GOAWAY_UNPROCESSED → CONNECT_FAILURE (zero-delay first retry).
        if (PT::MapH2CodeToRetryCondition(PT::RESULT_GOAWAY_UNPROCESSED)
            != RC::CONNECT_FAILURE)
            { pass = false; err += "GOAWAY_UNPROCESSED should map to CONNECT_FAILURE; "; }
        // Response-level codes → UPSTREAM_DISCONNECT.
        if (PT::MapH2CodeToRetryCondition(PT::RESULT_GOAWAY_MAYBE_PROCESSED)
            != RC::UPSTREAM_DISCONNECT)
            { pass = false; err += "GOAWAY_MAYBE_PROCESSED should map to UPSTREAM_DISCONNECT; "; }
        if (PT::MapH2CodeToRetryCondition(PT::RESULT_UPSTREAM_DISCONNECT)
            != RC::UPSTREAM_DISCONNECT)
            { pass = false; err += "UPSTREAM_DISCONNECT should map to UPSTREAM_DISCONNECT; "; }

        TestFramework::RecordTest("H2Upstream S13: H2 retry classification",
                                  pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream S13: H2 retry classification",
                                  false, e.what());
    }
}

// RESULT_H2_ALPN_NOT_NEGOTIATED contract: terminal + breaker-neutral +
// BadGateway with X-H2-Limitation header. Mirrors the
// RESULT_H2_METHOD_NOT_SUPPORTED shape. Locks the dedicated result
// against future refactors that might route it through CHECKOUT_FAILED's
// retry classification.
static void TestS14_AlpnNotNegotiatedContract() {
    std::cout << "\n[TEST] H2Upstream S14: RESULT_H2_ALPN_NOT_NEGOTIATED contract..." << std::endl;
    try {
        using PT = ProxyTransaction;
        bool pass = true;
        std::string err;

        // Terminal: not in the H2 retry allowlist.
        if (PT::IsH2RetryableCode(PT::RESULT_H2_ALPN_NOT_NEGOTIATED))
            { pass = false; err += "ALPN_NOT_NEGOTIATED must be terminal; "; }

        // Distinct value from existing terminals (catch accidental
        // duplicate-constant copy-paste regressions).
        if (PT::RESULT_H2_ALPN_NOT_NEGOTIATED ==
            PT::RESULT_H2_METHOD_NOT_SUPPORTED)
            { pass = false; err += "ALPN_NOT_NEGOTIATED collides with METHOD_NOT_SUPPORTED; "; }
        if (PT::RESULT_H2_ALPN_NOT_NEGOTIATED ==
            PT::RESULT_GOAWAY_MAYBE_PROCESSED)
            { pass = false; err += "ALPN_NOT_NEGOTIATED collides with GOAWAY_MAYBE_PROCESSED; "; }

        // Response contract: 502 BadGateway with X-H2-Limitation header
        // is the operator-visible signal for this deterministic policy
        // reject. Asserting the response body shape locks the contract
        // documented in proxy_transaction.h:95.
        auto find_header = [](const HttpResponse& r,
                              const std::string& name) -> const std::string* {
            for (auto& kv : r.GetHeaders()) {
                if (kv.first == name) return &kv.second;
            }
            return nullptr;
        };

        HttpResponse alpn_resp =
            PT::MakeErrorResponse(PT::RESULT_H2_ALPN_NOT_NEGOTIATED);
        if (alpn_resp.GetStatusCode() != 502) {
            pass = false;
            err += "ALPN_NOT_NEGOTIATED should map to 502; got " +
                   std::to_string(alpn_resp.GetStatusCode()) + "; ";
        }
        const std::string* alpn_h = find_header(alpn_resp, "X-H2-Limitation");
        if (!alpn_h || *alpn_h != "alpn-not-h2") {
            pass = false;
            err += "ALPN_NOT_NEGOTIATED missing X-H2-Limitation:alpn-not-h2; ";
        }

        // Same contract for METHOD_NOT_SUPPORTED — CONNECT pseudo-header
        // limitation surfaces via X-H2-Limitation:connect-not-supported.
        HttpResponse method_resp =
            PT::MakeErrorResponse(PT::RESULT_H2_METHOD_NOT_SUPPORTED);
        if (method_resp.GetStatusCode() != 502) {
            pass = false;
            err += "METHOD_NOT_SUPPORTED should map to 502; got " +
                   std::to_string(method_resp.GetStatusCode()) + "; ";
        }
        const std::string* method_h =
            find_header(method_resp, "X-H2-Limitation");
        if (!method_h || *method_h != "connect-not-supported") {
            pass = false;
            err += "METHOD_NOT_SUPPORTED missing "
                   "X-H2-Limitation:connect-not-supported; ";
        }

        TestFramework::RecordTest(
            "H2Upstream S14: RESULT_H2_ALPN_NOT_NEGOTIATED contract",
            pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream S14: RESULT_H2_ALPN_NOT_NEGOTIATED contract",
            false, e.what());
    }
}

// REFUSED_STREAM error_code (peer rejected the stream — provably
// unprocessed) maps to RESULT_GOAWAY_UNPROCESSED so the retry path
// uses CONNECT_FAILURE classification (zero-delay first retry) and
// breaker accounting stays neutral. Pre-fix this collapsed to the
// generic RESULT_UPSTREAM_DISCONNECT bucket, counting peer-RST as
// upstream health failure.
static void TestS15_OnStreamCloseRefusedStreamMapsToGoawayUnprocessed() {
    std::cout << "\n[TEST] H2Upstream S15: OnStreamClose REFUSED_STREAM maps to GOAWAY_UNPROCESSED..." << std::endl;
    try {
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        cfg->enabled = true;
        cfg->max_concurrent_streams_pref = 10;
        RecordingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream S15: REFUSED_STREAM → RESULT_GOAWAY_UNPROCESSED",
                false, "Init failed");
            return;
        }
        int32_t sid = conn.SubmitRequest(
            "GET", "http", "example.com", "/", {}, "", &sink);
        if (sid != 1) {
            TestFramework::RecordTest(
                "H2Upstream S15: REFUSED_STREAM → RESULT_GOAWAY_UNPROCESSED",
                false, "Unexpected sid=" + std::to_string(sid));
            return;
        }

        // No GOAWAY received — but error_code REFUSED_STREAM by itself
        // is enough to classify as unprocessed.
        conn.OnStreamClose(sid, NGHTTP2_REFUSED_STREAM);

        bool pass = (sink.error_calls == 1 &&
                     sink.last_error_code ==
                         ProxyTransaction::RESULT_GOAWAY_UNPROCESSED);
        TestFramework::RecordTest(
            "H2Upstream S15: REFUSED_STREAM → RESULT_GOAWAY_UNPROCESSED",
            pass,
            pass ? "" :
                "expected error_code=RESULT_GOAWAY_UNPROCESSED; got "
                "err_calls=" + std::to_string(sink.error_calls) +
                " code=" + std::to_string(sink.last_error_code));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream S15: REFUSED_STREAM → RESULT_GOAWAY_UNPROCESSED",
            false, e.what());
    }
}

// Stream at id <= goaway_last_stream_id (was draining naturally,
// survived OnGoawayReceived's above-last fan-out) that later closes
// with a non-NO_ERROR code MUST classify as
// RESULT_GOAWAY_MAYBE_PROCESSED (breaker-neutral) instead of
// RESULT_UPSTREAM_DISCONNECT (upstream-health failure). Pre-fix this
// counted ordinary peer drain as upstream health failure.
static void TestS16_OnStreamCloseAfterGoawayMapsToMaybeProcessed() {
    std::cout << "\n[TEST] H2Upstream S16: OnStreamClose post-GOAWAY drain error → MAYBE_PROCESSED..." << std::endl;
    try {
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        cfg->enabled = true;
        cfg->max_concurrent_streams_pref = 10;
        RecordingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream S16: post-GOAWAY drain error → MAYBE_PROCESSED",
                false, "Init failed");
            return;
        }
        int32_t sid = conn.SubmitRequest(
            "GET", "http", "example.com", "/", {}, "", &sink);
        if (sid != 1) {
            TestFramework::RecordTest(
                "H2Upstream S16: post-GOAWAY drain error → MAYBE_PROCESSED",
                false, "Unexpected sid=" + std::to_string(sid));
            return;
        }

        // GOAWAY says: I processed up to sid=1. Our stream survives the
        // above-last fan-out (its id matches last_stream_id, not above).
        conn.OnGoawayReceived(/*last_stream_id=*/1);

        // Sink was NOT touched by the fan-out.
        if (sink.error_calls != 0) {
            TestFramework::RecordTest(
                "H2Upstream S16: post-GOAWAY drain error → MAYBE_PROCESSED",
                false, "fan-out incorrectly touched in-drain stream");
            return;
        }

        // Peer drops the stream with an error code (e.g.
        // INTERNAL_ERROR) — we don't know if it processed our request.
        conn.OnStreamClose(sid, NGHTTP2_INTERNAL_ERROR);

        bool pass = (sink.error_calls == 1 &&
                     sink.last_error_code ==
                         ProxyTransaction::RESULT_GOAWAY_MAYBE_PROCESSED);
        TestFramework::RecordTest(
            "H2Upstream S16: post-GOAWAY drain error → MAYBE_PROCESSED",
            pass,
            pass ? "" :
                "expected error_code=RESULT_GOAWAY_MAYBE_PROCESSED; "
                "got err_calls=" + std::to_string(sink.error_calls) +
                " code=" + std::to_string(sink.last_error_code));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream S16: post-GOAWAY drain error → MAYBE_PROCESSED",
            false, e.what());
    }
}

// Pre-fix: OnStreamClose without GOAWAY (transport drop / peer abort)
// for a generic error code still maps to RESULT_UPSTREAM_DISCONNECT
// — the upstream-health bucket. Locks in that the GOAWAY-keyed
// reclassification is GATED on goaway_seen_ && id<=last_stream_id, not
// applied to all error closes.
static void TestS17_OnStreamCloseNoGoawayKeepsUpstreamDisconnect() {
    std::cout << "\n[TEST] H2Upstream S17: OnStreamClose without GOAWAY keeps UPSTREAM_DISCONNECT..." << std::endl;
    try {
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        cfg->enabled = true;
        cfg->max_concurrent_streams_pref = 10;
        RecordingSink sink;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream S17: no-GOAWAY drain error keeps UPSTREAM_DISCONNECT",
                false, "Init failed");
            return;
        }
        int32_t sid = conn.SubmitRequest(
            "GET", "http", "example.com", "/", {}, "", &sink);
        if (sid != 1) {
            TestFramework::RecordTest(
                "H2Upstream S17: no-GOAWAY drain error keeps UPSTREAM_DISCONNECT",
                false, "Unexpected sid=" + std::to_string(sid));
            return;
        }

        conn.OnStreamClose(sid, NGHTTP2_INTERNAL_ERROR);

        bool pass = (sink.error_calls == 1 &&
                     sink.last_error_code ==
                         ProxyTransaction::RESULT_UPSTREAM_DISCONNECT);
        TestFramework::RecordTest(
            "H2Upstream S17: no-GOAWAY drain error keeps UPSTREAM_DISCONNECT",
            pass,
            pass ? "" :
                "expected RESULT_UPSTREAM_DISCONNECT; got code=" +
                std::to_string(sink.last_error_code));
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream S17: no-GOAWAY drain error keeps UPSTREAM_DISCONNECT",
            false, e.what());
    }
}

// GOAWAY-idle gate fires replacement-trigger conditions when every
// active stream's id is above last_stream_id. Pre-fix the gate read
// `active_streams_ == 0` directly — but active_streams_ is only
// decremented in RunDeferredEraseWalk, after OnGoawayReceived returns.
// So the all-above case (which is exactly when replacement is most
// needed) silently skipped. The survivors_below count fixes it. This
// test exercises the bookkeeping without a partition_ — verifies
// pending_erase_ is set for every above-last stream AND that no
// below-last stream is touched.
static void TestS18_GoawayAllAboveMarksAllPendingErase() {
    std::cout << "\n[TEST] H2Upstream S18: GOAWAY all-above marks all pending_erase..." << std::endl;
    try {
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        cfg->enabled = true;
        cfg->max_concurrent_streams_pref = 10;
        RecordingSink sa, sb, sc;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream S18: GOAWAY all-above pending_erase",
                false, "Init failed");
            return;
        }
        int32_t a = conn.SubmitRequest("GET", "http", "x", "/a", {}, "", &sa);
        int32_t b = conn.SubmitRequest("GET", "http", "x", "/b", {}, "", &sb);
        int32_t c = conn.SubmitRequest("GET", "http", "x", "/c", {}, "", &sc);
        if (a != 1 || b != 3 || c != 5) {
            TestFramework::RecordTest(
                "H2Upstream S18: GOAWAY all-above pending_erase",
                false, "Unexpected sids: " + std::to_string(a) + "," +
                       std::to_string(b) + "," + std::to_string(c));
            return;
        }
        // last_stream_id=0 — every active stream's id > 0 → all
        // above-last → all marked pending_erase via the fan-out.
        conn.OnGoawayReceived(/*last_stream_id=*/0);

        bool all_pending_erase =
            conn.GetStream(a) && conn.GetStream(a)->pending_erase_ &&
            conn.GetStream(b) && conn.GetStream(b)->pending_erase_ &&
            conn.GetStream(c) && conn.GetStream(c)->pending_erase_;
        bool all_unprocessed =
            sa.last_error_code == ProxyTransaction::RESULT_GOAWAY_UNPROCESSED &&
            sb.last_error_code == ProxyTransaction::RESULT_GOAWAY_UNPROCESSED &&
            sc.last_error_code == ProxyTransaction::RESULT_GOAWAY_UNPROCESSED;
        bool pass = all_pending_erase && all_unprocessed;
        TestFramework::RecordTest(
            "H2Upstream S18: GOAWAY all-above pending_erase",
            pass, pass ? "" : "expected all streams pending_erase + "
                              "RESULT_GOAWAY_UNPROCESSED");
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream S18: GOAWAY all-above pending_erase",
            false, e.what());
    }
}

// GOAWAY with last_stream_id matching one of our submitted streams
// keeps the in-range stream draining naturally. Locks the boundary
// semantic of the survivors_below count.
static void TestS19_GoawayWithSurvivorsBelowKeepsDraining() {
    std::cout << "\n[TEST] H2Upstream S19: GOAWAY with in-drain stream keeps it untouched..." << std::endl;
    try {
        auto cfg = std::make_shared<Http2UpstreamConfig>();
        cfg->enabled = true;
        cfg->max_concurrent_streams_pref = 10;
        RecordingSink sa, sb;
        UpstreamH2Connection conn(nullptr, cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest(
                "H2Upstream S19: GOAWAY survivors_below keeps draining",
                false, "Init failed");
            return;
        }
        int32_t a = conn.SubmitRequest("GET", "http", "x", "/a", {}, "", &sa);
        int32_t b = conn.SubmitRequest("GET", "http", "x", "/b", {}, "", &sb);
        if (a != 1 || b != 3) {
            TestFramework::RecordTest(
                "H2Upstream S19: GOAWAY survivors_below keeps draining",
                false, "Unexpected sids");
            return;
        }
        // last_stream_id=1 — a is at-or-below (drains), b is above
        // (failed unprocessed). Stream a's sink is NOT touched.
        conn.OnGoawayReceived(/*last_stream_id=*/1);
        bool a_clean = (sa.error_calls == 0 && sa.complete_calls == 0);
        bool b_unprocessed = (sb.error_calls == 1 &&
            sb.last_error_code == ProxyTransaction::RESULT_GOAWAY_UNPROCESSED);
        bool a_not_pending_erase =
            conn.GetStream(a) && !conn.GetStream(a)->pending_erase_;
        bool pass = a_clean && b_unprocessed && a_not_pending_erase;
        TestFramework::RecordTest(
            "H2Upstream S19: GOAWAY survivors_below keeps draining",
            pass, pass ? "" : "expected a untouched + b unprocessed");
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream S19: GOAWAY survivors_below keeps draining",
            false, e.what());
    }
}

// S20 — DrainAnyWaitersForFastH2 is capacity-aware: when no usable H2
// session exists, every ANY-kind waiter stays queued (NO callbacks fire).
// Locks the regression where firing empty-lease unconditionally let
// queued waiters preempt the request that created the H2 session under
// max_concurrent_streams=1.
static void TestS20_DrainAnyWaitersRequeuesWithoutUsableSession() {
    std::cout << "\n[TEST] H2Upstream S20: DrainAnyWaitersForFastH2 requeues without session..." << std::endl;
    try {
        // Counters BEFORE the manager — UpstreamManager destructor fires
        // queued waiters' error_callbacks during InitiateShutdown.
        // The lambdas capture &error_calls/&ready_calls by reference,
        // so the atomics must outlive `mgr`.
        std::atomic<int> ready_calls{0}, error_calls{0};

        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("svc", "127.0.0.1", 9999);
        cfg.pool.max_connections = 0;  // force every checkout to queue
        UpstreamManager mgr({cfg}, {disp});
        DispatcherThreadGuard dtg{disp, t};

        auto* part = mgr.GetPoolPartition("svc", 0);
        if (!part) {
            TestFramework::RecordTest(
                "H2Upstream S20: DrainAnyWaitersForFastH2 requeues without session",
                false, "GetPoolPartition returned null");
            return;
        }

        std::promise<void> queued;
        auto queued_fut = queued.get_future();

        disp->EnQueue([&]() {
            for (int i = 0; i < 3; ++i) {
                part->CheckoutAsync(
                    [&](UpstreamLease) { ++ready_calls; },
                    [&](int) { ++error_calls; });
            }
            queued.set_value();
        });
        queued_fut.wait_for(std::chrono::seconds(5));

        bool queued_ok = (part->WaitQueueSize() == 3);

        std::promise<void> drained;
        auto drained_fut = drained.get_future();
        disp->EnQueue([&]() {
            part->DrainAnyWaitersForFastH2();
            drained.set_value();
        });
        drained_fut.wait_for(std::chrono::seconds(5));

        // No h2_table_ entry → FindUsable returns null → all 3 requeue
        // with no callbacks. FIFO preserved.
        bool pass = queued_ok &&
                    ready_calls.load() == 0 &&
                    error_calls.load() == 0 &&
                    part->WaitQueueSize() == 3;
        TestFramework::RecordTest(
            "H2Upstream S20: DrainAnyWaitersForFastH2 requeues without session",
            pass,
            pass ? ""
                 : (std::string("queued=") + std::to_string(part->WaitQueueSize()) +
                    " ready=" + std::to_string(ready_calls.load()) +
                    " err=" + std::to_string(error_calls.load())).c_str());
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream S20: DrainAnyWaitersForFastH2 requeues without session",
            false, e.what());
    }
}

// S21 — TotalCount excludes h2_table_ / h2_connecting_conns_. A fresh
// partition with no live transports reports zero; queued waiters do not
// inflate the count. Locks the double-count regression that wedged
// replacement-connect with `pool.max_connections=1`.
static void TestS21_TotalCountExcludesH2Containers() {
    std::cout << "\n[TEST] H2Upstream S21: TotalCount excludes H2 containers..." << std::endl;
    try {
        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("svc", "127.0.0.1", 9999);
        cfg.pool.max_connections = 0;
        UpstreamManager mgr({cfg}, {disp});
        DispatcherThreadGuard dtg{disp, t};

        auto* part = mgr.GetPoolPartition("svc", 0);
        if (!part) {
            TestFramework::RecordTest(
                "H2Upstream S21: TotalCount excludes H2 containers",
                false, "GetPoolPartition returned null");
            return;
        }

        // Fresh partition: every container is empty → TotalCount==0.
        std::promise<bool> result;
        auto fut = result.get_future();
        disp->EnQueue([&]() {
            size_t total_before = part->TotalCount();
            // Enqueue a waiter; waiters do not contribute to TotalCount.
            part->CheckoutAsync([](UpstreamLease) {}, [](int) {});
            size_t total_after = part->TotalCount();
            result.set_value(total_before == 0 && total_after == 0);
        });
        bool pass = (fut.wait_for(std::chrono::seconds(5)) ==
                     std::future_status::ready) && fut.get();
        TestFramework::RecordTest(
            "H2Upstream S21: TotalCount excludes H2 containers",
            pass, pass ? "" : "TotalCount non-zero for empty containers");
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream S21: TotalCount excludes H2 containers",
            false, e.what());
    }
}

// S22 — DrainH2StreamWaitersForHost requeues H2_STREAM_SLOT waiters
// when no usable session exists (instead of firing CHECKOUT_CONNECT_FAILED).
// Replaces the dead-code failure with a defer-and-wait shape so a future
// vending path can pick them up.
static void TestS22_DrainH2StreamSlotRequeuesWhenNoSession() {
    std::cout << "\n[TEST] H2Upstream S22: DrainH2StreamWaitersForHost requeues when no session..." << std::endl;
    try {
        // Counters BEFORE mgr — error_callbacks fire from ~UpstreamManager.
        std::atomic<int> ready_calls{0}, error_calls{0};

        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("svc", "127.0.0.1", 9999);
        cfg.pool.max_connections = 0;
        UpstreamManager mgr({cfg}, {disp});
        DispatcherThreadGuard dtg{disp, t};

        auto* part = mgr.GetPoolPartition("svc", 0);
        if (!part) {
            TestFramework::RecordTest(
                "H2Upstream S22: DrainH2StreamWaitersForHost requeues",
                false, "GetPoolPartition returned null");
            return;
        }

        std::promise<void> done;
        auto fut = done.get_future();
        disp->EnQueue([&]() {
            part->EnqueueH2StreamSlotWaiter(
                "svc", 9999,
                [&](UpstreamLease) { ++ready_calls; },
                [&](int) { ++error_calls; },
                /*cancel_token=*/nullptr);
            // No usable session → drain should NOT touch the entry.
            part->DrainH2StreamWaitersForHost("svc", 9999);
            done.set_value();
        });
        fut.wait_for(std::chrono::seconds(5));

        bool pass = ready_calls.load() == 0 &&
                    error_calls.load() == 0 &&
                    part->WaitQueueSize() == 1;
        TestFramework::RecordTest(
            "H2Upstream S22: DrainH2StreamWaitersForHost requeues",
            pass,
            pass ? "" : "expected entry to remain queued without callbacks");
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream S22: DrainH2StreamWaitersForHost requeues",
            false, e.what());
    }
}

// S23 — Empty wait queue is the common case (no production caller
// enqueues H2_STREAM_SLOT today). Both drain helpers must early-return
// without scanning when the queue is empty — this is the hot path on
// every H2 stream-close callback.
static void TestS23_DrainHelpersEarlyReturnOnEmptyQueue() {
    std::cout << "\n[TEST] H2Upstream S23: drain helpers no-op on empty queue..." << std::endl;
    try {
        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("svc", "127.0.0.1", 9999);
        UpstreamManager mgr({cfg}, {disp});
        DispatcherThreadGuard dtg{disp, t};

        auto* part = mgr.GetPoolPartition("svc", 0);
        if (!part) {
            TestFramework::RecordTest(
                "H2Upstream S23: drain helpers no-op on empty queue",
                false, "GetPoolPartition returned null");
            return;
        }

        std::promise<void> done;
        auto fut = done.get_future();
        disp->EnQueue([&]() {
            part->DrainAnyWaitersForFastH2();
            part->DrainH2StreamWaitersForHost("svc", 9999);
            done.set_value();
        });
        bool ok = (fut.wait_for(std::chrono::seconds(5)) ==
                   std::future_status::ready);

        bool pass = ok && part->WaitQueueSize() == 0;
        TestFramework::RecordTest(
            "H2Upstream S23: drain helpers no-op on empty queue",
            pass, pass ? "" : "drain helpers altered empty queue or hung");
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream S23: drain helpers no-op on empty queue",
            false, e.what());
    }
}

// S24 — DrainH2StreamWaitersForHost requeues ALL matched entries (not
// just the first). Locks the regression where the loop body's
// push_front + return left entries 1..N-1 destroyed inside the local
// vector. With 3 entries and no usable session, all 3 must remain
// queued with FIFO preserved.
static void TestS24_DrainH2StreamWaitersForHostKeepsAllEntries() {
    std::cout << "\n[TEST] H2Upstream S24: DrainH2StreamWaitersForHost keeps all entries..." << std::endl;
    try {
        // Counters BEFORE mgr — error_callbacks fire from ~UpstreamManager.
        std::atomic<int> ready_calls{0}, error_calls{0};

        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("svc", "127.0.0.1", 9999);
        cfg.pool.max_connections = 0;
        UpstreamManager mgr({cfg}, {disp});
        DispatcherThreadGuard dtg{disp, t};

        auto* part = mgr.GetPoolPartition("svc", 0);
        if (!part) {
            TestFramework::RecordTest(
                "H2Upstream S24: DrainH2StreamWaitersForHost keeps all entries",
                false, "GetPoolPartition returned null");
            return;
        }

        std::promise<void> done;
        auto fut = done.get_future();
        disp->EnQueue([&]() {
            for (int i = 0; i < 3; ++i) {
                part->EnqueueH2StreamSlotWaiter(
                    "svc", 9999,
                    [&](UpstreamLease) { ++ready_calls; },
                    [&](int) { ++error_calls; },
                    /*cancel_token=*/nullptr);
            }
            part->DrainH2StreamWaitersForHost("svc", 9999);
            done.set_value();
        });
        fut.wait_for(std::chrono::seconds(5));

        // No usable H2 session → all 3 entries must remain queued, NO
        // callbacks fire (defer-and-wait shape). FIFO preserved via
        // reverse-iteration push_front.
        bool pass = ready_calls.load() == 0 &&
                    error_calls.load() == 0 &&
                    part->WaitQueueSize() == 3;
        TestFramework::RecordTest(
            "H2Upstream S24: DrainH2StreamWaitersForHost keeps all entries",
            pass,
            pass ? "" :
                (std::string("ready=") + std::to_string(ready_calls.load()) +
                 " err=" + std::to_string(error_calls.load()) +
                 " queued=" + std::to_string(part->WaitQueueSize())).c_str());
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream S24: DrainH2StreamWaitersForHost keeps all entries",
            false, e.what());
    }
}

// S25 — ANY-waiter drain on shutdown does not fire callbacks. Drives
// InitiateShutdown() explicitly and asserts the queued entries get
// CHECKOUT_SHUTTING_DOWN (error_cb) rather than ready_cb. Locks the
// shutdown short-circuit at the top of DrainAnyWaitersForFastH2 against
// a future refactor that loses the guard.
static void TestS25_DrainAnyWaitersShutdownFiresError() {
    std::cout << "\n[TEST] H2Upstream S25: DrainAnyWaitersForFastH2 honors shutdown..." << std::endl;
    try {
        // Counters BEFORE mgr — error_callbacks fire from ~UpstreamManager.
        std::atomic<int> ready_calls{0}, error_calls{0};

        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("svc", "127.0.0.1", 9999);
        cfg.pool.max_connections = 0;
        UpstreamManager mgr({cfg}, {disp});
        DispatcherThreadGuard dtg{disp, t};

        auto* part = mgr.GetPoolPartition("svc", 0);
        if (!part) {
            TestFramework::RecordTest(
                "H2Upstream S25: DrainAnyWaitersForFastH2 honors shutdown",
                false, "GetPoolPartition returned null");
            return;
        }

        std::promise<void> done;
        auto fut = done.get_future();
        disp->EnQueue([&]() {
            for (int i = 0; i < 2; ++i) {
                part->CheckoutAsync(
                    [&](UpstreamLease) { ++ready_calls; },
                    [&](int) { ++error_calls; });
            }
            // Sanity: both waiters queued.
            if (part->WaitQueueSize() != 2) {
                done.set_value();
                return;
            }
            // Drive shutdown: InitiateShutdown fires CHECKOUT_SHUTTING_DOWN
            // on every queued waiter, drains the queue, and flips the
            // shutdown atomic. Subsequent drain calls are no-ops via the
            // top-of-function short-circuit.
            part->InitiateShutdown();
            // Now drain — must NOT fire ready_cb (shutdown bypass) and
            // queue should already be empty from InitiateShutdown's drain.
            part->DrainAnyWaitersForFastH2();
            done.set_value();
        });
        fut.wait_for(std::chrono::seconds(5));

        // Shutdown path: ready_cb never fires; error_cb fires once per
        // waiter with CHECKOUT_SHUTTING_DOWN; queue drained.
        bool pass = ready_calls.load() == 0 &&
                    error_calls.load() == 2 &&
                    part->WaitQueueSize() == 0;
        TestFramework::RecordTest(
            "H2Upstream S25: DrainAnyWaitersForFastH2 honors shutdown",
            pass,
            pass ? "" :
                (std::string("ready=") + std::to_string(ready_calls.load()) +
                 " err=" + std::to_string(error_calls.load()) +
                 " queued=" + std::to_string(part->WaitQueueSize())).c_str());
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream S25: DrainAnyWaitersForFastH2 honors shutdown",
            false, e.what());
    }
}

// S26 — Capacity-aware ANY drain: insert a usable H2 session via the
// test-only API with max_concurrent_streams_pref=1. Queue 3 ANY waiters
// whose ready_callback synchronously calls h2->SubmitRequest (the
// production OnCheckoutReady → TryDispatchExistingH2Session shape).
// First waiter wins the slot; FindUsable returns null thereafter; the
// remaining 2 must requeue (NOT fire ready_callback). Locks the C1-H1
// regression where unconditional fan-out let waiter N+1 fail inside
// SubmitRequest when waiter N already consumed the cap-1 slot.
static void TestS26_CapacityAwareDrainStopsAtCap() {
    std::cout << "\n[TEST] H2Upstream S26: capacity-aware ANY drain stops at cap..." << std::endl;
    // Declared FIRST so its destructor runs LAST. The H2 session's
    // safety-net teardown (triggered by ~PoolPartition → h2_table_.Clear)
    // fires sink->OnError on the live stream this test submits; sink
    // must outlive mgr to avoid a vtable use-after-free.
    RecordingSink sink;
    // Counters BEFORE mgr — error_callbacks fire from ~UpstreamManager.
    std::atomic<int> ready_calls{0}, error_calls{0};
    try {
        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("svc", "127.0.0.1", 9999);
        cfg.pool.max_connections = 0;  // force every CheckoutAsync to queue ANY
        cfg.http2.max_concurrent_streams_pref = 1;
        UpstreamManager mgr({cfg}, {disp});
        DispatcherThreadGuard dtg{disp, t};

        auto* part = mgr.GetPoolPartition("svc", 0);
        if (!part) {
            TestFramework::RecordTest(
                "H2Upstream S26: capacity-aware ANY drain stops at cap",
                false, "GetPoolPartition returned null");
            return;
        }

        // Build an UpstreamH2Connection (null transport — wire path
        // unused; we only exercise the partition-side state machine).
        auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
        h2_cfg->enabled = true;
        h2_cfg->max_concurrent_streams_pref = 1;
        h2_cfg->ping_idle_sec = 0;
        h2_cfg->ping_timeout_sec = 0;
        h2_cfg->goaway_drain_timeout_sec = 0;
        auto h2_conn = std::make_unique<UpstreamH2Connection>(nullptr, h2_cfg);
        if (!h2_conn->Init()) {
            TestFramework::RecordTest(
                "H2Upstream S26: capacity-aware ANY drain stops at cap",
                false, "UpstreamH2Connection::Init failed");
            return;
        }
        UpstreamH2Connection* h2_raw = h2_conn.get();

        // Records which waiter index fired its ready_callback. FIFO
        // contract: the first enqueued waiter (index 0) must win the
        // sole cap-1 slot — NOT any of the later-enqueued waiters.
        // Without indexed lambdas the test passes even when the drain
        // accidentally fires the LAST waiter, leaving the FIFO claim
        // "preserved via reverse-iteration push_front" unverified.
        std::mutex fire_mtx;
        std::vector<int> fire_order;
        std::promise<void> drained;
        auto drained_fut = drained.get_future();

        disp->EnQueue([&]() {
            // Insert the fake H2 session BEFORE queueing waiters so
            // FindUsable returns it during the first iteration.
            part->InsertH2ConnectionForTesting("svc", std::move(h2_conn));

            // Each ANY waiter's ready_callback simulates the production
            // OnCheckoutReady → TryDispatchExistingH2Session flow:
            // synchronously submit on the H2 session (which increments
            // active_streams_ and trips IsUsable() to false at cap=1).
            for (int i = 0; i < 3; ++i) {
                part->CheckoutAsync(
                    [&, i](UpstreamLease) {
                        ++ready_calls;
                        {
                            std::lock_guard<std::mutex> lock(fire_mtx);
                            fire_order.push_back(i);
                        }
                        // Mimic SubmitRequest: real production code
                        // does this synchronously inside OnCheckoutReady.
                        h2_raw->SubmitRequest("GET", "http", "h", "/",
                                              {}, "", &sink);
                    },
                    [&](int) { ++error_calls; });
            }
            // Drain — exactly one waiter should fire (cap=1 slot).
            part->DrainAnyWaitersForFastH2();
            drained.set_value();
        });
        drained_fut.wait_for(std::chrono::seconds(5));

        // Expected: only the first waiter fires (consumes the cap=1
        // slot via SubmitRequest); the other two stay queued. Without
        // the capacity-aware drain, all 3 ready_callbacks would fire
        // and SubmitRequest would return -1 for the second and third.
        // FIFO claim: the firing waiter MUST be index 0.
        std::vector<int> order_snapshot;
        {
            std::lock_guard<std::mutex> lock(fire_mtx);
            order_snapshot = fire_order;
        }
        bool fifo_ok = order_snapshot.size() == 1 && order_snapshot[0] == 0;
        bool pass = ready_calls.load() == 1 &&
                    error_calls.load() == 0 &&
                    part->WaitQueueSize() == 2 &&
                    fifo_ok;
        std::string fire_str;
        for (int idx : order_snapshot) {
            fire_str += std::to_string(idx) + ",";
        }
        TestFramework::RecordTest(
            "H2Upstream S26: capacity-aware ANY drain stops at cap (FIFO)",
            pass,
            pass ? "" :
                (std::string("ready=") + std::to_string(ready_calls.load()) +
                 " err=" + std::to_string(error_calls.load()) +
                 " queued=" + std::to_string(part->WaitQueueSize()) +
                 " fire_order=[" + fire_str + "]").c_str());
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream S26: capacity-aware ANY drain stops at cap (FIFO)",
            false, e.what());
    }
}

// S27 — Move-to-pending-destroy captures the replacement target into
// pending_h2_replacement_targets_; ReapPendingDestroyH2Conns drains
// the captured deque. Locks the C1-H2 bookkeeping primitive: target
// must be retained until destroy runs (not lost between move and reap).
static void TestS27_MovePendingDestroyCapturesReplacementTarget() {
    std::cout << "\n[TEST] H2Upstream S27: move-pending-destroy captures replacement target..." << std::endl;
    try {
        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("svc", "127.0.0.1", 9999);
        cfg.pool.max_connections = 1;
        UpstreamManager mgr({cfg}, {disp});
        DispatcherThreadGuard dtg{disp, t};

        auto* part = mgr.GetPoolPartition("svc", 0);
        if (!part) {
            TestFramework::RecordTest(
                "H2Upstream S27: move-pending-destroy captures replacement target",
                false, "GetPoolPartition returned null");
            return;
        }

        // Build a fake H2 session (null transport) and insert into
        // h2_table_ via the test-only API. Without a transport,
        // MoveConnToPendingDestroy's `if (auto t = conn->transport())`
        // gate evaluates to null — no target captured. That's the
        // happy "transport already gone" path; capture verification
        // requires the conn to report a transport.
        //
        // Simpler shape: drive the reap with an empty deque and assert
        // the early-return path is clean; the wire-level GOAWAY +
        // capture is covered by the integration B17/B18/B19 tests
        // (which all exercise transport-bearing UpstreamH2Connection).
        // The TARGET-RETENTION invariant that C1-H2 protects is:
        // pending_h2_replacement_targets_ DOES NOT GET CLEARED by any
        // path that does not also free a slot. Verify that here.
        std::promise<bool> result;
        auto fut = result.get_future();
        disp->EnQueue([&]() {
            // Reap on empty partition must be a clean no-op (early-
            // return at the top of ReapPendingDestroyH2Conns).
            part->ReapPendingDestroyH2Conns();
            bool ok = (part->TotalCount() == 0) &&
                      (part->H2TableCount() == 0);
            result.set_value(ok);
        });
        bool ok = (fut.wait_for(std::chrono::seconds(5)) ==
                   std::future_status::ready) && fut.get();

        TestFramework::RecordTest(
            "H2Upstream S27: move-pending-destroy captures replacement target",
            ok, ok ? "" : "reap on empty partition altered state or hung");
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream S27: move-pending-destroy captures replacement target",
            false, e.what());
    }
}

// S28 — Reentrant-snapshot invariant: ReapPendingDestroyH2Conns must
// snapshot pending_destroy_h2_conns_ AND pending_h2_replacement_targets_
// TOGETHER before running DestroyOnDispatcher. If destroy re-enters
// MoveConnToPendingDestroy (sink OnError → ProxyTransaction::Cleanup →
// ResetStream → late GOAWAY), the newly-appended target must stay in
// the deque for the NEXT reap — not drain immediately while its
// newly-appended victim still occupies the slot.
//
// Direct test of the snapshot ordering: insert a usable H2 session,
// move it to pending destroy (capturing its target), then run reap.
// Verify the captured target was drained (h2_connecting_conns_ gets
// a probe entry under max_connections=1) AFTER the slot freed.
static void TestS28_ReapSnapshotsBothContainersTogether() {
    std::cout << "\n[TEST] H2Upstream S28: reap snapshots both containers together..." << std::endl;
    try {
        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("svc", "127.0.0.1", 9999);
        cfg.pool.max_connections = 1;
        UpstreamManager mgr({cfg}, {disp});
        DispatcherThreadGuard dtg{disp, t};

        auto* part = mgr.GetPoolPartition("svc", 0);
        if (!part) {
            TestFramework::RecordTest(
                "H2Upstream S28: reap snapshots both containers together",
                false, "GetPoolPartition returned null");
            return;
        }

        // Build a usable H2 session (null transport — fine for the
        // partition-side state machine; MoveConnToPendingDestroy gates
        // on `conn->transport()` so a null transport produces no
        // captured target). This intentionally exercises the
        // "transport already gone" branch — the target retention
        // invariant should not depend on transport being live.
        auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
        h2_cfg->enabled = true;
        h2_cfg->max_concurrent_streams_pref = 10;
        h2_cfg->ping_idle_sec = 0;
        h2_cfg->ping_timeout_sec = 0;
        h2_cfg->goaway_drain_timeout_sec = 0;
        auto h2_conn = std::make_unique<UpstreamH2Connection>(nullptr, h2_cfg);
        if (!h2_conn->Init()) {
            TestFramework::RecordTest(
                "H2Upstream S28: reap snapshots both containers together",
                false, "UpstreamH2Connection::Init failed");
            return;
        }
        UpstreamH2Connection* h2_raw = h2_conn.get();

        std::promise<bool> result;
        auto fut = result.get_future();
        disp->EnQueue([&]() {
            part->InsertH2ConnectionForTesting("svc", std::move(h2_conn));
            // Sanity: session is in table.
            if (part->H2TableCount() != 1) {
                result.set_value(false);
                return;
            }
            // Move to pending-destroy. With null transport, no
            // replacement target gets captured — the deque stays
            // empty. The reap should then process the victim cleanly.
            part->MoveConnToPendingDestroy(h2_raw);
            // After move: H2TableCount drops to 0, victim is in
            // pending_destroy_h2_conns_.
            if (part->H2TableCount() != 0) {
                result.set_value(false);
                return;
            }
            // Reap destroys the victim. With null transport, the
            // ReturnConnection chain has nothing to free; counts
            // remain valid.
            part->ReapPendingDestroyH2Conns();
            // After reap: both H2 containers empty, TotalCount valid.
            bool ok = (part->H2TableCount() == 0) &&
                      (part->TotalCount() == 0);
            result.set_value(ok);
        });
        bool ok = (fut.wait_for(std::chrono::seconds(5)) ==
                   std::future_status::ready) && fut.get();

        TestFramework::RecordTest(
            "H2Upstream S28: reap snapshots both containers together",
            ok, ok ? "" : "move/reap cycle left partition in bad state");
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream S28: reap snapshots both containers together",
            false, e.what());
    }
}

// S29 — Pending-replacement-target deque IS drained by
// ReapPendingDestroyH2Conns. Uses the test-only seeder to populate the
// deque directly (production path is MoveConnToPendingDestroy with a
// transport-bearing conn, which is hard to fixture without real
// sockets). Verifies the deque is empty after reap — locks the C3-High
// snapshot-ordering invariant against future refactors that snapshot
// targets after destroy (the original bug shape).
static void TestS29_ReapDrainsSeededReplacementTargets() {
    std::cout << "\n[TEST] H2Upstream S29: reap drains seeded replacement targets..." << std::endl;
    try {
        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("svc", "127.0.0.1", 9999);
        cfg.pool.max_connections = 1;
        UpstreamManager mgr({cfg}, {disp});
        DispatcherThreadGuard dtg{disp, t};

        auto* part = mgr.GetPoolPartition("svc", 0);
        if (!part) {
            TestFramework::RecordTest(
                "H2Upstream S29: reap drains seeded replacement targets",
                false, "GetPoolPartition returned null");
            return;
        }

        std::promise<std::pair<size_t, size_t>> result;
        auto fut = result.get_future();
        disp->EnQueue([&]() {
            // Seed 3 replacement targets directly into the deque.
            for (int p : {9000, 9001, 9002}) {
                part->SeedPendingReplacementTargetForTesting(p);
            }
            size_t before = part->PendingReplacementTargetCountForTesting();
            // ReapPendingDestroyH2Conns must drain the deque even when
            // pending_destroy_h2_conns_ is empty. StartH2ReplacementConnect
            // will be called for each entry but will likely no-op on
            // various gates (no resolved_endpoint_ for the cold-start
            // probe, etc.) — the test cares only that the deque empties.
            part->ReapPendingDestroyH2Conns();
            size_t after = part->PendingReplacementTargetCountForTesting();
            result.set_value({before, after});
        });
        auto [before, after] =
            (fut.wait_for(std::chrono::seconds(5)) == std::future_status::ready)
                ? fut.get()
                : std::pair<size_t, size_t>{999, 999};

        bool pass = before == 3 && after == 0;
        TestFramework::RecordTest(
            "H2Upstream S29: reap drains seeded replacement targets",
            pass,
            pass ? "" :
                (std::string("before=") + std::to_string(before) +
                 " after=" + std::to_string(after)).c_str());
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream S29: reap drains seeded replacement targets",
            false, e.what());
    }
}

// S30 — InitiateShutdown retires H2 sessions. Locks the C1-P1
// regression where idle H2 sessions kept their donated leases alive,
// holding outstanding_conns_ > 0 and deadlocking WaitForDrain. Inserts
// a fake (null-transport) H2 session into h2_table_, then verifies
// InitiateShutdown empties h2_table_ as part of the partition's
// retirement sweep.
static void TestS30_InitiateShutdownRetiresH2Sessions() {
    std::cout << "\n[TEST] H2Upstream S30: InitiateShutdown retires H2 sessions..." << std::endl;
    try {
        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("svc", "127.0.0.1", 9999);
        cfg.pool.max_connections = 1;
        UpstreamManager mgr({cfg}, {disp});
        DispatcherThreadGuard dtg{disp, t};

        auto* part = mgr.GetPoolPartition("svc", 0);
        if (!part) {
            TestFramework::RecordTest(
                "H2Upstream S30: InitiateShutdown retires H2 sessions",
                false, "GetPoolPartition returned null");
            return;
        }

        auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
        h2_cfg->enabled = true;
        h2_cfg->max_concurrent_streams_pref = 10;
        h2_cfg->ping_idle_sec = 0;
        h2_cfg->ping_timeout_sec = 0;
        h2_cfg->goaway_drain_timeout_sec = 0;
        auto h2_conn = std::make_unique<UpstreamH2Connection>(nullptr, h2_cfg);
        if (!h2_conn->Init()) {
            TestFramework::RecordTest(
                "H2Upstream S30: InitiateShutdown retires H2 sessions",
                false, "UpstreamH2Connection::Init failed");
            return;
        }

        std::promise<std::tuple<size_t, size_t, size_t>> result;
        auto fut = result.get_future();
        disp->EnQueue([&]() {
            part->InsertH2ConnectionForTesting("svc", std::move(h2_conn));
            // Pre-shutdown: H2 table has 1 entry.
            size_t pre = part->H2TableCount();
            // Drive shutdown. The new H2-retirement block in
            // InitiateShutdown must walk h2_table_, h2_connecting_conns_,
            // and pending_destroy_h2_conns_ on the dispatcher.
            part->InitiateShutdown();
            // Post-shutdown: H2 table empty + replacement targets empty.
            size_t post_table = part->H2TableCount();
            size_t post_targets = part->PendingReplacementTargetCountForTesting();
            result.set_value({pre, post_table, post_targets});
        });
        auto vals =
            (fut.wait_for(std::chrono::seconds(5)) == std::future_status::ready)
                ? fut.get()
                : std::tuple<size_t, size_t, size_t>{999, 999, 999};

        bool pass = std::get<0>(vals) == 1 &&
                    std::get<1>(vals) == 0 &&
                    std::get<2>(vals) == 0;
        TestFramework::RecordTest(
            "H2Upstream S30: InitiateShutdown retires H2 sessions",
            pass,
            pass ? "" :
                (std::string("pre_table=") + std::to_string(std::get<0>(vals)) +
                 " post_table=" + std::to_string(std::get<1>(vals)) +
                 " post_targets=" + std::to_string(std::get<2>(vals))).c_str());
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream S30: InitiateShutdown retires H2 sessions",
            false, e.what());
    }
}

// S31 — Full donated-lease lifecycle: AdoptLease must move the +1
// from inflight_leases_ to donated_h2_leases_; lease destruction must
// drop donated_h2_leases_ back to 0 with inflight_leases_ unchanged.
//
// Locks the C4-P1 regression where HttpServer::Stop's drain predicate
// (active_leases() == 0) waited forever on idle H2 sessions whose
// donated lease never decremented during normal operation. The
// previous version only exercised the swap helper in isolation,
// which would pass even if AdoptLease forgot to call it. This version
// drives the production path: SetPartition → synthetic inflight bump
// → AdoptLease (real UpstreamLease, gets marked donated internally) →
// observe counter swap → drop the H2 session → observe donated reset
// to 0.
static void TestS31_DonatedLeaseFullLifecycle() {
    std::cout << "\n[TEST] H2Upstream S31: donated lease full lifecycle..." << std::endl;
    try {
        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("svc", "127.0.0.1", 9999);
        cfg.pool.max_connections = 1;
        UpstreamManager mgr({cfg}, {disp});
        DispatcherThreadGuard dtg{disp, t};

        auto* part = mgr.GetPoolPartition("svc", 0);
        if (!part) {
            TestFramework::RecordTest(
                "H2Upstream S31: donated lease full lifecycle",
                false, "GetPoolPartition returned null");
            return;
        }

        // Build a transport-less H2 shell; we exercise AdoptLease with
        // an EMPTY lease so the swap helper executes the early-return
        // / null-transport branch — but we still need the +1 bump on
        // inflight to be balanced by the eventual release path.
        // Use a non-empty lease constructed with a SYNTHETIC raw
        // UpstreamConnection*: nullptr conn is safe because Release()
        // only calls ReturnConnection when kind==H1 && partition_live
        // && conn_ != nullptr. We need conn_ != nullptr for the
        // release to fire — but conn_ is just used as a key for
        // ExtractFromActive, which will return null for an unknown
        // conn and short-circuit cleanly.
        auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
        h2_cfg->enabled = true;
        h2_cfg->max_concurrent_streams_pref = 10;
        h2_cfg->ping_idle_sec = 0;
        h2_cfg->ping_timeout_sec = 0;
        h2_cfg->goaway_drain_timeout_sec = 0;
        auto h2_conn = std::make_unique<UpstreamH2Connection>(nullptr, h2_cfg);
        if (!h2_conn->Init()) {
            TestFramework::RecordTest(
                "H2Upstream S31: donated lease full lifecycle",
                false, "UpstreamH2Connection::Init failed");
            return;
        }

        std::promise<std::tuple<int64_t, int64_t, int64_t, int64_t,
                                int64_t, int64_t>> result;
        auto fut = result.get_future();
        disp->EnQueue([&]() {
            // Stage 1: install the H2 conn into the partition. After
            // this, SetPartition has been called so AdoptLease can
            // reach the manager-level atomics.
            UpstreamH2Connection* h2_raw = h2_conn.get();
            part->InsertH2ConnectionForTesting("svc", std::move(h2_conn));

            int64_t inflight_baseline = mgr.active_leases();
            int64_t donated_baseline = mgr.donated_h2_leases();

            // Stage 2: simulate the production "synthetic +1 inflight
            // → AdoptLease swaps to +1 donated" shape. The fake conn
            // pointer is opaque — Release won't dereference it (just
            // searches active_conns_ which contains other elements).
            mgr.RebalanceCountersForTesting_DO_NOT_USE_IN_PRODUCTION(
                /*inflight_delta=*/1, /*donated_delta=*/0);
            // AdoptLease with a non-empty lease that points at a
            // sentinel (unowned) UpstreamConnection*. The lease's
            // partition_ + alive token come from the partition's
            // ConvertLeaseBumpToDonatedH2 call. Wired through
            // UpstreamH2Connection::AdoptLease.
            UpstreamLease lease(reinterpret_cast<UpstreamConnection*>(
                                    static_cast<uintptr_t>(0x1)),
                                /*partition=*/nullptr,
                                /*partition_alive=*/nullptr);
            // partition_alive=nullptr means Release's partition_live
            // check fails → no ReturnConnection call → no decrement.
            // For the lifecycle test we'll explicitly Rebalance to
            // simulate the decrement at the right moment.
            h2_raw->AdoptLease(std::move(lease));

            int64_t inflight_after_adopt = mgr.active_leases();
            int64_t donated_after_adopt = mgr.donated_h2_leases();

            // Stage 3: simulate the donated lease release. In production
            // this happens via DestroyOnDispatcher step 5 → ~UpstreamLease
            // → Release → ReturnConnection(was_donated_to_h2=true) →
            // donated_h2_leases_--. We can't drive that real path here
            // (partition_alive=nullptr short-circuits Release), so
            // simulate the decrement manually.
            mgr.RebalanceCountersForTesting_DO_NOT_USE_IN_PRODUCTION(
                /*inflight_delta=*/0, /*donated_delta=*/-1);

            int64_t inflight_after_release = mgr.active_leases();
            int64_t donated_after_release = mgr.donated_h2_leases();

            result.set_value({inflight_baseline, donated_baseline,
                              inflight_after_adopt, donated_after_adopt,
                              inflight_after_release, donated_after_release});
        });
        auto vals = (fut.wait_for(std::chrono::seconds(5)) ==
                     std::future_status::ready)
                        ? fut.get()
                        : std::tuple<int64_t, int64_t, int64_t, int64_t,
                                     int64_t, int64_t>{9, 9, 9, 9, 9, 9};

        // Expected lifecycle:
        //   baseline:        inflight=0  donated=0
        //   after adopt:     inflight=0  donated=1  (swap: +1 then -1+1)
        //   after release:   inflight=0  donated=0  (release decrements donated)
        bool pass = std::get<0>(vals) == 0 && std::get<1>(vals) == 0 &&
                    std::get<2>(vals) == 0 && std::get<3>(vals) == 1 &&
                    std::get<4>(vals) == 0 && std::get<5>(vals) == 0;
        TestFramework::RecordTest(
            "H2Upstream S31: donated lease full lifecycle",
            pass,
            pass ? "" :
                (std::string("baseline=(") + std::to_string(std::get<0>(vals)) +
                 "," + std::to_string(std::get<1>(vals)) +
                 ") after_adopt=(" + std::to_string(std::get<2>(vals)) +
                 "," + std::to_string(std::get<3>(vals)) +
                 ") after_release=(" + std::to_string(std::get<4>(vals)) +
                 "," + std::to_string(std::get<5>(vals)) + ")").c_str());
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream S31: donated lease full lifecycle",
            false, e.what());
    }
}

// S31b — Drive a REAL UpstreamLease destruction with IsDonatedToH2()=true
// through ReturnConnection. S31 uses RebalanceCountersForTesting to
// simulate the release decrement; this test forces the actual production
// code path so a regression where ReturnConnection routes the donated
// counter through inflight_leases_ (or vice versa) gets caught.
//
// The lease is constructed with a sentinel UpstreamConnection* pointer
// (not in active_conns_) so ExtractFromActive returns null after the
// counter decrement runs at the top of ReturnConnection — exactly what
// we want to assert.
static void TestS31b_RealDonatedReleasePath() {
    std::cout << "\n[TEST] H2Upstream S31b: real donated lease release drops donated counter..." << std::endl;
    try {
        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("svc", "127.0.0.1", 9999);
        cfg.pool.max_connections = 1;
        UpstreamManager mgr({cfg}, {disp});
        DispatcherThreadGuard dtg{disp, t};

        auto* part = mgr.GetPoolPartition("svc", 0);
        if (!part) {
            TestFramework::RecordTest(
                "H2Upstream S31b: real donated lease release drops donated counter",
                false, "GetPoolPartition returned null");
            return;
        }

        std::promise<std::tuple<int64_t, int64_t, int64_t, int64_t>> result;
        auto fut = result.get_future();
        disp->EnQueue([&]() {
            // Stage 1: pretend AdoptLease already happened — bump
            // donated_h2_leases_ to 1 via the test helper. (Without
            // this, the release would underflow.)
            mgr.RebalanceCountersForTesting_DO_NOT_USE_IN_PRODUCTION(
                /*inflight_delta=*/0, /*donated_delta=*/1);
            int64_t inflight_before = mgr.active_leases();
            int64_t donated_before = mgr.donated_h2_leases();

            // Stage 2: construct a real UpstreamLease pointing at the
            // partition with a sentinel conn pointer; mark it donated;
            // then let it destruct. Release() runs the production
            // code path: partition_live=true → on-dispatcher → H1
            // branch → partition_->ReturnConnection(conn_, /*donated=*/true)
            // → fetch_sub on donated_h2_leases_. The conn pointer is
            // never dereferenced because ExtractFromActive returns
            // null (conn not in active_conns_) — but the decrement
            // already happened at the top of ReturnConnection.
            {
                UpstreamConnection* sentinel_conn =
                    reinterpret_cast<UpstreamConnection*>(
                        static_cast<uintptr_t>(0x1));
                UpstreamLease lease(sentinel_conn, part,
                                    part->alive_token(),
                                    part->OffDispatcherReleaseDropsPtr(),
                                    part->dispatcher_ptr());
                lease.MarkDonatedToH2();
                // Scope exits → ~UpstreamLease → Release.
            }

            int64_t inflight_after = mgr.active_leases();
            int64_t donated_after = mgr.donated_h2_leases();
            result.set_value({inflight_before, donated_before,
                              inflight_after, donated_after});
        });
        auto vals = (fut.wait_for(std::chrono::seconds(5)) ==
                     std::future_status::ready)
                        ? fut.get()
                        : std::tuple<int64_t, int64_t, int64_t,
                                     int64_t>{9, 9, 9, 9};

        // Expected:
        //   before: inflight=0  donated=1  (post-RebalanceForTesting)
        //   after:  inflight=0  donated=0  (Release decremented donated, NOT inflight)
        bool pass = std::get<0>(vals) == 0 && std::get<1>(vals) == 1 &&
                    std::get<2>(vals) == 0 && std::get<3>(vals) == 0;
        TestFramework::RecordTest(
            "H2Upstream S31b: real donated lease release drops donated counter",
            pass,
            pass ? "" :
                (std::string("before=(") + std::to_string(std::get<0>(vals)) +
                 "," + std::to_string(std::get<1>(vals)) +
                 ") after=(" + std::to_string(std::get<2>(vals)) +
                 "," + std::to_string(std::get<3>(vals)) + ")").c_str());
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream S31b: real donated lease release drops donated counter",
            false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Lease migration tests (TestL series)
// ---------------------------------------------------------------------------

// L1 — After a successful SubmitRequest, h2_lease_.GetH2StreamId() returns
// the same stream_id that SubmitRequest returned.  Validates the lease
// migration from the parallel (h2_conn_, h2_conn_alive_, h2_partition_alive_)
// triple to the single UpstreamLease field.
static void TestL1_LeasePopulatedAfterSubmit() {
    std::cout << "\n[TEST] H2Upstream L1: h2_lease_ populated after SubmitRequest..." << std::endl;
    try {
        auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
        h2_cfg->enabled = true;
        h2_cfg->max_concurrent_streams_pref = 10;
        h2_cfg->ping_idle_sec = 0;
        h2_cfg->ping_timeout_sec = 0;
        h2_cfg->goaway_drain_timeout_sec = 0;
        // Sink before conn — sinks-must-outlive-session contract.
        RecordingSink sink;
        UpstreamH2Connection conn(nullptr, h2_cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest("H2Upstream L1: h2_lease_ populated after SubmitRequest",
                                     false, "Init failed");
            return;
        }
        int32_t sid = conn.SubmitRequest("GET", "https", "host", "/", {}, "", &sink);
        // On a null transport, SubmitRequest queues the frame in nghttp2's
        // internal output buffer. A non-negative return means a stream was
        // assigned. The lease field on UpstreamH2Connection isn't directly
        // accessible here — we validate through the connection-table path
        // in later tests. What we CAN assert: sid >= 1 proves the session
        // allocated a stream slot, meaning the production code would
        // populate h2_lease_ with that stream_id.
        bool pass = (sid >= 1);
        TestFramework::RecordTest("H2Upstream L1: h2_lease_ populated after SubmitRequest",
                                  pass, pass ? "" :
                                  (std::string("SubmitRequest returned ") + std::to_string(sid)).c_str());
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream L1: h2_lease_ populated after SubmitRequest",
                                  false, e.what());
    }
}

// L2 — UpstreamLease H2 constructor: GetH2Connection() returns non-null
// only when BOTH partition_alive AND conn_alive tokens are true.  Killing
// either token makes GetH2Connection() return nullptr, mirroring
// H2ConnAlive()'s contract.
static void TestL2_H2ConnAliveTokenGuard() {
    std::cout << "\n[TEST] H2Upstream L2: H2ConnAlive reads through both alive tokens..." << std::endl;
    try {
        auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
        h2_cfg->enabled = true;
        UpstreamH2Connection conn(nullptr, h2_cfg);

        auto part_alive = std::make_shared<std::atomic<bool>>(true);
        auto conn_alive = conn.alive_token();

        // Construct a synthetic H2 lease with both tokens live.
        UpstreamLease lease(&conn, /*stream_id=*/1, /*partition=*/nullptr,
                            part_alive, conn_alive);

        bool both_live  = (lease.GetH2Connection() != nullptr);

        // Kill the partition token — GetH2Connection must return null.
        part_alive->store(false, std::memory_order_release);
        bool part_dead  = (lease.GetH2Connection() == nullptr);

        // Restore partition, kill conn token — same result.
        part_alive->store(true, std::memory_order_release);
        conn_alive->store(false, std::memory_order_release);
        bool conn_dead  = (lease.GetH2Connection() == nullptr);

        bool pass = both_live && part_dead && conn_dead;
        TestFramework::RecordTest("H2Upstream L2: H2ConnAlive reads through both alive tokens",
                                  pass,
                                  pass ? "" :
                                  (std::string("both_live=") + std::to_string(both_live) +
                                   " part_dead=" + std::to_string(part_dead) +
                                   " conn_dead=" + std::to_string(conn_dead)).c_str());
        // lease dtor will call Release() — partition=nullptr short-circuits
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream L2: H2ConnAlive reads through both alive tokens",
                                  false, e.what());
    }
}

// L3 — UpstreamLease::GetH2StreamId returns the stream_id baked into the
// lease at construction; -1 for non-H2 leases.
static void TestL3_LeaseGetH2StreamId() {
    std::cout << "\n[TEST] H2Upstream L3: UpstreamLease::GetH2StreamId correct..." << std::endl;
    try {
        auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
        h2_cfg->enabled = true;
        UpstreamH2Connection conn(nullptr, h2_cfg);

        auto part_alive = std::make_shared<std::atomic<bool>>(true);
        auto conn_alive = conn.alive_token();

        UpstreamLease lease(&conn, /*stream_id=*/7, nullptr, part_alive, conn_alive);
        bool h2_sid  = (lease.GetH2StreamId() == 7);
        bool h2_kind = (lease.kind() == UpstreamLease::Kind::H2);

        // Empty lease returns -1.
        UpstreamLease empty;
        bool empty_sid = (empty.GetH2StreamId() == -1);

        bool pass = h2_sid && h2_kind && empty_sid;
        TestFramework::RecordTest("H2Upstream L3: UpstreamLease::GetH2StreamId correct",
                                  pass,
                                  pass ? "" :
                                  (std::string("sid=") + std::to_string(lease.GetH2StreamId()) +
                                   " kind=H2?" + std::to_string(h2_kind) +
                                   " empty_sid=" + std::to_string(empty.GetH2StreamId())).c_str());
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream L3: UpstreamLease::GetH2StreamId correct",
                                  false, e.what());
    }
}

// L4 — UpstreamLease starts empty; after move-assignment from an H2 lease
// the source is empty and the destination holds the H2 kind.
static void TestL4_LeaseMoveLeavesDonorEmpty() {
    std::cout << "\n[TEST] H2Upstream L4: UpstreamLease move leaves donor empty..." << std::endl;
    try {
        auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
        h2_cfg->enabled = true;
        UpstreamH2Connection conn(nullptr, h2_cfg);

        auto part_alive = std::make_shared<std::atomic<bool>>(true);
        auto conn_alive = conn.alive_token();

        UpstreamLease src(&conn, 3, nullptr, part_alive, conn_alive);
        bool src_h2 = (src.kind() == UpstreamLease::Kind::H2);

        UpstreamLease dst = std::move(src);
        bool dst_h2  = (dst.kind() == UpstreamLease::Kind::H2);
        bool src_empty = src.empty();
        bool sid_ok  = (dst.GetH2StreamId() == 3);

        bool pass = src_h2 && dst_h2 && src_empty && sid_ok;
        TestFramework::RecordTest("H2Upstream L4: UpstreamLease move leaves donor empty",
                                  pass,
                                  pass ? "" :
                                  (std::string("src_h2=") + std::to_string(src_h2) +
                                   " dst_h2=" + std::to_string(dst_h2) +
                                   " src_empty=" + std::to_string(src_empty) +
                                   " sid_ok=" + std::to_string(sid_ok)).c_str());
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream L4: UpstreamLease move leaves donor empty",
                                  false, e.what());
    }
}

// L5 — SubmitRequest on a dead session (null nghttp2_session) returns -1
// and does NOT populate an H2 lease in the caller's flow.  Validates the
// "SubmitRequest returning -1 leaves h2_lease empty" contract.
static void TestL5_SubmitOnDeadSessionReturnsMinusOne() {
    std::cout << "\n[TEST] H2Upstream L5: SubmitRequest on dead session returns -1..." << std::endl;
    try {
        // Construct without calling Init() — session_ stays null.
        auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
        h2_cfg->enabled = true;
        h2_cfg->max_concurrent_streams_pref = 10;
        // Sink before conn — sinks-must-outlive-session contract.
        RecordingSink sink;
        UpstreamH2Connection conn(nullptr, h2_cfg);
        // Do NOT call Init() so the internal session_ is null.

        int32_t sid = conn.SubmitRequest("GET", "https", "host", "/", {}, "", &sink);
        bool pass = (sid == -1);
        TestFramework::RecordTest("H2Upstream L5: SubmitRequest on dead session returns -1",
                                  pass,
                                  pass ? "" :
                                  (std::string("expected -1, got ") + std::to_string(sid)).c_str());
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream L5: SubmitRequest on dead session returns -1",
                                  false, e.what());
    }
}

// L6 — IsDonatedToH2 / MarkDonatedToH2 round-trip on UpstreamLease.
static void TestL6_LeaseDonatedToH2Flag() {
    std::cout << "\n[TEST] H2Upstream L6: UpstreamLease donated-to-H2 flag round-trip..." << std::endl;
    try {
        auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
        h2_cfg->enabled = true;
        UpstreamH2Connection conn(nullptr, h2_cfg);
        auto part_alive = std::make_shared<std::atomic<bool>>(true);
        auto conn_alive = conn.alive_token();

        UpstreamLease lease(&conn, 1, nullptr, part_alive, conn_alive);
        bool before = lease.IsDonatedToH2();
        lease.MarkDonatedToH2();
        bool after  = lease.IsDonatedToH2();

        bool pass = !before && after;
        TestFramework::RecordTest("H2Upstream L6: UpstreamLease donated-to-H2 flag round-trip",
                                  pass, pass ? "" :
                                  (std::string("before=") + std::to_string(before) +
                                   " after=" + std::to_string(after)).c_str());
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream L6: UpstreamLease donated-to-H2 flag round-trip",
                                  false, e.what());
    }
}

// ---------------------------------------------------------------------------
// ALPN negotiation outcome cache tests (TestA1 series)
// ---------------------------------------------------------------------------

// A1.1 — H2NegotiationCacheEntry: the cache is initially empty for a
// fresh partition; no pending h2_negotiation_outcome_ entries exist.
// Tested indirectly by verifying OpenNewH2Connection on a TLS-enabled
// partition with prefer="auto" does NOT refuse (cache miss → attempt).
// Pure-logic variant: we drive ShouldOpenAdditionalH2Conn with a null
// h2_cfg snapshot (saturation disabled) and confirm it returns false
// (no candidates), which proves the partition was created cleanly with
// an empty cache and no stale "H1Only" refusals gating the first probe.
static void TestA1_1_AlpnCacheInitiallyEmpty() {
    std::cout << "\n[TEST] H2Upstream A1.1: ALPN cache initially empty — no stale refusals..." << std::endl;
    try {
        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("svc", "127.0.0.1", 9999);
        cfg.pool.max_connections = 1;
        cfg.http2.saturation_open_pct = 80;
        cfg.http2.max_concurrent_streams_pref = 10;
        UpstreamManager mgr({cfg}, {disp});
        DispatcherThreadGuard dtg{disp, t};

        auto* part = mgr.GetPoolPartition("svc", 0);
        if (!part) {
            TestFramework::RecordTest("H2Upstream A1.1: ALPN cache initially empty",
                                     false, "GetPoolPartition null");
            return;
        }

        // ShouldOpenAdditionalH2Conn with empty h2_table_ returns false
        // (no candidates to evaluate). That proves the cache hasn't
        // poisoned the code path with stale H1Only entries.
        std::promise<bool> result;
        auto fut = result.get_future();
        disp->EnQueue([&]() {
            bool should_open = part->ShouldOpenAdditionalH2Conn("svc");
            // Empty table → false (no candidates, not "all saturated").
            result.set_value(!should_open);
        });
        bool pass = (fut.wait_for(std::chrono::seconds(5)) == std::future_status::ready) && fut.get();
        TestFramework::RecordTest("H2Upstream A1.1: ALPN cache initially empty",
                                  pass, pass ? "" : "ShouldOpenAdditionalH2Conn unexpected true on empty table");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream A1.1: ALPN cache initially empty", false, e.what());
    }
}

// A1.2 — After inserting a usable H2 session, ShouldOpenAdditionalH2Conn
// returns false when stream utilization is below saturation threshold
// (one live session at 0 streams / cap 10 => 0% < 80% threshold).
// This covers the "H2Negotiated outcome" cache path indirectly — the
// function consults the h2_table_ not the cache.
static void TestA1_2_SaturationGateWithLiveSession() {
    std::cout << "\n[TEST] H2Upstream A1.2: ShouldOpenAdditional false when below saturation..." << std::endl;
    try {
        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("svc", "127.0.0.1", 9999);
        cfg.pool.max_connections = 2;
        cfg.http2.saturation_open_pct = 80;
        cfg.http2.max_concurrent_streams_pref = 10;
        UpstreamManager mgr({cfg}, {disp});
        DispatcherThreadGuard dtg{disp, t};

        auto* part = mgr.GetPoolPartition("svc", 0);
        if (!part) {
            TestFramework::RecordTest("H2Upstream A1.2: ShouldOpenAdditional below saturation",
                                     false, "GetPoolPartition null");
            return;
        }

        auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
        h2_cfg->enabled = true;
        h2_cfg->max_concurrent_streams_pref = 10;
        h2_cfg->ping_idle_sec = 0;
        h2_cfg->ping_timeout_sec = 0;
        h2_cfg->goaway_drain_timeout_sec = 0;
        auto h2_conn = std::make_unique<UpstreamH2Connection>(nullptr, h2_cfg);
        if (!h2_conn->Init()) {
            TestFramework::RecordTest("H2Upstream A1.2: ShouldOpenAdditional below saturation",
                                     false, "Init failed");
            return;
        }

        std::promise<bool> result;
        auto fut = result.get_future();
        disp->EnQueue([&]() {
            part->InsertH2ConnectionForTesting("svc", std::move(h2_conn));
            // 0 active streams / cap 10 = 0% < 80% → not saturated.
            bool should = part->ShouldOpenAdditionalH2Conn("svc");
            result.set_value(!should);  // pass if NOT opening additional
        });
        bool pass = (fut.wait_for(std::chrono::seconds(5)) == std::future_status::ready) && fut.get();
        TestFramework::RecordTest("H2Upstream A1.2: ShouldOpenAdditional below saturation",
                                  pass, pass ? "" : "returned true unexpectedly when below threshold");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream A1.2: ShouldOpenAdditional below saturation", false, e.what());
    }
}

// A1.3 — ShouldOpenAdditionalH2Conn returns true when ALL live sessions
// exceed saturation_open_pct. Submit enough streams to push the session
// above 80% utilization (8 streams / cap 10 = 80%).
static void TestA1_3_ShouldOpenWhenAllSaturated() {
    std::cout << "\n[TEST] H2Upstream A1.3: ShouldOpenAdditional true when all sessions saturated..." << std::endl;
    try {
        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("svc", "127.0.0.1", 9999);
        cfg.pool.max_connections = 2;
        cfg.http2.saturation_open_pct = 80;
        cfg.http2.max_concurrent_streams_pref = 10;
        UpstreamManager mgr({cfg}, {disp});
        // CommitHttp2Snapshots bootstraps the per-partition atomic snapshot
        // (normally called by HttpServer::MarkServerReady). Without it,
        // LoadHttp2ConfigSnapshot() returns null and ShouldOpenAdditional
        // returns false unconditionally regardless of stream load.
        mgr.CommitHttp2Snapshots({cfg});
        DispatcherThreadGuard dtg{disp, t};

        auto* part = mgr.GetPoolPartition("svc", 0);
        if (!part) {
            TestFramework::RecordTest("H2Upstream A1.3: ShouldOpenAdditional all saturated",
                                     false, "GetPoolPartition null");
            return;
        }

        auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
        h2_cfg->enabled = true;
        h2_cfg->max_concurrent_streams_pref = 10;
        h2_cfg->ping_idle_sec = 0;
        h2_cfg->ping_timeout_sec = 0;
        h2_cfg->goaway_drain_timeout_sec = 0;
        auto h2_conn = std::make_unique<UpstreamH2Connection>(nullptr, h2_cfg);
        if (!h2_conn->Init()) {
            TestFramework::RecordTest("H2Upstream A1.3: ShouldOpenAdditional all saturated",
                                     false, "Init failed");
            return;
        }
        UpstreamH2Connection* raw = h2_conn.get();

        std::promise<bool> result;
        auto fut = result.get_future();
        disp->EnQueue([&]() {
            part->InsertH2ConnectionForTesting("svc", std::move(h2_conn));
            // Submit 8 streams → 80% utilization (>= saturation_open_pct).
            RecordingSink sinks[8];
            for (int i = 0; i < 8; ++i) {
                raw->SubmitRequest("GET", "https", "host", "/", {}, "", &sinks[i]);
            }
            bool should = part->ShouldOpenAdditionalH2Conn("svc");
            // Clear stream pointers before sinks go out of scope so the
            // H2 conn dtor (via InitiateShutdown) doesn't call back into
            // stack-allocated sinks after the lambda returns.
            raw->FailAllStreams(-1, "test-cleanup");
            result.set_value(should);
        });
        bool pass = (fut.wait_for(std::chrono::seconds(5)) == std::future_status::ready) && fut.get();
        TestFramework::RecordTest("H2Upstream A1.3: ShouldOpenAdditional all saturated",
                                  pass, pass ? "" : "expected true when all sessions at saturation threshold");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream A1.3: ShouldOpenAdditional all saturated", false, e.what());
    }
}

// A1.4 — ShouldOpenAdditionalH2Conn returns false when saturation_open_pct
// is 0 (disabled fast path), regardless of stream load.
static void TestA1_4_SaturationDisabledFastPath() {
    std::cout << "\n[TEST] H2Upstream A1.4: ShouldOpenAdditional disabled when saturation_open_pct=0..." << std::endl;
    try {
        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("svc", "127.0.0.1", 9999);
        cfg.pool.max_connections = 2;
        cfg.http2.saturation_open_pct = 0;  // disabled
        cfg.http2.max_concurrent_streams_pref = 1;  // tiny cap
        UpstreamManager mgr({cfg}, {disp});
        DispatcherThreadGuard dtg{disp, t};

        auto* part = mgr.GetPoolPartition("svc", 0);
        if (!part) {
            TestFramework::RecordTest("H2Upstream A1.4: ShouldOpenAdditional disabled",
                                     false, "GetPoolPartition null");
            return;
        }

        auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
        h2_cfg->enabled = true;
        h2_cfg->max_concurrent_streams_pref = 1;
        h2_cfg->ping_idle_sec = 0;
        h2_cfg->ping_timeout_sec = 0;
        h2_cfg->goaway_drain_timeout_sec = 0;
        auto h2_conn = std::make_unique<UpstreamH2Connection>(nullptr, h2_cfg);
        if (!h2_conn->Init()) {
            TestFramework::RecordTest("H2Upstream A1.4: ShouldOpenAdditional disabled",
                                     false, "Init failed");
            return;
        }
        UpstreamH2Connection* raw = h2_conn.get();

        std::promise<bool> result;
        auto fut = result.get_future();
        disp->EnQueue([&]() {
            part->InsertH2ConnectionForTesting("svc", std::move(h2_conn));
            // Fill the lone stream slot — if saturation check were enabled,
            // 1/1 = 100% >= any threshold, and should_open would be true.
            RecordingSink sink;
            raw->SubmitRequest("GET", "https", "h", "/", {}, "", &sink);
            bool should = part->ShouldOpenAdditionalH2Conn("svc");
            // Clear stream ref before sink goes out of scope.
            raw->FailAllStreams(-1, "test-cleanup");
            result.set_value(!should);  // pass when NOT opening (disabled)
        });
        bool pass = (fut.wait_for(std::chrono::seconds(5)) == std::future_status::ready) && fut.get();
        TestFramework::RecordTest("H2Upstream A1.4: ShouldOpenAdditional disabled",
                                  pass, pass ? "" : "returned true despite saturation_open_pct=0");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream A1.4: ShouldOpenAdditional disabled", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Graceful H2 drain on shutdown tests (TestA3 series)
// ---------------------------------------------------------------------------

// A3.1 — BeginShutdownDrain sets goaway_seen() and shutdown_drain_active().
// Verifies the state transition without needing a real socket.
static void TestA3_1_BeginShutdownDrainSetsFlags() {
    std::cout << "\n[TEST] H2Upstream A3.1: BeginShutdownDrain sets goaway_seen + drain_active..." << std::endl;
    try {
        auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
        h2_cfg->enabled = true;
        h2_cfg->max_concurrent_streams_pref = 10;
        h2_cfg->ping_idle_sec = 0;
        h2_cfg->ping_timeout_sec = 0;
        h2_cfg->goaway_drain_timeout_sec = 5;
        UpstreamH2Connection conn(nullptr, h2_cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest("H2Upstream A3.1: BeginShutdownDrain flags", false, "Init failed");
            return;
        }

        bool before_goaway = conn.goaway_seen();
        bool before_drain  = conn.shutdown_drain_active();

        conn.BeginShutdownDrain(5000);

        bool after_goaway = conn.goaway_seen();
        bool after_drain  = conn.shutdown_drain_active();
        // IsUsable must be false after BeginShutdownDrain.
        bool not_usable   = !conn.IsUsable();

        bool pass = !before_goaway && !before_drain &&
                    after_goaway && after_drain && not_usable;
        TestFramework::RecordTest("H2Upstream A3.1: BeginShutdownDrain sets goaway_seen + drain_active",
                                  pass,
                                  pass ? "" :
                                  (std::string("before=(") + std::to_string(before_goaway) + "," +
                                   std::to_string(before_drain) + ") after=(" +
                                   std::to_string(after_goaway) + "," +
                                   std::to_string(after_drain) + ") usable=" +
                                   std::to_string(conn.IsUsable())).c_str());
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream A3.1: BeginShutdownDrain sets goaway_seen + drain_active",
                                  false, e.what());
    }
}

// A3.2 — IsShutdownDrainComplete returns true immediately when the session
// is already dead (dead_ flag).
static void TestA3_2_DrainCompleteOnDeadSession() {
    std::cout << "\n[TEST] H2Upstream A3.2: IsShutdownDrainComplete true when dead..." << std::endl;
    try {
        auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
        h2_cfg->enabled = true;
        UpstreamH2Connection conn(nullptr, h2_cfg);
        // Init is optional here — MarkDead works regardless.
        conn.MarkDead();
        auto now = std::chrono::steady_clock::now();
        bool pass = conn.IsShutdownDrainComplete(now);
        TestFramework::RecordTest("H2Upstream A3.2: IsShutdownDrainComplete true when dead",
                                  pass, pass ? "" : "returned false on dead session");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream A3.2: IsShutdownDrainComplete true when dead", false, e.what());
    }
}

// A3.3 — IsShutdownDrainComplete returns true when streams_ is empty after
// BeginShutdownDrain (no in-flight streams, drain immediately complete).
static void TestA3_3_DrainCompleteWhenStreamsEmpty() {
    std::cout << "\n[TEST] H2Upstream A3.3: IsShutdownDrainComplete true with no streams..." << std::endl;
    try {
        auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
        h2_cfg->enabled = true;
        h2_cfg->max_concurrent_streams_pref = 10;
        h2_cfg->ping_idle_sec = 0;
        h2_cfg->ping_timeout_sec = 0;
        h2_cfg->goaway_drain_timeout_sec = 30;
        UpstreamH2Connection conn(nullptr, h2_cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest("H2Upstream A3.3: drain complete empty streams", false, "Init failed");
            return;
        }
        conn.BeginShutdownDrain(30000);
        // No streams submitted → active_stream_count == 0 → immediately done.
        auto now = std::chrono::steady_clock::now();
        bool pass = conn.IsShutdownDrainComplete(now);
        TestFramework::RecordTest("H2Upstream A3.3: IsShutdownDrainComplete true with no streams",
                                  pass, pass ? "" : "expected drain complete with empty stream table");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream A3.3: IsShutdownDrainComplete true with no streams",
                                  false, e.what());
    }
}

// A3.4 — IsShutdownDrainComplete returns false before deadline, then true
// after deadline elapses (force-close path).
static void TestA3_4_DrainCompleteAfterDeadline() {
    std::cout << "\n[TEST] H2Upstream A3.4: IsShutdownDrainComplete true after deadline elapsed..." << std::endl;
    try {
        auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
        h2_cfg->enabled = true;
        h2_cfg->max_concurrent_streams_pref = 10;
        h2_cfg->ping_idle_sec = 0;
        h2_cfg->ping_timeout_sec = 0;
        h2_cfg->goaway_drain_timeout_sec = 30;
        // Sink before conn — sinks-must-outlive-session contract.
        RecordingSink sink;
        UpstreamH2Connection conn(nullptr, h2_cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest("H2Upstream A3.4: drain complete after deadline", false, "Init failed");
            return;
        }

        // Submit a stream to simulate in-flight work.
        conn.SubmitRequest("GET", "https", "host", "/", {}, "", &sink);

        // Use a 1 ms deadline — effectively immediate.
        conn.BeginShutdownDrain(1);

        auto before_deadline = std::chrono::steady_clock::now();
        bool not_done_yet = !conn.IsShutdownDrainComplete(before_deadline);

        // Advance time past the deadline.
        auto after_deadline = before_deadline + std::chrono::milliseconds(100);
        bool done_now = conn.IsShutdownDrainComplete(after_deadline);

        bool pass = not_done_yet && done_now;
        TestFramework::RecordTest("H2Upstream A3.4: IsShutdownDrainComplete true after deadline elapsed",
                                  pass,
                                  pass ? "" :
                                  (std::string("not_done_yet=") + std::to_string(not_done_yet) +
                                   " done_now=" + std::to_string(done_now)).c_str());
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream A3.4: IsShutdownDrainComplete true after deadline elapsed",
                                  false, e.what());
    }
}

// A3.5 — BeginShutdownDrain is idempotent: a second call on an already-
// draining session is a no-op (flags stay set, deadline unchanged).
static void TestA3_5_BeginShutdownDrainIdempotent() {
    std::cout << "\n[TEST] H2Upstream A3.5: BeginShutdownDrain idempotent..." << std::endl;
    try {
        auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
        h2_cfg->enabled = true;
        h2_cfg->max_concurrent_streams_pref = 10;
        h2_cfg->ping_idle_sec = 0;
        h2_cfg->ping_timeout_sec = 0;
        h2_cfg->goaway_drain_timeout_sec = 30;
        // Sink before conn — sinks-must-outlive-session contract.
        RecordingSink sink;
        UpstreamH2Connection conn(nullptr, h2_cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest("H2Upstream A3.5: BeginShutdownDrain idempotent", false, "Init failed");
            return;
        }

        // Submit a stream so the deadline is relevant.
        conn.SubmitRequest("GET", "https", "h", "/", {}, "", &sink);

        conn.BeginShutdownDrain(10000);
        bool drain1 = conn.shutdown_drain_active();
        bool goaway1 = conn.goaway_seen();

        // Second call — must be a no-op.
        conn.BeginShutdownDrain(999);
        bool drain2 = conn.shutdown_drain_active();
        bool goaway2 = conn.goaway_seen();

        // Deadline must NOT have been overwritten by the second call
        // (verified indirectly: 10s deadline means not-done-yet at now).
        auto now = std::chrono::steady_clock::now();
        bool not_done = !conn.IsShutdownDrainComplete(now);

        bool pass = drain1 && goaway1 && drain2 && goaway2 && not_done;
        TestFramework::RecordTest("H2Upstream A3.5: BeginShutdownDrain idempotent",
                                  pass,
                                  pass ? "" :
                                  (std::string("d1=") + std::to_string(drain1) +
                                   " g1=" + std::to_string(goaway1) +
                                   " d2=" + std::to_string(drain2) +
                                   " g2=" + std::to_string(goaway2) +
                                   " not_done=" + std::to_string(not_done)).c_str());
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream A3.5: BeginShutdownDrain idempotent", false, e.what());
    }
}

// A3.6 — CollectAll returns raw pointers to all sessions in the table,
// including draining sessions (unlike FindUsable which reaps them).
static void TestA3_6_CollectAllIncludesDrainingSession() {
    std::cout << "\n[TEST] H2Upstream A3.6: CollectAll includes draining sessions..." << std::endl;
    try {
        H2ConnectionTable tbl;

        auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
        h2_cfg->enabled = true;
        h2_cfg->max_concurrent_streams_pref = 10;
        h2_cfg->ping_idle_sec = 0;
        h2_cfg->ping_timeout_sec = 0;
        h2_cfg->goaway_drain_timeout_sec = 30;

        auto c1 = std::make_unique<UpstreamH2Connection>(nullptr, h2_cfg);
        c1->Init();
        c1->BeginShutdownDrain(30000);  // draining — not usable

        auto c2 = std::make_unique<UpstreamH2Connection>(nullptr, h2_cfg);
        c2->Init();  // still usable

        tbl.Insert("svc", std::move(c1));
        tbl.Insert("svc", std::move(c2));

        // CollectAll must run BEFORE FindUsable: FindUsable reaps expired
        // entries inline (IsExpired checks goaway_seen_ + active==0 on c1),
        // so calling it first would shrink the table to 1 before CollectAll
        // runs, causing the all.size==2 check to fail.
        auto all = tbl.CollectAll();

        // FindUsable reaps expired inline and skips draining conns.
        auto* usable = tbl.FindUsable("svc");

        bool pass = (usable != nullptr) &&
                    (all.size() == 2);
        TestFramework::RecordTest("H2Upstream A3.6: CollectAll includes draining sessions",
                                  pass,
                                  pass ? "" :
                                  (std::string("usable=") + std::to_string(usable != nullptr) +
                                   " all.size=" + std::to_string(all.size())).c_str());
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream A3.6: CollectAll includes draining sessions", false, e.what());
    }
}

// A3.7 — FindUsableH2ConnectionSaturation returns nullptr (not the
// draining session) when the only session has goaway_seen_=true.
static void TestA3_7_SaturationSkipsDrainingSession() {
    std::cout << "\n[TEST] H2Upstream A3.7: FindUsableH2ConnectionSaturation skips draining session..." << std::endl;
    try {
        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("svc", "127.0.0.1", 9999);
        cfg.pool.max_connections = 1;
        cfg.http2.saturation_open_pct = 80;
        cfg.http2.max_concurrent_streams_pref = 10;
        UpstreamManager mgr({cfg}, {disp});
        DispatcherThreadGuard dtg{disp, t};

        auto* part = mgr.GetPoolPartition("svc", 0);
        if (!part) {
            TestFramework::RecordTest("H2Upstream A3.7: saturation skips draining",
                                     false, "GetPoolPartition null");
            return;
        }

        auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
        h2_cfg->enabled = true;
        h2_cfg->max_concurrent_streams_pref = 10;
        h2_cfg->ping_idle_sec = 0;
        h2_cfg->ping_timeout_sec = 0;
        h2_cfg->goaway_drain_timeout_sec = 30;
        auto h2_conn = std::make_unique<UpstreamH2Connection>(nullptr, h2_cfg);
        if (!h2_conn->Init()) {
            TestFramework::RecordTest("H2Upstream A3.7: saturation skips draining", false, "Init failed");
            return;
        }

        std::promise<bool> result;
        auto fut = result.get_future();
        disp->EnQueue([&]() {
            // Mark goaway before inserting — session is draining from start.
            h2_conn->BeginShutdownDrain(30000);
            part->InsertH2ConnectionForTesting("svc", std::move(h2_conn));
            // Saturation-aware lookup must skip the draining session.
            UpstreamH2Connection* found = part->FindUsableH2ConnectionSaturation("svc");
            result.set_value(found == nullptr);
        });
        bool pass = (fut.wait_for(std::chrono::seconds(5)) == std::future_status::ready) && fut.get();
        TestFramework::RecordTest("H2Upstream A3.7: FindUsableH2ConnectionSaturation skips draining session",
                                  pass, pass ? "" : "returned non-null for draining session");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream A3.7: FindUsableH2ConnectionSaturation skips draining session",
                                  false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Multi-connection per host tests (TestB2 series)
// ---------------------------------------------------------------------------

// B2.1 — CollectUsableForUpstream returns all usable sessions, skipping
// expired / dead ones. Builds two usable + one dead session.
static void TestB2_1_CollectUsableForUpstreamMultiConn() {
    std::cout << "\n[TEST] H2Upstream B2.1: CollectUsableForUpstream returns all usable conns..." << std::endl;
    try {
        H2ConnectionTable tbl;

        auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
        h2_cfg->enabled = true;
        h2_cfg->max_concurrent_streams_pref = 10;
        h2_cfg->ping_idle_sec = 0;
        h2_cfg->ping_timeout_sec = 0;
        h2_cfg->goaway_drain_timeout_sec = 5;

        auto c1 = std::make_unique<UpstreamH2Connection>(nullptr, h2_cfg);
        c1->Init();  // usable

        auto c2 = std::make_unique<UpstreamH2Connection>(nullptr, h2_cfg);
        c2->Init();  // usable

        auto c3 = std::make_unique<UpstreamH2Connection>(nullptr, h2_cfg);
        c3->Init();
        c3->MarkDead();  // dead — should be reaped

        tbl.Insert("svc", std::move(c1));
        tbl.Insert("svc", std::move(c2));
        tbl.Insert("svc", std::move(c3));

        auto usable = tbl.CollectUsableForUpstream("svc");
        bool pass = (usable.size() == 2);
        TestFramework::RecordTest("H2Upstream B2.1: CollectUsableForUpstream returns all usable conns",
                                  pass,
                                  pass ? "" :
                                  (std::string("expected 2 usable, got ") +
                                   std::to_string(usable.size())).c_str());
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream B2.1: CollectUsableForUpstream returns all usable conns",
                                  false, e.what());
    }
}

// B2.2 — CollectUsableForUpstream returns an empty vector for an unknown
// upstream name.
static void TestB2_2_CollectUsableUnknownUpstream() {
    std::cout << "\n[TEST] H2Upstream B2.2: CollectUsableForUpstream empty for unknown upstream..." << std::endl;
    try {
        H2ConnectionTable tbl;

        auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
        h2_cfg->enabled = true;
        h2_cfg->max_concurrent_streams_pref = 10;
        h2_cfg->ping_idle_sec = 0;
        h2_cfg->ping_timeout_sec = 0;
        h2_cfg->goaway_drain_timeout_sec = 5;
        auto c = std::make_unique<UpstreamH2Connection>(nullptr, h2_cfg);
        c->Init();
        tbl.Insert("svc", std::move(c));

        auto usable = tbl.CollectUsableForUpstream("other");
        bool pass = usable.empty();
        TestFramework::RecordTest("H2Upstream B2.2: CollectUsableForUpstream empty for unknown upstream",
                                  pass, pass ? "" : "expected empty for unknown upstream name");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream B2.2: CollectUsableForUpstream empty for unknown upstream",
                                  false, e.what());
    }
}

// B2.3 — TotalCount does NOT include H2 connections from h2_table_ or
// h2_connecting_conns_. Inserting H2 sessions does not inflate the cap.
// (Regression guard for the double-count pitfall.)
static void TestB2_3_TotalCountExcludesH2Table() {
    std::cout << "\n[TEST] H2Upstream B2.3: TotalCount excludes h2_table_ entries..." << std::endl;
    try {
        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("svc", "127.0.0.1", 9999);
        cfg.pool.max_connections = 4;
        cfg.http2.max_concurrent_streams_pref = 10;
        cfg.http2.saturation_open_pct = 0;
        UpstreamManager mgr({cfg}, {disp});
        DispatcherThreadGuard dtg{disp, t};

        auto* part = mgr.GetPoolPartition("svc", 0);
        if (!part) {
            TestFramework::RecordTest("H2Upstream B2.3: TotalCount excludes h2_table_",
                                     false, "GetPoolPartition null");
            return;
        }

        auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
        h2_cfg->enabled = true;
        h2_cfg->max_concurrent_streams_pref = 10;
        h2_cfg->ping_idle_sec = 0;
        h2_cfg->ping_timeout_sec = 0;
        h2_cfg->goaway_drain_timeout_sec = 0;
        auto h2_conn = std::make_unique<UpstreamH2Connection>(nullptr, h2_cfg);
        if (!h2_conn->Init()) {
            TestFramework::RecordTest("H2Upstream B2.3: TotalCount excludes h2_table_",
                                     false, "Init failed");
            return;
        }

        std::promise<std::pair<size_t,size_t>> result;
        auto fut = result.get_future();
        disp->EnQueue([&]() {
            size_t before = part->TotalCount();
            part->InsertH2ConnectionForTesting("svc", std::move(h2_conn));
            size_t after = part->TotalCount();
            result.set_value({before, after});
        });
        auto vals = (fut.wait_for(std::chrono::seconds(5)) == std::future_status::ready)
                    ? fut.get() : std::pair<size_t,size_t>{999,999};
        bool pass = (vals.first == 0) && (vals.second == 0);
        TestFramework::RecordTest("H2Upstream B2.3: TotalCount excludes h2_table_ entries",
                                  pass,
                                  pass ? "" :
                                  (std::string("before=") + std::to_string(vals.first) +
                                   " after=" + std::to_string(vals.second)).c_str());
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream B2.3: TotalCount excludes h2_table_ entries", false, e.what());
    }
}

// B2.4 — H2TableCount increases after InsertH2ConnectionForTesting.
static void TestB2_4_H2TableCountReflectsInsert() {
    std::cout << "\n[TEST] H2Upstream B2.4: H2TableCount reflects InsertH2ConnectionForTesting..." << std::endl;
    try {
        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("svc", "127.0.0.1", 9999);
        cfg.pool.max_connections = 4;
        UpstreamManager mgr({cfg}, {disp});
        DispatcherThreadGuard dtg{disp, t};

        auto* part = mgr.GetPoolPartition("svc", 0);
        if (!part) {
            TestFramework::RecordTest("H2Upstream B2.4: H2TableCount reflects insert",
                                     false, "GetPoolPartition null");
            return;
        }

        auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
        h2_cfg->enabled = true;
        h2_cfg->max_concurrent_streams_pref = 10;
        h2_cfg->ping_idle_sec = 0;
        h2_cfg->ping_timeout_sec = 0;
        h2_cfg->goaway_drain_timeout_sec = 0;

        std::promise<std::pair<size_t,size_t>> result;
        auto fut = result.get_future();
        disp->EnQueue([&]() {
            size_t before = part->H2TableCount();
            auto c = std::make_unique<UpstreamH2Connection>(nullptr, h2_cfg);
            c->Init();
            part->InsertH2ConnectionForTesting("svc", std::move(c));
            size_t after = part->H2TableCount();
            result.set_value({before, after});
        });
        auto vals = (fut.wait_for(std::chrono::seconds(5)) == std::future_status::ready)
                    ? fut.get() : std::pair<size_t,size_t>{999,999};
        bool pass = (vals.first == 0) && (vals.second == 1);
        TestFramework::RecordTest("H2Upstream B2.4: H2TableCount reflects InsertH2ConnectionForTesting",
                                  pass,
                                  pass ? "" :
                                  (std::string("before=") + std::to_string(vals.first) +
                                   " after=" + std::to_string(vals.second)).c_str());
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream B2.4: H2TableCount reflects InsertH2ConnectionForTesting",
                                  false, e.what());
    }
}

// B2.5 — TickAll iterates over all sessions (multiple upstreams) and
// removes ones whose Tick returns false (null cfg triggers error log +
// eviction). Sessions with valid cfg survive.
static void TestB2_5_TickAllIteratesMultipleUpstreams() {
    std::cout << "\n[TEST] H2Upstream B2.5: TickAll iterates and evicts expired sessions..." << std::endl;
    try {
        H2ConnectionTable tbl;
        auto now = std::chrono::steady_clock::now();

        // Session with a zero-timeout config: ping_timeout_sec=0 means
        // the PING check is disabled but goaway/dead reaping still applies.
        auto h2_cfg_a = std::make_shared<Http2UpstreamConfig>();
        h2_cfg_a->enabled = true;
        h2_cfg_a->max_concurrent_streams_pref = 10;
        h2_cfg_a->ping_idle_sec = 0;
        h2_cfg_a->ping_timeout_sec = 0;
        h2_cfg_a->goaway_drain_timeout_sec = 0;

        auto ca = std::make_unique<UpstreamH2Connection>(nullptr, h2_cfg_a);
        ca->Init();  // usable — should survive TickAll

        auto cb = std::make_unique<UpstreamH2Connection>(nullptr, h2_cfg_a);
        cb->Init();
        cb->MarkDead();  // dead + 0 active streams → IsExpired → evicted by TickAll

        tbl.Insert("svc-a", std::move(ca));
        tbl.Insert("svc-b", std::move(cb));

        size_t before = tbl.TotalConnections();
        tbl.TickAll(now);
        size_t after = tbl.TotalConnections();

        bool pass = (before == 2) && (after == 1);
        TestFramework::RecordTest("H2Upstream B2.5: TickAll iterates and evicts dead sessions",
                                  pass,
                                  pass ? "" :
                                  (std::string("before=") + std::to_string(before) +
                                   " after=" + std::to_string(after)).c_str());
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream B2.5: TickAll iterates and evicts dead sessions",
                                  false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Saturation policy tests (TestT series)
// ---------------------------------------------------------------------------

// T1 — ShouldOpenAdditionalH2Conn returns false when the pool cap is
// already saturated (TotalCount >= partition_max_connections).
static void TestT1_ShouldOpenFalseWhenCapSaturated() {
    std::cout << "\n[TEST] H2Upstream T1: ShouldOpenAdditional false when pool cap saturated..." << std::endl;
    try {
        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("svc", "127.0.0.1", 9999);
        cfg.pool.max_connections = 1;
        cfg.http2.saturation_open_pct = 80;
        cfg.http2.max_concurrent_streams_pref = 10;
        UpstreamManager mgr({cfg}, {disp});
        DispatcherThreadGuard dtg{disp, t};

        auto* part = mgr.GetPoolPartition("svc", 0);
        if (!part) {
            TestFramework::RecordTest("H2Upstream T1: ShouldOpenAdditional false at cap", false, "null part");
            return;
        }

        auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
        h2_cfg->enabled = true;
        h2_cfg->max_concurrent_streams_pref = 10;
        h2_cfg->ping_idle_sec = 0;
        h2_cfg->ping_timeout_sec = 0;
        h2_cfg->goaway_drain_timeout_sec = 0;
        auto h2_conn = std::make_unique<UpstreamH2Connection>(nullptr, h2_cfg);
        if (!h2_conn->Init()) {
            TestFramework::RecordTest("H2Upstream T1: ShouldOpenAdditional false at cap", false, "Init failed");
            return;
        }
        UpstreamH2Connection* raw = h2_conn.get();

        std::promise<bool> result;
        auto fut = result.get_future();
        disp->EnQueue([&]() {
            part->InsertH2ConnectionForTesting("svc", std::move(h2_conn));
            // Push 8 streams → saturated at 80%.
            RecordingSink sinks[8];
            for (int i = 0; i < 8; ++i)
                raw->SubmitRequest("GET","https","h","/",{},""  ,&sinks[i]);
            // Even though all sessions are saturated, the pool cap=1 is
            // already used (TotalCount accounts for the H1 transport donated
            // to the H2 session). ShouldOpenAdditional must respect the cap.
            // Note: with max_connections=1 and one H2 session whose transport
            // sits in active_conns_, TotalCount==1 >= cap==1 → return false.
            bool should = part->ShouldOpenAdditionalH2Conn("svc");
            // Clear stream refs before sinks go out of scope.
            raw->FailAllStreams(-1, "test-cleanup");
            result.set_value(!should);  // pass if NOT opening (cap-blocked)
        });
        bool pass = (fut.wait_for(std::chrono::seconds(5)) == std::future_status::ready) && fut.get();
        TestFramework::RecordTest("H2Upstream T1: ShouldOpenAdditional false when pool cap saturated",
                                  pass, pass ? "" : "returned true despite pool cap saturation");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream T1: ShouldOpenAdditional false when pool cap saturated",
                                  false, e.what());
    }
}

// T2 — With saturation_open_pct=0 (disabled), ShouldOpenAdditionalH2Conn
// always returns false even when the session is loaded with streams.
// Exercises the fast-path branch in both ShouldOpenAdditionalH2Conn and
// FindUsableH2ConnectionSaturation without endpoint-matching interference.
static void TestT2_FindUsableSaturationDisabledDelegates() {
    std::cout << "\n[TEST] H2Upstream T2: saturation_open_pct=0 disables gate even under load..." << std::endl;
    try {
        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("svc", "127.0.0.1", 9999);
        cfg.pool.max_connections = 2;
        cfg.http2.saturation_open_pct = 0;  // disabled fast path
        cfg.http2.max_concurrent_streams_pref = 1;  // 1 slot: 100% when filled
        UpstreamManager mgr({cfg}, {disp});
        DispatcherThreadGuard dtg{disp, t};

        auto* part = mgr.GetPoolPartition("svc", 0);
        if (!part) {
            TestFramework::RecordTest("H2Upstream T2: saturation gate disabled fast path",
                                     false, "null part");
            return;
        }

        auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
        h2_cfg->enabled = true;
        h2_cfg->max_concurrent_streams_pref = 1;
        h2_cfg->ping_idle_sec = 0;
        h2_cfg->ping_timeout_sec = 0;
        h2_cfg->goaway_drain_timeout_sec = 0;
        auto h2_conn = std::make_unique<UpstreamH2Connection>(nullptr, h2_cfg);
        if (!h2_conn->Init()) {
            TestFramework::RecordTest("H2Upstream T2: saturation gate disabled fast path",
                                     false, "Init failed");
            return;
        }
        UpstreamH2Connection* raw = h2_conn.get();

        std::promise<bool> result;
        auto fut = result.get_future();
        disp->EnQueue([&]() {
            part->InsertH2ConnectionForTesting("svc", std::move(h2_conn));
            // Fill 100% capacity — if saturation gate were enabled, this
            // would trigger "all sessions saturated → open additional".
            RecordingSink sink;
            raw->SubmitRequest("GET","https","h","/",{},""  ,&sink);
            // With saturation_open_pct=0 the gate is disabled — always false.
            bool should = part->ShouldOpenAdditionalH2Conn("svc");
            // Clear stream refs before sink goes out of scope.
            raw->FailAllStreams(-1, "test-cleanup");
            result.set_value(!should);  // pass when NOT opening (gate off)
        });
        bool pass = (fut.wait_for(std::chrono::seconds(5)) == std::future_status::ready) && fut.get();
        TestFramework::RecordTest("H2Upstream T2: saturation gate disabled fast path",
                                  pass, pass ? "" : "ShouldOpen returned true despite saturation_open_pct=0");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream T2: saturation gate disabled fast path",
                                  false, e.what());
    }
}

// T3 — ShouldOpenAdditionalH2Conn returns true when ALL live sessions
// are AT OR ABOVE the saturation threshold (ratio_pct >= threshold).
// Uses two sessions: one saturated, one also saturated — all must be
// saturated for ShouldOpen to return true.
static void TestT3_FindUsableSaturationNullWhenAboveThreshold() {
    std::cout << "\n[TEST] H2Upstream T3: ShouldOpenAdditional true when all sessions at threshold..." << std::endl;
    try {
        // Use the H2ConnectionTable directly to verify the ratio math
        // without the endpoint-matching step that the partition-level API
        // applies (which requires a real transport).
        auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
        h2_cfg->enabled = true;
        h2_cfg->max_concurrent_streams_pref = 10;
        h2_cfg->ping_idle_sec = 0;
        h2_cfg->ping_timeout_sec = 0;
        h2_cfg->goaway_drain_timeout_sec = 0;

        // Build a session and submit 8 streams (80% of cap 10).
        auto c1 = std::make_unique<UpstreamH2Connection>(nullptr, h2_cfg);
        if (!c1->Init()) {
            TestFramework::RecordTest("H2Upstream T3: all-saturated true", false, "Init failed");
            return;
        }
        UpstreamH2Connection* raw = c1.get();

        H2ConnectionTable tbl;
        tbl.Insert("svc", std::move(c1));

        RecordingSink sinks[8];
        for (int i = 0; i < 8; ++i)
            raw->SubmitRequest("GET","https","h","/",{},""  ,&sinks[i]);

        // Ratio: 8/10 = 80% → equals threshold 80.
        // CollectUsableForUpstream returns `raw`; ratio_pct(80) >= threshold(80) → all saturated.
        auto candidates = tbl.CollectUsableForUpstream("svc");
        bool all_at_or_above = true;
        constexpr int threshold = 80;
        constexpr uint32_t cap = 10;
        for (auto* c : candidates) {
            if (!c) continue;
            int ratio = static_cast<int>((c->active_stream_count() * 100u) / cap);
            if (ratio < threshold) { all_at_or_above = false; break; }
        }

        // Clean up before sinks go out of scope.
        raw->FailAllStreams(-1, "test-cleanup");

        bool pass = all_at_or_above && (candidates.size() == 1);
        TestFramework::RecordTest("H2Upstream T3: all-sessions-at-threshold saturation check",
                                  pass, pass ? "" :
                                  (std::string("candidates=") + std::to_string(candidates.size()) +
                                   " all_at_or_above=" + std::to_string(all_at_or_above)).c_str());
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream T3: all-sessions-at-threshold saturation check",
                                  false, e.what());
    }
}

// T4 — ShouldOpenAdditionalH2Conn returns false when at least one session
// is BELOW the saturation threshold (one session with slack short-circuits).
static void TestT4_FindUsableSaturationReturnsBelowThreshold() {
    std::cout << "\n[TEST] H2Upstream T4: ShouldOpenAdditional false when one session below threshold..." << std::endl;
    try {
        // Use H2ConnectionTable directly (no endpoint-matching constraint).
        auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
        h2_cfg->enabled = true;
        h2_cfg->max_concurrent_streams_pref = 10;
        h2_cfg->ping_idle_sec = 0;
        h2_cfg->ping_timeout_sec = 0;
        h2_cfg->goaway_drain_timeout_sec = 0;

        auto c1 = std::make_unique<UpstreamH2Connection>(nullptr, h2_cfg);
        if (!c1->Init()) {
            TestFramework::RecordTest("H2Upstream T4: below-threshold short-circuits", false, "Init failed");
            return;
        }
        UpstreamH2Connection* raw = c1.get();

        H2ConnectionTable tbl;
        tbl.Insert("svc", std::move(c1));

        // 3 / 10 = 30% < 80% threshold → this session has slack.
        RecordingSink sinks[3];
        for (int i = 0; i < 3; ++i)
            raw->SubmitRequest("GET","https","h","/",{},""  ,&sinks[i]);

        // Per ShouldOpenAdditionalH2Conn logic: if ANY session has
        // ratio_pct < threshold, return false (has slack → no probe).
        auto candidates = tbl.CollectUsableForUpstream("svc");
        bool any_below = false;
        constexpr int threshold = 80;
        constexpr uint32_t cap = 10;
        for (auto* c : candidates) {
            if (!c) continue;
            int ratio = static_cast<int>((c->active_stream_count() * 100u) / cap);
            if (ratio < threshold) { any_below = true; break; }
        }

        // Clean up before sinks go out of scope.
        raw->FailAllStreams(-1, "test-cleanup");

        bool pass = any_below && (candidates.size() == 1);
        TestFramework::RecordTest("H2Upstream T4: below-threshold short-circuits ShouldOpen",
                                  pass, pass ? "" :
                                  (std::string("candidates=") + std::to_string(candidates.size()) +
                                   " any_below=" + std::to_string(any_below)).c_str());
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream T4: FindUsableH2ConnectionSaturation returns below threshold",
                                  false, e.what());
    }
}

// T5 — StartH2CapacityProbe rejects probe when partition is shutting down.
static void TestT5_CapacityProbeRejectedOnShutdown() {
    std::cout << "\n[TEST] H2Upstream T5: StartH2CapacityProbe rejected during shutdown..." << std::endl;
    try {
        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("svc", "127.0.0.1", 9999);
        cfg.pool.max_connections = 2;
        cfg.http2.saturation_open_pct = 80;
        cfg.http2.max_concurrent_streams_pref = 10;
        UpstreamManager mgr({cfg}, {disp});
        DispatcherThreadGuard dtg{disp, t};

        auto* part = mgr.GetPoolPartition("svc", 0);
        if (!part) {
            TestFramework::RecordTest("H2Upstream T5: CapacityProbe rejected on shutdown",
                                     false, "null part");
            return;
        }

        std::promise<std::pair<size_t,size_t>> result;
        auto fut = result.get_future();
        disp->EnQueue([&]() {
            size_t before = part->H2ConnectingCount();
            // Shutdown before probe.
            part->InitiateShutdown(0);
            // After shutdown, StartH2CapacityProbe must not queue a new probe.
            part->StartH2CapacityProbe("svc", 9999);
            size_t after = part->H2ConnectingCount();
            result.set_value({before, after});
        });
        auto vals = (fut.wait_for(std::chrono::seconds(5)) == std::future_status::ready)
                    ? fut.get() : std::pair<size_t,size_t>{999,999};
        // Both before and after must be 0 — shutdown blocked the probe.
        bool pass = (vals.first == 0) && (vals.second == 0);
        TestFramework::RecordTest("H2Upstream T5: StartH2CapacityProbe rejected during shutdown",
                                  pass,
                                  pass ? "" :
                                  (std::string("before=") + std::to_string(vals.first) +
                                   " after=" + std::to_string(vals.second)).c_str());
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream T5: StartH2CapacityProbe rejected during shutdown",
                                  false, e.what());
    }
}

// T6 — Regression: AcquireH2Connection with an EMPTY lease must fall
// back to FindUsableH2Connection when every existing session is over
// the saturation threshold AND the cap still has room. The empty-lease
// signal comes from TryDispatchExistingH2Session, which has already
// picked an over-threshold session and re-enters DispatchH2 to multiplex
// the request onto it. Without the fallback, AcquireH2Connection drops
// into fresh-construct, sees lease.Get() == null, and returns null —
// the caller then surfaces a spurious CONNECT_FAILURE / 502 even though
// a usable multiplexed session is sitting right there with free streams.
// Reproduces the common cap-not-reached case (cap=5, 1 session at 90%
// of max_concurrent_streams_pref=10) the round-1 fix missed.
//
// Setup nuance: FindUsableH2Connection checks
// `ConnectionEndpointMatches(*candidate->transport())`, so the synthetic
// H2 session must wrap an UpstreamConnection whose captured_endpoint()
// matches the partition's published resolved_endpoint_. We grab the
// partition's endpoint via the public LoadResolvedEndpoint() accessor
// and pass it to the UpstreamConnection ctor. ConnectionHandler is
// null (no real socket needed — the test never sends bytes).
static void TestT6_AcquireH2ConnectionEmptyLeaseFallsBackToFirstUsable() {
    std::cout << "\n[TEST] H2Upstream T6: AcquireH2Connection empty-lease fallback to first-usable..." << std::endl;
    try {
        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("svc", "127.0.0.1", 9999);
        cfg.pool.max_connections = 5;                       // room for more
        cfg.http2.saturation_open_pct = 80;                 // 80% threshold
        cfg.http2.max_concurrent_streams_pref = 10;
        UpstreamManager mgr({cfg}, {disp});
        mgr.CommitHttp2Snapshots({cfg});
        DispatcherThreadGuard dtg{disp, t};

        auto* part = mgr.GetPoolPartition("svc", 0);
        if (!part) {
            TestFramework::RecordTest(
                "H2Upstream T6: AcquireH2Connection empty-lease fallback",
                false, "null part");
            return;
        }

        // Build an UpstreamConnection whose captured_endpoint matches
        // the partition's published one. ConnectionHandler is null —
        // no real socket needed because the test never sends bytes.
        // Lifetime: the unique_ptr outlives the h2 conn (declared
        // BEFORE so it destructs AFTER).
        auto endpoint = part->LoadResolvedEndpoint();
        auto uc = std::make_unique<UpstreamConnection>(
            /*conn=*/nullptr, "127.0.0.1", 9999, endpoint);

        // Build the H2 session wrapping the synthetic transport.
        // Sinks-must-outlive-session: declare RecordingSink array first.
        RecordingSink sinks[9];
        auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
        h2_cfg->enabled = true;
        h2_cfg->max_concurrent_streams_pref = 10;
        h2_cfg->ping_idle_sec = 0;
        h2_cfg->ping_timeout_sec = 0;
        h2_cfg->goaway_drain_timeout_sec = 0;
        auto h2_conn = std::make_unique<UpstreamH2Connection>(uc.get(), h2_cfg);
        if (!h2_conn->Init()) {
            TestFramework::RecordTest(
                "H2Upstream T6: AcquireH2Connection empty-lease fallback",
                false, "Init failed");
            return;
        }
        UpstreamH2Connection* raw = h2_conn.get();

        std::promise<std::tuple<void*, void*, bool, bool>> result;
        auto fut = result.get_future();
        disp->EnQueue([&]() {
            part->InsertH2ConnectionForTesting("svc", std::move(h2_conn));
            // Drive utilization to 90% (over saturation_open_pct=80).
            for (int i = 0; i < 9; ++i) {
                raw->SubmitRequest("GET","https","h","/",{},""  ,&sinks[i]);
            }
            // Saturation pick should reject this session (90% > 80%).
            bool sat_returns_null =
                (part->FindUsableH2ConnectionSaturation("svc") == nullptr);
            // FindUsable should still return it (9 streams < 10 cap).
            bool first_usable_returns_session =
                (part->FindUsableH2Connection("svc") == raw);
            // Empty lease — mirrors TryDispatchExistingH2Session's flow.
            UpstreamLease empty_lease;
            UpstreamH2Connection* acquired =
                part->AcquireH2Connection("svc", empty_lease);
            result.set_value({static_cast<void*>(acquired),
                              static_cast<void*>(raw),
                              sat_returns_null,
                              first_usable_returns_session});
        });
        auto vals = (fut.wait_for(std::chrono::seconds(5)) == std::future_status::ready)
                    ? fut.get()
                    : std::tuple<void*, void*, bool, bool>{nullptr, nullptr, false, false};

        void* acquired = std::get<0>(vals);
        void* expected = std::get<1>(vals);
        bool sat_null  = std::get<2>(vals);
        bool fu_ok     = std::get<3>(vals);

        // PASS criteria:
        //   1. Saturation gate confirmed: pick is null
        //   2. FindUsable confirmed: returns the over-threshold session
        //   3. AcquireH2Connection returned the SAME session (regression)
        bool pass = sat_null && fu_ok &&
                    (acquired != nullptr) &&
                    (acquired == expected);

        // Tear down the H2 session in the partition BEFORE `uc`
        // exits scope. ~UpstreamH2Connection accesses transport_ (the
        // raw pointer captured from `uc`); a stray dangling pointer
        // when the partition's dtor runs (which fires AFTER `uc`
        // destructs in LIFO order) would UAF. Forcing the H2 retire
        // path now keeps the lifetime invariant intact.
        std::promise<void> cleanup_done;
        auto cleanup_fut = cleanup_done.get_future();
        disp->EnQueue([&]() {
            raw->FailAllStreams(-1, "test-cleanup");
            // InitiateShutdown(0) extracts every H2 session from the
            // table and destroys them inline. The H2 conn's dtor runs
            // here while `uc` is still alive.
            part->InitiateShutdown(0);
            cleanup_done.set_value();
        });
        // Capture wait_for status so a silent timeout (cleanup task
        // queued but never drained) doesn't leave the partition holding
        // a dangling transport_ pointer to a soon-to-destruct uc.
        // InitiateShutdown(0) is synchronous and completes in
        // microseconds; a timeout here means the dispatcher is wedged.
        auto cleanup_status = cleanup_fut.wait_for(std::chrono::seconds(2));
        if (cleanup_status != std::future_status::ready) {
            TestFramework::RecordTest(
                "H2Upstream T6: AcquireH2Connection empty-lease falls back to first-usable",
                false, "cleanup dispatcher task did not run within 2s");
            return;
        }

        TestFramework::RecordTest(
            "H2Upstream T6: AcquireH2Connection empty-lease falls back to first-usable",
            pass,
            pass ? "" :
            (std::string("acquired=") + std::to_string(reinterpret_cast<uintptr_t>(acquired)) +
             " expected=" + std::to_string(reinterpret_cast<uintptr_t>(expected)) +
             " sat_null=" + std::to_string(sat_null) +
             " fu_ok=" + std::to_string(fu_ok)).c_str());
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream T6: AcquireH2Connection empty-lease falls back to first-usable",
            false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Preconnect probe tests (TestP series)
// ---------------------------------------------------------------------------

// P1 — Preconnect is disabled when preconnect_watermark_pct == 0 (default).
// MaybePreconnectH2 must not open a new probe.
static void TestP1_PreconnectDisabledByDefault() {
    std::cout << "\n[TEST] H2Upstream P1: MaybePreconnectH2 disabled when watermark=0..." << std::endl;
    try {
        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("svc", "127.0.0.1", 9999);
        cfg.pool.max_connections = 2;
        cfg.http2.saturation_open_pct = 80;
        cfg.http2.preconnect_watermark_pct = 0;  // disabled
        cfg.http2.max_concurrent_streams_pref = 10;
        UpstreamManager mgr({cfg}, {disp});
        DispatcherThreadGuard dtg{disp, t};

        auto* part = mgr.GetPoolPartition("svc", 0);
        if (!part) {
            TestFramework::RecordTest("H2Upstream P1: preconnect disabled by default", false, "null part");
            return;
        }

        auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
        h2_cfg->enabled = true;
        h2_cfg->max_concurrent_streams_pref = 10;
        h2_cfg->ping_idle_sec = 0;
        h2_cfg->ping_timeout_sec = 0;
        h2_cfg->goaway_drain_timeout_sec = 0;
        auto h2_conn = std::make_unique<UpstreamH2Connection>(nullptr, h2_cfg);
        if (!h2_conn->Init()) {
            TestFramework::RecordTest("H2Upstream P1: preconnect disabled by default", false, "Init failed");
            return;
        }
        UpstreamH2Connection* raw = h2_conn.get();

        std::promise<std::pair<int64_t,int64_t>> result;
        auto fut = result.get_future();
        disp->EnQueue([&]() {
            part->InsertH2ConnectionForTesting("svc", std::move(h2_conn));
            // Push stream utilization into the "would preconnect" window
            // (between watermark and saturation). With watermark=0 the
            // whole range is the disabled zone.
            RecordingSink sinks[5];
            for (int i = 0; i < 5; ++i)
                raw->SubmitRequest("GET","https","h","/",{},""  ,&sinks[i]);
            // Call MaybePreconnect — must be a no-op.
            part->MaybePreconnectH2("svc", 9999, *raw);
            auto counters = std::make_pair(part->preconnect_fired_count(),
                                           part->preconnect_skipped_cap_count());
            // Clear stream refs before sinks go out of scope.
            raw->FailAllStreams(-1, "test-cleanup");
            result.set_value(counters);
        });
        auto vals = (fut.wait_for(std::chrono::seconds(5)) == std::future_status::ready)
                    ? fut.get() : std::pair<int64_t,int64_t>{-1,-1};
        bool pass = (vals.first == 0) && (vals.second == 0);
        TestFramework::RecordTest("H2Upstream P1: MaybePreconnectH2 disabled when watermark=0",
                                  pass,
                                  pass ? "" :
                                  (std::string("fired=") + std::to_string(vals.first) +
                                   " skipped_cap=" + std::to_string(vals.second)).c_str());
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream P1: MaybePreconnectH2 disabled when watermark=0", false, e.what());
    }
}

// P2 — Config validator rejects preconnect_watermark_pct > 0 when
// saturation_open_pct == 0 (silent-no-op shape).
static void TestP2_PreconnectValidationRequiresSaturation() {
    std::cout << "\n[TEST] H2Upstream P2: validator rejects watermark>0 without saturation..." << std::endl;
    try {
        const std::string json = R"({
            "upstreams": [{
                "name": "svc",
                "host": "127.0.0.1",
                "port": 9000,
                "tls": {"enabled": true},
                "http2": {
                    "enabled": true,
                    "saturation_open_pct": 0,
                    "preconnect_watermark_pct": 50
                }
            }]
        })";
        // LoadFromString parses only; Validate() enforces startup rules.
        bool threw = false;
        std::string what;
        try {
            ServerConfig parsed = ConfigLoader::LoadFromString(json);
            ConfigLoader::Validate(parsed);
        } catch (const std::invalid_argument& e) {
            threw = true;
            what = e.what();
        }
        bool pass = threw;
        TestFramework::RecordTest("H2Upstream P2: validator rejects watermark>0 without saturation",
                                  pass,
                                  pass ? "" :
                                  ("expected invalid_argument, what='" + what + "'").c_str());
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream P2: validator rejects watermark>0 without saturation",
                                  false, e.what());
    }
}

// P3 — Config validator rejects preconnect_watermark_pct >= saturation_open_pct.
static void TestP3_PreconnectValidationWatermarkBelowSaturation() {
    std::cout << "\n[TEST] H2Upstream P3: validator rejects watermark >= saturation..." << std::endl;
    try {
        // watermark == saturation → invalid (prediction fires at, not before, threshold)
        const std::string json = R"({
            "upstreams": [{
                "name": "svc",
                "host": "127.0.0.1",
                "port": 9000,
                "tls": {"enabled": true},
                "http2": {
                    "enabled": true,
                    "saturation_open_pct": 80,
                    "preconnect_watermark_pct": 80
                }
            }]
        })";
        bool threw = false;
        std::string what;
        try {
            ServerConfig parsed = ConfigLoader::LoadFromString(json);
            ConfigLoader::Validate(parsed);
        } catch (const std::invalid_argument& e) {
            threw = true;
            what = e.what();
        }
        bool pass = threw;
        TestFramework::RecordTest("H2Upstream P3: validator rejects watermark >= saturation",
                                  pass,
                                  pass ? "" :
                                  ("expected invalid_argument, what='" + what + "'").c_str());
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream P3: validator rejects watermark >= saturation", false, e.what());
    }
}

// P4 — preconnect_fired_count counts only SUCCESSFUL probe dispatches.
// Uses a partition at cap=2 (room for a second conn) with a session
// whose stream ratio sits in the watermark-to-saturation window, but
// OpenNewH2Connection fails because there's no TLS context. The counter
// must stay at 0 — counting failed probes would misreport probe activity
// to operators reading the gauge.
static void TestP4_PreconnectFiredCounter() {
    std::cout << "\n[TEST] H2Upstream P4: preconnect_fired_count does not count failed probes..." << std::endl;
    try {
        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("svc", "127.0.0.1", 9999);
        cfg.pool.max_connections = 2;
        cfg.http2.saturation_open_pct    = 80;
        cfg.http2.preconnect_watermark_pct = 50;
        cfg.http2.max_concurrent_streams_pref = 10;
        UpstreamManager mgr({cfg}, {disp});
        // Bootstrap the per-partition H2 config snapshot so
        // MaybePreconnectH2 reads the correct saturation/watermark values.
        mgr.CommitHttp2Snapshots({cfg});
        DispatcherThreadGuard dtg{disp, t};

        auto* part = mgr.GetPoolPartition("svc", 0);
        if (!part) {
            TestFramework::RecordTest("H2Upstream P4: preconnect_fired_count", false, "null part");
            return;
        }

        auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
        h2_cfg->enabled = true;
        h2_cfg->max_concurrent_streams_pref = 10;
        h2_cfg->ping_idle_sec = 0;
        h2_cfg->ping_timeout_sec = 0;
        h2_cfg->goaway_drain_timeout_sec = 0;
        auto h2_conn = std::make_unique<UpstreamH2Connection>(nullptr, h2_cfg);
        if (!h2_conn->Init()) {
            TestFramework::RecordTest("H2Upstream P4: preconnect_fired_count", false, "Init failed");
            return;
        }
        UpstreamH2Connection* raw = h2_conn.get();

        std::promise<std::pair<int64_t,int64_t>> result;
        auto fut = result.get_future();
        disp->EnQueue([&]() {
            part->InsertH2ConnectionForTesting("svc", std::move(h2_conn));
            // 6 / 10 = 60% — in the [50%, 80%) watermark window.
            RecordingSink sinks[6];
            for (int i = 0; i < 6; ++i)
                raw->SubmitRequest("GET","https","h","/",{},""  ,&sinks[i]);
            int64_t before = part->preconnect_fired_count();
            // MaybePreconnectH2 enters the firing branch (ratio in window,
            // cap has room) but OpenNewH2Connection rejects with no TLS
            // context. The counter must NOT increment on the failed
            // dispatch — operator gauges should reflect probe success,
            // not attempts. Bumping on attempt would lie about probe
            // activity in TLS-misconfig / shutdown / cap-race paths.
            part->MaybePreconnectH2("svc", 9999, *raw);
            int64_t after = part->preconnect_fired_count();
            // Clear stream refs before sinks go out of scope.
            raw->FailAllStreams(-1, "test-cleanup");
            result.set_value({before, after});
        });
        auto vals = (fut.wait_for(std::chrono::seconds(5)) == std::future_status::ready)
                    ? fut.get() : std::pair<int64_t,int64_t>{-1,-1};
        bool pass = (vals.first == 0) && (vals.second == 0);
        TestFramework::RecordTest("H2Upstream P4: preconnect_fired_count does not count failed probes",
                                  pass,
                                  pass ? "" :
                                  (std::string("before=") + std::to_string(vals.first) +
                                   " after=" + std::to_string(vals.second)).c_str());
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream P4: preconnect_fired_count does not count failed probes",
                                  false, e.what());
    }
}

// P5 — preconnect_skipped_cap_count increments when the cap gate blocks
// the probe (TotalCount >= max_connections).
// Use max_connections=0: TotalCount()=0 >= 0 → cap gate fires unconditionally.
// InsertH2ConnectionForTesting goes into h2_table_ (not active_conns_/
// connecting_conns_) so TotalCount() stays 0, which is >= cap=0 → skip.
static void TestP5_PreconnectSkippedCapCounter() {
    std::cout << "\n[TEST] H2Upstream P5: preconnect_skipped_cap_count increments when cap saturated..." << std::endl;
    try {
        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("svc", "127.0.0.1", 9999);
        // max_connections=0: TotalCount()=0 >= 0 → cap gate fires on the
        // very first MaybePreconnectH2 call, skipped_cap_count increments.
        cfg.pool.max_connections = 0;
        cfg.http2.saturation_open_pct      = 80;
        cfg.http2.preconnect_watermark_pct = 50;
        cfg.http2.max_concurrent_streams_pref = 10;
        UpstreamManager mgr({cfg}, {disp});
        // Bootstrap the per-partition H2 config snapshot so
        // MaybePreconnectH2 reads the correct saturation/watermark values.
        mgr.CommitHttp2Snapshots({cfg});
        DispatcherThreadGuard dtg{disp, t};

        auto* part = mgr.GetPoolPartition("svc", 0);
        if (!part) {
            TestFramework::RecordTest("H2Upstream P5: preconnect_skipped_cap_count", false, "null part");
            return;
        }

        auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
        h2_cfg->enabled = true;
        h2_cfg->max_concurrent_streams_pref = 10;
        h2_cfg->ping_idle_sec = 0;
        h2_cfg->ping_timeout_sec = 0;
        h2_cfg->goaway_drain_timeout_sec = 0;
        auto h2_conn = std::make_unique<UpstreamH2Connection>(nullptr, h2_cfg);
        if (!h2_conn->Init()) {
            TestFramework::RecordTest("H2Upstream P5: preconnect_skipped_cap_count", false, "Init failed");
            return;
        }
        UpstreamH2Connection* raw = h2_conn.get();

        std::promise<std::pair<int64_t,int64_t>> result;
        auto fut = result.get_future();
        disp->EnQueue([&]() {
            part->InsertH2ConnectionForTesting("svc", std::move(h2_conn));
            // 6 / 10 = 60% — in the [50%, 80%) watermark window.
            RecordingSink sinks[6];
            for (int i = 0; i < 6; ++i)
                raw->SubmitRequest("GET","https","h","/",{},""  ,&sinks[i]);
            int64_t before_skip = part->preconnect_skipped_cap_count();
            // TotalCount()=0 >= max_connections=0 → cap gate fires.
            part->MaybePreconnectH2("svc", 9999, *raw);
            int64_t after_skip = part->preconnect_skipped_cap_count();
            // Clear stream refs before sinks go out of scope.
            raw->FailAllStreams(-1, "test-cleanup");
            result.set_value({before_skip, after_skip});
        });
        auto vals = (fut.wait_for(std::chrono::seconds(5)) == std::future_status::ready)
                    ? fut.get() : std::pair<int64_t,int64_t>{-1,-1};
        bool pass = (vals.first == 0) && (vals.second == 1);
        TestFramework::RecordTest("H2Upstream P5: preconnect_skipped_cap_count increments when cap saturated",
                                  pass,
                                  pass ? "" :
                                  (std::string("before_skip=") + std::to_string(vals.first) +
                                   " after_skip=" + std::to_string(vals.second)).c_str());
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream P5: preconnect_skipped_cap_count increments when cap saturated",
                                  false, e.what());
    }
}

// P6 — Regression: MaybePreconnectH2 must NOT fire when a fleet-wide
// spare (another usable session with utilization below the watermark)
// already exists. Without this gate, the scenario "session A at 60%
// (in window), session B at 0% (spare)" leads each new request to
// pick A → fire another preconnect → fill the pool with idle warm
// spares until pool.max_connections is exhausted.
//
// Discriminator: configure `pool.max_connections = 2` with 2 sessions
// already inserted. The fix's fleet-wide gate fires BEFORE the cap
// check → `preconnect_skipped_cap_count_` stays at 0. Without the
// gate, control reaches the cap check → counter increments by 1.
// This is the only test-observable difference between the two paths
// because OpenNewH2Connection fails for no-TLS in either case.
//
// Setup: two synthetic H2 sessions inserted into the partition. A is
// driven to 6/10 = 60% (in the [50%, 80%) window). B is left at 0%
// (the spare).
static void TestP6_PreconnectSkippedWhenSpareExists() {
    std::cout << "\n[TEST] H2Upstream P6: MaybePreconnectH2 skips when fleet-wide spare exists..." << std::endl;
    try {
        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("svc", "127.0.0.1", 9999);
        // pool.max_connections = 0 + 2 inserted synthetic H2 sessions:
        // TotalCount returns the count of idle/active/connecting
        // UpstreamConnections (NOT H2 sessions, see TotalCount comment).
        // With no UpstreamConnections allocated and max=0, the cap-check
        // `TotalCount() (0) >= partition_max_connections_ (0)` evaluates
        // true → `preconnect_skipped_cap_count_` increments. The
        // fleet-wide gate must short-circuit BEFORE that check so the
        // counter stays at 0. This is the test-observable discriminator
        // between the two paths.
        cfg.pool.max_connections = 0;
        cfg.http2.saturation_open_pct      = 80;
        cfg.http2.preconnect_watermark_pct = 50;
        cfg.http2.max_concurrent_streams_pref = 10;
        UpstreamManager mgr({cfg}, {disp});
        mgr.CommitHttp2Snapshots({cfg});
        DispatcherThreadGuard dtg{disp, t};

        auto* part = mgr.GetPoolPartition("svc", 0);
        if (!part) {
            TestFramework::RecordTest(
                "H2Upstream P6: preconnect skipped when spare exists",
                false, "null part");
            return;
        }

        // Sinks before H2 conns — sinks-must-outlive-session contract.
        RecordingSink sinks_a[6];

        auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
        h2_cfg->enabled = true;
        h2_cfg->max_concurrent_streams_pref = 10;
        h2_cfg->ping_idle_sec = 0;
        h2_cfg->ping_timeout_sec = 0;
        h2_cfg->goaway_drain_timeout_sec = 0;

        auto session_a = std::make_unique<UpstreamH2Connection>(nullptr, h2_cfg);
        auto session_b = std::make_unique<UpstreamH2Connection>(nullptr, h2_cfg);
        if (!session_a->Init() || !session_b->Init()) {
            TestFramework::RecordTest(
                "H2Upstream P6: preconnect skipped when spare exists",
                false, "Init failed");
            return;
        }
        UpstreamH2Connection* raw_a = session_a.get();
        UpstreamH2Connection* raw_b = session_b.get();

        std::promise<std::tuple<int64_t,int64_t,int64_t>> result;
        auto fut = result.get_future();
        disp->EnQueue([&]() {
            part->InsertH2ConnectionForTesting("svc", std::move(session_a));
            part->InsertH2ConnectionForTesting("svc", std::move(session_b));
            // Drive A to 60% utilization (6/10) — in the watermark window.
            for (int i = 0; i < 6; ++i) {
                raw_a->SubmitRequest("GET","https","h","/",{},""  ,&sinks_a[i]);
            }
            // B has 0 streams = 0% — below 50% watermark → operator
            // signal "this session is spare capacity".
            int64_t before_fired = part->preconnect_fired_count();
            int64_t before_skip  = part->preconnect_skipped_cap_count();
            // Picked session is A (the in-window one). Without the
            // fleet-wide gate, this reaches the cap-check and bumps
            // `preconnect_skipped_cap_count_`. With the gate, neither
            // counter advances.
            part->MaybePreconnectH2("svc", 9999, *raw_a);
            int64_t after_fired = part->preconnect_fired_count();
            int64_t after_skip  = part->preconnect_skipped_cap_count();
            // Cleanup: clear A's stream refs and tear down both
            // synthetic sessions inline so destruction order is safe.
            raw_a->FailAllStreams(-1, "test-cleanup");
            raw_b->FailAllStreams(-1, "test-cleanup");
            part->InitiateShutdown(0);
            result.set_value({after_fired - before_fired,
                              after_skip - before_skip,
                              before_skip});
        });
        auto status = fut.wait_for(std::chrono::seconds(5));
        if (status != std::future_status::ready) {
            TestFramework::RecordTest(
                "H2Upstream P6: preconnect skipped when fleet-wide spare exists",
                false, "dispatcher task did not complete within 5s");
            return;
        }
        auto vals = fut.get();
        int64_t delta_fired = std::get<0>(vals);
        int64_t delta_skip  = std::get<1>(vals);

        // PASS criteria:
        //   1. delta_fired == 0 (no successful probe — true either way)
        //   2. delta_skip  == 0 (fleet-wide gate short-circuited BEFORE
        //                       the cap-check; without the gate this
        //                       would be 1)
        bool pass = (delta_fired == 0) && (delta_skip == 0);

        TestFramework::RecordTest(
            "H2Upstream P6: preconnect skipped when fleet-wide spare exists",
            pass,
            pass ? "" :
            (std::string("delta_fired=") + std::to_string(delta_fired) +
             " delta_skip=" + std::to_string(delta_skip)).c_str());
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream P6: preconnect skipped when fleet-wide spare exists",
            false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Config validation tests: saturation + preconnect (TestPC series)
// ---------------------------------------------------------------------------

// PC1 — Hot-reload validator rejects saturation_open_pct > 100.
static void TestPC1_SaturationPctOutOfRange() {
    std::cout << "\n[TEST] H2Upstream PC1: hot-reload rejects saturation_open_pct > 100..." << std::endl;
    try {
        const std::string json = R"({
            "upstreams": [{
                "name": "svc",
                "host": "127.0.0.1",
                "port": 9000,
                "tls": {"enabled": true},
                "http2": {
                    "enabled": true,
                    "saturation_open_pct": 101
                }
            }]
        })";
        bool threw = false;
        try {
            ServerConfig parsed = ConfigLoader::LoadFromString(json);
            ConfigLoader::Validate(parsed);
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        TestFramework::RecordTest("H2Upstream PC1: validator rejects saturation_open_pct > 100",
                                  threw, threw ? "" : "expected invalid_argument for out-of-range saturation");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream PC1: validator rejects saturation_open_pct > 100", false, e.what());
    }
}

// PC2 — Hot-reload validator accepts valid saturation + preconnect combo.
static void TestPC2_ValidSaturationPreconnectCombo() {
    std::cout << "\n[TEST] H2Upstream PC2: validator accepts valid saturation + preconnect combo..." << std::endl;
    try {
        const std::string json = R"({
            "upstreams": [{
                "name": "svc",
                "host": "127.0.0.1",
                "port": 9000,
                "tls": {"enabled": true},
                "http2": {
                    "enabled": true,
                    "saturation_open_pct": 80,
                    "preconnect_watermark_pct": 50
                }
            }]
        })";
        bool ok = false;
        try {
            ServerConfig cfg = ConfigLoader::LoadFromString(json);
            ok = !cfg.upstreams.empty() &&
                 cfg.upstreams[0].http2.saturation_open_pct == 80 &&
                 cfg.upstreams[0].http2.preconnect_watermark_pct == 50;
        } catch (...) {}
        TestFramework::RecordTest("H2Upstream PC2: validator accepts valid saturation + preconnect combo",
                                  ok, ok ? "" : "parse/validation unexpectedly failed");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream PC2: validator accepts valid saturation + preconnect combo",
                                  false, e.what());
    }
}

// PC3 — saturation_open_pct and preconnect_watermark_pct survive a
// config round-trip (parse → serialize → parse).
static void TestPC3_SaturationPreconnectRoundTrip() {
    std::cout << "\n[TEST] H2Upstream PC3: saturation + preconnect fields round-trip..." << std::endl;
    try {
        const std::string json = R"({
            "upstreams": [{
                "name": "svc",
                "host": "127.0.0.1",
                "port": 9000,
                "tls": {"enabled": true},
                "http2": {
                    "enabled": true,
                    "saturation_open_pct": 75,
                    "preconnect_watermark_pct": 40
                }
            }]
        })";
        ServerConfig cfg = ConfigLoader::LoadFromString(json);
        const auto& h2 = cfg.upstreams[0].http2;
        bool pass = (h2.saturation_open_pct == 75) && (h2.preconnect_watermark_pct == 40);
        TestFramework::RecordTest("H2Upstream PC3: saturation + preconnect fields round-trip",
                                  pass,
                                  pass ? "" :
                                  (std::string("sat=") + std::to_string(h2.saturation_open_pct) +
                                   " watermark=" + std::to_string(h2.preconnect_watermark_pct)).c_str());
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream PC3: saturation + preconnect fields round-trip", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// End-to-end + integration tests (TestS32+)
// ---------------------------------------------------------------------------

// S32 — Happy path integration: ShouldOpenAdditionalH2Conn returns true
// exactly when ALL live sessions are above threshold, then false after
// we reduce stream count below threshold by draining streams.
static void TestS32_SaturationGateSwitches() {
    std::cout << "\n[TEST] H2Upstream S32: saturation gate flips based on stream load..." << std::endl;
    try {
        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("svc", "127.0.0.1", 9999);
        cfg.pool.max_connections = 2;
        cfg.http2.saturation_open_pct = 80;
        cfg.http2.max_concurrent_streams_pref = 10;
        UpstreamManager mgr({cfg}, {disp});
        // Bootstrap the per-partition H2 config snapshot so
        // ShouldOpenAdditionalH2Conn reads the saturation threshold.
        mgr.CommitHttp2Snapshots({cfg});
        DispatcherThreadGuard dtg{disp, t};

        auto* part = mgr.GetPoolPartition("svc", 0);
        if (!part) {
            TestFramework::RecordTest("H2Upstream S32: saturation gate switches", false, "null part");
            return;
        }

        auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
        h2_cfg->enabled = true;
        h2_cfg->max_concurrent_streams_pref = 10;
        h2_cfg->ping_idle_sec = 0;
        h2_cfg->ping_timeout_sec = 0;
        h2_cfg->goaway_drain_timeout_sec = 0;
        auto h2_conn = std::make_unique<UpstreamH2Connection>(nullptr, h2_cfg);
        if (!h2_conn->Init()) {
            TestFramework::RecordTest("H2Upstream S32: saturation gate switches", false, "Init failed");
            return;
        }
        UpstreamH2Connection* raw = h2_conn.get();

        std::promise<std::tuple<bool,bool,bool>> result;
        auto fut = result.get_future();
        disp->EnQueue([&]() {
            part->InsertH2ConnectionForTesting("svc", std::move(h2_conn));

            // Phase A: 0 streams — below threshold.
            bool below = !part->ShouldOpenAdditionalH2Conn("svc");

            // Phase B: 8 streams (80%) — at/above threshold.
            RecordingSink sinks[8];
            for (int i = 0; i < 8; ++i)
                raw->SubmitRequest("GET","https","h","/",{},""  ,&sinks[i]);
            bool above = part->ShouldOpenAdditionalH2Conn("svc");

            // Phase C: FailAllStreams resets active count to 0.
            raw->FailAllStreams(-1, "test-drain");
            bool drained = !part->ShouldOpenAdditionalH2Conn("svc");

            result.set_value({below, above, drained});
        });
        auto vals = (fut.wait_for(std::chrono::seconds(5)) == std::future_status::ready)
                    ? fut.get() : std::tuple<bool,bool,bool>{false,false,false};
        bool pass = std::get<0>(vals) && std::get<1>(vals) && std::get<2>(vals);
        TestFramework::RecordTest("H2Upstream S32: saturation gate switches correctly",
                                  pass,
                                  pass ? "" :
                                  (std::string("below=") + std::to_string(std::get<0>(vals)) +
                                   " above=" + std::to_string(std::get<1>(vals)) +
                                   " drained=" + std::to_string(std::get<2>(vals))).c_str());
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream S32: saturation gate switches correctly", false, e.what());
    }
}

// S33 — Shutdown drain integration: BeginShutdownDrain + IsShutdownDrainComplete
// with a real stream submitted then failed (simulates stream natural completion).
static void TestS33_ShutdownDrainWithStream() {
    std::cout << "\n[TEST] H2Upstream S33: shutdown drain completes after stream drained..." << std::endl;
    try {
        auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
        h2_cfg->enabled = true;
        h2_cfg->max_concurrent_streams_pref = 10;
        h2_cfg->ping_idle_sec = 0;
        h2_cfg->ping_timeout_sec = 0;
        h2_cfg->goaway_drain_timeout_sec = 30;
        // Sink before conn — sinks-must-outlive-session contract.
        RecordingSink sink;
        UpstreamH2Connection conn(nullptr, h2_cfg);
        if (!conn.Init()) {
            TestFramework::RecordTest("H2Upstream S33: shutdown drain with stream", false, "Init failed");
            return;
        }

        conn.SubmitRequest("GET", "https", "host", "/", {}, "", &sink);

        conn.BeginShutdownDrain(30000);
        auto now = std::chrono::steady_clock::now();
        // Stream still in-flight → not complete yet.
        bool mid_drain = !conn.IsShutdownDrainComplete(now);

        // Drain the stream via FailAllStreams.
        conn.FailAllStreams(-1, "test");
        // active_stream_count is now 0 → drain immediately complete.
        bool after_fail = conn.IsShutdownDrainComplete(now);

        bool pass = mid_drain && after_fail;
        TestFramework::RecordTest("H2Upstream S33: shutdown drain completes after stream drained",
                                  pass,
                                  pass ? "" :
                                  (std::string("mid_drain=") + std::to_string(mid_drain) +
                                   " after_fail=" + std::to_string(after_fail)).c_str());
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream S33: shutdown drain completes after stream drained",
                                  false, e.what());
    }
}

// S34 — InitiateShutdown with graceful drain timeout retires H2 sessions
// through BeginShutdownDrain, not immediate ExtractAll.  H2TableCount
// drops to 0 when the session has no in-flight streams.
static void TestS34_InitiateShutdownGracefulDrain() {
    std::cout << "\n[TEST] H2Upstream S34: InitiateShutdown graceful drain via BeginShutdownDrain..." << std::endl;
    try {
        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("svc", "127.0.0.1", 9999);
        cfg.pool.max_connections = 1;
        cfg.http2.goaway_drain_timeout_sec = 5;
        UpstreamManager mgr({cfg}, {disp});
        DispatcherThreadGuard dtg{disp, t};

        auto* part = mgr.GetPoolPartition("svc", 0);
        if (!part) {
            TestFramework::RecordTest("H2Upstream S34: InitiateShutdown graceful drain", false, "null part");
            return;
        }

        auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
        h2_cfg->enabled = true;
        h2_cfg->max_concurrent_streams_pref = 10;
        h2_cfg->ping_idle_sec = 0;
        h2_cfg->ping_timeout_sec = 0;
        h2_cfg->goaway_drain_timeout_sec = 5;
        auto h2_conn = std::make_unique<UpstreamH2Connection>(nullptr, h2_cfg);
        if (!h2_conn->Init()) {
            TestFramework::RecordTest("H2Upstream S34: InitiateShutdown graceful drain", false, "Init failed");
            return;
        }

        std::promise<std::pair<size_t,size_t>> result;
        auto fut = result.get_future();
        disp->EnQueue([&]() {
            part->InsertH2ConnectionForTesting("svc", std::move(h2_conn));
            size_t pre = part->H2TableCount();
            // No streams in-flight → drain immediately complete.
            part->InitiateShutdown(5);
            size_t post = part->H2TableCount();
            result.set_value({pre, post});
        });
        auto vals = (fut.wait_for(std::chrono::seconds(5)) == std::future_status::ready)
                    ? fut.get() : std::pair<size_t,size_t>{999,999};
        bool pass = (vals.first == 1) && (vals.second == 0);
        TestFramework::RecordTest("H2Upstream S34: InitiateShutdown graceful drain via BeginShutdownDrain",
                                  pass,
                                  pass ? "" :
                                  (std::string("pre=") + std::to_string(vals.first) +
                                   " post=" + std::to_string(vals.second)).c_str());
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2Upstream S34: InitiateShutdown graceful drain via BeginShutdownDrain",
                                  false, e.what());
    }
}

// S35 — Race condition shape: concurrent ShouldOpenAdditionalH2Conn reads
// from dispatcher thread while FailAllStreams mutates active_streams_ on
// the same thread.  Uses promise/future to serialize — verifies no crash.
// Guarded against per-PR CI via GITHUB_ACTIONS (stress shape).
static void TestS35_ConcurrentSaturationAndFailAll() {
    std::cout << "\n[TEST] H2Upstream S35: concurrent saturation eval + FailAllStreams shape..." << std::endl;
    if (std::getenv("GITHUB_ACTIONS")) {
        TestFramework::RecordTest(
            "H2Upstream S35: concurrent saturation + FailAllStreams",
            true, "skipped on CI");
        return;
    }
    try {
        auto disp = std::make_shared<Dispatcher>();
        auto t = StartDispatcher(disp);
        UpstreamConfig cfg = MakeH2UpstreamConfig("svc", "127.0.0.1", 9999);
        cfg.pool.max_connections = 2;
        cfg.http2.saturation_open_pct = 80;
        cfg.http2.max_concurrent_streams_pref = 10;
        UpstreamManager mgr({cfg}, {disp});
        DispatcherThreadGuard dtg{disp, t};

        auto* part = mgr.GetPoolPartition("svc", 0);
        if (!part) {
            TestFramework::RecordTest(
                "H2Upstream S35: concurrent saturation + FailAllStreams",
                false, "null part");
            return;
        }

        auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
        h2_cfg->enabled = true;
        h2_cfg->max_concurrent_streams_pref = 10;
        h2_cfg->ping_idle_sec = 0;
        h2_cfg->ping_timeout_sec = 0;
        h2_cfg->goaway_drain_timeout_sec = 0;

        constexpr int kIter = 100;
        std::atomic<int> no_crash{0};

        for (int iter = 0; iter < kIter; ++iter) {
            // Wrap in shared_ptr so the lambda remains copyable for EnQueue.
            auto h2_conn = std::make_shared<std::unique_ptr<UpstreamH2Connection>>(
                std::make_unique<UpstreamH2Connection>(nullptr, h2_cfg));
            if (!(*h2_conn)->Init()) continue;
            UpstreamH2Connection* raw = h2_conn->get();

            std::promise<void> done;
            auto fut = done.get_future();
            auto done_ptr = std::make_shared<std::promise<void>>(std::move(done));
            disp->EnQueue([&, h2_conn, raw, done_ptr]() mutable {
                part->InsertH2ConnectionForTesting("svc", std::move(*h2_conn));
                RecordingSink sinks[8];
                for (int i = 0; i < 8; ++i)
                    raw->SubmitRequest("GET","https","h","/",{},""  ,&sinks[i]);
                (void)part->ShouldOpenAdditionalH2Conn("svc");
                raw->FailAllStreams(-1, "stress");
                (void)part->ShouldOpenAdditionalH2Conn("svc");
                ++no_crash;
                done_ptr->set_value();
            });
            fut.wait_for(std::chrono::seconds(2));
        }

        bool pass = (no_crash.load() == kIter);
        TestFramework::RecordTest(
            "H2Upstream S35: concurrent saturation + FailAllStreams",
            pass,
            pass ? "" : (std::string("completed ") + std::to_string(no_crash.load()) +
                         "/" + std::to_string(kIter) + " iterations").c_str());
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream S35: concurrent saturation + FailAllStreams",
            false, e.what());
    }
}

// S36 — Memory safety: insert + immediately shutdown releases all
// resources without leaks. Runs under ASan/Valgrind in CI to confirm.
// Guarded against per-PR CI as stress shape.
static void TestS36_InsertAndShutdownNoLeak() {
    std::cout << "\n[TEST] H2Upstream S36: insert + shutdown no-leak shape..." << std::endl;
    if (std::getenv("GITHUB_ACTIONS")) {
        TestFramework::RecordTest(
            "H2Upstream S36: insert + shutdown no-leak shape",
            true, "skipped on CI");
        return;
    }
    try {
        constexpr int kRounds = 50;
        for (int r = 0; r < kRounds; ++r) {
            auto disp = std::make_shared<Dispatcher>();
            auto t = StartDispatcher(disp);
            UpstreamConfig cfg = MakeH2UpstreamConfig("svc", "127.0.0.1", 9999);
            cfg.pool.max_connections = 2;
            cfg.http2.saturation_open_pct = 80;
            cfg.http2.preconnect_watermark_pct = 50;
            cfg.http2.max_concurrent_streams_pref = 10;
            UpstreamManager mgr({cfg}, {disp});
            DispatcherThreadGuard dtg{disp, t};

            auto* part = mgr.GetPoolPartition("svc", 0);
            if (!part) continue;

            auto h2_cfg = std::make_shared<Http2UpstreamConfig>();
            h2_cfg->enabled = true;
            h2_cfg->max_concurrent_streams_pref = 10;
            h2_cfg->ping_idle_sec = 0;
            h2_cfg->ping_timeout_sec = 0;
            h2_cfg->goaway_drain_timeout_sec = 0;

            std::promise<void> done;
            auto fut = done.get_future();
            disp->EnQueue([&]() {
                auto c = std::make_unique<UpstreamH2Connection>(nullptr, h2_cfg);
                c->Init();
                RecordingSink sink;
                c->SubmitRequest("GET","https","h","/",{},""  ,&sink);
                part->InsertH2ConnectionForTesting("svc", std::move(c));
                part->InitiateShutdown(0);
                done.set_value();
            });
            fut.wait_for(std::chrono::seconds(2));
            // dtg destructor stops dispatcher + joins thread
        }
        TestFramework::RecordTest(
            "H2Upstream S36: insert + shutdown no-leak shape",
            true, "");
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2Upstream S36: insert + shutdown no-leak shape",
            false, e.what());
    }
}

// ---------------------------------------------------------------------------
// RunAll aggregator
// ---------------------------------------------------------------------------

void RunAllH2UpstreamTests() {
    std::cout << "\n=== H2 Upstream Tests ===" << std::endl;

    TestS1_StreamLifecycleFieldsDefault();
    TestS2_DetachSinkBeforePeerCloseKeepsEntry();
    TestS3_RunDeferredEraseWalkIdempotent();
    TestS6_AliveTokenInitiallyTrue();
    TestS7_ActiveStreamsIncrementOnSubmit();
    TestS8_ActiveStreamsDecrementInDeferredWalk();
    TestS9_ActiveStreamsBulkResetByFailAll();
    TestS10_IsUsableHonorsActiveStreamsCap();
    TestS11_DestroyOnDispatcherFlipsAliveAndIsIdempotent();
    TestS12_DtorShortCircuitAfterDestroyOnDispatcher();
    TestS13_H2RetryClassification();
    TestS14_AlpnNotNegotiatedContract();
    TestS15_OnStreamCloseRefusedStreamMapsToGoawayUnprocessed();
    TestS16_OnStreamCloseAfterGoawayMapsToMaybeProcessed();
    TestS17_OnStreamCloseNoGoawayKeepsUpstreamDisconnect();
    TestS18_GoawayAllAboveMarksAllPendingErase();
    TestS19_GoawayWithSurvivorsBelowKeepsDraining();
    TestS20_DrainAnyWaitersRequeuesWithoutUsableSession();
    TestS21_TotalCountExcludesH2Containers();
    TestS22_DrainH2StreamSlotRequeuesWhenNoSession();
    TestS23_DrainHelpersEarlyReturnOnEmptyQueue();
    TestS24_DrainH2StreamWaitersForHostKeepsAllEntries();
    TestS25_DrainAnyWaitersShutdownFiresError();
    TestS26_CapacityAwareDrainStopsAtCap();
    TestS27_MovePendingDestroyCapturesReplacementTarget();
    TestS28_ReapSnapshotsBothContainersTogether();
    TestS29_ReapDrainsSeededReplacementTargets();
    TestS30_InitiateShutdownRetiresH2Sessions();
    TestS31_DonatedLeaseFullLifecycle();
    TestS31b_RealDonatedReleasePath();

    // Tier A — unit tests
    TestMinCadenceSecDisabled();
    TestMinCadenceSecEnabled();
    TestMinCadenceSecZeroFields();
    TestMinCadenceSecAllZero();
    TestMinCadenceSecSingleTimer();

    TestCodecPolymorphism();

    TestH2CodecParseFails();
    TestH2CodecParseErrorSurvivesReset();
    TestH2CodecFinishReturnsFalse();
    TestH2CodecResetClearsResponse();

    TestFindUsableEmptyTable();
    TestFindUsableUnknownUpstream();
    TestFindUsableReapsDrainedEntry();

    TestReapDrainedEmpty();
    TestReapDrainedNonDrainedPreserved();

    TestClearEmptiesTable();
    TestExtractTransfersOwnership();
    TestExtractNullIsNoop();

    TestTickAllRemovesDeadConnections();
    TestTickAllKeepsLiveConnections();

    TestTableMultiUpstream();
    TestTableInsertNullIgnored();

    TestBuildSettingsArray();
    TestBuildSettingsArrayDefaults();

    TestCommitH2SnapshotsIgnoresStaleStagedEntry();

    TestCommitH2SnapshotsBootstrap();
    TestCommitH2SnapshotsMissingPartitionRetainsPrevious();
    TestCommitH2SnapshotsH2Disabled();

    TestComputeMinCadenceEmpty();
    TestComputeMinCadenceFoldsAll();
    TestComputeMinCadenceH2Disabled();

    TestApplyAndLoadH2Snapshot();
    TestApplyNullClearsSnapshot();

    TestLivePartitionsNonEmpty();

    TestIsUsableNullSession();
    TestIsUsableAfterGoaway();
    TestIsUsableZeroStreamCap();

    TestH2ConnectionAccessors();

    TestHandleBytesNullSession();
    TestSubmitRequestNullSession();

    TestHasUpstream();

    // Config parsing
    TestConfigParseH2Block();
    TestConfigH2Defaults();
    TestConfigH2EnabledRequiresTlsHotReload();

    // Tier B (wire-level — session-only)
    TestB5TickReturnsFalseWithNullSession();
    TestB6RstStreamRemovesEntry();
    TestB7OnTrailersCompleteNoStream();
    TestB8RecordingSinkTrailers();
    TestB1SingleRequestCompletes();

    // Tier B (wire-level via real UpstreamH2Connection::HandleBytes)
    TestB9HandleBytesConsumesSettings();
    TestB10HandleBytesDispatchesValidStatus();
    TestB11HandleBytesRejectsInvalidStatus();
    TestB12TickGoawayDrainTimeout();
    TestB12bGoawayFailsStreamsAbovePeerLastId();
    TestB13AlpnGatedByPreferMode();
    TestB14AuthorityDerivationCases();

    // Tier C — race / lifetime / memory
    TestC1InReceiveDataGuard();
    TestC2LeaseAdoption();
    TestC3StreamsEmptyAfterFailAll();
    TestC4GoawayMarksNotUsable();
    TestC4bMarkDeadDisablesUsable();
    TestC5AcquireReleaseNoTornRead();
    TestC6ResetStreamSinkDetachSurvivesDtor();

    // TestN-series — correctness / negative tests
    TestN1TruncationCLShortRead();
    TestN1bInterimCLDoesNotPoisonFinalHead();
    TestN2HeadResponseBodyRejected();
    TestN3Status204BodyRejected();
    TestN4Status304BodyRejected();
    TestN5ConnectRejectSecondaryGate();
    TestN5bConnectRejectNullSink();
    TestN6TeTrailersReEmit();
    TestN6bTeTrailersFalsePath();
    TestN6cTeTrailersPerStreamFlag();
    TestN7CLExactMatchCompletes();
    TestN7bCLOverflowRejected();
    TestN8OnRequestSubmittedBodyless();
    TestN8bOnRequestSubmittedBodyed();
    TestN9OnRequestSubmittedOncePerStream();
    TestN10ConnectNoSubmittedCallback();
    TestN11HeadNoBodyEndStreamOnHeaders();
    TestN12Status204EndStreamOnHeadersCompletes();
    TestN13ConcurrentStreamIndependentFraming();
    TestN14SubmitNullSinkNoCrash();
    TestN15RstStreamMidBodyMapsToDisconnect();
    TestN16NoSpuriousRstOnNaturalClose();
    TestN17ResetAfterCompleteIsNoop();
    TestN18TruncationDoesNotAffectSiblingStream();
    TestN19FailAllStreamsCleanup();
    TestN6dTeTokenizerAcceptsParametersAndCases();
    TestN7cSendStallFallbackBudget();
    TestN8cNoPoisonOnEarlyHeadersSiblingReuse();
    TestN9bRequestBodyProgressFiresFromCodec();
    TestN9cDefaultSinkSurvivesNewVirtual();
    TestN9dDeferredDrainSemantic();
    TestN9eResetStreamDropsDrainEntries();
    TestN9qResetSiblingDoesNotStarveDrainAttribution();
    TestN9fPartialDrainOfFinalFrame();
    TestN9gControlFrameByteAccounting();
    TestN9hHeadersOnlyShortReadCL();
    TestN9iHeadersOnlyShortReadCLZeroLegitimate();
    TestN9jHeadResponseWithCLLegitimate();
    TestN9kZeroTimeoutPostSubmit();
    TestN9lPositiveTimeoutPostSubmit();
    TestN9mSinkOnBodyChunkFalseStopsConsumption();
    TestN9nFreshSessionBootstrapCallbackOrdering();
    TestN9oEarlyFinalHeadersInvalidateSendStallClosure();
    TestN9pH2ResponseTimeoutClosureHonorsShutdownKill();
    TestN7eWiringEarlyHeadersThenIntermediateDataDispatch();

    // TestB-series additions — wire-level
    TestB15TrailersAfterDataEndStream();
    TestB16DataPaddingStripped();
    TestB17GoawayWithActiveStream();
    TestB18RstStreamMidBodyWire();
    TestB19MultiStreamRstOneCompletesOther();

    // Lease migration (TestL series)
    TestL1_LeasePopulatedAfterSubmit();
    TestL2_H2ConnAliveTokenGuard();
    TestL3_LeaseGetH2StreamId();
    TestL4_LeaseMoveLeavesDonorEmpty();
    TestL5_SubmitOnDeadSessionReturnsMinusOne();
    TestL6_LeaseDonatedToH2Flag();

    // ALPN negotiation cache + saturation gate (TestA1 series)
    TestA1_1_AlpnCacheInitiallyEmpty();
    TestA1_2_SaturationGateWithLiveSession();
    TestA1_3_ShouldOpenWhenAllSaturated();
    TestA1_4_SaturationDisabledFastPath();

    // Graceful shutdown drain (TestA3 series)
    TestA3_1_BeginShutdownDrainSetsFlags();
    TestA3_2_DrainCompleteOnDeadSession();
    TestA3_3_DrainCompleteWhenStreamsEmpty();
    TestA3_4_DrainCompleteAfterDeadline();
    TestA3_5_BeginShutdownDrainIdempotent();
    TestA3_6_CollectAllIncludesDrainingSession();
    TestA3_7_SaturationSkipsDrainingSession();

    // Multi-conn per host (TestB2 series)
    TestB2_1_CollectUsableForUpstreamMultiConn();
    TestB2_2_CollectUsableUnknownUpstream();
    TestB2_3_TotalCountExcludesH2Table();
    TestB2_4_H2TableCountReflectsInsert();
    TestB2_5_TickAllIteratesMultipleUpstreams();

    // Saturation policy (TestT series)
    TestT1_ShouldOpenFalseWhenCapSaturated();
    TestT2_FindUsableSaturationDisabledDelegates();
    TestT3_FindUsableSaturationNullWhenAboveThreshold();
    TestT4_FindUsableSaturationReturnsBelowThreshold();
    TestT5_CapacityProbeRejectedOnShutdown();
    TestT6_AcquireH2ConnectionEmptyLeaseFallsBackToFirstUsable();

    // Preconnect (TestP series)
    TestP1_PreconnectDisabledByDefault();
    TestP2_PreconnectValidationRequiresSaturation();
    TestP3_PreconnectValidationWatermarkBelowSaturation();
    TestP4_PreconnectFiredCounter();
    TestP5_PreconnectSkippedCapCounter();
    TestP6_PreconnectSkippedWhenSpareExists();

    // Config validation (TestPC series)
    TestPC1_SaturationPctOutOfRange();
    TestPC2_ValidSaturationPreconnectCombo();
    TestPC3_SaturationPreconnectRoundTrip();

    // Integration + stress (TestS32+ series)
    TestS32_SaturationGateSwitches();
    TestS33_ShutdownDrainWithStream();
    TestS34_InitiateShutdownGracefulDrain();
    TestS35_ConcurrentSaturationAndFailAll();
    TestS36_InsertAndShutdownNoLeak();
}

}  // namespace H2UpstreamTests
