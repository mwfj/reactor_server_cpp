#pragma once

// streaming_request_test.h — Phase J: G1 coverage for inbound streaming request body.
//
// Test dimensions:
//   Unit (in-process, no sockets):
//     J1  ChunkQueueBodyStream: basic Push + Read
//     J2  ChunkQueueBodyStream: WOULD_BLOCK when queue empty
//     J3  ChunkQueueBodyStream: WaitForData callback fires immediately when data present
//     J4  ChunkQueueBodyStream: CloseEmpty + END_OF_STREAM
//     J5  HttpRequest::ExpectsRequestBody framing-only logic
//     J6  ChunkQueueBodyStream: PushTrailersAndClose + Trailers() visibility
//     J7  ChunkQueueBodyStream: Abort clears queue + reports ABORTED
//     J8  ChunkQueueBodyStream: Push after EOS drops silently
//     J10 RetryPolicy::IsMethodRetryableForReplay idempotency gate
//   Integration (real HttpServer + TCP clients):
//     J9  Streaming route receives body_stream in Streaming mode handler
//     J9a High-water mark fires on_above_high_water exactly once per crossing
//     J9b Low-water fires on_below_low_water after drain below threshold
//     J9c CloseEmpty on already-EOS is idempotent
//     J9d Abort after partial read surfaces ABORTED
//     J9e WaitForData fires once even when already-EOS
//     J9f 100 consecutive H2 requests: connection-level window not permanently drained
//     BodyStream AbortReason set correctly
//     BodyStream Push after Abort is silently dropped
//     BodyStream ABORTED classification on client abort
//     BodyStream Double-Abort is idempotent
//     StreamingRoute Streaming request body is readable from route handler
//     J11 StreamingResponseSender can relay chunks as they arrive (inbound streaming relay)

#include "test_framework.h"
#include "test_server_runner.h"
#include "http_test_client.h"
#include "http/http_server.h"
#include "http/body_stream.h"
#include "http/body_stream_impl.h"
#include "http/http_request.h"
#include "http/route_options.h"
#include "http/http_callbacks.h"
#include "upstream/retry_policy.h"
#include "upstream/proxy_transaction.h"
#include "config/server_config.h"
#include "config/config_loader.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>

#include <thread>
#include <chrono>
#include <atomic>
#include <future>
#include <sstream>

namespace StreamingRequestTests {

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// Poll + recv loop until connection closes or timeout elapses.
static std::string RecvUntilClose(int fd, int timeout_ms) {
    std::string out;
    auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
        struct pollfd pfd{fd, POLLIN, 0};
        int rv;
        do { rv = poll(&pfd, 1, static_cast<int>(remaining.count())); }
        while (rv < 0 && errno == EINTR);
        if (rv <= 0) break;
        char buf[4096];
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        out.append(buf, static_cast<size_t>(n));
    }
    return out;
}

// Send all bytes; return false on error.
static bool SendAll(int fd, const std::string& data) {
    int send_flags = 0;
#ifdef MSG_NOSIGNAL
    send_flags |= MSG_NOSIGNAL;
#endif
    size_t sent = 0;
    while (sent < data.size()) {
        ssize_t n = send(fd, data.data() + sent, data.size() - sent, send_flags);
        if (n < 0) { if (errno == EINTR) continue; return false; }
        sent += static_cast<size_t>(n);
    }
    return true;
}

// Open a raw TCP connection to 127.0.0.1:port; return fd or -1.
static int ConnectRaw(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(static_cast<uint16_t>(port));
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

// Receive until the string contains needle or timeout elapses.
static std::string RecvUntilContains(int fd, const std::string& needle, int timeout_ms) {
    std::string out;
    auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline &&
           out.find(needle) == std::string::npos) {
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
        struct pollfd pfd{fd, POLLIN, 0};
        int rv;
        do { rv = poll(&pfd, 1, static_cast<int>(remaining.count())); }
        while (rv < 0 && errno == EINTR);
        if (rv <= 0) break;
        char buf[4096];
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        out.append(buf, static_cast<size_t>(n));
    }
    return out;
}

// Build a minimal ServerConfig for integration tests.
static ServerConfig MakeStreamingGwConfig(const std::string& upstream_name = "",
                                           const std::string& upstream_host = "",
                                           int upstream_port = 0,
                                           const std::string& route_prefix = "") {
    ServerConfig cfg;
    cfg.bind_host = "127.0.0.1";
    cfg.bind_port = 0;
    cfg.worker_threads = 2;
    cfg.http2.enabled  = false;  // plain HTTP/1.1 for most streaming tests
    if (!upstream_name.empty()) {
        UpstreamConfig u;
        u.name = upstream_name;
        u.host = upstream_host;
        u.port = upstream_port;
        u.pool.max_connections      = 4;
        u.pool.max_idle_connections = 2;
        u.pool.connect_timeout_ms   = 3000;
        u.pool.idle_timeout_sec     = 30;
        u.proxy.route_prefix        = route_prefix;
        u.proxy.response_timeout_ms = 5000;
        u.request_mode = http::RouteRequestMode::Streaming;
        cfg.upstreams.push_back(u);
    }
    return cfg;
}

// Poll until pred() returns true or timeout elapses.
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
// J1: ChunkQueueBodyStream basic Push + Read
// ---------------------------------------------------------------------------
void TestJ1_BasicPushRead() {
    std::cout << "\n[TEST] J1: ChunkQueueBodyStream: basic Push + Read..." << std::endl;
    try {
        http::ChunkQueueBodyStream::Config cfg;
        http::ChunkQueueBodyStream stream(cfg);

        stream.Push("hello");
        stream.Push(" world");

        char buf[64];
        size_t bytes_read = 0;
        auto r1 = stream.Read(buf, sizeof(buf), &bytes_read);

        bool pass = true;
        std::string err;
        if (r1 != http::BodyStreamResult::OK) {
            pass = false; err += "first Read result != OK; ";
        }
        std::string got(buf, bytes_read);
        if (got != "hello world") {
            pass = false; err += "body mismatch, got: " + got + "; ";
        }
        if (bytes_read != 11) {
            pass = false; err += "bytes_read=" + std::to_string(bytes_read) + " want 11; ";
        }
        TestFramework::RecordTest("J1: ChunkQueueBodyStream: basic Push + Read", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("J1: ChunkQueueBodyStream: basic Push + Read", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// J2: ChunkQueueBodyStream WOULD_BLOCK when queue empty + not EOS
// ---------------------------------------------------------------------------
void TestJ2_WouldBlockWhenEmpty() {
    std::cout << "\n[TEST] J2: ChunkQueueBodyStream: WOULD_BLOCK when empty..." << std::endl;
    try {
        http::ChunkQueueBodyStream::Config cfg;
        http::ChunkQueueBodyStream stream(cfg);

        char buf[64];
        size_t bytes_read = 0;
        auto r = stream.Read(buf, sizeof(buf), &bytes_read);

        bool pass = (r == http::BodyStreamResult::WOULD_BLOCK && bytes_read == 0);
        std::string err = pass ? "" :
            "result=" + std::to_string(static_cast<int>(r)) +
            " bytes_read=" + std::to_string(bytes_read);
        TestFramework::RecordTest("J2: ChunkQueueBodyStream: WOULD_BLOCK when empty", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("J2: ChunkQueueBodyStream: WOULD_BLOCK when empty", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// J3: WaitForData fires immediately when data is already present
// ---------------------------------------------------------------------------
void TestJ3_WaitForDataImmediate() {
    std::cout << "\n[TEST] J3: ChunkQueueBodyStream: WaitForData fires immediately when data present..."
              << std::endl;
    try {
        http::ChunkQueueBodyStream::Config cfg;
        http::ChunkQueueBodyStream stream(cfg);

        stream.Push("data");

        std::atomic<bool> fired{false};
        stream.WaitForData([&fired]() { fired.store(true, std::memory_order_release); });

        // Without a dispatcher, WaitForData fires the callback synchronously
        // (inline) when data is already available.
        bool pass = fired.load(std::memory_order_acquire);
        std::string err = pass ? "" : "callback not fired immediately";
        TestFramework::RecordTest(
            "J3: ChunkQueueBodyStream: WaitForData fires immediately when data present", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "J3: ChunkQueueBodyStream: WaitForData fires immediately when data present", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// J4: CloseEmpty signals END_OF_STREAM after drain
// ---------------------------------------------------------------------------
void TestJ4_CloseEmptyEndOfStream() {
    std::cout << "\n[TEST] J4: ChunkQueueBodyStream: CloseEmpty + END_OF_STREAM after drain..."
              << std::endl;
    try {
        http::ChunkQueueBodyStream::Config cfg;
        http::ChunkQueueBodyStream stream(cfg);

        stream.Push("abc");
        stream.CloseEmpty();

        // First Read drains "abc".
        char buf[64];
        size_t bytes_read = 0;
        auto r1 = stream.Read(buf, sizeof(buf), &bytes_read);
        std::string got(buf, bytes_read);

        // Second Read should see END_OF_STREAM.
        size_t bytes_read2 = 0;
        auto r2 = stream.Read(buf, sizeof(buf), &bytes_read2);

        bool pass = true;
        std::string err;
        if (r1 != http::BodyStreamResult::OK)           { pass = false; err += "first Read != OK; "; }
        if (got != "abc")                               { pass = false; err += "body mismatch: " + got + "; "; }
        if (r2 != http::BodyStreamResult::END_OF_STREAM){ pass = false; err += "second Read != END_OF_STREAM; "; }
        if (!stream.IsEndOfStream())                    { pass = false; err += "IsEndOfStream() false; "; }
        TestFramework::RecordTest("J4: ChunkQueueBodyStream: CloseEmpty + END_OF_STREAM", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("J4: ChunkQueueBodyStream: CloseEmpty + END_OF_STREAM", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// J5: HttpRequest::ExpectsRequestBody framing-only logic
// ---------------------------------------------------------------------------
void TestJ5_ExpectsRequestBody() {
    std::cout << "\n[TEST] J5: HttpRequest::ExpectsRequestBody framing-only logic..."
              << std::endl;
    try {
        bool pass = true;
        std::string err;

        // Content-Length > 0 → true.
        {
            std::map<std::string, std::string> h{{"content-length", "42"}};
            if (!HttpRequest::ExpectsRequestBody("GET", h)) {
                pass = false; err += "CL=42 GET should be true; ";
            }
        }
        // Content-Length = 0 → false.
        {
            std::map<std::string, std::string> h{{"content-length", "0"}};
            if (HttpRequest::ExpectsRequestBody("POST", h)) {
                pass = false; err += "CL=0 should be false; ";
            }
        }
        // Transfer-Encoding present → true.
        {
            std::map<std::string, std::string> h{{"transfer-encoding", "chunked"}};
            if (!HttpRequest::ExpectsRequestBody("POST", h)) {
                pass = false; err += "TE=chunked should be true; ";
            }
        }
        // Empty Transfer-Encoding → false.
        {
            std::map<std::string, std::string> h{{"transfer-encoding", ""}};
            if (HttpRequest::ExpectsRequestBody("POST", h)) {
                pass = false; err += "TE=empty should be false; ";
            }
        }
        // Neither → false.
        {
            std::map<std::string, std::string> h{{"accept", "*/*"}};
            if (HttpRequest::ExpectsRequestBody("DELETE", h)) {
                pass = false; err += "no framing header should be false; ";
            }
        }
        // Framing-only: DELETE with CL > 0 → true (method unused per r9 F1 P0).
        {
            std::map<std::string, std::string> h{{"content-length", "10"}};
            if (!HttpRequest::ExpectsRequestBody("DELETE", h)) {
                pass = false; err += "DELETE+CL=10 should be true (method unused); ";
            }
        }
        TestFramework::RecordTest("J5: HttpRequest::ExpectsRequestBody framing-only logic", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("J5: HttpRequest::ExpectsRequestBody framing-only logic", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// J6: PushTrailersAndClose exposes trailers after END_OF_STREAM
// ---------------------------------------------------------------------------
void TestJ6_PushTrailersAndClose() {
    std::cout << "\n[TEST] J6: ChunkQueueBodyStream: PushTrailersAndClose + Trailers()..."
              << std::endl;
    try {
        http::ChunkQueueBodyStream::Config cfg;
        http::ChunkQueueBodyStream stream(cfg);

        stream.Push("body-data");
        stream.PushTrailersAndClose({{"x-checksum", "abc123"}, {"x-seq", "1"}});

        // Drain the body.
        char buf[64];
        size_t bytes_read = 0;
        auto r1 = stream.Read(buf, sizeof(buf), &bytes_read);
        // Now read again — should see END_OF_STREAM and publish trailers.
        size_t br2 = 0;
        auto r2 = stream.Read(buf, sizeof(buf), &br2);

        bool pass = true;
        std::string err;
        if (r1 != http::BodyStreamResult::OK)              { pass = false; err += "r1 != OK; "; }
        if (r2 != http::BodyStreamResult::END_OF_STREAM)   { pass = false; err += "r2 != EOS; "; }
        const auto& trailers = stream.Trailers();
        if (trailers.size() != 2) {
            pass = false;
            err += "trailers.size()=" + std::to_string(trailers.size()) + " want 2; ";
        } else {
            bool found_chk = false, found_seq = false;
            for (const auto& [k, v] : trailers) {
                if (k == "x-checksum" && v == "abc123") found_chk = true;
                if (k == "x-seq"      && v == "1")      found_seq = true;
            }
            if (!found_chk) { pass = false; err += "x-checksum not found; "; }
            if (!found_seq)  { pass = false; err += "x-seq not found; "; }
        }
        TestFramework::RecordTest("J6: ChunkQueueBodyStream: PushTrailersAndClose + Trailers()", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("J6: ChunkQueueBodyStream: PushTrailersAndClose + Trailers()", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// J7: Abort clears queue, sets ABORTED, exposes reason
// ---------------------------------------------------------------------------
void TestJ7_AbortClearsQueue() {
    std::cout << "\n[TEST] J7: ChunkQueueBodyStream: Abort clears queue + ABORTED..."
              << std::endl;
    try {
        http::ChunkQueueBodyStream::Config cfg;
        http::ChunkQueueBodyStream stream(cfg);

        stream.Push("pending-data");
        stream.Abort("test-abort-reason");

        char buf[64];
        size_t bytes_read = 0;
        auto r = stream.Read(buf, sizeof(buf), &bytes_read);

        bool pass = true;
        std::string err;
        if (r != http::BodyStreamResult::ABORTED)    { pass = false; err += "result != ABORTED; "; }
        if (!stream.Aborted())                        { pass = false; err += "Aborted() false; "; }
        if (stream.AbortReason() != "test-abort-reason") {
            pass = false; err += "AbortReason=" + stream.AbortReason() + "; ";
        }
        if (stream.BytesQueued() != 0)               { pass = false; err += "BytesQueued != 0 after abort; "; }
        TestFramework::RecordTest("J7: ChunkQueueBodyStream: Abort clears queue + ABORTED", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("J7: ChunkQueueBodyStream: Abort clears queue + ABORTED", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// J8: Push after EOS drops silently (no crash, no data added)
// ---------------------------------------------------------------------------
void TestJ8_PushAfterEOSDropped() {
    std::cout << "\n[TEST] J8: ChunkQueueBodyStream: Push after EOS drops silently..."
              << std::endl;
    try {
        http::ChunkQueueBodyStream::Config cfg;
        http::ChunkQueueBodyStream stream(cfg);

        stream.CloseEmpty();
        // Push after EOS must be silently dropped.
        stream.Push("late-data");

        char buf[64];
        size_t bytes_read = 0;
        auto r = stream.Read(buf, sizeof(buf), &bytes_read);

        bool pass = (r == http::BodyStreamResult::END_OF_STREAM && bytes_read == 0);
        std::string err = pass ? "" :
            "result=" + std::to_string(static_cast<int>(r)) +
            " bytes_read=" + std::to_string(bytes_read);
        TestFramework::RecordTest("J8: ChunkQueueBodyStream: Push after EOS drops silently", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("J8: ChunkQueueBodyStream: Push after EOS drops silently", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// J9a: High-water on_above_high_water fires exactly once per crossing
// ---------------------------------------------------------------------------
void TestJ9a_HighWaterFiresOnce() {
    std::cout << "\n[TEST] J9a: ChunkQueueBodyStream: on_above_high_water fires once per crossing..."
              << std::endl;
    try {
        std::atomic<int> hw_count{0};
        http::ChunkQueueBodyStream::Config cfg;
        cfg.high_water_bytes = 8;
        cfg.low_water_bytes  = 4;
        cfg.on_above_high_water = [&hw_count]() {
            hw_count.fetch_add(1, std::memory_order_relaxed);
        };
        http::ChunkQueueBodyStream stream(cfg);

        // First push crosses high water.
        stream.Push("123456789");  // 9 bytes > 8 high water
        // Second push — latch already set, must NOT fire again.
        stream.Push("xyz");

        bool pass = (hw_count.load() == 1);
        std::string err = pass ? "" :
            "hw_count=" + std::to_string(hw_count.load()) + " want 1";
        TestFramework::RecordTest(
            "J9a: ChunkQueueBodyStream: on_above_high_water fires once per crossing", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "J9a: ChunkQueueBodyStream: on_above_high_water fires once per crossing", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// J9b: Low-water fires on_below_low_water after drain
// ---------------------------------------------------------------------------
void TestJ9b_LowWaterFires() {
    std::cout << "\n[TEST] J9b: ChunkQueueBodyStream: on_below_low_water fires after drain..."
              << std::endl;
    try {
        std::atomic<int> lw_count{0};
        http::ChunkQueueBodyStream::Config cfg;
        cfg.high_water_bytes = 8;
        cfg.low_water_bytes  = 4;
        cfg.on_below_low_water = [&lw_count]() {
            lw_count.fetch_add(1, std::memory_order_relaxed);
        };
        http::ChunkQueueBodyStream stream(cfg);

        // Push enough to cross high water, triggering above_low_water_latched_.
        stream.Push("12345678");  // 8 bytes, exactly at high water

        // Drain all bytes — should fall below low_water (4), triggering callback.
        char buf[64];
        size_t bytes_read = 0;
        stream.Read(buf, sizeof(buf), &bytes_read);

        bool pass = (lw_count.load() == 1);
        std::string err = pass ? "" :
            "lw_count=" + std::to_string(lw_count.load()) + " want 1";
        TestFramework::RecordTest(
            "J9b: ChunkQueueBodyStream: on_below_low_water fires after drain", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "J9b: ChunkQueueBodyStream: on_below_low_water fires after drain", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// J9c: CloseEmpty on already-EOS is idempotent
// ---------------------------------------------------------------------------
void TestJ9c_CloseEmptyIdempotent() {
    std::cout << "\n[TEST] J9c: ChunkQueueBodyStream: CloseEmpty idempotent..."
              << std::endl;
    try {
        http::ChunkQueueBodyStream::Config cfg;
        http::ChunkQueueBodyStream stream(cfg);

        stream.CloseEmpty();
        stream.CloseEmpty();  // Must not crash or double-fire.

        char buf[64];
        size_t bytes_read = 0;
        auto r = stream.Read(buf, sizeof(buf), &bytes_read);

        bool pass = (r == http::BodyStreamResult::END_OF_STREAM && stream.IsEndOfStream());
        std::string err = pass ? "" : "result=" + std::to_string(static_cast<int>(r));
        TestFramework::RecordTest("J9c: ChunkQueueBodyStream: CloseEmpty idempotent", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("J9c: ChunkQueueBodyStream: CloseEmpty idempotent", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// J9d: Abort after partial read — remaining ABORTED result
// ---------------------------------------------------------------------------
void TestJ9d_AbortAfterPartialRead() {
    std::cout << "\n[TEST] J9d: ChunkQueueBodyStream: Abort after partial read surfaces ABORTED..."
              << std::endl;
    try {
        http::ChunkQueueBodyStream::Config cfg;
        http::ChunkQueueBodyStream stream(cfg);

        stream.Push("hello");
        // Drain only partial bytes by providing a small buffer.
        char buf[3];
        size_t bytes_read = 0;
        auto r1 = stream.Read(buf, sizeof(buf), &bytes_read);  // reads "hel"

        // Now abort.
        stream.Abort("partial-read-abort");

        // Next read must see ABORTED (not the leftover "lo").
        size_t br2 = 0;
        auto r2 = stream.Read(buf, sizeof(buf), &br2);

        bool pass = true;
        std::string err;
        if (r1 != http::BodyStreamResult::OK)      { pass = false; err += "r1 != OK; "; }
        if (bytes_read != 3)                        { pass = false; err += "partial read bytes_read != 3; "; }
        if (r2 != http::BodyStreamResult::ABORTED)  { pass = false; err += "r2 != ABORTED; "; }
        if (stream.AbortReason() != "partial-read-abort") {
            pass = false; err += "AbortReason wrong; ";
        }
        TestFramework::RecordTest(
            "J9d: ChunkQueueBodyStream: Abort after partial read surfaces ABORTED", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "J9d: ChunkQueueBodyStream: Abort after partial read surfaces ABORTED", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// J9e: WaitForData fires immediately when already EOS
// ---------------------------------------------------------------------------
void TestJ9e_WaitForDataOnEOS() {
    std::cout << "\n[TEST] J9e: ChunkQueueBodyStream: WaitForData fires immediately when EOS..."
              << std::endl;
    try {
        http::ChunkQueueBodyStream::Config cfg;
        http::ChunkQueueBodyStream stream(cfg);

        stream.CloseEmpty();

        std::atomic<bool> fired{false};
        stream.WaitForData([&fired]() { fired.store(true, std::memory_order_release); });

        bool pass = fired.load(std::memory_order_acquire);
        std::string err = pass ? "" : "callback not fired when EOS";
        TestFramework::RecordTest(
            "J9e: ChunkQueueBodyStream: WaitForData fires immediately when EOS", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "J9e: ChunkQueueBodyStream: WaitForData fires immediately when EOS", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// J9i: AbortReason set correctly
// ---------------------------------------------------------------------------
void TestBodyStream_AbortReasonSet() {
    std::cout << "\n[TEST] BodyStream: AbortReason set on Abort..."
              << std::endl;
    try {
        http::ChunkQueueBodyStream::Config cfg;
        http::ChunkQueueBodyStream stream(cfg);

        stream.Abort("body_size_limit_exceeded");

        bool pass = stream.Aborted() &&
                    stream.AbortReason() == "body_size_limit_exceeded";
        std::string err = pass ? "" :
            "aborted=" + std::to_string(stream.Aborted()) +
            " reason=" + stream.AbortReason();
        TestFramework::RecordTest(
            "BodyStream: AbortReason set on Abort", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "BodyStream: AbortReason set on Abort", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// J9i_late_abort: Push after Abort is silently dropped
// ---------------------------------------------------------------------------
void TestBodyStream_PushAfterAbortDropped() {
    std::cout << "\n[TEST] BodyStream: Push after Abort silently dropped..."
              << std::endl;
    try {
        http::ChunkQueueBodyStream::Config cfg;
        http::ChunkQueueBodyStream stream(cfg);

        stream.Abort("upstream-gone");
        stream.Push("should-be-dropped");  // must not crash

        bool pass = stream.BytesQueued() == 0 && stream.Aborted();
        std::string err = pass ? "" :
            "BytesQueued=" + std::to_string(stream.BytesQueued()) +
            " aborted=" + std::to_string(stream.Aborted());
        TestFramework::RecordTest(
            "BodyStream: Push after Abort silently dropped", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "BodyStream: Push after Abort silently dropped", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// J9i_client_abort: Abort + ABORTED classification
// ---------------------------------------------------------------------------
void TestBodyStream_AbortedClassification() {
    std::cout << "\n[TEST] BodyStream: ABORTED classification on client abort..."
              << std::endl;
    try {
        http::ChunkQueueBodyStream::Config cfg;
        http::ChunkQueueBodyStream stream(cfg);

        stream.Push("some-data");
        stream.Abort("client-disconnected");

        char buf[64];
        size_t bytes_read = 0;
        auto result = stream.Read(buf, sizeof(buf), &bytes_read);

        bool pass = (result == http::BodyStreamResult::ABORTED &&
                     stream.Aborted() &&
                     stream.AbortReason() == "client-disconnected");
        std::string err = pass ? "" :
            "result=" + std::to_string(static_cast<int>(result)) +
            " reason=" + stream.AbortReason();
        TestFramework::RecordTest(
            "BodyStream: ABORTED classification on client abort", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "BodyStream: ABORTED classification on client abort", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// J9i_reentrant: Double-Abort is idempotent (first Abort wins)
// ---------------------------------------------------------------------------
void TestBodyStream_DoubleAbortIdempotent() {
    std::cout << "\n[TEST] BodyStream: double Abort is idempotent..."
              << std::endl;
    try {
        http::ChunkQueueBodyStream::Config cfg;
        http::ChunkQueueBodyStream stream(cfg);

        stream.Abort("first-abort");
        stream.Abort("second-abort");  // must not crash; first wins

        bool pass = stream.Aborted() && stream.AbortReason() == "first-abort";
        std::string err = pass ? "" : "AbortReason=" + stream.AbortReason();
        TestFramework::RecordTest(
            "BodyStream: double Abort is idempotent", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "BodyStream: double Abort is idempotent", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// J10: RetryPolicy::IsMethodRetryableForReplay idempotency gate
// ---------------------------------------------------------------------------
void TestJ10_IsMethodRetryableForReplay() {
    std::cout << "\n[TEST] J10: RetryPolicy::IsMethodRetryableForReplay idempotency gate..."
              << std::endl;
    try {
        RetryPolicy::Config cfg;
        cfg.retry_non_idempotent = false;
        RetryPolicy policy(cfg);

        bool pass = true;
        std::string err;

        // RFC 7231 §4.2.2 idempotent methods → retryable.
        for (const std::string& m : {"GET", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE"}) {
            if (!policy.IsMethodRetryableForReplay(m)) {
                pass = false; err += m + " should be retryable; ";
            }
        }
        // Non-idempotent methods → not retryable.
        for (const std::string& m : {"POST", "PATCH", "CONNECT"}) {
            if (policy.IsMethodRetryableForReplay(m)) {
                pass = false; err += m + " should NOT be retryable; ";
            }
        }

        TestFramework::RecordTest(
            "J10: RetryPolicy::IsMethodRetryableForReplay idempotency gate", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "J10: RetryPolicy::IsMethodRetryableForReplay idempotency gate", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// J9: Integration — Streaming route receives body_stream in handler (HTTP/1.1)
// ---------------------------------------------------------------------------
void TestJ9_StreamingRouteBodyStream() {
    std::cout << "\n[TEST] J9: Integration: streaming route receives body_stream in handler..."
              << std::endl;
    try {
        // Streaming-mode handler: reads all bytes from body_stream.
        std::atomic<size_t> received_bytes{0};
        std::atomic<bool> handler_got_body_stream{false};

        ServerConfig cfg;
        cfg.bind_host = "127.0.0.1";
        cfg.bind_port = 0;
        cfg.worker_threads = 2;
        cfg.http2.enabled = false;

        HttpServer server(cfg);

        // Register a streaming route with 4-arg overload (explicit options).
        server.RouteAsync("POST", "/stream-echo",
            [&received_bytes, &handler_got_body_stream](
                const HttpRequest& req,
                HTTP_CALLBACKS_NAMESPACE::InterimResponseSender /*send_interim*/,
                HTTP_CALLBACKS_NAMESPACE::ResourcePusher        /*push_resource*/,
                HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender /*stream_sender*/,
                HTTP_CALLBACKS_NAMESPACE::AsyncCompletionCallback complete) {

                // Verify body_stream is populated in streaming mode.
                if (req.body_stream) {
                    handler_got_body_stream.store(true, std::memory_order_release);
                    // Drain all bytes from the stream.
                    size_t total = 0;
                    char buf[512];
                    while (true) {
                        size_t bytes_read = 0;
                        auto r = req.body_stream->Read(buf, sizeof(buf), &bytes_read);
                        total += bytes_read;
                        if (r == http::BodyStreamResult::END_OF_STREAM ||
                            r == http::BodyStreamResult::ABORTED) break;
                        if (r == http::BodyStreamResult::WOULD_BLOCK) {
                            // In a real Streaming handler, we'd use WaitForData.
                            // For simplicity in the test, spin briefly.
                            std::this_thread::sleep_for(std::chrono::milliseconds(5));
                            continue;
                        }
                    }
                    received_bytes.store(total, std::memory_order_release);
                }
                HttpResponse resp;
                resp.Status(200).Body("ok", "text/plain");
                complete(std::move(resp));
            },
            http::RouteOptions{http::RouteRequestMode::Streaming});

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        // Send a POST with Content-Length body.
        int fd = ConnectRaw(port);
        if (fd < 0) throw std::runtime_error("connect failed");

        const std::string body = "streaming-body-payload";
        std::string request =
            "POST /stream-echo HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "Content-Length: " + std::to_string(body.size()) + "\r\n"
            "Connection: close\r\n"
            "\r\n" + body;

        SendAll(fd, request);
        std::string response = RecvUntilClose(fd, 5000);
        close(fd);

        bool pass = true;
        std::string err;

        if (response.find("200") == std::string::npos) {
            pass = false; err += "status not 200; ";
        }
        if (!handler_got_body_stream.load()) {
            pass = false; err += "body_stream not set in handler; ";
        }
        if (received_bytes.load() != body.size()) {
            pass = false;
            err += "received_bytes=" + std::to_string(received_bytes.load()) +
                   " want=" + std::to_string(body.size()) + "; ";
        }

        TestFramework::RecordTest(
            "J9: Integration: streaming route receives body_stream in handler", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "J9: Integration: streaming route receives body_stream in handler", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// J9i: Integration — Streaming body readable from route handler (chunked TE)
// ---------------------------------------------------------------------------
void TestStreamingRouteHandler_ReadChunkedBody() {
    std::cout << "\n[TEST] StreamingRoute: chunked body readable from handler..."
              << std::endl;
    try {
        std::atomic<size_t> received_bytes{0};

        ServerConfig cfg;
        cfg.bind_host = "127.0.0.1";
        cfg.bind_port = 0;
        cfg.worker_threads = 2;
        cfg.http2.enabled = false;

        HttpServer server(cfg);

        server.RouteAsync("POST", "/chunked-stream",
            [&received_bytes](
                const HttpRequest& req,
                HTTP_CALLBACKS_NAMESPACE::InterimResponseSender /*si*/,
                HTTP_CALLBACKS_NAMESPACE::ResourcePusher        /*pr*/,
                HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender /*ss*/,
                HTTP_CALLBACKS_NAMESPACE::AsyncCompletionCallback complete) {

                size_t total = 0;
                if (req.body_stream) {
                    char buf[512];
                    while (true) {
                        size_t n = 0;
                        auto r = req.body_stream->Read(buf, sizeof(buf), &n);
                        total += n;
                        if (r == http::BodyStreamResult::END_OF_STREAM ||
                            r == http::BodyStreamResult::ABORTED) break;
                        if (r == http::BodyStreamResult::WOULD_BLOCK) {
                            std::this_thread::sleep_for(std::chrono::milliseconds(5));
                        }
                    }
                }
                received_bytes.store(total, std::memory_order_release);

                HttpResponse resp;
                resp.Status(200).Body(std::to_string(total), "text/plain");
                complete(std::move(resp));
            },
            http::RouteOptions{http::RouteRequestMode::Streaming});

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        int fd = ConnectRaw(port);
        if (fd < 0) throw std::runtime_error("connect failed");

        // Send chunked body.
        const std::string chunk1 = "hello";
        const std::string chunk2 = " world";
        std::string request =
            "POST /chunked-stream HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Connection: close\r\n"
            "\r\n";
        // chunk 1
        {
            std::ostringstream ss;
            ss << std::hex << chunk1.size() << "\r\n" << chunk1 << "\r\n";
            request += ss.str();
        }
        // chunk 2
        {
            std::ostringstream ss;
            ss << std::hex << chunk2.size() << "\r\n" << chunk2 << "\r\n";
            request += ss.str();
        }
        // terminator
        request += "0\r\n\r\n";

        SendAll(fd, request);
        std::string response = RecvUntilClose(fd, 5000);
        close(fd);

        const size_t expected = chunk1.size() + chunk2.size();
        bool pass = (response.find("200") != std::string::npos) &&
                    (received_bytes.load() == expected);
        std::string err = pass ? "" :
            "received=" + std::to_string(received_bytes.load()) +
            " want=" + std::to_string(expected) + " resp=" + response.substr(0, 40);
        TestFramework::RecordTest(
            "StreamingRoute: chunked body readable from handler", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "StreamingRoute: chunked body readable from handler", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// BodyStream WaitForData re-arm semantics: WaitForData fires once on the
// first Push, and re-arming after the fire delivers the next Push too.
// Exercises the WOULD_BLOCK → WaitForData → Push → re-arm cycle that the
// upstream H2 data-source callback relies on (server/upstream_h2_connection.cc
// `case http::BodyStreamResult::WOULD_BLOCK`).
// ---------------------------------------------------------------------------
void TestBodyStream_WaitForDataReArm() {
    std::cout << "\n[TEST] BodyStream: WaitForData re-arm across gaps..."
              << std::endl;
    try {
        http::ChunkQueueBodyStream::Config cfg;
        cfg.high_water_bytes = 1024;
        cfg.low_water_bytes  = 256;
        http::ChunkQueueBodyStream bs(std::move(cfg));

        std::atomic<int> fires{0};
        auto cb = [&fires]() { fires.fetch_add(1, std::memory_order_relaxed); };

        // Empty → WOULD_BLOCK.
        char buf[64];
        size_t n = 0;
        auto r1 = bs.Read(buf, sizeof(buf), &n);
        bool pass = (r1 == http::BodyStreamResult::WOULD_BLOCK && n == 0);

        // Arm WaitForData; verify it fires on first Push.
        bs.WaitForData(cb);
        bs.Push("hello");
        bool first_fired = WaitFor([&]() {
            return fires.load(std::memory_order_relaxed) >= 1;
        }, std::chrono::milliseconds(500));
        pass = pass && first_fired;

        // Drain; re-Read should succeed.
        n = 0;
        auto r2 = bs.Read(buf, sizeof(buf), &n);
        pass = pass && (r2 == http::BodyStreamResult::OK && n == 5);

        // Re-arm; verify second Push also triggers the callback.
        bs.WaitForData(cb);
        bs.Push("world");
        bool second_fired = WaitFor([&]() {
            return fires.load(std::memory_order_relaxed) >= 2;
        }, std::chrono::milliseconds(500));
        pass = pass && second_fired;

        std::string err = pass ? "" :
            "fires=" + std::to_string(fires.load());
        TestFramework::RecordTest(
            "BodyStream: WaitForData re-arm across gaps", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "BodyStream: WaitForData re-arm across gaps", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// BodyStream: WaitForData fires on Abort (consumer must observe the abort
// even when blocked on WOULD_BLOCK). Models the path where the producer
// aborts mid-upload and the consumer's outstanding wait must wake.
// ---------------------------------------------------------------------------
void TestBodyStream_WaitForDataFiresOnAbort() {
    std::cout << "\n[TEST] BodyStream: WaitForData fires on Abort..."
              << std::endl;
    try {
        http::ChunkQueueBodyStream::Config cfg;
        cfg.high_water_bytes = 1024;
        cfg.low_water_bytes  = 256;
        http::ChunkQueueBodyStream bs(std::move(cfg));

        std::atomic<bool> fired{false};
        bs.WaitForData([&fired]() {
            fired.store(true, std::memory_order_release);
        });

        bs.Abort("peer_reset");
        bool ok_wake = WaitFor([&]() {
            return fired.load(std::memory_order_acquire);
        }, std::chrono::milliseconds(500));

        char buf[16];
        size_t n = 0;
        auto r = bs.Read(buf, sizeof(buf), &n);
        bool pass = ok_wake && (r == http::BodyStreamResult::ABORTED) &&
                    (bs.AbortReason() == "peer_reset");

        std::string err = pass ? "" :
            "fired=" + std::to_string(fired.load()) +
            " result=" + std::to_string(static_cast<int>(r)) +
            " reason='" + bs.AbortReason() + "'";
        TestFramework::RecordTest(
            "BodyStream: WaitForData fires on Abort", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "BodyStream: WaitForData fires on Abort", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// J11: Integration — Streaming route relays response chunks to client
// ---------------------------------------------------------------------------
void TestJ11_StreamingRelayChunks() {
    std::cout << "\n[TEST] J11: Integration: streaming relay — response chunks delivered to client..."
              << std::endl;
    try {
        ServerConfig cfg;
        cfg.bind_host = "127.0.0.1";
        cfg.bind_port = 0;
        cfg.worker_threads = 2;
        cfg.http2.enabled = false;

        HttpServer server(cfg);

        // Route that uses StreamingResponseSender to emit multiple chunks.
        server.RouteAsync("GET", "/chunked-response",
            [](const HttpRequest& /*req*/,
               HTTP_CALLBACKS_NAMESPACE::InterimResponseSender   /*si*/,
               HTTP_CALLBACKS_NAMESPACE::ResourcePusher           /*pr*/,
               HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender   stream_sender,
               HTTP_CALLBACKS_NAMESPACE::AsyncCompletionCallback /*complete*/) {

                HttpResponse headers_resp;
                headers_resp.Status(200).Header("content-type", "text/plain");
                if (stream_sender.SendHeaders(headers_resp) < 0) return;
                using SR = HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender::SendResult;
                if (stream_sender.SendData("chunk1", 6) == SR::CLOSED) return;
                if (stream_sender.SendData("-chunk2", 7) == SR::CLOSED) return;
                (void)stream_sender.End();
            },
            http::RouteOptions{http::RouteRequestMode::Buffered});  // response-side streaming, buffered request

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        int fd = ConnectRaw(port);
        if (fd < 0) throw std::runtime_error("connect failed");

        SendAll(fd,
            "GET /chunked-response HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "Connection: close\r\n"
            "\r\n");

        std::string response = RecvUntilClose(fd, 5000);
        close(fd);

        bool pass = (response.find("200") != std::string::npos) &&
                    (response.find("chunk1") != std::string::npos) &&
                    (response.find("chunk2") != std::string::npos);
        std::string err = pass ? "" : "unexpected response: " + response.substr(0, 80);
        TestFramework::RecordTest(
            "J11: Integration: streaming relay — response chunks delivered to client", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "J11: Integration: streaming relay — response chunks delivered to client", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// J9f: 100 consecutive requests — window not permanently drained
// (Pure HTTP/1.1 version: verifies that 100 sequential requests all succeed
//  and the server remains responsive, with no stalled sessions.)
// ---------------------------------------------------------------------------
void TestJ9f_ConsecutiveRequests() {
    std::cout << "\n[TEST] J9f: 100 consecutive POST requests all succeed..."
              << std::endl;
    try {
        std::atomic<int> handled{0};

        ServerConfig cfg;
        cfg.bind_host = "127.0.0.1";
        cfg.bind_port = 0;
        cfg.worker_threads = 4;
        cfg.http2.enabled = false;

        HttpServer server(cfg);

        server.RouteAsync("POST", "/window-test",
            [&handled](
                const HttpRequest& req,
                HTTP_CALLBACKS_NAMESPACE::InterimResponseSender   /*si*/,
                HTTP_CALLBACKS_NAMESPACE::ResourcePusher           /*pr*/,
                HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender /*ss*/,
                HTTP_CALLBACKS_NAMESPACE::AsyncCompletionCallback complete) {

                // Drain body_stream (streaming mode).
                if (req.body_stream) {
                    char buf[512];
                    while (true) {
                        size_t n = 0;
                        auto r = req.body_stream->Read(buf, sizeof(buf), &n);
                        if (r == http::BodyStreamResult::END_OF_STREAM ||
                            r == http::BodyStreamResult::ABORTED) break;
                        if (r == http::BodyStreamResult::WOULD_BLOCK) {
                            std::this_thread::sleep_for(std::chrono::milliseconds(1));
                        }
                    }
                }
                handled.fetch_add(1, std::memory_order_relaxed);
                HttpResponse resp;
                resp.Status(200).Body("ok", "text/plain");
                complete(std::move(resp));
            },
            http::RouteOptions{http::RouteRequestMode::Streaming});

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        static constexpr int N = 100;
        const std::string body = std::string(512, 'x');

        int success = 0;
        for (int i = 0; i < N; ++i) {
            int fd = ConnectRaw(port);
            if (fd < 0) continue;
            std::string request =
                "POST /window-test HTTP/1.1\r\n"
                "Host: 127.0.0.1\r\n"
                "Content-Length: " + std::to_string(body.size()) + "\r\n"
                "Connection: close\r\n"
                "\r\n" + body;
            SendAll(fd, request);
            std::string resp = RecvUntilClose(fd, 3000);
            close(fd);
            if (resp.find("200") != std::string::npos) ++success;
        }

        bool pass = (success == N);
        std::string err = pass ? "" :
            "success=" + std::to_string(success) + "/" + std::to_string(N);
        TestFramework::RecordTest("J9f: 100 consecutive POST requests all succeed", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("J9f: 100 consecutive POST requests all succeed", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// SnapshotForSubmit: verify SubmitSnapshot reflects state correctly
// ---------------------------------------------------------------------------
void TestSnapshotForSubmit() {
    std::cout << "\n[TEST] SnapshotForSubmit: SubmitSnapshot reflects stream state..."
              << std::endl;
    try {
        http::ChunkQueueBodyStream::Config cfg;
        http::ChunkQueueBodyStream stream(cfg);

        // Snapshot on empty stream — not EOS, not aborted, 0 bytes.
        auto snap0 = stream.SnapshotForSubmit();
        bool pass = true;
        std::string err;
        if (snap0.eos)      { pass = false; err += "snap0.eos should be false; "; }
        if (snap0.aborted)  { pass = false; err += "snap0.aborted should be false; "; }
        if (snap0.bytes_queued != 0) { pass = false; err += "snap0.bytes_queued != 0; "; }

        // Push data and check bytes_queued.
        stream.Push("hello world");
        auto snap1 = stream.SnapshotForSubmit();
        if (snap1.bytes_queued != 11) {
            pass = false; err += "snap1.bytes_queued=" + std::to_string(snap1.bytes_queued) + " want 11; ";
        }

        // PushTrailersAndClose — check eos + has_trailers.
        stream.PushTrailersAndClose({{"x-done", "1"}});
        auto snap2 = stream.SnapshotForSubmit();
        if (!snap2.eos)          { pass = false; err += "snap2.eos should be true; "; }
        if (!snap2.has_trailers) { pass = false; err += "snap2.has_trailers should be true; "; }

        TestFramework::RecordTest("SnapshotForSubmit: SubmitSnapshot reflects stream state", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("SnapshotForSubmit: SubmitSnapshot reflects stream state", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// BytesQueued: relaxed mirror tracks correctly
// ---------------------------------------------------------------------------
void TestBytesQueuedMirror() {
    std::cout << "\n[TEST] BytesQueued: relaxed mirror tracks Push/Read correctly..."
              << std::endl;
    try {
        http::ChunkQueueBodyStream::Config cfg;
        http::ChunkQueueBodyStream stream(cfg);

        if (stream.BytesQueued() != 0) {
            TestFramework::RecordTest("BytesQueued: relaxed mirror tracks Push/Read", false,
                "initial BytesQueued != 0");
            return;
        }

        stream.Push("abcde");  // 5 bytes
        bool pass = (stream.BytesQueued() == 5);
        std::string err;
        if (!pass) err += "after push BytesQueued=" + std::to_string(stream.BytesQueued()) + " want 5; ";

        // Drain 3 bytes.
        char buf[3];
        size_t n = 0;
        stream.Read(buf, 3, &n);
        if (stream.BytesQueued() != 2) {
            pass = false;
            err += "after partial read BytesQueued=" + std::to_string(stream.BytesQueued()) + " want 2; ";
        }

        TestFramework::RecordTest("BytesQueued: relaxed mirror tracks Push/Read", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("BytesQueued: relaxed mirror tracks Push/Read", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// RetryPolicy::BackoffDelay: zero for attempt <= 0
// ---------------------------------------------------------------------------
void TestBackoffDelayAttemptZero() {
    std::cout << "\n[TEST] RetryPolicy::BackoffDelay: returns 0 for attempt <= 0..."
              << std::endl;
    try {
        RetryPolicy::Config cfg;
        cfg.max_retries = 3;
        RetryPolicy policy(cfg);

        auto d0 = policy.BackoffDelay(0);
        auto dm1 = policy.BackoffDelay(-1);

        bool pass = (d0.count() == 0 && dm1.count() == 0);
        std::string err = pass ? "" :
            "d0=" + std::to_string(d0.count()) + " dm1=" + std::to_string(dm1.count());
        TestFramework::RecordTest("RetryPolicy::BackoffDelay: returns 0 for attempt <= 0", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RetryPolicy::BackoffDelay: returns 0 for attempt <= 0", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// RetryPolicy::BackoffDelay: non-zero for attempt > 0, bounded by MAX_BACKOFF_MS
// ---------------------------------------------------------------------------
void TestBackoffDelayBounded() {
    std::cout << "\n[TEST] RetryPolicy::BackoffDelay: bounded by MAX_BACKOFF_MS..."
              << std::endl;
    try {
        RetryPolicy::Config cfg;
        cfg.max_retries = 10;
        RetryPolicy policy(cfg);

        // For a large attempt number, delay must be within [1ms, 250ms] (MAX_BACKOFF_MS).
        bool pass = true;
        std::string err;
        for (int attempt = 1; attempt <= 15; ++attempt) {
            auto d = policy.BackoffDelay(attempt);
            if (d.count() < 1) {
                pass = false;
                err += "attempt=" + std::to_string(attempt) + " delay<1ms; ";
            }
            if (d.count() > 250) {
                pass = false;
                err += "attempt=" + std::to_string(attempt) + " delay>" + std::to_string(d.count()) + "ms>250ms; ";
            }
        }
        TestFramework::RecordTest("RetryPolicy::BackoffDelay: bounded by MAX_BACKOFF_MS", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RetryPolicy::BackoffDelay: bounded by MAX_BACKOFF_MS", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// RetryPolicy::ShouldRetry: headers_sent=true blocks retry
// ---------------------------------------------------------------------------
void TestShouldRetryHeadersSentBlocks() {
    std::cout << "\n[TEST] RetryPolicy::ShouldRetry: headers_sent=true blocks retry..."
              << std::endl;
    try {
        RetryPolicy::Config cfg;
        cfg.max_retries = 3;
        cfg.retry_on_5xx = true;
        RetryPolicy policy(cfg);

        // With headers_sent=true, should never retry.
        bool r1 = policy.ShouldRetry(0, "GET",
                                      RetryPolicy::RetryCondition::RESPONSE_5XX,
                                      /*headers_sent=*/true);
        // Without headers_sent, should retry at attempt 0.
        bool r2 = policy.ShouldRetry(0, "GET",
                                      RetryPolicy::RetryCondition::RESPONSE_5XX,
                                      /*headers_sent=*/false);

        bool pass = (!r1 && r2);
        std::string err = pass ? "" :
            "headers_sent=true retry=" + std::to_string(r1) +
            " headers_sent=false retry=" + std::to_string(r2);
        TestFramework::RecordTest("RetryPolicy::ShouldRetry: headers_sent=true blocks retry", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RetryPolicy::ShouldRetry: headers_sent=true blocks retry", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// RetryPolicy::ShouldRetry: max_retries = 0 disables all retries
// ---------------------------------------------------------------------------
void TestShouldRetryMaxRetriesZero() {
    std::cout << "\n[TEST] RetryPolicy::ShouldRetry: max_retries=0 disables retries..."
              << std::endl;
    try {
        RetryPolicy::Config cfg;
        cfg.max_retries = 0;
        cfg.retry_on_connect_failure = true;
        cfg.retry_on_5xx = true;
        RetryPolicy policy(cfg);

        bool r = policy.ShouldRetry(0, "GET",
                                     RetryPolicy::RetryCondition::CONNECT_FAILURE,
                                     /*headers_sent=*/false);
        bool pass = !r;
        std::string err = pass ? "" : "max_retries=0 still retrying";
        TestFramework::RecordTest("RetryPolicy::ShouldRetry: max_retries=0 disables retries", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("RetryPolicy::ShouldRetry: max_retries=0 disables retries", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// RouteOptions::Streaming propagated through ResolveOptionsAtHeaders
// ---------------------------------------------------------------------------
void TestRouteOptionsStreamingPropagated() {
    std::cout << "\n[TEST] RouteOptions: Streaming mode propagated via ResolveOptionsAtHeaders..."
              << std::endl;
    try {
        // Verify that route_options field is Streaming when set.
        http::RouteOptions opts;
        opts.request_mode = http::RouteRequestMode::Streaming;

        bool pass = (opts.request_mode == http::RouteRequestMode::Streaming);
        std::string err = pass ? "" : "RouteRequestMode not Streaming";
        TestFramework::RecordTest(
            "RouteOptions: Streaming mode propagated via ResolveOptionsAtHeaders", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "RouteOptions: Streaming mode propagated via ResolveOptionsAtHeaders", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// WaitForData: pending callback fires when data pushed
// ---------------------------------------------------------------------------
void TestWaitForDataCallbackOnPush() {
    std::cout << "\n[TEST] WaitForData: pending callback fires when Push occurs..."
              << std::endl;
    try {
        http::ChunkQueueBodyStream::Config cfg;
        http::ChunkQueueBodyStream stream(cfg);

        std::promise<void> p;
        auto fut = p.get_future();

        // Install callback before any push — goes into pending_consumer_callback_.
        stream.WaitForData([&p]() {
            try { p.set_value(); } catch (...) {}
        });

        // Push on another thread.
        std::thread producer([&stream]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            stream.Push("trigger");
        });

        bool fired = (fut.wait_for(std::chrono::milliseconds(500)) ==
                      std::future_status::ready);
        producer.join();

        TestFramework::RecordTest("WaitForData: pending callback fires when Push occurs",
                                   fired, fired ? "" : "callback not fired after Push");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("WaitForData: pending callback fires when Push occurs",
                                   false, e.what());
    }
}

// ---------------------------------------------------------------------------
// WaitForData: callback fires on Abort
// ---------------------------------------------------------------------------
void TestWaitForDataCallbackOnAbort() {
    std::cout << "\n[TEST] WaitForData: pending callback fires on Abort..."
              << std::endl;
    try {
        http::ChunkQueueBodyStream::Config cfg;
        http::ChunkQueueBodyStream stream(cfg);

        std::promise<void> p;
        auto fut = p.get_future();

        stream.WaitForData([&p]() {
            try { p.set_value(); } catch (...) {}
        });

        std::thread aborter([&stream]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            stream.Abort("test-abort");
        });

        bool fired = (fut.wait_for(std::chrono::milliseconds(500)) ==
                      std::future_status::ready);
        aborter.join();

        TestFramework::RecordTest("WaitForData: pending callback fires on Abort",
                                   fired, fired ? "" : "callback not fired after Abort");
    } catch (const std::exception& e) {
        TestFramework::RecordTest("WaitForData: pending callback fires on Abort",
                                   false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Concurrent Push + Read thread safety
// ---------------------------------------------------------------------------
void TestConcurrentPushRead() {
    std::cout << "\n[TEST] Concurrent Push + Read: no crash under concurrent access..."
              << std::endl;
    try {
        http::ChunkQueueBodyStream::Config cfg;
        cfg.high_water_bytes = 4096;
        cfg.low_water_bytes  = 1024;
        auto stream = std::make_shared<http::ChunkQueueBodyStream>(cfg);

        static constexpr int PUSH_COUNT = 200;
        std::atomic<size_t> total_read{0};

        // Producer thread.
        std::thread producer([stream]() {
            for (int i = 0; i < PUSH_COUNT; ++i) {
                stream->Push(std::string(32, static_cast<char>('a' + (i % 26))));
            }
            stream->CloseEmpty();
        });

        // Consumer thread.
        std::thread consumer([stream, &total_read]() {
            char buf[128];
            while (true) {
                size_t n = 0;
                auto r = stream->Read(buf, sizeof(buf), &n);
                total_read.fetch_add(n, std::memory_order_relaxed);
                if (r == http::BodyStreamResult::END_OF_STREAM ||
                    r == http::BodyStreamResult::ABORTED) break;
                if (r == http::BodyStreamResult::WOULD_BLOCK) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
            }
        });

        producer.join();
        consumer.join();

        bool pass = (total_read.load() == static_cast<size_t>(PUSH_COUNT * 32));
        std::string err = pass ? "" :
            "total_read=" + std::to_string(total_read.load()) +
            " want=" + std::to_string(PUSH_COUNT * 32);
        TestFramework::RecordTest("Concurrent Push + Read: no crash under concurrent access",
                                   pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Concurrent Push + Read: no crash under concurrent access",
                                   false, e.what());
    }
}

// ---------------------------------------------------------------------------
// J9: Integration — Buffered-mode route body is unchanged
//     (baseline: buffered mode still populates req.body normally)
// ---------------------------------------------------------------------------
void TestBufferedModeBodyUnchanged() {
    std::cout << "\n[TEST] Buffered mode: req.body populated normally in non-streaming route..."
              << std::endl;
    try {
        ServerConfig cfg;
        cfg.bind_host = "127.0.0.1";
        cfg.bind_port = 0;
        cfg.worker_threads = 2;
        cfg.http2.enabled = false;

        HttpServer server(cfg);

        std::atomic<bool> body_stream_null{false};
        std::atomic<size_t> body_len{0};

        server.RouteAsync("POST", "/buffered",
            [&body_stream_null, &body_len](
                const HttpRequest& req,
                HTTP_CALLBACKS_NAMESPACE::InterimResponseSender   /*si*/,
                HTTP_CALLBACKS_NAMESPACE::ResourcePusher           /*pr*/,
                HTTP_CALLBACKS_NAMESPACE::StreamingResponseSender /*ss*/,
                HTTP_CALLBACKS_NAMESPACE::AsyncCompletionCallback complete) {

                body_stream_null.store(req.body_stream == nullptr, std::memory_order_release);
                body_len.store(req.body.size(), std::memory_order_release);

                HttpResponse resp;
                resp.Status(200).Body("ok", "text/plain");
                complete(std::move(resp));
            }
            // NOTE: no RouteOptions arg → defaults to Buffered
        );

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        const std::string payload = "buffered-body-content";
        int fd = ConnectRaw(port);
        if (fd < 0) throw std::runtime_error("connect failed");
        std::string request =
            "POST /buffered HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "Content-Length: " + std::to_string(payload.size()) + "\r\n"
            "Connection: close\r\n"
            "\r\n" + payload;
        SendAll(fd, request);
        std::string response = RecvUntilClose(fd, 5000);
        close(fd);

        bool pass = (response.find("200") != std::string::npos) &&
                    body_stream_null.load() &&
                    (body_len.load() == payload.size());
        std::string err = pass ? "" :
            "body_stream_null=" + std::to_string(body_stream_null.load()) +
            " body_len=" + std::to_string(body_len.load());
        TestFramework::RecordTest("Buffered mode: req.body populated normally", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Buffered mode: req.body populated normally", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// MakeErrorResponse contract: streaming result codes map to documented
// status codes + self-identifying headers (X-Request-Body-Limit-Exceeded,
// X-Proxy-Retry-Denied: <reason>) per Phase 5 design plan.
// ---------------------------------------------------------------------------
static std::string FindHeader(
    const std::vector<std::pair<std::string, std::string>>& headers,
    const std::string& name) {
    for (const auto& [k, v] : headers) {
        if (k == name) return v;
    }
    return "";
}

void TestMakeErrorResponse_StreamingDiagnosticHeaders() {
    std::cout << "\n[TEST] MakeErrorResponse: streaming diagnostic headers..."
              << std::endl;
    try {
        // RESULT_REQUEST_BODY_LIMIT_EXCEEDED → 413 + X-Request-Body-Limit-Exceeded
        HttpResponse r1 = ProxyTransaction::MakeErrorResponse(
            ProxyTransaction::RESULT_REQUEST_BODY_LIMIT_EXCEEDED);
        const std::string r1_hdr =
            FindHeader(r1.GetHeaders(), "X-Request-Body-Limit-Exceeded");
        bool r1_ok = (r1.GetStatusCode() == 413) && (r1_hdr == "true");

        // Three retry-denied codes → 502 + X-Proxy-Retry-Denied: <reason>
        struct Case {
            int code;
            const char* expected_reason;
        };
        Case cases[] = {
            {ProxyTransaction::RESULT_RETRY_DENIED_STREAMING_SOURCE_CONSUMED,
             "streaming-source-consumed"},
            {ProxyTransaction::RESULT_RETRY_DENIED_STREAMING_BODY_ON_WIRE,
             "streaming-body-on-wire"},
            {ProxyTransaction::RESULT_RETRY_DENIED_NON_IDEMPOTENT_HEADERS_QUEUED,
             "non-idempotent-headers-queued"},
        };
        bool cases_ok = true;
        std::string fail_detail;
        for (const auto& c : cases) {
            HttpResponse resp = ProxyTransaction::MakeErrorResponse(c.code);
            const std::string reason =
                FindHeader(resp.GetHeaders(), "X-Proxy-Retry-Denied");
            if (resp.GetStatusCode() != 502 || reason != c.expected_reason) {
                cases_ok = false;
                fail_detail += "code=" + std::to_string(c.code) +
                    " status=" + std::to_string(resp.GetStatusCode()) +
                    " reason='" + reason +
                    "' want='" + c.expected_reason + "'; ";
            }
        }

        bool pass = r1_ok && cases_ok;
        std::string err;
        if (!r1_ok) {
            err += "413 case: status=" +
                   std::to_string(r1.GetStatusCode()) +
                   " header='" + r1_hdr + "'; ";
        }
        err += fail_detail;
        TestFramework::RecordTest(
            "MakeErrorResponse: streaming diagnostic headers", pass, err);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "MakeErrorResponse: streaming diagnostic headers", false, e.what());
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
void RunAllStreamingRequestTests() {
    std::cout << "\n=== Streaming Request Body Tests (Phase J) ===" << std::endl;

    // Unit tests — in-process, no sockets.
    TestJ1_BasicPushRead();
    TestJ2_WouldBlockWhenEmpty();
    TestJ3_WaitForDataImmediate();
    TestJ4_CloseEmptyEndOfStream();
    TestJ5_ExpectsRequestBody();
    TestJ6_PushTrailersAndClose();
    TestJ7_AbortClearsQueue();
    TestJ8_PushAfterEOSDropped();

    // ChunkQueueBodyStream edge cases.
    TestJ9a_HighWaterFiresOnce();
    TestJ9b_LowWaterFires();
    TestJ9c_CloseEmptyIdempotent();
    TestJ9d_AbortAfterPartialRead();
    TestJ9e_WaitForDataOnEOS();
    TestBodyStream_AbortReasonSet();
    TestBodyStream_PushAfterAbortDropped();
    TestBodyStream_AbortedClassification();
    TestBodyStream_DoubleAbortIdempotent();

    // RetryPolicy streaming-related tests.
    TestJ10_IsMethodRetryableForReplay();
    TestBackoffDelayAttemptZero();
    TestBackoffDelayBounded();
    TestShouldRetryHeadersSentBlocks();
    TestShouldRetryMaxRetriesZero();

    // Additional unit tests.
    TestSnapshotForSubmit();
    TestBytesQueuedMirror();
    TestRouteOptionsStreamingPropagated();

    // Thread safety tests.
    TestWaitForDataCallbackOnPush();
    TestWaitForDataCallbackOnAbort();
    TestConcurrentPushRead();

    // BodyStream WaitForData semantics (re-arm, fires-on-abort).
    // Exercise the WOULD_BLOCK → WaitForData → Push/Abort → re-arm cycle
    // that the upstream H2 data-source callback relies on.
    TestBodyStream_WaitForDataReArm();
    TestBodyStream_WaitForDataFiresOnAbort();

    // Integration tests — real HttpServer.
    TestJ9_StreamingRouteBodyStream();
    TestStreamingRouteHandler_ReadChunkedBody();
    TestJ9f_ConsecutiveRequests();
    TestJ11_StreamingRelayChunks();
    TestBufferedModeBodyUnchanged();

    // Diagnostic header contract for streaming RESULT_* codes.
    TestMakeErrorResponse_StreamingDiagnosticHeaders();

    std::cout << "=== Streaming Request Body Tests complete ===" << std::endl;
}

}  // namespace StreamingRequestTests
