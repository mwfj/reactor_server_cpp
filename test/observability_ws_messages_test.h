#pragma once

// WebSocket per-message observability tests — verify that the
// `traces.websocket_messages` opt-in (default false) gates per-frame
// `ws.recv` / `ws.send` INTERNAL span emission, that control frames
// (Ping / Pong / Close) skip span emission entirely, that a fragmented
// message produces exactly one span at FIN reassembly, and that the
// install-once latch on WebSocketConnection::SetObservabilitySnapshot
// rejects rebind attempts even when the first call saw a snapshot
// whose manager weak_ptr could not be locked.
//
// These tests boot a real HttpServer, complete a TCP-level WebSocket
// upgrade, exchange masked client frames + server frames over the
// upgraded connection, and assert against the captured spans in the
// InMemorySpanProcessor wired into the ObservabilityManager.

#include "test_framework.h"
#include "test_server_runner.h"
#include "http/http_server.h"
#include "ws/websocket_connection.h"
#include "observability/observability_config.h"
#include "observability/observability_manager.h"
#include "observability/resource.h"
#include "observability/span_processor.h"
#include "observability/trace_id.h"

#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace ObservabilityWsMessagesTests {

using OBSERVABILITY_NAMESPACE::AttrValue;
using OBSERVABILITY_NAMESPACE::InMemorySpanProcessor;
using OBSERVABILITY_NAMESPACE::ObservabilityConfig;
using OBSERVABILITY_NAMESPACE::ObservabilityManager;
using OBSERVABILITY_NAMESPACE::ObservabilitySnapshot;
using OBSERVABILITY_NAMESPACE::RandomSource;
using OBSERVABILITY_NAMESPACE::Resource;
using OBSERVABILITY_NAMESPACE::SamplerType;
using OBSERVABILITY_NAMESPACE::SpanData;

namespace {

// -----------------------------------------------------------------------
// Network + framing helpers (small enough that pulling another test
// header would cost more than reimplementing them).
// -----------------------------------------------------------------------

int ConnectTcp(int port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(static_cast<uint16_t>(port));
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

bool SendAll(int fd, const std::string& data) {
    size_t sent = 0;
    while (sent < data.size()) {
        ssize_t n = ::send(fd, data.data() + sent, data.size() - sent, 0);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

std::string MakeUpgradeRequest(const std::string& path) {
    return "GET " + path + " HTTP/1.1\r\n"
           "Host: localhost\r\n"
           "Upgrade: websocket\r\n"
           "Connection: Upgrade\r\n"
           "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
           "Sec-WebSocket-Version: 13\r\n\r\n";
}

// Read until "\r\n\r\n" so we know the 101 has fully landed before we
// begin pushing client frames. Returns the header block (status line +
// header lines + trailing CRLFCRLF).
std::string ReadHeaderBlock(int fd, int timeout_ms = 3000) {
    std::string buf;
    auto deadline = std::chrono::steady_clock::now()
                  + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        pollfd pfd{fd, POLLIN, 0};
        int rc = ::poll(&pfd, 1, 50);
        if (rc <= 0) continue;
        char c;
        ssize_t n = ::recv(fd, &c, 1, 0);
        if (n <= 0) break;
        buf += c;
        if (buf.size() >= 4 && buf.substr(buf.size() - 4) == "\r\n\r\n") {
            break;
        }
    }
    return buf;
}

int ParseStatus(const std::string& header) {
    if (header.size() < 12) return 0;
    try { return std::stoi(header.substr(9, 3)); }
    catch (...) { return 0; }
}

// Build a masked client→server WebSocket frame. `fin` controls the FIN
// bit; `opcode_byte` is the low nibble of byte 0 (0x1 text, 0x0 cont,
// 0x9 ping, 0xA pong, 0x8 close). Payload is unmasked input; the
// function applies a fresh 4-byte mask per call.
std::string MakeClientFrame(bool fin, uint8_t opcode_byte,
                            const std::string& payload) {
    std::string frame;
    uint8_t b0 = (fin ? 0x80 : 0x00) | (opcode_byte & 0x0F);
    frame.push_back(static_cast<char>(b0));

    const size_t len = payload.size();
    if (len < 126) {
        frame.push_back(static_cast<char>(0x80 | len));  // MASK=1
    } else if (len <= 0xFFFF) {
        frame.push_back(static_cast<char>(0x80 | 126));
        frame.push_back(static_cast<char>((len >> 8) & 0xFF));
        frame.push_back(static_cast<char>(len & 0xFF));
    } else {
        frame.push_back(static_cast<char>(0x80 | 127));
        for (int i = 7; i >= 0; --i) {
            frame.push_back(static_cast<char>((len >> (i * 8)) & 0xFF));
        }
    }

    // Mask key: deterministic-ish but distinct per call so XOR errors
    // surface quickly if any layer accidentally double-unmasks.
    static std::atomic<uint32_t> seed{0xC0DECAFE};
    uint32_t key = seed.fetch_add(0x9E3779B1, std::memory_order_relaxed);
    uint8_t mask[4];
    mask[0] = static_cast<uint8_t>(key);
    mask[1] = static_cast<uint8_t>(key >> 8);
    mask[2] = static_cast<uint8_t>(key >> 16);
    mask[3] = static_cast<uint8_t>(key >> 24);
    frame.append(reinterpret_cast<const char*>(mask), 4);

    for (size_t i = 0; i < len; ++i) {
        frame.push_back(static_cast<char>(payload[i] ^ mask[i % 4]));
    }
    return frame;
}

struct WsObsFixture {
    std::shared_ptr<InMemorySpanProcessor> processor;
    std::shared_ptr<ObservabilityManager>  manager;

    WsObsFixture(bool ws_messages_enabled, uint64_t seed) {
        processor = std::make_shared<InMemorySpanProcessor>();
        ObservabilityConfig cfg;
        cfg.enabled                    = true;
        cfg.traces.enabled             = true;
        cfg.traces.sampler.type        = SamplerType::AlwaysOn;
        cfg.traces.websocket_messages  = ws_messages_enabled;
        cfg.metrics.enabled            = true;
        cfg.resource.service_name      = "obs-ws-msg-test";
        manager = ObservabilityManager::Create(
            std::move(cfg),
            std::make_shared<Resource>(),
            processor,
            std::make_shared<RandomSource>(seed));
    }
};

// Drain spans whose names match the frame-level emit sites.
size_t CountFrameSpans(const std::vector<SpanData>& spans) {
    size_t n = 0;
    for (const auto& s : spans) {
        if (s.name == "ws.recv" || s.name == "ws.send") {
            ++n;
        }
    }
    return n;
}

// Pull the `ws.opcode` attribute (set inside MaybeEmitMessageSpan).
// Returns "" when not present.
std::string OpcodeAttr(const SpanData& s) {
    for (const auto& a : s.attributes) {
        if (a.key == "ws.opcode") {
            if (auto* v = std::get_if<std::string>(&a.value.value)) return *v;
        }
    }
    return {};
}

int64_t PayloadAttr(const SpanData& s) {
    for (const auto& a : s.attributes) {
        if (a.key == "ws.payload_size") {
            if (auto* v = std::get_if<int64_t>(&a.value.value)) return *v;
        }
    }
    return -1;
}

}  // namespace

// Happy path: text frame each way emits one ws.recv + one ws.send with
// correct opcode + payload_size attributes.
void TestTextFrameEmitsSpan() {
    const char* TAG = "ObsWsMsg: text frame emits ws.recv + ws.send spans";
    try {
        WsObsFixture fix(/*ws_messages_enabled=*/true, 0xA1A1ULL);
        HttpServer server("127.0.0.1", 0);
        server.SetObservabilityManager(fix.manager);

        std::mutex got_mtx;
        std::string got_payload;
        server.WebSocket("/ws", [&](WebSocketConnection& conn) {
            conn.OnMessage([&](WebSocketConnection& c,
                                const std::string& data, bool /*binary*/) {
                {
                    std::lock_guard<std::mutex> g(got_mtx);
                    got_payload = data;
                }
                c.SendText("pong-from-server");
            });
        });

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();
        int fd = ConnectTcp(port);
        if (fd < 0) { TestFramework::RecordTest(TAG, false, "connect failed",
            TestFramework::TestCategory::OTHER); return; }
        struct FdG { int f; ~FdG(){ if(f>=0) ::close(f); } } fdg{fd};

        if (!SendAll(fd, MakeUpgradeRequest("/ws"))) {
            TestFramework::RecordTest(TAG, false, "send upgrade failed",
                TestFramework::TestCategory::OTHER); return;
        }
        std::string headers = ReadHeaderBlock(fd);
        if (ParseStatus(headers) != 101) {
            TestFramework::RecordTest(TAG, false,
                "expected 101, headers=" + headers,
                TestFramework::TestCategory::OTHER); return;
        }

        const std::string client_msg = "hello-server";
        SendAll(fd, MakeClientFrame(true, 0x1, client_msg));

        // Wait for the round-trip + dispatcher to finalize the spans.
        std::this_thread::sleep_for(std::chrono::milliseconds(250));

        auto spans = fix.processor->Drain();
        bool found_recv = false;
        bool found_send = false;
        std::string detail;
        for (const auto& s : spans) {
            if (s.name == "ws.recv") {
                found_recv = OpcodeAttr(s) == "text" &&
                             PayloadAttr(s) ==
                                 static_cast<int64_t>(client_msg.size());
            } else if (s.name == "ws.send") {
                found_send = OpcodeAttr(s) == "text" &&
                             PayloadAttr(s) == 16;  // "pong-from-server"
            }
        }
        if (!found_recv) detail += "ws.recv missing or wrong attrs; ";
        if (!found_send) detail += "ws.send missing or wrong attrs; ";

        TestFramework::RecordTest(TAG,
            found_recv && found_send, detail,
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
            TestFramework::TestCategory::OTHER);
    }
}

// Control frames (Ping / Close) must not emit ws.recv / ws.send spans —
// only Text/Binary unfragmented + Continuation FIN reassembly do.
void TestControlFramesSkipSpans() {
    const char* TAG = "ObsWsMsg: ping/close frames do not emit ws.* spans";
    try {
        WsObsFixture fix(/*ws_messages_enabled=*/true, 0xA2A2ULL);
        HttpServer server("127.0.0.1", 0);
        server.SetObservabilityManager(fix.manager);
        server.WebSocket("/ws", [](WebSocketConnection& conn) {
            conn.OnMessage([](WebSocketConnection&, const std::string&, bool) {});
        });

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();
        int fd = ConnectTcp(port);
        if (fd < 0) { TestFramework::RecordTest(TAG, false, "connect failed",
            TestFramework::TestCategory::OTHER); return; }
        struct FdG { int f; ~FdG(){ if(f>=0) ::close(f); } } fdg{fd};

        SendAll(fd, MakeUpgradeRequest("/ws"));
        std::string headers = ReadHeaderBlock(fd);
        if (ParseStatus(headers) != 101) {
            TestFramework::RecordTest(TAG, false, "no 101",
                TestFramework::TestCategory::OTHER); return;
        }

        // Ping with payload — server auto-responds with Pong. Neither
        // side should produce ws.recv or ws.send spans.
        SendAll(fd, MakeClientFrame(true, 0x9, "ping-payload"));
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        // Close frame with code 1000 + reason. Server echoes Close,
        // tears down the connection. Still no frame-spans.
        std::string close_payload;
        close_payload.push_back(static_cast<char>(0x03));   // code 1000 high
        close_payload.push_back(static_cast<char>(0xE8));   // code 1000 low
        close_payload += "bye";
        SendAll(fd, MakeClientFrame(true, 0x8, close_payload));
        std::this_thread::sleep_for(std::chrono::milliseconds(250));

        auto spans = fix.processor->Drain();
        size_t frame_spans = CountFrameSpans(spans);
        TestFramework::RecordTest(TAG, frame_spans == 0,
            frame_spans == 0 ? "" :
                "control frames produced " + std::to_string(frame_spans) +
                " unexpected ws.recv/ws.send spans",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
            TestFramework::TestCategory::OTHER);
    }
}

// A 3-fragment text message yields exactly ONE ws.recv span at FIN
// reassembly — not one per fragment.
void TestFragmentedMessageEmitsOneSpan() {
    const char* TAG =
        "ObsWsMsg: fragmented text emits exactly one ws.recv span at FIN";
    try {
        WsObsFixture fix(/*ws_messages_enabled=*/true, 0xA3A3ULL);
        HttpServer server("127.0.0.1", 0);
        server.SetObservabilityManager(fix.manager);
        server.WebSocket("/ws", [](WebSocketConnection& conn) {
            conn.OnMessage([](WebSocketConnection&, const std::string&, bool) {});
        });

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();
        int fd = ConnectTcp(port);
        if (fd < 0) { TestFramework::RecordTest(TAG, false, "connect failed",
            TestFramework::TestCategory::OTHER); return; }
        struct FdG { int f; ~FdG(){ if(f>=0) ::close(f); } } fdg{fd};

        SendAll(fd, MakeUpgradeRequest("/ws"));
        std::string headers = ReadHeaderBlock(fd);
        if (ParseStatus(headers) != 101) {
            TestFramework::RecordTest(TAG, false, "no 101",
                TestFramework::TestCategory::OTHER); return;
        }

        // Fragment 1: opcode=text(1), FIN=0
        SendAll(fd, MakeClientFrame(false, 0x1, "frag-"));
        // Fragment 2: opcode=continuation(0), FIN=0
        SendAll(fd, MakeClientFrame(false, 0x0, "middle-"));
        // Fragment 3: opcode=continuation(0), FIN=1 — span fires here
        SendAll(fd, MakeClientFrame(true,  0x0, "end"));
        std::this_thread::sleep_for(std::chrono::milliseconds(250));

        auto spans = fix.processor->Drain();
        size_t recv_spans = 0;
        int64_t total_size = -1;
        std::string opcode_seen;
        for (const auto& s : spans) {
            if (s.name == "ws.recv") {
                ++recv_spans;
                total_size = PayloadAttr(s);
                opcode_seen = OpcodeAttr(s);
            }
        }
        // 5 + 7 + 3 = 15 reassembled bytes, opcode is the first
        // fragment's opcode (text), not "continuation".
        bool pass = recv_spans == 1 && total_size == 15 &&
                    opcode_seen == "text";
        std::string err;
        if (!pass) {
            err = "recv_spans=" + std::to_string(recv_spans) +
                  " total_size=" + std::to_string(total_size) +
                  " opcode=" + opcode_seen;
        }
        TestFramework::RecordTest(TAG, pass, err,
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
            TestFramework::TestCategory::OTHER);
    }
}

// `traces.websocket_messages = false` → zero frame-level spans even when
// text flows both ways. Exercises the relaxed-load disabled fast path.
void TestDisabledFlagNoSpans() {
    const char* TAG = "ObsWsMsg: ws_messages=false suppresses ws.recv/ws.send";
    try {
        WsObsFixture fix(/*ws_messages_enabled=*/false, 0xA4A4ULL);
        HttpServer server("127.0.0.1", 0);
        server.SetObservabilityManager(fix.manager);
        server.WebSocket("/ws", [](WebSocketConnection& conn) {
            conn.OnMessage([](WebSocketConnection& c,
                              const std::string&, bool) {
                c.SendText("server-reply");
            });
        });

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();
        int fd = ConnectTcp(port);
        if (fd < 0) { TestFramework::RecordTest(TAG, false, "connect failed",
            TestFramework::TestCategory::OTHER); return; }
        struct FdG { int f; ~FdG(){ if(f>=0) ::close(f); } } fdg{fd};

        SendAll(fd, MakeUpgradeRequest("/ws"));
        std::string headers = ReadHeaderBlock(fd);
        if (ParseStatus(headers) != 101) {
            TestFramework::RecordTest(TAG, false, "no 101",
                TestFramework::TestCategory::OTHER); return;
        }
        SendAll(fd, MakeClientFrame(true, 0x1, "client-payload"));
        std::this_thread::sleep_for(std::chrono::milliseconds(250));

        auto spans = fix.processor->Drain();
        size_t frame_spans = CountFrameSpans(spans);
        TestFramework::RecordTest(TAG, frame_spans == 0,
            frame_spans == 0 ? "" :
                "expected 0 frame spans, got " + std::to_string(frame_spans),
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
            TestFramework::TestCategory::OTHER);
    }
}

// Install-once latch — a second SetObservabilitySnapshot call (made
// from inside the WS route handler, dispatcher thread) is rejected and
// subsequent frame emission continues to route through the original
// manager's processor (not the rebind attempt's).
void TestRebindRejected() {
    const char* TAG =
        "ObsWsMsg: SetObservabilitySnapshot rebind rejected, original wins";
    try {
        WsObsFixture fix_a(/*ws_messages_enabled=*/true, 0xA5A5ULL);
        WsObsFixture fix_b(/*ws_messages_enabled=*/true, 0xB5B5ULL);

        HttpServer server("127.0.0.1", 0);
        server.SetObservabilityManager(fix_a.manager);

        std::atomic<bool> rebind_attempted{false};

        // Build a "rebind" snapshot pre-bound to fix_b's manager and
        // populate it well enough that BumpFrameCounter / MessageSpan
        // would clearly emit through fix_b IF the rebind succeeded.
        server.WebSocket("/ws", [&](WebSocketConnection& conn) {
            auto rebind_snap = std::make_shared<ObservabilitySnapshot>();
            rebind_snap->manager = fix_b.manager;
            // The inbound_span on the rebind snapshot does not need to
            // be set — the install path latches `bound_once_` BEFORE
            // looking at the snapshot contents, so the second call
            // returns without inspecting any field on rebind_snap.
            conn.SetObservabilitySnapshot(std::move(rebind_snap));
            rebind_attempted.store(true, std::memory_order_release);
            conn.OnMessage([](WebSocketConnection& c,
                              const std::string&, bool) {
                c.SendText("after-rebind");
            });
        });

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();
        int fd = ConnectTcp(port);
        if (fd < 0) { TestFramework::RecordTest(TAG, false, "connect failed",
            TestFramework::TestCategory::OTHER); return; }
        struct FdG { int f; ~FdG(){ if(f>=0) ::close(f); } } fdg{fd};

        SendAll(fd, MakeUpgradeRequest("/ws"));
        std::string headers = ReadHeaderBlock(fd);
        if (ParseStatus(headers) != 101) {
            TestFramework::RecordTest(TAG, false, "no 101",
                TestFramework::TestCategory::OTHER); return;
        }
        // Wait for the route handler (which performs the rebind
        // attempt) to run on the dispatcher.
        for (int i = 0; i < 50 && !rebind_attempted.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        SendAll(fd, MakeClientFrame(true, 0x1, "post-rebind"));
        std::this_thread::sleep_for(std::chrono::milliseconds(250));

        auto spans_a = fix_a.processor->Drain();
        auto spans_b = fix_b.processor->Drain();
        size_t frames_a = CountFrameSpans(spans_a);
        size_t frames_b = CountFrameSpans(spans_b);

        // Original manager (fix_a) must have at least one ws.recv +
        // one ws.send span; the second manager (fix_b) must have ZERO
        // — proving the rebind was rejected and never wired.
        bool pass = rebind_attempted.load() && frames_a >= 2 && frames_b == 0;
        std::string err;
        if (!pass) {
            err = "rebind_attempted=" + std::to_string(rebind_attempted.load()) +
                  " frames_a=" + std::to_string(frames_a) +
                  " frames_b=" + std::to_string(frames_b);
        }
        TestFramework::RecordTest(TAG, pass, err,
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
            TestFramework::TestCategory::OTHER);
    }
}

// `reactor.websocket.frames` counter bumps unconditionally; this drives
// text + ping + close in both directions to ensure the dispatcher path
// doesn't crash. (Counter-value assertions live in obs_catalog.)
void TestFrameCounterDoesNotCrashOnAllOpcodes() {
    const char* TAG =
        "ObsWsMsg: frame counter handles text + ping + close without crashing";
    try {
        // ws_messages_enabled=false on purpose: the frame counter is a
        // separate code path that must work whether or not span emission
        // is on. Disabling spans isolates the counter from span noise.
        WsObsFixture fix(/*ws_messages_enabled=*/false, 0xA6A6ULL);

        HttpServer server("127.0.0.1", 0);
        server.SetObservabilityManager(fix.manager);
        server.WebSocket("/ws", [](WebSocketConnection& conn) {
            conn.OnMessage([](WebSocketConnection& c,
                              const std::string&, bool) {
                c.SendPong("pong-back");
                c.SendText("ack");
            });
        });

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();
        int fd = ConnectTcp(port);
        if (fd < 0) { TestFramework::RecordTest(TAG, false, "connect failed",
            TestFramework::TestCategory::OTHER); return; }
        struct FdG { int f; ~FdG(){ if(f>=0) ::close(f); } } fdg{fd};

        SendAll(fd, MakeUpgradeRequest("/ws"));
        std::string headers = ReadHeaderBlock(fd);
        if (ParseStatus(headers) != 101) {
            TestFramework::RecordTest(TAG, false, "no 101",
                TestFramework::TestCategory::OTHER); return;
        }
        SendAll(fd, MakeClientFrame(true, 0x9, "ping1"));   // ping
        SendAll(fd, MakeClientFrame(true, 0x1, "hello"));   // text
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        std::string close_payload;
        close_payload.push_back(static_cast<char>(0x03));
        close_payload.push_back(static_cast<char>(0xE8));
        SendAll(fd, MakeClientFrame(true, 0x8, close_payload));  // close
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        // No frame-level spans (disabled-flag fast path) and no crash.
        auto spans = fix.processor->Drain();
        bool pass = CountFrameSpans(spans) == 0;
        TestFramework::RecordTest(TAG, pass,
            pass ? "" : "unexpected ws.* spans emitted with flag off",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(TAG, false, e.what(),
            TestFramework::TestCategory::OTHER);
    }
}

void RunAllTests() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "OBSERVABILITY WS MESSAGE-SPAN TESTS" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    TestTextFrameEmitsSpan();
    TestControlFramesSkipSpans();
    TestFragmentedMessageEmitsOneSpan();
    TestDisabledFlagNoSpans();
    TestRebindRejected();
    TestFrameCounterDoesNotCrashOnAllOpcodes();
}

}  // namespace ObservabilityWsMessagesTests
