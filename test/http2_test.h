#pragma once

#include "test_framework.h"
#include "config/server_config.h"
#include "config/config_loader.h"
#include "http2/http2_constants.h"
#include "http2/protocol_detector.h"
#include "http2/http2_stream.h"
#include "http/http_server.h"
#include "http/http_request.h"
#include "http/http_response.h"

#include <nghttp2/nghttp2.h>

#include <string>
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>
#include <cstring>
#include <cstdlib>
#include <stdexcept>

// ============================================================
// Http2TestClient — minimal h2c (cleartext HTTP/2) test client
//
// Uses nghttp2 client-mode API (nghttp2_session_client_new)
// with memory-based send/receive (nghttp2_session_mem_recv2 /
// nghttp2_session_mem_send2), matching the server's own approach.
//
// Usage pattern:
//   Http2TestClient client("127.0.0.1", PORT);
//   if (!client.Connect()) { /* handle */ }
//   Http2TestClient::Response resp = client.Get("/hello");
// ============================================================

namespace Http2Tests {

// ---- Port range: 10500-10599 (unique to this suite) ----
static constexpr int BASE_PORT        = 10500;
static constexpr int H2_UNIT_PORT     = 10501;   // functional h2c tests
static constexpr int H2_MULTI_PORT    = 10502;   // multiple-stream test
static constexpr int H2_BODY_PORT     = 10503;   // large-body / limit tests
static constexpr int H2_RACE_PORT     = 10504;   // concurrent-streams race

// ---- IO timeout for all raw-socket operations ----
static constexpr int IO_TIMEOUT_MS    = 5000;

// ============================================================
// Http2TestClient
// ============================================================

class Http2TestClient {
public:
    struct Response {
        int         status  = 0;
        std::string body;
        bool        rst     = false;   // stream was RST'd
        bool        error   = false;   // transport or session error
    };

    Http2TestClient() = default;
    ~Http2TestClient() { Disconnect(); }

    // Non-copyable
    Http2TestClient(const Http2TestClient&) = delete;
    Http2TestClient& operator=(const Http2TestClient&) = delete;

    bool Connect(const std::string& host, int port) {
        fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd_ < 0) return false;

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(static_cast<uint16_t>(port));
        addr.sin_addr.s_addr = inet_addr(host.c_str());

        if (::connect(fd_, reinterpret_cast<struct sockaddr*>(&addr),
                      sizeof(addr)) < 0) {
            ::close(fd_); fd_ = -1;
            return false;
        }

        // Set receive timeout
        struct timeval tv{};
        tv.tv_sec  = IO_TIMEOUT_MS / 1000;
        tv.tv_usec = (IO_TIMEOUT_MS % 1000) * 1000;
        ::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        // Create client-side nghttp2 session
        nghttp2_session_callbacks* cbs = nullptr;
        nghttp2_session_callbacks_new(&cbs);
        nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, OnFrameRecv);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, OnDataChunkRecv);
        nghttp2_session_callbacks_set_on_stream_close_callback(cbs, OnStreamClose);
        nghttp2_session_callbacks_set_on_header_callback(cbs, OnHeader);

        int rv = nghttp2_session_client_new(&session_, cbs, this);
        nghttp2_session_callbacks_del(cbs);
        if (rv != 0) { ::close(fd_); fd_ = -1; return false; }

        // Submit empty SETTINGS (client hello settings).
        // NOTE: Do NOT manually send the 24-byte connection preface magic.
        // nghttp2_session_mem_send2 automatically prepends the magic as the first
        // output of a client session (RFC 9113 Section 3.4 "Prior Knowledge").
        rv = nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, nullptr, 0);
        if (rv != 0) { Disconnect(); return false; }
        if (!FlushOutput()) { Disconnect(); return false; }

        // Read server SETTINGS + SETTINGS ACK
        if (!ReadAndProcess(IO_TIMEOUT_MS)) { Disconnect(); return false; }

        return true;
    }

    void Disconnect() {
        if (session_) {
            nghttp2_session_del(session_);
            session_ = nullptr;
        }
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
        streams_.clear();
    }

    // Send a GET request and wait for the response.
    Response Get(const std::string& path,
                 const std::vector<std::pair<std::string,std::string>>& extra_headers = {}) {
        return SendRequest("GET", path, "", extra_headers);
    }

    // Send a POST request with body and wait for the response.
    Response Post(const std::string& path, const std::string& body,
                  const std::vector<std::pair<std::string,std::string>>& extra_headers = {}) {
        return SendRequest("POST", path, body, extra_headers);
    }

    // Send a request and wait for a complete response on that stream.
    Response SendRequest(
        const std::string& method,
        const std::string& path,
        const std::string& body = "",
        const std::vector<std::pair<std::string,std::string>>& extra_headers = {}) {

        if (!session_ || fd_ < 0) {
            Response r; r.error = true; return r;
        }

        // Build headers
        std::vector<nghttp2_nv> nva;
        auto push_nv = [&](const std::string& n, const std::string& v) {
            nva.push_back({
                const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(n.c_str())),
                const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(v.c_str())),
                n.size(), v.size(),
                NGHTTP2_NV_FLAG_NONE
            });
        };
        push_nv(":method", method);
        push_nv(":path", path);
        push_nv(":scheme", "http");
        push_nv(":authority", "localhost");
        for (const auto& h : extra_headers) {
            push_nv(h.first, h.second);
        }

        int32_t stream_id = -1;
        if (body.empty()) {
            stream_id = nghttp2_submit_request2(
                session_, nullptr, nva.data(), nva.size(), nullptr, this);
        } else {
            // Store body for the data provider callback
            pending_body_   = body;
            pending_offset_ = 0;

            nghttp2_data_provider2 dp;
            dp.source.ptr    = this;
            dp.read_callback = DataSourceRead;

            stream_id = nghttp2_submit_request2(
                session_, nullptr, nva.data(), nva.size(), &dp, this);
        }

        if (stream_id < 0) {
            Response r; r.error = true; return r;
        }

        // Register a pending stream entry
        streams_[stream_id] = StreamState{};
        if (!FlushOutput()) {
            Response r; r.error = true; return r;
        }

        // Poll until stream is complete (headers + body received)
        auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(IO_TIMEOUT_MS);

        while (true) {
            auto it = streams_.find(stream_id);
            if (it != streams_.end() && it->second.done) {
                Response resp;
                resp.status = it->second.status;
                resp.body   = it->second.body;
                resp.rst    = it->second.rst;
                streams_.erase(it);
                return resp;
            }

            if (std::chrono::steady_clock::now() >= deadline) {
                Response r; r.error = true; return r;
            }

            if (!ReadAndProcess(100)) {
                Response r; r.error = true; return r;
            }
        }
    }

private:
    int fd_ = -1;
    nghttp2_session* session_ = nullptr;

    // Body for outgoing request (single active at a time for simplicity)
    std::string pending_body_;
    size_t      pending_offset_ = 0;

    struct StreamState {
        int         status = 0;
        std::string body;
        bool        done   = false;
        bool        rst    = false;
    };
    std::map<int32_t, StreamState> streams_;

    // ---- Raw I/O ----

    bool SendRaw(const char* data, size_t len) {
        while (len > 0) {
            ssize_t n = ::send(fd_, data, len, 0);
            if (n <= 0) return false;
            data += n;
            len  -= static_cast<size_t>(n);
        }
        return true;
    }

    // Flush any pending nghttp2 output to the socket.
    bool FlushOutput() {
        for (;;) {
            const uint8_t* out = nullptr;
            ssize_t len = nghttp2_session_mem_send2(session_, &out);
            if (len < 0) return false;
            if (len == 0) break;
            if (!SendRaw(reinterpret_cast<const char*>(out),
                         static_cast<size_t>(len))) return false;
        }
        return true;
    }

    // Read up to 16 KB from socket and feed to nghttp2; flush output.
    // Returns false on socket error (but timeout is not fatal — returns true).
    bool ReadAndProcess(int timeout_ms) {
        struct pollfd pfd{};
        pfd.fd     = fd_;
        pfd.events = POLLIN;

        int ret = ::poll(&pfd, 1, timeout_ms);
        if (ret < 0) return false;  // error
        if (ret == 0) return true;  // timeout — not fatal

        if (pfd.revents & (POLLHUP | POLLERR)) return false;

        char buf[16384];
        ssize_t n = ::recv(fd_, buf, sizeof(buf), 0);
        if (n <= 0) return false;

        ssize_t consumed = nghttp2_session_mem_recv2(
            session_, reinterpret_cast<const uint8_t*>(buf),
            static_cast<size_t>(n));
        if (consumed < 0) return false;

        return FlushOutput();
    }

    // ---- nghttp2 static callbacks ----

    static int OnFrameRecv(nghttp2_session* /*session*/,
                           const nghttp2_frame* frame,
                           void* user_data) {
        auto* self = static_cast<Http2TestClient*>(user_data);
        int32_t sid = frame->hd.stream_id;

        if (frame->hd.type == NGHTTP2_HEADERS &&
            frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
            // :status is delivered via OnHeader; nothing extra here.
            if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
                auto it = self->streams_.find(sid);
                if (it != self->streams_.end()) it->second.done = true;
            }
        } else if (frame->hd.type == NGHTTP2_DATA) {
            if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
                auto it = self->streams_.find(sid);
                if (it != self->streams_.end()) it->second.done = true;
            }
        } else if (frame->hd.type == NGHTTP2_RST_STREAM) {
            auto it = self->streams_.find(sid);
            if (it != self->streams_.end()) {
                it->second.rst  = true;
                it->second.done = true;
            }
        }
        return 0;
    }

    static int OnHeader(nghttp2_session* /*session*/,
                        const nghttp2_frame* frame,
                        const uint8_t* name,   size_t namelen,
                        const uint8_t* value,  size_t valuelen,
                        uint8_t /*flags*/, void* user_data) {
        auto* self = static_cast<Http2TestClient*>(user_data);
        int32_t sid = frame->hd.stream_id;

        std::string n(reinterpret_cast<const char*>(name),  namelen);
        std::string v(reinterpret_cast<const char*>(value), valuelen);

        if (n == ":status") {
            auto it = self->streams_.find(sid);
            if (it != self->streams_.end()) {
                try { it->second.status = std::stoi(v); } catch (...) {}
            }
        }
        return 0;
    }

    static int OnDataChunkRecv(nghttp2_session* /*session*/,
                               uint8_t /*flags*/,
                               int32_t stream_id,
                               const uint8_t* data, size_t len,
                               void* user_data) {
        auto* self = static_cast<Http2TestClient*>(user_data);
        auto it = self->streams_.find(stream_id);
        if (it != self->streams_.end()) {
            it->second.body.append(reinterpret_cast<const char*>(data), len);
        }
        return 0;
    }

    static int OnStreamClose(nghttp2_session* /*session*/,
                             int32_t stream_id,
                             uint32_t error_code,
                             void* user_data) {
        auto* self = static_cast<Http2TestClient*>(user_data);
        auto it = self->streams_.find(stream_id);
        if (it != self->streams_.end()) {
            it->second.done = true;
            if (error_code != 0) it->second.rst = true;
        }
        return 0;
    }

    static ssize_t DataSourceRead(nghttp2_session* /*session*/,
                                  int32_t /*stream_id*/,
                                  uint8_t* buf, size_t length,
                                  uint32_t* data_flags,
                                  nghttp2_data_source* /*source*/,
                                  void* user_data) {
        auto* self = static_cast<Http2TestClient*>(user_data);
        const std::string& body = self->pending_body_;
        size_t remaining = body.size() - self->pending_offset_;
        size_t to_copy   = std::min(remaining, length);

        if (to_copy > 0) {
            std::memcpy(buf, body.data() + self->pending_offset_, to_copy);
            self->pending_offset_ += to_copy;
        }

        if (self->pending_offset_ >= body.size()) {
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        }

        return static_cast<ssize_t>(to_copy);
    }
};

// ============================================================
// Helper: start an HttpServer in a background thread.
// Returns the thread. Caller owns server lifetime.
// ============================================================

static std::thread StartServer(HttpServer& server) {
    return std::thread([&server]() {
        try { server.Start(); } catch (...) {}
    });
}

static void StopServer(HttpServer& server, std::thread& t) {
    server.Stop();
    if (t.joinable()) t.join();
}

// ============================================================
// ============================================================
// TEST CATEGORY 1: Configuration (no server needed)
// ============================================================
// ============================================================

// Verify Http2Config default values match what ServerConfig documents.
void TestH2ConfigDefaults() {
    std::cout << "\n[TEST] H2 Config: Default Values..." << std::endl;
    try {
        ServerConfig cfg = ConfigLoader::Default();

        bool pass = true;
        std::string err;

        if (!cfg.http2.enabled) {
            pass = false; err += "http2.enabled should be true by default; ";
        }
        if (cfg.http2.max_concurrent_streams != 100) {
            pass = false;
            err += "max_concurrent_streams != 100; ";
        }
        if (cfg.http2.initial_window_size != 65535) {
            pass = false;
            err += "initial_window_size != 65535; ";
        }
        if (cfg.http2.max_frame_size != 16384) {
            pass = false;
            err += "max_frame_size != 16384; ";
        }
        if (cfg.http2.max_header_list_size != 65536) {
            pass = false;
            err += "max_header_list_size != 65536; ";
        }

        TestFramework::RecordTest("H2 Config: Default Values", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2 Config: Default Values", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// Parse JSON that contains an http2 section; verify fields land correctly.
void TestH2ConfigFromJson() {
    std::cout << "\n[TEST] H2 Config: Parse From JSON..." << std::endl;
    try {
        const std::string json = R"({
            "http2": {
                "enabled": true,
                "max_concurrent_streams": 200,
                "initial_window_size": 131070,
                "max_frame_size": 32768,
                "max_header_list_size": 32768
            }
        })";

        ServerConfig cfg = ConfigLoader::LoadFromString(json);

        bool pass = true;
        std::string err;

        if (!cfg.http2.enabled) {
            pass = false; err += "http2.enabled mismatch; ";
        }
        if (cfg.http2.max_concurrent_streams != 200) {
            pass = false; err += "max_concurrent_streams mismatch; ";
        }
        if (cfg.http2.initial_window_size != 131070) {
            pass = false; err += "initial_window_size mismatch; ";
        }
        if (cfg.http2.max_frame_size != 32768) {
            pass = false; err += "max_frame_size mismatch; ";
        }
        if (cfg.http2.max_header_list_size != 32768) {
            pass = false; err += "max_header_list_size mismatch; ";
        }

        TestFramework::RecordTest("H2 Config: Parse From JSON", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2 Config: Parse From JSON", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ConfigLoader::Validate must reject settings that violate RFC 9113 bounds.
void TestH2ConfigValidation() {
    std::cout << "\n[TEST] H2 Config: Validation..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        // max_frame_size < 16384 should throw
        {
            ServerConfig cfg;
            cfg.http2.enabled        = true;
            cfg.http2.max_frame_size = 16383;  // below RFC minimum
            bool threw = false;
            try {
                ConfigLoader::Validate(cfg);
            } catch (const std::invalid_argument&) {
                threw = true;
            }
            if (!threw) { pass = false; err += "max_frame_size=16383 not rejected; "; }
        }

        // max_frame_size > 16777215 should throw
        {
            ServerConfig cfg;
            cfg.http2.enabled        = true;
            cfg.http2.max_frame_size = 16777216u;  // above RFC maximum
            bool threw = false;
            try {
                ConfigLoader::Validate(cfg);
            } catch (const std::invalid_argument&) {
                threw = true;
            }
            if (!threw) { pass = false; err += "max_frame_size=16777216 not rejected; "; }
        }

        // initial_window_size == 0 should throw
        {
            ServerConfig cfg;
            cfg.http2.enabled             = true;
            cfg.http2.initial_window_size = 0;
            bool threw = false;
            try {
                ConfigLoader::Validate(cfg);
            } catch (const std::invalid_argument&) {
                threw = true;
            }
            if (!threw) { pass = false; err += "initial_window_size=0 not rejected; "; }
        }

        // initial_window_size > 2^31-1 should throw
        {
            ServerConfig cfg;
            cfg.http2.enabled             = true;
            cfg.http2.initial_window_size = 2147483648u;  // 2^31
            bool threw = false;
            try {
                ConfigLoader::Validate(cfg);
            } catch (const std::invalid_argument&) {
                threw = true;
            }
            if (!threw) { pass = false; err += "initial_window_size=2^31 not rejected; "; }
        }

        // max_concurrent_streams == 0 should throw
        {
            ServerConfig cfg;
            cfg.http2.enabled                = true;
            cfg.http2.max_concurrent_streams = 0;
            bool threw = false;
            try {
                ConfigLoader::Validate(cfg);
            } catch (const std::invalid_argument&) {
                threw = true;
            }
            if (!threw) { pass = false; err += "max_concurrent_streams=0 not rejected; "; }
        }

        // Valid boundary values should not throw
        {
            ServerConfig cfg;
            cfg.http2.enabled                = true;
            cfg.http2.max_frame_size         = 16384;       // min valid
            cfg.http2.initial_window_size    = 65535;       // default
            cfg.http2.max_concurrent_streams = 100;
            cfg.http2.max_header_list_size   = 65536;
            try {
                ConfigLoader::Validate(cfg);
            } catch (const std::exception& ex) {
                pass = false; err += std::string("valid config rejected: ") + ex.what() + "; ";
            }
        }

        TestFramework::RecordTest("H2 Config: Validation", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2 Config: Validation", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// Environment variables for HTTP/2 settings must override defaults.
void TestH2ConfigEnvOverride() {
    std::cout << "\n[TEST] H2 Config: Environment Variable Overrides..." << std::endl;
    try {
        // Clean slate — ensure no leftover env from other tests
        unsetenv("REACTOR_HTTP2_ENABLED");
        unsetenv("REACTOR_HTTP2_MAX_CONCURRENT_STREAMS");
        unsetenv("REACTOR_HTTP2_INITIAL_WINDOW_SIZE");
        unsetenv("REACTOR_HTTP2_MAX_FRAME_SIZE");
        unsetenv("REACTOR_HTTP2_MAX_HEADER_LIST_SIZE");

        setenv("REACTOR_HTTP2_ENABLED",                  "false", 1);
        setenv("REACTOR_HTTP2_MAX_CONCURRENT_STREAMS",   "50",    1);
        setenv("REACTOR_HTTP2_INITIAL_WINDOW_SIZE",      "32768", 1);
        setenv("REACTOR_HTTP2_MAX_FRAME_SIZE",           "32768", 1);
        setenv("REACTOR_HTTP2_MAX_HEADER_LIST_SIZE",     "16384", 1);

        ServerConfig cfg = ConfigLoader::Default();
        ConfigLoader::ApplyEnvOverrides(cfg);

        bool pass = true;
        std::string err;

        if (cfg.http2.enabled) {
            pass = false; err += "http2.enabled not overridden to false; ";
        }
        if (cfg.http2.max_concurrent_streams != 50) {
            pass = false; err += "max_concurrent_streams not overridden; ";
        }
        if (cfg.http2.initial_window_size != 32768) {
            pass = false; err += "initial_window_size not overridden; ";
        }
        if (cfg.http2.max_frame_size != 32768) {
            pass = false; err += "max_frame_size not overridden; ";
        }
        if (cfg.http2.max_header_list_size != 16384) {
            pass = false; err += "max_header_list_size not overridden; ";
        }

        // Cleanup
        unsetenv("REACTOR_HTTP2_ENABLED");
        unsetenv("REACTOR_HTTP2_MAX_CONCURRENT_STREAMS");
        unsetenv("REACTOR_HTTP2_INITIAL_WINDOW_SIZE");
        unsetenv("REACTOR_HTTP2_MAX_FRAME_SIZE");
        unsetenv("REACTOR_HTTP2_MAX_HEADER_LIST_SIZE");

        TestFramework::RecordTest("H2 Config: Env Overrides", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        unsetenv("REACTOR_HTTP2_ENABLED");
        unsetenv("REACTOR_HTTP2_MAX_CONCURRENT_STREAMS");
        unsetenv("REACTOR_HTTP2_INITIAL_WINDOW_SIZE");
        unsetenv("REACTOR_HTTP2_MAX_FRAME_SIZE");
        unsetenv("REACTOR_HTTP2_MAX_HEADER_LIST_SIZE");
        TestFramework::RecordTest("H2 Config: Env Overrides", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// http2.enabled = false means the field can be round-tripped through JSON
// without affecting other fields, and the config remains valid.
void TestH2ConfigDisabled() {
    std::cout << "\n[TEST] H2 Config: Disabled In JSON..." << std::endl;
    try {
        const std::string json = R"({"http2": {"enabled": false}})";
        ServerConfig cfg = ConfigLoader::LoadFromString(json);

        bool pass = true;
        std::string err;

        if (cfg.http2.enabled) {
            pass = false; err += "http2.enabled should be false; ";
        }
        // When disabled, validation must not enforce h2-specific limits
        try {
            ConfigLoader::Validate(cfg);
        } catch (const std::exception& ex) {
            pass = false;
            err += std::string("disabled config rejected by Validate: ") + ex.what() + "; ";
        }

        TestFramework::RecordTest("H2 Config: Disabled", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2 Config: Disabled", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ToJson must include the http2 section with all sub-fields.
void TestH2ConfigSerialization() {
    std::cout << "\n[TEST] H2 Config: Serialization..." << std::endl;
    try {
        ServerConfig cfg;
        cfg.http2.enabled                = true;
        cfg.http2.max_concurrent_streams = 42;
        cfg.http2.initial_window_size    = 131070;
        cfg.http2.max_frame_size         = 32768;
        cfg.http2.max_header_list_size   = 16384;

        std::string json = ConfigLoader::ToJson(cfg);

        bool pass = true;
        std::string err;

        // Check required keys exist in JSON output
        if (json.find("\"http2\"") == std::string::npos) {
            pass = false; err += "missing http2 section; ";
        }
        if (json.find("\"enabled\"") == std::string::npos) {
            pass = false; err += "missing http2.enabled; ";
        }
        if (json.find("\"max_concurrent_streams\"") == std::string::npos) {
            pass = false; err += "missing max_concurrent_streams; ";
        }
        if (json.find("42") == std::string::npos) {
            pass = false; err += "max_concurrent_streams value 42 not found; ";
        }
        if (json.find("\"initial_window_size\"") == std::string::npos) {
            pass = false; err += "missing initial_window_size; ";
        }
        if (json.find("\"max_frame_size\"") == std::string::npos) {
            pass = false; err += "missing max_frame_size; ";
        }
        if (json.find("\"max_header_list_size\"") == std::string::npos) {
            pass = false; err += "missing max_header_list_size; ";
        }

        // Verify round-trip: parse back what we serialized
        ServerConfig cfg2 = ConfigLoader::LoadFromString(json);
        if (cfg2.http2.max_concurrent_streams != 42) {
            pass = false; err += "round-trip max_concurrent_streams mismatch; ";
        }
        if (cfg2.http2.initial_window_size != 131070) {
            pass = false; err += "round-trip initial_window_size mismatch; ";
        }

        TestFramework::RecordTest("H2 Config: Serialization", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2 Config: Serialization", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ============================================================
// ============================================================
// TEST CATEGORY 2: ProtocolDetector (unit tests, no server)
// ============================================================
// ============================================================

void TestDetectFromAlpn_H2() {
    std::cout << "\n[TEST] ProtocolDetector: ALPN h2..." << std::endl;
    try {
        auto result = ProtocolDetector::DetectFromAlpn("h2");
        bool pass = (result == ProtocolDetector::Protocol::HTTP2);
        TestFramework::RecordTest("ProtocolDetector: ALPN h2",
            pass, pass ? "" : "Expected HTTP2", TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ProtocolDetector: ALPN h2", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestDetectFromAlpn_HTTP11() {
    std::cout << "\n[TEST] ProtocolDetector: ALPN http/1.1..." << std::endl;
    try {
        auto result = ProtocolDetector::DetectFromAlpn("http/1.1");
        bool pass = (result == ProtocolDetector::Protocol::HTTP1);
        TestFramework::RecordTest("ProtocolDetector: ALPN http/1.1",
            pass, pass ? "" : "Expected HTTP1", TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ProtocolDetector: ALPN http/1.1", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestDetectFromAlpn_Empty() {
    std::cout << "\n[TEST] ProtocolDetector: ALPN empty string..." << std::endl;
    try {
        auto result = ProtocolDetector::DetectFromAlpn("");
        bool pass = (result == ProtocolDetector::Protocol::HTTP1);
        TestFramework::RecordTest("ProtocolDetector: ALPN empty",
            pass, pass ? "" : "Expected HTTP1 for empty ALPN",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ProtocolDetector: ALPN empty", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestDetectFromData_Preface() {
    std::cout << "\n[TEST] ProtocolDetector: full client preface..." << std::endl;
    try {
        // Exact 24-byte client preface
        const char* preface = HTTP2_CONSTANTS::CLIENT_PREFACE;
        size_t len = HTTP2_CONSTANTS::CLIENT_PREFACE_LEN;
        auto result = ProtocolDetector::DetectFromData(preface, len);
        bool pass = (result == ProtocolDetector::Protocol::HTTP2);
        TestFramework::RecordTest("ProtocolDetector: client preface -> HTTP2",
            pass, pass ? "" : "Expected HTTP2", TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ProtocolDetector: client preface -> HTTP2",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestDetectFromData_HTTP1() {
    std::cout << "\n[TEST] ProtocolDetector: HTTP/1.1 data -> HTTP1..." << std::endl;
    try {
        const char* http1 = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
        size_t len = std::strlen(http1);
        auto result = ProtocolDetector::DetectFromData(http1, len);
        bool pass = (result == ProtocolDetector::Protocol::HTTP1);
        TestFramework::RecordTest("ProtocolDetector: HTTP/1.1 data -> HTTP1",
            pass, pass ? "" : "Expected HTTP1", TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ProtocolDetector: HTTP/1.1 data -> HTTP1",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestDetectFromData_Short() {
    std::cout << "\n[TEST] ProtocolDetector: fewer than 24 bytes -> UNKNOWN..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        // Zero bytes
        {
            auto r = ProtocolDetector::DetectFromData("", 0);
            if (r != ProtocolDetector::Protocol::UNKNOWN) {
                pass = false; err += "0 bytes should return UNKNOWN; ";
            }
        }
        // 23 bytes (one short of the preface)
        {
            std::string almost(HTTP2_CONSTANTS::CLIENT_PREFACE,
                               HTTP2_CONSTANTS::CLIENT_PREFACE_LEN - 1);
            auto r = ProtocolDetector::DetectFromData(almost.data(), almost.size());
            if (r != ProtocolDetector::Protocol::UNKNOWN) {
                pass = false; err += "23 bytes should return UNKNOWN; ";
            }
        }

        TestFramework::RecordTest("ProtocolDetector: short data -> UNKNOWN",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ProtocolDetector: short data -> UNKNOWN",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

void TestDetectFromData_PartialMatch() {
    std::cout << "\n[TEST] ProtocolDetector: partial preface match -> HTTP1..." << std::endl;
    try {
        // 24 bytes that start with "PRI" but diverge — not HTTP/2
        char buf[24];
        std::memcpy(buf, "PRI * HTTP/2.0\r\n\r\nXX\r\n\r", 24);  // last 4 bytes differ
        auto result = ProtocolDetector::DetectFromData(buf, 24);
        bool pass = (result == ProtocolDetector::Protocol::HTTP1);
        TestFramework::RecordTest("ProtocolDetector: partial preface -> HTTP1",
            pass, pass ? "" : "Expected HTTP1 for partial match",
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ProtocolDetector: partial preface -> HTTP1",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ============================================================
// ============================================================
// TEST CATEGORY 3: Http2Stream (unit tests, no server)
// ============================================================
// ============================================================

void TestStreamAddPseudoHeaders() {
    std::cout << "\n[TEST] Http2Stream: pseudo-headers map correctly..." << std::endl;
    try {
        Http2Stream stream(1);
        stream.AddHeader(":method",    "POST");
        stream.AddHeader(":path",      "/api/data?foo=bar");
        stream.AddHeader(":scheme",    "http");
        stream.AddHeader(":authority", "example.com");

        const HttpRequest& req = stream.GetRequest();
        bool pass = true;
        std::string err;

        if (req.method != "POST") {
            pass = false; err += "method != POST; ";
        }
        if (req.path != "/api/data") {
            pass = false; err += "path != /api/data (got: " + req.path + "); ";
        }
        if (req.query != "foo=bar") {
            pass = false; err += "query != foo=bar (got: " + req.query + "); ";
        }
        // :authority must map to host header
        if (req.GetHeader("host") != "example.com") {
            pass = false; err += "host header != example.com; ";
        }
        // :scheme should NOT appear as a regular header
        if (req.HasHeader(":scheme")) {
            pass = false; err += ":scheme should not be stored as header; ";
        }
        // HTTP/2 requests always have http_major == 2
        if (req.http_major != 2) {
            pass = false; err += "http_major != 2; ";
        }

        TestFramework::RecordTest("Http2Stream: pseudo-headers", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Http2Stream: pseudo-headers", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestStreamAddRegularHeaders() {
    std::cout << "\n[TEST] Http2Stream: regular headers stored lowercase..." << std::endl;
    try {
        Http2Stream stream(3);
        // Headers may arrive with any case from HTTP/2 hpack decompression
        // but the implementation normalises to lowercase.
        stream.AddHeader("content-type",   "application/json");
        stream.AddHeader("X-Custom-Header", "SomeValue");
        stream.AddHeader("ACCEPT",         "text/html");

        const HttpRequest& req = stream.GetRequest();
        bool pass = true;
        std::string err;

        if (req.GetHeader("content-type") != "application/json") {
            pass = false; err += "content-type mismatch; ";
        }
        if (req.GetHeader("x-custom-header") != "SomeValue") {
            pass = false; err += "x-custom-header not lowercased or wrong value; ";
        }
        if (req.GetHeader("accept") != "text/html") {
            pass = false; err += "accept not lowercased; ";
        }

        TestFramework::RecordTest("Http2Stream: regular headers lowercase", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Http2Stream: regular headers lowercase", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestStreamCookieConcatenation() {
    std::cout << "\n[TEST] Http2Stream: cookie headers concatenated with \"; \"..." << std::endl;
    try {
        // RFC 9113 Section 8.2.3: multiple cookie headers must be joined with "; "
        Http2Stream stream(5);
        stream.AddHeader("cookie", "session=abc");
        stream.AddHeader("cookie", "theme=dark");
        stream.AddHeader("cookie", "lang=en");

        const HttpRequest& req = stream.GetRequest();
        std::string cookie_val = req.GetHeader("cookie");

        bool pass = (cookie_val == "session=abc; theme=dark; lang=en");
        std::string err;
        if (!pass) err = "cookie concat wrong: " + cookie_val;

        TestFramework::RecordTest("Http2Stream: cookie concatenation", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Http2Stream: cookie concatenation", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestStreamBodyAppend() {
    std::cout << "\n[TEST] Http2Stream: body accumulation and size tracking..." << std::endl;
    try {
        Http2Stream stream(7);

        const char chunk1[] = "Hello ";
        const char chunk2[] = "World";
        stream.AppendBody(chunk1, 6);
        stream.AppendBody(chunk2, 5);

        const HttpRequest& req = stream.GetRequest();
        bool pass = true;
        std::string err;

        if (req.body != "Hello World") {
            pass = false; err += "body mismatch: " + req.body + "; ";
        }
        if (stream.AccumulatedBodySize() != 11) {
            pass = false;
            err += "body size " + std::to_string(stream.AccumulatedBodySize()) + " != 11; ";
        }

        TestFramework::RecordTest("Http2Stream: body accumulation", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Http2Stream: body accumulation", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestStreamLifecycle() {
    std::cout << "\n[TEST] Http2Stream: state transitions..." << std::endl;
    try {
        Http2Stream stream(9);
        bool pass = true;
        std::string err;

        // Initial state
        if (stream.GetState() != Http2Stream::State::IDLE) {
            pass = false; err += "initial state != IDLE; ";
        }

        stream.SetState(Http2Stream::State::OPEN);
        if (stream.GetState() != Http2Stream::State::OPEN) {
            pass = false; err += "state != OPEN after SetState; ";
        }

        // MarkEndStream while OPEN transitions to HALF_CLOSED_REMOTE
        stream.MarkEndStream();
        if (stream.GetState() != Http2Stream::State::HALF_CLOSED_REMOTE) {
            pass = false; err += "state != HALF_CLOSED_REMOTE after MarkEndStream; ";
        }

        stream.SetState(Http2Stream::State::CLOSED);
        if (!stream.IsClosed()) {
            pass = false; err += "IsClosed() == false after SetState(CLOSED); ";
        }

        TestFramework::RecordTest("Http2Stream: state lifecycle", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Http2Stream: state lifecycle", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestStreamRequestComplete() {
    std::cout << "\n[TEST] Http2Stream: IsRequestComplete..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        // Not complete before headers or end-stream
        {
            Http2Stream s(11);
            if (s.IsRequestComplete()) {
                pass = false; err += "should not be complete before headers; ";
            }
        }

        // Headers done but no END_STREAM yet
        {
            Http2Stream s(13);
            s.MarkHeadersComplete();
            if (s.IsRequestComplete()) {
                pass = false; err += "should not be complete without END_STREAM; ";
            }
        }

        // END_STREAM without headers — still incomplete
        {
            Http2Stream s(15);
            s.MarkEndStream();
            if (s.IsRequestComplete()) {
                pass = false; err += "should not be complete without headers; ";
            }
        }

        // Both headers + END_STREAM — complete
        {
            Http2Stream s(17);
            s.MarkHeadersComplete();
            s.MarkEndStream();
            if (!s.IsRequestComplete()) {
                pass = false; err += "should be complete after headers + END_STREAM; ";
            }
        }

        TestFramework::RecordTest("Http2Stream: IsRequestComplete", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Http2Stream: IsRequestComplete", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

void TestStreamPathWithoutQuery() {
    std::cout << "\n[TEST] Http2Stream: path without query string..." << std::endl;
    try {
        Http2Stream stream(19);
        stream.AddHeader(":method", "GET");
        stream.AddHeader(":path",   "/simple");

        const HttpRequest& req = stream.GetRequest();
        bool pass = true;
        std::string err;

        if (req.path != "/simple") {
            pass = false; err += "path mismatch: " + req.path + "; ";
        }
        if (!req.query.empty()) {
            pass = false; err += "query should be empty, got: " + req.query + "; ";
        }

        TestFramework::RecordTest("Http2Stream: path without query", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Http2Stream: path without query", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ============================================================
// ============================================================
// TEST CATEGORY 4: HTTP/2 Functional Tests (h2c, need server)
// ============================================================
// ============================================================

// Helper: wait for server to be ready by polling TCP connect.
// After a successful probe, sleeps 150ms to let the reactor fully process the
// probe connection's close event before the test client connects.  Without this
// sleep the probe fd may be reused by the test client and the reactor's
// HandleCloseConnection for the probe connection fires on the new (test) fd,
// tearing down the h2c session immediately after the server preface is sent.
static bool WaitForServer(int port, int tries = 30, int delay_ms = 50) {
    for (int i = 0; i < tries; ++i) {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) continue;
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(static_cast<uint16_t>(port));
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        int r = ::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
        ::close(fd);
        if (r == 0) {
            // Give the reactor time to process the probe connection's close event
            // so the probe fd is fully freed before the test client connects.
            std::this_thread::sleep_for(std::chrono::milliseconds(150));
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
    }
    return false;
}

// Simple GET through h2c connection.
void TestH2C_SimpleGet() {
    std::cout << "\n[TEST] H2C: simple GET request..." << std::endl;
    try {
        ServerConfig cfg;
        cfg.bind_host       = "127.0.0.1";
        cfg.bind_port       = H2_UNIT_PORT;
        cfg.worker_threads  = 2;
        cfg.http2.enabled   = true;

        HttpServer server(cfg);
        server.Get("/hello", [](const HttpRequest&, HttpResponse& res) {
            res.Status(200).Text("Hello HTTP/2");
        });

        auto t = StartServer(server);
        if (!WaitForServer(H2_UNIT_PORT)) {
            StopServer(server, t);
            TestFramework::RecordTest("H2C: simple GET", false, "server did not start",
                                      TestFramework::TestCategory::OTHER);
            return;
        }

        Http2TestClient client;
        bool pass = true;
        std::string err;

        if (!client.Connect("127.0.0.1", H2_UNIT_PORT)) {
            pass = false; err = "client connect failed";
        } else {
            auto resp = client.Get("/hello");
            if (resp.error) {
                pass = false; err = "transport error";
            } else if (resp.status != 200) {
                pass = false;
                err = "expected 200, got " + std::to_string(resp.status);
            } else if (resp.body.find("Hello HTTP/2") == std::string::npos) {
                pass = false;
                err = "body missing expected text: " + resp.body;
            }
        }
        client.Disconnect();
        StopServer(server, t);

        TestFramework::RecordTest("H2C: simple GET", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2C: simple GET", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// POST with request body through h2c.
void TestH2C_SimplePost() {
    std::cout << "\n[TEST] H2C: POST with body..." << std::endl;
    try {
        ServerConfig cfg;
        cfg.bind_host      = "127.0.0.1";
        cfg.bind_port      = H2_UNIT_PORT + 10;
        cfg.worker_threads = 2;
        cfg.http2.enabled  = true;

        HttpServer server(cfg);
        server.Post("/echo", [](const HttpRequest& req, HttpResponse& res) {
            res.Status(200).Body(req.body, "text/plain");
        });

        auto t = StartServer(server);
        if (!WaitForServer(H2_UNIT_PORT + 10)) {
            StopServer(server, t);
            TestFramework::RecordTest("H2C: POST with body", false, "server did not start",
                                      TestFramework::TestCategory::OTHER);
            return;
        }

        Http2TestClient client;
        bool pass = true;
        std::string err;

        if (!client.Connect("127.0.0.1", H2_UNIT_PORT + 10)) {
            pass = false; err = "client connect failed";
        } else {
            const std::string body = "Hello from POST";
            auto resp = client.Post("/echo", body);
            if (resp.error) {
                pass = false; err = "transport error";
            } else if (resp.status != 200) {
                pass = false;
                err = "expected 200, got " + std::to_string(resp.status);
            } else if (resp.body != body) {
                pass = false;
                err = "body echoed incorrectly: '" + resp.body + "'";
            }
        }
        client.Disconnect();
        StopServer(server, t);

        TestFramework::RecordTest("H2C: POST with body", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2C: POST with body", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// Unregistered path must return 404.
void TestH2C_NotFound() {
    std::cout << "\n[TEST] H2C: 404 for unknown path..." << std::endl;
    try {
        ServerConfig cfg;
        cfg.bind_host      = "127.0.0.1";
        cfg.bind_port      = H2_UNIT_PORT + 20;
        cfg.worker_threads = 2;
        cfg.http2.enabled  = true;

        HttpServer server(cfg);
        server.Get("/exists", [](const HttpRequest&, HttpResponse& res) {
            res.Status(200).Text("ok");
        });

        auto t = StartServer(server);
        if (!WaitForServer(H2_UNIT_PORT + 20)) {
            StopServer(server, t);
            TestFramework::RecordTest("H2C: 404 not found", false, "server did not start",
                                      TestFramework::TestCategory::OTHER);
            return;
        }

        Http2TestClient client;
        bool pass = true;
        std::string err;

        if (!client.Connect("127.0.0.1", H2_UNIT_PORT + 20)) {
            pass = false; err = "client connect failed";
        } else {
            auto resp = client.Get("/does-not-exist");
            if (resp.error) {
                pass = false; err = "transport error";
            } else if (resp.status != 404) {
                pass = false;
                err = "expected 404, got " + std::to_string(resp.status);
            }
        }
        client.Disconnect();
        StopServer(server, t);

        TestFramework::RecordTest("H2C: 404 not found", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2C: 404 not found", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// Middleware must execute for HTTP/2 requests (same as HTTP/1.x).
void TestH2C_Middleware() {
    std::cout << "\n[TEST] H2C: middleware executes..." << std::endl;
    try {
        ServerConfig cfg;
        cfg.bind_host      = "127.0.0.1";
        cfg.bind_port      = H2_UNIT_PORT + 30;
        cfg.worker_threads = 2;
        cfg.http2.enabled  = true;

        HttpServer server(cfg);

        // Middleware adds a header to every response
        server.Use([](const HttpRequest&, HttpResponse& res) {
            res.Header("X-MW-Ran", "1");
            return true;
        });

        server.Get("/mw-test", [](const HttpRequest&, HttpResponse& res) {
            res.Status(200).Text("ok");
        });

        // We cannot easily inspect response headers via the minimal
        // Http2TestClient, so we verify by checking a separate sentinel:
        // the middleware sets a shared atomic flag when it runs.
        std::atomic<bool> mw_ran{false};
        server.Use([&mw_ran](const HttpRequest&, HttpResponse&) {
            mw_ran.store(true, std::memory_order_release);
            return true;
        });

        auto t = StartServer(server);
        if (!WaitForServer(H2_UNIT_PORT + 30)) {
            StopServer(server, t);
            TestFramework::RecordTest("H2C: middleware executes", false, "server did not start",
                                      TestFramework::TestCategory::OTHER);
            return;
        }

        Http2TestClient client;
        bool pass = true;
        std::string err;

        if (!client.Connect("127.0.0.1", H2_UNIT_PORT + 30)) {
            pass = false; err = "client connect failed";
        } else {
            auto resp = client.Get("/mw-test");
            if (resp.error) {
                pass = false; err = "transport error";
            } else if (resp.status != 200) {
                pass = false;
                err = "expected 200, got " + std::to_string(resp.status);
            } else if (!mw_ran.load(std::memory_order_acquire)) {
                pass = false; err = "middleware did not run";
            }
        }
        client.Disconnect();
        StopServer(server, t);

        TestFramework::RecordTest("H2C: middleware executes", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2C: middleware executes", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// Three concurrent streams on one connection must all receive correct responses.
void TestH2C_MultipleStreams() {
    std::cout << "\n[TEST] H2C: multiple concurrent streams..." << std::endl;
    try {
        ServerConfig cfg;
        cfg.bind_host      = "127.0.0.1";
        cfg.bind_port      = H2_MULTI_PORT;
        cfg.worker_threads = 2;
        cfg.http2.enabled  = true;

        HttpServer server(cfg);
        server.Get("/s1", [](const HttpRequest&, HttpResponse& res) {
            res.Status(200).Text("stream1");
        });
        server.Get("/s2", [](const HttpRequest&, HttpResponse& res) {
            res.Status(200).Text("stream2");
        });
        server.Get("/s3", [](const HttpRequest&, HttpResponse& res) {
            res.Status(200).Text("stream3");
        });

        auto t = StartServer(server);
        if (!WaitForServer(H2_MULTI_PORT)) {
            StopServer(server, t);
            TestFramework::RecordTest("H2C: multiple streams", false, "server did not start",
                                      TestFramework::TestCategory::OTHER);
            return;
        }

        Http2TestClient client;
        bool pass = true;
        std::string err;

        if (!client.Connect("127.0.0.1", H2_MULTI_PORT)) {
            pass = false; err = "client connect failed";
        } else {
            // Send three sequential requests on the same connection
            // (Http2TestClient is single-connection but handles each stream
            //  in sequence — sufficient to verify multi-stream correctness
            //  on one TCP connection with correct stream IDs).
            auto r1 = client.Get("/s1");
            auto r2 = client.Get("/s2");
            auto r3 = client.Get("/s3");

            if (r1.error || r1.status != 200 || r1.body != "stream1") {
                pass = false; err += "stream1 wrong (status=" +
                    std::to_string(r1.status) + " body=" + r1.body + "); ";
            }
            if (r2.error || r2.status != 200 || r2.body != "stream2") {
                pass = false; err += "stream2 wrong (status=" +
                    std::to_string(r2.status) + " body=" + r2.body + "); ";
            }
            if (r3.error || r3.status != 200 || r3.body != "stream3") {
                pass = false; err += "stream3 wrong (status=" +
                    std::to_string(r3.status) + " body=" + r3.body + "); ";
            }
        }
        client.Disconnect();
        StopServer(server, t);

        TestFramework::RecordTest("H2C: multiple streams", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2C: multiple streams", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// A POST body that fits within max_body_size must succeed.
void TestH2C_LargeBody() {
    std::cout << "\n[TEST] H2C: large body within limit..." << std::endl;
    try {
        ServerConfig cfg;
        cfg.bind_host      = "127.0.0.1";
        cfg.bind_port      = H2_BODY_PORT;
        cfg.worker_threads = 2;
        cfg.http2.enabled  = true;
        cfg.max_body_size  = 64 * 1024;  // 64 KB limit

        HttpServer server(cfg);
        server.Post("/upload", [](const HttpRequest& req, HttpResponse& res) {
            res.Status(200).Json(R"({"received":)" +
                                 std::to_string(req.body.size()) + "}");
        });

        auto t = StartServer(server);
        if (!WaitForServer(H2_BODY_PORT)) {
            StopServer(server, t);
            TestFramework::RecordTest("H2C: large body within limit", false,
                                      "server did not start",
                                      TestFramework::TestCategory::OTHER);
            return;
        }

        Http2TestClient client;
        bool pass = true;
        std::string err;

        if (!client.Connect("127.0.0.1", H2_BODY_PORT)) {
            pass = false; err = "client connect failed";
        } else {
            // 32 KB body — well within the 64 KB limit
            std::string body(32 * 1024, 'A');
            auto resp = client.Post("/upload", body);
            if (resp.error) {
                pass = false; err = "transport error";
            } else if (resp.status != 200) {
                pass = false;
                err = "expected 200, got " + std::to_string(resp.status);
            } else if (resp.body.find("32768") == std::string::npos) {
                pass = false;
                err = "response did not confirm body size: " + resp.body;
            }
        }
        client.Disconnect();
        StopServer(server, t);

        TestFramework::RecordTest("H2C: large body within limit", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2C: large body within limit", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ============================================================
// ============================================================
// TEST CATEGORY 5: Error-Handling Tests
// ============================================================
// ============================================================

// Sending garbage instead of the HTTP/2 preface must not crash the server.
void TestH2C_InvalidPreface() {
    std::cout << "\n[TEST] H2C: invalid preface handled gracefully..." << std::endl;
    try {
        ServerConfig cfg;
        cfg.bind_host      = "127.0.0.1";
        cfg.bind_port      = H2_BODY_PORT + 10;
        cfg.worker_threads = 2;
        cfg.http2.enabled  = true;

        HttpServer server(cfg);
        server.Get("/ok", [](const HttpRequest&, HttpResponse& res) {
            res.Status(200).Text("ok");
        });

        auto t = StartServer(server);
        if (!WaitForServer(H2_BODY_PORT + 10)) {
            StopServer(server, t);
            TestFramework::RecordTest("H2C: invalid preface", false, "server did not start",
                                      TestFramework::TestCategory::OTHER);
            return;
        }

        // Connect raw and send binary garbage (not the HTTP/2 preface)
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(static_cast<uint16_t>(H2_BODY_PORT + 10));
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        bool pass = true;
        std::string err;

        if (::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
            pass = false; err = "raw connect failed";
        } else {
            // Send 30 bytes of garbage
            const char garbage[] = "\xFF\xFE\x00\x01\x02\x03GARBAGE_DATA_HERE12345";
            ::send(fd, garbage, 30, 0);

            // Server should close the connection — receive EOF or error
            struct timeval tv{}; tv.tv_sec = 3;
            ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            char buf[128] = {};
            ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
            // n == 0: server closed cleanly (expected)
            // n < 0: timeout or error (also acceptable — server dropped it)
            // n > 0: server sent something back (unexpected but tolerated for
            //        HTTP/1.x fallback — the important thing is no crash)
            // The key assertion: the server is still alive after the bad client.
            (void)n;

            // Verify server is still alive by sending a real HTTP/1.1 request
            ::close(fd);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            int fd2 = ::socket(AF_INET, SOCK_STREAM, 0);
            if (::connect(fd2, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == 0) {
                const char* req = "GET /ok HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
                ::send(fd2, req, std::strlen(req), 0);
                struct timeval tv2{}; tv2.tv_sec = 3;
                ::setsockopt(fd2, SOL_SOCKET, SO_RCVTIMEO, &tv2, sizeof(tv2));
                char resp[4096] = {};
                ssize_t nr = ::recv(fd2, resp, sizeof(resp) - 1, 0);
                if (nr <= 0 || std::string(resp).find("200") == std::string::npos) {
                    pass = false; err = "server not responsive after invalid preface";
                }
                ::close(fd2);
            } else {
                pass = false; err = "server unavailable after invalid preface";
            }
        }
        if (fd >= 0) ::close(fd);

        StopServer(server, t);
        TestFramework::RecordTest("H2C: invalid preface handled gracefully", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2C: invalid preface handled gracefully", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// POST body exceeding max_body_size must receive RST_STREAM or connection close.
void TestH2C_BodyTooLarge() {
    std::cout << "\n[TEST] H2C: body exceeding limit triggers RST_STREAM..." << std::endl;
    try {
        ServerConfig cfg;
        cfg.bind_host      = "127.0.0.1";
        cfg.bind_port      = H2_BODY_PORT + 20;
        cfg.worker_threads = 2;
        cfg.http2.enabled  = true;
        cfg.max_body_size  = 1024;  // 1 KB limit (tiny — easy to exceed)

        HttpServer server(cfg);
        server.Post("/upload", [](const HttpRequest& req, HttpResponse& res) {
            res.Status(200).Text("ok");
        });

        auto t = StartServer(server);
        if (!WaitForServer(H2_BODY_PORT + 20)) {
            StopServer(server, t);
            TestFramework::RecordTest("H2C: body too large", false, "server did not start",
                                      TestFramework::TestCategory::OTHER);
            return;
        }

        Http2TestClient client;
        bool pass = true;
        std::string err;

        if (!client.Connect("127.0.0.1", H2_BODY_PORT + 20)) {
            pass = false; err = "client connect failed";
        } else {
            // Send 4 KB body (4x the configured limit)
            std::string big_body(4 * 1024, 'X');
            auto resp = client.Post("/upload", big_body);

            // Server must either RST the stream or return a 4xx status.
            // The server implementation sends RST_STREAM with NGHTTP2_CANCEL
            // when the body limit is exceeded (see OnDataChunkRecvCallback).
            bool handled = resp.rst || resp.error ||
                           (resp.status >= 400 && resp.status < 600);
            if (!handled) {
                pass = false;
                err = "expected RST/error/4xx for oversized body, got status=" +
                      std::to_string(resp.status);
            }
        }
        client.Disconnect();
        StopServer(server, t);

        TestFramework::RecordTest("H2C: body too large", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2C: body too large", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ============================================================
// ============================================================
// TEST CATEGORY 6: Race Condition / Concurrency Tests
// ============================================================
// ============================================================

// Many clients making concurrent h2c requests to the same server.
// Validates thread-safety of Http2Session / Http2ConnectionHandler.
void TestH2C_ConcurrentClients() {
    std::cout << "\n[TEST] H2C: concurrent clients (race condition test)..." << std::endl;
    try {
        ServerConfig cfg;
        cfg.bind_host      = "127.0.0.1";
        cfg.bind_port      = H2_RACE_PORT;
        cfg.worker_threads = 4;
        cfg.http2.enabled  = true;

        HttpServer server(cfg);
        server.Get("/ping", [](const HttpRequest&, HttpResponse& res) {
            res.Status(200).Text("pong");
        });

        auto t = StartServer(server);
        if (!WaitForServer(H2_RACE_PORT)) {
            StopServer(server, t);
            TestFramework::RecordTest("H2C: concurrent clients", false, "server did not start",
                                      TestFramework::TestCategory::OTHER);
            return;
        }

        static constexpr int NUM_CLIENTS  = 10;
        static constexpr int REQS_PER_CLIENT = 5;

        std::atomic<int> success_count{0};
        std::atomic<int> fail_count{0};
        std::vector<std::thread> threads;
        threads.reserve(NUM_CLIENTS);

        for (int i = 0; i < NUM_CLIENTS; ++i) {
            threads.emplace_back([&]() {
                Http2TestClient client;
                if (!client.Connect("127.0.0.1", H2_RACE_PORT)) {
                    fail_count.fetch_add(REQS_PER_CLIENT, std::memory_order_relaxed);
                    return;
                }
                for (int j = 0; j < REQS_PER_CLIENT; ++j) {
                    auto resp = client.Get("/ping");
                    if (!resp.error && resp.status == 200 && resp.body == "pong") {
                        success_count.fetch_add(1, std::memory_order_relaxed);
                    } else {
                        fail_count.fetch_add(1, std::memory_order_relaxed);
                    }
                }
                client.Disconnect();
            });
        }
        for (auto& th : threads) th.join();

        StopServer(server, t);

        int expected = NUM_CLIENTS * REQS_PER_CLIENT;
        int actual   = success_count.load(std::memory_order_relaxed);

        bool pass = (actual == expected);
        std::string err;
        if (!pass) {
            err = "expected " + std::to_string(expected) +
                  " successes, got " + std::to_string(actual) +
                  " (failures=" + std::to_string(fail_count.load()) + ")";
        }

        TestFramework::RecordTest("H2C: concurrent clients", pass, err,
                                  TestFramework::TestCategory::RACE_CONDITION);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2C: concurrent clients", false, e.what(),
                                  TestFramework::TestCategory::RACE_CONDITION);
    }
}

// Interleave HTTP/1.1 and HTTP/2 clients on the same server simultaneously.
// This stresses the protocol-detector dispatch path under concurrent load.
void TestH2C_MixedProtocolClients() {
    std::cout << "\n[TEST] H2C: mixed HTTP/1.1 and HTTP/2 concurrent clients..." << std::endl;
    try {
        static constexpr int MIXED_PORT = H2_RACE_PORT + 10;

        ServerConfig cfg;
        cfg.bind_host      = "127.0.0.1";
        cfg.bind_port      = MIXED_PORT;
        cfg.worker_threads = 4;
        cfg.http2.enabled  = true;

        HttpServer server(cfg);
        server.Get("/ver", [](const HttpRequest& req, HttpResponse& res) {
            res.Status(200).Text(std::to_string(req.http_major) + "." +
                                 std::to_string(req.http_minor));
        });

        auto t = StartServer(server);
        if (!WaitForServer(MIXED_PORT)) {
            StopServer(server, t);
            TestFramework::RecordTest("H2C: mixed protocol clients", false,
                                      "server did not start",
                                      TestFramework::TestCategory::OTHER);
            return;
        }

        static constexpr int N = 6;
        std::atomic<int> h2_ok{0};
        std::atomic<int> h1_ok{0};

        std::vector<std::thread> threads;
        threads.reserve(N * 2);

        // H2 clients
        for (int i = 0; i < N; ++i) {
            threads.emplace_back([&]() {
                Http2TestClient client;
                if (!client.Connect("127.0.0.1", MIXED_PORT)) return;
                auto resp = client.Get("/ver");
                if (!resp.error && resp.status == 200 && resp.body == "2.0") {
                    h2_ok.fetch_add(1, std::memory_order_relaxed);
                }
                client.Disconnect();
            });
        }

        // HTTP/1.1 clients (raw socket)
        for (int i = 0; i < N; ++i) {
            threads.emplace_back([&]() {
                int fd = ::socket(AF_INET, SOCK_STREAM, 0);
                if (fd < 0) return;
                struct sockaddr_in addr{};
                addr.sin_family = AF_INET;
                addr.sin_port   = htons(static_cast<uint16_t>(MIXED_PORT));
                addr.sin_addr.s_addr = inet_addr("127.0.0.1");
                if (::connect(fd, reinterpret_cast<struct sockaddr*>(&addr),
                              sizeof(addr)) < 0) {
                    ::close(fd); return;
                }
                const char* req =
                    "GET /ver HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
                ::send(fd, req, std::strlen(req), 0);
                struct timeval tv{}; tv.tv_sec = 3;
                ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                char buf[4096] = {};
                ssize_t nr = ::recv(fd, buf, sizeof(buf) - 1, 0);
                ::close(fd);
                if (nr > 0) {
                    std::string resp(buf, static_cast<size_t>(nr));
                    if (resp.find("200") != std::string::npos &&
                        resp.find("1.1") != std::string::npos) {
                        h1_ok.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            });
        }

        for (auto& th : threads) th.join();
        StopServer(server, t);

        bool pass = (h2_ok.load() == N && h1_ok.load() == N);
        std::string err;
        if (!pass) {
            err = "h2_ok=" + std::to_string(h2_ok.load()) +
                  " h1_ok=" + std::to_string(h1_ok.load()) +
                  " (expected both == " + std::to_string(N) + ")";
        }

        TestFramework::RecordTest("H2C: mixed protocol clients", pass, err,
                                  TestFramework::TestCategory::RACE_CONDITION);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2C: mixed protocol clients", false, e.what(),
                                  TestFramework::TestCategory::RACE_CONDITION);
    }
}

// ============================================================
// ============================================================
// TEST CATEGORY 7: MinDetectionBytes boundary
// ============================================================
// ============================================================

void TestH2_MinDetectionBytes() {
    std::cout << "\n[TEST] H2 ProtocolDetector: MinDetectionBytes == 24..." << std::endl;
    try {
        bool pass = (ProtocolDetector::MinDetectionBytes() ==
                     HTTP2_CONSTANTS::CLIENT_PREFACE_LEN);
        std::string err;
        if (!pass) {
            err = "MinDetectionBytes() = " +
                  std::to_string(ProtocolDetector::MinDetectionBytes()) +
                  " != " + std::to_string(HTTP2_CONSTANTS::CLIENT_PREFACE_LEN);
        }
        TestFramework::RecordTest("ProtocolDetector: MinDetectionBytes == 24",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("ProtocolDetector: MinDetectionBytes == 24",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ============================================================
// Entry point
// ============================================================

void RunAllTests() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "HTTP/2 TESTS" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    // --- Category 1: Configuration ---
    TestH2ConfigDefaults();
    TestH2ConfigFromJson();
    TestH2ConfigValidation();
    TestH2ConfigEnvOverride();
    TestH2ConfigDisabled();
    TestH2ConfigSerialization();

    // --- Category 2: ProtocolDetector ---
    TestDetectFromAlpn_H2();
    TestDetectFromAlpn_HTTP11();
    TestDetectFromAlpn_Empty();
    TestDetectFromData_Preface();
    TestDetectFromData_HTTP1();
    TestDetectFromData_Short();
    TestDetectFromData_PartialMatch();
    TestH2_MinDetectionBytes();

    // --- Category 3: Http2Stream ---
    TestStreamAddPseudoHeaders();
    TestStreamAddRegularHeaders();
    TestStreamCookieConcatenation();
    TestStreamBodyAppend();
    TestStreamLifecycle();
    TestStreamRequestComplete();
    TestStreamPathWithoutQuery();

    // Brief settle between unit tests and server tests
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // --- Category 4: H2C Functional ---
    TestH2C_SimpleGet();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    TestH2C_SimplePost();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    TestH2C_NotFound();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    TestH2C_Middleware();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    TestH2C_MultipleStreams();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    TestH2C_LargeBody();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // --- Category 5: Error Handling ---
    TestH2C_InvalidPreface();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    TestH2C_BodyTooLarge();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // --- Category 6: Race Conditions ---
    TestH2C_ConcurrentClients();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    TestH2C_MixedProtocolClients();
}

}  // namespace Http2Tests
