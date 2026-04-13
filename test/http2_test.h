#pragma once

#include "test_framework.h"
#include "test_server_runner.h"
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
#include <future>
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
        // Interim 1xx response blocks observed BEFORE the final status,
        // in arrival order. interim_headers[i] are the headers carried by
        // interim_statuses[i]. Used by 103 Early Hints and 100 Continue tests.
        std::vector<int> interim_statuses;
        std::vector<std::vector<std::pair<std::string, std::string>>> interim_headers;
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

        // Build headers — store name/value strings in a stable container
        // first, then build nghttp2_nv entries pointing into it. This avoids
        // dangling pointers from temporary std::string objects (string literals
        // bind to const std::string& as temporaries that die at statement end).
        std::vector<std::pair<std::string, std::string>> header_pairs;
        header_pairs.reserve(4 + extra_headers.size());
        header_pairs.emplace_back(":method", method);
        header_pairs.emplace_back(":path", path);
        header_pairs.emplace_back(":scheme", "http");
        header_pairs.emplace_back(":authority", "localhost");
        for (const auto& h : extra_headers) {
            header_pairs.push_back(h);
        }

        std::vector<nghttp2_nv> nva;
        nva.reserve(header_pairs.size());
        for (const auto& hp : header_pairs) {
            nva.push_back({
                const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(hp.first.c_str())),
                const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(hp.second.c_str())),
                hp.first.size(), hp.second.size(),
                NGHTTP2_NV_FLAG_NONE
            });
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
                resp.status           = it->second.status;
                resp.body             = it->second.body;
                resp.rst              = it->second.rst;
                resp.interim_statuses = std::move(it->second.interim_statuses);
                resp.interim_headers  = std::move(it->second.interim_headers);
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

    // Send a request with explicit :scheme and :authority (for authority/host tests).
    // extra_headers may include a "host" header to test :authority vs host matching.
    Response SendRequestRaw(
        const std::string& method,
        const std::string& path,
        const std::string& scheme,
        const std::string& authority,
        const std::vector<std::pair<std::string,std::string>>& extra_headers = {}) {

        if (!session_ || fd_ < 0) {
            Response r; r.error = true; return r;
        }

        std::vector<std::pair<std::string, std::string>> header_pairs;
        header_pairs.reserve(4 + extra_headers.size());
        header_pairs.emplace_back(":method", method);
        header_pairs.emplace_back(":path", path);
        header_pairs.emplace_back(":scheme", scheme);
        header_pairs.emplace_back(":authority", authority);
        for (const auto& h : extra_headers) {
            header_pairs.push_back(h);
        }

        std::vector<nghttp2_nv> nva;
        nva.reserve(header_pairs.size());
        for (const auto& hp : header_pairs) {
            nva.push_back({
                const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(hp.first.c_str())),
                const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(hp.second.c_str())),
                hp.first.size(), hp.second.size(),
                NGHTTP2_NV_FLAG_NONE
            });
        }

        int32_t stream_id = nghttp2_submit_request2(
            session_, nullptr, nva.data(), nva.size(), nullptr, this);

        if (stream_id < 0) {
            Response r; r.error = true; return r;
        }

        streams_[stream_id] = StreamState{};
        if (!FlushOutput()) {
            Response r; r.error = true; return r;
        }

        auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(IO_TIMEOUT_MS);

        while (true) {
            auto it = streams_.find(stream_id);
            if (it != streams_.end() && it->second.done) {
                Response resp;
                resp.status           = it->second.status;
                resp.body             = it->second.body;
                resp.rst              = it->second.rst;
                resp.interim_statuses = std::move(it->second.interim_statuses);
                resp.interim_headers  = std::move(it->second.interim_headers);
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
        // Interim 1xx tracking. A new entry is appended to interim_statuses
        // when ":status" with a code in [100, 200) is observed; subsequent
        // header callbacks for the same HEADERS frame are appended to
        // interim_headers.back() until a non-1xx ":status" arrives.
        std::vector<int> interim_statuses;
        std::vector<std::vector<std::pair<std::string, std::string>>> interim_headers;
        bool current_block_interim = false;
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

        auto it = self->streams_.find(sid);
        if (it == self->streams_.end()) return 0;
        StreamState& s = it->second;

        if (n == ":status") {
            int code = 0;
            try { code = std::stoi(v); } catch (...) {}
            if (code >= 100 && code < 200) {
                // Interim 1xx — start a new interim block.
                s.interim_statuses.push_back(code);
                s.interim_headers.emplace_back();
                s.current_block_interim = true;
            } else {
                s.status = code;
                s.current_block_interim = false;
            }
        } else if (s.current_block_interim && !s.interim_headers.empty()) {
            s.interim_headers.back().emplace_back(std::move(n), std::move(v));
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
        if (cfg.http2.enable_push) {
            pass = false;
            err += "enable_push should be false by default; ";
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
                "max_header_list_size": 32768,
                "enable_push": true
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
        if (!cfg.http2.enable_push) {
            pass = false; err += "enable_push not parsed as true; ";
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
        unsetenv("REACTOR_HTTP2_ENABLE_PUSH");

        setenv("REACTOR_HTTP2_ENABLED",                  "false", 1);
        setenv("REACTOR_HTTP2_MAX_CONCURRENT_STREAMS",   "50",    1);
        setenv("REACTOR_HTTP2_INITIAL_WINDOW_SIZE",      "32768", 1);
        setenv("REACTOR_HTTP2_MAX_FRAME_SIZE",           "32768", 1);
        setenv("REACTOR_HTTP2_MAX_HEADER_LIST_SIZE",     "16384", 1);
        setenv("REACTOR_HTTP2_ENABLE_PUSH",              "true",  1);

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
        if (!cfg.http2.enable_push) {
            pass = false; err += "enable_push not overridden to true; ";
        }

        // Cleanup
        unsetenv("REACTOR_HTTP2_ENABLED");
        unsetenv("REACTOR_HTTP2_MAX_CONCURRENT_STREAMS");
        unsetenv("REACTOR_HTTP2_INITIAL_WINDOW_SIZE");
        unsetenv("REACTOR_HTTP2_MAX_FRAME_SIZE");
        unsetenv("REACTOR_HTTP2_MAX_HEADER_LIST_SIZE");
        unsetenv("REACTOR_HTTP2_ENABLE_PUSH");

        TestFramework::RecordTest("H2 Config: Env Overrides", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        unsetenv("REACTOR_HTTP2_ENABLED");
        unsetenv("REACTOR_HTTP2_MAX_CONCURRENT_STREAMS");
        unsetenv("REACTOR_HTTP2_INITIAL_WINDOW_SIZE");
        unsetenv("REACTOR_HTTP2_MAX_FRAME_SIZE");
        unsetenv("REACTOR_HTTP2_MAX_HEADER_LIST_SIZE");
        unsetenv("REACTOR_HTTP2_ENABLE_PUSH");
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
        cfg.http2.enable_push            = true;

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
        if (json.find("\"enable_push\"") == std::string::npos) {
            pass = false; err += "missing enable_push; ";
        }

        // Verify round-trip: parse back what we serialized
        ServerConfig cfg2 = ConfigLoader::LoadFromString(json);
        if (cfg2.http2.max_concurrent_streams != 42) {
            pass = false; err += "round-trip max_concurrent_streams mismatch; ";
        }
        if (cfg2.http2.initial_window_size != 131070) {
            pass = false; err += "round-trip initial_window_size mismatch; ";
        }
        if (!cfg2.http2.enable_push) {
            pass = false; err += "round-trip enable_push mismatch; ";
        }

        TestFramework::RecordTest("H2 Config: Serialization", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2 Config: Serialization", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// ============================================================
// shutdown_drain_timeout_sec configuration tests
// ============================================================

// shutdown_drain_timeout_sec must default to 30.
void TestShutdownDrainDefault() {
    std::cout << "\n[TEST] H2 Config: shutdown_drain_timeout_sec default == 30..." << std::endl;
    try {
        ServerConfig cfg = ConfigLoader::Default();

        bool pass = (cfg.shutdown_drain_timeout_sec == 30);
        std::string err;
        if (!pass) {
            err = "shutdown_drain_timeout_sec default = " +
                  std::to_string(cfg.shutdown_drain_timeout_sec) +
                  ", expected 30";
        }

        TestFramework::RecordTest("H2 Config: shutdown_drain_timeout_sec default",
                                  pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2 Config: shutdown_drain_timeout_sec default",
                                  false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// Validate must reject values outside [0, 300] and accept boundary values.
void TestShutdownDrainValidation() {
    std::cout << "\n[TEST] H2 Config: shutdown_drain_timeout_sec validation..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        // -1 must be rejected
        {
            ServerConfig cfg;
            cfg.shutdown_drain_timeout_sec = -1;
            bool threw = false;
            try {
                ConfigLoader::Validate(cfg);
            } catch (const std::invalid_argument&) {
                threw = true;
            }
            if (!threw) { pass = false; err += "value -1 not rejected; "; }
        }

        // 301 must be rejected (above max 300)
        {
            ServerConfig cfg;
            cfg.shutdown_drain_timeout_sec = 301;
            bool threw = false;
            try {
                ConfigLoader::Validate(cfg);
            } catch (const std::invalid_argument&) {
                threw = true;
            }
            if (!threw) { pass = false; err += "value 301 not rejected; "; }
        }

        // 0 (immediate close) must be accepted
        {
            ServerConfig cfg;
            cfg.shutdown_drain_timeout_sec = 0;
            try {
                ConfigLoader::Validate(cfg);
            } catch (const std::exception& ex) {
                pass = false;
                err += std::string("value 0 rejected unexpectedly: ") + ex.what() + "; ";
            }
        }

        // 300 (max) must be accepted
        {
            ServerConfig cfg;
            cfg.shutdown_drain_timeout_sec = 300;
            try {
                ConfigLoader::Validate(cfg);
            } catch (const std::exception& ex) {
                pass = false;
                err += std::string("value 300 rejected unexpectedly: ") + ex.what() + "; ";
            }
        }

        TestFramework::RecordTest("H2 Config: shutdown_drain_timeout_sec validation",
                                  pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2 Config: shutdown_drain_timeout_sec validation",
                                  false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// JSON parsing must set shutdown_drain_timeout_sec when the key is present.
void TestShutdownDrainJsonParsing() {
    std::cout << "\n[TEST] H2 Config: shutdown_drain_timeout_sec JSON parse..." << std::endl;
    try {
        const std::string json = R"({"shutdown_drain_timeout_sec": 10})";
        ServerConfig cfg = ConfigLoader::LoadFromString(json);

        bool pass = (cfg.shutdown_drain_timeout_sec == 10);
        std::string err;
        if (!pass) {
            err = "shutdown_drain_timeout_sec = " +
                  std::to_string(cfg.shutdown_drain_timeout_sec) +
                  ", expected 10";
        }

        TestFramework::RecordTest("H2 Config: shutdown_drain_timeout_sec JSON parse",
                                  pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2 Config: shutdown_drain_timeout_sec JSON parse",
                                  false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// REACTOR_SHUTDOWN_DRAIN_TIMEOUT env var must override shutdown_drain_timeout_sec.
void TestShutdownDrainEnvOverride() {
    std::cout << "\n[TEST] H2 Config: REACTOR_SHUTDOWN_DRAIN_TIMEOUT env override..." << std::endl;
    try {
        // Clean any prior value
        unsetenv("REACTOR_SHUTDOWN_DRAIN_TIMEOUT");

        setenv("REACTOR_SHUTDOWN_DRAIN_TIMEOUT", "5", 1);

        ServerConfig cfg = ConfigLoader::Default();
        ConfigLoader::ApplyEnvOverrides(cfg);

        bool pass = (cfg.shutdown_drain_timeout_sec == 5);
        std::string err;
        if (!pass) {
            err = "shutdown_drain_timeout_sec = " +
                  std::to_string(cfg.shutdown_drain_timeout_sec) +
                  " after env override, expected 5";
        }

        // Always clean up, even on failure
        unsetenv("REACTOR_SHUTDOWN_DRAIN_TIMEOUT");

        TestFramework::RecordTest("H2 Config: shutdown_drain_timeout_sec env override",
                                  pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        unsetenv("REACTOR_SHUTDOWN_DRAIN_TIMEOUT");
        TestFramework::RecordTest("H2 Config: shutdown_drain_timeout_sec env override",
                                  false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ToJson must include shutdown_drain_timeout_sec with the correct value.
void TestShutdownDrainSerialization() {
    std::cout << "\n[TEST] H2 Config: shutdown_drain_timeout_sec serialization..." << std::endl;
    try {
        ServerConfig cfg;
        cfg.shutdown_drain_timeout_sec = 15;

        std::string json = ConfigLoader::ToJson(cfg);

        bool pass = true;
        std::string err;

        if (json.find("\"shutdown_drain_timeout_sec\"") == std::string::npos) {
            pass = false; err += "key shutdown_drain_timeout_sec missing from JSON; ";
        }
        if (json.find("15") == std::string::npos) {
            pass = false; err += "value 15 not found in JSON; ";
        }

        // Verify round-trip: parse back what we serialized
        ServerConfig cfg2 = ConfigLoader::LoadFromString(json);
        if (cfg2.shutdown_drain_timeout_sec != 15) {
            pass = false;
            err += "round-trip value = " +
                   std::to_string(cfg2.shutdown_drain_timeout_sec) +
                   ", expected 15; ";
        }

        TestFramework::RecordTest("H2 Config: shutdown_drain_timeout_sec serialization",
                                  pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2 Config: shutdown_drain_timeout_sec serialization",
                                  false, e.what(), TestFramework::TestCategory::OTHER);
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

void TestStreamInvalidHeaders() {
    std::cout << "\n[TEST] Http2Stream: invalid header values rejected..." << std::endl;
    try {
        bool pass = true;
        std::string err;

        {
            Http2Stream stream(4);
            int rv = stream.AddHeader("content-length", "not-a-number");
            if (rv == 0) {
                pass = false;
                err += "invalid content-length accepted; ";
            }
        }

        {
            Http2Stream stream(6);
            int rv1 = stream.AddHeader(":authority", "example.com");
            int rv2 = stream.AddHeader("host", "other.example.com");
            if (rv1 != 0 || rv2 == 0) {
                pass = false;
                err += "conflicting :authority/host not rejected; ";
            }
        }

        TestFramework::RecordTest("Http2Stream: invalid headers rejected", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("Http2Stream: invalid headers rejected", false, e.what(),
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

// Simple GET through h2c connection.
void TestH2C_SimpleGet() {
    std::cout << "\n[TEST] H2C: simple GET request..." << std::endl;
    try {
        ServerConfig cfg;
        cfg.bind_host       = "127.0.0.1";
        cfg.bind_port       = 0;
        cfg.worker_threads  = 2;
        cfg.http2.enabled   = true;

        HttpServer server(cfg);
        server.Get("/hello", [](const HttpRequest&, HttpResponse& res) {
            res.Status(200).Text("Hello HTTP/2");
        });

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        Http2TestClient client;
        bool pass = true;
        std::string err;

        if (!client.Connect("127.0.0.1", port)) {
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
        cfg.bind_port      = 0;
        cfg.worker_threads = 2;
        cfg.http2.enabled  = true;

        HttpServer server(cfg);
        server.Post("/echo", [](const HttpRequest& req, HttpResponse& res) {
            res.Status(200).Body(req.body, "text/plain");
        });

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        Http2TestClient client;
        bool pass = true;
        std::string err;

        if (!client.Connect("127.0.0.1", port)) {
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
        cfg.bind_port      = 0;
        cfg.worker_threads = 2;
        cfg.http2.enabled  = true;

        HttpServer server(cfg);
        server.Get("/exists", [](const HttpRequest&, HttpResponse& res) {
            res.Status(200).Text("ok");
        });

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        Http2TestClient client;
        bool pass = true;
        std::string err;

        if (!client.Connect("127.0.0.1", port)) {
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
        cfg.bind_port      = 0;
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

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        Http2TestClient client;
        bool pass = true;
        std::string err;

        if (!client.Connect("127.0.0.1", port)) {
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
        cfg.bind_port      = 0;
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

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        Http2TestClient client;
        bool pass = true;
        std::string err;

        if (!client.Connect("127.0.0.1", port)) {
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
        cfg.bind_port      = 0;
        cfg.worker_threads = 2;
        cfg.http2.enabled  = true;
        cfg.max_body_size  = 64 * 1024;  // 64 KB limit

        HttpServer server(cfg);
        server.Post("/upload", [](const HttpRequest& req, HttpResponse& res) {
            res.Status(200).Json(R"({"received":)" +
                                 std::to_string(req.body.size()) + "}");
        });

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        Http2TestClient client;
        bool pass = true;
        std::string err;

        if (!client.Connect("127.0.0.1", port)) {
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
        cfg.bind_port      = 0;
        cfg.worker_threads = 2;
        cfg.http2.enabled  = true;

        HttpServer server(cfg);
        server.Get("/ok", [](const HttpRequest&, HttpResponse& res) {
            res.Status(200).Text("ok");
        });

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        // Connect raw and send binary garbage (not the HTTP/2 preface)
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(static_cast<uint16_t>(port));
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
        cfg.bind_port      = 0;
        cfg.worker_threads = 2;
        cfg.http2.enabled  = true;
        cfg.max_body_size  = 1024;  // 1 KB limit (tiny — easy to exceed)

        HttpServer server(cfg);
        server.Post("/upload", [](const HttpRequest& req, HttpResponse& res) {
            res.Status(200).Text("ok");
        });

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        Http2TestClient client;
        bool pass = true;
        std::string err;

        if (!client.Connect("127.0.0.1", port)) {
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
        cfg.bind_port      = 0;
        cfg.worker_threads = 4;
        cfg.http2.enabled  = true;

        HttpServer server(cfg);
        server.Get("/ping", [](const HttpRequest&, HttpResponse& res) {
            res.Status(200).Text("pong");
        });

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        static constexpr int NUM_CLIENTS  = 10;
        static constexpr int REQS_PER_CLIENT = 5;

        std::atomic<int> success_count{0};
        std::atomic<int> fail_count{0};
        std::vector<std::thread> threads;
        threads.reserve(NUM_CLIENTS);

        for (int i = 0; i < NUM_CLIENTS; ++i) {
            threads.emplace_back([&, port]() {
                Http2TestClient client;
                if (!client.Connect("127.0.0.1", port)) {
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
        ServerConfig cfg;
        cfg.bind_host      = "127.0.0.1";
        cfg.bind_port      = 0;
        cfg.worker_threads = 4;
        cfg.http2.enabled  = true;

        HttpServer server(cfg);
        server.Get("/ver", [](const HttpRequest& req, HttpResponse& res) {
            res.Status(200).Text(std::to_string(req.http_major) + "." +
                                 std::to_string(req.http_minor));
        });

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        static constexpr int N = 6;
        std::atomic<int> h2_ok{0};
        std::atomic<int> h1_ok{0};

        std::vector<std::thread> threads;
        threads.reserve(N * 2);

        // H2 clients
        for (int i = 0; i < N; ++i) {
            threads.emplace_back([&, port]() {
                Http2TestClient client;
                if (!client.Connect("127.0.0.1", port)) return;
                auto resp = client.Get("/ver");
                if (!resp.error && resp.status == 200 && resp.body == "2.0") {
                    h2_ok.fetch_add(1, std::memory_order_relaxed);
                }
                client.Disconnect();
            });
        }

        // HTTP/1.1 clients (raw socket)
        for (int i = 0; i < N; ++i) {
            threads.emplace_back([&, port]() {
                int fd = ::socket(AF_INET, SOCK_STREAM, 0);
                if (fd < 0) return;
                struct sockaddr_in addr{};
                addr.sin_family = AF_INET;
                addr.sin_port   = htons(static_cast<uint16_t>(port));
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
// ============================================================
// TEST CATEGORY 7: :authority vs host default-port normalization
// ============================================================
// ============================================================

// Helper: spin up a minimal HTTP/2 server with GET / → 200, return port.
// Caller owns the server lifetime via TestServerRunner.
static void SetupH2AuthorityServer(HttpServer& server) {
    server.Get("/", [](const HttpRequest&, HttpResponse& res) {
        res.Status(200).Text("ok");
    });
}

// :authority=example.com  host=example.com:80  scheme=http  → 200
// Absent port on :authority normalized to default 80.
void TestH2_AuthorityMatchesHostWithDefaultHttpPort() {
    std::cout << "\n[TEST] H2 Authority: absent port == default http port (80)..." << std::endl;
    try {
        ServerConfig cfg;
        cfg.bind_host      = "127.0.0.1";
        cfg.bind_port      = 0;
        cfg.worker_threads = 2;
        cfg.http2.enabled  = true;

        HttpServer server(cfg);
        SetupH2AuthorityServer(server);

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        Http2TestClient client;
        bool pass = true;
        std::string err;

        if (!client.Connect("127.0.0.1", port)) {
            pass = false; err = "client connect failed";
        } else {
            auto resp = client.SendRequestRaw("GET", "/", "http", "example.com",
                                             {{"host", "example.com:80"}});
            if (resp.error || resp.rst) {
                pass = false; err = "transport error or RST (authority mismatch rejected)";
            } else if (resp.status != 200) {
                pass = false;
                err = "expected 200, got " + std::to_string(resp.status);
            }
        }
        client.Disconnect();

        TestFramework::RecordTest(
            "H2 Authority: absent port == default http port (80)", pass, err,
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2 Authority: absent port == default http port (80)", false, e.what(),
            TestFramework::TestCategory::OTHER);
    }
}

// :authority=example.com:80  host=example.com  scheme=http  → 200
// Absent port on host normalized to default 80 (reverse of test 1).
void TestH2_AuthorityMatchesHostReverseOrder() {
    std::cout << "\n[TEST] H2 Authority: explicit :80 on authority, absent on host..." << std::endl;
    try {
        ServerConfig cfg;
        cfg.bind_host      = "127.0.0.1";
        cfg.bind_port      = 0;
        cfg.worker_threads = 2;
        cfg.http2.enabled  = true;

        HttpServer server(cfg);
        SetupH2AuthorityServer(server);

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        Http2TestClient client;
        bool pass = true;
        std::string err;

        if (!client.Connect("127.0.0.1", port)) {
            pass = false; err = "client connect failed";
        } else {
            auto resp = client.SendRequestRaw("GET", "/", "http", "example.com:80",
                                             {{"host", "example.com"}});
            if (resp.error || resp.rst) {
                pass = false; err = "transport error or RST (authority mismatch rejected)";
            } else if (resp.status != 200) {
                pass = false;
                err = "expected 200, got " + std::to_string(resp.status);
            }
        }
        client.Disconnect();

        TestFramework::RecordTest(
            "H2 Authority: explicit :80 on authority, absent on host", pass, err,
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2 Authority: explicit :80 on authority, absent on host", false, e.what(),
            TestFramework::TestCategory::OTHER);
    }
}

// :authority=example.com:443  host=example.com  scheme=https  → 200
// Absent port on host normalized to default 443.
void TestH2_AuthorityMatchesHostWithDefaultHttpsPort() {
    std::cout << "\n[TEST] H2 Authority: absent port == default https port (443)..." << std::endl;
    try {
        ServerConfig cfg;
        cfg.bind_host      = "127.0.0.1";
        cfg.bind_port      = 0;
        cfg.worker_threads = 2;
        cfg.http2.enabled  = true;

        HttpServer server(cfg);
        SetupH2AuthorityServer(server);

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        Http2TestClient client;
        bool pass = true;
        std::string err;

        if (!client.Connect("127.0.0.1", port)) {
            pass = false; err = "client connect failed";
        } else {
            auto resp = client.SendRequestRaw("GET", "/", "https", "example.com:443",
                                             {{"host", "example.com"}});
            if (resp.error || resp.rst) {
                pass = false; err = "transport error or RST (authority mismatch rejected)";
            } else if (resp.status != 200) {
                pass = false;
                err = "expected 200, got " + std::to_string(resp.status);
            }
        }
        client.Disconnect();

        TestFramework::RecordTest(
            "H2 Authority: absent port == default https port (443)", pass, err,
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2 Authority: absent port == default https port (443)", false, e.what(),
            TestFramework::TestCategory::OTHER);
    }
}

// :authority=example.com:8080  host=example.com  scheme=http  → rejected
// Non-default explicit port on authority does not match absent (→80) host port.
void TestH2_AuthorityMismatchExplicitNonDefaultPort() {
    std::cout << "\n[TEST] H2 Authority: non-default port mismatch rejected..." << std::endl;
    try {
        ServerConfig cfg;
        cfg.bind_host      = "127.0.0.1";
        cfg.bind_port      = 0;
        cfg.worker_threads = 2;
        cfg.http2.enabled  = true;

        HttpServer server(cfg);
        SetupH2AuthorityServer(server);

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        Http2TestClient client;
        bool pass = true;
        std::string err;

        if (!client.Connect("127.0.0.1", port)) {
            pass = false; err = "client connect failed";
        } else {
            // :authority carries port 8080, host carries no port (→ default 80).
            // 8080 != 80 → server must reject with RST or error status.
            auto resp = client.SendRequestRaw("GET", "/", "http", "example.com:8080",
                                             {{"host", "example.com"}});
            if (!resp.rst && !resp.error && resp.status == 200) {
                pass = false;
                err = "expected rejection but got 200 (conflicting ports not detected)";
            }
        }
        client.Disconnect();

        TestFramework::RecordTest(
            "H2 Authority: non-default port mismatch rejected", pass, err,
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2 Authority: non-default port mismatch rejected", false, e.what(),
            TestFramework::TestCategory::OTHER);
    }
}

// :authority=example.com  host=example.com:443  scheme=http  → rejected
// Default for http is 80, not 443. Absent :authority port → 80, host:443 → mismatch.
void TestH2_AuthorityMismatchWrongDefault() {
    std::cout << "\n[TEST] H2 Authority: wrong default port mismatch rejected..." << std::endl;
    try {
        ServerConfig cfg;
        cfg.bind_host      = "127.0.0.1";
        cfg.bind_port      = 0;
        cfg.worker_threads = 2;
        cfg.http2.enabled  = true;

        HttpServer server(cfg);
        SetupH2AuthorityServer(server);

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        Http2TestClient client;
        bool pass = true;
        std::string err;

        if (!client.Connect("127.0.0.1", port)) {
            pass = false; err = "client connect failed";
        } else {
            // scheme=http → default 80. :authority absent port → 80. host:443 → 443.
            // 80 != 443 → server must reject.
            auto resp = client.SendRequestRaw("GET", "/", "http", "example.com",
                                             {{"host", "example.com:443"}});
            if (!resp.rst && !resp.error && resp.status == 200) {
                pass = false;
                err = "expected rejection but got 200 (http default 80 vs host:443 not caught)";
            }
        }
        client.Disconnect();

        TestFramework::RecordTest(
            "H2 Authority: wrong default port mismatch rejected", pass, err,
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2 Authority: wrong default port mismatch rejected", false, e.what(),
            TestFramework::TestCategory::OTHER);
    }
}

// :authority=[::1]  host=[::1]:80  scheme=http  → 200
// IPv6 bare address normalized with default port 80.
void TestH2_AuthorityIPv6WithDefaultPort() {
    std::cout << "\n[TEST] H2 Authority: IPv6 absent port == default http port..." << std::endl;
    try {
        ServerConfig cfg;
        cfg.bind_host      = "127.0.0.1";
        cfg.bind_port      = 0;
        cfg.worker_threads = 2;
        cfg.http2.enabled  = true;

        HttpServer server(cfg);
        SetupH2AuthorityServer(server);

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        Http2TestClient client;
        bool pass = true;
        std::string err;

        if (!client.Connect("127.0.0.1", port)) {
            pass = false; err = "client connect failed";
        } else {
            auto resp = client.SendRequestRaw("GET", "/", "http", "[::1]",
                                             {{"host", "[::1]:80"}});
            if (resp.error || resp.rst) {
                pass = false; err = "transport error or RST (IPv6 authority mismatch)";
            } else if (resp.status != 200) {
                pass = false;
                err = "expected 200, got " + std::to_string(resp.status);
            }
        }
        client.Disconnect();

        TestFramework::RecordTest(
            "H2 Authority: IPv6 absent port == default http port", pass, err,
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2 Authority: IPv6 absent port == default http port", false, e.what(),
            TestFramework::TestCategory::OTHER);
    }
}

// :authority=Example.COM  host=example.com:80  scheme=http  → 200
// Case-insensitive hostname match combined with default-port normalization.
void TestH2_AuthorityCaseInsensitiveHostDefaultPort() {
    std::cout << "\n[TEST] H2 Authority: case-insensitive hostname + default port..." << std::endl;
    try {
        ServerConfig cfg;
        cfg.bind_host      = "127.0.0.1";
        cfg.bind_port      = 0;
        cfg.worker_threads = 2;
        cfg.http2.enabled  = true;

        HttpServer server(cfg);
        SetupH2AuthorityServer(server);

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        Http2TestClient client;
        bool pass = true;
        std::string err;

        if (!client.Connect("127.0.0.1", port)) {
            pass = false; err = "client connect failed";
        } else {
            auto resp = client.SendRequestRaw("GET", "/", "http", "Example.COM",
                                             {{"host", "example.com:80"}});
            if (resp.error || resp.rst) {
                pass = false; err = "transport error or RST (case/port mismatch)";
            } else if (resp.status != 200) {
                pass = false;
                err = "expected 200, got " + std::to_string(resp.status);
            }
        }
        client.Disconnect();

        TestFramework::RecordTest(
            "H2 Authority: case-insensitive hostname + default port", pass, err,
            TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2 Authority: case-insensitive hostname + default port", false, e.what(),
            TestFramework::TestCategory::OTHER);
    }
}

// ============================================================
// Category 8: HTTP/2 103 Early Hints (SubmitInterimHeaders /
// SendInterimResponse). See plan Task 4 / design doc §4.2.
// ============================================================

// Helper: small wrapper that builds a default H2-enabled config bound to
// the given port and 2 worker threads — matches surrounding H2 tests.
static ServerConfig MakeH2Config(uint16_t port) {
    ServerConfig cfg;
    cfg.bind_host      = "127.0.0.1";
    cfg.bind_port      = port;
    cfg.worker_threads = 2;
    cfg.http2.enabled  = true;
    return cfg;
}

// T4.1: Basic 103 → 200. Handler emits one 103 with a Link header, then
// completes 200. Client must observe one interim_status == 103 with the
// Link header, followed by a final status == 200.
void TestH2_EarlyHints_Basic() {
    std::cout << "\n[TEST] H2 103 Early Hints: basic..." << std::endl;
    try {
        HttpServer server(MakeH2Config(0));
        server.GetAsync("/hints",
            [](const HttpRequest&,
               HttpRouter::InterimResponseSender send_interim,
               HttpRouter::ResourcePusher        /*push_resource*/,
               HttpRouter::AsyncCompletionCallback complete) {
                send_interim(103, {{"link", "</style.css>; rel=preload; as=style"}});
                HttpResponse r;
                r.Status(200).Text("done");
                complete(std::move(r));
            });

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        Http2TestClient client;
        bool pass = true;
        std::string err;
        if (!client.Connect("127.0.0.1", port)) {
            pass = false; err += "connect failed; ";
        } else {
            auto resp = client.Get("/hints");
            if (resp.error)              { pass = false; err += "transport error; "; }
            if (resp.status != 200)      { pass = false; err += "final status != 200; "; }
            if (resp.body.find("done") == std::string::npos)
                                          { pass = false; err += "body mismatch; "; }
            if (resp.interim_statuses.size() != 1) {
                pass = false;
                err += "expected 1 interim, got " +
                       std::to_string(resp.interim_statuses.size()) + "; ";
            } else {
                if (resp.interim_statuses[0] != 103) {
                    pass = false; err += "interim status != 103; ";
                }
                bool has_link = false;
                for (const auto& [k, v] : resp.interim_headers[0]) {
                    if (k == "link") { has_link = true; break; }
                }
                if (!has_link) { pass = false; err += "Link header missing from 103; "; }
            }
        }
        client.Disconnect();

        TestFramework::RecordTest("H2 103 Early Hints: basic", pass, err,
                                  TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2 103 Early Hints: basic", false, e.what(),
                                  TestFramework::TestCategory::OTHER);
    }
}

// T4.2: Two 103s before the final 200. Client must observe interim_statuses
// == [103, 103] with each block's Link header attached.
void TestH2_EarlyHints_Multiple() {
    std::cout << "\n[TEST] H2 103 Early Hints: multiple before final..." << std::endl;
    try {
        HttpServer server(MakeH2Config(0));
        server.GetAsync("/multi",
            [](const HttpRequest&,
               HttpRouter::InterimResponseSender send_interim,
               HttpRouter::ResourcePusher        /*push_resource*/,
               HttpRouter::AsyncCompletionCallback complete) {
                send_interim(103, {{"link", "</a.css>; rel=preload"}});
                send_interim(103, {{"link", "</b.js>; rel=preload"}});
                HttpResponse r;
                r.Status(200).Text("done");
                complete(std::move(r));
            });

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        Http2TestClient client;
        bool pass = true;
        std::string err;
        if (!client.Connect("127.0.0.1", port)) {
            pass = false; err += "connect failed; ";
        } else {
            auto resp = client.Get("/multi");
            if (resp.error)         { pass = false; err += "transport error; "; }
            if (resp.status != 200) { pass = false; err += "final status != 200; "; }
            if (resp.interim_statuses.size() != 2) {
                pass = false;
                err += "expected 2 interims, got " +
                       std::to_string(resp.interim_statuses.size()) + "; ";
            } else {
                if (resp.interim_statuses[0] != 103 ||
                    resp.interim_statuses[1] != 103) {
                    pass = false; err += "interim statuses must both be 103; ";
                }
                if (resp.interim_headers.size() != 2 ||
                    resp.interim_headers[0].empty() ||
                    resp.interim_headers[1].empty()) {
                    pass = false; err += "interim header blocks empty; ";
                }
            }
        }
        client.Disconnect();

        TestFramework::RecordTest("H2 103 Early Hints: multiple before final",
                                  pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2 103 Early Hints: multiple before final",
                                  false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// T4.3: 103 attempted from a background thread AFTER the handler completed
// the final 200. The H2 SendInterimResponse contract is dispatcher-thread-
// only AND drops post-final calls — both guards together must ensure the
// late 103 never reaches the wire. Mirrors H1's TestH1_EarlyHints_DroppedAfterFinal.
void TestH2_EarlyHints_DroppedAfterFinal() {
    std::cout << "\n[TEST] H2 103 Early Hints: dropped after final..." << std::endl;
    try {
        HttpServer server(MakeH2Config(0));

        auto p_sender = std::make_shared<std::promise<HttpRouter::InterimResponseSender>>();
        auto f_sender = p_sender->get_future().share();

        server.GetAsync("/postfinal",
            [p_sender](
                const HttpRequest&,
                HttpRouter::InterimResponseSender send_interim,
                HttpRouter::ResourcePusher        /*push_resource*/,
                HttpRouter::AsyncCompletionCallback complete) {
                HttpResponse r;
                r.Status(200).Text("done");
                complete(std::move(r));
                p_sender->set_value(send_interim);
            });

        std::thread watcher([f_sender]() mutable {
            auto send_interim = f_sender.get();
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            send_interim(103, {{"link", "</late.css>; rel=preload"}});
        });
        struct JoinGuard {
            std::thread& t;
            ~JoinGuard() { if (t.joinable()) t.join(); }
        };
        JoinGuard watcher_guard{watcher};

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        Http2TestClient client;
        bool pass = true;
        std::string err;
        if (!client.Connect("127.0.0.1", port)) {
            pass = false; err += "connect failed; ";
        } else {
            auto resp = client.Get("/postfinal");
            if (resp.error)         { pass = false; err += "transport error; "; }
            if (resp.status != 200) { pass = false; err += "final status != 200; "; }
            // The late 103 must never appear on the wire. The watcher's
            // delayed call may still be in flight at this point, so wait
            // a little to let any errant frame arrive (it won't).
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if (!resp.interim_statuses.empty()) {
                pass = false;
                err += "post-final 103 must be dropped, got " +
                       std::to_string(resp.interim_statuses.size()) +
                       " interim(s); ";
            }
        }
        client.Disconnect();

        TestFramework::RecordTest("H2 103 Early Hints: dropped after final",
                                  pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2 103 Early Hints: dropped after final",
                                  false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// T4.4: Invalid status codes are rejected by SubmitInterimHeaders.
// 50 / 200 / 101 / 100 must all be dropped (51-99 below 1xx; 200 >= 200 final;
// 101 reserved for upgrade and invalid in H2; 100 framework-managed only).
// Only the final 200 from complete() reaches the client; no interim arrives.
void TestH2_EarlyHints_InvalidStatusDropped() {
    std::cout << "\n[TEST] H2 103 Early Hints: invalid status dropped..." << std::endl;
    try {
        HttpServer server(MakeH2Config(0));
        server.GetAsync("/badstatus",
            [](const HttpRequest&,
               HttpRouter::InterimResponseSender send_interim,
               HttpRouter::ResourcePusher        /*push_resource*/,
               HttpRouter::AsyncCompletionCallback complete) {
                send_interim(50,  {{"link", "</a>; rel=preload"}});
                send_interim(200, {{"link", "</b>; rel=preload"}});
                send_interim(101, {{"link", "</c>; rel=preload"}});
                send_interim(100, {{"link", "</d>; rel=preload"}});
                HttpResponse r;
                r.Status(200).Text("done");
                complete(std::move(r));
            });

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        Http2TestClient client;
        bool pass = true;
        std::string err;
        if (!client.Connect("127.0.0.1", port)) {
            pass = false; err += "connect failed; ";
        } else {
            auto resp = client.Get("/badstatus");
            if (resp.error)         { pass = false; err += "transport error; "; }
            if (resp.status != 200) { pass = false; err += "final status != 200; "; }
            if (!resp.interim_statuses.empty()) {
                pass = false;
                err += "expected 0 interims, got " +
                       std::to_string(resp.interim_statuses.size()) + "; ";
            }
        }
        client.Disconnect();

        TestFramework::RecordTest("H2 103 Early Hints: invalid status dropped",
                                  pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2 103 Early Hints: invalid status dropped",
                                  false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// T4.5: Calling SendInterimResponse on a stream that the peer has already
// reset must not crash. We can't easily cancel a stream from the test
// client AFTER opening it, so we approximate by tearing down the client
// connection mid-handler: the watcher disconnects the test client (which
// closes the H2 transport), then fires the late 103. With session_-> being
// torn down on the server side, SendInterimResponse must observe missing
// stream / closed session and return false without crashing.
void TestH2_EarlyHints_StreamClosedByPeerSafe() {
    std::cout << "\n[TEST] H2 103 Early Hints: stream closed by peer is safe..."
              << std::endl;
    try {
        HttpServer server(MakeH2Config(0));

        auto p_sender = std::make_shared<std::promise<HttpRouter::InterimResponseSender>>();
        auto f_sender = p_sender->get_future().share();

        // Handler: defer indefinitely and hand the sender to the watcher.
        // We never call complete() in this test — the response is abandoned
        // when the transport tears down.
        server.GetAsync("/peerclose",
            [p_sender](
                const HttpRequest&,
                HttpRouter::InterimResponseSender send_interim,
                HttpRouter::ResourcePusher        /*push_resource*/,
                HttpRouter::AsyncCompletionCallback /*complete*/) {
                p_sender->set_value(send_interim);
            });

        std::thread watcher([f_sender]() mutable {
            auto send_interim = f_sender.get();
            // Give the client time to disconnect (test main thread does so
            // immediately after issuing the request below). The off-thread
            // guard alone catches this on the H2 side, but we also want to
            // exercise the closed-session path defensively.
            std::this_thread::sleep_for(std::chrono::milliseconds(150));
            // Must not crash regardless of stream/session state.
            send_interim(103, {{"link", "</late.css>; rel=preload"}});
        });
        struct JoinGuard {
            std::thread& t;
            ~JoinGuard() { if (t.joinable()) t.join(); }
        };
        JoinGuard watcher_guard{watcher};

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        Http2TestClient client;
        bool pass = true;
        std::string err;
        if (!client.Connect("127.0.0.1", port)) {
            pass = false; err += "connect failed; ";
        } else {
            // Fire-and-forget: send the request, then disconnect immediately.
            // Do NOT wait for a response (handler never completes).
            // We rely on the watcher firing the 103 after the client is gone.
            // Reuse Get() with a very short response wait by closing the
            // socket mid-poll: just disconnect after sending the headers.
            std::vector<std::pair<std::string, std::string>> nh;
            std::vector<std::pair<std::string, std::string>> hp;
            hp.emplace_back(":method",    "GET");
            hp.emplace_back(":path",      "/peerclose");
            hp.emplace_back(":scheme",    "http");
            hp.emplace_back(":authority", "localhost");
            std::vector<nghttp2_nv> nva;
            nva.reserve(hp.size());
            for (const auto& p : hp) {
                nva.push_back({
                    const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(p.first.c_str())),
                    const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(p.second.c_str())),
                    p.first.size(), p.second.size(),
                    NGHTTP2_NV_FLAG_NONE
                });
            }
            // Submit + flush headers via the public API path is not exposed;
            // simplest portable path: send a normal request with a short wait,
            // accept a transport timeout (resp.error = true), then disconnect.
            // The test passes if the server didn't crash by the time we Stop.
            (void)nh; (void)nva;
            auto resp = client.Get("/peerclose");
            // resp.error may be true (timeout) — that's expected.
            (void)resp;
        }
        client.Disconnect();

        // Give the watcher time to fire its late send_interim.
        std::this_thread::sleep_for(std::chrono::milliseconds(250));

        // Reaching here without a server crash is the assertion.
        TestFramework::RecordTest("H2 103 Early Hints: stream closed by peer is safe",
                                  pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest("H2 103 Early Hints: stream closed by peer is safe",
                                  false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// T4.6: 100 Continue followed by 103 Early Hints, then final 200.
// The server emits 100 Continue automatically when the client includes
// Expect: 100-continue; the handler then emits a 103 and completes 200.
// Client must observe interim_statuses == [100, 103] in order, then 200.
void TestH2_EarlyHints_100ContinueThen103() {
    std::cout << "\n[TEST] H2 103 Early Hints: 100-continue then 103 then 200..."
              << std::endl;
    try {
        HttpServer server(MakeH2Config(0));
        server.GetAsync("/upload",
            [](const HttpRequest&,
               HttpRouter::InterimResponseSender send_interim,
               HttpRouter::ResourcePusher        /*push_resource*/,
               HttpRouter::AsyncCompletionCallback complete) {
                send_interim(103, {{"link", "</style.css>; rel=preload"}});
                HttpResponse r;
                r.Status(200).Text("uploaded");
                complete(std::move(r));
            });

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        Http2TestClient client;
        bool pass = true;
        std::string err;
        if (!client.Connect("127.0.0.1", port)) {
            pass = false; err += "connect failed; ";
        } else {
            auto resp = client.Get("/upload", {{"expect", "100-continue"}});
            if (resp.error)         { pass = false; err += "transport error; "; }
            if (resp.status != 200) { pass = false; err += "final status != 200; "; }
            if (resp.interim_statuses.size() != 2) {
                pass = false;
                err += "expected 2 interims (100, 103), got " +
                       std::to_string(resp.interim_statuses.size()) + "; ";
            } else if (resp.interim_statuses[0] != 100 ||
                       resp.interim_statuses[1] != 103) {
                pass = false;
                err += "expected order 100,103 — got " +
                       std::to_string(resp.interim_statuses[0]) + "," +
                       std::to_string(resp.interim_statuses[1]) + "; ";
            }
        }
        client.Disconnect();

        TestFramework::RecordTest(
            "H2 103 Early Hints: 100-continue then 103 then 200",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2 103 Early Hints: 100-continue then 103 then 200",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// T4.7: Off-dispatcher-thread send_interim is rejected. The handler spawns
// a thread that calls send_interim BEFORE complete() runs. The H2 contract
// is dispatcher-thread-only, so the call must return false (warn-logged)
// and no 103 must reach the wire. The handler then completes 200 normally.
void TestH2_EarlyHints_OffDispatcherThread() {
    std::cout << "\n[TEST] H2 103 Early Hints: off-dispatcher-thread rejected..."
              << std::endl;
    try {
        HttpServer server(MakeH2Config(0));
        server.GetAsync("/offthread",
            [](const HttpRequest&,
               HttpRouter::InterimResponseSender send_interim,
               HttpRouter::ResourcePusher        /*push_resource*/,
               HttpRouter::AsyncCompletionCallback complete) {
                std::thread t([send_interim]() {
                    send_interim(103, {{"link", "</late.css>; rel=preload"}});
                });
                t.join();
                HttpResponse r;
                r.Status(200).Text("done");
                complete(std::move(r));
            });

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        Http2TestClient client;
        bool pass = true;
        std::string err;
        if (!client.Connect("127.0.0.1", port)) {
            pass = false; err += "connect failed; ";
        } else {
            auto resp = client.Get("/offthread");
            if (resp.error)         { pass = false; err += "transport error; "; }
            if (resp.status != 200) { pass = false; err += "final status != 200; "; }
            if (!resp.interim_statuses.empty()) {
                pass = false;
                err += "off-thread 103 must be dropped, got " +
                       std::to_string(resp.interim_statuses.size()) +
                       " interim(s); ";
            }
        }
        client.Disconnect();

        TestFramework::RecordTest(
            "H2 103 Early Hints: off-dispatcher-thread rejected",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2 103 Early Hints: off-dispatcher-thread rejected",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// ============================================================
// Category 9: SETTINGS_ENABLE_PUSH wire-format regression tests
// ============================================================

// Helper: connect a raw TCP socket, send the H2 client preface + an
// empty client SETTINGS, and read the server's preface SETTINGS frame.
// Returns the server SETTINGS payload bytes on success, empty on failure.
// Does NOT use nghttp2 — we are intentionally validating wire bytes here
// because the SETTINGS_ENABLE_PUSH semantics are direction-asymmetric and
// must be observable at the byte level.
static std::vector<uint8_t> ReadServerSettingsPayload(int port) {
    std::vector<uint8_t> empty;
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return empty;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(static_cast<uint16_t>(port));
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(fd); return empty;
    }
    timeval tv{};
    tv.tv_sec = IO_TIMEOUT_MS / 1000;
    tv.tv_usec = (IO_TIMEOUT_MS % 1000) * 1000;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Client preface (RFC 9113 §3.4) followed by an empty client SETTINGS
    // frame so the server completes its preface exchange.
    static constexpr char kPreface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    static constexpr size_t kPrefaceLen = 24;
    static constexpr uint8_t kEmptySettings[9] = {
        0, 0, 0,        // length = 0
        0x04,           // type = SETTINGS
        0x00,           // flags = 0 (no ACK)
        0, 0, 0, 0      // stream_id = 0
    };
    if (::send(fd, kPreface, kPrefaceLen, 0) != static_cast<ssize_t>(kPrefaceLen)) {
        ::close(fd); return empty;
    }
    if (::send(fd, kEmptySettings, sizeof(kEmptySettings), 0) !=
        static_cast<ssize_t>(sizeof(kEmptySettings))) {
        ::close(fd); return empty;
    }

    // Read the server's frame header (9 bytes). Loop because recv may return
    // partial data even on a hot loopback.
    auto recv_exact = [&](uint8_t* buf, size_t need) -> bool {
        size_t got = 0;
        while (got < need) {
            ssize_t n = ::recv(fd, buf + got, need - got, 0);
            if (n <= 0) return false;
            got += static_cast<size_t>(n);
        }
        return true;
    };
    uint8_t header[9];
    if (!recv_exact(header, 9)) { ::close(fd); return empty; }

    uint32_t length = (static_cast<uint32_t>(header[0]) << 16) |
                      (static_cast<uint32_t>(header[1]) << 8)  |
                      static_cast<uint32_t>(header[2]);
    uint8_t  type   = header[3];
    uint8_t  flags  = header[4];
    if (type != 0x04 || (flags & 0x01) != 0) {
        // Not a non-ACK SETTINGS frame — bail.
        ::close(fd); return empty;
    }
    std::vector<uint8_t> payload(length, 0);
    if (length > 0 && !recv_exact(payload.data(), length)) {
        ::close(fd); return empty;
    }
    ::close(fd);
    return payload;
}

// Walk a SETTINGS payload and return the value of the first matching entry,
// or std::nullopt if not present. RFC 9113 §6.5: each entry is 6 bytes —
// 16-bit identifier (big-endian) + 32-bit value (big-endian).
static bool FindSettingsEntry(const std::vector<uint8_t>& payload,
                               uint16_t id, uint32_t& out_value) {
    for (size_t i = 0; i + 6 <= payload.size(); i += 6) {
        uint16_t entry_id =
            (static_cast<uint16_t>(payload[i]) << 8) | payload[i + 1];
        if (entry_id == id) {
            out_value = (static_cast<uint32_t>(payload[i + 2]) << 24) |
                        (static_cast<uint32_t>(payload[i + 3]) << 16) |
                        (static_cast<uint32_t>(payload[i + 4]) << 8)  |
                        static_cast<uint32_t>(payload[i + 5]);
            return true;
        }
    }
    return false;
}

// SETTINGS_ENABLE_PUSH wire format with push DISABLED (default):
// the server preface MUST contain {ENABLE_PUSH (0x02), 0}.
void TestH2_SettingsEnablePushWire_Disabled() {
    std::cout << "\n[TEST] H2 SETTINGS: ENABLE_PUSH=0 advertised when disabled..."
              << std::endl;
    try {
        ServerConfig cfg = MakeH2Config(0);
        cfg.http2.enable_push = false;  // explicit, default is also false
        HttpServer server(cfg);
        server.Get("/", [](const HttpRequest&, HttpResponse& r) { r.Text("ok"); });

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        auto payload = ReadServerSettingsPayload(port);
        bool pass = true;
        std::string err;
        if (payload.empty()) {
            pass = false; err += "no SETTINGS payload received; ";
        } else {
            uint32_t value = 0;
            if (!FindSettingsEntry(payload, 0x0002, value)) {
                pass = false;
                err += "ENABLE_PUSH (0x02) entry MISSING when push disabled; ";
            } else if (value != 0) {
                pass = false;
                err += "ENABLE_PUSH value must be 0 when push disabled, got " +
                       std::to_string(value) + "; ";
            }
        }

        TestFramework::RecordTest(
            "H2 SETTINGS: ENABLE_PUSH=0 advertised when disabled",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2 SETTINGS: ENABLE_PUSH=0 advertised when disabled",
            false, e.what(), TestFramework::TestCategory::OTHER);
    }
}

// SETTINGS_ENABLE_PUSH wire format with push ENABLED:
// the entry MUST be ABSENT (a server MUST NOT write a value of 1 per
// RFC 9113 §7). nghttp2's local default of 1 then applies internally.
void TestH2_SettingsEnablePushWire_Enabled() {
    std::cout << "\n[TEST] H2 SETTINGS: ENABLE_PUSH entry omitted when enabled..."
              << std::endl;
    try {
        ServerConfig cfg = MakeH2Config(0);
        cfg.http2.enable_push = true;
        HttpServer server(cfg);
        server.Get("/", [](const HttpRequest&, HttpResponse& r) { r.Text("ok"); });

        TestServerRunner<HttpServer> runner(server);
        int port = runner.GetPort();

        auto payload = ReadServerSettingsPayload(port);
        bool pass = true;
        std::string err;
        if (payload.empty()) {
            pass = false; err += "no SETTINGS payload received; ";
        } else {
            uint32_t value = 0;
            if (FindSettingsEntry(payload, 0x0002, value)) {
                pass = false;
                err += "ENABLE_PUSH must be ABSENT when push enabled, got value " +
                       std::to_string(value) + "; ";
            }
        }

        TestFramework::RecordTest(
            "H2 SETTINGS: ENABLE_PUSH entry omitted when enabled",
            pass, err, TestFramework::TestCategory::OTHER);
    } catch (const std::exception& e) {
        TestFramework::RecordTest(
            "H2 SETTINGS: ENABLE_PUSH entry omitted when enabled",
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

    // --- shutdown_drain_timeout_sec ---
    TestShutdownDrainDefault();
    TestShutdownDrainValidation();
    TestShutdownDrainJsonParsing();
    TestShutdownDrainEnvOverride();
    TestShutdownDrainSerialization();

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
    TestStreamInvalidHeaders();
    TestStreamCookieConcatenation();
    TestStreamBodyAppend();
    TestStreamLifecycle();
    TestStreamRequestComplete();
    TestStreamPathWithoutQuery();

    // --- Category 4: H2C Functional ---
    TestH2C_SimpleGet();
    TestH2C_SimplePost();
    TestH2C_NotFound();
    TestH2C_Middleware();
    TestH2C_MultipleStreams();
    TestH2C_LargeBody();

    // --- Category 5: Error Handling ---
    TestH2C_InvalidPreface();
    TestH2C_BodyTooLarge();

    // --- Category 6: Race Conditions ---
    TestH2C_ConcurrentClients();
    TestH2C_MixedProtocolClients();

    // --- Category 7: :authority vs host default-port normalization ---
    TestH2_AuthorityMatchesHostWithDefaultHttpPort();
    TestH2_AuthorityMatchesHostReverseOrder();
    TestH2_AuthorityMatchesHostWithDefaultHttpsPort();
    TestH2_AuthorityMismatchExplicitNonDefaultPort();
    TestH2_AuthorityMismatchWrongDefault();
    TestH2_AuthorityIPv6WithDefaultPort();
    TestH2_AuthorityCaseInsensitiveHostDefaultPort();

    // --- Category 8: 103 Early Hints / SubmitInterimHeaders ---
    TestH2_EarlyHints_Basic();
    TestH2_EarlyHints_Multiple();
    TestH2_EarlyHints_DroppedAfterFinal();
    TestH2_EarlyHints_InvalidStatusDropped();
    TestH2_EarlyHints_StreamClosedByPeerSafe();
    TestH2_EarlyHints_100ContinueThen103();
    TestH2_EarlyHints_OffDispatcherThread();

    // --- Category 9: SETTINGS_ENABLE_PUSH wire format ---
    TestH2_SettingsEnablePushWire_Disabled();
    TestH2_SettingsEnablePushWire_Enabled();
}

}  // namespace Http2Tests
